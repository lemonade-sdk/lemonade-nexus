#ifndef LEMONADE_NEXUS_SDK_H
#define LEMONADE_NEXUS_SDK_H

/**
 * @file lemonade_nexus.h
 * @brief C API for the Lemonade Nexus Client SDK.
 *
 * Opaque-handle API suitable for FFI from Python, Go, Rust, Swift, etc.
 * All complex outputs are returned as JSON strings via char** out_json.
 * Use ln_free() to release any string returned by the API.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Error codes                                                         */
/* ------------------------------------------------------------------ */

typedef enum {
    LN_OK             =  0,
    LN_ERR_NULL_ARG   = -1,
    LN_ERR_CONNECT    = -2,
    LN_ERR_AUTH       = -3,
    LN_ERR_NOT_FOUND  = -4,
    LN_ERR_REJECTED   = -5,
    LN_ERR_NO_IDENTITY = -6,
    LN_ERR_INTERNAL   = -99,
} ln_error_t;

/* ------------------------------------------------------------------ */
/* Opaque handles                                                      */
/* ------------------------------------------------------------------ */

typedef struct ln_client_s  ln_client_t;
typedef struct ln_identity_s ln_identity_t;

/* ------------------------------------------------------------------ */
/* Memory management                                                   */
/* ------------------------------------------------------------------ */

/** Free a string returned by any ln_* function. */
void ln_free(char* ptr);

/* ------------------------------------------------------------------ */
/* Client lifecycle                                                    */
/* ------------------------------------------------------------------ */

/** Create a client connecting to host:port (plaintext HTTP). */
ln_client_t* ln_create(const char* host, uint16_t port);

/** Create a client connecting to host:port (TLS). */
ln_client_t* ln_create_tls(const char* host, uint16_t port);

/** Destroy a client and release resources. */
void ln_destroy(ln_client_t* client);

/* ------------------------------------------------------------------ */
/* Identity management                                                 */
/* ------------------------------------------------------------------ */

/** Generate a new Ed25519 identity keypair. */
ln_identity_t* ln_identity_generate(void);

/** Load an identity from a JSON file. */
ln_identity_t* ln_identity_load(const char* path);

/** Save an identity to a JSON file. */
ln_error_t ln_identity_save(const ln_identity_t* identity, const char* path);

/** Get the public key string ("ed25519:<base64>"). Caller must ln_free(). */
char* ln_identity_pubkey(const ln_identity_t* identity);

/** Destroy an identity and release resources. */
void ln_identity_destroy(ln_identity_t* identity);

/** Attach an identity to a client for delta signing. */
ln_error_t ln_set_identity(ln_client_t* client, const ln_identity_t* identity);

/* ------------------------------------------------------------------ */
/* Health                                                              */
/* ------------------------------------------------------------------ */

/** GET /api/health. Returns JSON via out_json. Caller must ln_free(*out_json). */
ln_error_t ln_health(ln_client_t* client, char** out_json);

/* ------------------------------------------------------------------ */
/* Authentication                                                      */
/* ------------------------------------------------------------------ */

/** Authenticate with username/password. Returns JSON via out_json. */
ln_error_t ln_auth_password(ln_client_t* client,
                             const char* username,
                             const char* password,
                             char** out_json);

/** Authenticate with passkey/FIDO2 data (JSON string). Returns JSON via out_json. */
ln_error_t ln_auth_passkey(ln_client_t* client,
                            const char* passkey_json,
                            char** out_json);

/** Authenticate with a token-link token. Returns JSON via out_json. */
ln_error_t ln_auth_token(ln_client_t* client,
                          const char* token,
                          char** out_json);

/* ------------------------------------------------------------------ */
/* Tree operations                                                     */
/* ------------------------------------------------------------------ */

/** GET /api/tree/node/{id}. Returns JSON via out_json. */
ln_error_t ln_tree_get_node(ln_client_t* client,
                             const char* node_id,
                             char** out_json);

/** POST /api/tree/delta. delta_json is a JSON string of the delta. */
ln_error_t ln_tree_submit_delta(ln_client_t* client,
                                 const char* delta_json,
                                 char** out_json);

/* ------------------------------------------------------------------ */
/* IPAM                                                                */
/* ------------------------------------------------------------------ */

/** POST /api/ipam/allocate. block_type: "tunnel", "private", "shared". */
ln_error_t ln_ipam_allocate(ln_client_t* client,
                             const char* node_id,
                             const char* block_type,
                             char** out_json);

/* ------------------------------------------------------------------ */
/* Relay                                                               */
/* ------------------------------------------------------------------ */

/** GET /api/relay/list. Returns JSON array via out_json. */
ln_error_t ln_relay_list(ln_client_t* client, char** out_json);

/** POST /api/relay/ticket. Returns JSON via out_json. */
ln_error_t ln_relay_ticket(ln_client_t* client,
                            const char* peer_id,
                            const char* relay_id,
                            char** out_json);

/** POST /api/relay/register. reg_json is a JSON string. */
ln_error_t ln_relay_register(ln_client_t* client,
                              const char* reg_json,
                              char** out_json);

/* ------------------------------------------------------------------ */
/* Certificates                                                        */
/* ------------------------------------------------------------------ */

/** GET /api/certs/{domain}. Returns JSON via out_json. */
ln_error_t ln_cert_status(ln_client_t* client,
                           const char* domain,
                           char** out_json);

/** POST /api/certs/issue — request a TLS cert for this client's hostname.
 *  Returns JSON with encrypted cert bundle. Caller must ln_free(*out_json). */
ln_error_t ln_cert_request(ln_client_t* client,
                            const char* hostname,
                            char** out_json);

/** Decrypt an issued certificate bundle. bundle_json is the JSON from ln_cert_request.
 *  Returns JSON with {domain, fullchain_pem, privkey_pem, expires_at}.
 *  Caller must ln_free(*out_json). */
ln_error_t ln_cert_decrypt(ln_client_t* client,
                            const char* bundle_json,
                            char** out_json);

/* ------------------------------------------------------------------ */
/* Tree: children                                                      */
/* ------------------------------------------------------------------ */

/** GET /api/tree/children/{parent_id}. Returns JSON array via out_json. */
ln_error_t ln_tree_get_children(ln_client_t* client,
                                 const char* parent_id,
                                 char** out_json);

/* ------------------------------------------------------------------ */
/* Passkey registration                                                */
/* ------------------------------------------------------------------ */

/** POST /api/auth/register — register a passkey credential. */
ln_error_t ln_register_passkey(ln_client_t* client,
                                const char* user_id,
                                const char* credential_id,
                                const char* public_key_x,
                                const char* public_key_y,
                                char** out_json);

/* ------------------------------------------------------------------ */
/* Group membership                                                    */
/* ------------------------------------------------------------------ */

/** Add a member to a group node's assignments. permissions_json is a JSON array of strings. */
ln_error_t ln_add_group_member(ln_client_t* client,
                                const char* node_id,
                                const char* pubkey,
                                const char* permissions_json,
                                char** out_json);

/** Remove a member from a group node's assignments by pubkey. */
ln_error_t ln_remove_group_member(ln_client_t* client,
                                   const char* node_id,
                                   const char* pubkey,
                                   char** out_json);

/** Get members (assignments) of a group node. Returns JSON array via out_json. */
ln_error_t ln_get_group_members(ln_client_t* client,
                                 const char* node_id,
                                 char** out_json);

/** Join an existing group: create endpoint child + allocate tunnel IP. */
ln_error_t ln_join_group(ln_client_t* client,
                          const char* parent_node_id,
                          char** out_json);

/* ------------------------------------------------------------------ */
/* High-level operations                                               */
/* ------------------------------------------------------------------ */

/** Authenticate + create node + allocate IP. Returns JSON via out_json. */
ln_error_t ln_join_network(ln_client_t* client,
                            const char* username,
                            const char* password,
                            char** out_json);

/** Submit delete_node delta for current node. */
ln_error_t ln_leave_network(ln_client_t* client, char** out_json);

/* ------------------------------------------------------------------ */
/* Latency-based auto-switching                                        */
/* ------------------------------------------------------------------ */

/** Enable automatic server switching based on latency.
 *  @param threshold_ms  RTT threshold to trigger switch evaluation (default 200.0)
 *  @param hysteresis    Fraction by which new server must be better (default 0.3 = 30%)
 *  @param cooldown_sec  Minimum seconds between switches (default 60)
 */
ln_error_t ln_enable_auto_switching(ln_client_t* client,
                                     double threshold_ms,
                                     double hysteresis,
                                     uint32_t cooldown_sec);

/** Disable automatic server switching. */
ln_error_t ln_disable_auto_switching(ln_client_t* client);

/** Get current latency to the active server in milliseconds.
 *  Returns 0.0 if auto-switching is not enabled. */
double ln_current_latency_ms(ln_client_t* client);

/** Get latency stats for all known servers. Returns JSON array via out_json.
 *  Each element: {host, port, smoothed_rtt_ms, reachable, consecutive_failures}.
 *  Caller must ln_free(*out_json). */
ln_error_t ln_server_latencies(ln_client_t* client, char** out_json);

/* ------------------------------------------------------------------ */
/* WireGuard tunnel management                                         */
/* ------------------------------------------------------------------ */

/** Bring up the WireGuard tunnel with the given config (JSON string).
 *  Config JSON keys: private_key, public_key, tunnel_ip, server_public_key,
 *  server_endpoint, dns_server, listen_port, allowed_ips (array), keepalive.
 *  Returns status JSON via out_json. Caller must ln_free(*out_json). */
ln_error_t ln_tunnel_up(ln_client_t* client,
                         const char* config_json,
                         char** out_json);

/** Tear down the WireGuard tunnel.
 *  Returns status JSON via out_json. Caller must ln_free(*out_json). */
ln_error_t ln_tunnel_down(ln_client_t* client, char** out_json);

/** Get the current WireGuard tunnel status as JSON.
 *  Returns: {is_up, tunnel_ip, server_endpoint, last_handshake,
 *            rx_bytes, tx_bytes, latency_ms}.
 *  Caller must ln_free(*out_json). */
ln_error_t ln_tunnel_status(ln_client_t* client, char** out_json);

/** Get the WireGuard configuration string (wg-quick format).
 *  Useful on mobile platforms (iOS/Android) where the app manages
 *  the tunnel via NetworkExtension or VpnService.
 *  Returns NULL if no config is stored. Caller must ln_free(). */
char* ln_get_wg_config(ln_client_t* client);

/** Generate a WireGuard keypair (Curve25519).
 *  Returns JSON: {private_key: "base64", public_key: "base64"}.
 *  Caller must ln_free(). */
char* ln_wg_generate_keypair(void);

#ifdef __cplusplus
}
#endif

#endif /* LEMONADE_NEXUS_SDK_H */
