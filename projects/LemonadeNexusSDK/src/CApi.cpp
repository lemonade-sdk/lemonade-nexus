#include <LemonadeNexusSDK/lemonade_nexus.h>
#include <LemonadeNexusSDK/LemonadeNexusClient.hpp>

#include <nlohmann/json.hpp>

#include <cstdlib>
#include <cstring>

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

struct ln_client_s {
    lnsdk::LemonadeNexusClient client;
    explicit ln_client_s(const lnsdk::ServerConfig& cfg) : client{cfg} {}
};

struct ln_identity_s {
    lnsdk::Identity identity;
};

static char* strdup_json(const json& j) {
    auto s = j.dump();
    char* out = static_cast<char*>(std::malloc(s.size() + 1));
    if (out) {
        std::memcpy(out, s.c_str(), s.size() + 1);
    }
    return out;
}

static char* strdup_str(const std::string& s) {
    char* out = static_cast<char*>(std::malloc(s.size() + 1));
    if (out) {
        std::memcpy(out, s.c_str(), s.size() + 1);
    }
    return out;
}

// ---------------------------------------------------------------------------
// Memory management
// ---------------------------------------------------------------------------

void ln_free(char* ptr) {
    std::free(ptr);
}

// ---------------------------------------------------------------------------
// Client lifecycle
// ---------------------------------------------------------------------------

ln_client_t* ln_create(const char* host, uint16_t port) {
    if (!host) return nullptr;
    lnsdk::ServerConfig cfg(host, port, false);
    return new(std::nothrow) ln_client_s{cfg};
}

ln_client_t* ln_create_tls(const char* host, uint16_t port) {
    if (!host) return nullptr;
    lnsdk::ServerConfig cfg(host, port, true);
    return new(std::nothrow) ln_client_s{cfg};
}

void ln_destroy(ln_client_t* client) {
    delete client;
}

// ---------------------------------------------------------------------------
// Identity management
// ---------------------------------------------------------------------------

ln_identity_t* ln_identity_generate(void) {
    auto* id = new(std::nothrow) ln_identity_s;
    if (id) {
        id->identity.generate();
    }
    return id;
}

ln_identity_t* ln_identity_load(const char* path) {
    if (!path) return nullptr;
    auto* id = new(std::nothrow) ln_identity_s;
    if (!id) return nullptr;
    if (!id->identity.load(path)) {
        delete id;
        return nullptr;
    }
    return id;
}

ln_error_t ln_identity_save(const ln_identity_t* identity, const char* path) {
    if (!identity || !path) return LN_ERR_NULL_ARG;
    return identity->identity.save(path) ? LN_OK : LN_ERR_INTERNAL;
}

char* ln_identity_pubkey(const ln_identity_t* identity) {
    if (!identity) return nullptr;
    return strdup_str(identity->identity.pubkey_string());
}

void ln_identity_destroy(ln_identity_t* identity) {
    delete identity;
}

ln_error_t ln_set_identity(ln_client_t* client, const ln_identity_t* identity) {
    if (!client || !identity) return LN_ERR_NULL_ARG;
    client->client.set_identity(identity->identity);
    return LN_OK;
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

ln_error_t ln_health(ln_client_t* client, char** out_json) {
    if (!client || !out_json) return LN_ERR_NULL_ARG;

    auto result = client->client.check_health();
    json j;
    j["status"]  = result.value.status;
    j["service"] = result.value.service;
    j["ok"]      = result.ok;
    if (!result.ok) j["error"] = result.error;

    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_CONNECT;
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

ln_error_t ln_auth_password(ln_client_t* client,
                             const char* username,
                             const char* password,
                             char** out_json) {
    if (!client || !username || !password || !out_json) return LN_ERR_NULL_ARG;

    auto result = client->client.authenticate(username, password);
    json j;
    j["authenticated"] = result.value.authenticated;
    j["user_id"]       = result.value.user_id;
    j["session_token"] = result.value.session_token;
    if (!result.ok) j["error"] = result.error;

    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_AUTH;
}

ln_error_t ln_auth_passkey(ln_client_t* client,
                            const char* passkey_json,
                            char** out_json) {
    if (!client || !passkey_json || !out_json) return LN_ERR_NULL_ARG;

    auto data = json::parse(passkey_json, nullptr, false);
    if (data.is_discarded()) return LN_ERR_INTERNAL;

    auto result = client->client.authenticate_passkey(data);
    json j;
    j["authenticated"] = result.value.authenticated;
    j["user_id"]       = result.value.user_id;
    j["session_token"] = result.value.session_token;
    if (!result.ok) j["error"] = result.error;

    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_AUTH;
}

ln_error_t ln_auth_token(ln_client_t* client,
                          const char* token,
                          char** out_json) {
    if (!client || !token || !out_json) return LN_ERR_NULL_ARG;

    auto result = client->client.authenticate_token(token);
    json j;
    j["authenticated"] = result.value.authenticated;
    j["user_id"]       = result.value.user_id;
    j["session_token"] = result.value.session_token;
    if (!result.ok) j["error"] = result.error;

    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_AUTH;
}

// ---------------------------------------------------------------------------
// Tree operations
// ---------------------------------------------------------------------------

ln_error_t ln_tree_get_node(ln_client_t* client,
                             const char* node_id,
                             char** out_json) {
    if (!client || !node_id || !out_json) return LN_ERR_NULL_ARG;

    auto result = client->client.get_tree_node(node_id);
    if (result.ok) {
        json j = result.value;
        *out_json = strdup_json(j);
        return LN_OK;
    }

    json err;
    err["error"] = result.error;
    *out_json = strdup_json(err);
    return LN_ERR_NOT_FOUND;
}

ln_error_t ln_tree_submit_delta(ln_client_t* client,
                                 const char* delta_json,
                                 char** out_json) {
    if (!client || !delta_json || !out_json) return LN_ERR_NULL_ARG;

    auto parsed = json::parse(delta_json, nullptr, false);
    if (parsed.is_discarded()) {
        json err; err["error"] = "invalid JSON in delta";
        *out_json = strdup_json(err);
        return LN_ERR_INTERNAL;
    }

    lnsdk::TreeDelta delta;
    try {
        delta = parsed.get<lnsdk::TreeDelta>();
    } catch (const std::exception& e) {
        json err; err["error"] = std::string("delta parse error: ") + e.what();
        *out_json = strdup_json(err);
        return LN_ERR_INTERNAL;
    }

    auto result = client->client.submit_delta(delta);
    json j;
    j["success"]        = result.value.success;
    j["delta_sequence"] = result.value.delta_sequence;
    j["node_id"]        = result.value.node_id;
    j["tunnel_ip"]      = result.value.tunnel_ip;
    j["private_subnet"] = result.value.private_subnet;
    if (!result.ok) j["error"] = result.error;

    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_REJECTED;
}

ln_error_t ln_create_child_node(ln_client_t* client,
                                 const char* parent_id,
                                 const char* node_type,
                                 char** out_json) {
    if (!client || !parent_id || !node_type || !out_json) return LN_ERR_NULL_ARG;

    lnsdk::TreeNode child;
    std::string type_str(node_type);
    try {
        child.type = lnsdk::string_to_node_type(type_str);
    } catch (...) {
        json err; err["error"] = "invalid node type: " + type_str;
        *out_json = strdup_json(err);
        return LN_ERR_INTERNAL;
    }
    child.parent_id = parent_id;

    auto result = client->client.create_child_node(parent_id, child);
    json j;
    j["success"]        = result.value.success;
    j["delta_sequence"] = result.value.delta_sequence;
    j["node_id"]        = result.value.node_id;
    j["tunnel_ip"]      = result.value.tunnel_ip;
    j["private_subnet"] = result.value.private_subnet;
    if (!result.ok) j["error"] = result.error;

    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_REJECTED;
}

ln_error_t ln_update_node(ln_client_t* client,
                           const char* node_id,
                           const char* updates_json,
                           char** out_json) {
    if (!client || !node_id || !updates_json || !out_json) return LN_ERR_NULL_ARG;

    auto parsed = json::parse(updates_json, nullptr, false);
    if (parsed.is_discarded()) {
        json err; err["error"] = "invalid JSON in updates";
        *out_json = strdup_json(err);
        return LN_ERR_INTERNAL;
    }

    auto result = client->client.update_node(node_id, parsed);
    json j;
    j["success"]        = result.value.success;
    j["delta_sequence"] = result.value.delta_sequence;
    j["node_id"]        = result.value.node_id;
    if (!result.ok) j["error"] = result.error;

    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_REJECTED;
}

ln_error_t ln_delete_node(ln_client_t* client,
                           const char* node_id,
                           char** out_json) {
    if (!client || !node_id || !out_json) return LN_ERR_NULL_ARG;

    auto result = client->client.delete_node(node_id);
    json j;
    j["success"]        = result.value.success;
    j["delta_sequence"] = result.value.delta_sequence;
    if (!result.ok) j["error"] = result.error;

    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_REJECTED;
}

// ---------------------------------------------------------------------------
// IPAM
// ---------------------------------------------------------------------------

ln_error_t ln_ipam_allocate(ln_client_t* client,
                             const char* node_id,
                             const char* block_type,
                             char** out_json) {
    if (!client || !node_id || !block_type || !out_json) return LN_ERR_NULL_ARG;

    lnsdk::AllocationRequest req;
    req.node_id = node_id;

    std::string bt = block_type;
    if (bt == "tunnel")       req.block_type = lnsdk::BlockType::Tunnel;
    else if (bt == "private") req.block_type = lnsdk::BlockType::Private;
    else if (bt == "shared")  req.block_type = lnsdk::BlockType::Shared;
    else return LN_ERR_INTERNAL;

    auto result = client->client.allocate_ip(req);
    json j;
    j["success"] = result.value.success;
    j["network"] = result.value.network;
    j["node_id"] = result.value.node_id;
    if (!result.ok) j["error"] = result.error;

    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_REJECTED;
}

// ---------------------------------------------------------------------------
// Relay
// ---------------------------------------------------------------------------

ln_error_t ln_relay_list(ln_client_t* client, char** out_json) {
    if (!client || !out_json) return LN_ERR_NULL_ARG;

    auto result = client->client.list_relays();
    json arr = json::array();
    for (const auto& r : result.value) {
        arr.push_back({
            {"relay_id",         r.relay_id},
            {"endpoint",         r.endpoint},
            {"region",           r.region},
            {"reputation_score", r.reputation_score},
            {"supports_stun",    r.supports_stun},
            {"supports_relay",   r.supports_relay},
        });
    }
    *out_json = strdup_json(arr);
    return result.ok ? LN_OK : LN_ERR_CONNECT;
}

ln_error_t ln_relay_ticket(ln_client_t* client,
                            const char* peer_id,
                            const char* relay_id,
                            char** out_json) {
    if (!client || !peer_id || !relay_id || !out_json) return LN_ERR_NULL_ARG;

    auto result = client->client.request_relay_ticket(peer_id, relay_id);
    json j;
    j["peer_id"]       = result.value.peer_id;
    j["relay_id"]      = result.value.relay_id;
    j["session_nonce"] = result.value.session_nonce;
    j["issued_at"]     = result.value.issued_at;
    j["expires_at"]    = result.value.expires_at;
    j["signature"]     = result.value.signature;

    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_CONNECT;
}

ln_error_t ln_relay_register(ln_client_t* client,
                              const char* reg_json,
                              char** out_json) {
    if (!client || !reg_json || !out_json) return LN_ERR_NULL_ARG;

    auto parsed = json::parse(reg_json, nullptr, false);
    if (parsed.is_discarded()) return LN_ERR_INTERNAL;

    lnsdk::RelayRegistration reg;
    reg.relay_id       = parsed.value("relay_id", "");
    reg.endpoint       = parsed.value("endpoint", "");
    reg.region         = parsed.value("region", "");
    reg.public_key     = parsed.value("public_key", "");
    reg.capacity_mbps  = parsed.value("capacity_mbps", uint32_t{0});
    reg.supports_stun  = parsed.value("supports_stun", true);
    reg.supports_relay = parsed.value("supports_relay", true);

    auto result = client->client.register_relay(reg);
    json j;
    j["success"]  = result.value.success;
    j["relay_id"] = result.value.relay_id;
    if (!result.ok) j["error"] = result.error;

    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_REJECTED;
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

ln_error_t ln_cert_status(ln_client_t* client,
                           const char* domain,
                           char** out_json) {
    if (!client || !domain || !out_json) return LN_ERR_NULL_ARG;

    auto result = client->client.get_cert_status(domain);
    json j;
    j["domain"]     = result.value.domain;
    j["has_cert"]   = result.value.has_cert;
    j["expires_at"] = result.value.expires_at;
    if (!result.ok) j["error"] = result.error;

    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_NOT_FOUND;
}

ln_error_t ln_cert_request(ln_client_t* client,
                            const char* hostname,
                            char** out_json) {
    if (!client || !hostname || !out_json) return LN_ERR_NULL_ARG;

    auto result = client->client.request_certificate(hostname);
    json j;
    j["domain"]           = result.value.domain;
    j["fullchain_pem"]    = result.value.fullchain_pem;
    j["encrypted_privkey"] = result.value.encrypted_privkey;
    j["nonce"]            = result.value.nonce;
    j["ephemeral_pubkey"] = result.value.ephemeral_pubkey;
    j["expires_at"]       = result.value.expires_at;
    if (!result.ok) j["error"] = result.error;

    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_CONNECT;
}

ln_error_t ln_cert_decrypt(ln_client_t* client,
                            const char* bundle_json,
                            char** out_json) {
    if (!client || !bundle_json || !out_json) return LN_ERR_NULL_ARG;

    auto parsed = json::parse(bundle_json, nullptr, false);
    if (parsed.is_discarded()) return LN_ERR_INTERNAL;

    lnsdk::IssuedCertBundle bundle;
    bundle.domain           = parsed.value("domain", "");
    bundle.fullchain_pem    = parsed.value("fullchain_pem", "");
    bundle.encrypted_privkey = parsed.value("encrypted_privkey", "");
    bundle.nonce            = parsed.value("nonce", "");
    bundle.ephemeral_pubkey = parsed.value("ephemeral_pubkey", "");
    bundle.expires_at       = parsed.value("expires_at", uint64_t{0});

    auto result = client->client.decrypt_certificate(bundle);
    json j;
    j["domain"]        = result.value.domain;
    j["fullchain_pem"] = result.value.fullchain_pem;
    j["privkey_pem"]   = result.value.privkey_pem;
    j["expires_at"]    = result.value.expires_at;
    if (!result.ok) j["error"] = result.error;

    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_INTERNAL;
}

// ---------------------------------------------------------------------------
// Tree: children
// ---------------------------------------------------------------------------

ln_error_t ln_tree_get_children(ln_client_t* client,
                                 const char* parent_id,
                                 char** out_json) {
    if (!client || !parent_id || !out_json) return LN_ERR_NULL_ARG;

    auto result = client->client.get_children(parent_id);
    json arr = json::array();
    for (const auto& child : result.value) {
        json j = child;
        arr.push_back(j);
    }
    *out_json = strdup_json(arr);
    return result.ok ? LN_OK : LN_ERR_CONNECT;
}

// ---------------------------------------------------------------------------
// Passkey registration
// ---------------------------------------------------------------------------

ln_error_t ln_register_passkey(ln_client_t* client,
                                const char* user_id,
                                const char* credential_id,
                                const char* public_key_x,
                                const char* public_key_y,
                                char** out_json) {
    if (!client || !user_id || !credential_id || !public_key_x || !public_key_y || !out_json)
        return LN_ERR_NULL_ARG;

    lnsdk::PasskeyCredential cred;
    cred.credential_id = credential_id;
    cred.public_key_x  = public_key_x;
    cred.public_key_y  = public_key_y;

    auto result = client->client.register_passkey_credential(user_id, cred);
    json j;
    j["authenticated"] = result.value.authenticated;
    j["user_id"]       = result.value.user_id;
    j["session_token"] = result.value.session_token;
    if (!result.ok) j["error"] = result.error;

    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_AUTH;
}

// ---------------------------------------------------------------------------
// Group membership
// ---------------------------------------------------------------------------

ln_error_t ln_add_group_member(ln_client_t* client,
                                const char* node_id,
                                const char* pubkey,
                                const char* permissions_json,
                                char** out_json) {
    if (!client || !node_id || !pubkey || !permissions_json || !out_json)
        return LN_ERR_NULL_ARG;

    auto perms = json::parse(permissions_json, nullptr, false);
    if (perms.is_discarded() || !perms.is_array()) return LN_ERR_INTERNAL;

    lnsdk::GroupMember member;
    member.management_pubkey = pubkey;
    for (const auto& p : perms) {
        if (p.is_string()) member.permissions.push_back(p.get<std::string>());
    }

    auto result = client->client.add_group_member(node_id, member);
    json j;
    j["success"] = result.value.success;
    j["node_id"] = result.value.node_id;
    if (!result.ok) j["error"] = result.error;

    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_REJECTED;
}

ln_error_t ln_remove_group_member(ln_client_t* client,
                                   const char* node_id,
                                   const char* pubkey,
                                   char** out_json) {
    if (!client || !node_id || !pubkey || !out_json) return LN_ERR_NULL_ARG;

    auto result = client->client.remove_group_member(node_id, pubkey);
    json j;
    j["success"] = result.value.success;
    j["node_id"] = result.value.node_id;
    if (!result.ok) j["error"] = result.error;

    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_REJECTED;
}

ln_error_t ln_get_group_members(ln_client_t* client,
                                 const char* node_id,
                                 char** out_json) {
    if (!client || !node_id || !out_json) return LN_ERR_NULL_ARG;

    auto result = client->client.get_group_members(node_id);
    json arr = json::array();
    for (const auto& m : result.value) {
        arr.push_back({
            {"management_pubkey", m.management_pubkey},
            {"permissions",       m.permissions},
        });
    }
    *out_json = strdup_json(arr);
    return result.ok ? LN_OK : LN_ERR_NOT_FOUND;
}

ln_error_t ln_join_group(ln_client_t* client,
                          const char* parent_node_id,
                          char** out_json) {
    if (!client || !parent_node_id || !out_json) return LN_ERR_NULL_ARG;

    auto result = client->client.join_group(parent_node_id);
    json j;
    j["success"]        = result.value.success;
    j["node_id"]        = result.value.node_id;
    j["tunnel_ip"]      = result.value.tunnel_ip;
    j["parent_node_id"] = result.value.parent_node_id;
    if (!result.ok) j["error"] = result.error;

    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_REJECTED;
}

// ---------------------------------------------------------------------------
// High-level operations
// ---------------------------------------------------------------------------

ln_error_t ln_join_network(ln_client_t* client,
                            const char* username,
                            const char* password,
                            char** out_json) {
    if (!client || !username || !password || !out_json) return LN_ERR_NULL_ARG;

    auto result = client->client.join_network(username, password);
    json j;
    j["success"]        = result.value.success;
    j["node_id"]        = result.value.node_id;
    j["tunnel_ip"]      = result.value.tunnel_ip;
    j["private_subnet"] = result.value.private_subnet;
    j["wg_pubkey"]      = result.value.wg_pubkey;
    if (!result.ok) j["error"] = result.error;

    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_AUTH;
}

ln_error_t ln_leave_network(ln_client_t* client, char** out_json) {
    if (!client || !out_json) return LN_ERR_NULL_ARG;

    auto result = client->client.leave_network();
    json j;
    j["success"] = result.ok;
    if (!result.ok) j["error"] = result.error;

    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_REJECTED;
}

// ---------------------------------------------------------------------------
// Latency-based auto-switching
// ---------------------------------------------------------------------------

ln_error_t ln_enable_auto_switching(ln_client_t* client,
                                     double threshold_ms,
                                     double hysteresis,
                                     uint32_t cooldown_sec) {
    if (!client) return LN_ERR_NULL_ARG;

    lnsdk::LatencyConfig config;
    config.threshold_ms = threshold_ms;
    config.hysteresis   = hysteresis;
    config.cooldown_sec = cooldown_sec;

    try {
        client->client.enable_auto_switching(config);
        return LN_OK;
    } catch (...) {
        return LN_ERR_INTERNAL;
    }
}

ln_error_t ln_disable_auto_switching(ln_client_t* client) {
    if (!client) return LN_ERR_NULL_ARG;

    try {
        client->client.disable_auto_switching();
        return LN_OK;
    } catch (...) {
        return LN_ERR_INTERNAL;
    }
}

double ln_current_latency_ms(ln_client_t* client) {
    if (!client) return 0.0;
    return client->client.current_latency_ms();
}

ln_error_t ln_server_latencies(ln_client_t* client, char** out_json) {
    if (!client || !out_json) return LN_ERR_NULL_ARG;

    auto stats = client->client.server_latencies();
    json arr = json::array();
    for (const auto& sl : stats) {
        json entry;
        if (!sl.server.servers.empty()) {
            entry["host"] = sl.server.servers[0].host;
            entry["port"] = sl.server.servers[0].port;
            entry["use_tls"] = sl.server.servers[0].use_tls;
        }
        entry["smoothed_rtt_ms"]      = sl.smoothed_rtt_ms;
        entry["reachable"]            = sl.reachable;
        entry["last_probe_time"]      = sl.last_probe_time;
        entry["consecutive_failures"] = sl.consecutive_failures;
        arr.push_back(std::move(entry));
    }
    *out_json = strdup_json(arr);
    return LN_OK;
}

// ---------------------------------------------------------------------------
// WireGuard tunnel management
// ---------------------------------------------------------------------------

ln_error_t ln_tunnel_up(ln_client_t* client,
                         const char* config_json,
                         char** out_json) {
    if (!client || !config_json || !out_json) return LN_ERR_NULL_ARG;

    auto parsed = json::parse(config_json, nullptr, false);
    if (parsed.is_discarded()) return LN_ERR_INTERNAL;

    lnsdk::WireGuardConfig config;
    config.private_key       = parsed.value("private_key", "");
    config.public_key        = parsed.value("public_key", "");
    config.tunnel_ip         = parsed.value("tunnel_ip", "");
    config.server_public_key = parsed.value("server_public_key", "");
    config.server_endpoint   = parsed.value("server_endpoint", "");
    config.dns_server        = parsed.value("dns_server", "");
    config.listen_port       = parsed.value("listen_port", uint16_t{0});
    config.keepalive         = parsed.value("keepalive", uint32_t{25});

    if (parsed.contains("allowed_ips") && parsed["allowed_ips"].is_array()) {
        for (const auto& ip : parsed["allowed_ips"]) {
            if (ip.is_string()) config.allowed_ips.push_back(ip.get<std::string>());
        }
    }

    auto result = client->client.tunnel_up(config);
    json j;
    j["success"] = result.ok;
    if (!result.ok) j["error"] = result.error;

    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_INTERNAL;
}

ln_error_t ln_tunnel_down(ln_client_t* client, char** out_json) {
    if (!client || !out_json) return LN_ERR_NULL_ARG;

    auto result = client->client.tunnel_down();
    json j;
    j["success"] = result.ok;
    if (!result.ok) j["error"] = result.error;

    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_INTERNAL;
}

ln_error_t ln_tunnel_status(ln_client_t* client, char** out_json) {
    if (!client || !out_json) return LN_ERR_NULL_ARG;

    auto st = client->client.tunnel_status();
    json j;
    j["is_up"]            = st.is_up;
    j["tunnel_ip"]        = st.tunnel_ip;
    j["server_endpoint"]  = st.server_endpoint;
    j["last_handshake"]   = st.last_handshake;
    j["rx_bytes"]         = st.rx_bytes;
    j["tx_bytes"]         = st.tx_bytes;
    j["latency_ms"]       = st.latency_ms;

    *out_json = strdup_json(j);
    return LN_OK;
}

char* ln_get_wg_config(ln_client_t* client) {
    if (!client) return nullptr;
    auto cfg = client->client.get_wireguard_config();
    if (cfg.empty()) return nullptr;
    return strdup_str(cfg);
}

char* ln_wg_generate_keypair(void) {
    auto [priv, pub] = lnsdk::WireGuardTunnel::generate_keypair();
    json j;
    j["private_key"] = priv;
    j["public_key"]  = pub;
    return strdup_json(j);
}

// ---------------------------------------------------------------------------
// Identity: seed-based creation
// ---------------------------------------------------------------------------

ln_identity_t* ln_identity_from_seed(const uint8_t* seed, uint32_t seed_len) {
    if (!seed || seed_len != 32) return nullptr;
    auto* id = new(std::nothrow) ln_identity_s;
    if (!id) return nullptr;
    id->identity.from_seed({seed, seed_len});
    if (!id->identity.is_valid()) {
        delete id;
        return nullptr;
    }
    return id;
}

char* ln_derive_seed(const char* username, const char* password) {
    if (!username || !password) return nullptr;
    auto seed = lnsdk::Identity::derive_seed(username, password);
    if (seed.empty()) return nullptr;
    return strdup_str(lnsdk::Identity::to_base64(seed));
}

// ---------------------------------------------------------------------------
// Ed25519 challenge-response authentication
// ---------------------------------------------------------------------------

ln_error_t ln_auth_ed25519(ln_client_t* client, char** out_json) {
    if (!client || !out_json) return LN_ERR_NULL_ARG;

    auto result = client->client.authenticate_ed25519();
    json j;
    j["authenticated"] = result.value.authenticated;
    j["user_id"]       = result.value.user_id;
    j["session_token"] = result.value.session_token;
    if (!result.ok) j["error"] = result.error;

    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_AUTH;
}

// ---------------------------------------------------------------------------
// Stats & server listing
// ---------------------------------------------------------------------------

ln_error_t ln_stats(ln_client_t* client, char** out_json) {
    if (!client || !out_json) return LN_ERR_NULL_ARG;
    auto result = client->client.get_stats();
    json j;
    j["service"]             = result.value.service;
    j["peer_count"]          = result.value.peer_count;
    j["private_api_enabled"] = result.value.private_api_enabled;
    if (!result.ok) j["error"] = result.error;
    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_CONNECT;
}

ln_error_t ln_servers(ln_client_t* client, char** out_json) {
    if (!client || !out_json) return LN_ERR_NULL_ARG;
    auto result = client->client.get_servers();
    json arr = json::array();
    for (const auto& s : result.value) {
        arr.push_back({
            {"endpoint",  s.endpoint},
            {"pubkey",    s.pubkey},
            {"http_port", s.http_port},
            {"last_seen", s.last_seen},
            {"healthy",   s.healthy},
        });
    }
    *out_json = strdup_json(arr);
    return result.ok ? LN_OK : LN_ERR_CONNECT;
}

// ---------------------------------------------------------------------------
// Trust & attestation
// ---------------------------------------------------------------------------

ln_error_t ln_trust_status(ln_client_t* client, char** out_json) {
    if (!client || !out_json) return LN_ERR_NULL_ARG;
    auto result = client->client.get_trust_status();
    json j;
    j["our_tier"]    = result.value.our_tier;
    j["our_platform"] = result.value.our_platform;
    j["require_tee"] = result.value.require_tee;
    j["binary_hash"] = result.value.binary_hash;
    j["peer_count"]  = result.value.peer_count;
    json peers = json::array();
    for (const auto& p : result.value.peers) {
        peers.push_back({
            {"pubkey",               p.pubkey},
            {"tier",                 p.tier},
            {"tier_name",            p.tier_name},
            {"platform",             p.platform},
            {"last_verified",        p.last_verified},
            {"binary_hash",          p.binary_hash},
            {"failed_verifications", p.failed_verifications},
        });
    }
    j["peers"] = peers;
    if (!result.ok) j["error"] = result.error;
    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_CONNECT;
}

ln_error_t ln_trust_peer(ln_client_t* client, const char* pubkey, char** out_json) {
    if (!client || !pubkey || !out_json) return LN_ERR_NULL_ARG;
    auto result = client->client.get_trust_peer(pubkey);
    json j;
    j["pubkey"]               = result.value.pubkey;
    j["tier"]                 = result.value.tier;
    j["tier_name"]            = result.value.tier_name;
    j["platform"]             = result.value.platform;
    j["last_verified"]        = result.value.last_verified;
    j["attestation_hash"]     = result.value.attestation_hash;
    j["binary_hash"]          = result.value.binary_hash;
    j["failed_verifications"] = result.value.failed_verifications;
    if (!result.ok) j["error"] = result.error;
    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_NOT_FOUND;
}

// ---------------------------------------------------------------------------
// DDNS status
// ---------------------------------------------------------------------------

ln_error_t ln_ddns_status(ln_client_t* client, char** out_json) {
    if (!client || !out_json) return LN_ERR_NULL_ARG;
    auto result = client->client.get_ddns_status();
    json j;
    j["has_credentials"] = result.value.has_credentials;
    j["last_ip"]         = result.value.last_ip;
    j["binary_hash"]     = result.value.binary_hash;
    j["binary_approved"] = result.value.binary_approved;
    if (!result.ok) j["error"] = result.error;
    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_CONNECT;
}

// ---------------------------------------------------------------------------
// Enrollment
// ---------------------------------------------------------------------------

ln_error_t ln_enrollment_status(ln_client_t* client, char** out_json) {
    if (!client || !out_json) return LN_ERR_NULL_ARG;
    auto result = client->client.get_enrollment_status();
    json j;
    j["enabled"]          = result.value.enabled;
    j["quorum_ratio"]     = result.value.quorum_ratio;
    j["vote_timeout_sec"] = result.value.vote_timeout_sec;
    j["pending_count"]    = result.value.pending_count;
    json enrollments = json::array();
    for (const auto& e : result.value.enrollments) {
        json entry;
        entry["request_id"]          = e.request_id;
        entry["candidate_pubkey"]    = e.candidate_pubkey;
        entry["candidate_server_id"] = e.candidate_server_id;
        entry["sponsor_pubkey"]      = e.sponsor_pubkey;
        entry["state"]               = e.state;
        entry["state_name"]          = e.state_name;
        entry["created_at"]          = e.created_at;
        entry["timeout_at"]          = e.timeout_at;
        entry["retries"]             = e.retries;
        json votes = json::array();
        for (const auto& v : e.votes) {
            votes.push_back({
                {"voter_pubkey", v.voter_pubkey},
                {"approve",      v.approve},
                {"reason",       v.reason},
                {"timestamp",    v.timestamp},
            });
        }
        entry["votes"] = votes;
        enrollments.push_back(std::move(entry));
    }
    j["enrollments"] = enrollments;
    if (!result.ok) j["error"] = result.error;
    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_CONNECT;
}

// ---------------------------------------------------------------------------
// Governance
// ---------------------------------------------------------------------------

ln_error_t ln_governance_proposals(ln_client_t* client, char** out_json) {
    if (!client || !out_json) return LN_ERR_NULL_ARG;
    auto result = client->client.get_governance_proposals();
    json arr = json::array();
    for (const auto& p : result.value) {
        json entry;
        entry["proposal_id"]    = p.proposal_id;
        entry["proposer_pubkey"] = p.proposer_pubkey;
        entry["parameter"]      = p.parameter;
        entry["new_value"]      = p.new_value;
        entry["old_value"]      = p.old_value;
        entry["rationale"]      = p.rationale;
        entry["created_at"]     = p.created_at;
        entry["expires_at"]     = p.expires_at;
        entry["state"]          = p.state;
        entry["state_name"]     = p.state_name;
        json votes = json::array();
        for (const auto& v : p.votes) {
            votes.push_back({
                {"voter_pubkey", v.voter_pubkey},
                {"approve",      v.approve},
                {"reason",       v.reason},
                {"timestamp",    v.timestamp},
            });
        }
        entry["votes"] = votes;
        arr.push_back(std::move(entry));
    }
    *out_json = strdup_json(arr);
    return result.ok ? LN_OK : LN_ERR_CONNECT;
}

ln_error_t ln_governance_propose(ln_client_t* client,
                                   uint8_t parameter,
                                   const char* new_value,
                                   const char* rationale,
                                   char** out_json) {
    if (!client || !new_value || !rationale || !out_json) return LN_ERR_NULL_ARG;
    auto result = client->client.submit_governance_proposal(parameter, new_value, rationale);
    json j;
    j["proposal_id"] = result.value.proposal_id;
    j["status"]      = result.value.status;
    if (!result.ok) j["error"] = result.error;
    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_REJECTED;
}

// ---------------------------------------------------------------------------
// Attestation manifests
// ---------------------------------------------------------------------------

ln_error_t ln_attestation_manifests(ln_client_t* client, char** out_json) {
    if (!client || !out_json) return LN_ERR_NULL_ARG;
    auto result = client->client.get_attestation_manifests();
    json j;
    j["self_hash"]     = result.value.self_hash;
    j["self_approved"] = result.value.self_approved;
    j["github_url"]    = result.value.github_url;
    j["minimum_version"] = result.value.minimum_version;
    j["manifest_fetch_interval_sec"] = result.value.manifest_fetch_interval_sec;
    json manifests = json::array();
    for (const auto& m : result.value.manifests) {
        manifests.push_back({
            {"version",       m.version},
            {"platform",      m.platform},
            {"binary_sha256", m.binary_sha256},
            {"timestamp",     m.timestamp},
        });
    }
    j["manifests"] = manifests;
    if (!result.ok) j["error"] = result.error;
    *out_json = strdup_json(j);
    return result.ok ? LN_OK : LN_ERR_CONNECT;
}

// ---------------------------------------------------------------------------
// Session management
// ---------------------------------------------------------------------------

ln_error_t ln_set_session_token(ln_client_t* client, const char* token) {
    if (!client || !token) return LN_ERR_NULL_ARG;
    client->client.set_session_token(token);
    return LN_OK;
}

char* ln_get_session_token(ln_client_t* client) {
    if (!client) return nullptr;
    auto token = client->client.session_token();
    if (token.empty()) return nullptr;
    return strdup_str(token);
}

ln_error_t ln_set_node_id(ln_client_t* client, const char* node_id) {
    if (!client || !node_id) return LN_ERR_NULL_ARG;
    client->client.set_node_id(node_id);
    return LN_OK;
}

char* ln_get_node_id(ln_client_t* client) {
    if (!client) return nullptr;
    auto id = client->client.node_id();
    if (id.empty()) return nullptr;
    return strdup_str(id);
}
