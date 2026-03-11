#pragma once

/// @file WireGuardWindowsBridge.h
/// C-callable bridge for wireguard-nt on Windows.
///
/// Wraps the wireguard-nt kernel driver API (wireguard.dll), handling
/// dynamic loading via LoadLibrary/GetProcAddress. All WireGuard operations
/// go through the kernel driver for native performance.
///
/// The wireguard.dll must be present in the application directory or
/// system32 at runtime. Download from:
/// https://download.wireguard.com/wireguard-nt/

#ifdef _WIN32

#ifdef __cplusplus
extern "C" {
#endif

/// Initialize the wireguard-nt DLL (LoadLibrary + resolve all function pointers).
///
/// Must be called once before any other wg_nt_* function.
///
/// @return 0 on success, -1 on failure (DLL not found or symbol resolution failed).
int wg_nt_init(void);

/// Unload the wireguard-nt DLL.
void wg_nt_deinit(void);

/// Check if the wireguard-nt DLL is loaded and ready.
///
/// @return 1 if initialized, 0 if not.
int wg_nt_is_initialized(void);

/// Get the running driver version.
///
/// @return Driver version (major in high word, minor in low word), or 0 on error.
unsigned long wg_nt_get_driver_version(void);

/// Create a new WireGuard adapter.
///
/// @param name        Adapter name (UTF-8, will be converted to wide string).
/// @param tunnel_type Tunnel type string (UTF-8, e.g. "WireGuard").
/// @return            Opaque adapter handle, or NULL on failure.
void* wg_nt_create_adapter(const char* name, const char* tunnel_type);

/// Open an existing WireGuard adapter by name.
///
/// @param name  Adapter name (UTF-8).
/// @return      Opaque adapter handle, or NULL if not found.
void* wg_nt_open_adapter(const char* name);

/// Close and destroy an adapter.
///
/// @param adapter  Handle returned by wg_nt_create_adapter or wg_nt_open_adapter.
void wg_nt_close_adapter(void* adapter);

/// Set the adapter state (up or down).
///
/// @param adapter  Adapter handle.
/// @param up       1 to bring up, 0 to bring down.
/// @return         0 on success, -1 on failure.
int wg_nt_set_adapter_state(void* adapter, int up);

/// Configure the interface (private key + listen port).
///
/// @param adapter      Adapter handle.
/// @param private_key  Base64-encoded WireGuard private key (44 chars).
/// @param listen_port  UDP listen port (0 = random).
/// @return             0 on success, -1 on failure.
int wg_nt_set_interface(void* adapter, const char* private_key, unsigned short listen_port);

/// Add a peer to the adapter.
///
/// @param adapter      Adapter handle.
/// @param pubkey       Base64-encoded public key (44 chars).
/// @param allowed_ips  Comma-separated CIDR list (e.g. "10.0.0.0/24, 192.168.1.0/24").
/// @param endpoint     Endpoint "ip:port" or "[ipv6]:port" (may be empty/NULL).
/// @param keepalive    Persistent keepalive interval in seconds (0 = disabled).
/// @return             0 on success, -1 on failure.
int wg_nt_add_peer(void* adapter, const char* pubkey, const char* allowed_ips,
                   const char* endpoint, unsigned short keepalive);

/// Remove a peer from the adapter.
///
/// @param adapter  Adapter handle.
/// @param pubkey   Base64-encoded public key (44 chars).
/// @return         0 on success, -1 on failure.
int wg_nt_remove_peer(void* adapter, const char* pubkey);

/// Peer information returned by wg_nt_get_peers.
typedef struct {
    char public_key[45];       ///< Base64 public key + null terminator
    char allowed_ips[256];     ///< Comma-separated CIDRs
    char endpoint[64];         ///< "ip:port" or empty
    unsigned long long last_handshake;  ///< Windows FILETIME (100ns since 1601)
    unsigned long long rx_bytes;
    unsigned long long tx_bytes;
    unsigned short persistent_keepalive;
} wg_nt_peer_info;

/// Get all peers configured on the adapter.
///
/// @param adapter    Adapter handle.
/// @param[out] peers Pointer to array of wg_nt_peer_info (caller allocates).
/// @param max_peers  Maximum number of peers to return.
/// @return           Number of peers written, or -1 on error.
int wg_nt_get_peers(void* adapter, wg_nt_peer_info* peers, int max_peers);

/// Auto-download wireguard.dll from the official WireGuard download server.
///
/// Downloads the wireguard-nt release ZIP, extracts the architecture-appropriate
/// DLL (amd64/x86/arm64), verifies its Authenticode code-signing signature,
/// and places it in the application directory.
///
/// Called automatically by wg_nt_init() if LoadLibrary fails, but can also
/// be called explicitly to pre-stage the DLL.
///
/// @return 0 on success (DLL already present or successfully downloaded),
///         -1 on failure (network error, extraction failed, unsupported arch,
///         or Authenticode signature verification failed).
int wg_nt_download_dll(void);

/// Assign an IP address to the adapter using the Windows IP Helper API.
///
/// @param adapter  Adapter handle.
/// @param address  CIDR address (e.g. "10.64.0.1/32").
/// @return         0 on success, -1 on failure.
int wg_nt_set_address(void* adapter, const char* address);

/// Add a route for a subnet via the adapter.
///
/// @param adapter      Adapter handle.
/// @param destination  CIDR destination (e.g. "10.128.0.0/24").
/// @return             0 on success, -1 on failure.
int wg_nt_add_route(void* adapter, const char* destination);

#ifdef __cplusplus
}
#endif

#endif // _WIN32
