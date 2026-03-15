#pragma once

/// C header for BoringTun's FFI API (matches the Rust crate's exported symbols).
/// See: https://github.com/cloudflare/boringtun

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Opaque tunnel handle.
typedef struct Tunn Tunn;

/// Result type returned by wireguard_* functions.
enum result_type {
    WIREGUARD_DONE       = 0,  ///< No operation required
    WRITE_TO_NETWORK     = 1,  ///< Send dst buffer over UDP to server
    WIREGUARD_ERROR      = 2,  ///< Error occurred
    WRITE_TO_TUNNEL_IPV4 = 4,  ///< Write dst buffer to TUN device (IPv4 packet)
    WRITE_TO_TUNNEL_IPV6 = 6,  ///< Write dst buffer to TUN device (IPv6 packet)
};

/// Result struct: operation + byte count.
struct wireguard_result {
    enum result_type op;
    size_t           size;
};

/// Create a new WireGuard tunnel.
/// @param static_private       Base64-encoded Curve25519 private key
/// @param server_static_public Base64-encoded Curve25519 public key of the peer
/// @param log_printer          Optional log callback (NULL to disable)
/// @param log_level            Verbosity (0 = silent, higher = more verbose)
/// @return Opaque tunnel handle, or NULL on error
Tunn* new_tunnel(const char* static_private,
                 const char* server_static_public,
                 void (*log_printer)(const char*),
                 uint32_t log_level);

/// Free a tunnel handle.
void tunnel_free(Tunn* tunnel);

/// Encrypt an IP packet for sending over the network.
/// @param src      Plaintext IP packet from TUN device
/// @param src_size Size of src
/// @param dst      Output buffer for encrypted WireGuard packet
/// @param dst_size Capacity of dst (should be >= src_size + 148)
struct wireguard_result wireguard_write(Tunn* tunnel,
                                       const uint8_t* src, uint32_t src_size,
                                       uint8_t* dst, uint32_t dst_size);

/// Decrypt a received WireGuard packet.
/// @param src      Encrypted WireGuard packet from UDP
/// @param src_size Size of src
/// @param dst      Output buffer for decrypted IP packet
/// @param dst_size Capacity of dst
struct wireguard_result wireguard_read(Tunn* tunnel,
                                      const uint8_t* src, uint32_t src_size,
                                      uint8_t* dst, uint32_t dst_size);

/// Periodic timer — call every ~100-250 ms.
/// Handles keepalives and handshake retries.
struct wireguard_result wireguard_tick(Tunn* tunnel,
                                      uint8_t* dst, uint32_t dst_size);

/// Force a new handshake with the peer.
struct wireguard_result wireguard_force_handshake(Tunn* tunnel,
                                                  uint8_t* dst, uint32_t dst_size);

#ifdef __cplusplus
}
#endif
