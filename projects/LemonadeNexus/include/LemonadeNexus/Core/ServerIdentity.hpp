#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

// Forward declarations — keep the header lightweight
namespace nexus::core { struct ServerConfig; }
namespace nexus::crypto { class SodiumCryptoService; }
namespace nexus::storage { class FileStorageService; }
namespace nexus::ipam { class IPAMService; }
namespace nexus::gossip { class GossipService; }
namespace nexus::security { class StorageVault; }

namespace nexus::core {

/// Result of TLS certificate resolution.
///
/// `key_bytes` carries the private key in memory whenever a storage vault covers
/// it (Phase 7): the listener uses the in-memory key and never opens the on-disk
/// file, which is DEK ciphertext and unreadable while the DEK is locked. When the
/// vault does not cover the key, `key_bytes` is empty and the listener loads
/// `key_path` from disk. `valid` stays false while a covered key cannot be
/// decrypted, so callers fail closed (no HTTP listener, pending API) instead of
/// serving or exposing plaintext.
struct TlsResolution {
    std::string cert_path;
    std::string key_path;
    std::string key_bytes;
    bool valid{false};
    bool needs_acme_background{false};
};

/// Resolve JWT secret: config value > persisted file > auto-generate and persist.
/// With `vault` (Phase 7, not owning), identity/jwt_secret.hex is read and
/// written through it; a file that exists but does not open returns an empty
/// string, and the caller must stop instead of replacing the secret.
[[nodiscard]] std::string resolve_jwt_secret(
    const ServerConfig& config,
    const std::filesystem::path& data_root,
    crypto::SodiumCryptoService& crypto,
    security::StorageVault* vault = nullptr);

/// Read the server_node_id from the stored server certificate.
[[nodiscard]] std::string resolve_server_node_id(
    storage::FileStorageService& storage);

/// Resolve server hostname: config > persisted > auto-generated.
/// Mutates config.server_hostname in-place if it was empty.
void resolve_server_hostname(
    ServerConfig& config,
    const std::filesystem::path& data_root,
    gossip::GossipService& gossip);

/// Resolve server region: config > persisted > auto-detect via HostnameGenerator.
/// Mutates config.region in-place and persists to data/identity/region.
void resolve_server_region(
    ServerConfig& config,
    const std::filesystem::path& data_root);

/// Resolve public IP: config > non-wildcard bind address > ipify auto-detect.
[[nodiscard]] std::string resolve_public_ip(const ServerConfig& config);

/// TCP connect probe with timeout. Used to sanity-check that our advertised
/// public IP actually accepts connections (auto-detection measures the egress
/// path, which is not necessarily the ingress on multihomed/VPN'd hosts).
[[nodiscard]] bool tcp_connect_check(const std::string& ip, uint16_t port,
                                     int timeout_sec);

/// Resolve IPv4 (A) records for a hostname via the system resolver (getaddrinfo).
/// Returns de-duplicated dotted-quad strings; empty on failure.
[[nodiscard]] std::vector<std::string> resolve_a_records(const std::string& hostname);

/// Extract TXT record strings from a raw DNS response message.
///
/// Bounds-checked and fail-closed: malformed input (truncated fields, labels
/// longer than 63 octets, name pointers that do not point backward into the
/// message, RDATA overruns) returns empty, as do non-responses and responses
/// with a nonzero rcode. Length-prefixed chunks within one TXT answer RR are
/// concatenated; each TXT answer RR yields one string.
[[nodiscard]] std::vector<std::string> parse_dns_txt_records(
    const std::vector<uint8_t>& message);

/// Encode a minimal DNS query: header (given ID, RD set, QDCOUNT=1) plus one
/// question (name, qtype, class IN), per RFC 1035 wire format.
/// Label encoding is fail-closed: an empty label or a label longer than 63
/// octets (including a trailing dot) returns an empty vector instead of a
/// truncated/oversized query. Callers must not send an empty result.
/// @param name  Query name, e.g. "tier1.us.seip.example.com".
/// @param qtype Question type (1 = A, 16 = TXT, ...).
/// @param id    Transaction ID to place in the header.
[[nodiscard]] std::vector<uint8_t> build_dns_query(
    const std::string& name, uint16_t qtype, uint16_t id);

/// Resolve TXT records for a hostname via a raw UDP DNS query to the system
/// resolver (first IPv4 `nameserver` line of /etc/resolv.conf, port 53).
/// getaddrinfo cannot return TXT data, so the query and reply are hand-rolled;
/// the reply must echo the query's random ID or is dropped. The TXT payload
/// is decoded by parse_dns_txt_records. Fails closed: returns empty on any
/// error, timeout, or malformed response, and on platforms without a
/// /etc/resolv.conf (e.g. Windows) where discovery is unavailable.
[[nodiscard]] std::vector<std::string> resolve_txt_records(const std::string& hostname);

/// Pure selection step (no network): turn an ordered list of candidate IPs into a
/// de-duplicated list of "ip:port" seed endpoints, excluding our own public IP and
/// preserving priority order. Factored out of discover_seed_endpoints for testing.
[[nodiscard]] std::vector<std::string> select_seed_endpoints(
    const std::vector<std::string>& candidate_ips,
    const std::string& our_public_ip,
    uint16_t gossip_port);

/// Discover gossip seed endpoints ("ip:port") from public tier+region DNS records.
/// Queries tier1/tier2.<region>.seip.<base_domain> for our region plus the nearest
/// regions (by geo distance), preferring higher tier and closer region first.
/// Excludes our_public_ip (no self-seeding) and de-duplicates. Empty on failure.
[[nodiscard]] std::vector<std::string> discover_seed_endpoints(
    const std::string& base_domain,
    const std::string& our_region,
    const std::string& our_public_ip,
    uint16_t gossip_port);

/// Build server FQDN from hostname + base domain.
[[nodiscard]] std::string build_server_fqdn(
    const std::string& server_hostname,
    const std::string& dns_base_domain);

/// Resolve this server's client-plane tunnel address, where it answers its
/// private API. The address follows the server's backbone allocation
/// (IPAMService::allocate_backbone_ip, keyed on `gossip_pubkey_b64`, the base64
/// gossip identity key) through IPAMService::server_tunnel_for_backbone, so it
/// is unique in the fleet and the same after a restart. Records the address in
/// IPAM. Returns the address without a prefix (e.g. "10.64.252.37"), or an
/// empty string when `server_node_id` or `gossip_pubkey_b64` is empty or no
/// address can be derived. Throws what allocate_backbone_ip throws.
[[nodiscard]] std::string resolve_tunnel_ip(
    const std::string& server_node_id,
    const std::string& gossip_pubkey_b64,
    ipam::IPAMService& ipam);

/// Resolve the TLS certificate for `server_fqdn`. The cert is always
/// ACME-issued (public CA on the SEIP FQDN); this returns the cert on disk for
/// THIS FQDN, or needs_acme_background=true when it must still be requested.
/// Each listener resolves its OWN FQDN independently — the private listener
/// (private.<seip>) never receives the public cert.
///
/// When `vault` is non-null and covers the private key, the key is read through
/// the vault and returned in `key_bytes` (never the raw on-disk file). A covered
/// key that cannot be decrypted yet keeps `valid` false, so the caller fails
/// closed. Without a vault the key path is returned as before.
[[nodiscard]] TlsResolution resolve_tls_cert(
    const std::filesystem::path& data_root,
    const std::string& server_fqdn,
    const security::StorageVault* vault = nullptr);

} // namespace nexus::core
