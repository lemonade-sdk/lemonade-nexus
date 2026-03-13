#pragma once

#include <filesystem>
#include <string>

// Forward declarations — keep the header lightweight
namespace nexus::core { struct ServerConfig; }
namespace nexus::crypto { class SodiumCryptoService; }
namespace nexus::storage { class FileStorageService; }
namespace nexus::ipam { class IPAMService; }
namespace nexus::gossip { class GossipService; }

namespace nexus::core {

/// Result of TLS certificate resolution.
struct TlsResolution {
    std::string cert_path;
    std::string key_path;
    bool needs_acme_background{false};
};

/// Resolve JWT secret: config value > persisted file > auto-generate and persist.
[[nodiscard]] std::string resolve_jwt_secret(
    const ServerConfig& config,
    const std::filesystem::path& data_root,
    crypto::SodiumCryptoService& crypto);

/// Read the server_node_id from the stored server certificate.
[[nodiscard]] std::string resolve_server_node_id(
    storage::FileStorageService& storage);

/// Resolve server hostname: config > persisted > auto-generated.
/// Mutates config.server_hostname in-place if it was empty.
void resolve_server_hostname(
    ServerConfig& config,
    const std::filesystem::path& data_root,
    gossip::GossipService& gossip);

/// Resolve public IP: config > non-wildcard bind address > ipify auto-detect.
[[nodiscard]] std::string resolve_public_ip(const ServerConfig& config);

/// Build server FQDN from hostname + base domain.
[[nodiscard]] std::string build_server_fqdn(
    const std::string& server_hostname,
    const std::string& dns_base_domain);

/// Allocate tunnel IP for this server:
/// existing IPAM allocation > gossip assignment > self-allocate.
/// Returns IP with CIDR stripped (e.g. "10.64.0.1").
[[nodiscard]] std::string resolve_tunnel_ip(
    const std::string& server_node_id,
    const ServerConfig& config,
    ipam::IPAMService& ipam,
    gossip::GossipService& gossip);

/// Resolve TLS certificate paths:
/// manual override > existing ACME cert on disk > needs_acme_background flag.
[[nodiscard]] TlsResolution resolve_tls_cert(
    const ServerConfig& config,
    const std::filesystem::path& data_root,
    const std::string& server_fqdn);

} // namespace nexus::core
