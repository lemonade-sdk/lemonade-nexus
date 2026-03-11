#pragma once

#include <LemonadeNexus/Core/BinaryAttestation.hpp>
#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <asio.hpp>
#include <nlohmann/json.hpp>

#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace nexus::network {

/// Configuration for the Dynamic DNS provider.
struct DdnsConfig {
    std::string provider{"namecheap"};     // "namecheap" (extensible for future providers)
    std::string domain;                     // Base domain, e.g. "example.com"
    std::string ddns_password;              // Namecheap DDNS password
    uint32_t    update_interval_sec{300};   // How often to check/update (default 5 min)
    bool        enabled{false};
};

void to_json(nlohmann::json& j, const DdnsConfig& c);
void from_json(const nlohmann::json& j, DdnsConfig& c);

/// Dynamic DNS service for Namecheap.
///
/// Allows verified servers to dynamically register their public IPs in DNS.
/// Only servers that pass BOTH certificate AND binary attestation checks can
/// receive the DDNS credentials via the encrypted credential distribution protocol.
///
/// Flow:
/// 1. Root server holds DDNS credentials (encrypted at rest)
/// 2. Verified server requests credentials via POST /api/credentials/request
/// 3. Root verifies: server certificate + binary hash in approved manifest
/// 4. Root encrypts credentials via X25519 key exchange + AES-256-GCM
/// 5. Server decrypts, stores encrypted locally, makes DDNS API calls
///
/// Namecheap DDNS API:
///   GET https://dynamicdns.park-your-domain.com/update
///       ?host={subdomain}&domain={base_domain}&password={ddns_password}&ip={public_ip}
class DdnsService : public core::IService<DdnsService> {
    friend class core::IService<DdnsService>;

public:
    DdnsService(asio::io_context& io,
                crypto::SodiumCryptoService& crypto,
                storage::FileStorageService& storage,
                core::BinaryAttestationService& attestation,
                gossip::GossipService& gossip);

    /// Set TrustPolicy for tier enforcement on credential distribution.
    void set_trust_policy(core::TrustPolicyService* policy);

    /// Set DDNS credentials directly (root server config, or after decryption).
    void set_credentials(const DdnsConfig& config);

    /// Set our hostname (subdomain) for DDNS registration.
    /// Typically derived from the server certificate's server_id.
    void set_hostname(const std::string& hostname);

    /// Request encrypted DDNS credentials from a root server.
    /// Called by non-root servers after startup.
    /// @param root_http_endpoint  "host:port" of the root server's HTTP API
    /// @param our_privkey         our server's Ed25519 private key (for X25519 DH)
    /// @param our_cert_json       our server certificate JSON (for identity proof)
    /// @return true if credentials were received and stored
    bool request_credentials(const std::string& root_http_endpoint,
                             const crypto::Ed25519PrivateKey& our_privkey,
                             const std::string& our_cert_json);

    /// Handle a credential request from another server (called on root server).
    /// Verifies the requesting server's certificate and binary hash, then
    /// encrypts and returns the DDNS credentials.
    /// @param request       JSON body from POST /api/credentials/request
    /// @param root_privkey  root server's Ed25519 private key (for X25519 DH)
    /// @param root_pubkey   root server's Ed25519 public key
    /// @return encrypted credentials JSON string, or nullopt if verification fails
    [[nodiscard]] std::optional<std::string> handle_credential_request(
        const nlohmann::json& request,
        const crypto::Ed25519PrivateKey& root_privkey,
        const crypto::Ed25519PublicKey& root_pubkey);

    /// Force an immediate DDNS update.
    bool update_now();

    /// Get last known public IP.
    [[nodiscard]] std::string last_ip() const;

    /// Check if we have valid DDNS credentials.
    [[nodiscard]] bool has_credentials() const;

private:
    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "DdnsService"; }

    /// Execute a Namecheap DDNS update for the given host and IP.
    bool do_namecheap_update(const std::string& host, const std::string& ip);

    /// Detect our public IP using multiple external services (consensus-based).
    [[nodiscard]] std::string detect_public_ip();

    /// Query a single IP detection service.
    [[nodiscard]] std::string query_ip_service(const std::string& host,
                                                const std::string& path);

    /// Timer-based periodic DDNS update check.
    void start_update_timer();
    void on_update_tick();

    /// Save DDNS credentials encrypted at rest using our server identity key.
    bool save_encrypted_credentials();

    /// Load DDNS credentials from encrypted storage.
    bool load_encrypted_credentials();

    asio::io_context& io_;
    asio::steady_timer update_timer_;
    crypto::SodiumCryptoService& crypto_;
    storage::FileStorageService& storage_;
    core::BinaryAttestationService& attestation_;
    gossip::GossipService& gossip_;

    DdnsConfig  config_;
    std::string our_hostname_;       // subdomain for this server
    std::string last_known_ip_;
    bool        has_credentials_{false};
    bool        timer_running_{false};
    mutable std::mutex mutex_;

    // Zero-trust enforcement (nullptr = trust checks disabled)
    core::TrustPolicyService* trust_policy_{nullptr};
};

} // namespace nexus::network
