#pragma once

#include <LemonadeNexus/Acme/IAcmeProvider.hpp>
#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <cstdint>
#include <filesystem>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::network { class DnsService; }

namespace nexus::acme {

/// ACME certificate management service (RFC 8555).
///
/// Implements a full ACME client supporting:
///   - ECDSA P-256 account key generation and registration
///   - JWS (RFC 7515) request signing with ES256
///   - DNS-01 challenge validation via local authoritative DNS (gossip-synced)
///   - CSR generation, order finalization, certificate download
///   - File-based storage of certificates under data/certs/<domain>/
///
/// DNS-01 challenges are served by the local DnsService and propagated to all
/// Tier 1 nameservers via gossip. Cloudflare fallback is retained if configured.
class AcmeService : public core::IService<AcmeService>,
                     public IAcmeProvider<AcmeService> {
    friend class core::IService<AcmeService>;
    friend class IAcmeProvider<AcmeService>;

public:
    /// Construct with storage backend, ACME provider config, and DNS provider.
    /// @param storage         File storage service for cert persistence
    /// @param provider_config ACME CA provider configuration
    /// @param dns_provider    DNS provider identifier (default: "local")
    AcmeService(storage::FileStorageService& storage,
                AcmeProviderConfig provider_config = AcmeProviderConfig::letsencrypt(),
                std::string dns_provider = "local");

    /// Set the local DNS service for DNS-01 challenge management.
    /// When set and dns_provider is "local", ACME challenges are served
    /// directly by the DnsService and gossip-synced to all Tier 1 peers.
    void set_dns_service(network::DnsService* dns);

    /// Destructor — frees the OpenSSL account key.
    ~AcmeService();

    // Non-copyable, non-movable (owns raw EVP_PKEY*)
    AcmeService(const AcmeService&) = delete;
    AcmeService& operator=(const AcmeService&) = delete;
    AcmeService(AcmeService&&) = delete;
    AcmeService& operator=(AcmeService&&) = delete;

    // IService
    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "AcmeService"; }

    // IAcmeProvider
    [[nodiscard]] AcmeResult do_request_certificate(const std::string& domain);
    [[nodiscard]] AcmeResult do_renew_certificate(const std::string& domain);
    [[nodiscard]] bool do_set_dns_txt_record(const std::string& fqdn,
                                              const std::string& value);
    [[nodiscard]] bool do_remove_dns_txt_record(const std::string& fqdn);
    [[nodiscard]] std::optional<CertBundle> do_get_certificate(const std::string& domain);

private:
    // -----------------------------------------------------------------------
    // ACME protocol helpers
    // -----------------------------------------------------------------------

    /// Fetch the ACME directory JSON and cache endpoint URLs.
    bool get_directory();

    /// Create or load the ACME account key (ECDSA P-256).
    /// Returns true if the key is ready for use.
    bool ensure_account_key();

    /// Register a new account with the ACME server, or confirm existing.
    /// Sets account_url_ on success. Includes EAB if provider requires it.
    bool create_account();

    /// Build External Account Binding JWS for providers that require it
    /// (e.g., ZeroSSL). Returns the EAB JSON object, or nullopt on failure.
    [[nodiscard]] std::optional<nlohmann::json> build_eab_jws();

    /// Build a JWS (JSON Web Signature) for an ACME request.
    /// @param url     The ACME endpoint URL
    /// @param payload The JSON payload (empty string for POST-as-GET)
    /// @return        The flattened JWS JSON, or empty string on failure
    [[nodiscard]] std::string sign_jws(const std::string& url,
                                        const std::string& payload);

    /// Get a fresh anti-replay nonce from the ACME server.
    [[nodiscard]] std::string get_nonce();

    /// Compute the JWK thumbprint of the account key (SHA-256, base64url).
    [[nodiscard]] std::string compute_thumbprint() const;

    /// Compute the key authorization digest for DNS-01:
    /// base64url(SHA256(token + "." + thumbprint))
    [[nodiscard]] std::string compute_key_authorization_digest(
        const std::string& token) const;

    /// Poll an order or authorization URL until it reaches a terminal state.
    /// @param url          The URL to poll
    /// @param target_status The desired status (e.g. "valid", "ready")
    /// @param max_attempts Maximum number of poll attempts
    /// @param delay_secs   Seconds between poll attempts
    /// @return             The final JSON response, or nullopt on timeout/error
    [[nodiscard]] std::optional<nlohmann::json> poll_until(
        const std::string& url,
        const std::string& target_status,
        int max_attempts = 30,
        int delay_secs = 2);

    /// Generate an ECDSA P-256 key and create a DER-encoded CSR for the domain.
    /// @param domain       The domain name for the CSR
    /// @param out_privkey  Receives the PEM-encoded private key
    /// @return             DER-encoded CSR bytes, or empty on failure
    [[nodiscard]] std::vector<uint8_t> create_csr(const std::string& domain,
                                                    std::string& out_privkey);

    /// Send a signed POST request to an ACME endpoint.
    /// @param url     The endpoint URL
    /// @param payload The JSON payload string
    /// @return        The response, or nullopt on network error
    struct AcmeResponse {
        int status{0};
        std::string body;
        std::string location;    // Location header if present
        std::string replay_nonce; // Replay-Nonce header if present
    };
    [[nodiscard]] std::optional<AcmeResponse> acme_post(const std::string& url,
                                                         const std::string& payload);

    /// Send a signed POST-as-GET request (empty payload).
    [[nodiscard]] std::optional<AcmeResponse> acme_post_as_get(const std::string& url);

    // -----------------------------------------------------------------------
    // DNS challenge helpers
    // -----------------------------------------------------------------------

    // Non-locking DNS operations (called from within do_request_certificate
    // which already holds mutex_)
    bool set_dns_txt_record_unlocked(const std::string& fqdn, const std::string& value);
    bool remove_dns_txt_record_unlocked(const std::string& fqdn);

    // Local DNS (via DnsService + gossip sync)
    bool set_local_dns_txt(const std::string& fqdn, const std::string& value);
    bool remove_local_dns_txt(const std::string& fqdn);

    // Cloudflare DNS API fallback

    /// Validate a domain string contains only safe characters.
    [[nodiscard]] static bool is_valid_domain(const std::string& domain);

    /// Extract the base domain from an FQDN for zone lookup.
    /// e.g. "_acme-challenge.sub.example.com" -> "example.com"
    [[nodiscard]] static std::string extract_base_domain(const std::string& fqdn);

    /// Get the Cloudflare zone ID for a domain.
    [[nodiscard]] std::string cf_get_zone_id(const std::string& domain);

    /// Create a TXT DNS record via Cloudflare API.
    /// Returns the record ID on success, empty string on failure.
    [[nodiscard]] std::string cf_create_txt_record(const std::string& zone_id,
                                                     const std::string& fqdn,
                                                     const std::string& value);

    /// Delete a DNS record via Cloudflare API.
    bool cf_delete_record(const std::string& zone_id,
                           const std::string& record_id);

    // -----------------------------------------------------------------------
    // Base64url encoding
    // -----------------------------------------------------------------------

    /// Encode raw bytes to base64url (no padding).
    [[nodiscard]] static std::string base64url_encode(
        const std::vector<uint8_t>& data);
    [[nodiscard]] static std::string base64url_encode(
        const uint8_t* data, std::size_t len);
    [[nodiscard]] static std::string base64url_encode(const std::string& data);

    // -----------------------------------------------------------------------
    // File and cert helpers
    // -----------------------------------------------------------------------

    /// Scan data/certs/ for existing certificate directories and log status.
    void scan_existing_certs();

    /// Read a raw file from disk and return its contents.
    [[nodiscard]] std::string read_raw_file(const std::filesystem::path& path) const;

    /// Write raw content to a file, creating directories as needed.
    bool write_raw_file(const std::filesystem::path& path,
                         const std::string& content) const;

    /// Parse the expiry (Not After) from a PEM certificate chain.
    /// Returns Unix timestamp, or 0 on failure.
    [[nodiscard]] static uint64_t parse_cert_expiry(const std::string& pem);

    /// Extract the path component from a full URL.
    [[nodiscard]] static std::string url_path(const std::string& url);

    /// Extract host from a full URL.
    [[nodiscard]] static std::string url_host(const std::string& url);

    // -----------------------------------------------------------------------
    // Members
    // -----------------------------------------------------------------------

    storage::FileStorageService& storage_;
    std::string                  dns_provider_;
    AcmeProviderConfig           provider_config_;
    std::mutex                   mutex_;

    // Local authoritative DNS service (nullptr = use Cloudflare fallback)
    network::DnsService*         dns_service_{nullptr};

    // ACME directory endpoints (populated by get_directory)
    std::string new_nonce_url_;
    std::string new_account_url_;
    std::string new_order_url_;

    // Account state
    std::filesystem::path account_key_path_;
    std::string           account_url_;    // Set after registration (kid)
    EVP_PKEY*             account_key_{nullptr};

    // Current nonce for anti-replay
    std::string current_nonce_;

    // Cloudflare: track created record IDs for cleanup
    // Maps FQDN -> {zone_id, record_id}
    struct DnsRecordInfo {
        std::string zone_id;
        std::string record_id;
    };
    std::map<std::string, DnsRecordInfo> dns_records_;
};

} // namespace nexus::acme
