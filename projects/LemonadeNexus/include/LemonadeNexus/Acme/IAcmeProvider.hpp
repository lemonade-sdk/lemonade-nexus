#pragma once

#include <concepts>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>

namespace nexus::acme {

/// The result of an ACME certificate request or renewal.
struct AcmeResult {
    bool        success{false};
    std::string domain;
    std::string error_message;
    std::string cert_path;
    std::string key_path;
};

/// A PEM certificate bundle with its expiry timestamp.
struct CertBundle {
    std::string fullchain_pem;
    std::string privkey_pem;
    uint64_t    expires_at{0};
};

/// Configuration for an ACME certificate authority provider.
///
/// Use the static factory methods to create pre-configured providers:
///   AcmeProviderConfig::letsencrypt()          — production
///   AcmeProviderConfig::letsencrypt_staging()   — staging (for testing)
///   AcmeProviderConfig::zerossl()               — requires EAB credentials
struct AcmeProviderConfig {
    std::string name;              ///< Display name (e.g., "Let's Encrypt")
    std::string host;              ///< ACME server hostname
    std::string directory_url;     ///< ACME directory URL

    /// External Account Binding (required by ZeroSSL, optional for others)
    std::string eab_kid;           ///< EAB Key ID
    std::string eab_hmac_key;      ///< EAB HMAC key (base64url-encoded)

    /// Whether this config uses a staging/test CA.
    bool staging{false};

    /// Returns true if this provider requires External Account Binding.
    [[nodiscard]] bool requires_eab() const {
        return !eab_kid.empty() && !eab_hmac_key.empty();
    }

    /// Let's Encrypt production.
    static AcmeProviderConfig letsencrypt() {
        return {
            .name          = "Let's Encrypt",
            .host          = "acme-v02.api.letsencrypt.org",
            .directory_url = "https://acme-v02.api.letsencrypt.org/directory",
        };
    }

    /// Let's Encrypt staging (fake certs, for testing).
    static AcmeProviderConfig letsencrypt_staging() {
        return {
            .name          = "Let's Encrypt (Staging)",
            .host          = "acme-staging-v02.api.letsencrypt.org",
            .directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory",
            .staging       = true,
        };
    }

    /// ZeroSSL production (requires EAB credentials).
    /// EAB credentials can be passed directly or read from environment
    /// variables ZEROSSL_EAB_KID and ZEROSSL_EAB_HMAC_KEY.
    static AcmeProviderConfig zerossl(std::string kid = {},
                                       std::string hmac = {}) {
        if (kid.empty()) {
            const char* env = std::getenv("ZEROSSL_EAB_KID");
            if (env && std::strlen(env) > 0) kid = env;
        }
        if (hmac.empty()) {
            const char* env = std::getenv("ZEROSSL_EAB_HMAC_KEY");
            if (env && std::strlen(env) > 0) hmac = env;
        }
        return {
            .name          = "ZeroSSL",
            .host          = "acme.zerossl.com",
            .directory_url = "https://acme.zerossl.com/v2/DV90",
            .eab_kid       = std::move(kid),
            .eab_hmac_key  = std::move(hmac),
        };
    }
};

/// CRTP base for ACME certificate management.
/// Derived must implement:
///   AcmeResult do_request_certificate(const std::string& domain)
///   AcmeResult do_renew_certificate(const std::string& domain)
///   bool do_set_dns_txt_record(const std::string& fqdn, const std::string& value)
///   bool do_remove_dns_txt_record(const std::string& fqdn)
///   std::optional<CertBundle> do_get_certificate(const std::string& domain)
template <typename Derived>
class IAcmeProvider {
public:
    [[nodiscard]] AcmeResult request_certificate(const std::string& domain) {
        return self().do_request_certificate(domain);
    }

    [[nodiscard]] AcmeResult renew_certificate(const std::string& domain) {
        return self().do_renew_certificate(domain);
    }

    [[nodiscard]] bool set_dns_txt_record(const std::string& fqdn,
                                           const std::string& value) {
        return self().do_set_dns_txt_record(fqdn, value);
    }

    [[nodiscard]] bool remove_dns_txt_record(const std::string& fqdn) {
        return self().do_remove_dns_txt_record(fqdn);
    }

    [[nodiscard]] std::optional<CertBundle> get_certificate(const std::string& domain) {
        return self().do_get_certificate(domain);
    }

protected:
    ~IAcmeProvider() = default;

private:
    [[nodiscard]] Derived& self() { return static_cast<Derived&>(*this); }
    [[nodiscard]] const Derived& self() const { return static_cast<const Derived&>(*this); }
};

/// Concept constraining a valid IAcmeProvider implementation.
template <typename T>
concept AcmeProviderType = requires(T t,
                                     const std::string& s) {
    { t.do_request_certificate(s) } -> std::same_as<AcmeResult>;
    { t.do_renew_certificate(s) } -> std::same_as<AcmeResult>;
    { t.do_set_dns_txt_record(s, s) } -> std::same_as<bool>;
    { t.do_remove_dns_txt_record(s) } -> std::same_as<bool>;
    { t.do_get_certificate(s) } -> std::same_as<std::optional<CertBundle>>;
};

} // namespace nexus::acme
