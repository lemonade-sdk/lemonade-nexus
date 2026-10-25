#pragma once

#include <LemonadeNexus/Core/IService.hpp>

#include <httplib.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>

namespace nexus::network {

/// HTTP/HTTPS server for the control plane (auth, ACL, coordination endpoints).
/// Wraps cpp-httplib and runs in its own thread.
///
/// Supports two modes:
///   1. Plain HTTP (no TLS cert provided) — uses httplib::Server
///   2. HTTPS (TLS cert + key provided)   — uses httplib::SSLServer
///
/// The server can be constructed initially as plain HTTP and upgraded to HTTPS
/// later (e.g., after ACME issues a certificate) via upgrade_to_tls().
/// Hot-reload of certificates on a running HTTPS server is supported via
/// reload_tls_certs().
class HttpServer : public core::IService<HttpServer> {
    friend class core::IService<HttpServer>;
public:
    /// Construct a plain HTTP server.
    explicit HttpServer(uint16_t port, std::string bind_address = "0.0.0.0");

    /// Upgrade this (plain) HTTP server to HTTPS from cert/key file paths.
    /// No-op (returns false) when already TLS or the cert/key won't load.
    /// After a successful upgrade the caller must re-register routes and
    /// (re)start the server.
    bool enable_tls_from_paths(const std::string& tls_cert_path, const std::string& tls_key_path);

    /// Upgrade this (plain) HTTP server to HTTPS from a cert file path plus an
    /// in-memory PEM private key (Phase 7). Used when the private key is a
    /// vault-covered file decrypted into memory. No-op (returns false) when the
    /// server is already TLS or the key is empty (e.g. still vault-locked). The
    /// public cert is opened from its path. After a successful upgrade the
    /// caller must re-register routes and (re)start the server.
    bool enable_tls_inmemory_key(const std::string& tls_cert_path, const std::string& key_pem,
                                 const std::string& key_path);

    ~HttpServer();

    // Non-copyable, non-movable (owns server + thread)
    HttpServer(const HttpServer&) = delete;
    HttpServer& operator=(const HttpServer&) = delete;
    HttpServer(HttpServer&&) = delete;
    HttpServer& operator=(HttpServer&&) = delete;

    /// Set the bind address (must be called before start()).
    void set_bind_address(const std::string& addr) { bind_address_ = addr; }

    /// Access the underlying httplib::Server to register routes before starting.
    /// This works for both plain Server and SSLServer (SSLServer inherits from Server).
    [[nodiscard]] httplib::Server& server();

    /// Returns true if this server is configured for HTTPS.
    [[nodiscard]] bool is_tls() const { return is_tls_; }

    /// Returns the TLS certificate path (empty if not TLS).
    [[nodiscard]] const std::string& tls_cert_path() const { return tls_cert_path_; }

    /// Returns the TLS key path (empty if not TLS).
    [[nodiscard]] const std::string& tls_key_path() const { return tls_key_path_; }

    /// Upgrade a running plain HTTP server to HTTPS.
    /// This stops the current server, creates an SSLServer with the given cert/key,
    /// re-registers all routes (the caller must re-register routes after calling this
    /// since the underlying server object changes), then restarts.
    ///
    /// Returns true if the upgrade succeeded; false if cert/key don't exist or SSLServer
    /// creation failed (the server continues running as plain HTTP in that case).
    ///
    /// IMPORTANT: The caller must stop the server, call this, re-register routes, then start again.
    bool upgrade_to_tls(const std::string& cert_path, const std::string& key_path);

    /// Hot-reload TLS certificates on a running HTTPS server.
    /// Uses httplib::SSLServer::update_certs() to atomically swap certs
    /// without stopping the server.
    /// Returns true if reload succeeded; false if not running TLS or certs failed to load.
    bool reload_tls_certs();

    /// Hot-reload TLS certificates from specific file paths.
    bool reload_tls_certs(const std::string& cert_path, const std::string& key_path);

    /// Hot-reload from a certificate file path plus an in-memory PEM private
    /// key (Phase 7: the key file is vault-covered, so its bytes on disk are
    /// DEK ciphertext). `key_path` is recorded for logging only. Returns false,
    /// and keeps the current certificate, when the server is not TLS, the key
    /// is empty or does not parse, or the key does not match the certificate.
    bool reload_tls_certs_inmemory_key(const std::string& cert_path, const std::string& key_pem,
                                       const std::string& key_path);

    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "HttpServer"; }

private:
    /// Try to create an SSLServer from cert/key paths. Returns nullptr on failure.
    static std::unique_ptr<httplib::SSLServer> try_create_ssl_server(
        const std::string& cert_path, const std::string& key_path);

    /// Try to create an SSLServer from a cert file path (public, opened from
    /// disk) plus an in-memory PEM private key (vault-covered, decrypted into
    /// memory). Returns nullptr on failure.
    static std::unique_ptr<httplib::SSLServer> try_create_ssl_server_inmemory_key(
        const std::string& cert_path, const std::string& key_pem);

    /// Load X509 cert and EVP_PKEY from PEM files for hot-reload.
    /// Returns {cert, key} pair; both are nullptr on failure. Caller must free.
    struct CertKeyPair {
        X509* cert{nullptr};
        EVP_PKEY* key{nullptr};
    };
    static CertKeyPair load_cert_key(const std::string& cert_path,
                                      const std::string& key_path);

    std::unique_ptr<httplib::Server> server_;
    uint16_t        port_;
    std::string     bind_address_;
    std::string     tls_cert_path_;
    std::string     tls_key_path_;
    bool            is_tls_{false};
    std::thread     listen_thread_;
    std::mutex      mutex_;
};

} // namespace nexus::network
