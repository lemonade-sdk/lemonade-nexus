#include <LemonadeNexus/Network/HttpServer.hpp>

#include <spdlog/spdlog.h>

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <filesystem>
#include <utility>

namespace nexus::network {

// ---------------------------------------------------------------------------
// Constructors / Destructor
// ---------------------------------------------------------------------------

HttpServer::HttpServer(uint16_t port, std::string bind_address)
    : server_{std::make_unique<httplib::Server>()}
    , port_{port}
    , bind_address_{std::move(bind_address)}
{
}

HttpServer::HttpServer(uint16_t port, std::string bind_address,
                       const std::string& tls_cert_path,
                       const std::string& tls_key_path)
    : port_{port}
    , bind_address_{std::move(bind_address)}
{
    if (!tls_cert_path.empty() && !tls_key_path.empty()) {
        auto ssl_server = try_create_ssl_server(tls_cert_path, tls_key_path);
        if (ssl_server) {
            server_ = std::move(ssl_server);
            tls_cert_path_ = tls_cert_path;
            tls_key_path_ = tls_key_path;
            is_tls_ = true;
            spdlog::info("HttpServer: TLS enabled (cert={}, key={})",
                          tls_cert_path, tls_key_path);
        } else {
            spdlog::warn("HttpServer: TLS cert/key failed to load, falling back to plain HTTP");
            server_ = std::make_unique<httplib::Server>();
        }
    } else {
        server_ = std::make_unique<httplib::Server>();
    }
}

HttpServer::~HttpServer() = default;

// ---------------------------------------------------------------------------
// Server access
// ---------------------------------------------------------------------------

httplib::Server& HttpServer::server() {
    return *server_;
}

// ---------------------------------------------------------------------------
// TLS upgrade (stop -> swap -> restart)
// ---------------------------------------------------------------------------

bool HttpServer::upgrade_to_tls(const std::string& cert_path,
                                 const std::string& key_path) {
    std::lock_guard lock(mutex_);

    auto ssl_server = try_create_ssl_server(cert_path, key_path);
    if (!ssl_server) {
        spdlog::warn("HttpServer: TLS upgrade failed — cert/key not usable");
        return false;
    }

    // Replace the underlying server object.
    // IMPORTANT: this invalidates all registered routes on the old server.
    // The caller must re-register routes on the new server() after this call.
    server_ = std::move(ssl_server);
    tls_cert_path_ = cert_path;
    tls_key_path_ = key_path;
    is_tls_ = true;

    spdlog::info("HttpServer: upgraded to HTTPS (cert={}, key={})",
                  cert_path, key_path);
    return true;
}

// ---------------------------------------------------------------------------
// TLS hot-reload
// ---------------------------------------------------------------------------

bool HttpServer::reload_tls_certs() {
    return reload_tls_certs(tls_cert_path_, tls_key_path_);
}

bool HttpServer::reload_tls_certs(const std::string& cert_path,
                                    const std::string& key_path) {
    std::lock_guard lock(mutex_);

    if (!is_tls_) {
        spdlog::warn("HttpServer: cannot reload certs — not running in TLS mode");
        return false;
    }

    auto [cert, pkey] = load_cert_key(cert_path, key_path);
    if (!cert || !pkey) {
        spdlog::error("HttpServer: failed to load cert/key for hot-reload");
        return false;
    }

    // SSLServer inherits from Server; downcast is safe because is_tls_ is true.
    auto* ssl_srv = static_cast<httplib::SSLServer*>(server_.get());
    ssl_srv->update_certs(cert, pkey);

    // update_certs takes ownership via SSL_CTX_use_certificate / SSL_CTX_use_PrivateKey
    // which copy the cert/key into the SSL_CTX, so we must free our copies.
    X509_free(cert);
    EVP_PKEY_free(pkey);

    tls_cert_path_ = cert_path;
    tls_key_path_ = key_path;

    spdlog::info("HttpServer: TLS certificates hot-reloaded (cert={}, key={})",
                  cert_path, key_path);
    return true;
}

// ---------------------------------------------------------------------------
// Service lifecycle
// ---------------------------------------------------------------------------

void HttpServer::on_start() {
    server_->set_address_family(AF_INET);
    server_->set_socket_options([](socket_t sock) {
        int yes = 1;
        setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    });
    listen_thread_ = std::thread([this]() {
        if (is_tls_) {
            spdlog::info("HttpServer (HTTPS) listening on {}:{}", bind_address_, port_);
        } else {
            spdlog::info("HttpServer (HTTP) listening on {}:{}", bind_address_, port_);
        }
        server_->listen(bind_address_, port_);
    });
}

void HttpServer::on_stop() {
    server_->stop();
    if (listen_thread_.joinable()) {
        listen_thread_.join();
    }
    spdlog::info("HttpServer stopped (was {}:{})", bind_address_, port_);
}

// ---------------------------------------------------------------------------
// SSL helpers
// ---------------------------------------------------------------------------

std::unique_ptr<httplib::SSLServer> HttpServer::try_create_ssl_server(
    const std::string& cert_path, const std::string& key_path)
{
    if (!std::filesystem::exists(cert_path)) {
        spdlog::warn("HttpServer: TLS cert file not found: {}", cert_path);
        return nullptr;
    }
    if (!std::filesystem::exists(key_path)) {
        spdlog::warn("HttpServer: TLS key file not found: {}", key_path);
        return nullptr;
    }

    try {
        auto srv = std::make_unique<httplib::SSLServer>(
            cert_path.c_str(), key_path.c_str());
        if (!srv->is_valid()) {
            spdlog::error("HttpServer: SSLServer creation failed (invalid cert/key)");
            return nullptr;
        }
        return srv;
    } catch (const std::exception& e) {
        spdlog::error("HttpServer: SSLServer creation exception: {}", e.what());
        return nullptr;
    }
}

HttpServer::CertKeyPair HttpServer::load_cert_key(
    const std::string& cert_path, const std::string& key_path)
{
    CertKeyPair result;

    // Load certificate
    FILE* cert_fp = std::fopen(cert_path.c_str(), "r");
    if (!cert_fp) {
        spdlog::error("HttpServer: cannot open cert file: {}", cert_path);
        return result;
    }
    result.cert = PEM_read_X509(cert_fp, nullptr, nullptr, nullptr);
    std::fclose(cert_fp);
    if (!result.cert) {
        spdlog::error("HttpServer: failed to parse X509 cert from: {}", cert_path);
        return result;
    }

    // Load private key
    FILE* key_fp = std::fopen(key_path.c_str(), "r");
    if (!key_fp) {
        spdlog::error("HttpServer: cannot open key file: {}", key_path);
        X509_free(result.cert);
        result.cert = nullptr;
        return result;
    }
    result.key = PEM_read_PrivateKey(key_fp, nullptr, nullptr, nullptr);
    std::fclose(key_fp);
    if (!result.key) {
        spdlog::error("HttpServer: failed to parse private key from: {}", key_path);
        X509_free(result.cert);
        result.cert = nullptr;
        return result;
    }

    return result;
}

} // namespace nexus::network
