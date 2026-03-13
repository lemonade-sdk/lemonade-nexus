#include <LemonadeNexus/Api/CertApiHandler.hpp>

#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>
#include <LemonadeNexus/Network/HttpServer.hpp>
#include <LemonadeNexus/Acme/AcmeService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>

#include <spdlog/spdlog.h>

#include <cctype>
#include <cstring>

namespace nexus::api {

using nexus::auth::require_auth;
using nexus::auth::SessionClaims;

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

void CertApiHandler::do_register_routes([[maybe_unused]] httplib::Server& pub,
                                        httplib::Server& priv) {
    // POST /api/tls/reload — hot-reload TLS certificates
    priv.Post("/api/tls/reload", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        std::string reload_cert = ctx_.http_server.tls_cert_path();
        std::string reload_key  = ctx_.http_server.tls_key_path();

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (!body.is_discarded()) {
            if (body.contains("cert_path")) reload_cert = body["cert_path"].get<std::string>();
            if (body.contains("key_path"))  reload_key  = body["key_path"].get<std::string>();
        }

        if (!ctx_.http_server.is_tls()) {
            if (reload_cert.empty() || reload_key.empty()) {
                res.status = 400;
                nlohmann::json j = network::ErrorResponse{
                    .error = "not running TLS and no cert/key paths provided"};
                res.set_content(j.dump(), "application/json");
                return;
            }
            res.status = 400;
            nlohmann::json j = network::ErrorResponse{
                .error = "server is running plain HTTP — restart with TLS cert to enable HTTPS"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        bool ok = ctx_.http_server.reload_tls_certs(reload_cert, reload_key);
        nlohmann::json resp = {
            {"success",   ok},
            {"cert_path", reload_cert},
            {"key_path",  reload_key},
        };
        res.status = ok ? 200 : 500;
        res.set_content(resp.dump(), "application/json");
    }));

    // POST /api/tls/renew — request ACME cert renewal and hot-reload
    priv.Post("/api/tls/renew", require_auth(ctx_.auth,
        [this](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        if (ctx_.server_fqdn.empty()) {
            res.status = 400;
            nlohmann::json j = network::ErrorResponse{
                .error = "no server FQDN configured — set --server-hostname"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        auto result = ctx_.acme.renew_certificate(ctx_.server_fqdn);
        if (!result.success) {
            res.status = 502;
            nlohmann::json j = network::ErrorResponse{
                .error  = "ACME renewal failed",
                .detail = result.error_message,
            };
            res.set_content(j.dump(), "application/json");
            return;
        }

        bool reloaded = false;
        if (ctx_.http_server.is_tls() && !result.cert_path.empty() && !result.key_path.empty()) {
            reloaded = ctx_.http_server.reload_tls_certs(result.cert_path, result.key_path);
        }

        nlohmann::json resp = {
            {"success",      true},
            {"domain",       ctx_.server_fqdn},
            {"cert_path",    result.cert_path},
            {"key_path",     result.key_path},
            {"hot_reloaded", reloaded},
        };
        res.set_content(resp.dump(), "application/json");
    }));

    // GET /api/certs/{domain} — get certificate status for a domain
    priv.Get(R"(/api/certs/(.+))", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        auto domain = req.matches[1].str();
        auto bundle = ctx_.acme.get_certificate(domain);
        if (!bundle) {
            res.status = 404;
            nlohmann::json j = network::ErrorResponse{.error = "certificate not found"};
            res.set_content(j.dump(), "application/json");
            return;
        }
        network::CertStatusResponse resp{
            .domain     = domain,
            .has_cert   = true,
            .expires_at = bundle->expires_at,
        };
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // POST /api/certs/issue — issue certificate for client (borrowed license)
    priv.Post("/api/certs/issue", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            nlohmann::json j = network::ErrorResponse{.error = "invalid json"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        auto cert_req = body.get<network::CertIssueRequest>();

        if (cert_req.hostname.empty() || cert_req.client_pubkey.empty()) {
            res.status = 400;
            nlohmann::json j = network::ErrorResponse{.error = "hostname and client_pubkey required"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        for (char c : cert_req.hostname) {
            if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_') {
                res.status = 400;
                nlohmann::json j = network::ErrorResponse{.error = "invalid hostname characters"};
                res.set_content(j.dump(), "application/json");
                return;
            }
        }

        std::string fqdn = cert_req.hostname + ".capi." + ctx_.config.dns_base_domain;

        auto existing = ctx_.acme.get_certificate(fqdn);
        if (!existing) {
            spdlog::info("[CertIssue] requesting ACME cert for {}", fqdn);
            auto result = ctx_.acme.request_certificate(fqdn);
            if (!result.success) {
                res.status = 502;
                nlohmann::json j = network::ErrorResponse{
                    .error  = "ACME certificate request failed",
                    .detail = result.error_message,
                };
                res.set_content(j.dump(), "application/json");
                return;
            }
            existing = ctx_.acme.get_certificate(fqdn);
            if (!existing) {
                res.status = 500;
                nlohmann::json j = network::ErrorResponse{.error = "certificate issued but not found in storage"};
                res.set_content(j.dump(), "application/json");
                return;
            }
        }

        std::string pk_data = cert_req.client_pubkey;
        if (pk_data.starts_with("ed25519:")) {
            pk_data = pk_data.substr(8);
        }
        auto pk_bytes = crypto::from_base64(pk_data);
        if (pk_bytes.size() != crypto::kEd25519PublicKeySize) {
            res.status = 400;
            nlohmann::json j = network::ErrorResponse{.error = "invalid client_pubkey size"};
            res.set_content(j.dump(), "application/json");
            return;
        }
        crypto::Ed25519PublicKey client_ed_pk{};
        std::memcpy(client_ed_pk.data(), pk_bytes.data(), pk_bytes.size());

        auto client_x_pk = crypto::SodiumCryptoService::ed25519_pk_to_x25519(client_ed_pk);
        auto ephemeral = ctx_.crypto.x25519_keygen();

        auto shared_secret = ctx_.crypto.x25519_dh(ephemeral.private_key, client_x_pk);

        const std::string info_str = "lemonade-nexus-cert-issue";
        auto enc_key = ctx_.crypto.hkdf_sha256(shared_secret, {},
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(info_str.data()), info_str.size()), 32);
        crypto::AesGcmKey aes_key{};
        std::memcpy(aes_key.data(), enc_key.data(), std::min(enc_key.size(), aes_key.size()));

        auto privkey_bytes = std::vector<uint8_t>(
            existing->privkey_pem.begin(), existing->privkey_pem.end());
        auto encrypted = ctx_.crypto.aes_gcm_encrypt(aes_key, privkey_bytes, {});

        network::CertIssueResponse resp{
            .domain            = fqdn,
            .fullchain_pem     = existing->fullchain_pem,
            .encrypted_privkey = crypto::to_base64(encrypted.ciphertext),
            .nonce             = crypto::to_base64(encrypted.nonce),
            .ephemeral_pubkey  = crypto::to_base64(ephemeral.public_key),
            .expires_at        = existing->expires_at,
        };
        spdlog::info("[CertIssue] issued cert for {} to client {}", fqdn, cert_req.client_pubkey.substr(0, 16));
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));
}

} // namespace nexus::api
