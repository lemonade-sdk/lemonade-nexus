#include <LemonadeNexus/Api/CertApiHandler.hpp>

#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>
#include <LemonadeNexus/Network/HttpServer.hpp>
#include <LemonadeNexus/Acme/AcmeService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>

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
                error_response(res, "not running TLS and no cert/key paths provided");
                return;
            }
            error_response(res, "server is running plain HTTP — restart with TLS cert to enable HTTPS");
            return;
        }

        bool ok = ctx_.http_server.reload_tls_certs(reload_cert, reload_key);
        nlohmann::json resp = {
            {"success",   ok},
            {"cert_path", reload_cert},
            {"key_path",  reload_key},
        };
        json_response(res, resp, ok ? 200 : 500);
    }));

    // POST /api/tls/renew — request ACME cert renewal and hot-reload
    priv.Post("/api/tls/renew", require_auth(ctx_.auth,
        [this](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        if (ctx_.server_fqdn.empty()) {
            error_response(res, "no server FQDN configured — set --server-hostname");
            return;
        }

        auto result = ctx_.acme.renew_certificate(ctx_.server_fqdn);
        if (!result.success) {
            error_response(res, "ACME renewal failed", 502);
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
        json_response(res, resp);
    }));

    // GET /api/certs/{domain} — get certificate status for a domain
    priv.Get(R"(/api/certs/(.+))", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        auto domain = req.matches[1].str();
        auto bundle = ctx_.acme.get_certificate(domain);
        if (!bundle) {
            error_response(res, "certificate not found", 404);
            return;
        }
        network::CertStatusResponse resp{
            .domain     = domain,
            .has_cert   = true,
            .expires_at = bundle->expires_at,
        };
        nlohmann::json j = resp;
        json_response(res, j);
    }));

    // POST /api/certs/issue — issue certificate for client (borrowed license)
    priv.Post("/api/certs/issue", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res, const SessionClaims& claims) {
        auto body_opt = parse_body(req, res);
        if (!body_opt) return;

        auto cert_req = body_opt->get<network::CertIssueRequest>();

        if (cert_req.hostname.empty() || cert_req.client_pubkey.empty()) {
            error_response(res, "hostname and client_pubkey required");
            return;
        }

        for (char c : cert_req.hostname) {
            if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_') {
                error_response(res, "invalid hostname characters");
                return;
            }
        }

        // Validate hostname ownership: the requesting user must own a node
        // with this hostname. Prevents users from requesting certs for
        // "root" or other users' hostnames.
        {
            // Normalize the JWT pubkey to match tree format
            auto caller_pk = normalize_pubkey(claims.pubkey);

            // Check that the caller owns a node with this hostname
            bool owns_hostname = false;
            auto node_id = claims.node_id.empty() ? claims.user_id : claims.node_id;
            if (!node_id.empty()) {
                // Check the user's node and customer group
                for (const auto& check_id : {node_id, std::string("customer-") + node_id}) {
                    auto node = ctx_.tree.get_node(check_id);
                    if (node && node->hostname == cert_req.hostname &&
                        node->mgmt_pubkey == caller_pk) {
                        owns_hostname = true;
                        break;
                    }
                }
            }

            if (!owns_hostname) {
                error_response(res, "hostname ownership required", 403);
                return;
            }
        }

        std::string fqdn = cert_req.hostname + ".capi." + ctx_.config.dns_base_domain;

        auto existing = ctx_.acme.get_certificate(fqdn);
        if (!existing) {
            spdlog::info("[CertIssue] requesting ACME cert for {}", fqdn);
            auto result = ctx_.acme.request_certificate(fqdn);
            if (!result.success) {
                error_response(res, "ACME certificate request failed", 502);
                return;
            }
            existing = ctx_.acme.get_certificate(fqdn);
            if (!existing) {
                error_response(res, "certificate issued but not found in storage", 500);
                return;
            }
        }

        std::string pk_data = cert_req.client_pubkey;
        if (pk_data.starts_with("ed25519:")) {
            pk_data = pk_data.substr(8);
        }
        auto pk_bytes = crypto::from_base64(pk_data);
        if (pk_bytes.size() != crypto::kEd25519PublicKeySize) {
            error_response(res, "invalid client_pubkey size");
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
        json_response(res, j);
    }));
}

} // namespace nexus::api
