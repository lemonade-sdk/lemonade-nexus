#include <LemonadeNexus/Api/AdminApiHandler.hpp>

#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Core/BinaryAttestation.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Network/DdnsService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>

#include <spdlog/spdlog.h>

namespace nexus::api {

using nexus::auth::require_auth;
using nexus::auth::SessionClaims;

void AdminApiHandler::do_register_routes([[maybe_unused]] httplib::Server& pub,
                                         httplib::Server& priv) {
    // POST /api/credentials/request — DDNS credential distribution
    priv.Post("/api/credentials/request", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        auto body_opt = parse_body(req, res);
        if (!body_opt) return;

        auto root_privkey = ctx_.key_wrapping.unlock_identity({});
        auto root_pubkey = ctx_.key_wrapping.load_identity_pubkey();
        if (!root_privkey || !root_pubkey) {
            error_response(res, "root identity not available", 503);
            return;
        }

        auto response = ctx_.ddns.handle_credential_request(*body_opt, *root_privkey, *root_pubkey);
        if (!response) {
            res.status = 403;
            nlohmann::json j = network::CredentialErrorResponse{.success = false, .error = "verification failed"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        res.set_content(*response, "application/json");
    }));

    // GET /api/ddns/status — DDNS status
    priv.Get("/api/ddns/status", require_auth(ctx_.auth,
        [this](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        network::DdnsStatusResponse resp{
            .has_credentials = ctx_.ddns.has_credentials(),
            .last_ip         = ctx_.ddns.last_ip(),
            .binary_hash     = ctx_.attestation.diagnostic_self_hash(),
            .binary_approved = ctx_.attestation.is_approved_binary(ctx_.attestation.diagnostic_self_hash()),
        };
        nlohmann::json j = resp;
        json_response(res, j);
    }));

    // POST /api/ddns/update — Force DDNS update
    priv.Post("/api/ddns/update", require_auth(ctx_.auth,
        [this](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        bool ok = ctx_.ddns.update_now();
        network::DdnsUpdateResponse resp{
            .success = ok,
            .ip      = ctx_.ddns.last_ip(),
        };
        nlohmann::json j = resp;
        json_response(res, j, ok ? 200 : 500);
    }));

    // GET /api/attestation/manifests — List binary attestation manifests
    priv.Get("/api/attestation/manifests", require_auth(ctx_.auth,
        [this](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        auto manifests = ctx_.attestation.get_manifests();
        network::AttestationManifestsResponse resp{
            .self_hash                   = ctx_.attestation.diagnostic_self_hash(),
            .self_approved               = ctx_.attestation.is_approved_binary(ctx_.attestation.diagnostic_self_hash()),
            .github_url                  = ctx_.config.github_releases_url,
            .minimum_version             = ctx_.config.minimum_version,
            .manifest_fetch_interval_sec = ctx_.config.manifest_fetch_interval_sec,
        };
        resp.manifests.reserve(manifests.size());
        for (const auto& m : manifests) {
            resp.manifests.push_back({
                .version       = m.version,
                .platform      = m.platform,
                .binary_sha256 = m.binary_sha256,
                .timestamp     = m.timestamp,
            });
        }
        nlohmann::json j = resp;
        json_response(res, j);
    }));

    // POST /api/attestation/fetch — Trigger GitHub manifest fetch
    priv.Post("/api/attestation/fetch", require_auth(ctx_.auth,
        [this](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        auto count = ctx_.attestation.fetch_github_manifests();
        network::AttestationFetchResponse resp{
            .success         = true,
            .new_manifests   = count,
            .total_manifests = ctx_.attestation.get_manifests().size(),
        };
        nlohmann::json j = resp;
        json_response(res, j);
    }));

}

} // namespace nexus::api
