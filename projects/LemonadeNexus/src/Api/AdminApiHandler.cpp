#include <LemonadeNexus/Api/AdminApiHandler.hpp>

#include <LemonadeNexus/ACL/Permission.hpp>
#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Core/BinaryAttestation.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Network/DdnsService.hpp>
#include <LemonadeNexus/Security/Storage/StorageVault.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>

#include <spdlog/spdlog.h>

namespace nexus::api {

using nexus::auth::require_auth;
using nexus::auth::SessionClaims;

void AdminApiHandler::do_register_routes([[maybe_unused]] httplib::Server& pub,
                                         httplib::Server& priv) {
    // GET /api/storage/status and POST /api/storage/rotate-data-key — files
    // under the data key (Phase 7). Root admin only: a valid JWT alone is not
    // enough. The rotation runs in the background; the request only records
    // it (durably) for the next tick that can run it.
    const auto storage_admin = [this](const SessionClaims& claims, httplib::Response& res) {
        if (ctx_.storage_vault == nullptr) {
            error_response(res, "storage files are not enabled", 404);
            return false;
        }
        if (!ctx_.tree.check_permission(normalize_pubkey(claims.pubkey), "root",
                                         acl::Permission::Admin)) {
            error_response(res, "admin authorization required", 403);
            return false;
        }
        return true;
    };
    const auto storage_status = [this] {
        const auto& vault = *ctx_.storage_vault;
        return nlohmann::json{
            {"mode", std::string(security::vault_mode_name(vault.mode()))},
            {"phase", std::string(security::vault_phase_name(vault.phase()))},
            {"files_ready", vault.files_ready()},
            {"last_rotation_ms", vault.last_rotation_ms()},
            {"rotation_requested", vault.rotation_requested()},
        };
    };
    priv.Get("/api/storage/status", require_auth(ctx_.auth,
        [storage_admin, storage_status](const httplib::Request&, httplib::Response& res,
                                        const SessionClaims& claims) {
        if (!storage_admin(claims, res)) return;
        json_response(res, storage_status());
    }));
    priv.Post("/api/storage/rotate-data-key", require_auth(ctx_.auth,
        [this, storage_admin, storage_status](const httplib::Request&, httplib::Response& res,
                                              const SessionClaims& claims) {
        if (!storage_admin(claims, res)) return;
        if (!ctx_.storage_vault->request_rotation()) {
            error_response(res, "the files are not migrated yet, or the request was not saved",
                           409);
            return;
        }
        spdlog::info("[storage] data key rotation requested by an administrator");
        auto j = storage_status();
        j["success"] = true;
        json_response(res, j);
    }));

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

    // GET /api/dns/sync — DNS catch-up state: Tier 1 status, per-origin
    // summaries, and each Tier 1 peer's backbone readiness and sync status
    priv.Get("/api/dns/sync", require_auth(ctx_.auth,
        [this](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        json_response(res, ctx_.gossip.dns_sync_status());
    }));

    // GET /api/account/sync — account envelope replication state, in the same
    // shape as /api/dns/sync
    priv.Get("/api/account/sync", require_auth(ctx_.auth,
        [this](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        json_response(res, ctx_.gossip.account_sync_status());
    }));

    // GET /api/link/sync — link token (invite) replication state between Tier
    // 1 servers, in the same shape as /api/dns/sync
    priv.Get("/api/link/sync", require_auth(ctx_.auth,
        [this](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        json_response(res, ctx_.gossip.link_sync_status());
    }));

    // GET /api/tree/sync — tree log state (mode, height, state root, halt
    // reason, last refused entry) and its replication status per peer
    priv.Get("/api/tree/sync", require_auth(ctx_.auth,
        [this](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        if (!ctx_.tree_log_status) {
            error_response(res, "the tree log is not enabled on this server", 404);
            return;
        }
        json_response(res, ctx_.tree_log_status());
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

    // POST /api/credentials/unrevoke — Operator un-revoke of a revoked Ed25519
    // key. Root-admin only: a valid JWT alone is not enough.
    priv.Post("/api/credentials/unrevoke", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res, const SessionClaims& claims) {
        if (!ctx_.tree.check_permission(normalize_pubkey(claims.pubkey), "root",
                                         acl::Permission::Admin)) {
            error_response(res, "admin authorization required", 403);
            return;
        }

        auto body_opt = parse_body(req, res);
        if (!body_opt || !body_opt->is_object()) {
            error_response(res, "body must be a JSON object");
            return;
        }

        auto pubkey = body_opt->value("pubkey", std::string{});
        if (pubkey.empty()) {
            error_response(res, "pubkey is required");
            return;
        }

        if (!ctx_.auth.unrevoke_ed25519(pubkey)) {
            error_response(res, "pubkey was not revoked", 400);
            return;
        }
        nlohmann::json j{{"success", true}};
        json_response(res, j);
    }));

}

} // namespace nexus::api
