#include <LemonadeNexus/Api/AuthApiHandler.hpp>

#include <LemonadeNexus/ACL/Permission.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>
#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/TokenLinkAuthProvider.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>

namespace nexus::api {

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

void AuthApiHandler::do_register_routes(httplib::Server& pub,
                                        httplib::Server& priv) {
    using nexus::auth::require_auth;
    using nexus::auth::SessionClaims;

    // POST /api/auth — authenticate (password, passkey, token-link, or ed25519)
    pub.Post("/api/auth", [this](const httplib::Request& req, httplib::Response& res) {
        auto body = parse_body(req, res);
        if (!body) return;

        auto result = ctx_.auth.authenticate(*body);

        // Authentication never creates, claims, or modifies the application
        // root. Root initialization is deferred to the authority work; an
        // existing root is left untouched by this endpoint.

        network::AuthResponse resp{
            .authenticated = result.authenticated,
            .user_id       = result.user_id,
            .session_token = result.session_token,
            .error         = result.error_message,
        };
        nlohmann::json j = resp;
        json_response(res, j, result.authenticated ? 200 : 401);
    });

    // POST /api/auth/register — passkey / FIDO2 registration
    pub.Post("/api/auth/register", [this](const httplib::Request& req, httplib::Response& res) {
        auto body = parse_body(req, res);
        if (!body) return;

        auto result = ctx_.auth.register_passkey(*body);

        network::AuthResponse resp{
            .authenticated = result.authenticated,
            .user_id       = result.user_id,
            .session_token = result.session_token,
            .error         = result.error_message,
        };
        nlohmann::json j = resp;
        json_response(res, j, result.authenticated ? 200 : 400);
    });

    // POST /api/auth/challenge — issue an Ed25519 challenge nonce, or a
    // WebAuthn assertion challenge ({"type":"passkey","user_id":"..."}) bound
    // to that user. The passkey assertion's clientDataJSON must carry the
    // returned challenge; it expires and is single-use.
    pub.Post("/api/auth/challenge", [this](const httplib::Request& req, httplib::Response& res) {
        auto body = parse_body(req, res);
        if (!body) return;

        if (body->value("type", std::string{}) == "passkey") {
            auto user_id = body->value("user_id", std::string{});
            if (user_id.empty()) {
                error_response(res, "user_id required");
                return;
            }
            // Same bound the provider enforces; checked here so callers get a
            // 400 (bad request) instead of a 503 (capacity) for bad input.
            if (user_id.size() > 128) {
                error_response(res, "user_id too long (max 128)");
                return;
            }

            auto challenge = ctx_.auth.issue_passkey_challenge(user_id);
            if (!challenge) {
                error_response(res, "too many pending passkey challenges", 503);
                return;
            }
            json_response(res, *challenge);
            return;
        }

        auto pubkey = body->value("pubkey", std::string{});
        if (pubkey.empty()) {
            error_response(res, "pubkey required");
            return;
        }

        auto challenge = ctx_.auth.issue_ed25519_challenge(pubkey);
        json_response(res, challenge);
    });

    // No public key-registration endpoint: identities are auto-registered on a
    // successful challenge-response in /api/auth (proof of possession required).

    // POST /api/link/token (PRIVATE, auth required) — mint a single-use device
    // link token; the joining device passes it to /api/join to be placed under
    // the caller's Customer group.
    priv.Post("/api/link/token", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        nlohmann::json body = nlohmann::json::object();
        if (!req.body.empty()) {
            body = nlohmann::json::parse(req.body, nullptr, false);
            if (body.is_discarded()) {
                error_response(res, "invalid JSON body");
                return;
            }
        }

        auto caller_pubkey = normalize_pubkey(claims.pubkey);

        // Resolve the caller's Customer group: parent of their endpoint node,
        // falling back to the group derived from their user id.
        std::string group_id;
        if (auto node = ctx_.tree.get_node(claims.user_id)) {
            if (auto parent = ctx_.tree.get_node(node->parent_id);
                parent && parent->type == tree::NodeType::Customer) {
                group_id = parent->id;
            }
        }
        if (group_id.empty() && ctx_.tree.get_node("customer-" + claims.user_id)) {
            group_id = "customer-" + claims.user_id;
        }
        if (group_id.empty()) {
            error_response(res, "no customer group for caller — join first", 409);
            return;
        }

        if (!ctx_.tree.check_permission(caller_pubkey, group_id,
                                        acl::Permission::AddChild)) {
            error_response(res, "add_child permission required on " + group_id, 403);
            return;
        }

        auto ttl_sec = body.value("ttl_sec",
            static_cast<uint64_t>(auth::TokenLinkAuthProvider::kDefaultTtl.count()));
        auto minted = ctx_.auth.mint_link_token(
            claims.user_id, caller_pubkey, group_id, std::chrono::seconds{ttl_sec});
        if (!minted) {
            error_response(res, "failed to mint link token", 500);
            return;
        }

        nlohmann::json j = {
            {"link_token",    minted->first},
            {"group_node_id", minted->second.group_node_id},
            {"expires_at",    minted->second.expires_at},
        };
        json_response(res, j);
    }));
}

} // namespace nexus::api
