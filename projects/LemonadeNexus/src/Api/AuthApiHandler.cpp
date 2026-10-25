#include <LemonadeNexus/Api/AuthApiHandler.hpp>

#include <LemonadeNexus/ACL/Permission.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>
#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/TokenLinkAuthProvider.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeRules.hpp>
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

    // POST /api/auth/register — passkey / FIDO2 credential registration.
    // Requires a valid session: the credential binds to the session's
    // verified identity. A caller-supplied user_id is never honored, so a
    // session can never create or replace another identity's credentials.
    pub.Post("/api/auth/register",
             require_auth(ctx_.auth,
                 [this](const httplib::Request& req, httplib::Response& res,
                        const SessionClaims& claims) {
        auto body = parse_body(req, res);
        if (!body) return;

        (*body)["user_id"] = claims.user_id;

        auto result = ctx_.auth.register_passkey(*body);

        network::AuthResponse resp{
            .authenticated = result.authenticated,
            .user_id       = result.user_id,
            .session_token = result.session_token,
            .error         = result.error_message,
        };
        nlohmann::json j = resp;
        json_response(res, j, result.authenticated ? 200 : 400);
    }));

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

    // POST /api/link/token (PRIVATE, auth required) — mint a single-use link
    // token (an invite) for a target group. Body (all optional):
    //   {"ttl_sec": N, "target_node_id": "<group>", "permissions": [...]}
    // Without target_node_id the target is the caller's own group. A new
    // device passes the token to /api/join to be placed under the target; an
    // identity that already joined passes it to /api/link/accept (or
    // /api/join) to become a member of the target with the permissions.
    // Without permissions the invite carries
    // tree::rules::kDefaultInvitePermissions that the caller holds.
    priv.Post("/api/link/token", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        nlohmann::json body = nlohmann::json::object();
        if (!req.body.empty()) {
            body = nlohmann::json::parse(req.body, nullptr, false);
            if (body.is_discarded() || !body.is_object()) {
                error_response(res, "invalid JSON body");
                return;
            }
        }

        auto caller_pubkey = normalize_pubkey(claims.pubkey);

        std::string group_id;
        if (body.contains("target_node_id")) {
            if (!body["target_node_id"].is_string()) {
                error_response(res, "target_node_id must be a string");
                return;
            }
            group_id = body["target_node_id"].get<std::string>();
        }
        if (group_id.empty()) {
            // Resolve the caller's Customer group: parent of their endpoint
            // node, falling back to the group derived from their user id.
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
        }

        const auto nodes = ctx_.tree.nodes_snapshot();
        std::vector<std::string> permissions;
        if (body.contains("permissions")) {
            if (!body["permissions"].is_array()) {
                error_response(res, "permissions must be an array of strings");
                return;
            }
            for (const auto& p : body["permissions"]) {
                if (!p.is_string()) {
                    error_response(res, "permissions must be an array of strings");
                    return;
                }
                permissions.push_back(p.get<std::string>());
            }
        } else {
            for (const auto p : tree::rules::kDefaultInvitePermissions) {
                if (tree::rules::holds_or_administers(nodes, group_id, caller_pubkey,
                                                      tree::rules::permission_from_string(p))) {
                    permissions.emplace_back(p);
                }
            }
        }

        // The inviter's own authority on the target bounds the invite.
        if (const auto ruling =
                tree::rules::invite_refusal(nodes, group_id, caller_pubkey, permissions)) {
            using R = tree::rules::AssignmentRefusal;
            const int status = ruling->refusal == R::NotFound    ? 404
                               : ruling->refusal == R::Forbidden ? 403
                               : ruling->refusal == R::Conflict  ? 409
                                                                 : 400;
            error_response(res, ruling->reason, status);
            return;
        }

        auto ttl_sec = body.value("ttl_sec",
            static_cast<uint64_t>(auth::TokenLinkAuthProvider::kDefaultTtl.count()));
        auto minted = ctx_.auth.mint_link_token(
            claims.user_id, caller_pubkey, group_id, std::chrono::seconds{ttl_sec},
            permissions);
        if (!minted) {
            error_response(res, "failed to mint link token", 500);
            return;
        }

        nlohmann::json j = {
            {"link_token",     minted->first},
            {"group_node_id",  minted->second.group_node_id},
            {"target_node_id", minted->second.group_node_id},
            {"permissions",    minted->second.permissions},
            {"expires_at",     minted->second.expires_at},
        };
        json_response(res, j);
    }));
}

} // namespace nexus::api
