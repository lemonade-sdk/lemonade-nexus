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
// Private helper — shared root-bootstrap logic
// ---------------------------------------------------------------------------

void AuthApiHandler::ensure_root_node(const std::string& pubkey) {
    if (pubkey.empty()) return;

    auto prefixed = normalize_pubkey(pubkey);

    if (!ctx_.tree.get_node("root")) {
        // First authenticated Ed25519 key becomes the root owner.
        tree::TreeNode root_node;
        root_node.id          = "root";
        root_node.parent_id   = "";
        root_node.type        = tree::NodeType::Root;
        root_node.hostname    = "root";
        root_node.mgmt_pubkey = prefixed;
        root_node.assignments = {{
            .management_pubkey = prefixed,
            .permissions = {"read", "write", "add_child", "delete_node",
                            "edit_node", "admin"},
        }};
        ctx_.tree.bootstrap_root(root_node);
    } else if (ctx_.config.open_registration) {
        // Root already exists — grant basic access. With closed registration,
        // new keys get no root grants; devices join via link tokens instead.
        ctx_.tree.grant_assignment("root", {
            .management_pubkey = prefixed,
            .permissions       = {"read", "add_child"},
        });
    }
}

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

        // After successful Ed25519 auth, bootstrap or extend root permissions.
        if (result.authenticated && body->value("method", "") == "ed25519") {
            ensure_root_node(body->value("pubkey", std::string{}));
        }

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

    // POST /api/auth/challenge — issue an Ed25519 challenge nonce
    pub.Post("/api/auth/challenge", [this](const httplib::Request& req, httplib::Response& res) {
        auto body = parse_body(req, res);
        if (!body) return;

        auto pubkey = body->value("pubkey", std::string{});
        if (pubkey.empty()) {
            error_response(res, "pubkey required");
            return;
        }

        auto challenge = ctx_.auth.issue_ed25519_challenge(pubkey);
        json_response(res, challenge);
    });

    // POST /api/auth/register/ed25519 — register an Ed25519 public key
    pub.Post("/api/auth/register/ed25519", [this](const httplib::Request& req, httplib::Response& res) {
        auto body = parse_body(req, res);
        if (!body) return;

        auto result = ctx_.auth.register_ed25519(*body);

        // On successful registration, bootstrap or extend root permissions.
        if (result.authenticated) {
            ensure_root_node(body->value("pubkey", std::string{}));
        }

        network::AuthResponse resp{
            .authenticated = result.authenticated,
            .user_id       = result.user_id,
            .session_token = result.session_token,
            .error         = result.error_message,
        };
        nlohmann::json j = resp;
        json_response(res, j, result.authenticated ? 200 : 400);
    });

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
