#include <LemonadeNexus/Api/AuthApiHandler.hpp>

#include <LemonadeNexus/Auth/AuthService.hpp>
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
    } else {
        // Root already exists — grant basic access.
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
                                        [[maybe_unused]] httplib::Server& priv) {
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
}

} // namespace nexus::api
