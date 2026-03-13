#include <LemonadeNexus/Api/TreeApiHandler.hpp>

#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>

#include <spdlog/spdlog.h>

namespace nexus::api {

void TreeApiHandler::do_register_routes(httplib::Server& pub, httplib::Server& priv) {
    using nexus::auth::require_auth;
    using nexus::auth::SessionClaims;

    // ========================================================================
    // POST /api/join (PUBLIC, no auth)
    // Composite bootstrap endpoint: authenticate, create node, allocate tunnel
    // IP, return WireGuard config.
    // ========================================================================
    pub.Post("/api/join", [this](const httplib::Request& req, httplib::Response& res) {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            nlohmann::json j = network::ErrorResponse{.error = "invalid json"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        auto auth_result = ctx_.auth.authenticate(body);
        if (!auth_result.authenticated) {
            res.status = 401;
            nlohmann::json j = network::ErrorResponse{
                .error  = "authentication failed",
                .detail = auth_result.error_message,
            };
            res.set_content(j.dump(), "application/json");
            return;
        }

        auto client_pubkey = body.value("public_key", "");
        if (client_pubkey.empty()) {
            res.status = 400;
            nlohmann::json j = network::ErrorResponse{.error = "public_key required"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        auto node_id = auth_result.user_id;
        if (node_id.empty()) {
            node_id = "node-" + client_pubkey.substr(0, 16);
        }

        auto existing_root = ctx_.tree.get_node("root");
        if (!existing_root) {
            tree::TreeNode root_node;
            root_node.id        = "root";
            root_node.parent_id = "";
            root_node.type      = tree::NodeType::Root;
            root_node.hostname  = ctx_.config.server_hostname.empty()
                                      ? "root"
                                      : ctx_.config.server_hostname;
            root_node.mgmt_pubkey = client_pubkey;
            root_node.assignments = {{
                .management_pubkey = client_pubkey,
                .permissions = {"read", "write", "add_child", "delete_node",
                                "edit_node", "admin"},
            }};
            ctx_.tree.bootstrap_root(root_node);
            node_id = "root";
        } else if (node_id != "root") {
            tree::TreeNode endpoint_node;
            endpoint_node.id          = node_id;
            endpoint_node.parent_id   = "root";
            endpoint_node.type        = tree::NodeType::Endpoint;
            endpoint_node.hostname    = body.value("hostname",
                                                   "endpoint-" + node_id.substr(0, 8));
            endpoint_node.mgmt_pubkey = client_pubkey;
            ctx_.tree.insert_join_node(endpoint_node);
        }

        auto alloc = ctx_.ipam.allocate_tunnel_ip(node_id);
        if (alloc.base_network.empty()) {
            res.status = 409;
            nlohmann::json j = network::ErrorResponse{.error = "IP allocation failed"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        std::string wg_server_pubkey;
        if (auto pk = ctx_.key_wrapping.load_identity_pubkey()) {
            wg_server_pubkey = crypto::to_base64(*pk);
        }

        std::string server_tunnel = ctx_.tunnel_bind_ip.empty()
                                        ? "10.100.0.1"
                                        : ctx_.tunnel_bind_ip;

        nlohmann::json resp = {
            {"token",            auth_result.session_token},
            {"node_id",          node_id},
            {"tunnel_ip",        alloc.base_network},
            {"server_tunnel_ip", server_tunnel},
            {"private_api_port", !ctx_.tunnel_bind_ip.empty()
                                     ? ctx_.config.private_http_port
                                     : ctx_.config.http_port},
            {"wg_server_pubkey", wg_server_pubkey},
            {"wg_endpoint",      ctx_.config.bind_address + ":"
                                     + std::to_string(ctx_.config.relay_port)},
            {"dns_servers",      nlohmann::json::array({server_tunnel})},
        };
        spdlog::info("[Join] node={} tunnel_ip={}", node_id, alloc.base_network);
        res.set_content(resp.dump(), "application/json");
    });

    // ========================================================================
    // GET /api/tree/node/{id} (PRIVATE, auth required)
    // ========================================================================
    priv.Get(R"(/api/tree/node/(.+))", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims&) {
        auto node_id = req.matches[1].str();
        auto node = ctx_.tree.get_node(node_id);
        if (!node) {
            res.status = 404;
            nlohmann::json j = network::ErrorResponse{.error = "node not found"};
            res.set_content(j.dump(), "application/json");
            return;
        }
        nlohmann::json j = *node;
        res.set_content(j.dump(), "application/json");
    }));

    // ========================================================================
    // POST /api/tree/delta (PRIVATE, auth required)
    // ========================================================================
    priv.Post("/api/tree/delta", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims&) {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            nlohmann::json j = network::ErrorResponse{.error = "invalid json"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        tree::TreeDelta delta;
        try {
            delta = body.get<tree::TreeDelta>();
        } catch (...) {
            delta.operation      = body.value("operation", "");
            delta.target_node_id = body.value("target_node_id", "");
            if (body.contains("node_data")) {
                auto& nd = body["node_data"];
                delta.node_data.id        = nd.value("id", "");
                delta.node_data.parent_id = nd.value("parent_id", "");
            }
            delta.signer_pubkey = body.value("signer_pubkey", "");
            delta.signature     = body.value("signature", "");
        }

        bool ok = ctx_.tree.apply_delta(delta);
        network::DeltaResponse resp{.success = ok};
        if (!ok) {
            res.status = 403;
            resp.error = "delta rejected";
        }
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // ========================================================================
    // GET /api/tree/children/{id} (PRIVATE, auth required)
    // ========================================================================
    priv.Get(R"(/api/tree/children/(.+))", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims&) {
        auto parent_id = req.matches[1].str();
        auto children = ctx_.tree.get_children(parent_id);
        nlohmann::json j = children;
        res.set_content(j.dump(), "application/json");
    }));

    // ========================================================================
    // POST /api/ipam/allocate (PRIVATE, auth required)
    // ========================================================================
    priv.Post("/api/ipam/allocate", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims&) {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            nlohmann::json j = network::ErrorResponse{.error = "invalid json"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        auto ipam_req = body.get<network::IpamAllocateRequest>();

        ipam::Allocation alloc;
        if (ipam_req.block_type == "tunnel") {
            alloc = ctx_.ipam.allocate_tunnel_ip(ipam_req.node_id);
        } else if (ipam_req.block_type == "private") {
            alloc = ctx_.ipam.allocate_private_subnet(ipam_req.node_id,
                                                       ipam_req.prefix_len);
        } else if (ipam_req.block_type == "shared") {
            alloc = ctx_.ipam.allocate_shared_block(ipam_req.node_id,
                                                     ipam_req.prefix_len);
        } else {
            res.status = 400;
            nlohmann::json j = network::ErrorResponse{.error = "invalid block_type"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        bool ok = !alloc.base_network.empty();
        network::IpamAllocateResponse resp{
            .success = ok,
            .network = alloc.base_network,
            .node_id = alloc.customer_node_id,
        };
        res.status = ok ? 200 : 409;
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));
}

} // namespace nexus::api
