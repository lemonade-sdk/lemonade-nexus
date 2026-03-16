#include <LemonadeNexus/Api/TreeApiHandler.hpp>

#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/WireGuard/WireGuardService.hpp>
#include <LemonadeNexus/ACL/Permission.hpp>

#include <spdlog/spdlog.h>

#include <cstring>

namespace {
/// Ensure a pubkey string has the "ed25519:" prefix for tree storage.
std::string normalize_pubkey(const std::string& pk) {
    constexpr std::string_view prefix = "ed25519:";
    if (pk.starts_with(prefix)) return pk;
    return std::string(prefix) + pk;
}
} // anonymous namespace

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

        // Normalize pubkey to "ed25519:base64..." format for tree storage
        auto norm_pubkey = normalize_pubkey(client_pubkey);

        auto existing_root = ctx_.tree.get_node("root");
        if (!existing_root) {
            // First user bootstraps root and gets a Customer group
            tree::TreeNode root_node;
            root_node.id        = "root";
            root_node.parent_id = "";
            root_node.type      = tree::NodeType::Root;
            root_node.hostname  = ctx_.config.server_hostname.empty()
                                      ? "root"
                                      : ctx_.config.server_hostname;
            root_node.mgmt_pubkey = norm_pubkey;
            root_node.assignments = {{
                .management_pubkey = norm_pubkey,
                .permissions = {"read", "write", "add_child", "delete_node",
                                "edit_node", "admin"},
            }};
            ctx_.tree.bootstrap_root(root_node);

            // Create a Customer group for the root owner
            std::string customer_id = "customer-" + node_id;
            tree::TreeNode customer_node;
            customer_node.id          = customer_id;
            customer_node.parent_id   = "root";
            customer_node.type        = tree::NodeType::Customer;
            customer_node.hostname    = body.value("hostname",
                                                   "group-" + node_id.substr(0, 8));
            customer_node.mgmt_pubkey = norm_pubkey;
            customer_node.assignments = {{
                .management_pubkey = norm_pubkey,
                .permissions = {"read", "write", "add_child", "delete_node",
                                "edit_node"},
            }};
            ctx_.tree.insert_join_node(customer_node);

            // Create the user's Endpoint under their Customer group
            tree::TreeNode endpoint_node;
            endpoint_node.id          = node_id;
            endpoint_node.parent_id   = customer_id;
            endpoint_node.type        = tree::NodeType::Endpoint;
            endpoint_node.hostname    = body.value("hostname",
                                                   "endpoint-" + node_id.substr(0, 8));
            endpoint_node.mgmt_pubkey = norm_pubkey;
            endpoint_node.wg_pubkey   = body.value("wg_pubkey", std::string{});
            ctx_.tree.insert_join_node(endpoint_node);
        } else if (node_id != "root") {
            // Returning or new user — find or create their Customer group
            std::string customer_id = "customer-" + node_id;
            auto existing_customer = ctx_.tree.get_node(customer_id);
            if (!existing_customer) {
                tree::TreeNode customer_node;
                customer_node.id          = customer_id;
                customer_node.parent_id   = "root";
                customer_node.type        = tree::NodeType::Customer;
                customer_node.hostname    = body.value("hostname",
                                                       "group-" + node_id.substr(0, 8));
                customer_node.mgmt_pubkey = norm_pubkey;
                customer_node.assignments = {{
                    .management_pubkey = norm_pubkey,
                    .permissions = {"read", "write", "add_child", "delete_node",
                                    "edit_node"},
                }};
                ctx_.tree.insert_join_node(customer_node);
            }

            // Create Endpoint under the Customer group (idempotent)
            tree::TreeNode endpoint_node;
            endpoint_node.id          = node_id;
            endpoint_node.parent_id   = customer_id;
            endpoint_node.type        = tree::NodeType::Endpoint;
            endpoint_node.hostname    = body.value("hostname",
                                                   "endpoint-" + node_id.substr(0, 8));
            endpoint_node.mgmt_pubkey = norm_pubkey;
            endpoint_node.wg_pubkey   = body.value("wg_pubkey", std::string{});
            ctx_.tree.insert_join_node(endpoint_node);
        }

        auto alloc = ctx_.ipam.allocate_tunnel_ip(node_id);
        if (alloc.base_network.empty()) {
            res.status = 409;
            nlohmann::json j = network::ErrorResponse{.error = "IP allocation failed"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        // Convert server's Ed25519 identity key to Curve25519 (X25519) for WireGuard
        std::string wg_server_pubkey;
        if (auto ed_pk = ctx_.key_wrapping.load_identity_pubkey()) {
            auto x_pk = crypto::SodiumCryptoService::ed25519_pk_to_x25519(*ed_pk);
            wg_server_pubkey = crypto::to_base64(
                std::span<const uint8_t>(x_pk.data(), x_pk.size()));
        }

        std::string server_tunnel = ctx_.tunnel_bind_ip.empty()
                                        ? "10.64.0.1"
                                        : ctx_.tunnel_bind_ip;

        // Add the client as a WireGuard peer on the server interface
        auto client_wg_pubkey = body.value("wg_pubkey", std::string{});
        if (ctx_.wireguard && !client_wg_pubkey.empty() && !alloc.base_network.empty()) {
            // Convert Ed25519 wg_pubkey to Curve25519 if it has the ed25519: prefix
            std::string peer_wg_key = client_wg_pubkey;
            constexpr std::string_view ed_prefix = "ed25519:";
            if (peer_wg_key.starts_with(ed_prefix)) {
                // Client sent Ed25519 key — convert to Curve25519 for WireGuard
                auto ed_bytes = crypto::from_base64(peer_wg_key.substr(ed_prefix.size()));
                if (ed_bytes.size() == crypto::kEd25519PublicKeySize) {
                    crypto::Ed25519PublicKey ed_pk{};
                    std::memcpy(ed_pk.data(), ed_bytes.data(), ed_bytes.size());
                    auto x_pk = crypto::SodiumCryptoService::ed25519_pk_to_x25519(ed_pk);
                    peer_wg_key = crypto::to_base64(
                        std::span<const uint8_t>(x_pk.data(), x_pk.size()));
                }
            }

            if (ctx_.wireguard->add_peer(peer_wg_key, alloc.base_network, "")) {
                spdlog::info("[Join] added WG peer {} allowed_ips={}", peer_wg_key.substr(0, 12), alloc.base_network);
            } else {
                spdlog::warn("[Join] failed to add WG peer for node {}", node_id);
            }
        }

        // Build the WireGuard endpoint: public_ip:udp_port
        std::string wg_endpoint;
        if (!ctx_.server_public_ip.empty()) {
            wg_endpoint = ctx_.server_public_ip + ":" + std::to_string(ctx_.config.udp_port);
        }

        nlohmann::json resp = {
            {"token",            auth_result.session_token},
            {"node_id",          node_id},
            {"tunnel_ip",        alloc.base_network},
            {"tunnel_subnet",    "10.64.0.0/10"},
            {"server_tunnel_ip", server_tunnel},
            {"private_api_port", !ctx_.tunnel_bind_ip.empty()
                                     ? ctx_.config.private_http_port
                                     : ctx_.config.http_port},
            {"wg_server_pubkey", wg_server_pubkey},
            {"wg_endpoint",      wg_endpoint},
            {"dns_servers",      nlohmann::json::array({server_tunnel})},
        };
        spdlog::info("[Join] node={} tunnel_ip={} wg_endpoint={}", node_id, alloc.base_network, wg_endpoint);
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
    // POST /api/tree/node (PRIVATE, auth required)
    // Create a child node. Server handles ID generation and persistence.
    // ========================================================================
    priv.Post("/api/tree/node", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            nlohmann::json j = network::ErrorResponse{.error = "invalid json"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        auto parent_id = body.value("parent_id", std::string{"root"});
        auto type_str  = body.value("type", std::string{"endpoint"});
        auto hostname  = body.value("hostname", std::string{});

        // Normalize pubkey for tree comparison (JWT stores raw base64,
        // tree assignments use "ed25519:" prefix)
        auto caller_pubkey = normalize_pubkey(claims.pubkey);

        // Check AddChild permission on the parent
        if (!ctx_.tree.check_permission(caller_pubkey, parent_id,
                                         acl::Permission::AddChild)) {
            res.status = 403;
            nlohmann::json j = network::ErrorResponse{.error = "no add_child permission on parent"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        tree::TreeNode node;
        node.parent_id   = parent_id;
        node.mgmt_pubkey = caller_pubkey;

        if (type_str == "endpoint")  node.type = tree::NodeType::Endpoint;
        else if (type_str == "customer") node.type = tree::NodeType::Customer;
        else if (type_str == "relay")    node.type = tree::NodeType::Relay;
        else {
            res.status = 400;
            nlohmann::json j = network::ErrorResponse{.error = "invalid type"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        // Generate node ID from pubkey
        auto pubkey_short = claims.pubkey.substr(0, std::min<size_t>(claims.pubkey.size(), 16));
        node.id = "node-" + pubkey_short;
        if (hostname.empty()) {
            hostname = type_str + "-" + node.id.substr(0, 12);
        }
        node.hostname = hostname;

        if (!ctx_.tree.insert_join_node(node)) {
            res.status = 409;
            nlohmann::json j = network::ErrorResponse{.error = "node creation failed"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        nlohmann::json resp = {
            {"success", true},
            {"node_id", node.id},
        };
        spdlog::info("[TreeApi] created node '{}' under '{}'", node.id, parent_id);
        res.set_content(resp.dump(), "application/json");
    }));

    // ========================================================================
    // POST /api/tree/node/update/{id} (PRIVATE, auth required)
    // Update node fields. Server handles persistence.
    // ========================================================================
    priv.Post(R"(/api/tree/node/update/(.+))", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto node_id = req.matches[1].str();
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            nlohmann::json j = network::ErrorResponse{.error = "invalid json"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        // Check EditNode permission (normalize pubkey format)
        if (!ctx_.tree.check_permission(normalize_pubkey(claims.pubkey), node_id,
                                         acl::Permission::EditNode)) {
            res.status = 403;
            nlohmann::json j = network::ErrorResponse{.error = "no edit_node permission"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        auto existing = ctx_.tree.get_node(node_id);
        if (!existing) {
            res.status = 404;
            nlohmann::json j = network::ErrorResponse{.error = "node not found"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        // Apply partial updates to the existing node
        auto updated = *existing;
        if (body.contains("hostname"))    updated.hostname    = body["hostname"].get<std::string>();
        if (body.contains("tunnel_ip"))   updated.tunnel_ip   = body["tunnel_ip"].get<std::string>();
        if (body.contains("private_subnet")) updated.private_subnet = body["private_subnet"].get<std::string>();
        if (body.contains("shared_domain"))  updated.shared_domain  = body["shared_domain"].get<std::string>();
        if (body.contains("wg_pubkey"))   updated.wg_pubkey   = body["wg_pubkey"].get<std::string>();
        if (body.contains("listen_endpoint")) updated.listen_endpoint = body["listen_endpoint"].get<std::string>();
        if (body.contains("region"))      updated.region      = body["region"].get<std::string>();
        if (body.contains("capacity_mbps")) updated.capacity_mbps = body["capacity_mbps"].get<uint32_t>();
        if (body.contains("reputation_score")) updated.reputation_score = body["reputation_score"].get<float>();
        if (body.contains("expires_at"))  updated.expires_at  = body["expires_at"].get<uint64_t>();

        if (!ctx_.tree.update_node_direct(node_id, updated)) {
            res.status = 500;
            nlohmann::json j = network::ErrorResponse{.error = "update failed"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        nlohmann::json resp = {{"success", true}, {"node_id", node_id}};
        spdlog::info("[TreeApi] updated node '{}'", node_id);
        res.set_content(resp.dump(), "application/json");
    }));

    // ========================================================================
    // POST /api/tree/node/delete/{id} (PRIVATE, auth required)
    // Delete a node. Server handles cleanup.
    // ========================================================================
    priv.Post(R"(/api/tree/node/delete/(.+))", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto node_id = req.matches[1].str();

        // Check DeleteNode permission (normalize pubkey format)
        if (!ctx_.tree.check_permission(normalize_pubkey(claims.pubkey), node_id,
                                         acl::Permission::DeleteNode)) {
            res.status = 403;
            nlohmann::json j = network::ErrorResponse{.error = "no delete_node permission"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        if (!ctx_.tree.delete_node_direct(node_id)) {
            res.status = 404;
            nlohmann::json j = network::ErrorResponse{.error = "node not found or delete failed"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        nlohmann::json resp = {{"success", true}};
        spdlog::info("[TreeApi] deleted node '{}'", node_id);
        res.set_content(resp.dump(), "application/json");
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
