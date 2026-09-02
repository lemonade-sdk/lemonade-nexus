#include <LemonadeNexus/Api/TreeApiHandler.hpp>

#include <LemonadeNexus/Api/MeshRekey.hpp>
#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>
#include <LemonadeNexus/Routing/IdentifierDerivation.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Boringtun/BoringtunService.hpp>
#include <LemonadeNexus/Network/DnsService.hpp>
#include <LemonadeNexus/ACL/Permission.hpp>

#include <spdlog/spdlog.h>

#include <cstring>

namespace nexus::api {

namespace {

// Caller-scoped JSON view of a tree node. Always redacts the wrapped management
// private key (secret key material must never leave the server). Reduces the
// assignment map to the caller's own entry unless `full_assignments` is set —
// management readers (EditNode) need the whole ACL for read-modify-write group
// edits, but lesser readers must not see every principal on the node.
nlohmann::json redact_node_for_caller(const tree::TreeNode& node,
                                      const std::string& caller_pubkey,
                                      bool full_assignments) {
    nlohmann::json j = node;
    j["wrapped_mgmt_privkey"] = ""; // keep the field present, drop the secret
    if (!full_assignments) {
        nlohmann::json own = nlohmann::json::array();
        const auto caller_canon = tree::canonical_principal(caller_pubkey);
        for (const auto& a : node.assignments) {
            if (tree::canonical_principal(a.management_pubkey) == caller_canon) own.push_back(a);
        }
        j["assignments"] = std::move(own);
    }
    return j;
}

} // namespace

void TreeApiHandler::do_register_routes(httplib::Server& pub, httplib::Server& priv) {
    using nexus::auth::require_auth;
    using nexus::auth::SessionClaims;

    // ========================================================================
    // POST /api/join (PUBLIC, no auth)
    // Composite bootstrap endpoint: authenticate, create node, allocate tunnel
    // IP, return mesh config.
    // ========================================================================
    pub.Post("/api/join", [this](const httplib::Request& req, httplib::Response& res) {
        auto body_opt = parse_body(req, res);
        if (!body_opt) return;
        auto& body = *body_opt;

        auto auth_result = ctx_.auth.authenticate(body);
        if (!auth_result.authenticated) {
            error_response(res, "authentication failed", 401);
            return;
        }

        auto client_pubkey = body.value("public_key", "");
        if (client_pubkey.empty()) {
            error_response(res, "public_key required");
            return;
        }

        // public_key drives mgmt_pubkey, every ACL principal, and the
        // is_root_owner check — it MUST be the Ed25519-authenticated identity,
        // not an unverified body field. Bind it to body.pubkey (already verified
        // against the challenge signature by ctx_.auth.authenticate above).
        {
            constexpr std::string_view ed_prefix = "ed25519:";
            std::string_view claimed_b64 = client_pubkey;
            if (claimed_b64.starts_with(ed_prefix)) {
                claimed_b64.remove_prefix(ed_prefix.size());
            }
            bool matches = false;
            try {
                matches = crypto::from_base64(claimed_b64) ==
                          crypto::from_base64(body.value("pubkey", std::string{}));
            } catch (...) {
                matches = false;
            }
            if (!matches) {
                error_response(res,
                    "public_key does not match authenticated identity", 403);
                return;
            }
        }

        auto node_id = auth_result.user_id;
        if (node_id.empty()) {
            node_id = "node-" + client_pubkey.substr(0, 16);
        }

        // Normalize pubkey to "ed25519:base64..." format for tree storage
        auto norm_pubkey = normalize_pubkey(client_pubkey);

        // A WireGuard static binds to one node identity. The Ed25519 challenge
        // authenticated WHO is joining; this guard decides what that identity
        // may claim: its own identity-bound static (possession proved
        // transitively through the challenge), its previously registered key,
        // or a fresh opaque one — never a key another node registered, and
        // never another enrolled identity's bound form. Checked before any
        // tree write or dataplane change, so a hostile claim moves no route.
        if (const auto advertised = body.value("wg_pubkey", std::string{});
            !advertised.empty()) {
            if (const auto refusal =
                    api::wg_claim_refusal(ctx_.tree, advertised, node_id, norm_pubkey)) {
                error_response(res, *refusal, 409);
                return;
            }
        }

        // Optional device-link token (single use, minted via POST /api/link/token):
        // places the new endpoint under the token owner's Customer group.
        auto link_token = body.value("link_token", std::string{});
        std::optional<auth::LinkTokenRecord> link;
        if (!link_token.empty()) {
            link = ctx_.auth.consume_link_token(link_token);
            if (!link) {
                error_response(res, "invalid or expired link token", 403);
                return;
            }
        }

        // cpu_id/net_mac are self-reported label seeds (not security controls).
        auto cpu_id       = body.value("cpu_id", std::string{});
        auto net_mac      = body.value("net_mac", std::string{});
        auto node_region  = body.value("region", std::string{});
        bool is_inference = body.value("is_inference", false);
        auto endpoint_identifier = routing::derive_endpoint_identifier(
                node_id, node_region, cpu_id, net_mac, is_inference);

        auto stamp_endpoint_identity = [&](tree::TreeNode& n) {
            n.endpoint_identifier = endpoint_identifier;
            n.cpu_id              = cpu_id;
            n.net_mac             = net_mac;
            n.region              = node_region;
            n.is_inference        = is_inference;
        };

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
            // Explicit ACL grant for the endpoint's owner. Heartbeat authorizes
            // via ownership, but node-scoped reads (GET /api/mesh/peers/<node>,
            // /api/mesh/status/<node>) require an explicit Read permission on the
            // node; without this assignment they 403. Mirrors the Customer grant
            // so the owner has full control of their own endpoint.
            endpoint_node.assignments = {{
                .management_pubkey = norm_pubkey,
                .permissions = {"read", "write", "add_child", "delete_node",
                                "edit_node"},
            }};
            endpoint_node.wg_pubkey   = body.value("wg_pubkey", std::string{});
            stamp_endpoint_identity(endpoint_node);
            if (!ctx_.tree.insert_join_node(endpoint_node)) {
                error_response(res, "endpoint identifier conflict", 409);
                return;
            }
        } else if (node_id != "root") {
            std::string customer_id;
            auto existing_endpoint = ctx_.tree.get_node(node_id);

            if (existing_endpoint) {
                // Returning device — keep its current placement (a linked device
                // must not be reparented into a fresh group of its own).
                customer_id = existing_endpoint->parent_id;
            } else if (link) {
                // Linked join — place the device under the token owner's group.
                customer_id = link->group_node_id;
                if (!ctx_.tree.get_node(customer_id)) {
                    error_response(res, "link token group no longer exists", 409);
                    return;
                }
            } else {
                // Under closed registration a brand-new identity needs a link
                // token — except the root owner, who bootstraps their own
                // account (their key already owns root via /api/auth).
                bool is_root_owner = false;
                if (auto root = ctx_.tree.get_node("root")) {
                    is_root_owner = (tree::canonical_principal(root->mgmt_pubkey) ==
                                     tree::canonical_principal(norm_pubkey));
                }
                if (!ctx_.config.open_registration && !is_root_owner &&
                    !ctx_.tree.get_node("customer-" + node_id)) {
                    error_response(res, "registration closed — link token required", 403);
                    return;
                }

                // Returning or new user — find or create their Customer group
                customer_id = "customer-" + node_id;
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
            }

            if (!existing_endpoint) {
                // Create Endpoint under the Customer group
                tree::TreeNode endpoint_node;
                endpoint_node.id          = node_id;
                endpoint_node.parent_id   = customer_id;
                endpoint_node.type        = tree::NodeType::Endpoint;
                endpoint_node.hostname    = body.value("hostname",
                                                       "endpoint-" + node_id.substr(0, 8));
                endpoint_node.mgmt_pubkey = norm_pubkey;
                // Explicit ACL grant for the endpoint's owner. Heartbeat authorizes
                // via ownership, but node-scoped reads (GET /api/mesh/peers/<node>,
                // /api/mesh/status/<node>) require an explicit Read permission on the
                // node; without this assignment they 403. Mirrors the Customer grant
                // so the owner has full control of their own endpoint.
                if (link) {
                    // The device manages itself; the group owner keeps control.
                    endpoint_node.assignments = {
                        {.management_pubkey = norm_pubkey,
                         .permissions = {"read", "write", "edit_node"}},
                        {.management_pubkey = link->owner_pubkey,
                         .permissions = {"read", "write", "add_child", "delete_node",
                                         "edit_node"}},
                    };
                } else {
                    endpoint_node.assignments = {{
                        .management_pubkey = norm_pubkey,
                        .permissions = {"read", "write", "add_child", "delete_node",
                                        "edit_node"},
                    }};
                }
                endpoint_node.wg_pubkey   = body.value("wg_pubkey", std::string{});
                stamp_endpoint_identity(endpoint_node);
                if (!ctx_.tree.insert_join_node(endpoint_node)) {
                    error_response(res, "endpoint identifier conflict", 409);
                    return;
                }

                if (link) {
                    // Pairwise grants so devices in the group can list and dial
                    // each other (peer reads and connects check the sibling node)
                    for (const auto& sibling : ctx_.tree.get_children(customer_id)) {
                        if (sibling.type != tree::NodeType::Endpoint ||
                            sibling.id == node_id) {
                            continue;
                        }
                        if (!sibling.mgmt_pubkey.empty()) {
                            ctx_.tree.grant_assignment(node_id, {
                                .management_pubkey = sibling.mgmt_pubkey,
                                .permissions       = {"read", "connect_private"},
                            });
                        }
                        ctx_.tree.grant_assignment(sibling.id, {
                            .management_pubkey = norm_pubkey,
                            .permissions       = {"read", "connect_private"},
                        });
                    }
                    // Let the device read its group node
                    ctx_.tree.grant_assignment(customer_id, {
                        .management_pubkey = norm_pubkey,
                        .permissions       = {"read"},
                    });
                    spdlog::info("[Join] linked device {} into group {} (owner {})",
                                 node_id, customer_id, link->owner_user_id);
                }
            }
        }

        // Allocate tunnel IP (returns existing if already allocated for this node)
        auto alloc = ctx_.ipam.allocate_tunnel_ip(node_id);

        // Decide what this (re)join does to the stored node and the dataplane
        // peer. On a re-join the IP is unchanged but the key may have rotated;
        // plan_mesh_rekey rewrites the node when either changed and identifies
        // the stale peer to drop below (see MeshRekey.hpp).
        api::MeshRekeyPlan rekey;
        if (!alloc.base_network.empty()) {
            auto existing_node = ctx_.tree.get_node(node_id);
            if (existing_node) {
                auto new_wg = body.value("wg_pubkey", existing_node->wg_pubkey);
                rekey = api::plan_mesh_rekey(existing_node->tunnel_ip, alloc.base_network,
                                             existing_node->wg_pubkey, new_wg);
                if (rekey.update_node) {
                    tree::TreeNode updated = *existing_node;
                    updated.tunnel_ip = alloc.base_network;
                    updated.wg_pubkey = new_wg;
                    ctx_.tree.update_node_direct(node_id, updated);
                }
            }
        }
        if (alloc.base_network.empty()) {
            error_response(res, "IP allocation failed", 409);
            return;
        }

        // Convert server's Ed25519 identity key to Curve25519 (X25519) for the mesh
        std::string wg_server_pubkey;
        if (auto ed_pk = ctx_.key_wrapping.load_identity_pubkey()) {
            auto x_pk = crypto::SodiumCryptoService::ed25519_pk_to_x25519(*ed_pk);
            wg_server_pubkey = crypto::to_base64(
                std::span<const uint8_t>(x_pk.data(), x_pk.size()));
        }

        std::string server_tunnel = ctx_.tunnel_bind_ip.empty()
                                        ? "10.64.0.1"
                                        : ctx_.tunnel_bind_ip;

        // Add the client as a mesh peer on the server interface.
        auto client_wg_pubkey = body.value("wg_pubkey", std::string{});
        if (ctx_.boringtun && !client_wg_pubkey.empty() && !alloc.base_network.empty()) {
            auto peer_wg_key = api::normalize_mesh_pubkey(client_wg_pubkey);

            // Re-join with a rotated key: drop the stale peer first, or its
            // allowed_ips route shadows the new key and return traffic is
            // encrypted to a dead handshake.
            if (rekey.remove_stale_peer &&
                ctx_.boringtun->remove_peer(rekey.stale_peer_key)) {
                spdlog::info("[Join] removed stale WG peer {} for node {}",
                             rekey.stale_peer_key.substr(0, 12), node_id);
            }

            if (ctx_.boringtun->add_peer(peer_wg_key, alloc.base_network, "")) {
                spdlog::info("[Join] added WG peer {} allowed_ips={}",
                             peer_wg_key.substr(0, 12), alloc.base_network);
            } else {
                spdlog::warn("[Join] failed to add WG peer for node {}", node_id);
            }
        }

        // Build the mesh endpoint: public_ip:udp_port
        std::string wg_endpoint;
        if (!ctx_.server_public_ip.empty()) {
            wg_endpoint = ctx_.server_public_ip + ":" + std::to_string(ctx_.config.udp_port);
        }

        // Register private DNS for this client: private.<node_id>.ep.<domain> -> tunnel IP
        std::string client_tunnel_ip_bare = alloc.base_network;
        if (auto slash = client_tunnel_ip_bare.find('/'); slash != std::string::npos) {
            client_tunnel_ip_bare = client_tunnel_ip_bare.substr(0, slash);
        }
        std::string client_private_fqdn;
        if (ctx_.dns && !client_tunnel_ip_bare.empty()) {
            client_private_fqdn = "private." + node_id + ".ep." + ctx_.config.dns_base_domain;
            ctx_.dns->set_record(client_private_fqdn, "A", client_tunnel_ip_bare, 300);
            spdlog::info("[Join] registered DNS: {} -> {}", client_private_fqdn, client_tunnel_ip_bare);
        }

        nlohmann::json resp = {
            {"token",            auth_result.session_token},
            {"node_id",          node_id},
            {"endpoint_identifier", endpoint_identifier},
            {"tunnel_ip",        alloc.base_network},
            {"tunnel_subnet",    "10.64.0.0/10"},
            {"server_tunnel_ip", server_tunnel},
            {"server_seip_fqdn",    ctx_.server_seip_fqdn},
            {"server_private_fqdn", ctx_.server_private_fqdn},
            {"client_private_fqdn", client_private_fqdn},
            {"private_api_port", !ctx_.tunnel_bind_ip.empty()
                                     ? ctx_.config.private_http_port
                                     : ctx_.config.http_port},
            {"wg_server_pubkey", wg_server_pubkey},
            {"wg_endpoint",      wg_endpoint},
            {"dns_servers",      nlohmann::json::array({server_tunnel})},
        };
        spdlog::info("[Join] node={} tunnel_ip={} wg_endpoint={} private_fqdn={}",
                      node_id, alloc.base_network, wg_endpoint, client_private_fqdn);
        json_response(res, resp);
    });

    // ========================================================================
    // GET /api/tree/node/{id} (PRIVATE, auth required)
    // ========================================================================
    priv.Get(R"(/api/tree/node/(.+))", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto node_id = req.matches[1].str();
        auto caller_pubkey = normalize_pubkey(claims.pubkey);
        // Gate the read on an explicit Read grant scoped to this node.
        if (!ctx_.tree.check_permission(caller_pubkey, node_id,
                                         acl::Permission::Read)) {
            error_response(res, "no read permission", 403);
            return;
        }
        auto node = ctx_.tree.get_node(node_id);
        if (!node) {
            error_response(res, "node not found", 404);
            return;
        }
        // Management readers get the full ACL (needed for read-modify-write
        // group edits); everyone else sees only their own assignment.
        bool full_acl = ctx_.tree.check_permission(caller_pubkey, node_id,
                                                    acl::Permission::EditNode);
        json_response(res, redact_node_for_caller(*node, caller_pubkey, full_acl));
    }));

    // ========================================================================
    // POST /api/tree/delta (PRIVATE, auth required)
    // ========================================================================
    priv.Post("/api/tree/delta", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims&) {
        auto body_opt = parse_body(req, res);
        if (!body_opt) return;
        auto& body = *body_opt;

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
        if (!ok) resp.error = "delta rejected";
        nlohmann::json j = resp;
        json_response(res, j, ok ? 200 : 403);
    }));

    // ========================================================================
    // GET /api/tree/children/{id} (PRIVATE, auth required)
    // ========================================================================
    priv.Get(R"(/api/tree/children/(.+))", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto parent_id = req.matches[1].str();
        auto caller_pubkey = normalize_pubkey(claims.pubkey);
        // Gate enumeration on a Read grant on the parent node.
        if (!ctx_.tree.check_permission(caller_pubkey, parent_id,
                                         acl::Permission::Read)) {
            error_response(res, "no read permission", 403);
            return;
        }
        nlohmann::json j = nlohmann::json::array();
        for (const auto& child : ctx_.tree.get_children(parent_id)) {
            bool full_acl = ctx_.tree.check_permission(caller_pubkey, child.id,
                                                        acl::Permission::EditNode);
            j.push_back(redact_node_for_caller(child, caller_pubkey, full_acl));
        }
        json_response(res, j);
    }));

    // ========================================================================
    // POST /api/tree/node (PRIVATE, auth required)
    // Create a child node. Server handles ID generation and persistence.
    // ========================================================================
    priv.Post("/api/tree/node", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto body_opt = parse_body(req, res);
        if (!body_opt) return;
        auto& body = *body_opt;

        auto parent_id = body.value("parent_id", std::string{"root"});
        auto type_str  = body.value("type", std::string{"endpoint"});
        auto hostname  = body.value("hostname", std::string{});

        // Normalize pubkey for tree comparison (JWT stores raw base64,
        // tree assignments use "ed25519:" prefix)
        auto caller_pubkey = normalize_pubkey(claims.pubkey);

        // Check AddChild permission on the parent
        if (!ctx_.tree.check_permission(caller_pubkey, parent_id,
                                         acl::Permission::AddChild)) {
            error_response(res, "no add_child permission on parent", 403);
            return;
        }

        tree::TreeNode node;
        node.parent_id   = parent_id;
        node.mgmt_pubkey = caller_pubkey;

        if (type_str == "endpoint")  node.type = tree::NodeType::Endpoint;
        else if (type_str == "customer") node.type = tree::NodeType::Customer;
        else if (type_str == "relay")    node.type = tree::NodeType::Relay;
        else {
            error_response(res, "invalid type");
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
            error_response(res, "node creation failed", 409);
            return;
        }

        nlohmann::json resp = {
            {"success", true},
            {"node_id", node.id},
        };
        spdlog::info("[TreeApi] created node '{}' under '{}'", node.id, parent_id);
        json_response(res, resp);
    }));

    // ========================================================================
    // POST /api/tree/node/update/{id} (PRIVATE, auth required)
    // Update node fields. Server handles persistence.
    // ========================================================================
    priv.Post(R"(/api/tree/node/update/(.+))", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto node_id = req.matches[1].str();
        auto body_opt = parse_body(req, res);
        if (!body_opt) return;
        auto& body = *body_opt;

        // Check EditNode permission (normalize pubkey format)
        if (!ctx_.tree.check_permission(normalize_pubkey(claims.pubkey), node_id,
                                         acl::Permission::EditNode)) {
            error_response(res, "no edit_node permission", 403);
            return;
        }

        auto existing = ctx_.tree.get_node(node_id);
        if (!existing) {
            error_response(res, "node not found", 404);
            return;
        }

        // Apply partial updates to the existing node
        auto updated = *existing;
        if (body.contains("hostname"))    updated.hostname    = body["hostname"].get<std::string>();
        if (body.contains("tunnel_ip"))   updated.tunnel_ip   = body["tunnel_ip"].get<std::string>();
        if (body.contains("private_subnet")) updated.private_subnet = body["private_subnet"].get<std::string>();
        if (body.contains("shared_domain"))  updated.shared_domain  = body["shared_domain"].get<std::string>();
        if (body.contains("wg_pubkey")) {
            // Same ownership rule as the join path: edit permission on this
            // node never extends to claiming a static another node holds or
            // another identity's bound form.
            const auto claimed = body["wg_pubkey"].get<std::string>();
            if (const auto refusal = api::wg_claim_refusal(ctx_.tree, claimed, node_id,
                                                           normalize_pubkey(claims.pubkey))) {
                error_response(res, *refusal, 409);
                return;
            }
            updated.wg_pubkey = claimed;
        }
        if (body.contains("listen_endpoint")) updated.listen_endpoint = body["listen_endpoint"].get<std::string>();
        if (body.contains("region"))      updated.region      = body["region"].get<std::string>();
        if (body.contains("capacity_mbps")) updated.capacity_mbps = body["capacity_mbps"].get<uint32_t>();
        if (body.contains("reputation_score")) updated.reputation_score = body["reputation_score"].get<float>();
        if (body.contains("expires_at"))  updated.expires_at  = body["expires_at"].get<uint64_t>();

        if (!ctx_.tree.update_node_direct(node_id, updated)) {
            error_response(res, "update failed", 500);
            return;
        }

        nlohmann::json resp = {{"success", true}, {"node_id", node_id}};
        spdlog::info("[TreeApi] updated node '{}'", node_id);
        json_response(res, resp);
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
            error_response(res, "no delete_node permission", 403);
            return;
        }

        // Snapshot identity/allocations before removal so we can cascade cleanup.
        auto doomed = ctx_.tree.get_node(node_id);

        if (!ctx_.tree.delete_node_direct(node_id)) {
            error_response(res, "node not found or delete failed", 404);
            return;
        }

        if (doomed) {
            // 1. Revoke the device's Ed25519 credential so a deleted device
            //    cannot silently auto-re-register (node_id is key-deterministic).
            //    Owner-protection: an owner's key is the mgmt_pubkey of their
            //    customer group AND every sibling endpoint, so deleting ONE of
            //    their own devices must NOT blocklist that shared key. Only revoke
            //    a key that no surviving node still owns — i.e. a linked-device
            //    key, which owns only the endpoint just deleted.
            if (!doomed->mgmt_pubkey.empty() &&
                !ctx_.tree.is_mgmt_pubkey_in_use(doomed->mgmt_pubkey)) {
                constexpr std::string_view ed_prefix = "ed25519:";
                std::string_view mk = doomed->mgmt_pubkey;
                if (mk.starts_with(ed_prefix)) mk.remove_prefix(ed_prefix.size());
                ctx_.auth.revoke_ed25519(std::string(mk));
            }
            // 2. Release the node's IP allocations back to the pools.
            (void)ctx_.ipam.release(node_id, ipam::BlockType::Tunnel);
            (void)ctx_.ipam.release(node_id, ipam::BlockType::Private);
            (void)ctx_.ipam.release(node_id, ipam::BlockType::Shared);
            // 3. Remove the mesh WG peer (mirror the join-time key conversion).
            if (ctx_.boringtun && !doomed->wg_pubkey.empty()) {
                std::string peer_wg_key = doomed->wg_pubkey;
                constexpr std::string_view ed_prefix = "ed25519:";
                if (peer_wg_key.starts_with(ed_prefix)) {
                    auto ed_bytes = crypto::from_base64(peer_wg_key.substr(ed_prefix.size()));
                    if (ed_bytes.size() == crypto::kEd25519PublicKeySize) {
                        crypto::Ed25519PublicKey ed_pk{};
                        std::memcpy(ed_pk.data(), ed_bytes.data(), ed_bytes.size());
                        auto x_pk = crypto::SodiumCryptoService::ed25519_pk_to_x25519(ed_pk);
                        peer_wg_key = crypto::to_base64(
                            std::span<const uint8_t>(x_pk.data(), x_pk.size()));
                    }
                }
                if (ctx_.boringtun->remove_peer(peer_wg_key)) {
                    spdlog::info("[TreeApi] removed WG peer for deleted node '{}'", node_id);
                }
            }
        }

        nlohmann::json resp = {{"success", true}};
        spdlog::info("[TreeApi] deleted node '{}'", node_id);
        json_response(res, resp);
    }));

    // ========================================================================
    // POST /api/ipam/allocate (PRIVATE, auth required)
    // ========================================================================
    priv.Post("/api/ipam/allocate", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto body_opt = parse_body(req, res);
        if (!body_opt) return;
        auto& body = *body_opt;

        auto ipam_req = body.get<network::IpamAllocateRequest>();

        if (ipam_req.node_id.empty()) {
            error_response(res, "node_id required");
            return;
        }

        // Ownership + authorization: the caller must administer the target node.
        // Mirrors the delta path, which maps allocate_ip to EditNode.
        if (!ctx_.tree.check_permission(normalize_pubkey(claims.pubkey),
                                         ipam_req.node_id, acl::Permission::EditNode)) {
            error_response(res, "no allocate permission on node", 403);
            return;
        }

        // Bound block size so a single request can't drain a pool. Tunnel is a
        // fixed /32 and ignores prefix_len.
        constexpr uint8_t kMinBlockPrefix = 24; // no block larger than a /24
        constexpr uint8_t kMaxBlockPrefix = 30;
        if (ipam_req.block_type == "private" || ipam_req.block_type == "shared") {
            if (ipam_req.prefix_len < kMinBlockPrefix ||
                ipam_req.prefix_len > kMaxBlockPrefix) {
                error_response(res, "prefix_len out of range (24-30)");
                return;
            }
        }

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
            error_response(res, "invalid block_type");
            return;
        }

        bool ok = !alloc.base_network.empty();
        network::IpamAllocateResponse resp{
            .success = ok,
            .network = alloc.base_network,
            .node_id = alloc.customer_node_id,
        };
        nlohmann::json j = resp;
        json_response(res, j, ok ? 200 : 409);
    }));
}

} // namespace nexus::api
