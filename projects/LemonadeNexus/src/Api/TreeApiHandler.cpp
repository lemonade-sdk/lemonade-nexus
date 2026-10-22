#include <LemonadeNexus/Api/TreeApiHandler.hpp>
#include <algorithm>

#include <LemonadeNexus/Api/MeshRekey.hpp>
#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeOpSubmitter.hpp>
#include <LemonadeNexus/Tree/TreeOps.hpp>
#include <LemonadeNexus/Tree/TreeRules.hpp>
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

// Private EP FQDN registered at join (private.<node_id>.ep.<base_domain>).
// Join and the delete cascade must construct this byte-identically, or the
// cascade would remove a name the join never created.
std::string client_ep_fqdn(const std::string& node_id, const std::string& base_domain) {
    return "private." + node_id + ".ep." + base_domain;
}

// Strip the "ed25519:" identity prefix (when present) so bare base64 key
// bytes can be compared.
[[nodiscard]] std::string_view strip_ed25519_prefix(std::string_view key) {
    constexpr std::string_view ed_prefix = "ed25519:";
    return key.starts_with(ed_prefix) ? key.substr(ed_prefix.size()) : key;
}

// Apply an optional JSON field to `dst`, leaving it unchanged when the key
// is absent. Mirrors the prior per-field body.contains/get chain.
template <typename T>
void apply_optional_field(const nlohmann::json& body, const char* key, T& dst) {
    if (body.contains(key)) dst = body[key].get<T>();
}

// --- Tree operations (ServerConfig::tree_ops_enabled, Phase 1) ---
//
// With the flag on, every tree write below builds a TreeOp and applies it
// through TreeOpSubmitter (validate_op + apply_op). Request checks that run
// before a write, HTTP status codes, and response bodies stay those of the
// direct paths.

/// The configured submitter, or nullptr after answering 500. The flag never
/// falls back to the direct write paths.
tree::TreeOpSubmitter* tree_op_submitter(ApiContext& ctx, httplib::Response& res) {
    if (!ctx.tree_ops) {
        spdlog::error("[TreeApi] tree_ops_enabled is set but no tree-op submitter is wired");
        error_response(res, "tree operations unavailable", 500);
    }
    return ctx.tree_ops;
}

/// Phase 1 clients send no base version, so a route reads it from the current
/// tree when it builds the op. A concurrent write between that read and the
/// apply makes the op stale; rebuilding it from the new state keeps the direct
/// paths' last-writer-wins behavior. Bounded, so a busy node cannot hold a
/// request in a loop.
constexpr int kStaleBaseAttempts = 3;

/// Submit `build()`, rebuilding and resubmitting while the result is
/// StaleBaseVersion, at most kStaleBaseAttempts times in total.
template <typename Build>
tree::TreeOpVerdict submit_rebased(tree::TreeOpSubmitter& submitter, Build&& build) {
    tree::TreeOpVerdict verdict;
    for (int attempt = 0; attempt < kStaleBaseAttempts; ++attempt) {
        verdict = submitter.submit(build());
        if (verdict.refusal != tree::TreeOpRefusal::StaleBaseVersion) break;
    }
    return verdict;
}

/// Wrap a client-signed delta in a TreeOp and submit it. Returns whether the
/// op was applied; the delta route answers every refusal the same way.
bool submit_delta_op(tree::TreeOpSubmitter& submitter, tree::PermissionTreeService& tree,
                     const tree::TreeDelta& delta) {
    tree::TreeOp op;
    if (delta.operation == "create_node") {
        op.kind = tree::TreeOpKind::CreateNode;
        op.target = delta.node_data.id;
    } else if (delta.operation == "delete_node") {
        op.kind = tree::TreeOpKind::DeleteNode;
        op.target = delta.target_node_id;
    } else if (tree::rules::required_permission_for(delta.operation) ==
               acl::Permission::EditNode) {
        op.kind = tree::TreeOpKind::UpdateFields;
        op.target = delta.target_node_id;
    } else {
        return false;
    }
    if (op.target.empty()) return false;
    // The delta's own signed time is the op's signed time. A zero timestamp
    // leaves the op unequal to its delta, so validate_op refuses it.
    op.signed_at = delta.timestamp;
    op.principal = delta.signer_pubkey;
    op.body.source = tree::TreeOpSource::Delta;
    op.body.delta = delta;
    return submit_rebased(submitter, [&] {
        if (op.kind != tree::TreeOpKind::CreateNode) {
            const auto current = tree.get_node(op.target);
            op.base_version = current ? current->version : 0;
        }
        return op;
    }).ok();
}

/// The tree part of POST /api/join with tree operations on: the direct path's
/// placement checks, then one Join op. The op is validated before the IPAM
/// allocation, so a refused join allocates no address, and submitted with the
/// allocated address after it. Fills `alloc` and `rekey` for the dataplane
/// steps (an empty `alloc` means allocation failed). Returns false after
/// writing an error response.
bool join_via_tree_op(ApiContext& ctx, httplib::Response& res, const nlohmann::json& body,
                      const std::string& node_id, const std::string& norm_pubkey,
                      const std::optional<auth::LinkTokenRecord>& link,
                      const std::string& cpu_id, const std::string& net_mac,
                      const std::string& node_region, bool is_inference, bool is_root_owner,
                      ipam::Allocation& alloc, api::MeshRekeyPlan& rekey) {
    auto* submitter = tree_op_submitter(ctx, res);
    if (!submitter) return false;

    const auto existing = ctx.tree.get_node(node_id);
    if (!existing) {
        if (link) {
            if (!ctx.tree.get_node(link->group_node_id)) {
                error_response(res, "link token group no longer exists", 409);
                return false;
            }
        } else if (!ctx.config.open_registration && !is_root_owner &&
                   !ctx.tree.get_node("customer-" + node_id)) {
            error_response(res, "registration closed — link token required", 403);
            return false;
        }
    }

    tree::TreeOp op;
    op.kind = tree::TreeOpKind::Join;
    op.target = node_id;
    op.base_version = existing ? existing->version : 0;
    op.principal = norm_pubkey;
    op.body.source = tree::TreeOpSource::Device;
    auto& js = op.body.join;
    js.device_pubkey = norm_pubkey;
    js.challenge = body.value("challenge", std::string{});
    js.challenge_signature = body.value("signature", std::string{});
    js.hostname_present = body.contains("hostname");
    if (js.hostname_present) js.hostname = body.value("hostname", std::string{});
    js.mesh_pubkey_present = body.contains("mesh_pubkey");
    js.mesh_pubkey = body.value("mesh_pubkey", std::string{});
    js.cpu_id = cpu_id;
    js.net_mac = net_mac;
    js.region = node_region;
    js.is_inference = is_inference;
    if (!existing && link) {
        js.link_group_id = link->group_node_id;
        js.link_owner_pubkey = link->owner_pubkey;
    }

    auto answer_refusal = [&](const tree::TreeOpVerdict& v) {
        switch (v.refusal) {
            case tree::TreeOpRefusal::Conflict:
                error_response(res, v.reason, 409);
                break;
            case tree::TreeOpRefusal::NotFound:
                error_response(res,
                    "application root not established — root initialization is unavailable",
                    409);
                break;
            default:
                spdlog::warn("[Join] tree op for {} refused: {}", node_id, v.reason);
                error_response(res, "tree operation refused", 500);
                break;
        }
    };

    // A stale base version here only means another write landed meanwhile;
    // the submission below re-reads it.
    if (const auto v = submitter->dry_run(op);
        !v.ok() && v.refusal != tree::TreeOpRefusal::StaleBaseVersion) {
        answer_refusal(v);
        return false;
    }

    alloc = ctx.ipam.allocate_tunnel_ip(node_id);
    if (alloc.base_network.empty()) return true;
    js.tunnel_ip = alloc.base_network;

    for (int attempt = 0;; ++attempt) {
        // A concurrent join of the same device may have written the node
        // since the last read; the op then applies as a returning-device join.
        const auto current = attempt == 0 ? existing : ctx.tree.get_node(node_id);
        op.base_version = current ? current->version : 0;
        // Same re-key decision as the direct path, made from the stored node
        // before the op (a new node "stores" the key this join carries).
        const std::string prev_ip = current ? current->tunnel_ip : std::string{};
        const std::string prev_mesh = current ? current->mesh_pubkey : js.mesh_pubkey;
        const std::string new_mesh = js.mesh_pubkey_present ? js.mesh_pubkey : prev_mesh;

        const auto v = submitter->submit(op);
        if (v.ok()) {
            rekey = api::plan_mesh_rekey(prev_ip, alloc.base_network, prev_mesh, new_mesh);
            return true;
        }
        if (v.refusal != tree::TreeOpRefusal::StaleBaseVersion ||
            attempt + 1 >= kStaleBaseAttempts) {
            answer_refusal(v);
            return false;
        }
    }
}

} // namespace

// Post-delete cascade shared by the direct-delete and delta-delete routes so
// both stay behaviorally identical. Failures follow the direct route's
// existing conventions: IPAM release results are ignored, and peer/DNS removal
// is logged on success only.
void TreeApiHandler::cascade_node_cleanup(const std::string& node_id,
                                          const std::optional<tree::TreeNode>& doomed) {
    if (!doomed) return;
    // 1. Revoke the device's Ed25519 credential so a deleted device
    //    cannot silently auto-re-register (node_id is key-deterministic).
    //    Owner-protection: an owner's key is the mgmt_pubkey of their
    //    customer group AND every sibling endpoint, so deleting ONE of
    //    their own devices must NOT blocklist that shared key. Only revoke
    //    a key that no surviving node still owns — i.e. a linked-device
    //    key, which owns only the endpoint just deleted.
    if (!doomed->mgmt_pubkey.empty() &&
        !ctx_.tree.is_mgmt_pubkey_in_use(doomed->mgmt_pubkey)) {
        ctx_.auth.revoke_ed25519(
            std::string(strip_ed25519_prefix(doomed->mgmt_pubkey)));
    }
    // 2. Release the node's IP allocations back to the pools.
    (void)ctx_.ipam.release(node_id, ipam::BlockType::Tunnel);
    (void)ctx_.ipam.release(node_id, ipam::BlockType::Private);
    (void)ctx_.ipam.release(node_id, ipam::BlockType::Shared);
    // 3. Remove the mesh peer using the join-time key conversion.
    if (ctx_.boringtun && !doomed->mesh_pubkey.empty()) {
        // Same Ed25519->Curve25519 conversion the join route performs; the
        // stored key must match the dataplane peer key byte-for-byte.
        const auto peer_mesh_key = api::normalize_mesh_pubkey(doomed->mesh_pubkey);
        if (ctx_.boringtun->remove_peer(peer_mesh_key)) {
            spdlog::info("[TreeApi] removed mesh peer for deleted node '{}'", node_id);
        }
    }
    // 4. Remove the private EP A record registered at join; otherwise the
    //    stale record keeps serving a tunnel IP IPAM has already recycled
    //    (it could resolve to a different, live node). Best-effort like the
    //    other steps: absence is fine, a failure never aborts the cascade.
    if (ctx_.dns) {
        if (ctx_.dns->remove_record(client_ep_fqdn(node_id, ctx_.config.dns_base_domain), "A")) {
            spdlog::info("[TreeApi] removed private EP DNS record for deleted node '{}'",
                         node_id);
        }
    }
}

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
            const auto claimed_b64 = strip_ed25519_prefix(client_pubkey);
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

        // A mesh transport key binds to one node identity. The Ed25519 challenge
        // authenticated WHO is joining; this guard decides what that identity
        // may claim: its own identity-bound static (possession proved
        // transitively through the challenge), its previously registered key,
        // or a fresh opaque one — never a key another node registered, and
        // never another enrolled identity's bound form. Checked before any
        // tree write or dataplane change, so a hostile claim moves no route.
        if (const auto advertised = body.value("mesh_pubkey", std::string{});
            !advertised.empty()) {
            if (const auto refusal =
                    api::mesh_key_claim_refusal(ctx_.tree, advertised, node_id, norm_pubkey)) {
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

        // Root initialization is deferred: no public caller may create the
        // application root, and this endpoint never modifies an existing
        // root's data or assignments. Ownership below is pure validation of
        // the stored root record for the closed-registration exemption.
        const auto existing_root = ctx_.tree.get_node("root");
        if (!existing_root) {
            error_response(res,
                "application root not established — root initialization is unavailable",
                409);
            return;
        }
        const bool is_root_owner = !existing_root->mgmt_pubkey.empty() &&
            tree::canonical_principal(existing_root->mgmt_pubkey) ==
            tree::canonical_principal(norm_pubkey);

        if (!ctx_.config.tree_ops_enabled && node_id != "root") {
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
                                        "edit_node", "admin"},
                    }};
                    ctx_.tree.insert_join_node(customer_node);
                }
            }

            // The group creator administers the group: only an admin may change
            // assignments, so an owner without it could not manage members.
            // Groups created before that rule gain it on the owner's next join.
            if (auto group = ctx_.tree.get_node(customer_id);
                group && group->type == tree::NodeType::Customer &&
                tree::canonical_principal(group->mgmt_pubkey) ==
                    tree::canonical_principal(norm_pubkey)) {
                auto upgraded = *group;
                bool changed = false;
                for (auto& a : upgraded.assignments) {
                    if (tree::canonical_principal(a.management_pubkey) !=
                        tree::canonical_principal(norm_pubkey)) continue;
                    if (std::find(a.permissions.begin(), a.permissions.end(), "admin") ==
                        a.permissions.end()) {
                        a.permissions.push_back("admin");
                        changed = true;
                    }
                }
                if (changed && ctx_.tree.update_node_direct(customer_id, upgraded)) {
                    spdlog::info("[Join] group owner now administers {}", customer_id);
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
                endpoint_node.mesh_pubkey = body.value("mesh_pubkey", std::string{});
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

        ipam::Allocation alloc;
        api::MeshRekeyPlan rekey;
        if (ctx_.config.tree_ops_enabled) {
            if (!join_via_tree_op(ctx_, res, body, node_id, norm_pubkey, link, cpu_id,
                                  net_mac, node_region, is_inference, is_root_owner, alloc,
                                  rekey)) {
                return;
            }
        } else {
            // Allocate tunnel IP (returns existing if already allocated for this node)
            alloc = ctx_.ipam.allocate_tunnel_ip(node_id);

            // Decide what this (re)join does to the stored node and the dataplane
            // peer. On a re-join the IP is unchanged but the key may have rotated;
            // plan_mesh_rekey rewrites the node when either changed and identifies
            // the stale peer to drop below (see MeshRekey.hpp).
            if (!alloc.base_network.empty()) {
                auto existing_node = ctx_.tree.get_node(node_id);
                if (existing_node) {
                    auto new_mesh_pubkey = body.value("mesh_pubkey", existing_node->mesh_pubkey);
                    rekey = api::plan_mesh_rekey(existing_node->tunnel_ip, alloc.base_network,
                                                 existing_node->mesh_pubkey, new_mesh_pubkey);
                    if (rekey.update_node) {
                        tree::TreeNode updated = *existing_node;
                        updated.tunnel_ip = alloc.base_network;
                        updated.mesh_pubkey = new_mesh_pubkey;
                        ctx_.tree.update_node_direct(node_id, updated);
                    }
                }
            }
        }
        if (alloc.base_network.empty()) {
            error_response(res, "IP allocation failed", 409);
            return;
        }

        // Convert server's Ed25519 identity key to Curve25519 (X25519) for the mesh
        std::string mesh_server_pubkey;
        if (auto ed_pk = ctx_.key_wrapping.load_identity_pubkey()) {
            auto x_pk = crypto::SodiumCryptoService::ed25519_pk_to_x25519(*ed_pk);
            mesh_server_pubkey = crypto::to_base64(
                std::span<const uint8_t>(x_pk.data(), x_pk.size()));
        }

        std::string server_tunnel = ctx_.tunnel_bind_ip.empty()
                                        ? "10.64.0.1"
                                        : ctx_.tunnel_bind_ip;

        // Add the client as a mesh peer on the server interface.
        auto client_mesh_pubkey = body.value("mesh_pubkey", std::string{});
        if (ctx_.boringtun && !client_mesh_pubkey.empty() && !alloc.base_network.empty()) {
            auto peer_mesh_key = api::normalize_mesh_pubkey(client_mesh_pubkey);

            // Re-join with a rotated key: drop the stale peer first, or its
            // allowed_ips route shadows the new key and return traffic is
            // encrypted to a dead handshake.
            if (rekey.remove_stale_peer &&
                ctx_.boringtun->remove_peer(rekey.stale_peer_key)) {
                spdlog::info("[Join] removed stale mesh peer {} for node {}",
                             rekey.stale_peer_key.substr(0, 12), node_id);
            }

            if (ctx_.boringtun->add_peer(peer_mesh_key, alloc.base_network, "")) {
                spdlog::info("[Join] added mesh peer {} allowed_ips={}",
                             peer_mesh_key.substr(0, 12), alloc.base_network);
            } else {
                spdlog::warn("[Join] failed to add mesh peer for node {}", node_id);
            }
        }

        // Build the mesh endpoint: public_ip:udp_port
        std::string mesh_endpoint;
        if (!ctx_.server_public_ip.empty()) {
            mesh_endpoint = ctx_.server_public_ip + ":" + std::to_string(ctx_.config.udp_port);
        }

        // Register private DNS for this client: private.<node_id>.ep.<domain> -> tunnel IP
        std::string client_tunnel_ip_bare = alloc.base_network;
        if (auto slash = client_tunnel_ip_bare.find('/'); slash != std::string::npos) {
            client_tunnel_ip_bare = client_tunnel_ip_bare.substr(0, slash);
        }
        std::string client_private_fqdn;
        if (ctx_.dns && !client_tunnel_ip_bare.empty()) {
            client_private_fqdn = client_ep_fqdn(node_id, ctx_.config.dns_base_domain);
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
            {"mesh_server_pubkey", mesh_server_pubkey},
            {"mesh_endpoint",      mesh_endpoint},
            {"dns_servers",      nlohmann::json::array({server_tunnel})},
        };
        spdlog::info("[Join] node={} tunnel_ip={} mesh_endpoint={} private_fqdn={}",
                      node_id, alloc.base_network, mesh_endpoint, client_private_fqdn);
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
        // Gate the read on an explicit Read grant scoped to this node, or on
        // administering it (admin on the node or an ancestor group).
        const bool administers = ctx_.tree.administers(caller_pubkey, node_id);
        if (!administers && !ctx_.tree.check_permission(caller_pubkey, node_id,
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
        bool full_acl = administers || ctx_.tree.check_permission(caller_pubkey, node_id,
                                                                  acl::Permission::EditNode);
        json_response(res, redact_node_for_caller(*node, caller_pubkey, full_acl));
    }));

    // ========================================================================
    // POST /api/tree/delta (PRIVATE, auth required)
    // ========================================================================
    priv.Post("/api/tree/delta", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto body_opt = parse_body(req, res);
        if (!body_opt) return;
        auto& body = *body_opt;

        tree::TreeDelta delta;
        try {
            delta = body.get<tree::TreeDelta>();
        } catch (...) {
            // Typed parse is the single source of truth for delta bodies;
            // anything it rejects is rejected here (fail closed).
            error_response(res, "invalid delta body", 400);
            return;
        }

        // Two-plane agreement: the authenticated session identity must be the
        // delta signer. apply_delta authorizes on delta.signer_pubkey's tree
        // assignments plus a signature the caller claims to possess, so without
        // this check any session holder could submit deltas signed with another
        // principal's key (e.g. a captured management key). Compare by key bytes
        // (canonical_principal), same as do_apply_delta.
        if (delta.signer_pubkey.empty() ||
            tree::canonical_principal(normalize_pubkey(claims.pubkey)) !=
                tree::canonical_principal(delta.signer_pubkey)) {
            spdlog::warn("[TreeApi] delta signer does not match authenticated session");
            error_response(res, "delta signer does not match session", 403);
            return;
        }

        // Pre-delete snapshot so the post-delete cascade (credential revocation,
        // IPAM release, mesh peer removal) has the node's identity and keys.
        std::optional<tree::TreeNode> doomed =
            (delta.operation == "delete_node" && !delta.target_node_id.empty())
                ? ctx_.tree.get_node(delta.target_node_id)
                : std::nullopt;

        bool ok = false;
        if (ctx_.config.tree_ops_enabled) {
            auto* submitter = tree_op_submitter(ctx_, res);
            if (!submitter) return;
            ok = submit_delta_op(*submitter, ctx_.tree, delta);
        } else {
            ok = ctx_.tree.apply_delta(delta);
        }
        if (ok && doomed) {
            cascade_node_cleanup(delta.target_node_id, doomed);
        }
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
            bool full_acl = ctx_.tree.administers(caller_pubkey, child.id) ||
                            ctx_.tree.check_permission(caller_pubkey, child.id,
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

        if (ctx_.config.tree_ops_enabled) {
            auto* submitter = tree_op_submitter(ctx_, res);
            if (!submitter) return;
            tree::TreeOp op;
            op.kind = tree::TreeOpKind::CreateNode;
            op.target = node.id;
            op.principal = caller_pubkey;
            op.body.source = tree::TreeOpSource::Session;
            op.body.node = node;
            const auto v = submitter->submit(std::move(op));
            // The direct path treats an existing node as success; keep that.
            if (!v.ok() && v.refusal != tree::TreeOpRefusal::AlreadyExists) {
                error_response(res, "node creation failed", 409);
                return;
            }
        } else if (!ctx_.tree.insert_join_node(node)) {
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

        // Apply the partial update to a copy of a stored node. Returns the
        // mesh-key refusal, if any.
        auto apply_body = [&](tree::TreeNode& updated) -> std::optional<std::string> {
            apply_optional_field(body, "hostname", updated.hostname);
            apply_optional_field(body, "tunnel_ip", updated.tunnel_ip);
            apply_optional_field(body, "private_subnet", updated.private_subnet);
            apply_optional_field(body, "shared_domain", updated.shared_domain);
            if (body.contains("mesh_pubkey")) {
                // Same ownership rule as the join path: edit permission on this
                // node never extends to claiming a static another node holds or
                // another identity's bound form.
                const auto claimed = body.value("mesh_pubkey", std::string{});
                if (auto refusal = api::mesh_key_claim_refusal(
                        ctx_.tree, claimed, node_id, normalize_pubkey(claims.pubkey))) {
                    return refusal;
                }
                updated.mesh_pubkey = claimed;
            }
            apply_optional_field(body, "listen_endpoint", updated.listen_endpoint);
            apply_optional_field(body, "region", updated.region);
            apply_optional_field(body, "capacity_mbps", updated.capacity_mbps);
            apply_optional_field(body, "reputation_score", updated.reputation_score);
            apply_optional_field(body, "expires_at", updated.expires_at);
            return std::nullopt;
        };

        auto updated = *existing;
        if (const auto refusal = apply_body(updated)) {
            error_response(res, *refusal, 409);
            return;
        }

        if (ctx_.config.tree_ops_enabled) {
            auto* submitter = tree_op_submitter(ctx_, res);
            if (!submitter) return;
            // A retry (stale base version) re-reads the node and re-applies
            // the request to it, as the direct path's last write would.
            tree::TreeOpVerdict v;
            auto current = existing;
            for (int attempt = 0; attempt < kStaleBaseAttempts; ++attempt) {
                if (attempt > 0) {
                    current = ctx_.tree.get_node(node_id);
                    if (!current) break;
                    updated = *current;
                    if (const auto refusal = apply_body(updated)) {
                        error_response(res, *refusal, 409);
                        return;
                    }
                }
                tree::TreeOp op;
                op.kind = tree::TreeOpKind::UpdateFields;
                op.target = node_id;
                op.base_version = current->version;
                op.principal = normalize_pubkey(claims.pubkey);
                op.body.source = tree::TreeOpSource::Session;
                op.body.node = updated;
                op.body.node.id = node_id;
                v = submitter->submit(std::move(op));
                if (v.refusal != tree::TreeOpRefusal::StaleBaseVersion) break;
            }
            if (!current) {
                error_response(res, "node not found", 404);
                return;
            }
            if (v.refusal == tree::TreeOpRefusal::NotFound) {
                error_response(res, "node not found", 404);
                return;
            }
            if (!v.ok()) {
                error_response(res, "update failed", 500);
                return;
            }
        } else if (!ctx_.tree.update_node_direct(node_id, updated)) {
            error_response(res, "update failed", 500);
            return;
        }

        nlohmann::json resp = {{"success", true}, {"node_id", node_id}};
        spdlog::info("[TreeApi] updated node '{}'", node_id);
        json_response(res, resp);
    }));

    // ========================================================================
    // POST /api/tree/node/assignments/{id} (PRIVATE, auth required)
    // Body: {"pubkey": "<key>", "permissions": ["read", ...]}. Sets exactly
    // those permissions for the key on the node; an empty list removes it.
    // The tree enforces who may administer and who may be granted.
    // ========================================================================
    priv.Post(R"(/api/tree/node/assignments/(.+))", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto node_id = req.matches[1].str();
        auto body_opt = parse_body(req, res);
        if (!body_opt) return;
        auto& body = *body_opt;

        const auto principal = body.value("pubkey", std::string{});
        if (principal.empty() || !body.contains("permissions") ||
            !body["permissions"].is_array()) {
            error_response(res, "pubkey and permissions[] required");
            return;
        }
        std::vector<std::string> permissions;
        for (const auto& p : body["permissions"]) {
            if (!p.is_string()) {
                error_response(res, "permissions must be strings");
                return;
            }
            permissions.push_back(p.get<std::string>());
        }

        if (ctx_.config.tree_ops_enabled) {
            auto* submitter = tree_op_submitter(ctx_, res);
            if (!submitter) return;
            tree::TreeOp op;
            op.kind = tree::TreeOpKind::SetAssignment;
            op.target = node_id;
            op.principal = normalize_pubkey(claims.pubkey);
            op.body.source = tree::TreeOpSource::Session;
            op.body.assignment_principal = normalize_pubkey(principal);
            op.body.assignment_permissions = permissions;
            const auto v = submit_rebased(*submitter, [&] {
                const auto current = ctx_.tree.get_node(node_id);
                op.base_version = current ? current->version : 0;
                return op;
            });
            using R = tree::TreeOpRefusal;
            switch (v.refusal) {
                case R::None:
                    json_response(res, {{"success", true}, {"node_id", node_id}});
                    return;
                case R::NotFound:         error_response(res, v.reason, 404); return;
                case R::Forbidden:        error_response(res, v.reason, 403); return;
                case R::Invalid:          error_response(res, v.reason, 400); return;
                case R::StaleBaseVersion: error_response(res, v.reason, 409); return;
                case R::StorageError:     error_response(res, v.reason, 500); return;
                default:
                    error_response(res, "tree operation refused", 500);
                    return;
            }
        }

        std::string reason;
        using Change = tree::PermissionTreeService::AssignmentChange;
        switch (ctx_.tree.set_assignment(node_id, normalize_pubkey(claims.pubkey),
                                         normalize_pubkey(principal), permissions,
                                         reason)) {
            case Change::Applied:
                json_response(res, {{"success", true}, {"node_id", node_id}});
                return;
            case Change::NotFound:     error_response(res, reason, 404); return;
            case Change::Forbidden:    error_response(res, reason, 403); return;
            case Change::Invalid:      error_response(res, reason, 400); return;
            case Change::StorageError: error_response(res, reason, 500); return;
        }
    }));

    // ========================================================================
    // POST /api/tree/node/delete/{id} (PRIVATE, auth required)
    // Delete a node. Server handles cleanup.
    // ========================================================================
    priv.Post(R"(/api/tree/node/delete/(.+))", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {
        auto node_id = req.matches[1].str();

        // DeleteNode on the node itself, or an admin of the node or an ancestor
        // group (a group admin removes the group's devices). The root is never
        // removed through the API.
        const auto caller = normalize_pubkey(claims.pubkey);
        if (auto target = ctx_.tree.get_node(node_id); target && target->parent_id.empty()) {
            error_response(res, "the root node cannot be deleted", 403);
            return;
        }
        if (!ctx_.tree.check_permission(caller, node_id, acl::Permission::DeleteNode) &&
            !ctx_.tree.administers(caller, node_id)) {
            error_response(res, "no delete_node permission", 403);
            return;
        }

        // Snapshot identity/allocations before removal so we can cascade cleanup.
        auto doomed = ctx_.tree.get_node(node_id);

        if (ctx_.config.tree_ops_enabled) {
            auto* submitter = tree_op_submitter(ctx_, res);
            if (!submitter) return;
            tree::TreeOp op;
            op.kind = tree::TreeOpKind::DeleteNode;
            op.target = node_id;
            op.principal = normalize_pubkey(claims.pubkey);
            op.body.source = tree::TreeOpSource::Session;
            const auto v = submit_rebased(*submitter, [&] {
                // The cascade below uses the record the op actually deleted.
                doomed = ctx_.tree.get_node(node_id);
                op.base_version = doomed ? doomed->version : 0;
                return op;
            });
            if (!v.ok()) {
                error_response(res, "node not found or delete failed", 404);
                return;
            }
        } else if (!ctx_.tree.delete_node_direct(node_id)) {
            error_response(res, "node not found or delete failed", 404);
            return;
        }

        cascade_node_cleanup(node_id, doomed);

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
