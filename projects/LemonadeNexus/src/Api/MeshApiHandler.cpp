#include <LemonadeNexus/Api/MeshApiHandler.hpp>

#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeOpSubmitter.hpp>
#include <LemonadeNexus/Tree/TreeRules.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Boringtun/BoringtunService.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <regex>
#include <unordered_map>
#include <unordered_set>

namespace nexus::api {

namespace {
/// Staleness threshold: 3 missed 5-second keepalives = offline.
constexpr uint64_t kStaleThresholdSec = 15;

/// Strip CIDR prefix from tunnel IP (e.g. "10.64.0.3/32" -> "10.64.0.3")
std::string strip_cidr(const std::string& ip) {
    auto slash = ip.find('/');
    return (slash != std::string::npos) ? ip.substr(0, slash) : ip;
}

/// Build a map from tunnel address to the last Noise handshake epoch.
/// Used to determine peer liveness from the boringtun layer.
std::unordered_map<std::string, uint64_t> build_mesh_handshake_map(
    nexus::boringtun::BoringtunService* dataplane) {
    std::unordered_map<std::string, uint64_t> m;
    if (!dataplane) return m;
    for (const auto& peer : dataplane->get_peers()) {
        auto ip = strip_cidr(peer.allowed_ips);
        if (!ip.empty() && peer.last_handshake > 0) {
            m[ip] = peer.last_handshake;
        }
    }
    return m;
}
} // anonymous namespace

bool mesh_peer_listed(const tree::PermissionTreeService& tree,
                      std::string_view caller_pubkey,
                      const tree::TreeNode& peer) {
    switch (peer.type) {
        case tree::NodeType::Endpoint:
            return tree.check_permission(caller_pubkey, peer.id, acl::Permission::ConnectPrivate) ||
                   tree.check_permission(caller_pubkey, peer.id, acl::Permission::ConnectShared);
        case tree::NodeType::Relay:
            return tree.check_permission(caller_pubkey, peer.id, acl::Permission::Read);
        default:
            return false;
    }
}

namespace {

/// The endpoints that `from`, acting as `caller_pubkey`, may connect to
/// (tree::rules::endpoint_may_connect): first those in `home_scope` (the
/// parent-group subtree, in its order), then those outside it that an invite
/// membership covers, sorted by node id.
std::vector<tree::TreeNode> connectable_endpoints(const tree::PermissionTreeService& tree,
                                                  std::string_view caller_pubkey,
                                                  const tree::TreeNode& from,
                                                  const std::vector<tree::TreeNode>& home_scope) {
    const auto nodes = tree.nodes_snapshot();
    std::vector<tree::TreeNode> out;
    std::unordered_set<std::string> seen;
    for (const auto& n : home_scope) {
        if (n.type != tree::NodeType::Endpoint) continue;
        seen.insert(n.id);
        if (tree::rules::endpoint_may_connect(nodes, caller_pubkey, from, n)) out.push_back(n);
    }
    std::vector<tree::TreeNode> members;
    for (const auto& [id, n] : nodes) {
        if (n.type != tree::NodeType::Endpoint || seen.contains(id)) continue;
        if (tree::rules::endpoint_may_connect(nodes, caller_pubkey, from, n)) members.push_back(n);
    }
    std::sort(members.begin(), members.end(),
              [](const tree::TreeNode& a, const tree::TreeNode& b) { return a.id < b.id; });
    out.insert(out.end(), std::make_move_iterator(members.begin()),
               std::make_move_iterator(members.end()));
    return out;
}

}  // namespace

namespace {
/// Validate that a mesh heartbeat endpoint string is a well-formed ip:port
/// or hostname:port. Empty strings are allowed (no endpoint to report).
/// Rejects arbitrary strings that could be injected downstream, and IPv4
/// addresses that have an octet above 255 or are not unicast (0.0.0.0/8,
/// 224.0.0.0/4, 240.0.0.0/4).
bool is_valid_mesh_endpoint(const std::string& ep) {
    if (ep.empty()) return true;
    // Max length sanity check (longest reasonable hostname:port)
    if (ep.size() > 253 + 6) return false;  // 253 char hostname + ":" + 5 digit port
    // IPv4:port
    static const std::regex ipv4_re(R"(^(\d{1,3}\.){3}\d{1,3}:\d{1,5}$)");
    // [IPv6]:port
    static const std::regex ipv6_re(R"(^\[[0-9a-fA-F:]+\]:\d{1,5}$)");
    // hostname:port
    static const std::regex host_re(
        R"(^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*:\d{1,5}$)");
    const bool ipv4 = std::regex_match(ep, ipv4_re);
    if (!ipv4 &&
        !std::regex_match(ep, ipv6_re) &&
        !std::regex_match(ep, host_re)) {
        return false;
    }
    if (ipv4) {
        // The pattern guarantees four 1-3 digit octets before the port.
        int octets[4] = {};
        std::size_t start = 0;
        for (int& octet : octets) {
            const auto end = ep.find_first_of(".:", start);
            octet = std::stoi(ep.substr(start, end - start));
            if (octet > 255) return false;
            start = end + 1;
        }
        if (octets[0] == 0 || octets[0] >= 224) return false;
    }
    // Validate port range (1-65535)
    auto colon_pos = ep.rfind(':');
    if (colon_pos == std::string::npos) return false;
    auto port_str = ep.substr(colon_pos + 1);
    try {
        auto port = std::stoul(port_str);
        return port >= 1 && port <= 65535;
    } catch (...) {
        return false;
    }
}
} // anonymous namespace

void MeshApiHandler::do_register_routes([[maybe_unused]] httplib::Server& pub,
                                        httplib::Server& priv) {
    using nexus::auth::require_auth;
    using nexus::auth::SessionClaims;

    // ========================================================================
    // GET /api/mesh/peers/:node_id (PRIVATE, auth required)
    //
    // Returns the server peer, the endpoints the requesting node may connect
    // to (tree::rules::endpoint_may_connect: a connect grant in the parent-group
    // subtree, or an invite membership), and the relays in that subtree that
    // mesh_peer_listed admits. Read on the requesting node lets the caller ask.
    // ========================================================================
    priv.Get(R"(/api/mesh/peers/([a-zA-Z0-9_-]+))", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {

        std::string node_id = req.matches[1];
        if (node_id.empty()) {
            error_response(res, "node_id required");
            return;
        }

        // Look up the requesting node
        auto node_opt = ctx_.tree.get_node(node_id);
        if (!node_opt) {
            error_response(res, "node not found", 404);
            return;
        }
        const auto& node = *node_opt;

        // Check that the authenticated user has Read permission on this node
        // Permission assignments are keyed by the caller's pubkey (see the join
        // flow + createChildNode), NOT the user_id (which is a hash-derived node
        // id). Using user_id here made every Read check miss its assignment -> 403.
        auto caller_pubkey = normalize_pubkey(claims.pubkey);
        if (!ctx_.tree.check_permission(caller_pubkey, node_id, acl::Permission::Read)) {
            error_response(res, "insufficient permissions", 403);
            return;
        }

        // Find the parent group to get all sibling nodes
        if (node.parent_id.empty()) {
            // Root node has no siblings — return just the server peer
            nlohmann::json j;
            j["node_id"] = node_id;
            j["peers"] = nlohmann::json::array();
            j["server_peer"] = build_server_peer();
            json_response(res, j);
            return;
        }

        // Descendants of the caller's parent group (relays below), and the
        // endpoints the connect rule admits, including invite memberships.
        auto reachable = ctx_.tree.collect_subtree(node.parent_id);
        const auto endpoints = connectable_endpoints(ctx_.tree, caller_pubkey, node, reachable);

        // Use Noise handshake activity to determine peer liveness.
        auto mesh_handshakes = build_mesh_handshake_map(ctx_.boringtun);
        auto now = epoch_seconds();

        // Build peer list: every endpoint the caller's node may connect to
        nlohmann::json peers = nlohmann::json::array();
        for (const auto& sibling : endpoints) {

            // Determine online status from the last Noise handshake.
            auto sip = strip_cidr(sibling.tunnel_ip);
            uint64_t last_seen = 0;
            bool online = false;
            auto it = mesh_handshakes.find(sip);
            if (it != mesh_handshakes.end()) {
                last_seen = it->second;
                online = (now - last_seen) < kStaleThresholdSec;
            }

            nlohmann::json peer;
            peer["node_id"]        = sibling.id;
            peer["hostname"]       = sibling.hostname;
            peer["mesh_pubkey"]    = sibling.mesh_pubkey;
            peer["tunnel_ip"]      = sibling.tunnel_ip;
            peer["private_subnet"] = sibling.private_subnet;
            peer["endpoint"]       = sibling.listen_endpoint;
            peer["relay_endpoint"] = "";  // filled by relay discovery
            peer["is_online"]      = online;
            peer["last_seen"]      = last_seen;
            peers.push_back(std::move(peer));
        }

        // Also include Relay-type nodes in scope as potential relay endpoints
        for (const auto& sibling : reachable) {
            if (sibling.type != tree::NodeType::Relay) continue;
            if (!mesh_peer_listed(ctx_.tree, caller_pubkey, sibling)) continue;

            nlohmann::json peer;
            peer["node_id"]        = sibling.id;
            peer["hostname"]       = sibling.hostname;
            peer["mesh_pubkey"]    = sibling.mesh_pubkey;
            peer["tunnel_ip"]      = sibling.tunnel_ip;
            peer["private_subnet"] = sibling.private_subnet;
            peer["endpoint"]       = sibling.listen_endpoint;
            peer["relay_endpoint"] = sibling.listen_endpoint;
            peer["is_online"]      = true;  // relays are always considered online
            peer["is_relay"]       = true;
            peer["region"]         = sibling.region;
            peer["capacity_mbps"]  = sibling.capacity_mbps;
            peers.push_back(std::move(peer));
        }

        nlohmann::json j;
        j["node_id"]     = node_id;
        j["parent_id"]   = node.parent_id;
        j["peers"]       = std::move(peers);
        j["server_peer"] = build_server_peer();
        json_response(res, j);
    }));

    // ========================================================================
    // POST /api/mesh/heartbeat (PRIVATE, auth required)
    //
    // Client reports its current public endpoint (learned via STUN) and
    // online status.  The server updates the node's listen_endpoint in the
    // tree so that other peers can discover it. An empty or absent endpoint
    // means the client has none to report (no STUN answer yet): the stored
    // endpoint stays as it is, so a heartbeat never erases a punch target.
    //
    // Body: { "node_id": "...", "endpoint": "ip:port" }
    // ========================================================================
    priv.Post("/api/mesh/heartbeat", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {

        auto body_opt = parse_body(req, res);
        if (!body_opt) return;
        const auto& body = *body_opt;

        auto hb_node_id = body.value("node_id", "");
        auto hb_endpoint = body.value("endpoint", "");

        if (hb_node_id.empty()) {
            error_response(res, "node_id required");
            return;
        }

        // Validate endpoint format before storing (prevents injection downstream)
        if (!is_valid_mesh_endpoint(hb_endpoint)) {
            error_response(res, "invalid endpoint format (expected ip:port or hostname:port)");
            return;
        }

        // Verify the node exists
        auto node_opt = ctx_.tree.get_node(hb_node_id);
        if (!node_opt) {
            error_response(res, "node not found", 404);
            return;
        }

        // Verify the caller owns this node: the JWT user_id must match the
        // node_id being heartbeated (the node_id IS the user_id from join).
        if (claims.user_id != hb_node_id) {
            spdlog::warn("[MeshAPI] Heartbeat ownership mismatch: caller={} node={}",
                          claims.user_id, hb_node_id);
            error_response(res, "insufficient permissions", 403);
            return;
        }

        // The endpoint write is a SetEndpoint tree operation. A heartbeat
        // does not wait for the commit: it is periodic and best-effort,
        // and an unchanged endpoint writes nothing at all.
        if (!ctx_.tree_ops) {
            spdlog::error("[MeshAPI] no tree-op submitter is wired");
            error_response(res, "tree operations unavailable", 500);
            return;
        }
        std::string status = "unchanged";
        auto current = node_opt;
        for (int attempt = 0;
             current && !hb_endpoint.empty() && current->listen_endpoint != hb_endpoint;
             ++attempt) {
            tree::TreeOp op;
            op.kind = tree::TreeOpKind::SetEndpoint;
            op.target = hb_node_id;
            op.base_version = current->version;
            op.principal = normalize_pubkey(claims.pubkey);
            op.body.source = tree::TreeOpSource::Session;
            op.body.listen_endpoint = hb_endpoint;
            const auto admission = ctx_.tree_ops->submit_async(std::move(op));
            if (admission.verdict.ok()) {
                status = admission.ticket->current().status == tree::TreeOpStatus::Committed
                             ? "committed"
                             : "pending";
                break;
            }
            using R = tree::TreeOpRefusal;
            // A write that landed since the read: re-read and retry.
            if (admission.verdict.refusal == R::StaleBaseVersion && attempt < 2) {
                current = ctx_.tree.get_node(hb_node_id);
                continue;
            }
            switch (admission.verdict.refusal) {
                case R::NotFound:    error_response(res, "node not found", 404); return;
                case R::Forbidden:   error_response(res, "insufficient permissions", 403); return;
                case R::Unavailable:
                    // Not applied; a retry is safe (for example after the
                    // one-time tree merge commit is installed).
                    error_response(res, admission.verdict.reason, 503);
                    res.set_header("Retry-After", "30");
                    return;
                default:
                    error_response(res, "failed to update node endpoint", 500);
                    return;
            }
        }
        if (!current) {
            error_response(res, "node not found", 404);
            return;
        }
        nlohmann::json j;
        j["success"]  = true;
        j["node_id"]  = hb_node_id;
        j["endpoint"] = hb_endpoint.empty() ? current->listen_endpoint : hb_endpoint;
        j["status"]   = status;
        json_response(res, j);
    }));

    // ========================================================================
    // GET /api/mesh/status/:node_id (PRIVATE, auth required)
    //
    // Returns mesh status for a node including peer count, online count,
    // and the server's mesh peer info for that node.
    // ========================================================================
    priv.Get(R"(/api/mesh/status/([a-zA-Z0-9_-]+))", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res,
               const SessionClaims& claims) {

        std::string node_id = req.matches[1];
        if (node_id.empty()) {
            error_response(res, "node_id required");
            return;
        }

        auto node_opt = ctx_.tree.get_node(node_id);
        if (!node_opt) {
            error_response(res, "node not found", 404);
            return;
        }

        // Permission assignments are keyed by the caller's pubkey (see the join
        // flow + createChildNode), NOT the user_id (which is a hash-derived node
        // id). Using user_id here made every Read check miss its assignment -> 403.
        auto caller_pubkey = normalize_pubkey(claims.pubkey);
        if (!ctx_.tree.check_permission(caller_pubkey, node_id, acl::Permission::Read)) {
            error_response(res, "insufficient permissions", 403);
            return;
        }

        const auto& node = *node_opt;
        uint32_t peer_count = 0;
        uint32_t online_count = 0;

        if (!node.parent_id.empty()) {
            // Count the same peers that GET /api/mesh/peers lists.
            auto reachable = ctx_.tree.collect_subtree(node.parent_id);
            auto mesh_handshakes = build_mesh_handshake_map(ctx_.boringtun);
            auto now = epoch_seconds();
            for (const auto& s : connectable_endpoints(ctx_.tree, caller_pubkey, node, reachable)) {
                ++peer_count;
                auto sip = strip_cidr(s.tunnel_ip);
                auto it = mesh_handshakes.find(sip);
                if (it != mesh_handshakes.end() && (now - it->second) < kStaleThresholdSec) {
                    ++online_count;
                }
            }
            for (const auto& s : reachable) {
                if (s.type != tree::NodeType::Relay) continue;
                if (!mesh_peer_listed(ctx_.tree, caller_pubkey, s)) continue;
                ++peer_count;
                ++online_count;  // relays always considered online
            }
        }

        nlohmann::json j;
        j["node_id"]      = node_id;
        j["tunnel_ip"]    = node.tunnel_ip;
        j["peer_count"]   = peer_count;
        j["online_count"] = online_count;
        j["server_peer"]  = build_server_peer();
        json_response(res, j);
    }));
}

nlohmann::json MeshApiHandler::build_server_peer() const {
    nlohmann::json sp;
    sp["node_id"]   = "server";
    sp["hostname"]  = ctx_.server_fqdn;
    sp["endpoint"]  = ctx_.server_public_ip + ":" + std::to_string(ctx_.config.udp_port);
    sp["tunnel_ip"] = ctx_.tunnel_bind_ip;
    sp["is_online"] = true;
    sp["is_server"] = true;

    // Derive mesh public key from server identity for the peer entry
    sp["mesh_pubkey"] = "";
    if (ctx_.boringtun) {
        // The server mesh key is stored in the root node.
        auto root_nodes = ctx_.tree.get_nodes_by_type(tree::NodeType::Root);
        if (!root_nodes.empty()) {
            sp["mesh_pubkey"] = root_nodes[0].mesh_pubkey;
        }
    }

    return sp;
}

} // namespace nexus::api
