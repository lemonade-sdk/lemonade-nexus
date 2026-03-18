#include <LemonadeNexus/Api/MeshApiHandler.hpp>

#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/WireGuard/WireGuardService.hpp>

#include <spdlog/spdlog.h>

#include <regex>
#include <unordered_map>

namespace nexus::api {

namespace {
/// Staleness threshold: 3 missed 5-second keepalives = offline.
constexpr uint64_t kStaleThresholdSec = 15;

/// Strip CIDR prefix from tunnel IP (e.g. "10.64.0.3/32" -> "10.64.0.3")
std::string strip_cidr(const std::string& ip) {
    auto slash = ip.find('/');
    return (slash != std::string::npos) ? ip.substr(0, slash) : ip;
}

/// Build a map from tunnel_ip (without /prefix) to last WG handshake epoch.
/// Used to determine peer liveness from WireGuard layer.
std::unordered_map<std::string, uint64_t> build_wg_handshake_map(
    nexus::wireguard::WireGuardService* wg) {
    std::unordered_map<std::string, uint64_t> m;
    if (!wg) return m;
    for (const auto& peer : wg->get_peers()) {
        auto ip = strip_cidr(peer.allowed_ips);
        if (!ip.empty() && peer.last_handshake > 0) {
            m[ip] = peer.last_handshake;
        }
    }
    return m;
}
} // anonymous namespace

namespace {
/// Validate that a mesh heartbeat endpoint string is a well-formed ip:port
/// or hostname:port.  Empty strings are allowed (clears the endpoint).
/// Rejects arbitrary strings that could be injected downstream.
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
    if (!std::regex_match(ep, ipv4_re) &&
        !std::regex_match(ep, ipv6_re) &&
        !std::regex_match(ep, host_re)) {
        return false;
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
    // Returns the server as a peer plus all authorized sibling endpoints
    // under the same parent group.  Each entry contains the WireGuard
    // public key, tunnel IP, private subnet, and last-known endpoint,
    // so the client SDK can build a multi-peer WireGuard config.
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
        auto caller_pubkey = normalize_pubkey(claims.user_id);
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

        auto siblings = ctx_.tree.get_children(node.parent_id);

        // Build WG handshake map to determine peer liveness from the tunnel layer
        auto wg_map = build_wg_handshake_map(ctx_.wireguard);
        auto now = epoch_seconds();

        // Build peer list: all Endpoint-type siblings except the requesting node
        nlohmann::json peers = nlohmann::json::array();
        for (const auto& sibling : siblings) {
            if (sibling.id == node_id) continue;  // skip self
            if (sibling.type != tree::NodeType::Endpoint) continue;  // only endpoints

            // Check that we have Read permission on the sibling
            if (!ctx_.tree.check_permission(caller_pubkey, sibling.id,
                                             acl::Permission::Read)) {
                continue;  // skip nodes we can't see
            }

            // Determine online status from WG handshake timestamp
            auto sip = strip_cidr(sibling.tunnel_ip);
            uint64_t last_seen = 0;
            bool online = false;
            auto it = wg_map.find(sip);
            if (it != wg_map.end()) {
                last_seen = it->second;
                online = (now - last_seen) < kStaleThresholdSec;
            }

            nlohmann::json peer;
            peer["node_id"]        = sibling.id;
            peer["hostname"]       = sibling.hostname;
            peer["wg_pubkey"]      = sibling.wg_pubkey;
            peer["tunnel_ip"]      = sibling.tunnel_ip;
            peer["private_subnet"] = sibling.private_subnet;
            peer["endpoint"]       = sibling.listen_endpoint;
            peer["relay_endpoint"] = "";  // filled by relay discovery
            peer["is_online"]      = online;
            peer["last_seen"]      = last_seen;
            peers.push_back(std::move(peer));
        }

        // Also include Relay-type siblings as potential relay endpoints
        for (const auto& sibling : siblings) {
            if (sibling.type != tree::NodeType::Relay) continue;
            if (!ctx_.tree.check_permission(caller_pubkey, sibling.id,
                                             acl::Permission::Read)) {
                continue;
            }

            nlohmann::json peer;
            peer["node_id"]        = sibling.id;
            peer["hostname"]       = sibling.hostname;
            peer["wg_pubkey"]      = sibling.wg_pubkey;
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
    // tree so that other peers can discover it.
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

        // Verify the caller owns this node via management pubkey (defense in depth)
        auto caller_pubkey = normalize_pubkey(claims.user_id);
        if (node_opt->mgmt_pubkey != caller_pubkey) {
            spdlog::warn("[MeshAPI] Heartbeat ownership mismatch: caller={} node_mgmt={}",
                          caller_pubkey, node_opt->mgmt_pubkey);
            error_response(res, "insufficient permissions", 403);
            return;
        }

        // Also verify the caller has EditNode permission (belt and suspenders)
        if (!ctx_.tree.check_permission(caller_pubkey, hb_node_id,
                                         acl::Permission::EditNode)) {
            error_response(res, "insufficient permissions", 403);
            return;
        }

        // Atomically update only the listen_endpoint field (avoids TOCTOU race)
        if (!ctx_.tree.update_node_endpoint(hb_node_id, hb_endpoint)) {
            error_response(res, "failed to update node endpoint", 500);
            return;
        }

        spdlog::debug("Mesh heartbeat: node {} reported endpoint {}",
                        hb_node_id, hb_endpoint);

        nlohmann::json j;
        j["success"]  = true;
        j["node_id"]  = hb_node_id;
        j["endpoint"] = hb_endpoint;
        json_response(res, j);
    }));

    // ========================================================================
    // GET /api/mesh/status/:node_id (PRIVATE, auth required)
    //
    // Returns mesh status for a node including peer count, online count,
    // and the server's WireGuard peer info for that node.
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

        auto caller_pubkey = normalize_pubkey(claims.user_id);
        if (!ctx_.tree.check_permission(caller_pubkey, node_id, acl::Permission::Read)) {
            error_response(res, "insufficient permissions", 403);
            return;
        }

        const auto& node = *node_opt;
        uint32_t peer_count = 0;
        uint32_t online_count = 0;

        if (!node.parent_id.empty()) {
            auto siblings = ctx_.tree.get_children(node.parent_id);
            auto wg_map = build_wg_handshake_map(ctx_.wireguard);
            auto now = epoch_seconds();
            for (const auto& s : siblings) {
                if (s.id == node_id) continue;
                if (s.type != tree::NodeType::Endpoint &&
                    s.type != tree::NodeType::Relay) continue;
                ++peer_count;
                if (s.type == tree::NodeType::Relay) {
                    ++online_count;  // relays always considered online
                } else {
                    auto sip = strip_cidr(s.tunnel_ip);
                    auto it = wg_map.find(sip);
                    if (it != wg_map.end() && (now - it->second) < kStaleThresholdSec) {
                        ++online_count;
                    }
                }
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

    // Derive WireGuard public key from server identity for the peer entry
    sp["wg_pubkey"] = "";  // filled by caller if needed; server's WG pubkey
    if (ctx_.wireguard) {
        // The server's WG pubkey is stored in the root node or derived from identity
        auto root_nodes = ctx_.tree.get_nodes_by_type(tree::NodeType::Root);
        if (!root_nodes.empty()) {
            sp["wg_pubkey"] = root_nodes[0].wg_pubkey;
        }
    }

    return sp;
}

} // namespace nexus::api
