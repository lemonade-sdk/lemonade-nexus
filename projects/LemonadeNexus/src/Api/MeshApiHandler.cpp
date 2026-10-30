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

#define XXH_INLINE_ALL
#include <xxhash/xxhash.h>

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdio>
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

/// The endpoints in `nodes` that `from`, acting as `caller_pubkey`, may
/// connect to (tree::rules::endpoint_may_connect): first those in
/// `home_scope` (the parent-group subtree, in its order), then those outside
/// it that an invite membership covers, sorted by node id.
std::vector<tree::TreeNode> connectable_endpoints(const tree::rules::NodeMap& nodes,
                                                  std::string_view caller_pubkey,
                                                  const tree::TreeNode& from,
                                                  const std::vector<tree::TreeNode>& home_scope) {
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

/// A server handshake younger than this means the server holds a live session
/// with the peer: BoringTun's REJECT_AFTER_TIME (180 s), one retry, and
/// jitter. peers_revision uses it, not is_online (a handshake within
/// kStaleThresholdSec): a working session renews its handshake only about
/// every two minutes, so is_online flips twice per rekey without any change
/// in reachability, and each flip would make every client fetch its peers.
constexpr uint64_t kSessionLiveSec = 200;

/// The peers_revision of a heartbeat answer: an opaque value that changes
/// when the peer list that GET /api/mesh/peers gives the caller changes in a
/// way that matters for a path: a peer added or removed, or a listed peer's
/// mesh key, tunnel address, private subnet, endpoint, LAN endpoints,
/// hostname, or live session state (kSessionLiveSec) changed. `endpoints`
/// and `relays` are the listed peers in list order; `local` holds the LAN
/// endpoints of listed endpoints that have any. XXH3 over length-prefixed
/// fields; a change detector, not a security value.
std::string peers_revision(const std::vector<tree::TreeNode>& endpoints,
                           const std::vector<const tree::TreeNode*>& relays,
                           const std::unordered_map<std::string, uint64_t>& handshakes,
                           const std::unordered_map<std::string, std::vector<std::string>>& local,
                           uint64_t now) {
    std::string buf;
    const auto field = [&buf](std::string_view text) {
        buf += std::to_string(text.size());
        buf += ':';
        buf += text;
    };
    const auto peer = [&](const tree::TreeNode& n, char kind, bool live) {
        buf += kind;
        field(n.id);
        field(n.mesh_pubkey);
        field(n.tunnel_ip);
        field(n.private_subnet);
        field(n.listen_endpoint);
        field(n.hostname);
        buf += live ? '1' : '0';
    };
    for (const auto& n : endpoints) {
        const auto it = handshakes.find(strip_cidr(n.tunnel_ip));
        peer(n, 'E', it != handshakes.end() && now - it->second < kSessionLiveSec);
        // Only a peer with LAN endpoints adds this part, so the revision of
        // a list without any stays as servers without the field compute it.
        if (const auto lan = local.find(n.id); lan != local.end() && !lan->second.empty()) {
            buf += 'L';
            buf += std::to_string(lan->second.size());
            for (const auto& endpoint : lan->second) field(endpoint);
        }
    }
    for (const auto* n : relays) peer(*n, 'R', true);
    char out[17];
    std::snprintf(out, sizeof out, "%016llx",
                  static_cast<unsigned long long>(XXH3_64bits(buf.data(), buf.size())));
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
/// A decimal number of 1 to `max_digits` digits without a leading zero, at
/// most `max`.
std::optional<uint32_t> strict_decimal(std::string_view text, std::size_t max_digits,
                                       uint32_t max) {
    if (text.empty() || text.size() > max_digits || (text.size() > 1 && text[0] == '0')) {
        return std::nullopt;
    }
    uint32_t value = 0;
    for (const char c : text) {
        if (c < '0' || c > '9') return std::nullopt;
        value = value * 10 + static_cast<uint32_t>(c - '0');
    }
    if (value > max) return std::nullopt;
    return value;
}

/// A LAN endpoint "a.b.c.d:port" whose address is private (or loopback with
/// `allow_loopback`). See parse_mesh_local_endpoints.
bool local_endpoint_valid(std::string_view text, bool allow_loopback) {
    const auto colon = text.find(':');
    if (colon == std::string_view::npos || text.find(':', colon + 1) != std::string_view::npos) {
        return false;
    }
    const auto port = strict_decimal(text.substr(colon + 1), 5, 65535);
    if (!port || *port == 0) return false;
    uint32_t ip = 0;
    std::string_view rest = text.substr(0, colon);
    for (int i = 0; i < 4; ++i) {
        const auto dot = rest.find('.');
        const bool last = i == 3;
        if (last != (dot == std::string_view::npos)) return false;
        const auto octet = strict_decimal(rest.substr(0, dot), 3, 255);
        if (!octet) return false;
        ip = (ip << 8) | *octet;
        if (!last) rest = rest.substr(dot + 1);
    }
    const auto in = [ip](uint32_t network, int prefix) {
        return (ip & (~uint32_t{0} << (32 - prefix))) == network;
    };
    if (in(0x0A000000, 8) || in(0xAC100000, 12) || in(0xC0A80000, 16) || in(0x64400000, 10)) {
        return true;
    }
    return allow_loopback && in(0x7F000000, 8);
}

bool is_loopback_ipv4(const std::string& address) {
    return address.rfind("127.", 0) == 0;
}

} // anonymous namespace

std::optional<std::vector<std::string>> parse_mesh_local_endpoints(const nlohmann::json& value,
                                                                   bool allow_loopback) {
    if (!value.is_array() || value.size() > kMaxMeshLocalEndpoints) return std::nullopt;
    std::vector<std::string> out;
    for (const auto& entry : value) {
        if (!entry.is_string()) return std::nullopt;
        const auto& text = entry.get_ref<const std::string&>();
        if (!local_endpoint_valid(text, allow_loopback)) return std::nullopt;
        if (std::find(out.begin(), out.end(), text) == out.end()) out.push_back(text);
    }
    return out;
}

MeshApiHandler::MeshApiHandler(ApiContext& ctx) : ctx_(ctx) {
    // Every Tier 1 server applies the same committed log, so each wakes its
    // own waiters when a change may alter someone's peer list.
    ctx_.tree.set_changed_hook([this] { waiters_.notify(); });
}

MeshApiHandler::~MeshApiHandler() {
    ctx_.tree.set_changed_hook({});
    waiters_.shutdown();
}

std::string MeshApiHandler::caller_peers_revision(const std::string& caller_pubkey,
                                                  const tree::TreeNode& node,
                                                  uint64_t now) const {
    std::vector<tree::TreeNode> endpoints;
    std::vector<tree::TreeNode> reachable;
    std::vector<const tree::TreeNode*> relays;
    std::unordered_map<std::string, std::vector<std::string>> local;
    if (!node.parent_id.empty()) {
        reachable = ctx_.tree.collect_subtree(node.parent_id);
        endpoints = connectable_endpoints(ctx_.tree.nodes_snapshot(), caller_pubkey, node,
                                          reachable);
        for (const auto& n : reachable) {
            if (n.type == tree::NodeType::Relay && mesh_peer_listed(ctx_.tree, caller_pubkey, n)) {
                relays.push_back(&n);
            }
        }
        for (const auto& n : endpoints) {
            if (auto lan = local_endpoints_of(n.id, now); !lan.empty()) {
                local.emplace(n.id, std::move(lan));
            }
        }
    }
    return peers_revision(endpoints, relays, build_mesh_handshake_map(ctx_.boringtun), local, now);
}

void MeshApiHandler::store_local_endpoints(const std::string& node_id,
                                           std::vector<std::string> endpoints, uint64_t now) {
    std::lock_guard lock(local_mtx_);
    // Entries of devices that stopped sending heartbeats go once per TTL, so
    // the map holds at most the devices heard from within two TTLs.
    if (now - local_pruned_at_ >= kMeshLocalEndpointTtlSec) {
        std::erase_if(local_endpoints_, [now](const auto& entry) {
            return now - entry.second.reported_at >= kMeshLocalEndpointTtlSec;
        });
        local_pruned_at_ = now;
    }
    bool changed = false;
    if (endpoints.empty()) {
        changed = local_endpoints_.erase(node_id) > 0;
    } else {
        auto& entry = local_endpoints_[node_id];
        changed = entry.endpoints != endpoints;
        entry = LocalEndpoints{std::move(endpoints), now};
    }
    // notify() takes only the waiters' own lock, so it may run under this one.
    if (changed) waiters_.notify();
}

std::vector<std::string> MeshApiHandler::local_endpoints_of(const std::string& node_id,
                                                            uint64_t now) const {
    std::lock_guard lock(local_mtx_);
    const auto found = local_endpoints_.find(node_id);
    if (found == local_endpoints_.end() ||
        now - found->second.reported_at >= kMeshLocalEndpointTtlSec) {
        return {};
    }
    return found->second.endpoints;
}

void MeshApiHandler::do_register_routes([[maybe_unused]] httplib::Server& pub,
                                        httplib::Server& priv) {
    using nexus::auth::require_auth;
    using nexus::auth::SessionClaims;

    // Each held peer list long-poll occupies one worker of the server that
    // serves the private routes, so that server gets room for every admitted
    // waiter plus the other private requests.
    priv.new_task_queue = [] { return new httplib::ThreadPool(kPrivateApiWorkerThreads); };

    // ========================================================================
    // GET /api/mesh/peers/:node_id (PRIVATE, auth required)
    //
    // Returns the server peer, the endpoints the requesting node may connect
    // to (tree::rules::endpoint_may_connect: a connect grant in the parent-group
    // subtree, or an invite membership), and the relays in that subtree that
    // mesh_peer_listed admits. Read on the requesting node lets the caller ask.
    //
    // Each peer entry carries `mgmt_pubkey`, the peer node's management
    // public key as the tree stores it, and `peer_permissions`: the sorted,
    // de-duplicated permission names (tree names and `svc:` service
    // permissions) that this key holds on the requesting node and on its
    // ancestor groups, plus "admin" when the peer administers the requesting
    // node (tree::rules::peer_permissions). Together they let the requesting
    // device attribute a connecting peer and decide what it may do; they
    // change nothing about who is listed.
    //
    // The answer carries `peers_revision`, the same value as the heartbeat
    // answer. Query `wait_revision=<revision>` makes the request a long-poll:
    // the server answers as soon as the caller's revision differs from it,
    // or after `timeout` seconds (default kMeshPeerWaitDefaultSec, at most
    // kMeshPeerWaitMaxSec) with the unchanged list. A committed tree change,
    // a changed LAN endpoint list, or a changed live session wakes it.
    // Beyond kMeshPeerWaitersMax held requests per server, or
    // kMeshPeerWaitersPerCaller per device, it answers 429 with Retry-After.
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

        // Check that the authenticated user has Read permission on this node
        // Permission assignments are keyed by the caller's pubkey (see the join
        // flow + createChildNode), NOT the user_id (which is a hash-derived node
        // id). Using user_id here made every Read check miss its assignment -> 403.
        auto caller_pubkey = normalize_pubkey(claims.pubkey);
        if (!ctx_.tree.check_permission(caller_pubkey, node_id, acl::Permission::Read)) {
            error_response(res, "insufficient permissions", 403);
            return;
        }

        // Long-poll: with `wait_revision`, hold the request until this
        // caller's peers_revision differs from it, or `timeout` seconds
        // pass, then answer the list as usual. The wait changes nothing about
        // who is listed: the answer is built after it, from the tree as it is
        // then, under the same checks.
        if (req.has_param("wait_revision")) {
            const auto wait_for = req.get_param_value("wait_revision");
            uint32_t timeout = kMeshPeerWaitDefaultSec;
            if (req.has_param("timeout")) {
                const auto text = req.get_param_value("timeout");
                uint32_t value = 0;
                const auto [ptr, ec] = std::from_chars(text.data(), text.data() + text.size(), value);
                if (ec != std::errc{} || ptr != text.data() + text.size() || value == 0) {
                    error_response(res, "timeout must be a positive number of seconds", 400);
                    return;
                }
                timeout = std::min(value, kMeshPeerWaitMaxSec);
            }
            if (wait_for.size() > 64) {
                error_response(res, "wait_revision is too long", 400);
                return;
            }
            MeshPeerWaiters::Refusal why = MeshPeerWaiters::Refusal::None;
            const auto slot = waiters_.try_admit(caller_pubkey, why);
            if (!slot) {
                res.set_header("Retry-After", "5");
                if (why == MeshPeerWaiters::Refusal::ShuttingDown) {
                    error_response(res, "the server is stopping", 503);
                } else {
                    error_response(res, "too many waiting peer list requests", 429);
                }
                return;
            }
            const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(timeout);
            for (;;) {
                // Read the generation first, so a change during the check
                // below wakes the wait instead of being lost.
                const auto seen = waiters_.generation();
                const auto current = ctx_.tree.get_node(node_id);
                if (!current || waiters_.shutting_down() ||
                    !ctx_.tree.check_permission(caller_pubkey, node_id, acl::Permission::Read) ||
                    caller_peers_revision(caller_pubkey, *current, epoch_seconds()) != wait_for) {
                    break;
                }
                const auto now = std::chrono::steady_clock::now();
                if (now >= deadline) break;
                // A peer's live session state follows handshake ages, which
                // change without a notification, so check again at least
                // every kMeshPeerRecheckMs.
                const auto left =
                    std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
                waiters_.wait(seen, std::min(left, std::chrono::milliseconds(kMeshPeerRecheckMs)));
            }
            node_opt = ctx_.tree.get_node(node_id);
            if (!node_opt) {
                error_response(res, "node not found", 404);
                return;
            }
            if (!ctx_.tree.check_permission(caller_pubkey, node_id, acl::Permission::Read)) {
                error_response(res, "insufficient permissions", 403);
                return;
            }
        }
        const auto& node = *node_opt;

        // Find the parent group to get all sibling nodes
        if (node.parent_id.empty()) {
            // Root node has no siblings — return just the server peer
            nlohmann::json j;
            j["node_id"] = node_id;
            j["peers"] = nlohmann::json::array();
            j["server_peer"] = build_server_peer();
            j["peers_revision"] = caller_peers_revision(caller_pubkey, node, epoch_seconds());
            json_response(res, j);
            return;
        }

        // Descendants of the caller's parent group (relays below), and the
        // endpoints the connect rule admits, including invite memberships.
        auto reachable = ctx_.tree.collect_subtree(node.parent_id);
        const auto nodes = ctx_.tree.nodes_snapshot();
        const auto endpoints = connectable_endpoints(nodes, caller_pubkey, node, reachable);

        // Use Noise handshake activity to determine peer liveness.
        auto mesh_handshakes = build_mesh_handshake_map(ctx_.boringtun);
        auto now = epoch_seconds();

        // What the peer's key holds toward the requesting node; the peer is
        // already listed, so this adds information and no reach.
        const auto names_toward_caller = [&](const tree::TreeNode& peer) {
            return tree::rules::peer_permissions(nodes, peer.mgmt_pubkey, node).names;
        };

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
            peer["node_id"]          = sibling.id;
            peer["hostname"]         = sibling.hostname;
            peer["mesh_pubkey"]      = sibling.mesh_pubkey;
            peer["tunnel_ip"]        = sibling.tunnel_ip;
            peer["private_subnet"]   = sibling.private_subnet;
            peer["endpoint"]         = sibling.listen_endpoint;
            // The peer's LAN addresses, from its own heartbeats to this
            // server. Only a listed peer's entry carries them.
            peer["local_endpoints"]  = local_endpoints_of(sibling.id, now);
            peer["relay_endpoint"]   = "";  // filled by relay discovery
            peer["is_online"]        = online;
            peer["last_seen"]        = last_seen;
            peer["mgmt_pubkey"]      = sibling.mgmt_pubkey;
            peer["peer_permissions"] = names_toward_caller(sibling);
            peers.push_back(std::move(peer));
        }

        // Also include Relay-type nodes in scope as potential relay endpoints
        for (const auto& sibling : reachable) {
            if (sibling.type != tree::NodeType::Relay) continue;
            if (!mesh_peer_listed(ctx_.tree, caller_pubkey, sibling)) continue;

            nlohmann::json peer;
            peer["node_id"]          = sibling.id;
            peer["hostname"]         = sibling.hostname;
            peer["mesh_pubkey"]      = sibling.mesh_pubkey;
            peer["tunnel_ip"]        = sibling.tunnel_ip;
            peer["private_subnet"]   = sibling.private_subnet;
            peer["endpoint"]         = sibling.listen_endpoint;
            peer["relay_endpoint"]   = sibling.listen_endpoint;
            peer["is_online"]        = true;  // relays are always considered online
            peer["is_relay"]         = true;
            peer["region"]           = sibling.region;
            peer["capacity_mbps"]    = sibling.capacity_mbps;
            peer["mgmt_pubkey"]      = sibling.mgmt_pubkey;
            peer["peer_permissions"] = names_toward_caller(sibling);
            peers.push_back(std::move(peer));
        }

        nlohmann::json j;
        j["node_id"]     = node_id;
        j["parent_id"]   = node.parent_id;
        j["peers"]       = std::move(peers);
        j["server_peer"] = build_server_peer();
        j["peers_revision"] = caller_peers_revision(caller_pubkey, node, now);
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
    // Body: { "node_id": "...", "endpoint": "ip:port",
    //         "local_endpoints"?: ["192.168.1.20:41234", ...] }
    // local_endpoints are the device's LAN addresses with its dataplane port
    // (parse_mesh_local_endpoints): private IPv4 addresses only, at most
    // kMaxMeshLocalEndpoints. A malformed list refuses the heartbeat. The
    // server keeps them in memory, not in the tree, for
    // kMeshLocalEndpointTtlSec, and lists them only in the peer entries of
    // callers that already list this node. An empty array removes them; an
    // absent field (an older client) leaves them as they are.
    // Response: { success, node_id, endpoint, status, peers_revision?,
    //             tier1_departure?: { next_epoch } }
    // peers_revision is an opaque string that changes when the caller's peer
    // list (GET /api/mesh/peers) gains or loses a peer, or when a listed
    // peer's mesh key, tunnel address, private subnet, endpoint, LAN
    // endpoints, hostname, or live session with this server changes
    // (peers_revision()). It is
    // present when the caller holds Read on its node, as the peer list
    // requires. A client compares it with the previous answer and fetches
    // its peers at once on a change, so a peer that joined or moved is seen
    // within one heartbeat instead of one peer refresh interval. It carries
    // no peer data: the peer list stays the only source of peers.
    // tier1_departure is present while this server is a Tier 1 member that
    // the finalized next-epoch plan does not name (ApiContext::tier1_departure).
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
        std::optional<std::vector<std::string>> hb_local;
        if (const auto field = body.find("local_endpoints"); field != body.end()) {
            hb_local = parse_mesh_local_endpoints(*field, is_loopback_ipv4(ctx_.server_public_ip));
            if (!hb_local) {
                error_response(res, "invalid local_endpoints (expected at most 4 private "
                                    "a.b.c.d:port addresses)");
                return;
            }
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
        // LAN endpoints follow the SetEndpoint rule: only the node's own
        // management key reports them.
        if (hb_local && (node_opt->mgmt_pubkey.empty() ||
                         tree::canonical_principal(node_opt->mgmt_pubkey) !=
                             tree::canonical_principal(normalize_pubkey(claims.pubkey)))) {
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
        // The owner check above passed, so the list belongs to this node.
        const auto now = epoch_seconds();
        if (hb_local) store_local_endpoints(hb_node_id, std::move(*hb_local), now);
        nlohmann::json j;
        j["success"]  = true;
        j["node_id"]  = hb_node_id;
        j["endpoint"] = hb_endpoint.empty() ? current->listen_endpoint : hb_endpoint;
        j["status"]   = status;
        const auto caller_pubkey = normalize_pubkey(claims.pubkey);
        if (ctx_.tree.check_permission(caller_pubkey, hb_node_id, acl::Permission::Read)) {
            j["peers_revision"] = caller_peers_revision(caller_pubkey, *current, now);
        }
        // A member that the finalized next-epoch plan leaves out says so, so
        // the client moves its session before this server's authority ends.
        // The client verifies the new membership itself; this names no server.
        if (ctx_.tier1_departure) {
            if (const auto next_epoch = ctx_.tier1_departure()) {
                j["tier1_departure"] = {{"next_epoch", *next_epoch}};
            }
        }
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
            for (const auto& s : connectable_endpoints(ctx_.tree.nodes_snapshot(), caller_pubkey,
                                                       node, reachable)) {
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
