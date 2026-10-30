#pragma once

#include <LemonadeNexus/Api/IRequestHandler.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>

#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace nexus::api {

/// Decide whether the mesh peer list of `caller_pubkey` includes `peer`.
///
/// The client adds every listed peer to its dataplane, so a listed peer is a
/// peer the caller can reach. An Endpoint is listed only when the caller holds
/// ConnectPrivate or ConnectShared on that node. This is the per-node rule of
/// PermissionTreeService::resolve_authorized. Read alone lets the caller see a
/// node in the tree; it does not let the caller connect to it. Permissions are
/// not inherited, so an assignment on a parent group does not count.
///
/// A Relay is listed when the caller holds Read on it: a relay carries traffic
/// for others, and the relay protocol authorizes each relay session.
///
/// The caller must already limit `peer` to the requester's parent-group
/// subtree and exclude the requester's own node. `caller_pubkey` must be
/// normalized. Returns false for every other node type. Thread-safe.
///
/// GET /api/mesh/peers lists endpoints with tree::rules::endpoint_may_connect,
/// which applies this per-node rule inside the parent-group subtree and also
/// admits the endpoints an invite membership covers. Relays use this function.
[[nodiscard]] bool mesh_peer_listed(const tree::PermissionTreeService& tree,
                                    std::string_view caller_pubkey,
                                    const tree::TreeNode& peer);

/// Most LAN endpoints one heartbeat may report.
inline constexpr std::size_t kMaxMeshLocalEndpoints = 4;

/// How long the server lists the LAN endpoints of a heartbeat, in seconds.
/// Every heartbeat of a current client reports them again, so they disappear
/// from the peer lists this long after the device stops sending heartbeats.
inline constexpr uint64_t kMeshLocalEndpointTtlSec = 120;

/// Parse the `local_endpoints` of a mesh heartbeat: a JSON array of at most
/// kMaxMeshLocalEndpoints strings, each "a.b.c.d:port" with decimal octets
/// without leading zeros and a port from 1 to 65535. Each address must be
/// private: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, or 100.64.0.0/10
/// (shared address space). A loopback address (127.0.0.0/8) is accepted only
/// with `allow_loopback` (a single-host deployment whose server address is
/// loopback). A repeated entry is dropped. Returns nullopt when the value is
/// not such an array or any entry fails. Pure.
[[nodiscard]] std::optional<std::vector<std::string>> parse_mesh_local_endpoints(
    const nlohmann::json& value, bool allow_loopback);

/// Handles mesh networking endpoints: peer discovery and heartbeat reporting.
class MeshApiHandler : public IRequestHandler<MeshApiHandler> {
    friend class IRequestHandler<MeshApiHandler>;

public:
    explicit MeshApiHandler(ApiContext& ctx) : ctx_(ctx) {}

private:
    void do_register_routes(httplib::Server& pub, httplib::Server& priv);

    /// Build the server peer JSON entry (always included in peer lists).
    [[nodiscard]] nlohmann::json build_server_peer() const;

    /// Store the LAN endpoints that `node_id`'s owner reported at `now`
    /// (Unix seconds). An empty list removes the entry. Thread-safe.
    void store_local_endpoints(const std::string& node_id, std::vector<std::string> endpoints,
                               uint64_t now);

    /// The LAN endpoints `node_id` reported within kMeshLocalEndpointTtlSec
    /// of `now`; empty when none. Thread-safe.
    [[nodiscard]] std::vector<std::string> local_endpoints_of(const std::string& node_id,
                                                              uint64_t now) const;

    ApiContext& ctx_;

    /// LAN endpoints by node id. Runtime state of this server only: it is
    /// not part of the tree and is not replicated, so a peer list shows the
    /// LAN endpoints of the devices whose heartbeats reach this server.
    struct LocalEndpoints {
        std::vector<std::string> endpoints;
        uint64_t                 reported_at{0};  ///< Unix seconds
    };
    mutable std::mutex                              local_mtx_;
    std::unordered_map<std::string, LocalEndpoints> local_endpoints_;
    uint64_t                                        local_pruned_at_{0};
};

} // namespace nexus::api
