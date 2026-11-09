#pragma once

#include <LemonadeNexus/Api/IRequestHandler.hpp>
#include <LemonadeNexus/Api/MeshPeerWaiters.hpp>
#include <LemonadeNexus/Gossip/DevicePresence.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>

#include <cstdint>
#include <memory>
#include <mutex>
#include <thread>
#include <optional>
#include <string>
#include <string_view>
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

/// Most LAN endpoints one heartbeat may report: what a device's presence
/// carries (gossip::kDevicePresenceMaxLanEndpoints).
inline constexpr std::size_t kMaxMeshLocalEndpoints = gossip::kDevicePresenceMaxLanEndpoints;

/// Route of the private event socket (see MeshApiHandler).
inline constexpr const char* kMeshEventsRoute = "/api/events";

/// The devices revision of a session: an opaque value that changes when the
/// device list the SDK reads for it changes, that is GET /api/tree/memberships
/// and GET /api/tree/devices/{group} for each listed group. XXH3 over those
/// answers; a change detector, not a security value.
[[nodiscard]] std::string devices_revision(const tree::PermissionTreeService& tree,
                                           const auth::SessionClaims& claims);

/// How long the servers list the LAN endpoints of a heartbeat, in seconds
/// (gossip::kDevicePresenceLanTtlSec). Every heartbeat of a current client
/// reports them again, so they disappear from the peer lists this long after
/// the device stops sending heartbeats.
inline constexpr uint64_t kMeshLocalEndpointTtlSec = gossip::kDevicePresenceLanTtlSec;

/// Parse the `local_endpoints` of a mesh heartbeat: a JSON array of at most
/// kMaxMeshLocalEndpoints strings that pass
/// gossip::presence_lan_endpoint_valid: each "a.b.c.d:port" with decimal
/// octets without leading zeros and a port from 1 to 65535, and a private
/// address (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, or 100.64.0.0/10,
/// the shared address space). A loopback address (127.0.0.0/8) is accepted
/// only with `allow_loopback` (a single-host deployment whose server address
/// is loopback). A repeated entry is dropped. Returns nullopt when the value
/// is not such an array or any entry fails. Pure.
[[nodiscard]] std::optional<std::vector<std::string>> parse_mesh_local_endpoints(
    const nlohmann::json& value, bool allow_loopback);

/// Handles mesh networking endpoints: peer discovery and heartbeat reporting.
///
/// A device is present at this server while it sends authenticated
/// heartbeats or holds an open event socket; the gossip service's
/// DevicePresence table holds that time, the LAN endpoints the heartbeat
/// reported, and what other Tier 1 servers share of both. The peer list
/// reports a listed device's `is_online`, `last_seen`, and `local_endpoints`
/// from that table, so a device on another Tier 1 server reads online with
/// its LAN endpoints too.
class MeshApiHandler : public IRequestHandler<MeshApiHandler> {
    friend class IRequestHandler<MeshApiHandler>;

public:
    /// Registers a tree changed hook and a device presence hook that wake the
    /// peer list long-polls and the event sockets; the destructor clears
    /// both. One handler per tree and gossip service.
    explicit MeshApiHandler(ApiContext& ctx);
    ~MeshApiHandler();
    MeshApiHandler(const MeshApiHandler&)            = delete;
    MeshApiHandler& operator=(const MeshApiHandler&) = delete;

    /// The long-poll admission and wake-up state (tests read and tune it).
    [[nodiscard]] MeshPeerWaiters& peer_waiters() { return waiters_; }

    /// Event sockets open now.
    [[nodiscard]] std::size_t event_sockets() const;

private:
    void do_register_routes(httplib::Server& pub, httplib::Server& priv);

    /// The peers_revision of `node`'s peer list for `caller_pubkey` at `now`
    /// (Unix seconds), computed as the heartbeat answer and GET
    /// /api/mesh/peers report it. `caller_pubkey` must be normalized and hold
    /// Read on `node`. Thread-safe.
    [[nodiscard]] std::string caller_peers_revision(const std::string& caller_pubkey,
                                                    const tree::TreeNode& node,
                                                    uint64_t now) const;

    /// Build the server peer JSON entry (always included in peer lists).
    [[nodiscard]] nlohmann::json build_server_peer() const;

    ApiContext& ctx_;

    MeshPeerWaiters waiters_;

    // Event sockets. One thread (events_loop) sends every socket's events;
    // each socket's own server thread only reads, so a close is seen at once.
    struct EventSocket;
    void events_loop();
    /// Checks one socket's session and revisions and sends what changed. A
    /// socket whose session owns its node counts as that device's presence.
    /// Returns false when the socket must close.
    bool update_event_socket(EventSocket& socket, uint64_t now);
    mutable std::mutex                        events_mtx_;
    std::vector<std::shared_ptr<EventSocket>> event_sockets_;
    bool                                      events_stopping_{false};  // guarded by events_mtx_
    std::thread                               events_thread_;
};

} // namespace nexus::api
