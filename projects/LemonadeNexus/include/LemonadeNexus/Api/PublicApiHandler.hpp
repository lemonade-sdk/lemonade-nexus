#pragma once

#include <LemonadeNexus/Api/IRequestHandler.hpp>
#include <LemonadeNexus/Tree/TreeRules.hpp>

#include <cstddef>
#include <cstdint>
#include <mutex>

namespace nexus::gossip { class DevicePresence; }

namespace nexus::api {

/// Aggregate counts of the network for GET /api/stats. Counts only: no node
/// id, key, name, address, or owner.
struct NetworkCounts {
    std::size_t devices{0};         ///< device (Endpoint) nodes in the tree
    std::size_t devices_online{0};  ///< devices present within kDevicePresenceOnlineSec
    std::size_t groups{0};          ///< group (Customer) nodes
    std::size_t relays{0};          ///< relay nodes
};

/// Count `nodes` by type, and the devices that `presence` shows online at
/// `now` (Unix seconds). Reads `presence`; changes nothing.
[[nodiscard]] NetworkCounts count_network(const tree::rules::NodeMap& nodes,
                                          const gossip::DevicePresence& presence, uint64_t now);

/// Seconds a computed network count is reused. GET /api/stats is public, so
/// a burst of requests costs one tree snapshot per interval.
inline constexpr uint64_t kNetworkCountsCacheSec = 5;

/// Handles unauthenticated public endpoints: health, TLS status, stats, servers.
class PublicApiHandler : public IRequestHandler<PublicApiHandler> {
    friend class IRequestHandler<PublicApiHandler>;

public:
    explicit PublicApiHandler(ApiContext& ctx) : ctx_(ctx) {}

private:
    void do_register_routes(httplib::Server& pub, httplib::Server& priv);

    /// The network counts at `now`, computed at most once per
    /// kNetworkCountsCacheSec. Thread-safe.
    NetworkCounts network_counts(uint64_t now);

    ApiContext& ctx_;

    std::mutex     counts_mutex_;
    NetworkCounts  counts_;
    uint64_t       counts_at_{0};
};

} // namespace nexus::api
