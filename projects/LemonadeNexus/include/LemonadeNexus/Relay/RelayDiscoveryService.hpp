#pragma once

#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Relay/IRelayDiscovery.hpp>
#include <LemonadeNexus/Relay/RelayTypes.hpp>
#include <LemonadeNexus/Relay/ReputationEngine.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace nexus::relay {

/// Concrete relay discovery service.
/// Reads relay node descriptors from the file-based tree storage and selects
/// the best relay by sorting on reputation score and estimated latency.
class RelayDiscoveryService : public core::IService<RelayDiscoveryService>,
                                public IRelayDiscovery<RelayDiscoveryService> {
    friend class core::IService<RelayDiscoveryService>;
    friend class IRelayDiscovery<RelayDiscoveryService>;

public:
    explicit RelayDiscoveryService(storage::FileStorageService& storage);

    // -- IService --
    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "RelayDiscoveryService"; }

    // -- IRelayDiscovery --
    [[nodiscard]] std::vector<RelayNodeInfo> do_discover_relays(
            const RelaySelectionCriteria& criteria) const;
    [[nodiscard]] std::optional<RelayNodeInfo> do_select_best_relay(
            const RelaySelectionCriteria& criteria) const;
    void do_report_relay_quality(const RelayQualityReport& report);
    [[nodiscard]] bool do_is_relay_trusted(std::string_view relay_id) const;
    [[nodiscard]] std::vector<std::string> do_get_stun_servers() const;
    void do_refresh_relay_list();

private:
    /// Parse a single relay node from a JSON envelope stored on disk.
    [[nodiscard]] static std::optional<RelayNodeInfo> parse_relay_node(
            const std::string& json_data);

    storage::FileStorageService& storage_;
    ReputationEngine             reputation_;

    mutable std::mutex               mutex_;
    std::vector<RelayNodeInfo>       known_relays_;
    std::unordered_set<std::string>  trusted_relay_ids_;
};

} // namespace nexus::relay
