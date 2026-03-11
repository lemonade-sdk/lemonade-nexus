#pragma once

#include <LemonadeNexus/Relay/RelayTypes.hpp>

#include <concepts>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::relay {

/// CRTP base for relay discovery and selection.
/// Derived must implement:
///   std::vector<RelayNodeInfo> do_discover_relays(const RelaySelectionCriteria& criteria) const
///   std::optional<RelayNodeInfo> do_select_best_relay(const RelaySelectionCriteria& criteria) const
///   void do_report_relay_quality(const RelayQualityReport& report)
///   bool do_is_relay_trusted(std::string_view relay_id) const
///   std::vector<std::string> do_get_stun_servers() const
///   void do_refresh_relay_list()
template <typename Derived>
class IRelayDiscovery {
public:
    /// Discover relay nodes matching the given criteria.
    [[nodiscard]] std::vector<RelayNodeInfo> discover_relays(
            const RelaySelectionCriteria& criteria) const {
        return self().do_discover_relays(criteria);
    }

    /// Select the single best relay for the given criteria.
    [[nodiscard]] std::optional<RelayNodeInfo> select_best_relay(
            const RelaySelectionCriteria& criteria) const {
        return self().do_select_best_relay(criteria);
    }

    /// Report quality observations for a relay.
    void report_relay_quality(const RelayQualityReport& report) {
        self().do_report_relay_quality(report);
    }

    /// Check whether a relay is in the trusted set.
    [[nodiscard]] bool is_relay_trusted(std::string_view relay_id) const {
        return self().do_is_relay_trusted(relay_id);
    }

    /// Return a list of known STUN server endpoints.
    [[nodiscard]] std::vector<std::string> get_stun_servers() const {
        return self().do_get_stun_servers();
    }

    /// Refresh the local relay list from storage.
    void refresh_relay_list() {
        self().do_refresh_relay_list();
    }

protected:
    ~IRelayDiscovery() = default;

private:
    [[nodiscard]] Derived& self() { return static_cast<Derived&>(*this); }
    [[nodiscard]] const Derived& self() const { return static_cast<const Derived&>(*this); }
};

/// Concept constraining a valid IRelayDiscovery implementation.
template <typename T>
concept RelayDiscoveryType = requires(T t, const T ct,
                                       const RelaySelectionCriteria& criteria,
                                       const RelayQualityReport& report,
                                       std::string_view sv) {
    { ct.do_discover_relays(criteria) } -> std::same_as<std::vector<RelayNodeInfo>>;
    { ct.do_select_best_relay(criteria) } -> std::same_as<std::optional<RelayNodeInfo>>;
    { t.do_report_relay_quality(report) } -> std::same_as<void>;
    { ct.do_is_relay_trusted(sv) } -> std::same_as<bool>;
    { ct.do_get_stun_servers() } -> std::same_as<std::vector<std::string>>;
    { t.do_refresh_relay_list() } -> std::same_as<void>;
};

} // namespace nexus::relay
