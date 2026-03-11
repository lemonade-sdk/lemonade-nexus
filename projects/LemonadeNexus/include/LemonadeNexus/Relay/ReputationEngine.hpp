#pragma once

#include <LemonadeNexus/Relay/RelayTypes.hpp>

#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace nexus::relay {

/// Utility class that computes and tracks relay reputation scores.
///
/// Scores are in the range [0.0, 1.0].  A relay with a score below 0.3 is
/// considered unreliable and should be suspended from selection.
class ReputationEngine {
public:
    /// Compute a composite reputation score from raw metrics.
    ///
    /// @param uptime_ratio        Fraction of time the relay was reachable [0,1]
    /// @param loss_rate           Fraction of packets lost [0,1]
    /// @param latency_consistency 1.0 = perfectly consistent, 0.0 = wildly varying
    /// @param peer_rating         Average peer-reported rating [0,1]
    /// @return A blended score in [0, 1].
    [[nodiscard]] float compute_score(float uptime_ratio,
                                      float loss_rate,
                                      float latency_consistency,
                                      float peer_rating) const;

    /// Return true if the relay should be suspended from selection.
    [[nodiscard]] bool should_suspend(float score) const;

    /// Record a quality report for the given relay.
    void record_quality_report(const RelayQualityReport& report);

    /// Retrieve the current aggregated score for a relay.
    /// Returns 0.0 if no reports are available.
    [[nodiscard]] float get_score(std::string_view relay_id) const;

private:
    /// Derive a score from stored reports for a single relay.
    [[nodiscard]] float aggregate_reports(const std::vector<RelayQualityReport>& reports) const;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, std::vector<RelayQualityReport>> reports_;
};

} // namespace nexus::relay
