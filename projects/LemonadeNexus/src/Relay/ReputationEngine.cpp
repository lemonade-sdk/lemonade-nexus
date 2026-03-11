#include <LemonadeNexus/Relay/ReputationEngine.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cmath>
#include <numeric>

namespace nexus::relay {

// ---------------------------------------------------------------------------
// Score computation
// ---------------------------------------------------------------------------

float ReputationEngine::compute_score(float uptime_ratio,
                                       float loss_rate,
                                       float latency_consistency,
                                       float peer_rating) const {
    // Clamp inputs to [0, 1]
    uptime_ratio        = std::clamp(uptime_ratio, 0.0f, 1.0f);
    loss_rate           = std::clamp(loss_rate, 0.0f, 1.0f);
    latency_consistency = std::clamp(latency_consistency, 0.0f, 1.0f);
    peer_rating         = std::clamp(peer_rating, 0.0f, 1.0f);

    // Weighted blend -- uptime and loss are the strongest signals
    constexpr float kWeightUptime     = 0.30f;
    constexpr float kWeightLoss       = 0.30f;
    constexpr float kWeightLatency    = 0.20f;
    constexpr float kWeightPeerRating = 0.20f;

    float score = kWeightUptime     * uptime_ratio
                + kWeightLoss       * (1.0f - loss_rate)
                + kWeightLatency    * latency_consistency
                + kWeightPeerRating * peer_rating;

    return std::clamp(score, 0.0f, 1.0f);
}

// ---------------------------------------------------------------------------
// Suspension threshold
// ---------------------------------------------------------------------------

bool ReputationEngine::should_suspend(float score) const {
    return score < 0.3f;
}

// ---------------------------------------------------------------------------
// Report recording
// ---------------------------------------------------------------------------

void ReputationEngine::record_quality_report(const RelayQualityReport& report) {
    std::lock_guard lock(mutex_);

    auto& bucket = reports_[report.relay_id];
    bucket.push_back(report);

    // Keep at most the last 100 reports per relay to bound memory
    static constexpr std::size_t kMaxReports = 100;
    if (bucket.size() > kMaxReports) {
        bucket.erase(bucket.begin(),
                     bucket.begin() + static_cast<std::ptrdiff_t>(bucket.size() - kMaxReports));
    }

    spdlog::debug("ReputationEngine: recorded report for relay {} (total {})",
                  report.relay_id, bucket.size());
}

// ---------------------------------------------------------------------------
// Score lookup
// ---------------------------------------------------------------------------

float ReputationEngine::get_score(std::string_view relay_id) const {
    std::lock_guard lock(mutex_);

    auto it = reports_.find(std::string(relay_id));
    if (it == reports_.end() || it->second.empty()) {
        return 0.0f;
    }

    return aggregate_reports(it->second);
}

// ---------------------------------------------------------------------------
// Internal aggregation
// ---------------------------------------------------------------------------

float ReputationEngine::aggregate_reports(
        const std::vector<RelayQualityReport>& reports) const {
    if (reports.empty()) {
        return 0.0f;
    }

    // Compute averages from recent reports
    float total_loss      = 0.0f;
    float total_latency   = 0.0f;
    float total_jitter    = 0.0f;
    float clean_sessions  = 0.0f;

    for (const auto& r : reports) {
        total_loss    += r.packet_loss_rate;
        total_latency += r.avg_latency_ms;
        total_jitter  += r.jitter_ms;
        if (r.session_completed_cleanly) {
            clean_sessions += 1.0f;
        }
    }

    const auto n = static_cast<float>(reports.size());
    const float avg_loss    = total_loss / n;
    const float avg_latency = total_latency / n;
    const float avg_jitter  = total_jitter / n;
    const float uptime      = clean_sessions / n;

    // Derive latency consistency: lower jitter relative to latency = more consistent
    // If avg_latency is near zero, treat as perfect consistency.
    float latency_consistency = 1.0f;
    if (avg_latency > 1.0f) {
        latency_consistency = std::clamp(1.0f - (avg_jitter / avg_latency), 0.0f, 1.0f);
    }

    // Use uptime as both the uptime_ratio and peer_rating proxy
    return compute_score(uptime, avg_loss, latency_consistency, uptime);
}

} // namespace nexus::relay
