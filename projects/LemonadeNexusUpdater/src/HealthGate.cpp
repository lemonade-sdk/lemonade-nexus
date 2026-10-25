#include <LemonadeNexusUpdater/HealthGate.hpp>

namespace nexus::updater {

HealthResult evaluate_health(const ServerHealth& baseline, const std::optional<ServerHealth>& now,
                             uint64_t expected_release) {
    if (!now) return {HealthVerdict::Pending, "the server does not answer yet"};
    const auto& s = *now;
    if (s.running_release != expected_release) {
        return {HealthVerdict::Failed, "the server runs release " +
                                           std::to_string(s.running_release) + ", expected " +
                                           std::to_string(expected_release)};
    }
    if (s.driver_failed) {
        return {HealthVerdict::Failed, "the security driver failed (" + s.driver_phase + ")"};
    }
    if (!s.healthy) {
        return {HealthVerdict::Pending, "the server holds no verified epoch authority yet"};
    }
    if (baseline.tier1_member) {
        if (!s.tier1_member || !s.epoch) {
            return {HealthVerdict::Pending, "the server is not a Tier 1 member again"};
        }
        if (baseline.epoch && *s.epoch < *baseline.epoch) {
            return {HealthVerdict::Pending, "the server has not resumed the current epoch"};
        }
    }
    // The tree log starts only after the data key unlocks, so a locked key
    // (pending quorum) skips this check instead of waiting on it.
    if (baseline.tree && s.data_key != "locked") {
        if (!s.tree) return {HealthVerdict::Pending, "the tree log has not started"};
        if (!s.tree->healthy) return {HealthVerdict::Failed, "the tree log halted"};
        if (s.tree->behind || s.tree->held != 0 || s.tree->applied_height != s.tree->height ||
            s.tree->height < baseline.tree->height) {
            return {HealthVerdict::Pending, "the tree log has not caught up"};
        }
    }
    return {HealthVerdict::Healthy, "healthy on release " + std::to_string(expected_release)};
}

}  // namespace nexus::updater
