#include <LemonadeNexusUpdater/HealthGate.hpp>

namespace nexus::updater {

HealthResult evaluate_health(const update::UpdateServerStatus& baseline,
                             const std::optional<update::UpdateServerStatus>& now,
                             const HealthExpectation& expected) {
    if (!now) return {HealthVerdict::Pending, "the server does not answer yet"};
    const auto& s = *now;
    if (s.version != expected.version) {
        return {HealthVerdict::Failed,
                "the server reports version " + s.version + ", expected " + expected.version};
    }
    if (s.release_id != expected.release_id ||
        s.approval_digest_hex != expected.approval_digest_hex) {
        return {HealthVerdict::Failed, "the server has not loaded the new release approval"};
    }
    if (!s.storage_files_ready) {
        return {HealthVerdict::Pending, "the data key is not unlocked"};
    }
    if (baseline.tier1_member) {
        if (!s.epoch_known || !s.tier1_member) {
            return {HealthVerdict::Pending, "the server is not a Tier 1 member again"};
        }
        if (s.epoch < baseline.epoch) {
            return {HealthVerdict::Pending, "the server has not resumed the current epoch"};
        }
    }
    if (baseline.tree_enabled) {
        if (!s.tree_enabled) {
            return {HealthVerdict::Failed, "the tree log is disabled after the update"};
        }
        if (!s.tree_healthy) return {HealthVerdict::Failed, "the tree log halted"};
        if (s.tree_behind || s.tree_held != 0 || s.tree_applied_height != s.tree_height ||
            s.tree_height < baseline.tree_height) {
            return {HealthVerdict::Pending, "the tree log has not caught up"};
        }
    }
    return {HealthVerdict::Healthy, "healthy on " + expected.version};
}

}  // namespace nexus::updater
