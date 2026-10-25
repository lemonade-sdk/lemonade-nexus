#pragma once

// The health gate after a swap or a reboot (design Phase 4 step 7).
//
// The gate compares the server's health report ({"op":"health"} on the
// upgrade control socket) after the update with a baseline taken before it:
//   - release: the server runs the new release (running_release is the new
//     release number, read from the packaged approval it loaded and verified);
//   - health: the security driver has not failed and the server holds
//     verified epoch authority. This is the Healthy flag the Tier 1 witnesses
//     require before they record the server as upgraded;
//   - epoch role: a server that was a Tier 1 member before is a member again,
//     in the same or a later epoch. The mesh admits a member only after it
//     verifies the member's attestation;
//   - tree log: a log that was running is healthy, not behind, holds no
//     pending entries, has applied every entry, and has reached at least the
//     baseline height.
//
// The data key state is information only. During a rollout a server can stay
// locked until enough storage holders run the new release (pending quorum);
// that is not a failure, and the gate neither fails nor waits on it. The tree
// log starts only after the unlock, so a locked server skips the tree check.
//
// A wrong release, a failed driver, or a halted tree log fails at once.
// Anything else that is not yet true is pending until the deadline, then
// fails.

#include <LemonadeNexusUpdater/ControlClient.hpp>

#include <cstdint>
#include <optional>
#include <string>

namespace nexus::updater {

enum class HealthVerdict { Healthy, Pending, Failed };

struct HealthResult {
    HealthVerdict verdict{HealthVerdict::Pending};
    std::string reason;
};

/// `now` is nullopt while the server does not answer (still starting).
[[nodiscard]] HealthResult evaluate_health(const ServerHealth& baseline,
                                           const std::optional<ServerHealth>& now,
                                           uint64_t expected_release);

}  // namespace nexus::updater
