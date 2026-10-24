#pragma once

// The health gate after a swap or a reboot (design Phase 4 step 7).
//
// The gate compares the server's status after the update with a baseline
// taken before it, through the server's update control socket:
//   - version and approval: the server runs the new version and has loaded
//     and verified the new approval (release_id and digest);
//   - storage: the data key is unlocked;
//   - epoch role and attestation: a server that was a Tier 1 member before is
//     a member again, in the same or a later epoch. The mesh admits a member
//     only after it verifies the member's attestation, so this is the
//     attestation check. There is no self-attestation; a Tier 2 server has
//     no epoch role and no attestation requirement here;
//   - tree log: a log that was enabled is healthy, not behind, holds no
//     pending entries, has applied every entry, and has reached at least the
//     baseline height.
//
// A wrong version or approval, or a halted tree log, fails at once. Anything
// else that is not yet true is pending until the deadline, then fails.

#include <LemonadeNexus/Update/UpdateControl.hpp>

#include <optional>
#include <string>

namespace nexus::updater {

struct HealthExpectation {
    std::string version;
    std::string release_id;
    std::string approval_digest_hex;
};

enum class HealthVerdict { Healthy, Pending, Failed };

struct HealthResult {
    HealthVerdict verdict{HealthVerdict::Pending};
    std::string reason;
};

/// `now` is nullopt while the server does not answer (still starting).
[[nodiscard]] HealthResult evaluate_health(const update::UpdateServerStatus& baseline,
                                           const std::optional<update::UpdateServerStatus>& now,
                                           const HealthExpectation& expected);

}  // namespace nexus::updater
