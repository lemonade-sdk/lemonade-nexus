#pragma once

// Deterministic Tier 1 population targeting.
//
// A shortfall is recorded, never repaired: the active target can shrink to the
// eligible pool, but no shortfall lowers a quorum formula. Quorums always use
// the frozen epoch population N(E), computed elsewhere from the selected set.

#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <cstddef>

namespace nexus::security {

struct Tier1TargetOutcome {
    std::size_t desired = 0;
    std::size_t active_target = 0;

    bool target_shortfall = false;
    bool reserve_shortfall = false;
};

[[nodiscard]] constexpr Tier1TargetOutcome tier1_target_outcome(std::size_t admitted_servers,
                                                                std::size_t eligible_count) {
    Tier1TargetOutcome outcome{};
    outcome.desired = constants::tier1_target_count(admitted_servers);
    outcome.active_target = eligible_count < outcome.desired ? eligible_count : outcome.desired;
    outcome.target_shortfall = eligible_count < outcome.desired;
    outcome.reserve_shortfall = eligible_count < outcome.desired + constants::kMinTier1Reserve;
    return outcome;
}

}  // namespace nexus::security
