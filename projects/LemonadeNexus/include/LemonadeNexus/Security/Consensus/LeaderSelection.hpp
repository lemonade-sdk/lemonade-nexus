#pragma once

// Deterministic leader order for one epoch.
//
// The order is a pure function of the frozen member set, the previous
// finalized checkpoint, and the epoch. Every correct node computes the same
// order; no operator selects a leader.
//
// Architecture reference: Security Architecture Final Draft 1.0, section 11.5.

#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <span>
#include <vector>

namespace nexus::security {

class LeaderSelection {
public:
    // A permutation of members, independent of their input order.
    [[nodiscard]] static std::vector<NodeId> order(std::span<const NodeId> members,
                                                   const Digest& previous_checkpoint,
                                                   EpochId epoch);

    // order[view mod N(E)]. An empty order is a programming error and throws.
    [[nodiscard]] static NodeId leader(const std::vector<NodeId>& order, View view);
};

}  // namespace nexus::security
