#include <LemonadeNexus/Security/Consensus/LeaderSelection.hpp>

#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace nexus::security {

// The architecture pseudo-code concatenates seed inputs; this implementation
// defines the exact serialization through CanonicalEncoder.
std::vector<NodeId> LeaderSelection::order(std::span<const NodeId> members,
                                           const Digest& previous_checkpoint,
                                           EpochId epoch) {
    CanonicalEncoder seed_encoder(constants::kLeaderOrderDomain);
    seed_encoder.add_string("seed");
    seed_encoder.add_bytes(previous_checkpoint);
    seed_encoder.add_u64(epoch);
    const Digest seed = seed_encoder.digest();

    std::vector<std::pair<Digest, NodeId>> scored;
    scored.reserve(members.size());
    for (const auto& member : members) {
        CanonicalEncoder score_encoder(constants::kLeaderOrderDomain);
        score_encoder.add_string("score");
        score_encoder.add_bytes(seed);
        score_encoder.add_bytes(member.span());
        scored.emplace_back(score_encoder.digest(), member);
    }

    // The node_id tiebreak makes the order total, so it cannot depend on the
    // input order.
    std::sort(scored.begin(), scored.end());

    std::vector<NodeId> result;
    result.reserve(scored.size());
    for (const auto& [score, member] : scored) {
        result.push_back(member);
    }
    return result;
}

NodeId LeaderSelection::leader(const std::vector<NodeId>& order, View view) {
    if (order.empty()) {
        throw std::invalid_argument("leader order is empty");
    }
    return order[view % order.size()];
}

}  // namespace nexus::security
