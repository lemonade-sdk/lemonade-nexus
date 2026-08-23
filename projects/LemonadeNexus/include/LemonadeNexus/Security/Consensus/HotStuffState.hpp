#pragma once

// Durable BFT safety state.
//
// A node writes these values to disk before any vote leaves it. After a
// restart they bound what the node may still vote on. The JSON form fails
// closed: one malformed field yields no state at all, never a partial one —
// a partial state is how a node forgets a vote it already cast.
//
// Architecture reference: Security Architecture Final Draft 1.0, sections
// 11.6 and 11.12.

#include <LemonadeNexus/Security/Consensus/ConsensusTypes.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <nlohmann/json_fwd.hpp>

#include <optional>

namespace nexus::security {

struct HotStuffState {
    EpochId epoch = 0;
    ConsensusRulesetVersion consensus_ruleset = constants::kConsensusRulesetVersion;
    View last_voted_view = 0;
    QuorumCertificate high_qc{};
    QuorumCertificate locked_qc{};
};

// Digests, keys, and signatures encode as base64. Both certificates carry
// every header field and the full signer list.
[[nodiscard]] nlohmann::json hotstuff_state_to_json(const HotStuffState& state);

// nullopt on ANY malformed field.
[[nodiscard]] std::optional<HotStuffState> hotstuff_state_from_json(
    const nlohmann::json& document);

}  // namespace nexus::security
