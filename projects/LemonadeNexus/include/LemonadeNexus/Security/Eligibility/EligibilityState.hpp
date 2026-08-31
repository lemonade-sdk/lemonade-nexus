#pragma once

// The deterministic eligibility facts for one epoch boundary.
//
// Selection must start from state every honest node agrees on, so this object
// carries only facts a quorum produced: mesh observations, proved faults, the
// root-signed transport certificate, and platform claims a passing attestation
// left behind. A verdict that proved nothing contributes a zero claims digest
// rather than the reason it failed — two verifiers can fail one candidate
// differently and still have to arrive at the same state.
//
// The digest is what HotStuff finalizes. Nothing here decides anything:
// `eligible` is the Tier1EligibilityPolicy result the caller already computed,
// recorded so the decision itself is part of what consensus commits.

#include <LemonadeNexus/Security/Attestation/VerifiedPlatformClaims.hpp>
#include <LemonadeNexus/Security/Eligibility/EligibilityObservation.hpp>

#include <cstdint>
#include <vector>

namespace nexus::security {

/// One candidate's finalized facts.
struct EligibilityRecord {
    NodeId subject{};
    IncarnationId incarnation{};

    bool uptime_valid{false};
    bool mesh_health_valid{false};
    bool certificate_valid{false};

    /// Zero when the platform proved nothing. See platform_claims_digest.
    Digest platform_claims{};

    /// One bit per ObjectiveFault. Faults are proved, so this is evidence
    /// rather than an opinion, and it travels inside the finalized digest.
    uint32_t faults{0};

    bool eligible{false};

    auto operator<=>(const EligibilityRecord&) const = default;
};

[[nodiscard]] uint32_t objective_fault_bit(ObjectiveFault fault);

/// The claims, as one digest. Zero unless every required claim is proved and
/// the set is self-consistent: a partial proof is not a smaller proof.
[[nodiscard]] Digest platform_claims_digest(const VerifiedPlatformClaims& claims);

struct EligibilityState {
    NetworkId network_id{};

    /// The epoch whose observations produced this state.
    EpochId epoch{};
    /// The epoch this state decides membership for.
    EpochId next_epoch{};

    SecurityRulesetVersion security_ruleset{};
    ConsensusRulesetVersion consensus_ruleset{};

    /// The frozen observer set, as its participant-set digest, with the quorum
    /// that judged these facts. Both are inside the digest so a state cannot be
    /// replayed against a different membership.
    Digest observer_set{};
    std::size_t quorum{};

    /// One record per candidate, sorted by subject.
    std::vector<EligibilityRecord> records;
};

[[nodiscard]] Digest eligibility_state_digest(const EligibilityState& state);

/// What consensus commits. It is the transitions digest of the block that
/// finalizes this state, so a replica votes for it only when it independently
/// arrived at the same facts.
[[nodiscard]] Digest eligibility_commitment_digest(const EligibilityState& state);

/// The candidates the state marks eligible, in sorted order.
[[nodiscard]] std::vector<NodeId> eligible_nodes(const EligibilityState& state);

}  // namespace nexus::security
