#pragma once

// The bridge from one attestation verdict to a Tier 1 evidence state.
//
// AttestationVerdict::passed says the platform chain held. It is NOT the Tier 1
// decision: Tier 1 also depends on facts attestation cannot see — the transport
// certificate, how long the node has been up, mesh health, and which epoch and
// incarnation are current. Those arrive through Tier1MeshFacts.
//
// Every prerequisite without a producer stays false, and Tier1EligibilityPolicy
// is a conjunction, so an unproven prerequisite makes the node ineligible. That
// is deliberate. Nothing here may infer a prerequisite from `passed`.

#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>
#include <LemonadeNexus/Security/Policy/Tier1Eligibility.hpp>

#include <optional>

namespace nexus::security {

/// What the mesh knows and attestation does not.
///
/// No platform provider may set any of these. VerifiedPlatformClaims carries no
/// field for them, so a provider cannot express one even by mistake: a platform
/// proves what its hardware attests, and how a node has behaved on the mesh is
/// not that.
///
/// Both mesh facts are produced by EligibilityService from signed observations
/// that a witness threshold of the current committee agreed on, and both stay
/// false until that threshold is met.
struct Tier1MeshFacts {
    /// The candidate holds a root-signed transport certificate.
    bool certificate_valid{false};

    /// Mesh-observed continuity, NOT /proc/uptime and not a node self-report.
    /// The agreed rule (1.1 section 13.1) is the same incarnation, at least two
    /// mesh-recognized attestations, and an observation interval of at least
    /// REATTEST_INTERVAL_SECONDS. It affects next-epoch eligibility only and
    /// never changes a current epoch's member count or quorum.
    bool uptime_valid{false};

    /// Mesh-observed protocol participation: the witness threshold saw the
    /// subject alive, authenticated, and speaking the current network, epoch,
    /// incarnation and rulesets, with no unresolved objective fault. Local
    /// load, ping latency and self-reported health are not inputs.
    ///
    /// It is NOT a synchronization proof. A current member's votes do happen to
    /// prove it holds current consensus state, but a candidate proves
    /// participation by answering a challenge, and echoing an anchor is receipt
    /// rather than possession. Security-state possession is proved separately,
    /// once, during next-epoch adoption (CandidateStateProof).
    bool mesh_health_valid{false};

    /// The epoch and incarnation the mesh currently considers live. A verdict
    /// for any other epoch or incarnation is stale and cannot confer Tier 1.
    std::optional<EpochId> current_epoch;
    std::optional<IncarnationId> current_incarnation;
};

/// Map one verdict plus the mesh facts onto the thirteen prerequisites.
[[nodiscard]] Tier1EvidenceState tier1_evidence_state(const AttestationVerdict& verdict,
                                                       const Tier1MeshFacts& facts);

/// The full decision. Equivalent to evaluating the state above, and the only
/// call a caller should need.
[[nodiscard]] Tier1Eligibility tier1_eligibility(const AttestationVerdict& verdict,
                                                  const Tier1MeshFacts& facts);

/// Human-readable name for one prerequisite, for logs and diagnostics.
[[nodiscard]] std::string_view tier1_prerequisite_name(Tier1Prerequisite prerequisite);

}  // namespace nexus::security
