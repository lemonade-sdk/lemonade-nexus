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
/// `uptime_valid` and `mesh_health_valid` have NO producer in the tree yet.
/// They are carried here rather than dropped so the gap stays visible and fails
/// closed: leaving them false makes a node ineligible until something real
/// fills them in.
struct Tier1MeshFacts {
    /// The candidate holds a root-signed transport certificate.
    bool certificate_valid{false};

    /// Mesh-observed continuity, NOT /proc/uptime and not a node self-report.
    /// The agreed rule (1.1 section 13.1) is the same incarnation, at least two
    /// mesh-recognized attestations, and an observation interval of at least
    /// REATTEST_INTERVAL_SECONDS. It affects next-epoch eligibility only and
    /// never changes a current epoch's member count or quorum.
    bool uptime_valid{false};

    /// Mesh-observed protocol participation, as required from the quorum (1.1
    /// section 13.2): synchronized to current finalized state, recent
    /// authenticated observations from the required mesh quorum, no unresolved
    /// duplicate incarnation, and no unresolved equivocation evidence. Local
    /// load, ping latency and self-reported health are not inputs.
    ///
    /// The observation encoding must be deterministic and finalized before it
    /// can affect next-epoch membership, which is why no producer exists yet:
    /// a locally computed answer would be a self-report wearing another name.
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
