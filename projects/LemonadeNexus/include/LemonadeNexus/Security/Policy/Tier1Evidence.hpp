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
/// `uptime_valid` and `mesh_health_valid` have NO producer in the tree yet.
/// They are carried here rather than dropped so the gap stays visible and fails
/// closed: leaving them false makes a node ineligible until something real
/// fills them in.
struct Tier1MeshFacts {
    /// The candidate holds a root-signed transport certificate.
    bool certificate_valid{false};

    /// The candidate has been continuously present long enough to be selected.
    bool uptime_valid{false};

    /// The mesh itself is healthy enough to admit a new Tier 1 member.
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
