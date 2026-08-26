#pragma once

// What a platform evidence provider proved about one candidate.
//
// A claim is true only when a verifier step ran and held. Nothing here may be
// inferred from AttestationVerdict::passed: the claims ARE the result, and
// `passed` is only shorthand for "no step failed before the end". A provider
// that stops early leaves every later claim false, which is what makes an
// unproven fact fail closed.
//
// Tier1EligibilityPolicy consumes these together with mesh facts. A provider
// fills claims in. A provider never decides eligibility, and never sets a
// required claim true because its platform has no equivalent mechanism.
//
// Architecture reference: Security Architecture Final Draft 1.1, sections 5.1,
// 5.2 and 5.5.

#include <LemonadeNexus/Security/Attestation/AttestationProfileId.hpp>

#include <cstdint>
#include <string_view>
#include <vector>

namespace nexus::security {

enum class PlatformClaim : uint16_t {
    HardwareConfidentiality,
    PlatformIdentity,
    EvidenceFreshness,
    NodeIdentityBinding,
    IncarnationBinding,
    EpochBinding,
    SecurityRulesetBinding,
    BootIntegrity,
    RuntimeIntegrity,
    Tcb,
    AttestationProfile,
};

struct VerifiedPlatformClaims {
    /// Which provider produced these claims. Unknown means none did, so no
    /// claim in this object was proved by anything.
    AttestationProfileId profile_id{AttestationProfileId::Unknown};
    AttestationProfileRuleset profile_ruleset{0};

    // --- the claims Revision 1.1 requires ------------------------------------
    bool hardware_confidentiality_valid{false};
    bool platform_identity_valid{false};
    bool evidence_freshness_valid{false};
    bool node_identity_binding_valid{false};
    bool incarnation_binding_valid{false};
    bool epoch_binding_valid{false};
    bool security_ruleset_binding_valid{false};
    bool boot_integrity_valid{false};
    bool runtime_integrity_valid{false};
    bool tcb_valid{false};
    bool attestation_profile_valid{false};

    // --- the steps behind runtime_integrity_valid ----------------------------
    // Tier 1 names three separate runtime prerequisites. One composite claim
    // cannot tell them apart, so the steps stay visible here and
    // runtime_integrity_valid is exactly their conjunction.
    bool ima_anchored{false};
    bool binary_approved{false};
    bool runtime_profile_enforced{false};
};

[[nodiscard]] std::string_view platform_claim_name(PlatformClaim claim);

/// Every required claim `claims` does not carry, in declaration order.
[[nodiscard]] std::vector<PlatformClaim> missing_platform_claims(
    const VerifiedPlatformClaims& claims);

/// True when every required claim holds. NOT an eligibility decision: Tier 1
/// also needs mesh facts, which no provider may supply.
[[nodiscard]] bool all_platform_claims_proved(const VerifiedPlatformClaims& claims);

/// Structural rules a provider must not break:
///   - no claim is true unless a provider identified itself,
///   - runtime_integrity_valid is exactly the conjunction of its three steps.
/// A provider that breaks either has a bug rather than a proof, so callers
/// treat inconsistent claims as no claims.
[[nodiscard]] bool platform_claims_are_consistent(const VerifiedPlatformClaims& claims);

}  // namespace nexus::security
