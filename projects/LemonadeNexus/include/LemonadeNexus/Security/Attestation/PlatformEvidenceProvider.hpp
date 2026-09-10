#pragma once

// The boundary between platform-specific evidence and Nexus policy.
//
// A provider verifies ONE approved evidence profile and returns the facts it
// proved. That is the whole contract. A provider cannot select Tier 1, change
// quorum, change a security rule, grant authority, or lower a requirement
// because its platform has no equivalent mechanism. Tier1EligibilityPolicy
// combines what a provider proved with what only the mesh knows, and it is the
// only component that decides eligibility.
//
// Providers are compiled in. There is no dynamic loading, no configuration flag
// and no negotiation: AttestationVerifier dispatches on the profile ID the
// challenge names, and an ID with no compiled provider fails closed.
//
// Architecture reference: Security Architecture Final Draft 1.1, sections 5.1,
// 5.5 and 32.

#include <LemonadeNexus/Security/Attestation/AttestationProfileId.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>
#include <LemonadeNexus/Security/Attestation/VerifiedPlatformClaims.hpp>

#include <optional>

namespace nexus::security {

/// One provider's answer: the platform facts it proved, and the first step
/// that failed. `failure == None` means every step this provider owns held.
struct PlatformVerification {
    VerifiedPlatformClaims claims;
    AttestationFailure failure{AttestationFailure::None};
};

class PlatformEvidenceProvider {
public:
    virtual ~PlatformEvidenceProvider() = default;

    /// The profile this provider verifies. Dispatch is by this value alone.
    [[nodiscard]] virtual AttestationProfileId profile_id() const = 0;
    [[nodiscard]] virtual AttestationProfileRuleset profile_ruleset() const = 0;

    /// Digest of the pinned values this provider applies. It goes into the
    /// challenge and into the verdict, so a reader can tell which policy
    /// produced a result. A provider that pins nothing returns an empty digest.
    [[nodiscard]] virtual Digest policy_digest() const = 0;

    /// False when this provider cannot prove every platform claim Tier 1
    /// requires, on any host, by construction. Such a provider still proves
    /// what it can; the eligibility policy is what refuses the result. This is
    /// a property of the platform, never a runtime mode (1.1 section 5.5).
    [[nodiscard]] virtual bool tier1_capable() const = 0;

    /// Why this provider cannot decide right now, or nullopt when it can.
    /// Runs before any evidence is examined, so a provider that pins nothing —
    /// or that has no implemented evidence format — refuses every candidate
    /// instead of accepting on silence.
    [[nodiscard]] virtual std::optional<AttestationFailure> readiness() const = 0;

    /// Examines evidence the caller has already matched to this challenge and
    /// to this provider. Returns proved facts, never an eligibility result.
    [[nodiscard]] virtual PlatformVerification examine(
        const AttestationChallenge& challenge, const AttestationEvidence& evidence) const = 0;
};

}  // namespace nexus::security
