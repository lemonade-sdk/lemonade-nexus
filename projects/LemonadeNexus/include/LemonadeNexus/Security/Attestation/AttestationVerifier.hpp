#pragma once

// The protocol-layer verifier for Tier 1 candidate evidence.
//
// It composes the platform chain from EvidenceSnpVtpm and proves facts about
// one candidate under one compiled profile. It never decides eligibility or
// selection — the verdict feeds Tier1EligibilityPolicy.
//
// Architecture reference: section 7.4.

#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>
#include <LemonadeNexus/Security/Attestation/LinuxAttestationProfile.hpp>

#include <cstddef>
#include <string_view>

namespace nexus::security {

/// Hard cap on the variable-length platform fields, applied before any hash or
/// parse of the bundle (architecture 7.3). Local to the attestation layer
/// until a ruleset bump moves it into SecurityConstants.
inline constexpr std::size_t kMaxPlatformEvidenceBytes = 4 * 1024 * 1024;

/// Total bytes of the variable-length fields in a platform bundle.
[[nodiscard]] std::size_t platform_evidence_size(const SnpVtpmEvidence& platform);

/// True when `binary_sha256_hex` appears in the profile's approved list.
/// An empty list or an empty measurement approves nothing — fail closed.
[[nodiscard]] bool binary_approved(const LinuxAttestationProfile& profile,
                                   std::string_view binary_sha256_hex);

/// Deterministic mapping from the platform chain's verdict to the typed
/// failure model. Same verdict, same failure.
[[nodiscard]] AttestationFailure map_platform_failure(const EvidenceVerdict& verdict);

class AttestationVerifier {
public:
    /// Runs every check in the fixed order of architecture 7.4, cheap and
    /// binding checks first. The first failure wins; no check can be waived.
    [[nodiscard]] AttestationVerdict examine(const AttestationChallenge& challenge,
                                             const AttestationEvidence& evidence,
                                             const LinuxAttestationProfile& profile) const;
};

}  // namespace nexus::security
