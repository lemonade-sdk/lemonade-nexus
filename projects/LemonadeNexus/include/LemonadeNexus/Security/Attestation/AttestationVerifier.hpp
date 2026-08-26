#pragma once

// The provider-neutral half of Tier 1 attestation.
//
// The verifier owns what every profile shares: which provider must answer, that
// the bundle answers THIS challenge for THIS node, incarnation and epoch, and
// that the node's identity key signed it. It then hands the bundle to the one
// compiled provider that claims the challenge's profile ID and merges what that
// provider proved into the verdict.
//
// It decides no eligibility and selects no members. The verdict carries claims;
// Tier1EligibilityPolicy combines them with mesh facts.
//
// Architecture reference: Security Architecture Final Draft 1.1, sections 5.1,
// 9 and 31.

#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>
#include <LemonadeNexus/Security/Attestation/LinuxAttestationProfile.hpp>
#include <LemonadeNexus/Security/Attestation/PlatformEvidenceProvider.hpp>

#include <cstddef>
#include <memory>
#include <string_view>
#include <vector>

namespace nexus::security {

/// Hard cap on the variable-length platform fields, applied before any hash or
/// parse of the bundle. Local to the attestation layer until a ruleset bump
/// moves it into SecurityConstants.
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

using ProviderSet = std::vector<std::shared_ptr<PlatformEvidenceProvider>>;

/// The compiled provider set for `profile`. This is the whole registry: what
/// the verified binary constructs here is what can satisfy Tier 1. Nothing
/// loads a provider from configuration, and nothing removes one at runtime.
[[nodiscard]] ProviderSet compiled_providers(LinuxAttestationProfile profile);

class AttestationVerifier {
public:
    /// The compiled provider set for `profile`.
    explicit AttestationVerifier(LinuxAttestationProfile profile);

    /// An explicit provider set. This is a test seam for unknown, unsupported
    /// and substituted providers. Production uses the constructor above; there
    /// is no path from host configuration to either.
    explicit AttestationVerifier(ProviderSet providers);

    /// Runs the neutral checks in a fixed order, cheap and binding first, then
    /// the provider's. The first failure wins and no check can be waived.
    [[nodiscard]] AttestationVerdict examine(const AttestationChallenge& challenge,
                                             const AttestationEvidence& evidence) const;

    /// The provider that claims `id`, or nullptr when none does.
    [[nodiscard]] const PlatformEvidenceProvider* provider_for(AttestationProfileId id) const;

private:
    ProviderSet providers_;
};

}  // namespace nexus::security
