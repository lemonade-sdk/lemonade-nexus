#pragma once

// AMD SEV-SNP direct measured boot, without a TPM.
//
// A pinned launch measurement over firmware, kernel, initrd, command line and
// the dm-verity root hash can prove strong boot integrity with no TPM at all.
// It cannot prove runtime integrity: there is no protected measurement
// accumulator a normal guest cannot forge, so nothing anchors what the running
// system loaded AFTER boot.
//
// That is why this provider is not Tier 1 capable. runtime_integrity_valid
// stays false, Tier1EligibilityPolicy fails on the three runtime prerequisites,
// and the node is ineligible. Absence of a TPM is not permission to lower the
// policy (1.1 sections 5.5 and 7).
//
// The evidence format is not implemented: Nexus carries no direct-boot bundle
// today, so readiness() returns ProviderUnsupported and nothing is guessed.
// The type exists now so the "cannot reach Tier 1" rule is compiled and tested
// rather than remembered.

#include <LemonadeNexus/Security/Attestation/PlatformEvidenceProvider.hpp>

namespace nexus::security {

class SnpDirectBootProvider final : public PlatformEvidenceProvider {
public:
    [[nodiscard]] AttestationProfileId profile_id() const override {
        return AttestationProfileId::SnpDirectBoot;
    }
    [[nodiscard]] AttestationProfileRuleset profile_ruleset() const override {
        return kAttestationProfileRulesetVersion;
    }

    [[nodiscard]] Digest policy_digest() const override { return Digest{}; }

    /// False, and not because the format is unimplemented: this platform has
    /// no equivalent of a protected runtime accumulator. Implementing the
    /// evidence format will not change this answer.
    [[nodiscard]] bool tier1_capable() const override { return false; }

    [[nodiscard]] std::optional<AttestationFailure> readiness() const override {
        return AttestationFailure::ProviderUnsupported;
    }

    [[nodiscard]] PlatformVerification examine(
        const AttestationChallenge& challenge,
        const AttestationEvidence& evidence) const override;
};

}  // namespace nexus::security
