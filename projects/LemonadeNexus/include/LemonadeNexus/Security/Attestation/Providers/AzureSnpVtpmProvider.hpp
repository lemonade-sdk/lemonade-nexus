#pragma once

// AMD SEV-SNP with a vTPM bound through an HCL runtime-data blob.
//
// This is the SNP/vTPM chain Nexus has always verified, moved behind the
// provider boundary unchanged. The binding that makes it worth anything is in
// the blob: the SNP report's REPORT_DATA equals SHA-256 of the runtime data
// that carries HCLAkPub, so AMD's signature covers WHICH vTPM key belongs to
// this launch. A quote from any other TPM verifies under no key AMD vouched
// for, which is what rules out a host-side swtpm.
//
// The provider proves platform facts only. Node identity, incarnation, epoch
// and the challenge match are provider-neutral and stay in AttestationVerifier.
//
// Architecture reference: Security Architecture Final Draft 1.1, sections 5.4,
// 6.2 and 6.3.

#include <LemonadeNexus/Security/Attestation/LinuxAttestationProfile.hpp>
#include <LemonadeNexus/Security/Attestation/PlatformEvidenceProvider.hpp>

namespace nexus::security {

class AzureSnpVtpmProvider final : public PlatformEvidenceProvider {
public:
    explicit AzureSnpVtpmProvider(LinuxAttestationProfile profile);

    [[nodiscard]] AttestationProfileId profile_id() const override {
        return AttestationProfileId::AzureSnpVtpm;
    }
    [[nodiscard]] AttestationProfileRuleset profile_ruleset() const override {
        return kAttestationProfileRulesetVersion;
    }
    [[nodiscard]] Digest policy_digest() const override { return policy_digest_; }
    [[nodiscard]] bool tier1_capable() const override { return true; }

    /// ProfileIncomplete while the compiled profile leaves a prerequisite
    /// unpinned. Such a profile would accept a platform it never examined, so
    /// it refuses everyone instead.
    [[nodiscard]] std::optional<AttestationFailure> readiness() const override;

    [[nodiscard]] PlatformVerification examine(
        const AttestationChallenge& challenge,
        const AttestationEvidence& evidence) const override;

    [[nodiscard]] const LinuxAttestationProfile& profile() const { return profile_; }

private:
    LinuxAttestationProfile profile_;
    Digest policy_digest_;
};

}  // namespace nexus::security
