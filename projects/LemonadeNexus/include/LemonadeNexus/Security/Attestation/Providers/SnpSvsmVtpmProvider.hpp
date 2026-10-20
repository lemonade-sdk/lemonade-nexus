#pragma once

// AMD SEV-SNP with a COCONUT-SVSM vTPM.
//
// The service binding is the COCONUT-SVSM protocol, not an inferred HCL shape.
// readiness() still refuses an unpinned release or node enrollment.
//
// The VMPL rule inverts against AzureSnpVtpmProvider. Lower VMPL is more
// privileged, and here the SVSM holds VMPL0 while Linux runs above it, so a
// guest-requested report recorded at VMPL0 proves no SVSM was there. The
// evidence must prove both halves: SVSM at VMPL0, guest above it
// (VmplPolicy::RequireAboveVmpl0).
//
// Do not reuse Azure HCL bytes as a stand-in format. HCL binds its AK through a
// paravisor runtime-data hash; if SVSM binds differently the mismatch is silent,
// and a bundle would verify against a rule the platform never enforced.

#include <LemonadeNexus/Security/Attestation/PlatformEvidenceProvider.hpp>
#include <LemonadeNexus/Security/Attestation/LinuxAttestationProfile.hpp>

namespace nexus::security {

class SnpSvsmVtpmProvider final : public PlatformEvidenceProvider {
public:
    explicit SnpSvsmVtpmProvider(
        LinuxAttestationProfile profile = linux_attestation_profile_v2_svsm(),
        AmdRevocationSource revocation = {});
    [[nodiscard]] AttestationProfileId profile_id() const override {
        return AttestationProfileId::SnpSvsmVtpm;
    }
    [[nodiscard]] AttestationProfileRuleset profile_ruleset() const override {
        return kAttestationProfileRulesetVersion;
    }

    [[nodiscard]] Digest policy_digest() const override { return policy_digest_; }

    [[nodiscard]] bool tier1_capable() const override { return true; }

    [[nodiscard]] std::optional<AttestationFailure> readiness() const override;

    [[nodiscard]] PlatformVerification examine(
        const AttestationChallenge& challenge,
        const AttestationEvidence& evidence,
        const PlatformVerificationState& state) const override;

    [[nodiscard]] const LinuxAttestationProfile& profile() const { return profile_; }

private:
    LinuxAttestationProfile profile_;
    AmdRevocationSource revocation_;
    Digest policy_digest_{};
};

}  // namespace nexus::security
