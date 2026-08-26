#pragma once

// AMD SEV-SNP with a COCONUT-SVSM vTPM at VMPL0.
//
// This is the intended Tier 1 shape: the SVSM and its vTPM run at VMPL0 inside
// the SNP boundary, Linux runs at VMPL1 or lower, and the hypervisor is outside
// both. It replaces the host-side swtpm, which is not an approved Tier 1 TPM
// source because the host owns its private state.
//
// The provider is DELIBERATELY UNIMPLEMENTED. The SVSM service-manifest format
// and the exact binding from the SNP report to the vTPM AK are not invented
// here: they will be read from real evidence captured on an approved SVSM host
// (1.1 section 6.4). Until then readiness() returns ProviderUnsupported and the
// provider proves nothing, so a node presenting SVSM evidence fails closed
// rather than passing under a guessed format.
//
// When real evidence arrives, the chain to implement is:
//
//   AMD endorsement -> SNP report -> approved SVSM launch measurement
//     -> SVSM service binding -> vTPM AK -> fresh TPM quote
//     -> measured boot + IMA
//
// One rule inverts against AzureSnpVtpmProvider and must not be copied: under
// SVSM the guest Linux runs at VMPL1 or lower, so SnpPolicyRequirements
// require_vmpl0 cannot be applied to a guest-requested report. Which component
// requests the report, and at which VMPL, is part of what the captured
// evidence must settle.

#include <LemonadeNexus/Security/Attestation/PlatformEvidenceProvider.hpp>

namespace nexus::security {

class SnpSvsmVtpmProvider final : public PlatformEvidenceProvider {
public:
    [[nodiscard]] AttestationProfileId profile_id() const override {
        return AttestationProfileId::SnpSvsmVtpm;
    }
    [[nodiscard]] AttestationProfileRuleset profile_ruleset() const override {
        return kAttestationProfileRulesetVersion;
    }

    /// Nothing is pinned until real SVSM evidence defines what to pin.
    [[nodiscard]] Digest policy_digest() const override { return Digest{}; }

    /// True: the SVSM shape can prove every Tier 1 platform claim once it is
    /// implemented. Capability is not permission — readiness() still refuses.
    [[nodiscard]] bool tier1_capable() const override { return true; }

    [[nodiscard]] std::optional<AttestationFailure> readiness() const override {
        return AttestationFailure::ProviderUnsupported;
    }

    [[nodiscard]] PlatformVerification examine(
        const AttestationChallenge& challenge,
        const AttestationEvidence& evidence) const override;
};

}  // namespace nexus::security
