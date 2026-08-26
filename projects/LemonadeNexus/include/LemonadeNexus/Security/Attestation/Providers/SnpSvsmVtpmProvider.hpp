#pragma once

// AMD SEV-SNP with a COCONUT-SVSM vTPM at VMPL0.
//
// This is the intended Tier 1 shape:
//
//   SVSM  = VMPL0                      most privileged inside the guest
//   Linux = VMPL1 or higher            strictly less privileged than the SVSM
//
// VMPL is a privilege level and lower is more privileged, so "Linux runs above
// VMPL0" is the correct statement. The SVSM and its vTPM sit inside the SNP
// boundary and the hypervisor sits outside both. This replaces the host-side
// swtpm, which is not an approved Tier 1 TPM source because the host owns its
// private state.
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
// The VMPL rule inverts against AzureSnpVtpmProvider and must not be copied.
// There the paravisor owns VMPL0 and requests the report, so
// VmplPolicy::RequireVmpl0 is right. Here a guest-requested report recorded at
// VMPL0 would prove the OPPOSITE of what is wanted: it would mean the guest
// holds the most privileged level and no SVSM runs beneath it. The evidence
// model must prove both halves:
//
//   the approved SVSM holds VMPL0
//   the Linux guest runs at VMPL > 0    (VmplPolicy::RequireAboveVmpl0)
//
// How the SVSM attestation response carries the first half is exactly what the
// captured evidence must settle. It is not guessed here.

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
