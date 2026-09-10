#pragma once

// AMD SEV-SNP with a COCONUT-SVSM vTPM.
//
// Unimplemented on purpose: the SVSM service binding is read from real evidence,
// never guessed. readiness() refuses, so SVSM evidence fails closed rather than
// passing under an assumed format.
//
// Two traps for whoever implements it:
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
