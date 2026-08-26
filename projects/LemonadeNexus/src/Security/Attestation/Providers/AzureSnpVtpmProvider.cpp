#include <LemonadeNexus/Security/Attestation/Providers/AzureSnpVtpmProvider.hpp>

#include <LemonadeNexus/Security/Attestation/AttestationVerifier.hpp>

#include <utility>

namespace nexus::security {

AzureSnpVtpmProvider::AzureSnpVtpmProvider(LinuxAttestationProfile profile,
                                            AmdRevocationSource revocation)
    : profile_(std::move(profile)),
      revocation_(std::move(revocation)),
      policy_digest_(profile_digest(profile_)) {}

std::optional<AttestationFailure> AzureSnpVtpmProvider::readiness() const {
    if (!profile_is_complete(profile_)) {
        return AttestationFailure::ProfileIncomplete;
    }
    return std::nullopt;
}

PlatformVerification AzureSnpVtpmProvider::examine(const AttestationChallenge& challenge,
                                                    const AttestationEvidence& evidence) const {
    PlatformVerification result;
    result.claims.profile_id = profile_id();
    result.claims.profile_ruleset = profile_ruleset();

    const auto fail = [&result](AttestationFailure failure) {
        result.failure = failure;
        return result;
    };

    EvidenceRequirements requirements;
    requirements.policy = profile_.snp;
    requirements.expected_ak_spki_b64 = profile_.required_ak_spki_b64;
    requirements.require_ima = profile_.enforce_ima_policy;
    requirements.expected_pcrs = profile_.expected_pcrs;
    requirements.require_no_new_privs = profile_.require_no_new_privs;
    requirements.require_seccomp = profile_.require_seccomp;
    requirements.require_revocation_check = profile_.require_endorsement_revocation;
    if (revocation_) {
        requirements.revocation = revocation_();
    }
    if (profile_.enforce_ima_policy && profile_.ima_policy_digest != Digest{}) {
        requirements.expected_ima_policy_sha256 = hex_of(profile_.ima_policy_digest);
    }

    // The quote nonce is the challenge digest, so one quote proves the platform
    // answered THIS challenge as THIS identity.
    const EvidenceVerdict platform = verify_snp_vtpm_evidence(
        evidence.platform, evidence.challenge_digest, challenge.node_key, requirements);

    // Record what held even on the failing path: the caller needs the claims
    // that were proved, and the ones that were not stay false.
    result.claims.hardware_confidentiality_valid =
        platform.snp_signature_valid && platform.snp_policy_valid;
    result.claims.tcb_valid = platform.tcb_valid;
    result.claims.platform_identity_valid = platform.ak_bound_to_report;
    result.claims.evidence_freshness_valid = platform.quote_bound_to_challenge;
    result.claims.boot_integrity_valid = platform.boot_state_valid;
    result.claims.ima_anchored = platform.ima_anchored;
    result.claims.runtime_profile_enforced = platform.runtime_profile_valid;

    if (!platform.ok) {
        return fail(map_platform_failure(platform));
    }

    // The IMA-anchored binary must be on the approved release list. The
    // platform chain takes no list input, so the check belongs here.
    if (!binary_approved(profile_, platform.binary_sha256)) {
        return fail(AttestationFailure::BinaryMeasurementInvalid);
    }
    result.claims.binary_approved = true;

    result.claims.runtime_integrity_valid = result.claims.ima_anchored &&
                                            result.claims.binary_approved &&
                                            result.claims.runtime_profile_enforced;
    if (!result.claims.runtime_integrity_valid) {
        return fail(AttestationFailure::RuntimeProfileInvalid);
    }
    return result;
}

}  // namespace nexus::security
