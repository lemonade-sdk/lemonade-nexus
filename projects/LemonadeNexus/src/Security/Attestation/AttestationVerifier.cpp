#include <LemonadeNexus/Security/Attestation/AttestationVerifier.hpp>

#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <sodium.h>

#include <algorithm>
#include <string_view>

namespace nexus::security {

std::size_t platform_evidence_size(const SnpVtpmEvidence& platform) {
    return platform.hcl_blob.size() + platform.vcek_der.size() +
           platform.amd_chain_pem.size() + platform.tpms_attest.size() +
           platform.tpm_signature.size() + platform.pcr_values.size() +
           platform.ima_log.size() + platform.binary_path.size() +
           platform.binary_sha256.size() + platform.ima_unavailable.size();
}

bool binary_approved(const LinuxAttestationProfile& profile,
                     std::string_view binary_sha256_hex) {
    if (binary_sha256_hex.empty()) {
        return false;
    }
    return std::find(profile.approved_binary_sha256.begin(),
                     profile.approved_binary_sha256.end(),
                     binary_sha256_hex) != profile.approved_binary_sha256.end();
}

AttestationFailure map_platform_failure(const EvidenceVerdict& verdict) {
    if (verdict.ok) {
        return AttestationFailure::None;
    }
    const std::string_view why = verdict.failure;

    // quote_verified is the one structured flag the platform verdict exposes:
    // it splits the chain at "the quote held". Failure-string prefixes refine
    // each half; an unknown string maps to the most severe failure of its half.
    if (!verdict.quote_verified) {
        if (why.starts_with("the quote is not bound to this challenge")) {
            return AttestationFailure::ChallengeMismatch;
        }
        if (why.starts_with("the quote") || why.starts_with("the supplied PCR values")) {
            return AttestationFailure::TpmQuoteInvalid;
        }
        if (why.starts_with("the platform binding key")) {
            return AttestationFailure::VtpmBindingInvalid;
        }
        if (why.starts_with("the claimed binary measurement is not hex")) {
            return AttestationFailure::BinaryMeasurementInvalid;
        }
        if (why.starts_with("platform policy check failed")) {
            return why.find("below the required floor") != std::string_view::npos
                       ? AttestationFailure::TcbTooOld
                       : AttestationFailure::SnpInvalid;
        }
        return AttestationFailure::SnpInvalid;
    }

    // The platform proved itself; the failure is in the runtime measurements.
    if (why.starts_with("the boot measurement")) {
        return AttestationFailure::BootMeasurementInvalid;
    }
    if (why.starts_with("the runtime profile is wrong")) {
        return AttestationFailure::RuntimeProfileInvalid;
    }
    if (why.starts_with("the IMA log carries no measurement") ||
        why.starts_with("the claimed binary measurement") ||
        why.starts_with("the platform is verified but its binary is not measured")) {
        return AttestationFailure::BinaryMeasurementInvalid;
    }
    return AttestationFailure::ImaMeasurementInvalid;
}

AttestationVerdict AttestationVerifier::examine(const AttestationChallenge& challenge,
                                                const AttestationEvidence& evidence,
                                                const LinuxAttestationProfile& profile) const {
    AttestationVerdict verdict;
    verdict.node_id = challenge.node_id;
    verdict.epoch = challenge.epoch;
    verdict.incarnation = challenge.incarnation;
    verdict.policy_digest = profile_digest(profile);

    const auto fail = [&verdict](AttestationFailure failure) {
        verdict.passed = false;
        verdict.failure = failure;
        return verdict;
    };

    // 0. The profile must be able to decide. A profile that pins no launch
    // measurement, no TCB floor or no approved binary would accept a platform
    // it never examined, so an incomplete profile rejects everyone. This runs
    // first: no later check means anything under a policy that decides nothing.
    if (!profile_is_complete(profile)) {
        return fail(AttestationFailure::ProfileIncomplete);
    }

    // 1. The challenge must be for THIS compiled policy.
    if (challenge.policy_digest != verdict.policy_digest) {
        return fail(AttestationFailure::RulesetMismatch);
    }

    // 2. Both sides must run the compiled rulesets.
    if (challenge.security_ruleset != constants::kSecurityRulesetVersion ||
        evidence.security_ruleset != constants::kSecurityRulesetVersion ||
        evidence.consensus_ruleset != constants::kConsensusRulesetVersion) {
        return fail(AttestationFailure::RulesetMismatch);
    }

    // 3. The evidence must name the epoch the challenge was issued for. The
    //    epoch is inside challenge_digest too, so check 4 would catch a wrong
    //    one anyway — but it would report a digest mismatch, which reads as a
    //    replay rather than as an answer from the wrong epoch. Naming it first
    //    keeps the two diagnosable apart.
    if (evidence.epoch != challenge.epoch) {
        return fail(AttestationFailure::EpochMismatch);
    }

    // 4. The evidence must answer this challenge.
    if (evidence.challenge_digest != challenge_digest(challenge)) {
        return fail(AttestationFailure::ChallengeMismatch);
    }

    // 4. A valid attestation for node A must never authorize node B.
    if (evidence.node_id != challenge.node_id) {
        return fail(AttestationFailure::IdentityMismatch);
    }

    // 5. Only the current incarnation may attest.
    if (evidence.incarnation != challenge.incarnation) {
        return fail(AttestationFailure::IncarnationStale);
    }

    // 6. Size bound before any hash or parse of the bundle (architecture 7.3).
    //    An oversized bundle gets no evidence digest, so this failure stays
    //    cheap by construction.
    if (platform_evidence_size(evidence.platform) > kMaxPlatformEvidenceBytes) {
        return fail(AttestationFailure::EvidenceOversized);
    }

    verdict.evidence_digest = evidence_signing_digest(evidence);

    // 7. The node identity binds the epoch vote key (architecture 11.2).
    if (crypto_sign_verify_detached(evidence.identity_signature.data(),
                                    verdict.evidence_digest.data(),
                                    verdict.evidence_digest.size(),
                                    challenge.node_key.data()) != 0) {
        return fail(AttestationFailure::IdentitySignatureInvalid);
    }
    verdict.links.identity_signature_valid = true;

    // 8. The platform chain: SNP -> vTPM -> quote -> measured runtime. The
    //    quote nonce is the challenge digest, so the quote answers THIS
    //    challenge as THIS identity.
    EvidenceRequirements requirements;
    requirements.policy = profile.snp;
    requirements.expected_ak_spki_b64 = profile.required_ak_spki_b64;
    requirements.require_ima = profile.enforce_ima_policy;
    requirements.expected_pcrs = profile.expected_pcrs;
    requirements.require_no_new_privs = profile.require_no_new_privs;
    requirements.require_seccomp = profile.require_seccomp;
    if (profile.enforce_ima_policy && profile.ima_policy_digest != Digest{}) {
        requirements.expected_ima_policy_sha256 = hex_of(profile.ima_policy_digest);
    }

    const EvidenceVerdict platform = verify_snp_vtpm_evidence(
        evidence.platform, evidence.challenge_digest, challenge.node_key, requirements);

    // Record what the platform proved even on the failing path: a caller
    // building a Tier 1 state needs the links that DID hold, and the ones that
    // did not stay false.
    verdict.links.snp_signature_valid    = platform.snp_signature_valid;
    verdict.links.snp_policy_valid       = platform.snp_policy_valid;
    verdict.links.vtpm_bound             = platform.ak_bound_to_report;
    verdict.links.quote_fresh            = platform.quote_bound_to_challenge;
    verdict.links.boot_state_valid       = platform.boot_state_valid;
    verdict.links.ima_anchored           = platform.ima_anchored;
    verdict.links.runtime_profile_valid  = platform.runtime_profile_valid;

    if (!platform.ok) {
        return fail(map_platform_failure(platform));
    }

    // 9. The IMA-anchored binary must be on the approved release list. The
    //    platform chain has no list input, so the check lives here.
    if (!binary_approved(profile, platform.binary_sha256)) {
        return fail(AttestationFailure::BinaryMeasurementInvalid);
    }
    verdict.links.binary_approved = true;

    verdict.passed = true;
    verdict.failure = AttestationFailure::None;
    return verdict;
}

}  // namespace nexus::security
