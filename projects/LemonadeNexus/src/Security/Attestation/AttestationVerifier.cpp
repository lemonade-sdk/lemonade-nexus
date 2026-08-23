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

    // 3. The evidence must answer this challenge.
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

    // 8. The platform chain: SNP -> vTPM -> quote -> measured runtime. The
    //    quote nonce is the challenge digest, so the quote answers THIS
    //    challenge as THIS identity.
    EvidenceRequirements requirements;
    requirements.policy = profile.snp;
    requirements.expected_ak_spki_b64 = profile.required_ak_spki_b64;
    requirements.require_ima = profile.enforce_ima_policy;

    const EvidenceVerdict platform = verify_snp_vtpm_evidence(
        evidence.platform, evidence.challenge_digest, challenge.node_key, requirements);
    if (!platform.ok) {
        return fail(map_platform_failure(platform));
    }

    // 9. The IMA-anchored binary must be on the approved release list. The
    //    platform chain has no list input, so the check lives here.
    if (!binary_approved(profile, platform.binary_sha256)) {
        return fail(AttestationFailure::BinaryMeasurementInvalid);
    }

    verdict.passed = true;
    verdict.failure = AttestationFailure::None;
    return verdict;
}

}  // namespace nexus::security
