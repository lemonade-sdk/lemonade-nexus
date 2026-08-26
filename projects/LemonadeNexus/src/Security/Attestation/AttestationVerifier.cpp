#include <LemonadeNexus/Security/Attestation/AttestationVerifier.hpp>

#include <LemonadeNexus/Security/Attestation/Providers/AzureSnpVtpmProvider.hpp>
#include <LemonadeNexus/Security/Attestation/Providers/SnpDirectBootProvider.hpp>
#include <LemonadeNexus/Security/Attestation/Providers/SnpSvsmVtpmProvider.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <sodium.h>

#include <algorithm>
#include <string_view>
#include <utility>

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
        if (why.starts_with("AMD revocation check failed")) {
            return AttestationFailure::EndorsementRevoked;
        }
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

ProviderSet compiled_providers(LinuxAttestationProfile profile,
                               AmdRevocationSource revocation) {
    ProviderSet providers;
    providers.push_back(
        std::make_shared<AzureSnpVtpmProvider>(std::move(profile), std::move(revocation)));
    providers.push_back(std::make_shared<SnpSvsmVtpmProvider>());
    providers.push_back(std::make_shared<SnpDirectBootProvider>());
    return providers;
}

AttestationVerifier::AttestationVerifier(LinuxAttestationProfile profile,
                                         AmdRevocationSource revocation)
    : providers_(compiled_providers(std::move(profile), std::move(revocation))) {}

AttestationVerifier::AttestationVerifier(ProviderSet providers)
    : providers_(std::move(providers)) {}

const PlatformEvidenceProvider* AttestationVerifier::provider_for(
    AttestationProfileId id) const {
    if (id == AttestationProfileId::Unknown) {
        return nullptr;
    }
    for (const auto& provider : providers_) {
        if (provider && provider->profile_id() == id) {
            return provider.get();
        }
    }
    return nullptr;
}

AttestationVerdict AttestationVerifier::examine(const AttestationChallenge& challenge,
                                                 const AttestationEvidence& evidence) const {
    AttestationVerdict verdict;
    verdict.node_id = challenge.node_id;
    verdict.epoch = challenge.epoch;
    verdict.incarnation = challenge.incarnation;

    const auto fail = [&verdict](AttestationFailure failure) {
        verdict.passed = false;
        verdict.failure = failure;
        return verdict;
    };

    // 1. One compiled provider must own this profile. An unknown ID has none,
    //    which is how a profile this binary does not implement fails closed.
    const PlatformEvidenceProvider* provider = provider_for(challenge.profile_id);
    if (provider == nullptr) {
        // No provider ran, so no policy was applied. The digest stays empty
        // rather than echoing what the challenge asked for.
        return fail(AttestationFailure::ProviderUnknown);
    }
    verdict.policy_digest = provider->policy_digest();

    // 2. The provider must be able to decide before anything is examined. A
    //    profile that pins nothing, or a provider with no implemented evidence
    //    format, would otherwise accept a platform it never looked at.
    if (const auto refusal = provider->readiness(); refusal.has_value()) {
        return fail(*refusal);
    }

    // 3. The bundle must answer under the profile the challenge named. Without
    //    this, evidence built for a weaker provider could answer a stronger
    //    challenge, which is the downgrade path of 1.1 section 31.
    if (evidence.profile_id != challenge.profile_id) {
        return fail(AttestationFailure::ProfileIdMismatch);
    }
    if (challenge.profile_ruleset != provider->profile_ruleset() ||
        evidence.profile_ruleset != provider->profile_ruleset()) {
        return fail(AttestationFailure::ProfileRulesetMismatch);
    }

    // 4. Same profile, same pinned values. A challenge issued under another
    //    build of this profile applies a different bar, and this verifier
    //    cannot evaluate it. Ahead of the challenge digest deliberately: the
    //    digest would fail too, but "wrong policy" is the useful diagnosis.
    if (challenge.policy_digest != provider->policy_digest()) {
        return fail(AttestationFailure::RulesetMismatch);
    }
    verdict.claims.attestation_profile_valid = true;

    // 5. Both sides must run the compiled rulesets.
    if (challenge.security_ruleset != constants::kSecurityRulesetVersion ||
        challenge.consensus_ruleset != constants::kConsensusRulesetVersion ||
        evidence.security_ruleset != constants::kSecurityRulesetVersion ||
        evidence.consensus_ruleset != constants::kConsensusRulesetVersion) {
        return fail(AttestationFailure::RulesetMismatch);
    }

    // 6. The evidence must answer for this mesh. network_id is inside
    //    challenge_digest, so step 8 would catch a foreign answer anyway, but
    //    it would read as a replay. Naming it keeps the two apart.
    if (evidence.network_id != challenge.network_id) {
        return fail(AttestationFailure::NetworkMismatch);
    }

    // 7. The evidence must name the epoch the challenge was issued for. The
    //    epoch is inside challenge_digest too, so step 8 would catch a wrong
    //    one anyway — but it would report a digest mismatch, which reads as a
    //    replay rather than as an answer from the wrong epoch. Naming it first
    //    keeps the two diagnosable apart.
    if (evidence.epoch != challenge.epoch) {
        return fail(AttestationFailure::EpochMismatch);
    }

    // 8. The evidence must answer this challenge.
    if (evidence.challenge_digest != challenge_digest(challenge)) {
        return fail(AttestationFailure::ChallengeMismatch);
    }

    // 9. A valid attestation for node A must never authorize node B.
    if (evidence.node_id != challenge.node_id) {
        return fail(AttestationFailure::IdentityMismatch);
    }

    // 10. Only the current incarnation may attest.
    if (evidence.incarnation != challenge.incarnation) {
        return fail(AttestationFailure::IncarnationStale);
    }

    // 11. Size bound before any hash or parse of the bundle. An oversized bundle
    //    gets no evidence digest, so this failure stays cheap by construction.
    if (platform_evidence_size(evidence.platform) > kMaxPlatformEvidenceBytes) {
        return fail(AttestationFailure::EvidenceOversized);
    }

    verdict.evidence_digest = evidence_signing_digest(evidence);

    // 12. The node identity binds the epoch vote key.
    if (crypto_sign_verify_detached(evidence.identity_signature.data(),
                                    verdict.evidence_digest.data(),
                                    verdict.evidence_digest.size(),
                                    challenge.node_key.data()) != 0) {
        return fail(AttestationFailure::IdentitySignatureInvalid);
    }

    // The neutral claims. Each one names a check above that ran and held.
    verdict.claims.profile_id = provider->profile_id();
    verdict.claims.profile_ruleset = provider->profile_ruleset();
    verdict.claims.security_ruleset_binding_valid = true;
    verdict.claims.epoch_binding_valid = true;
    verdict.claims.node_identity_binding_valid = true;
    verdict.claims.incarnation_binding_valid = true;

    // 13. The platform chain, whichever profile owns it.
    const PlatformVerification platform = provider->examine(challenge, evidence);
    verdict.claims.hardware_confidentiality_valid =
        platform.claims.hardware_confidentiality_valid;
    verdict.claims.platform_identity_valid   = platform.claims.platform_identity_valid;
    verdict.claims.evidence_freshness_valid  = platform.claims.evidence_freshness_valid;
    verdict.claims.boot_integrity_valid      = platform.claims.boot_integrity_valid;
    verdict.claims.runtime_integrity_valid   = platform.claims.runtime_integrity_valid;
    verdict.claims.tcb_valid                 = platform.claims.tcb_valid;
    verdict.claims.ima_anchored              = platform.claims.ima_anchored;
    verdict.claims.binary_approved           = platform.claims.binary_approved;
    verdict.claims.runtime_profile_enforced  = platform.claims.runtime_profile_enforced;

    if (platform.failure != AttestationFailure::None) {
        return fail(platform.failure);
    }

    // A provider that returns no failure but inconsistent claims has a bug
    // rather than a proof. Trusting it would let a required claim be true with
    // nothing behind it, so the verdict refuses instead.
    if (!platform_claims_are_consistent(verdict.claims)) {
        return fail(AttestationFailure::ProviderUnsupported);
    }

    verdict.passed = true;
    verdict.failure = AttestationFailure::None;
    return verdict;
}

}  // namespace nexus::security
