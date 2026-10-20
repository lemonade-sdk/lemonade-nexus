#include <LemonadeNexus/Security/Attestation/Providers/SnpSvsmVtpmProvider.hpp>

#include <LemonadeNexus/Security/Attestation/AttestationVerifier.hpp>
#include <LemonadeNexus/Security/EvidenceSnpSvsmVtpm.hpp>

#include <algorithm>
#include <utility>

namespace nexus::security {

namespace {

// Exact-match-any against the release set; an empty set matches nothing.
bool launch_measurement_approved(const LinuxAttestationProfile& profile,
                                 const std::array<uint8_t, 48>& measurement) {
    const auto hex = hex_of(measurement);
    const auto& approved = profile.snp.expected_measurements_hex;
    return std::find(approved.begin(), approved.end(), hex) != approved.end();
}

bool checkpoint_matches_challenge_and_activation(
    const AttestationCheckpoint& checkpoint,
    const AttestationChallenge& challenge,
    const SvsmAkActivationRecord& activation,
    const LinuxAttestationProfile& profile) {
    return checkpoint.network_id == challenge.network_id &&
           checkpoint.node_id == challenge.node_id &&
           checkpoint.incarnation == challenge.incarnation &&
           checkpoint.profile_id == challenge.profile_id &&
           checkpoint.profile_ruleset == challenge.profile_ruleset &&
           checkpoint.policy_digest == challenge.policy_digest &&
           checkpoint.checkpoint_digest == challenge.ima_checkpoint_digest &&
           checkpoint.event_count == challenge.ima_prior_event_count &&
           checkpoint.pcr10 == challenge.ima_prior_pcr10 &&
           checkpoint.required_paths == challenge.ima_checkpoint_paths &&
           checkpoint.ek_name == activation.ek_name &&
           checkpoint.ak_name == activation.ak_name &&
           launch_measurement_approved(profile, checkpoint.launch_measurement);
}

bool has_pcr(const LinuxAttestationProfile& profile, uint32_t index) {
    return std::any_of(profile.expected_pcrs.begin(), profile.expected_pcrs.end(),
                       [index](const auto& pin) { return pin.first == index; });
}

bool has_exact_svsm_boot_pcr_pins(const LinuxAttestationProfile& profile) {
    if (profile.expected_pcrs.size() != std::size(kSvsmBootPcrs)) return false;
    return std::all_of(std::begin(kSvsmBootPcrs), std::end(kSvsmBootPcrs),
                       [&profile](uint32_t index) { return has_pcr(profile, index); });
}

AttestationFailure map_svsm_failure(SvsmEvidenceFailure failure) {
    switch (failure) {
        case SvsmEvidenceFailure::None: return AttestationFailure::None;
        case SvsmEvidenceFailure::RevocationInvalid: return AttestationFailure::EndorsementRevoked;
        case SvsmEvidenceFailure::ServiceTcbTooOld:
        case SvsmEvidenceFailure::GuestTcbTooOld: return AttestationFailure::TcbTooOld;
        case SvsmEvidenceFailure::EkMismatch:
        case SvsmEvidenceFailure::AkMismatch:
        case SvsmEvidenceFailure::ActivationReceiptInvalid:
        case SvsmEvidenceFailure::ServiceManifestInvalid:
        case SvsmEvidenceFailure::ServiceReportDataInvalid:
            return AttestationFailure::VtpmBindingInvalid;
        case SvsmEvidenceFailure::QuoteMalformed:
        case SvsmEvidenceFailure::QuoteSignatureInvalid:
        case SvsmEvidenceFailure::QuotePcrDigestInvalid: return AttestationFailure::TpmQuoteInvalid;
        case SvsmEvidenceFailure::QuoteNonceInvalid:
        case SvsmEvidenceFailure::GuestNonceInvalid: return AttestationFailure::ChallengeMismatch;
        case SvsmEvidenceFailure::BootPcrInvalid: return AttestationFailure::BootMeasurementInvalid;
        case SvsmEvidenceFailure::ImaCheckpointInvalid: return AttestationFailure::CheckpointInvalid;
        case SvsmEvidenceFailure::ImaMalformed:
        case SvsmEvidenceFailure::ImaViolation:
        case SvsmEvidenceFailure::ImaPcr10Mismatch: return AttestationFailure::ImaMeasurementInvalid;
        case SvsmEvidenceFailure::BinaryMeasurementInvalid:
            return AttestationFailure::BinaryMeasurementInvalid;
        case SvsmEvidenceFailure::RuntimeProfileInvalid:
            return AttestationFailure::RuntimeProfileInvalid;
        default: return AttestationFailure::SnpInvalid;
    }
}

}  // namespace

SnpSvsmVtpmProvider::SnpSvsmVtpmProvider(LinuxAttestationProfile profile,
                                         AmdRevocationSource revocation)
    : profile_(std::move(profile)), revocation_(std::move(revocation)),
      policy_digest_(profile_digest(profile_)) {}

std::optional<AttestationFailure> SnpSvsmVtpmProvider::readiness() const {
    if (!profile_is_complete(profile_) ||
        profile_.ima_replay_bank != ImaReplayBank::Sha256 ||
        profile_.ima_policy_proof != ImaPolicyProof::MeasuredKernelBinding ||
        !has_exact_svsm_boot_pcr_pins(profile_)) {
        return AttestationFailure::ProfileIncomplete;
    }
    return std::nullopt;
}

PlatformVerification SnpSvsmVtpmProvider::examine(
    const AttestationChallenge& challenge, const AttestationEvidence& evidence,
    const PlatformVerificationState& state) const {
    PlatformVerification result;
    result.claims.profile_id = profile_id();
    result.claims.profile_ruleset = profile_ruleset();
    const auto fail = [&result](AttestationFailure failure) {
        result.failure = failure;
        return result;
    };
    const auto* svsm = std::get_if<SnpSvsmVtpmEvidence>(&evidence.platform);
    if (!svsm) return fail(AttestationFailure::ProfileIdMismatch);
    if (!state.activation || !svsm_activation_record_valid(*state.activation))
        return fail(AttestationFailure::ActivationRequired);
    if (challenge.ima_mode == ImaEvidenceMode::Resume &&
        (!state.checkpoint || !attestation_checkpoint_valid(*state.checkpoint) ||
         !checkpoint_matches_challenge_and_activation(*state.checkpoint, challenge,
                                                      *state.activation, profile_)))
        return fail(AttestationFailure::CheckpointRequired);

    SvsmEvidenceRequirements requirements;
    requirements.policy = profile_.snp;
    requirements.expected_measurements_hex = profile_.snp.expected_measurements_hex;
    requirements.expected_ek_name_hex = crypto::to_hex(state.activation->ek_name);
    requirements.expected_ak_name_hex = crypto::to_hex(state.activation->ak_name);
    requirements.expected_ak_spki_b64 = state.activation->ak_spki_b64;
    requirements.expected_ak_ek_binding = state.activation->activation_receipt;
    requirements.approved_paths = approved_path_list(profile_);
    requirements.evidence_collector_path = profile_.evidence_collector_path;
    requirements.expected_pcrs = profile_.expected_pcrs;
    requirements.require_no_new_privs = profile_.require_no_new_privs;
    requirements.require_seccomp = profile_.require_seccomp;
    requirements.require_revocation_check = profile_.require_endorsement_revocation;
    requirements.ima_mode = challenge.ima_mode;
    requirements.checkpoint = state.checkpoint;
    if (revocation_) requirements.revocation = revocation_();

    const SvsmEvidenceVerdict platform = verify_snp_svsm_vtpm_evidence(
        *svsm, evidence.challenge_digest, challenge.node_key, requirements);
    result.claims.hardware_confidentiality_valid =
        platform.snp_signature_valid && platform.snp_policy_valid;
    result.claims.tcb_valid = platform.tcb_valid;
    result.claims.platform_identity_valid = platform.ak_bound_to_report;
    result.claims.evidence_freshness_valid = platform.quote_bound_to_challenge;
    result.claims.boot_integrity_valid = platform.boot_state_valid;
    result.claims.ima_anchored = platform.ima_anchored;
    result.claims.runtime_profile_enforced = platform.runtime_profile_valid;
    if (!platform.ok) return fail(map_svsm_failure(platform.svsm_failure));

    for (const auto& required : profile_.approved_paths) {
        const auto measured = std::find_if(platform.ima_state.paths.begin(),
                                           platform.ima_state.paths.end(),
                                           [&required](const auto& path) {
                                               return path.path == required.path;
                                           });
        if (measured == platform.ima_state.paths.end() ||
            !path_approved(profile_, measured->path, measured->sha256))
            return fail(AttestationFailure::BinaryMeasurementInvalid);
    }
    // MeasuredKernelBinding is verifier-owned: readiness required the pinned
    // launch measurement plus PCR8/PCR9, and those values were checked above.
    // The guest never supplies or selects ima_policy_digest.
    result.claims.binary_approved = true;
    result.claims.runtime_integrity_valid = result.claims.ima_anchored &&
                                            result.claims.binary_approved &&
                                            result.claims.runtime_profile_enforced;
    if (!result.claims.runtime_integrity_valid) {
        return fail(AttestationFailure::RuntimeProfileInvalid);
    }
    // The chain already replayed the transferred log once; hand that state out
    // so the caller never replays it again for the next checkpoint.
    if (state.ima_state_out) *state.ima_state_out = platform.ima_state;
    return result;
}

}  // namespace nexus::security
