#include <LemonadeNexus/Security/Attestation/AttestationService.hpp>

#include <LemonadeNexus/Security/EvidenceSnpSvsmVtpm.hpp>
#include <LemonadeNexus/Security/MeasurementIma.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/SnpReport.hpp>

#include <sodium.h>
#include <spdlog/spdlog.h>

#include <algorithm>

namespace nexus::security {

namespace {

/// Warn-log window for repeated enrollment refusals from one node.
constexpr auto kEnrollmentRefusalLogWindow = std::chrono::seconds(60);

bool checkpoint_matches_release_and_activation(
    const AttestationCheckpoint& checkpoint,
    const SvsmAkActivationRecord& activation,
    const LinuxAttestationProfile& profile) {
    // Exact-match-any against the release set; an empty set matches nothing.
    const auto& approved = profile.snp.expected_measurements_hex;
    const auto measurement_hex = hex_of(checkpoint.launch_measurement);
    return std::find(approved.begin(), approved.end(), measurement_hex) !=
               approved.end() &&
           checkpoint.ek_name == activation.ek_name &&
           checkpoint.ak_name == activation.ak_name &&
           checkpoint.network_id == activation.network_id &&
           checkpoint.node_id == activation.node_id &&
           checkpoint.incarnation == activation.incarnation &&
           checkpoint.profile_id == activation.profile_id &&
           checkpoint.profile_ruleset == activation.profile_ruleset;
}

}  // namespace

AttestationService::AttestationService(NetworkId network_id, LinuxAttestationProfile profile,
                                       AmdRevocationSource revocation,
                                       std::filesystem::path state_directory)
    : network_id_(network_id),
      profile_(std::move(profile)),
      policy_digest_(profile_digest(profile_)),
      revocation_(std::move(revocation)),
      verifier_(profile_, revocation_),
      checkpoints_(state_directory.empty() ? std::filesystem::path{}
                                           : state_directory / "attestation-checkpoints"),
      activations_(state_directory.empty() ? std::filesystem::path{}
                                           : state_directory / "svsm-activations") {}

AttestationChallenge AttestationService::make_challenge(
    const NodeId& node, const crypto::Ed25519PublicKey& node_key,
    IncarnationId incarnation, EpochId epoch, AttestationPurpose purpose,
    const Digest& context) {
    AttestationChallenge challenge;
    challenge.network_id = network_id_;
    randombytes_buf(challenge.nonce.data(), challenge.nonce.size());
    challenge.node_id = node;
    challenge.node_key = node_key;
    challenge.incarnation = incarnation;
    challenge.epoch = epoch;
    challenge.security_ruleset = constants::kSecurityRulesetVersion;
    challenge.consensus_ruleset = constants::kConsensusRulesetVersion;
    // The challenge names the profile. A candidate answers under this one or it
    // answers nothing: there is no negotiation and no weaker second choice.
    challenge.profile_id = kTier1AttestationProfileId;
    challenge.profile_ruleset = kAttestationProfileRulesetVersion;
    challenge.policy_digest = policy_digest_;
    challenge.purpose = purpose;
    challenge.context_digest = context;

    if (challenge.profile_id == AttestationProfileId::SnpSvsmVtpm &&
        purpose != AttestationPurpose::PlatformEnrollment) {
        const auto loaded = checkpoints_.load(network_id_, node, incarnation,
                                              challenge.profile_id);
        const auto enrolled = activations_.load(network_id_, node, incarnation,
                                                 challenge.profile_id);
        if (const auto* checkpoint = std::get_if<AttestationCheckpoint>(&loaded);
            checkpoint &&
            std::holds_alternative<SvsmAkActivationRecord>(enrolled) &&
            checkpoint->profile_ruleset == challenge.profile_ruleset &&
            checkpoint->policy_digest == policy_digest_ &&
            checkpoint_matches_release_and_activation(
                *checkpoint, std::get<SvsmAkActivationRecord>(enrolled), profile_)) {
            challenge.ima_mode = ImaEvidenceMode::Resume;
            challenge.ima_checkpoint_digest = checkpoint->checkpoint_digest;
            challenge.ima_prior_event_count = checkpoint->event_count;
            challenge.ima_prior_pcr10 = checkpoint->pcr10;
            challenge.ima_checkpoint_paths = checkpoint->required_paths;
        }
    }
    // A new challenge replaces any unanswered one: only the latest is live.
    pending_[node] = challenge;
    return challenge;
}

std::optional<AttestationChallenge> AttestationService::create_challenge(
    const NodeId& node, const crypto::Ed25519PublicKey& node_key,
    IncarnationId incarnation, EpochId epoch, AttestationPurpose purpose,
    const Digest& context) {
    // A final challenge with no bound context would recreate the reusable
    // attestation this binding exists to remove; an eligibility challenge with
    // a caller-chosen context would let the caller relabel one.
    if (purpose == AttestationPurpose::FinalEpochReadiness && context == Digest{}) {
        return std::nullopt;
    }
    if (purpose == AttestationPurpose::Eligibility && context != Digest{}) {
        return std::nullopt;
    }
    if (purpose == AttestationPurpose::FinalEpochReadiness) {
        auto& used = final_attempts_[{node, context}];
        if (used >= constants::kMaxFinalAttestAttemptsPerPlan) {
            return std::nullopt;
        }
        ++used;
        while (final_attempts_.size() > 4 * constants::kMaxActiveTier1) {
            final_attempts_.erase(final_attempts_.begin());
        }
    } else {
        auto& used = attempts_[{epoch, node}];
        if (used >= constants::kMaxTier1AttestAttemptsPerEpoch) {
            return std::nullopt;
        }
        ++used;
    }

    const Digest bound_context =
        purpose == AttestationPurpose::Eligibility
            ? eligibility_attestation_context(network_id_, epoch, node, incarnation)
            : context;
    if (kTier1AttestationProfileId == AttestationProfileId::SnpSvsmVtpm) {
        const auto activation = activations_.load(network_id_, node, incarnation,
                                                  kTier1AttestationProfileId);
        const auto* record = std::get_if<SvsmAkActivationRecord>(&activation);
        if (!record || record->node_key != node_key) {
            deferred_[node] = {purpose, bound_context, epoch};
            return make_challenge(node, node_key, incarnation, epoch,
                                  AttestationPurpose::PlatformEnrollment,
                                  bound_context);
        }
    }
    return make_challenge(node, node_key, incarnation, epoch, purpose, bound_context);
}

AttestationVerdict AttestationService::receive_evidence(const AttestationEvidence& evidence) {
    AttestationVerdict rejected;
    rejected.node_id = evidence.node_id;
    rejected.incarnation = evidence.incarnation;
    rejected.epoch = evidence.epoch;
    rejected.purpose = evidence.purpose;
    rejected.context_digest = evidence.context_digest;
    rejected.policy_digest = policy_digest_;
    rejected.failure = AttestationFailure::ChallengeMismatch;

    const auto pending = pending_.find(evidence.node_id);
    if (pending == pending_.end()) {
        return rejected;
    }

    // The challenge is one-shot, but only a bundle that actually answers it may
    // consume it. A stale or hostile bundle that names the right node otherwise
    // cancels the live challenge, and the honest answer that follows then finds
    // nothing pending. Match first, consume second.
    if (evidence.challenge_digest != challenge_digest(pending->second)) {
        return rejected;
    }
    const AttestationChallenge challenge = pending->second;
    pending_.erase(pending);

    PlatformVerificationState state;
    std::optional<ImaBinaryReplayState> ima_state;
    state.ima_state_out = &ima_state;
    std::optional<SvsmAkActivationRecord> activation;
    std::optional<AttestationCheckpoint> checkpoint;
    if (challenge.profile_id == AttestationProfileId::SnpSvsmVtpm) {
        auto loaded_activation = activations_.load(network_id_, challenge.node_id,
                                                   challenge.incarnation,
                                                   challenge.profile_id);
        if (const auto* value = std::get_if<SvsmAkActivationRecord>(&loaded_activation)) {
            activation = *value;
            state.activation = &*activation;
        }
        if (challenge.ima_mode == ImaEvidenceMode::Resume) {
            auto loaded_checkpoint = checkpoints_.load(network_id_, challenge.node_id,
                                                       challenge.incarnation,
                                                       challenge.profile_id);
            if (const auto* value = std::get_if<AttestationCheckpoint>(&loaded_checkpoint);
                value && value->checkpoint_digest == challenge.ima_checkpoint_digest &&
                value->event_count == challenge.ima_prior_event_count &&
                value->pcr10 == challenge.ima_prior_pcr10) {
                checkpoint = *value;
                state.checkpoint = &*checkpoint;
            }
        }
    }
    AttestationVerdict verdict = verifier_.examine(challenge, evidence, state);
    if (!verdict.passed && verdict.failure == AttestationFailure::VtpmBindingInvalid &&
        activation) {
        // The AK rotates on reboot; drop the record pinning the old one so the
        // next challenge re-runs enrollment.
        (void)activations_.remove(network_id_, challenge.node_id, challenge.incarnation,
                                  challenge.profile_id);
    }
    if (verdict.passed && activation) {
        const auto* svsm = std::get_if<SnpSvsmVtpmEvidence>(&evidence.platform);
        // The provider already replayed the transferred log once; the next
        // checkpoint is built from the state it carried out.
        const auto report = svsm ? parse_snp_report(svsm->svsm_report) : std::nullopt;
        if (!svsm || !ima_state || !report) {
            verdict.passed = false;
            verdict.failure = AttestationFailure::CheckpointInvalid;
        } else {
            AttestationCheckpoint next;
            next.network_id = network_id_;
            next.node_id = challenge.node_id;
            next.incarnation = challenge.incarnation;
            next.profile_id = challenge.profile_id;
            next.profile_ruleset = challenge.profile_ruleset;
            next.policy_digest = policy_digest_;
            next.launch_measurement = report->measurement;
            next.ek_name = activation->ek_name;
            next.ak_name = activation->ak_name;
            next.ima_bank = kTpmAlgSha256;
            next.event_count = ima_state->event_count;
            std::copy(ima_state->pcr10.begin(), ima_state->pcr10.end(),
                      next.pcr10.begin());
            for (const auto& required : profile_.approved_paths) {
                const auto found = std::find_if(ima_state->paths.begin(),
                                                ima_state->paths.end(),
                    [&required](const auto& path) { return path.path == required.path; });
                if (found != ima_state->paths.end())
                    next.required_paths.push_back({found->path, found->sha256});
            }
            next.previous_evidence_digest = verdict.evidence_digest;
            if (next.required_paths.size() != profile_.approved_paths.size() ||
                !checkpoints_.store(std::move(next))) {
                verdict.passed = false;
                verdict.failure = AttestationFailure::CheckpointInvalid;
            }
        }
    }
    verdicts_[evidence.node_id] = verdict;
    return verdict;
}

std::optional<SvsmAkActivationOfferMessage>
AttestationService::receive_enrollment_evidence(const AttestationEvidence& evidence,
                                                const NodeId& observer,
                                                EnrollmentRefusal* refusal) {
    const auto refuse = [refusal](EnrollmentRefusal reason)
        -> std::optional<SvsmAkActivationOfferMessage> {
        if (refusal) *refusal = reason;
        return std::nullopt;
    };
    if (refusal) *refusal = EnrollmentRefusal::None;
    const auto it = pending_.find(evidence.node_id);
    if (it == pending_.end() || it->second.purpose != AttestationPurpose::PlatformEnrollment ||
        evidence.challenge_digest != challenge_digest(it->second) ||
        evidence.purpose != AttestationPurpose::PlatformEnrollment ||
        evidence.node_id != it->second.node_id || evidence.incarnation != it->second.incarnation ||
        evidence.profile_id != AttestationProfileId::SnpSvsmVtpm ||
        evidence.profile_ruleset != kAttestationProfileRulesetVersion ||
        crypto_sign_verify_detached(evidence.identity_signature.data(),
                                    evidence_signing_digest(evidence).data(), kDigestSize,
                                    it->second.node_key.data()) != 0) {
        return refuse(EnrollmentRefusal::ChallengeMismatch);
    }
    const auto* svsm = std::get_if<SnpSvsmVtpmEvidence>(&evidence.platform);
    if (!svsm || !svsm->ima_binary_log.empty())
        return refuse(EnrollmentRefusal::EvidenceMalformed);
    SvsmAkEnrollmentRequirements requirements;
    requirements.policy = profile_.snp;
    requirements.require_revocation_check = profile_.require_endorsement_revocation;
    if (revocation_) requirements.revocation = revocation_();
    const auto identity = verify_svsm_ak_enrollment_identity(
        *svsm, evidence.challenge_digest, requirements);
    if (!identity.ok) {
        log_enrollment_refusal(evidence.node_id, identity.failure);
        return refuse(EnrollmentRefusal::IdentityRejected);
    }
    auto activation = make_svsm_ak_activation_challenge(svsm->ek_manifest, svsm->ak_public);
    if (!activation) return refuse(EnrollmentRefusal::ActivationUnavailable);

    SvsmAkActivationOfferMessage offer;
    offer.network_id = network_id_;
    offer.subject_node = evidence.node_id;
    offer.subject_key = it->second.node_key;
    offer.incarnation = evidence.incarnation;
    offer.epoch = evidence.epoch;
    offer.profile_id = evidence.profile_id;
    offer.profile_ruleset = evidence.profile_ruleset;
    offer.observer = observer;
    offer.enrollment_challenge_digest = evidence.challenge_digest;
    randombytes_buf(offer.verifier_nonce.data(), offer.verifier_nonce.size());
    offer.ek_public = svsm->ek_manifest;
    offer.ak_public = svsm->ak_public;
    offer.ek_name = identity.ek_name;
    offer.ak_name = identity.ak_name;
    const auto spki = crypto::from_base64(identity.ak_spki_b64);
    offer.ak_spki_digest = raw_ima_digest(spki);
    offer.activation = svsm_ak_activation_offer(evidence.challenge_digest, *activation);
    offer.activation.enrollment_context = svsm_ak_activation_offer_context(offer);
    const auto deferred = deferred_.find(evidence.node_id);
    if (deferred == deferred_.end()) return refuse(EnrollmentRefusal::DeferredMissing);
    PendingActivation pending;
    pending.exchange.emplace(*activation, offer);
    pending.enrollment_evidence_digest = evidence_signing_digest(evidence);
    pending.ak_spki_b64 = identity.ak_spki_b64;
    pending.deferred = deferred->second;
    pending_activations_.insert_or_assign(evidence.node_id, std::move(pending));
    pending_.erase(it);
    return offer;
}

void AttestationService::log_enrollment_refusal(const NodeId& node,
                                                const std::string& failure) {
    const auto now = std::chrono::steady_clock::now();
    const auto logged = refusal_logged_.find(node);
    if (logged != refusal_logged_.end() &&
        now - logged->second < kEnrollmentRefusalLogWindow) {
        return;
    }
    refusal_logged_[node] = now;
    while (refusal_logged_.size() > 4 * constants::kMaxActiveTier1) {
        refusal_logged_.erase(refusal_logged_.begin());
    }
    spdlog::warn("[security] enrollment refused for {}: {}",
                 crypto::to_hex(node.span().first(8)), failure);
}

std::optional<AttestationChallenge> AttestationService::receive_activation_response(
    const SvsmAkActivationResponseMessage& response) {
    const auto it = pending_activations_.find(response.subject_node);
    if (it == pending_activations_.end()) return std::nullopt;
    auto& pending = it->second;
    if (!pending.exchange || response.network_id != network_id_) return std::nullopt;
    const auto receipt = pending.exchange->complete(response);
    if (!receipt) return std::nullopt;
    const auto& activation_offer = pending.exchange->offer();
    SvsmAkActivationRecord record;
    record.network_id = network_id_;
    record.node_id = response.subject_node;
    record.node_key = activation_offer.subject_key;
    record.incarnation = response.incarnation;
    record.profile_id = response.profile_id;
    record.profile_ruleset = response.profile_ruleset;
    record.ek_name = activation_offer.ek_name;
    record.ak_name = activation_offer.ak_name;
    record.ak_spki_b64 = pending.ak_spki_b64;
    record.ak_spki_digest = activation_offer.ak_spki_digest;
    record.activation_receipt = *receipt;
    record.enrollment_evidence_digest = pending.enrollment_evidence_digest;
    if (!activations_.store(std::move(record))) return std::nullopt;
    // Copies: the erase below invalidates pending and activation_offer.
    const DeferredChallenge deferred = pending.deferred;
    const auto subject_key = activation_offer.subject_key;
    const auto incarnation = activation_offer.incarnation;
    pending_activations_.erase(it);
    deferred_.erase(response.subject_node);
    return make_challenge(response.subject_node, subject_key, incarnation,
                          deferred.epoch, deferred.purpose, deferred.context);
}

std::optional<AttestationChallenge> AttestationService::pending_challenge(
    const NodeId& node) const {
    const auto it = pending_.find(node);
    return it == pending_.end() ? std::nullopt
                                : std::optional<AttestationChallenge>{it->second};
}

std::optional<AttestationVerdict> AttestationService::verdict(const NodeId& node) const {
    const auto it = verdicts_.find(node);
    if (it == verdicts_.end()) {
        return std::nullopt;
    }
    return it->second;
}

uint32_t AttestationService::attempts(const NodeId& node, EpochId epoch) const {
    const auto it = attempts_.find({epoch, node});
    return it == attempts_.end() ? 0 : it->second;
}

uint32_t AttestationService::final_attempts(const NodeId& node, const Digest& context) const {
    const auto it = final_attempts_.find({node, context});
    return it == final_attempts_.end() ? 0 : it->second;
}

}  // namespace nexus::security
