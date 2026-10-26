#include <LemonadeNexus/Security/Transport/SecurityCodec.hpp>

#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Security/EvidenceSnpVtpm.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include "AuthorityChainCodecDetail.hpp"

#include <cstring>
#include <optional>
#include <string>

namespace nexus::security {

namespace {

using namespace codec_detail;

// --- Encoders ---------------------------------------------------------------

bool encode_challenge(Writer& w, const AttestationChallenge& c) {
    w.fixed(c.network_id);
    w.fixed(c.nonce);
    put_node(w, c.node_id);
    w.fixed(c.node_key);
    w.u64(c.incarnation);
    w.u64(c.epoch);
    w.u16(c.security_ruleset);
    w.u16(c.consensus_ruleset);
    w.u16(static_cast<uint16_t>(c.profile_id));
    w.u16(c.profile_ruleset);
    w.fixed(c.policy_digest);
    w.u16(static_cast<uint16_t>(c.purpose));
    w.fixed(c.context_digest);
    w.u16(static_cast<uint16_t>(c.ima_mode));
    w.fixed(c.ima_checkpoint_digest);
    w.u64(c.ima_prior_event_count);
    w.fixed(c.ima_prior_pcr10);
    if (c.ima_checkpoint_paths.size() > constants::kMaxSummarisedPaths) return false;
    w.u16(static_cast<uint16_t>(c.ima_checkpoint_paths.size()));
    for (const auto& path : c.ima_checkpoint_paths) {
        // Decode requires exactly 64 hex chars; refuse to emit anything else.
        if (path.sha256.size() != 64) return false;
        if (!w.bytes({reinterpret_cast<const uint8_t*>(path.path.data()), path.path.size()}, 4096) ||
            !w.bytes({reinterpret_cast<const uint8_t*>(path.sha256.data()), path.sha256.size()}, 64))
            return false;
    }
    return true;
}

bool encode_evidence(Writer& w, const AttestationEvidence& e) {
    w.fixed(e.network_id);
    w.fixed(e.challenge_digest);
    put_node(w, e.node_id);
    w.u64(e.incarnation);
    w.u64(e.epoch);
    w.u16(e.security_ruleset);
    w.u16(e.consensus_ruleset);
    w.u16(static_cast<uint16_t>(e.profile_id));
    w.u16(e.profile_ruleset);
    w.u16(static_cast<uint16_t>(e.purpose));
    w.fixed(e.context_digest);
    w.u16(static_cast<uint16_t>(e.ima_mode));
    w.u64(e.ima_bytes);
    w.fixed(e.ima_digest);
    w.fixed(e.epoch_vote_key);
    const std::string platform = encode_platform_evidence(e.platform);
    if (!w.bytes({reinterpret_cast<const uint8_t*>(platform.data()), platform.size()},
                 constants::kMaxPlatformEvidenceWireBytes)) {
        return false;
    }
    w.fixed(e.identity_signature);
    return true;
}

bool encode_transfer_start(Writer& w, const AttestationEvidenceStart& s) {
    w.fixed(s.challenge_digest); w.fixed(s.transfer_id);
    w.u16(static_cast<uint16_t>(s.mode)); w.u64(s.total_transfer_bytes);
    w.u64(s.ima_bytes); w.u32(s.total_chunks); w.fixed(s.ima_digest);
    w.fixed(s.platform_digest);
    return encode_evidence(w, s.evidence);
}

bool encode_transfer_chunk(Writer& w, const AttestationEvidenceChunk& c) {
    w.fixed(c.challenge_digest); w.fixed(c.transfer_id); w.u32(c.chunk_index);
    return w.bytes(c.bytes, constants::kMaxEvidenceChunkBytes);
}

bool encode_transfer_end(Writer& w, const AttestationEvidenceEnd& e) {
    w.fixed(e.challenge_digest); w.fixed(e.transfer_id); w.u64(e.total_transfer_bytes);
    w.u64(e.ima_bytes); w.u32(e.total_chunks); w.fixed(e.ima_digest);
    w.fixed(e.platform_digest); return true;
}

bool encode_activation_offer(Writer& w, const SvsmAkActivationOfferMessage& o) {
    w.fixed(o.network_id); put_node(w, o.subject_node); w.fixed(o.subject_key);
    w.u64(o.incarnation); w.u64(o.epoch); w.u16(static_cast<uint16_t>(o.profile_id));
    w.u16(o.profile_ruleset); put_node(w, o.observer);
    w.fixed(o.enrollment_challenge_digest); w.fixed(o.verifier_nonce);
    if (!w.bytes(o.ek_public, 4096) || !w.bytes(o.ak_public, 4096) ||
        !w.bytes(o.ek_name, 64) || !w.bytes(o.ak_name, 64)) return false;
    w.fixed(o.ak_spki_digest); w.u32(o.activation.version);
    w.fixed(o.activation.enrollment_context);
    return w.bytes(o.activation.credential_blob, 4096) &&
           w.bytes(o.activation.encrypted_secret, 4096);
}

bool encode_activation_response(Writer& w, const SvsmAkActivationResponseMessage& r) {
    w.fixed(r.network_id); put_node(w, r.subject_node); w.u64(r.incarnation); w.u64(r.epoch);
    w.u16(static_cast<uint16_t>(r.profile_id)); w.u16(r.profile_ruleset);
    put_node(w, r.observer); w.fixed(r.activation_context);
    if (!w.bytes(r.activated_secret, 64)) return false;
    w.fixed(r.identity_signature); return true;
}

bool encode_proposal(Writer& w, const ProposalMessage& m) {
    return encode_proposal_core(w, m.proposal, m.justify);
}

// The HotStuffProposal body: the proposal and certificate, then the payload
// when the block carries one. Nothing follows a payload-free proposal, so
// such a message keeps its earlier bytes.
bool encode_proposal_message(Writer& w, const ProposalMessage& m) {
    if (!encode_proposal(w, m)) {
        return false;
    }
    if (!m.payload.has_value()) {
        return true;
    }
    if (!block_payload_kind_known(static_cast<uint16_t>(m.payload->kind))) {
        return false;
    }
    w.u16(static_cast<uint16_t>(m.payload->kind));
    return w.bytes(m.payload->body, constants::kMaxBlockPayloadBytes);
}

bool encode_tree_op_submit(Writer& w, const TreeOpSubmitMsg& m) {
    if (!w.bytes(m.encoded_op, constants::kMaxConsensusBlockBytes)) {
        return false;
    }
    w.fixed(m.signature);
    return true;
}

constexpr std::size_t kMaxSealedPartialBytes = 256;

bool encode_storage_plan_proof(Writer& w, const StoragePlanProofMsg& m) {
    if (m.payload.kind != BlockPayloadKind::StorageHolderPlan &&
        m.payload.kind != BlockPayloadKind::StorageKeyRotation) {
        return false;
    }
    w.u16(static_cast<uint16_t>(m.payload.kind));
    if (!w.bytes(m.payload.body, constants::kMaxBlockPayloadBytes)) {
        return false;
    }
    return encode_commit_proof(w, m.proof);
}

bool encode_storage_key_package(Writer& w, const StorageKeyPackageMsg& m) {
    w.fixed(m.session);
    put_node(w, m.sender);
    w.u8(static_cast<uint8_t>(m.round));
    put_node(w, m.recipient);
    if (!w.bytes(m.payload, constants::kMaxStorageMessageBytes)) {
        return false;
    }
    w.fixed(m.signature);
    return true;
}

bool encode_storage_unlock_request(Writer& w, const StorageUnlockRequestMsg& m) {
    put_node(w, m.requester);
    w.u64(m.epoch);
    w.fixed(m.plan_digest);
    w.fixed(m.ephemeral_point);
    w.fixed(m.nonce);
    return true;
}

bool encode_storage_unlock_partial(Writer& w, const StorageUnlockPartialMsg& m) {
    put_node(w, m.holder);
    w.fixed(m.request_digest);
    w.u16(m.holder_id);
    return w.bytes(m.sealed_partial, kMaxSealedPartialBytes);
}

bool encode_storage_plan_request(Writer& w, const StoragePlanRequestMsg& m) {
    w.u64(m.have_sequence);
    return true;
}

bool encode_storage_wrap_claim(Writer& w, const StorageWrapClaimMsg& m) {
    if (m.wraps.empty() || m.wraps.size() > constants::kStorageMaxWrapsPerClaim) {
        return false;
    }
    put_node(w, m.node);
    w.u64(m.counter);
    w.u8(static_cast<uint8_t>(m.wraps.size()));
    for (const auto& wrap : m.wraps) {
        w.fixed(wrap.storage_public_key);
        w.fixed(wrap.ephemeral_point);
    }
    w.fixed(m.signature);
    return true;
}

bool upgrade_topic_known(uint8_t topic) {
    return topic >= static_cast<uint8_t>(UpgradeTopic::ApprovalOffer) &&
           topic <= static_cast<uint8_t>(UpgradeTopic::RecordRequest);
}

bool encode_upgrade(Writer& w, const UpgradeMsg& m) {
    if (!upgrade_topic_known(static_cast<uint8_t>(m.topic)) ||
        m.proof.has_value() != (m.topic == UpgradeTopic::RecordProof)) {
        return false;
    }
    w.u8(static_cast<uint8_t>(m.topic));
    if (!w.bytes(m.body, constants::kMaxUpgradeMessageBytes)) {
        return false;
    }
    return !m.proof.has_value() || encode_commit_proof(w, *m.proof);
}

bool encode_vote(Writer& w, const Vote& v) {
    w.u16(v.consensus_ruleset);
    w.fixed(v.network_id);
    w.u64(v.epoch);
    w.u64(v.height);
    w.u64(v.view);
    w.fixed(v.proposal_digest);
    put_node(w, v.voter);
    w.fixed(v.signature);
    return true;
}

bool encode_timeout(Writer& w, const TimeoutVote& t) {
    w.u16(t.consensus_ruleset);
    w.fixed(t.network_id);
    w.u64(t.epoch);
    w.u64(t.view);
    w.fixed(t.high_qc_digest);
    put_node(w, t.voter);
    w.fixed(t.signature);
    return true;
}

bool encode_dkg(Writer& w, const DkgMessage& d) {
    w.fixed(d.network_id);
    w.u64(d.target_epoch);
    w.fixed(d.session_digest);
    put_node(w, d.sender);
    w.u64(d.sender_incarnation);
    w.u16(static_cast<uint16_t>(d.round));
    put_node(w, d.recipient);
    return w.bytes(d.payload, constants::kMaxDkgPayloadBytes);
}

void encode_signing_header(Writer& w, const SigningMessageHeader& h) {
    w.fixed(h.network_id);
    w.u64(h.epoch);
    w.u64(h.key_generation);
    w.u64(h.session_id);
    w.fixed(h.object_digest);
    put_node(w, h.sender);
}

bool encode_commitment(Writer& w, const FrostCommitmentMessage& m) {
    encode_signing_header(w, m.header);
    return w.bytes(m.commitment, constants::kMaxFrostPayloadBytes);
}

bool encode_share(Writer& w, const FrostShareMessage& m) {
    encode_signing_header(w, m.header);
    return w.bytes(m.share, constants::kMaxFrostPayloadBytes);
}

bool encode_announcement(Writer& w, const EpochAnnouncement& a) {
    const EpochAuthority& e = a.authority;
    w.fixed(e.network_id);
    w.u64(e.epoch);
    w.u64(e.key_generation);
    w.u16(e.security_ruleset);
    w.u16(e.consensus_ruleset);
    w.fixed(e.tier1_set_digest);
    w.u64(e.consensus_quorum);
    w.u64(e.authority_threshold);
    if (!w.bytes({reinterpret_cast<const uint8_t*>(e.frost_ciphersuite.data()),
                  e.frost_ciphersuite.size()},
                 constants::kMaxCiphersuiteNameBytes)) {
        return false;
    }
    w.fixed(e.group_public_key);
    w.fixed(e.dkg_transcript_digest);
    w.fixed(e.attestation_root);
    w.fixed(e.previous_checkpoint);
    w.fixed(a.handoff_certificate_digest);
    return true;
}

bool encode_founding(Writer& w, const GenesisFounding& f) {
    if (f.members.size() > constants::kMaxActiveTier1) {
        return false;
    }
    w.u64(f.epoch);
    w.u16(static_cast<uint16_t>(f.members.size()));
    for (const auto& [node, vote_key] : f.members) {
        put_node(w, node);
        w.fixed(vote_key);
    }
    w.fixed(f.attestation_root);
    w.fixed(f.release_approval_digest);
    return true;
}

bool encode_transcript_attest(Writer& w, const DkgTranscriptAttest& a) {
    w.u64(a.epoch);
    w.fixed(a.participant_set_digest);
    w.fixed(a.transcript_digest);
    w.fixed(a.group_public_key);
    put_node(w, a.node);
    w.fixed(a.identity_signature);
    return true;
}

bool encode_observation(Writer& w, const EligibilityObservation& o) {
    w.fixed(o.network_id);
    w.u64(o.epoch);
    put_node(w, o.subject);
    w.u64(o.subject_incarnation);
    w.u16(static_cast<uint16_t>(o.kind));
    w.fixed(o.attestation_digest);
    w.u16(static_cast<uint16_t>(o.claims.profile_id));
    w.u16(o.claims.profile_ruleset);
    w.u16(platform_claim_bits(o.claims));
    w.u64(o.height);
    w.fixed(o.state_reference);
    put_node(w, o.observer);
    w.fixed(o.signature);
    return true;
}

bool encode_participation_challenge(Writer& w, const ParticipationChallenge& c) {
    w.fixed(c.network_id);
    w.u64(c.epoch);
    w.u16(c.security_ruleset);
    w.u16(c.consensus_ruleset);
    put_node(w, c.node_id);
    w.u64(c.incarnation);
    w.fixed(c.nonce);
    w.u64(c.anchor_height);
    w.fixed(c.anchor_state);
    put_node(w, c.observer);
    return true;
}

bool encode_participation_response(Writer& w, const ParticipationResponse& r) {
    w.fixed(r.challenge_digest);
    w.fixed(r.network_id);
    w.u64(r.epoch);
    w.u16(r.security_ruleset);
    w.u16(r.consensus_ruleset);
    put_node(w, r.node_id);
    w.u64(r.incarnation);
    w.u64(r.anchor_height);
    w.fixed(r.anchor_state);
    w.fixed(r.identity_signature);
    return true;
}

bool encode_next_epoch_plan(Writer& w, const NextEpochPlan& p) {
    if (p.selected.size() > constants::kMaxActiveTier1) {
        return false;
    }
    w.fixed(p.network_id);
    w.u64(p.current_epoch);
    w.u64(p.next_epoch);
    w.u32(p.attempt);
    w.u64(p.checkpoint_height);
    w.fixed(p.checkpoint_state_root);
    w.fixed(p.eligibility_commitment);
    w.fixed(p.selection_seed);
    w.u16(static_cast<uint16_t>(p.selected.size()));
    for (const auto& node : p.selected) {
        put_node(w, node);
        const auto incarnation = p.incarnations.find(node);
        w.u64(incarnation != p.incarnations.end() ? incarnation->second : 0);
    }
    w.u16(p.security_ruleset);
    w.u16(p.consensus_ruleset);
    w.u16(static_cast<uint16_t>(p.profile_id));
    w.u16(p.profile_ruleset);
    return true;
}

bool encode_plan_proof(Writer& w, const NextEpochPlanProof& m) {
    if (m.current_vote_keys.size() > constants::kMaxActiveTier1) {
        return false;
    }
    if (!encode_next_epoch_plan(w, m.plan) || !encode_commit_proof(w, m.proof)) {
        return false;
    }
    w.u16(static_cast<uint16_t>(m.current_vote_keys.size()));
    for (const auto& [node, key] : m.current_vote_keys) {
        put_node(w, node);
        w.fixed(key);
    }
    return true;
}

bool encode_state_ready(Writer& w, const CandidateStateReadyMsg& m) {
    w.fixed(m.network_id);
    w.fixed(m.plan_digest);
    put_node(w, m.node);
    w.u64(m.incarnation);
    if (!encode_certificate(w, m.verified_qc)) {
        return false;
    }
    w.fixed(m.identity_signature);
    return true;
}

bool encode_readiness(Writer& w, const CandidateReadiness& r) {
    if (r.entries.size() > constants::kMaxActiveTier1) {
        return false;
    }
    w.fixed(r.network_id);
    w.fixed(r.plan_digest);
    w.u64(r.next_epoch);
    w.u16(static_cast<uint16_t>(r.entries.size()));
    for (const auto& entry : r.entries) {
        put_node(w, entry.node);
        w.u64(entry.incarnation);
        w.fixed(entry.attestation_context);
        w.fixed(entry.vote_key);
    }
    return true;
}

bool encode_readiness_proof(Writer& w, const ReadinessProofMsg& m) {
    return encode_readiness(w, m.readiness) && encode_commit_proof(w, m.proof);
}

bool encode_genesis_eligibility_attest(Writer& w, const GenesisEligibilityAttest& a) {
    w.u64(a.epoch);
    w.fixed(a.founding_state_digest);
    put_node(w, a.node);
    w.fixed(a.identity_signature);
    return true;
}

bool encode_sync_request(Writer& w, const SyncRequest& s) {
    w.u64(s.epoch);
    if (s.after_height.has_value()) {
        w.u64(s.after_height->underlying());
    }
    return true;
}

bool encode_sync_response(Writer& w, const SyncResponse& s) {
    if (!encode_certificate(w, s.high_qc)) {
        return false;
    }
    if (s.chain.size() > constants::kMaxSyncChainBlocks) {
        return false;
    }
    w.u16(static_cast<uint16_t>(s.chain.size()));
    for (const auto& block : s.chain) {
        if (!encode_proposal(w, block)) {
            return false;
        }
    }
    return true;
}

// --- Decoders ---------------------------------------------------------------

// A profile ID this binary does not name is refused here rather than folded
// into Unknown: folding would make a corrupted or hostile value re-encode as a
// different one, which is a silent reinterpretation. Unknown itself still
// decodes, and the verifier refuses it with ProviderUnknown.
bool get_profile_id(Reader& r, AttestationProfileId& id) {
    uint16_t raw = 0;
    if (!r.u16(raw)) return false;
    const auto candidate = static_cast<AttestationProfileId>(raw);
    if (candidate != AttestationProfileId::Unknown &&
        !is_known_attestation_profile_id(candidate)) {
        return r.fail(CodecError::BadValue);
    }
    id = candidate;
    return true;
}

// A purpose this binary does not name is refused, not folded: the value picks
// which context rules apply, so a silent reinterpretation would pick them for
// the attacker.
bool get_purpose(Reader& r, AttestationPurpose& purpose) {
    uint16_t raw = 0;
    if (!r.u16(raw)) return false;
    const auto candidate = static_cast<AttestationPurpose>(raw);
    if (candidate != AttestationPurpose::Eligibility &&
        candidate != AttestationPurpose::FinalEpochReadiness &&
        candidate != AttestationPurpose::PlatformEnrollment &&
        candidate != AttestationPurpose::StorageUnlock &&
        candidate != AttestationPurpose::UpgradeHealth) {
        return r.fail(CodecError::BadValue);
    }
    purpose = candidate;
    return true;
}

bool get_ima_mode(Reader& r, ImaEvidenceMode& mode) {
    uint16_t raw = 0;
    if (!r.u16(raw)) return false;
    if (raw != static_cast<uint16_t>(ImaEvidenceMode::Full) &&
        raw != static_cast<uint16_t>(ImaEvidenceMode::Resume))
        return r.fail(CodecError::BadValue);
    mode = static_cast<ImaEvidenceMode>(raw);
    return true;
}

bool decode_challenge(Reader& r, AttestationChallenge& c) {
    if (!(r.fixed(c.network_id) && r.fixed(c.nonce) && get_node(r, c.node_id) &&
           r.fixed(c.node_key) &&
           r.u64(c.incarnation) && r.u64(c.epoch) && r.u16(c.security_ruleset) &&
           r.u16(c.consensus_ruleset) && get_profile_id(r, c.profile_id) &&
           r.u16(c.profile_ruleset) && r.fixed(c.policy_digest) &&
           get_purpose(r, c.purpose) && r.fixed(c.context_digest) &&
           get_ima_mode(r, c.ima_mode) && r.fixed(c.ima_checkpoint_digest) &&
           r.u64(c.ima_prior_event_count) && r.fixed(c.ima_prior_pcr10))) return false;
    uint16_t count = 0;
    if (!r.u16(count)) return false;
    if (count > constants::kMaxSummarisedPaths) return r.fail(CodecError::CountTooLarge);
    c.ima_checkpoint_paths.reserve(count);
    for (uint16_t i = 0; i < count; ++i) {
        std::vector<uint8_t> path, hash;
        // A reader failure keeps the reader's own error; only a hash that read
        // fine but has the wrong size is a bad value.
        if (!r.bytes(path, 4096) || !r.bytes(hash, 64)) return false;
        if (hash.size() != 64) return r.fail(CodecError::BadValue);
        c.ima_checkpoint_paths.push_back({std::string(path.begin(), path.end()),
                                          std::string(hash.begin(), hash.end())});
    }
    const bool full = c.ima_mode == ImaEvidenceMode::Full;
    if (full != (c.ima_checkpoint_digest == Digest{} && c.ima_prior_event_count == 0 &&
                 c.ima_prior_pcr10 == Digest{} && c.ima_checkpoint_paths.empty()))
        return r.fail(CodecError::BadValue);
    return true;
}

bool decode_evidence(Reader& r, AttestationEvidence& e) {
    std::vector<uint8_t> platform;
    if (!(r.fixed(e.network_id) && r.fixed(e.challenge_digest) &&
          get_node(r, e.node_id) && r.u64(e.incarnation) &&
          r.u64(e.epoch) && r.u16(e.security_ruleset) && r.u16(e.consensus_ruleset) &&
          get_profile_id(r, e.profile_id) && r.u16(e.profile_ruleset) &&
          get_purpose(r, e.purpose) && r.fixed(e.context_digest) &&
          get_ima_mode(r, e.ima_mode) && r.u64(e.ima_bytes) && r.fixed(e.ima_digest) &&
          r.fixed(e.epoch_vote_key) &&
          r.bytes(platform, constants::kMaxPlatformEvidenceWireBytes))) {
        return false;
    }
    // An empty bundle is a prover with nothing to show; it decodes to empty
    // evidence and fails verification later, never here.
    if (!platform.empty()) {
        auto decoded = decode_platform_evidence(
            std::string_view(reinterpret_cast<const char*>(platform.data()), platform.size()));
        if (!decoded.has_value()) {
            return r.fail(CodecError::BadValue);
        }
        e.platform = std::move(*decoded);
    }
    return r.fixed(e.identity_signature);
}

bool decode_transfer_start(Reader& r, AttestationEvidenceStart& s) {
    return r.fixed(s.challenge_digest) && r.fixed(s.transfer_id) && get_ima_mode(r, s.mode) &&
           r.u64(s.total_transfer_bytes) && r.u64(s.ima_bytes) && r.u32(s.total_chunks) &&
           r.fixed(s.ima_digest) && r.fixed(s.platform_digest) && decode_evidence(r, s.evidence);
}

bool decode_transfer_chunk(Reader& r, AttestationEvidenceChunk& c) {
    return r.fixed(c.challenge_digest) && r.fixed(c.transfer_id) && r.u32(c.chunk_index) &&
           r.bytes(c.bytes, constants::kMaxEvidenceChunkBytes);
}

bool decode_transfer_end(Reader& r, AttestationEvidenceEnd& e) {
    return r.fixed(e.challenge_digest) && r.fixed(e.transfer_id) &&
           r.u64(e.total_transfer_bytes) && r.u64(e.ima_bytes) && r.u32(e.total_chunks) &&
           r.fixed(e.ima_digest) && r.fixed(e.platform_digest);
}

bool decode_activation_offer(Reader& r, SvsmAkActivationOfferMessage& o) {
    return r.fixed(o.network_id) && get_node(r, o.subject_node) && r.fixed(o.subject_key) &&
           r.u64(o.incarnation) && r.u64(o.epoch) && get_profile_id(r, o.profile_id) &&
           r.u16(o.profile_ruleset) && get_node(r, o.observer) &&
           r.fixed(o.enrollment_challenge_digest) && r.fixed(o.verifier_nonce) &&
           r.bytes(o.ek_public, 4096) && r.bytes(o.ak_public, 4096) &&
           r.bytes(o.ek_name, 64) && r.bytes(o.ak_name, 64) &&
           r.fixed(o.ak_spki_digest) && r.u32(o.activation.version) &&
           r.fixed(o.activation.enrollment_context) &&
           r.bytes(o.activation.credential_blob, 4096) &&
           r.bytes(o.activation.encrypted_secret, 4096);
}

bool decode_activation_response(Reader& r, SvsmAkActivationResponseMessage& m) {
    return r.fixed(m.network_id) && get_node(r, m.subject_node) && r.u64(m.incarnation) &&
           r.u64(m.epoch) &&
           get_profile_id(r, m.profile_id) && r.u16(m.profile_ruleset) &&
           get_node(r, m.observer) && r.fixed(m.activation_context) &&
           r.bytes(m.activated_secret, 64) && r.fixed(m.identity_signature);
}

bool decode_proposal(Reader& r, ProposalMessage& m) {
    return decode_proposal_core(r, m.proposal, m.justify);
}

bool decode_proposal_message(Reader& r, ProposalMessage& m) {
    if (!decode_proposal(r, m)) {
        return false;
    }
    if (r.remaining() == 0) {
        return true;
    }
    uint16_t kind = 0;
    if (!r.u16(kind)) {
        return false;
    }
    if (!block_payload_kind_known(kind)) {
        return r.fail(CodecError::BadValue);
    }
    BlockPayload payload;
    payload.kind = static_cast<BlockPayloadKind>(kind);
    if (!r.bytes(payload.body, constants::kMaxBlockPayloadBytes)) {
        return false;
    }
    m.payload = std::move(payload);
    return true;
}

bool decode_tree_op_submit(Reader& r, TreeOpSubmitMsg& m) {
    return r.bytes(m.encoded_op, constants::kMaxConsensusBlockBytes) && !m.encoded_op.empty() &&
           r.fixed(m.signature);
}

bool decode_storage_plan_proof(Reader& r, StoragePlanProofMsg& m) {
    uint16_t kind = 0;
    if (!r.u16(kind)) {
        return false;
    }
    if (kind != static_cast<uint16_t>(BlockPayloadKind::StorageHolderPlan) &&
        kind != static_cast<uint16_t>(BlockPayloadKind::StorageKeyRotation)) {
        return r.fail(CodecError::BadValue);
    }
    m.payload.kind = static_cast<BlockPayloadKind>(kind);
    return r.bytes(m.payload.body, constants::kMaxBlockPayloadBytes) &&
           decode_commit_proof(r, m.proof);
}

bool decode_upgrade(Reader& r, UpgradeMsg& m) {
    uint8_t topic = 0;
    if (!r.u8(topic)) {
        return false;
    }
    if (!upgrade_topic_known(topic)) {
        return r.fail(CodecError::BadValue);
    }
    m.topic = static_cast<UpgradeTopic>(topic);
    if (!r.bytes(m.body, constants::kMaxUpgradeMessageBytes)) {
        return false;
    }
    if (m.topic == UpgradeTopic::RecordProof) {
        CommitProof proof;
        if (!decode_commit_proof(r, proof)) {
            return false;
        }
        m.proof = std::move(proof);
    }
    return true;
}

bool decode_storage_key_package(Reader& r, StorageKeyPackageMsg& m) {
    uint8_t round = 0;
    if (!(r.fixed(m.session) && get_node(r, m.sender) && r.u8(round))) {
        return false;
    }
    if (round < static_cast<uint8_t>(StorageRound::Round1) ||
        round > static_cast<uint8_t>(StorageRound::Confirm)) {
        return r.fail(CodecError::BadValue);
    }
    m.round = static_cast<StorageRound>(round);
    return get_node(r, m.recipient) && r.bytes(m.payload, constants::kMaxStorageMessageBytes) &&
           r.fixed(m.signature);
}

bool decode_storage_unlock_request(Reader& r, StorageUnlockRequestMsg& m) {
    return get_node(r, m.requester) && r.u64(m.epoch) && r.fixed(m.plan_digest) &&
           r.fixed(m.ephemeral_point) && r.fixed(m.nonce);
}

bool decode_storage_unlock_partial(Reader& r, StorageUnlockPartialMsg& m) {
    return get_node(r, m.holder) && r.fixed(m.request_digest) && r.u16(m.holder_id) &&
           r.bytes(m.sealed_partial, kMaxSealedPartialBytes);
}

bool decode_storage_wrap_claim(Reader& r, StorageWrapClaimMsg& m) {
    uint8_t count = 0;
    if (!(get_node(r, m.node) && r.u64(m.counter) && r.u8(count))) {
        return false;
    }
    if (count == 0 || count > constants::kStorageMaxWrapsPerClaim) {
        return r.fail(CodecError::CountTooLarge);
    }
    m.wraps.resize(count);
    for (auto& wrap : m.wraps) {
        if (!(r.fixed(wrap.storage_public_key) && r.fixed(wrap.ephemeral_point))) {
            return false;
        }
    }
    return r.fixed(m.signature);
}

bool decode_vote(Reader& r, Vote& v) {
    return r.u16(v.consensus_ruleset) && r.fixed(v.network_id) && r.u64(v.epoch) &&
           r.u64(v.height) && r.u64(v.view) && r.fixed(v.proposal_digest) &&
           get_node(r, v.voter) && r.fixed(v.signature);
}

bool decode_timeout(Reader& r, TimeoutVote& t) {
    return r.u16(t.consensus_ruleset) && r.fixed(t.network_id) && r.u64(t.epoch) &&
           r.u64(t.view) && r.fixed(t.high_qc_digest) && get_node(r, t.voter) &&
           r.fixed(t.signature);
}

bool decode_dkg(Reader& r, DkgMessage& d, SecurityMessageKind kind) {
    uint16_t round = 0;
    if (!(r.fixed(d.network_id) && r.u64(d.target_epoch) && r.fixed(d.session_digest) &&
          get_node(r, d.sender) && r.u64(d.sender_incarnation) && r.u16(round))) {
        return false;
    }
    if (round != static_cast<uint16_t>(DkgRound::Round1Broadcast) &&
        round != static_cast<uint16_t>(DkgRound::Round2Pairwise)) {
        return r.fail(CodecError::BadValue);
    }
    d.round = static_cast<DkgRound>(round);
    const bool pairwise = d.round == DkgRound::Round2Pairwise;
    if (pairwise != (kind == SecurityMessageKind::DkgPairwise)) {
        return r.fail(CodecError::KindMismatch);
    }
    return get_node(r, d.recipient) && r.bytes(d.payload, constants::kMaxDkgPayloadBytes);
}

bool decode_signing_header(Reader& r, SigningMessageHeader& h) {
    return r.fixed(h.network_id) && r.u64(h.epoch) && r.u64(h.key_generation) &&
           r.u64(h.session_id) && r.fixed(h.object_digest) && get_node(r, h.sender);
}

bool decode_commitment(Reader& r, FrostCommitmentMessage& m) {
    return decode_signing_header(r, m.header) &&
           r.bytes(m.commitment, constants::kMaxFrostPayloadBytes);
}

bool decode_share(Reader& r, FrostShareMessage& m) {
    return decode_signing_header(r, m.header) && r.bytes(m.share, constants::kMaxFrostPayloadBytes);
}

bool decode_announcement(Reader& r, EpochAnnouncement& a) {
    EpochAuthority& e = a.authority;
    std::vector<uint8_t> suite;
    uint64_t quorum = 0;
    uint64_t threshold = 0;
    if (!(r.fixed(e.network_id) && r.u64(e.epoch) && r.u64(e.key_generation) &&
          r.u16(e.security_ruleset) && r.u16(e.consensus_ruleset) && r.fixed(e.tier1_set_digest) &&
          r.u64(quorum) && r.u64(threshold) &&
          r.bytes(suite, constants::kMaxCiphersuiteNameBytes))) {
        return false;
    }
    e.consensus_quorum = static_cast<std::size_t>(quorum);
    e.authority_threshold = static_cast<std::size_t>(threshold);
    e.frost_ciphersuite.assign(suite.begin(), suite.end());
    return r.fixed(e.group_public_key) && r.fixed(e.dkg_transcript_digest) &&
           r.fixed(e.attestation_root) && r.fixed(e.previous_checkpoint) &&
           r.fixed(a.handoff_certificate_digest);
}

bool decode_founding(Reader& r, GenesisFounding& f) {
    uint16_t count = 0;
    if (!(r.u64(f.epoch) && r.u16(count))) {
        return false;
    }
    if (count > constants::kMaxActiveTier1) {
        return r.fail(CodecError::CountTooLarge);
    }
    f.members.resize(count);
    for (auto& [node, vote_key] : f.members) {
        if (!(get_node(r, node) && r.fixed(vote_key))) {
            return false;
        }
    }
    return r.fixed(f.attestation_root) && r.fixed(f.release_approval_digest);
}

bool decode_transcript_attest(Reader& r, DkgTranscriptAttest& a) {
    return r.u64(a.epoch) && r.fixed(a.participant_set_digest) && r.fixed(a.transcript_digest) &&
           r.fixed(a.group_public_key) && get_node(r, a.node) && r.fixed(a.identity_signature);
}

bool decode_observation(Reader& r, EligibilityObservation& o) {
    uint16_t kind = 0;
    AttestationProfileId profile = AttestationProfileId::Unknown;
    uint16_t profile_ruleset = 0;
    uint16_t claim_bits = 0;
    if (!(r.fixed(o.network_id) && r.u64(o.epoch) && get_node(r, o.subject) &&
          r.u64(o.subject_incarnation) && r.u16(kind) && r.fixed(o.attestation_digest) &&
          get_profile_id(r, profile) && r.u16(profile_ruleset) && r.u16(claim_bits) &&
          r.u64(o.height) && r.fixed(o.state_reference) && get_node(r, o.observer) &&
          r.fixed(o.signature))) {
        return false;
    }
    // An unnamed kind, profile or claim bit is refused rather than folded into
    // a named one: folding would let a hostile value re-encode as something the
    // sender never signed.
    if (kind > static_cast<uint16_t>(ObservationKind::Participation)) {
        return r.fail(CodecError::BadValue);
    }
    if ((claim_bits & ~kPlatformClaimBitMask) != 0) {
        return r.fail(CodecError::BadValue);
    }
    o.kind = static_cast<ObservationKind>(kind);
    o.claims = platform_claims_from_bits(profile, profile_ruleset, claim_bits);
    return true;
}

bool decode_participation_challenge(Reader& r, ParticipationChallenge& c) {
    return r.fixed(c.network_id) && r.u64(c.epoch) && r.u16(c.security_ruleset) &&
           r.u16(c.consensus_ruleset) && get_node(r, c.node_id) && r.u64(c.incarnation) &&
           r.fixed(c.nonce) && r.u64(c.anchor_height) && r.fixed(c.anchor_state) &&
           get_node(r, c.observer);
}

bool decode_participation_response(Reader& r, ParticipationResponse& p) {
    return r.fixed(p.challenge_digest) && r.fixed(p.network_id) && r.u64(p.epoch) &&
           r.u16(p.security_ruleset) && r.u16(p.consensus_ruleset) && get_node(r, p.node_id) &&
           r.u64(p.incarnation) && r.u64(p.anchor_height) && r.fixed(p.anchor_state) &&
           r.fixed(p.identity_signature);
}

bool decode_next_epoch_plan(Reader& r, NextEpochPlan& p) {
    uint16_t count = 0;
    if (!(r.fixed(p.network_id) && r.u64(p.current_epoch) && r.u64(p.next_epoch) &&
          r.u32(p.attempt) && r.u64(p.checkpoint_height) && r.fixed(p.checkpoint_state_root) &&
          r.fixed(p.eligibility_commitment) && r.fixed(p.selection_seed) && r.u16(count))) {
        return false;
    }
    if (count > constants::kMaxActiveTier1) {
        return r.fail(CodecError::CountTooLarge);
    }
    for (uint16_t i = 0; i < count; ++i) {
        NodeId node;
        uint64_t incarnation = 0;
        if (!(get_node(r, node) && r.u64(incarnation))) {
            return false;
        }
        p.selected.push_back(node);
        p.incarnations[node] = incarnation;
    }
    uint16_t profile = 0;
    if (!(r.u16(p.security_ruleset) && r.u16(p.consensus_ruleset) && r.u16(profile) &&
          r.u16(p.profile_ruleset))) {
        return false;
    }
    const auto named = static_cast<AttestationProfileId>(profile);
    if (named != AttestationProfileId::Unknown && !is_known_attestation_profile_id(named)) {
        return r.fail(CodecError::BadValue);
    }
    p.profile_id = named;
    return true;
}

bool decode_plan_proof(Reader& r, NextEpochPlanProof& m) {
    if (!(decode_next_epoch_plan(r, m.plan) && decode_commit_proof(r, m.proof))) {
        return false;
    }
    uint16_t count = 0;
    if (!r.u16(count)) {
        return false;
    }
    if (count > constants::kMaxActiveTier1) {
        return r.fail(CodecError::CountTooLarge);
    }
    for (uint16_t i = 0; i < count; ++i) {
        NodeId node;
        nexus::crypto::Ed25519PublicKey key{};
        if (!(get_node(r, node) && r.fixed(key))) {
            return false;
        }
        m.current_vote_keys.emplace_back(node, key);
    }
    return true;
}

bool decode_state_ready(Reader& r, CandidateStateReadyMsg& m) {
    return r.fixed(m.network_id) && r.fixed(m.plan_digest) && get_node(r, m.node) &&
           r.u64(m.incarnation) && decode_certificate(r, m.verified_qc) &&
           r.fixed(m.identity_signature);
}

bool decode_readiness(Reader& r, CandidateReadiness& out) {
    uint16_t count = 0;
    if (!(r.fixed(out.network_id) && r.fixed(out.plan_digest) && r.u64(out.next_epoch) &&
          r.u16(count))) {
        return false;
    }
    if (count > constants::kMaxActiveTier1) {
        return r.fail(CodecError::CountTooLarge);
    }
    out.entries.resize(count);
    for (auto& entry : out.entries) {
        if (!(get_node(r, entry.node) && r.u64(entry.incarnation) &&
              r.fixed(entry.attestation_context) && r.fixed(entry.vote_key))) {
            return false;
        }
    }
    return true;
}

bool decode_readiness_proof(Reader& r, ReadinessProofMsg& m) {
    return decode_readiness(r, m.readiness) && decode_commit_proof(r, m.proof);
}

bool decode_genesis_eligibility_attest(Reader& r, GenesisEligibilityAttest& a) {
    return r.u64(a.epoch) && r.fixed(a.founding_state_digest) && get_node(r, a.node) &&
           r.fixed(a.identity_signature);
}

bool decode_sync_request(Reader& r, SyncRequest& s) {
    if (!r.u64(s.epoch)) {
        return false;
    }
    if (r.remaining() == 0) {
        return true;
    }
    uint64_t after = 0;
    if (!r.u64(after)) {
        return false;
    }
    s.after_height = Height{after};
    return true;
}

bool decode_sync_response(Reader& r, SyncResponse& s) {
    if (!decode_certificate(r, s.high_qc)) {
        return false;
    }
    uint16_t count = 0;
    if (!r.u16(count)) {
        return false;
    }
    if (count > constants::kMaxSyncChainBlocks) {
        return r.fail(CodecError::CountTooLarge);
    }
    s.chain.resize(count);
    for (auto& block : s.chain) {
        if (!decode_proposal(r, block)) {
            return false;
        }
    }
    return true;
}

bool decode_body(Reader& r, SecurityMessageKind kind, SecurityBody& body) {
    switch (kind) {
        case SecurityMessageKind::AttestationChallenge: {
            AttestationChallenge c;
            if (!decode_challenge(r, c)) return false;
            body = std::move(c);
            return true;
        }
        case SecurityMessageKind::AttestationEvidence: {
            AttestationEvidence e;
            if (!decode_evidence(r, e)) return false;
            body = std::move(e);
            return true;
        }
        case SecurityMessageKind::HotStuffProposal: {
            ProposalMessage m;
            if (!decode_proposal_message(r, m)) return false;
            body = std::move(m);
            return true;
        }
        case SecurityMessageKind::TreeOpSubmit: {
            TreeOpSubmitMsg m;
            if (!decode_tree_op_submit(r, m)) return false;
            body = std::move(m);
            return true;
        }
        case SecurityMessageKind::StoragePlanProof: {
            StoragePlanProofMsg m;
            if (!decode_storage_plan_proof(r, m)) return false;
            body = std::move(m);
            return true;
        }
        case SecurityMessageKind::StorageKeyPackage: {
            StorageKeyPackageMsg m;
            if (!decode_storage_key_package(r, m)) return false;
            body = std::move(m);
            return true;
        }
        case SecurityMessageKind::StorageUnlockRequest: {
            StorageUnlockRequestMsg m;
            if (!decode_storage_unlock_request(r, m)) return false;
            body = std::move(m);
            return true;
        }
        case SecurityMessageKind::StorageUnlockPartial: {
            StorageUnlockPartialMsg m;
            if (!decode_storage_unlock_partial(r, m)) return false;
            body = std::move(m);
            return true;
        }
        case SecurityMessageKind::StoragePlanRequest: {
            StoragePlanRequestMsg m;
            if (!r.u64(m.have_sequence)) return false;
            body = std::move(m);
            return true;
        }
        case SecurityMessageKind::StorageWrapClaim: {
            StorageWrapClaimMsg m;
            if (!decode_storage_wrap_claim(r, m)) return false;
            body = std::move(m);
            return true;
        }
        case SecurityMessageKind::Upgrade: {
            UpgradeMsg m;
            if (!decode_upgrade(r, m)) return false;
            body = std::move(m);
            return true;
        }
        case SecurityMessageKind::HotStuffVote: {
            Vote v;
            if (!decode_vote(r, v)) return false;
            body = std::move(v);
            return true;
        }
        case SecurityMessageKind::HotStuffTimeout: {
            TimeoutVote t;
            if (!decode_timeout(r, t)) return false;
            body = std::move(t);
            return true;
        }
        case SecurityMessageKind::DkgBroadcast:
        case SecurityMessageKind::DkgPairwise: {
            DkgMessage d;
            if (!decode_dkg(r, d, kind)) return false;
            body = std::move(d);
            return true;
        }
        case SecurityMessageKind::FrostCommitment: {
            FrostCommitmentMessage m;
            if (!decode_commitment(r, m)) return false;
            body = std::move(m);
            return true;
        }
        case SecurityMessageKind::FrostSignatureShare: {
            FrostShareMessage m;
            if (!decode_share(r, m)) return false;
            body = std::move(m);
            return true;
        }
        case SecurityMessageKind::EpochAnnouncement: {
            EpochAnnouncement a;
            if (!decode_announcement(r, a)) return false;
            body = std::move(a);
            return true;
        }
        case SecurityMessageKind::GenesisFounding: {
            GenesisFounding f;
            if (!decode_founding(r, f)) return false;
            body = std::move(f);
            return true;
        }
        case SecurityMessageKind::DkgTranscriptAttest: {
            DkgTranscriptAttest a;
            if (!decode_transcript_attest(r, a)) return false;
            body = std::move(a);
            return true;
        }
        case SecurityMessageKind::BootstrapCertificate: {
            BootstrapCertificate c;
            if (!decode_bootstrap(r, c)) return false;
            body = std::move(c);
            return true;
        }
        case SecurityMessageKind::SyncRequest: {
            SyncRequest s;
            if (!decode_sync_request(r, s)) return false;
            body = std::move(s);
            return true;
        }
        case SecurityMessageKind::SyncResponse: {
            SyncResponse s;
            if (!decode_sync_response(r, s)) return false;
            body = std::move(s);
            return true;
        }
        case SecurityMessageKind::EligibilityObservation: {
            EligibilityObservation o;
            if (!decode_observation(r, o)) return false;
            body = std::move(o);
            return true;
        }
        case SecurityMessageKind::GenesisEligibilityAttest: {
            GenesisEligibilityAttest a;
            if (!decode_genesis_eligibility_attest(r, a)) return false;
            body = std::move(a);
            return true;
        }
        case SecurityMessageKind::ParticipationChallenge: {
            ParticipationChallenge c;
            if (!decode_participation_challenge(r, c)) return false;
            body = std::move(c);
            return true;
        }
        case SecurityMessageKind::ParticipationResponse: {
            ParticipationResponse p;
            if (!decode_participation_response(r, p)) return false;
            body = std::move(p);
            return true;
        }
        case SecurityMessageKind::NextEpochPlanProof: {
            NextEpochPlanProof m;
            if (!decode_plan_proof(r, m)) return false;
            body = std::move(m);
            return true;
        }
        case SecurityMessageKind::CandidateStateReady: {
            CandidateStateReadyMsg m;
            if (!decode_state_ready(r, m)) return false;
            body = std::move(m);
            return true;
        }
        case SecurityMessageKind::ReadinessProof: {
            ReadinessProofMsg m;
            if (!decode_readiness_proof(r, m)) return false;
            body = std::move(m);
            return true;
        }
        case SecurityMessageKind::EpochHandoffProof: {
            EpochHandoffProofMsg m;
            if (!decode_handoff_proof(r, m)) return false;
            body = std::move(m);
            return true;
        }
        case SecurityMessageKind::AuthorityChainRequest: {
            AuthorityChainRequest m;
            if (!decode_chain_request(r, m)) return false;
            body = m;
            return true;
        }
        case SecurityMessageKind::AuthorityChainPage: {
            AuthorityChainPage m;
            if (!decode_chain_page(r, m)) return false;
            body = std::move(m);
            return true;
        }
        case SecurityMessageKind::AttestationEvidenceStart: {
            AttestationEvidenceStart m;
            if (!decode_transfer_start(r, m)) return false;
            body = std::move(m); return true;
        }
        case SecurityMessageKind::AttestationEvidenceChunk: {
            AttestationEvidenceChunk m;
            if (!decode_transfer_chunk(r, m)) return false;
            body = std::move(m); return true;
        }
        case SecurityMessageKind::AttestationEvidenceEnd: {
            AttestationEvidenceEnd m;
            if (!decode_transfer_end(r, m)) return false;
            body = std::move(m); return true;
        }
        case SecurityMessageKind::SvsmAkActivationOffer: {
            SvsmAkActivationOfferMessage m;
            if (!decode_activation_offer(r, m)) return false;
            body = std::move(m); return true;
        }
        case SecurityMessageKind::SvsmAkActivationResponse: {
            SvsmAkActivationResponseMessage m;
            if (!decode_activation_response(r, m)) return false;
            body = std::move(m); return true;
        }
    }
    return r.fail(CodecError::UnknownKind);
}

bool known_kind(uint16_t raw) {
    return raw >= static_cast<uint16_t>(SecurityMessageKind::AttestationChallenge) &&
           raw <= static_cast<uint16_t>(SecurityMessageKind::Upgrade);
}

}  // namespace

Digest candidate_state_ready_digest(const CandidateStateReadyMsg& message) {
    CanonicalEncoder encoder("lemonade-nexus/candidate-state-ready:v1");
    encoder.add_bytes(message.network_id);
    encoder.add_bytes(message.plan_digest);
    encoder.add_bytes(message.node.bytes);
    encoder.add_u64(message.incarnation.underlying());
    encoder.add_bytes(qc_digest(message.verified_qc));
    return encoder.digest();
}

std::optional<SecurityMessageKind> kind_of(const SecurityBody& body) {
    return std::visit(
        [](const auto& value) -> std::optional<SecurityMessageKind> {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, AttestationChallenge>) {
                return SecurityMessageKind::AttestationChallenge;
            } else if constexpr (std::is_same_v<T, AttestationEvidence>) {
                return SecurityMessageKind::AttestationEvidence;
            } else if constexpr (std::is_same_v<T, ProposalMessage>) {
                return SecurityMessageKind::HotStuffProposal;
            } else if constexpr (std::is_same_v<T, Vote>) {
                return SecurityMessageKind::HotStuffVote;
            } else if constexpr (std::is_same_v<T, TimeoutVote>) {
                return SecurityMessageKind::HotStuffTimeout;
            } else if constexpr (std::is_same_v<T, DkgMessage>) {
                if (value.round == DkgRound::Round1Broadcast) {
                    return SecurityMessageKind::DkgBroadcast;
                }
                if (value.round == DkgRound::Round2Pairwise) {
                    return SecurityMessageKind::DkgPairwise;
                }
                return std::nullopt;
            } else if constexpr (std::is_same_v<T, FrostCommitmentMessage>) {
                return SecurityMessageKind::FrostCommitment;
            } else if constexpr (std::is_same_v<T, FrostShareMessage>) {
                return SecurityMessageKind::FrostSignatureShare;
            } else if constexpr (std::is_same_v<T, EpochAnnouncement>) {
                return SecurityMessageKind::EpochAnnouncement;
            } else if constexpr (std::is_same_v<T, GenesisFounding>) {
                return SecurityMessageKind::GenesisFounding;
            } else if constexpr (std::is_same_v<T, DkgTranscriptAttest>) {
                return SecurityMessageKind::DkgTranscriptAttest;
            } else if constexpr (std::is_same_v<T, BootstrapCertificate>) {
                return SecurityMessageKind::BootstrapCertificate;
            } else if constexpr (std::is_same_v<T, SyncRequest>) {
                return SecurityMessageKind::SyncRequest;
            } else if constexpr (std::is_same_v<T, SyncResponse>) {
                return SecurityMessageKind::SyncResponse;
            } else if constexpr (std::is_same_v<T, EligibilityObservation>) {
                return SecurityMessageKind::EligibilityObservation;
            } else if constexpr (std::is_same_v<T, GenesisEligibilityAttest>) {
                return SecurityMessageKind::GenesisEligibilityAttest;
            } else if constexpr (std::is_same_v<T, ParticipationChallenge>) {
                return SecurityMessageKind::ParticipationChallenge;
            } else if constexpr (std::is_same_v<T, ParticipationResponse>) {
                return SecurityMessageKind::ParticipationResponse;
            } else if constexpr (std::is_same_v<T, NextEpochPlanProof>) {
                return SecurityMessageKind::NextEpochPlanProof;
            } else if constexpr (std::is_same_v<T, CandidateStateReadyMsg>) {
                return SecurityMessageKind::CandidateStateReady;
            } else if constexpr (std::is_same_v<T, ReadinessProofMsg>) {
                return SecurityMessageKind::ReadinessProof;
            } else if constexpr (std::is_same_v<T, EpochHandoffProofMsg>) {
                return SecurityMessageKind::EpochHandoffProof;
            } else if constexpr (std::is_same_v<T, AuthorityChainRequest>) {
                return SecurityMessageKind::AuthorityChainRequest;
            } else if constexpr (std::is_same_v<T, AuthorityChainPage>) {
                return SecurityMessageKind::AuthorityChainPage;
            } else if constexpr (std::is_same_v<T, AttestationEvidenceStart>) {
                return SecurityMessageKind::AttestationEvidenceStart;
            } else if constexpr (std::is_same_v<T, AttestationEvidenceChunk>) {
                return SecurityMessageKind::AttestationEvidenceChunk;
            } else if constexpr (std::is_same_v<T, AttestationEvidenceEnd>) {
                return SecurityMessageKind::AttestationEvidenceEnd;
            } else if constexpr (std::is_same_v<T, SvsmAkActivationOfferMessage>) {
                return SecurityMessageKind::SvsmAkActivationOffer;
            } else if constexpr (std::is_same_v<T, TreeOpSubmitMsg>) {
                return SecurityMessageKind::TreeOpSubmit;
            } else if constexpr (std::is_same_v<T, StoragePlanProofMsg>) {
                return SecurityMessageKind::StoragePlanProof;
            } else if constexpr (std::is_same_v<T, StorageKeyPackageMsg>) {
                return SecurityMessageKind::StorageKeyPackage;
            } else if constexpr (std::is_same_v<T, StorageUnlockRequestMsg>) {
                return SecurityMessageKind::StorageUnlockRequest;
            } else if constexpr (std::is_same_v<T, StorageUnlockPartialMsg>) {
                return SecurityMessageKind::StorageUnlockPartial;
            } else if constexpr (std::is_same_v<T, StoragePlanRequestMsg>) {
                return SecurityMessageKind::StoragePlanRequest;
            } else if constexpr (std::is_same_v<T, StorageWrapClaimMsg>) {
                return SecurityMessageKind::StorageWrapClaim;
            } else if constexpr (std::is_same_v<T, UpgradeMsg>) {
                return SecurityMessageKind::Upgrade;
            } else {
                return SecurityMessageKind::SvsmAkActivationResponse;
            }
        },
        body);
}

std::vector<uint8_t> encode_security_message(const SecurityMessage& message) {
    const auto kind = kind_of(message.body);
    if (!kind.has_value() || *kind != message.kind) {
        return {};
    }

    Writer body;
    const bool ok = std::visit(
        [&body](const auto& value) -> bool {
            using T = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<T, AttestationChallenge>) {
                return encode_challenge(body, value);
            } else if constexpr (std::is_same_v<T, AttestationEvidence>) {
                return encode_evidence(body, value);
            } else if constexpr (std::is_same_v<T, ProposalMessage>) {
                return encode_proposal_message(body, value);
            } else if constexpr (std::is_same_v<T, TreeOpSubmitMsg>) {
                return encode_tree_op_submit(body, value);
            } else if constexpr (std::is_same_v<T, StoragePlanProofMsg>) {
                return encode_storage_plan_proof(body, value);
            } else if constexpr (std::is_same_v<T, StorageKeyPackageMsg>) {
                return encode_storage_key_package(body, value);
            } else if constexpr (std::is_same_v<T, StorageUnlockRequestMsg>) {
                return encode_storage_unlock_request(body, value);
            } else if constexpr (std::is_same_v<T, StorageUnlockPartialMsg>) {
                return encode_storage_unlock_partial(body, value);
            } else if constexpr (std::is_same_v<T, StoragePlanRequestMsg>) {
                return encode_storage_plan_request(body, value);
            } else if constexpr (std::is_same_v<T, StorageWrapClaimMsg>) {
                return encode_storage_wrap_claim(body, value);
            } else if constexpr (std::is_same_v<T, UpgradeMsg>) {
                return encode_upgrade(body, value);
            } else if constexpr (std::is_same_v<T, Vote>) {
                return encode_vote(body, value);
            } else if constexpr (std::is_same_v<T, TimeoutVote>) {
                return encode_timeout(body, value);
            } else if constexpr (std::is_same_v<T, DkgMessage>) {
                return encode_dkg(body, value);
            } else if constexpr (std::is_same_v<T, FrostCommitmentMessage>) {
                return encode_commitment(body, value);
            } else if constexpr (std::is_same_v<T, FrostShareMessage>) {
                return encode_share(body, value);
            } else if constexpr (std::is_same_v<T, EpochAnnouncement>) {
                return encode_announcement(body, value);
            } else if constexpr (std::is_same_v<T, GenesisFounding>) {
                return encode_founding(body, value);
            } else if constexpr (std::is_same_v<T, DkgTranscriptAttest>) {
                return encode_transcript_attest(body, value);
            } else if constexpr (std::is_same_v<T, BootstrapCertificate>) {
                return encode_bootstrap(body, value);
            } else if constexpr (std::is_same_v<T, SyncRequest>) {
                return encode_sync_request(body, value);
            } else if constexpr (std::is_same_v<T, SyncResponse>) {
                return encode_sync_response(body, value);
            } else if constexpr (std::is_same_v<T, EligibilityObservation>) {
                return encode_observation(body, value);
            } else if constexpr (std::is_same_v<T, GenesisEligibilityAttest>) {
                return encode_genesis_eligibility_attest(body, value);
            } else if constexpr (std::is_same_v<T, ParticipationChallenge>) {
                return encode_participation_challenge(body, value);
            } else if constexpr (std::is_same_v<T, ParticipationResponse>) {
                return encode_participation_response(body, value);
            } else if constexpr (std::is_same_v<T, NextEpochPlanProof>) {
                return encode_plan_proof(body, value);
            } else if constexpr (std::is_same_v<T, CandidateStateReadyMsg>) {
                return encode_state_ready(body, value);
            } else if constexpr (std::is_same_v<T, ReadinessProofMsg>) {
                return encode_readiness_proof(body, value);
            } else if constexpr (std::is_same_v<T, EpochHandoffProofMsg>) {
                return encode_handoff_proof(body, value);
            } else if constexpr (std::is_same_v<T, AuthorityChainRequest>) {
                return encode_chain_request(body, value);
            } else if constexpr (std::is_same_v<T, AuthorityChainPage>) {
                return encode_chain_page(body, value);
            } else if constexpr (std::is_same_v<T, AttestationEvidenceStart>) {
                return encode_transfer_start(body, value);
            } else if constexpr (std::is_same_v<T, AttestationEvidenceChunk>) {
                return encode_transfer_chunk(body, value);
            } else if constexpr (std::is_same_v<T, AttestationEvidenceEnd>) {
                return encode_transfer_end(body, value);
            } else if constexpr (std::is_same_v<T, SvsmAkActivationOfferMessage>) {
                return encode_activation_offer(body, value);
            } else {
                return encode_activation_response(body, value);
            }
        },
        message.body);
    if (!ok) {
        return {};
    }
    const std::vector<uint8_t> body_bytes = body.take();

    Writer envelope;
    envelope.u8(constants::kSecurityWireVersion);
    envelope.u16(static_cast<uint16_t>(message.kind));
    envelope.u16(message.security_ruleset);
    envelope.u16(message.consensus_ruleset);
    envelope.fixed(message.network_id);
    envelope.u64(message.epoch);
    put_node(envelope, message.sender);
    if (!envelope.bytes(body_bytes, constants::kMaxSecurityMessageBytes)) {
        return {};
    }
    std::vector<uint8_t> out = envelope.take();
    if (out.size() > constants::kMaxSecurityMessageBytes) {
        return {};
    }
    return out;
}

std::variant<SecurityMessage, CodecError> decode_security_message(std::span<const uint8_t> bytes) {
    if (bytes.size() > constants::kMaxSecurityMessageBytes) {
        return CodecError::Oversized;
    }

    Reader r(bytes);
    SecurityMessage message;
    uint8_t version = 0;
    uint16_t raw_kind = 0;
    if (!r.u8(version)) {
        return *r.error();
    }
    if (version != constants::kSecurityWireVersion) {
        return CodecError::BadVersion;
    }
    if (!r.u16(raw_kind)) {
        return *r.error();
    }
    if (!known_kind(raw_kind)) {
        return CodecError::UnknownKind;
    }
    message.kind = static_cast<SecurityMessageKind>(raw_kind);

    std::vector<uint8_t> body_bytes;
    if (!(r.u16(message.security_ruleset) && r.u16(message.consensus_ruleset) &&
          r.fixed(message.network_id) && r.u64(message.epoch) && get_node(r, message.sender) &&
          r.bytes(body_bytes, constants::kMaxSecurityMessageBytes))) {
        return *r.error();
    }
    if (!r.done()) {
        return CodecError::TrailingBytes;
    }

    Reader body(body_bytes);
    if (!decode_body(body, message.kind, message.body)) {
        return body.error().value_or(CodecError::BadValue);
    }
    if (!body.done()) {
        return CodecError::TrailingBytes;
    }
    return message;
}

}  // namespace nexus::security
