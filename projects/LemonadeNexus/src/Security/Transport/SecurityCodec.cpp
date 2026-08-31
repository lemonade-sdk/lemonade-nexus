#include <LemonadeNexus/Security/Transport/SecurityCodec.hpp>

#include <LemonadeNexus/Security/EvidenceSnpVtpm.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <cstring>
#include <optional>
#include <string>

namespace nexus::security {

namespace {

class Writer {
public:
    void u8(uint8_t value) { out_.push_back(value); }
    void u16(uint16_t value) { put_le(value, 2); }
    void u32(uint32_t value) { put_le(value, 4); }
    void u64(uint64_t value) { put_le(value, 8); }
    void fixed(std::span<const uint8_t> bytes) { out_.insert(out_.end(), bytes.begin(), bytes.end()); }

    /// Length-prefixed field. Returns false when the field exceeds its bound,
    /// so a caller can never emit a message the decoder would reject.
    [[nodiscard]] bool bytes(std::span<const uint8_t> field, std::size_t max) {
        if (field.size() > max) {
            return false;
        }
        u32(static_cast<uint32_t>(field.size()));
        fixed(field);
        return true;
    }

    [[nodiscard]] std::vector<uint8_t> take() { return std::move(out_); }

private:
    void put_le(uint64_t value, int width) {
        for (int i = 0; i < width; ++i) {
            out_.push_back(static_cast<uint8_t>((value >> (i * 8)) & 0xFF));
        }
    }

    std::vector<uint8_t> out_;
};

class Reader {
public:
    explicit Reader(std::span<const uint8_t> bytes) : bytes_(bytes) {}

    [[nodiscard]] bool u8(uint8_t& value) { return read_le(value, 1); }
    [[nodiscard]] bool u16(uint16_t& value) { return read_le(value, 2); }
    [[nodiscard]] bool u32(uint32_t& value) { return read_le(value, 4); }
    [[nodiscard]] bool u64(uint64_t& value) { return read_le(value, 8); }

    template <std::size_t N>
    [[nodiscard]] bool fixed(std::array<uint8_t, N>& value) {
        if (remaining() < N) {
            return fail(CodecError::Truncated);
        }
        std::memcpy(value.data(), bytes_.data() + offset_, N);
        offset_ += N;
        return true;
    }

    /// The length is bounded before any allocation: an attacker-chosen
    /// length never reserves memory.
    [[nodiscard]] bool bytes(std::vector<uint8_t>& value, std::size_t max) {
        uint32_t length = 0;
        if (!u32(length)) {
            return false;
        }
        if (length > max) {
            return fail(CodecError::LengthTooLarge);
        }
        if (remaining() < length) {
            return fail(CodecError::Truncated);
        }
        value.assign(bytes_.begin() + static_cast<std::ptrdiff_t>(offset_),
                     bytes_.begin() + static_cast<std::ptrdiff_t>(offset_ + length));
        offset_ += length;
        return true;
    }

    [[nodiscard]] std::size_t remaining() const { return bytes_.size() - offset_; }
    [[nodiscard]] bool done() const { return offset_ == bytes_.size(); }
    [[nodiscard]] std::optional<CodecError> error() const { return error_; }
    [[nodiscard]] bool fail(CodecError error) {
        if (!error_.has_value()) {
            error_ = error;
        }
        return false;
    }

private:
    template <typename T>
    bool read_le(T& value, std::size_t width) {
        if (remaining() < width) {
            return fail(CodecError::Truncated);
        }
        uint64_t raw = 0;
        for (std::size_t i = 0; i < width; ++i) {
            raw |= static_cast<uint64_t>(bytes_[offset_ + i]) << (i * 8);
        }
        value = static_cast<T>(raw);
        offset_ += width;
        return true;
    }

    std::span<const uint8_t> bytes_;
    std::size_t offset_ = 0;
    std::optional<CodecError> error_;
};

// --- Encoders ---------------------------------------------------------------

void put_node(Writer& w, const NodeId& node) { w.fixed(node.bytes); }

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
    w.fixed(e.epoch_vote_key);
    const std::string platform = encode_snp_vtpm_evidence(e.platform);
    if (!w.bytes({reinterpret_cast<const uint8_t*>(platform.data()), platform.size()},
                 constants::kMaxPlatformEvidenceWireBytes)) {
        return false;
    }
    w.fixed(e.identity_signature);
    return true;
}

bool encode_certificate(Writer& w, const QuorumCertificate& qc) {
    if (qc.signers.size() > constants::kMaxQcSignatures) {
        return false;
    }
    w.u16(qc.qc_format_version);
    w.u16(qc.consensus_ruleset);
    w.fixed(qc.network_id);
    w.u64(qc.epoch);
    w.u64(qc.height);
    w.u64(qc.view);
    w.fixed(qc.proposal_digest);
    w.u16(static_cast<uint16_t>(qc.signers.size()));
    for (const auto& signer : qc.signers) {
        put_node(w, signer.node_id);
        w.fixed(signer.signature);
    }
    return true;
}

bool encode_proposal(Writer& w, const ProposalMessage& m) {
    const Proposal& p = m.proposal;
    w.u16(p.security_ruleset);
    w.u16(p.consensus_ruleset);
    w.fixed(p.network_id);
    w.u64(p.epoch);
    w.u64(p.height);
    w.u64(p.view);
    put_node(w, p.leader);
    w.fixed(p.parent_digest);
    w.fixed(p.justify_qc_digest);
    w.fixed(p.previous_state_root);
    w.fixed(p.proposed_state_root);
    w.fixed(p.transitions_digest);
    w.u64(p.timestamp_hint);
    return encode_certificate(w, m.justify);
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
    w.fixed(d.participant_set_digest);
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

bool encode_bootstrap(Writer& w, const BootstrapCertificate& c) {
    w.fixed(c.network_id);
    w.u64(c.epoch);
    w.fixed(c.tier1_set_digest);
    w.u64(c.authority_threshold);
    w.fixed(c.authority_public_key);
    w.fixed(c.dkg_transcript_digest);
    w.fixed(c.attestation_root);
    w.fixed(c.founding_eligibility_digest);
    w.u16(c.security_ruleset);
    w.u16(c.consensus_ruleset);
    w.fixed(c.genesis_signature);
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
    w.u64(c.finalized_height);
    w.fixed(c.finalized_state);
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
    w.u64(r.finalized_height);
    w.fixed(r.finalized_state);
    w.fixed(r.identity_signature);
    return true;
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

bool get_node(Reader& r, NodeId& node) { return r.fixed(node.bytes); }

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

bool decode_challenge(Reader& r, AttestationChallenge& c) {
    return r.fixed(c.network_id) && r.fixed(c.nonce) && get_node(r, c.node_id) &&
           r.fixed(c.node_key) &&
           r.u64(c.incarnation) && r.u64(c.epoch) && r.u16(c.security_ruleset) &&
           r.u16(c.consensus_ruleset) && get_profile_id(r, c.profile_id) &&
           r.u16(c.profile_ruleset) && r.fixed(c.policy_digest);
}

bool decode_evidence(Reader& r, AttestationEvidence& e) {
    std::vector<uint8_t> platform;
    if (!(r.fixed(e.network_id) && r.fixed(e.challenge_digest) &&
          get_node(r, e.node_id) && r.u64(e.incarnation) &&
          r.u64(e.epoch) && r.u16(e.security_ruleset) && r.u16(e.consensus_ruleset) &&
          get_profile_id(r, e.profile_id) && r.u16(e.profile_ruleset) &&
          r.fixed(e.epoch_vote_key) &&
          r.bytes(platform, constants::kMaxPlatformEvidenceWireBytes))) {
        return false;
    }
    // An empty bundle is a prover with nothing to show; it decodes to empty
    // evidence and fails verification later, never here.
    if (!platform.empty()) {
        auto decoded = decode_snp_vtpm_evidence(
            std::string_view(reinterpret_cast<const char*>(platform.data()), platform.size()));
        if (!decoded.has_value()) {
            return r.fail(CodecError::BadValue);
        }
        e.platform = std::move(*decoded);
    }
    return r.fixed(e.identity_signature);
}

bool decode_certificate(Reader& r, QuorumCertificate& qc) {
    uint16_t count = 0;
    if (!(r.u16(qc.qc_format_version) && r.u16(qc.consensus_ruleset) && r.fixed(qc.network_id) &&
          r.u64(qc.epoch) && r.u64(qc.height) && r.u64(qc.view) && r.fixed(qc.proposal_digest) &&
          r.u16(count))) {
        return false;
    }
    // Bound before the signer loop: a claimed count never drives allocation
    // or signature work past the compiled maximum.
    if (count > constants::kMaxQcSignatures) {
        return r.fail(CodecError::CountTooLarge);
    }
    qc.signers.resize(count);
    for (auto& signer : qc.signers) {
        if (!(get_node(r, signer.node_id) && r.fixed(signer.signature))) {
            return false;
        }
    }
    return true;
}

bool decode_proposal(Reader& r, ProposalMessage& m) {
    Proposal& p = m.proposal;
    return r.u16(p.security_ruleset) && r.u16(p.consensus_ruleset) && r.fixed(p.network_id) &&
           r.u64(p.epoch) && r.u64(p.height) && r.u64(p.view) && get_node(r, p.leader) &&
           r.fixed(p.parent_digest) && r.fixed(p.justify_qc_digest) &&
           r.fixed(p.previous_state_root) && r.fixed(p.proposed_state_root) &&
           r.fixed(p.transitions_digest) && r.u64(p.timestamp_hint) &&
           decode_certificate(r, m.justify);
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
    if (!(r.fixed(d.network_id) && r.u64(d.target_epoch) && r.fixed(d.participant_set_digest) &&
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
    return r.fixed(f.attestation_root);
}

bool decode_transcript_attest(Reader& r, DkgTranscriptAttest& a) {
    return r.u64(a.epoch) && r.fixed(a.participant_set_digest) && r.fixed(a.transcript_digest) &&
           r.fixed(a.group_public_key) && get_node(r, a.node) && r.fixed(a.identity_signature);
}

bool decode_bootstrap(Reader& r, BootstrapCertificate& c) {
    uint64_t threshold = 0;
    if (!(r.fixed(c.network_id) && r.u64(c.epoch) && r.fixed(c.tier1_set_digest) &&
          r.u64(threshold) && r.fixed(c.authority_public_key) && r.fixed(c.dkg_transcript_digest) &&
          r.fixed(c.attestation_root) && r.fixed(c.founding_eligibility_digest) &&
          r.u16(c.security_ruleset) && r.u16(c.consensus_ruleset) &&
          r.fixed(c.genesis_signature))) {
        return false;
    }
    c.authority_threshold = static_cast<std::size_t>(threshold);
    return true;
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
           r.fixed(c.nonce) && r.u64(c.finalized_height) && r.fixed(c.finalized_state) &&
           get_node(r, c.observer);
}

bool decode_participation_response(Reader& r, ParticipationResponse& p) {
    return r.fixed(p.challenge_digest) && r.fixed(p.network_id) && r.u64(p.epoch) &&
           r.u16(p.security_ruleset) && r.u16(p.consensus_ruleset) && get_node(r, p.node_id) &&
           r.u64(p.incarnation) && r.u64(p.finalized_height) && r.fixed(p.finalized_state) &&
           r.fixed(p.identity_signature);
}

bool decode_genesis_eligibility_attest(Reader& r, GenesisEligibilityAttest& a) {
    return r.u64(a.epoch) && r.fixed(a.founding_state_digest) && get_node(r, a.node) &&
           r.fixed(a.identity_signature);
}

bool decode_sync_request(Reader& r, SyncRequest& s) { return r.u64(s.epoch); }

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
            if (!decode_proposal(r, m)) return false;
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
    }
    return r.fail(CodecError::UnknownKind);
}

bool known_kind(uint16_t raw) {
    return raw >= static_cast<uint16_t>(SecurityMessageKind::AttestationChallenge) &&
           raw <= static_cast<uint16_t>(SecurityMessageKind::ParticipationResponse);
}

}  // namespace

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
            } else {
                return SecurityMessageKind::ParticipationResponse;
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
                return encode_proposal(body, value);
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
            } else {
                return encode_participation_response(body, value);
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
