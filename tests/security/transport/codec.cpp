#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Transport/SecurityCodec.hpp>

#include <gtest/gtest.h>

#include <cstring>
#include <vector>

using namespace nexus::security;
namespace constants = nexus::security::constants;

namespace {

NodeId node(uint8_t byte) {
    NodeId id;
    id.bytes.fill(byte);
    return id;
}

Digest digest(uint8_t byte) {
    Digest d;
    d.fill(byte);
    return d;
}

nexus::crypto::Ed25519Signature signature(uint8_t byte) {
    nexus::crypto::Ed25519Signature s;
    s.fill(byte);
    return s;
}

SecurityMessage envelope(SecurityMessageKind kind, SecurityBody body) {
    SecurityMessage m;
    m.kind = kind;
    m.security_ruleset = constants::kSecurityRulesetVersion;
    m.consensus_ruleset = constants::kConsensusRulesetVersion;
    m.network_id = digest(0xAA);
    m.epoch = 7;
    m.sender = node(0x01);
    m.body = std::move(body);
    return m;
}

QuorumCertificate certificate(std::size_t signers) {
    QuorumCertificate qc;
    qc.qc_format_version = constants::kQcFormatVersion;
    qc.consensus_ruleset = constants::kConsensusRulesetVersion;
    qc.network_id = digest(0xAA);
    qc.epoch = 7;
    qc.height = 3;
    qc.view = 4;
    qc.proposal_digest = digest(0x31);
    for (std::size_t i = 0; i < signers; ++i) {
        qc.signers.push_back({node(static_cast<uint8_t>(0x10 + i)),
                              signature(static_cast<uint8_t>(0x50 + i))});
    }
    return qc;
}

ProposalMessage proposal_message() {
    ProposalMessage m;
    m.proposal.security_ruleset = constants::kSecurityRulesetVersion;
    m.proposal.consensus_ruleset = constants::kConsensusRulesetVersion;
    m.proposal.network_id = digest(0xAA);
    m.proposal.epoch = 7;
    m.proposal.height = 4;
    m.proposal.view = 5;
    m.proposal.leader = node(0x02);
    m.proposal.parent_digest = digest(0x31);
    m.proposal.justify_qc_digest = digest(0x32);
    m.proposal.previous_state_root = digest(0x33);
    m.proposal.proposed_state_root = digest(0x34);
    m.proposal.transitions_digest = digest(0x35);
    m.proposal.timestamp_hint = 123456;
    m.justify = certificate(4);
    return m;
}

DkgMessage dkg_message(DkgRound round) {
    DkgMessage d;
    d.network_id = digest(0xAA);
    d.target_epoch = 8;
    d.participant_set_digest = digest(0x41);
    d.sender = node(0x01);
    d.sender_incarnation = 9;
    d.round = round;
    d.recipient = round == DkgRound::Round2Pairwise ? node(0x03) : NodeId{};
    d.payload = std::vector<uint8_t>(231, 0x5A);
    return d;
}

SigningMessageHeader signing_header() {
    SigningMessageHeader h;
    h.network_id = digest(0xAA);
    h.epoch = 7;
    h.key_generation = 7;
    h.session_id = 0x1122334455667788ULL;
    h.object_digest = digest(0x61);
    h.sender = node(0x01);
    return h;
}

std::vector<SecurityMessage> all_kinds() {
    std::vector<SecurityMessage> messages;

    AttestationChallenge c;
    c.nonce.fill(0x11);
    c.node_id = node(0x03);
    c.node_key.fill(0x12);
    c.incarnation = 2;
    c.epoch = 7;
    c.security_ruleset = constants::kSecurityRulesetVersion;
    c.policy_digest = digest(0x13);
    messages.push_back(envelope(SecurityMessageKind::AttestationChallenge, c));

    AttestationEvidence e;
    e.challenge_digest = digest(0x21);
    e.node_id = node(0x03);
    e.incarnation = 2;
    e.security_ruleset = constants::kSecurityRulesetVersion;
    e.consensus_ruleset = constants::kConsensusRulesetVersion;
    e.epoch_vote_key.fill(0x22);
    e.platform.binary_sha256 = "abcd";
    e.platform.ima_log = "10 aaaa ima-ng sha256:bbbb /usr/local/bin/nexus\n";
    e.identity_signature = signature(0x23);
    messages.push_back(envelope(SecurityMessageKind::AttestationEvidence, e));

    messages.push_back(envelope(SecurityMessageKind::HotStuffProposal, proposal_message()));

    Vote v;
    v.consensus_ruleset = constants::kConsensusRulesetVersion;
    v.network_id = digest(0xAA);
    v.epoch = 7;
    v.height = 4;
    v.view = 5;
    v.proposal_digest = digest(0x36);
    v.voter = node(0x01);
    v.signature = signature(0x37);
    messages.push_back(envelope(SecurityMessageKind::HotStuffVote, v));

    TimeoutVote t;
    t.consensus_ruleset = constants::kConsensusRulesetVersion;
    t.network_id = digest(0xAA);
    t.epoch = 7;
    t.view = 6;
    t.high_qc_digest = digest(0x38);
    t.voter = node(0x01);
    t.signature = signature(0x39);
    messages.push_back(envelope(SecurityMessageKind::HotStuffTimeout, t));

    messages.push_back(
        envelope(SecurityMessageKind::DkgBroadcast, dkg_message(DkgRound::Round1Broadcast)));
    messages.push_back(
        envelope(SecurityMessageKind::DkgPairwise, dkg_message(DkgRound::Round2Pairwise)));

    FrostCommitmentMessage fc;
    fc.header = signing_header();
    fc.commitment = std::vector<uint8_t>(69, 0x6A);
    messages.push_back(envelope(SecurityMessageKind::FrostCommitment, fc));

    FrostShareMessage fs;
    fs.header = signing_header();
    fs.share = std::vector<uint8_t>(32, 0x6B);
    messages.push_back(envelope(SecurityMessageKind::FrostSignatureShare, fs));

    EpochAnnouncement a;
    a.authority.network_id = digest(0xAA);
    a.authority.epoch = 8;
    a.authority.key_generation = 8;
    a.authority.security_ruleset = constants::kSecurityRulesetVersion;
    a.authority.consensus_ruleset = constants::kConsensusRulesetVersion;
    a.authority.tier1_set_digest = digest(0x71);
    a.authority.consensus_quorum = 4;
    a.authority.authority_threshold = 5;
    a.authority.frost_ciphersuite = std::string(constants::kFrostCiphersuite);
    a.authority.group_public_key.fill(0x72);
    a.authority.dkg_transcript_digest = digest(0x73);
    a.authority.attestation_root = digest(0x74);
    a.authority.previous_checkpoint = digest(0x75);
    a.handoff_certificate_digest = digest(0x76);
    messages.push_back(envelope(SecurityMessageKind::EpochAnnouncement, a));

    GenesisFounding founding;
    founding.epoch = 1;
    for (uint8_t i = 1; i <= 5; ++i) {
        nexus::crypto::Ed25519PublicKey vote_key{};
        vote_key.fill(static_cast<uint8_t>(0x80 + i));
        founding.members.emplace_back(node(i), vote_key);
    }
    founding.attestation_root = digest(0x91);
    messages.push_back(envelope(SecurityMessageKind::GenesisFounding, founding));

    DkgTranscriptAttest attest;
    attest.epoch = 1;
    attest.participant_set_digest = digest(0x92);
    attest.transcript_digest = digest(0x93);
    attest.group_public_key.fill(0x94);
    attest.node = node(0x01);
    attest.identity_signature = signature(0x95);
    messages.push_back(envelope(SecurityMessageKind::DkgTranscriptAttest, attest));

    BootstrapCertificate bootstrap;
    bootstrap.network_id = digest(0xAA);
    bootstrap.epoch = 1;
    bootstrap.tier1_set_digest = digest(0x92);
    bootstrap.authority_threshold = 5;
    bootstrap.authority_public_key.fill(0x94);
    bootstrap.dkg_transcript_digest = digest(0x93);
    bootstrap.attestation_root = digest(0x91);
    bootstrap.security_ruleset = constants::kSecurityRulesetVersion;
    bootstrap.consensus_ruleset = constants::kConsensusRulesetVersion;
    bootstrap.genesis_signature = signature(0x96);
    messages.push_back(envelope(SecurityMessageKind::BootstrapCertificate, bootstrap));

    messages.push_back(envelope(SecurityMessageKind::SyncRequest, SyncRequest{7}));
    messages.push_back(envelope(SecurityMessageKind::SyncResponse, SyncResponse{certificate(4)}));

    return messages;
}

bool same_wire(const SecurityMessage& a, const SecurityMessage& b) {
    return encode_security_message(a) == encode_security_message(b);
}

TEST(SecurityCodec, EveryKindRoundTrips) {
    for (const auto& message : all_kinds()) {
        const auto bytes = encode_security_message(message);
        ASSERT_FALSE(bytes.empty()) << static_cast<int>(message.kind);
        const auto decoded = decode_security_message(bytes);
        ASSERT_TRUE(std::holds_alternative<SecurityMessage>(decoded))
            << "kind " << static_cast<int>(message.kind) << " error "
            << static_cast<int>(std::get<CodecError>(decoded));
        const auto& back = std::get<SecurityMessage>(decoded);
        EXPECT_EQ(back.kind, message.kind);
        EXPECT_EQ(back.epoch, message.epoch);
        EXPECT_EQ(back.sender, message.sender);
        EXPECT_EQ(back.body.index(), message.body.index());
        EXPECT_TRUE(same_wire(back, message));
    }
}

TEST(SecurityCodec, EveryPrefixIsRejected) {
    for (const auto& message : all_kinds()) {
        const auto bytes = encode_security_message(message);
        for (std::size_t n = 0; n < bytes.size(); ++n) {
            const auto decoded =
                decode_security_message(std::span<const uint8_t>(bytes.data(), n));
            EXPECT_TRUE(std::holds_alternative<CodecError>(decoded))
                << "kind " << static_cast<int>(message.kind) << " prefix " << n;
        }
    }
}

TEST(SecurityCodec, TrailingBytesAreRejected) {
    auto bytes = encode_security_message(all_kinds()[3]);
    bytes.push_back(0x00);
    const auto decoded = decode_security_message(bytes);
    ASSERT_TRUE(std::holds_alternative<CodecError>(decoded));
    EXPECT_EQ(std::get<CodecError>(decoded), CodecError::TrailingBytes);
}

TEST(SecurityCodec, OversizedBufferRejectedBeforeParsing) {
    const std::vector<uint8_t> huge(constants::kMaxSecurityMessageBytes + 1, 0x01);
    const auto decoded = decode_security_message(huge);
    ASSERT_TRUE(std::holds_alternative<CodecError>(decoded));
    EXPECT_EQ(std::get<CodecError>(decoded), CodecError::Oversized);
}

TEST(SecurityCodec, VersionAndKindAreChecked) {
    auto bytes = encode_security_message(all_kinds()[3]);
    auto bad_version = bytes;
    bad_version[0] = 2;
    EXPECT_EQ(std::get<CodecError>(decode_security_message(bad_version)), CodecError::BadVersion);

    auto bad_kind = bytes;
    bad_kind[1] = 99;
    bad_kind[2] = 0;
    EXPECT_EQ(std::get<CodecError>(decode_security_message(bad_kind)), CodecError::UnknownKind);

    auto zero_kind = bytes;
    zero_kind[1] = 0;
    zero_kind[2] = 0;
    EXPECT_EQ(std::get<CodecError>(decode_security_message(zero_kind)), CodecError::UnknownKind);
}

TEST(SecurityCodec, CertificateCountIsBoundedBeforeSignerWork) {
    // Encoding refuses a certificate above the compiled maximum.
    auto message = envelope(SecurityMessageKind::HotStuffProposal, proposal_message());
    std::get<ProposalMessage>(message.body).justify =
        certificate(constants::kMaxQcSignatures + 1);
    EXPECT_TRUE(encode_security_message(message).empty());

    // Decoding rejects a claimed count above the maximum without reading a
    // single signer, even when the bytes for them are absent.
    std::get<ProposalMessage>(message.body).justify = certificate(constants::kMaxQcSignatures);
    auto bytes = encode_security_message(message);
    ASSERT_FALSE(bytes.empty());
    constexpr std::size_t kEnvelopeHeader = 1 + 2 + 2 + 2 + 32 + 8 + 32 + 4;
    constexpr std::size_t kProposalFixed = 2 + 2 + 32 + 8 + 8 + 8 + 32 + 32 + 32 + 32 + 32 + 32 + 8;
    constexpr std::size_t kCertificateHeader = 2 + 2 + 32 + 8 + 8 + 8 + 32;
    const std::size_t count_offset = kEnvelopeHeader + kProposalFixed + kCertificateHeader;
    bytes[count_offset] = static_cast<uint8_t>(constants::kMaxQcSignatures + 1);
    bytes[count_offset + 1] = 0;
    EXPECT_EQ(std::get<CodecError>(decode_security_message(bytes)), CodecError::CountTooLarge);

    bytes[count_offset] = 0xFF;
    bytes[count_offset + 1] = 0xFF;
    EXPECT_EQ(std::get<CodecError>(decode_security_message(bytes)), CodecError::CountTooLarge);
}

TEST(SecurityCodec, LengthFieldsAreBoundedBeforeAllocation) {
    auto message = all_kinds()[1];
    auto bytes = encode_security_message(message);
    ASSERT_FALSE(bytes.empty());
    constexpr std::size_t kEnvelopeHeader = 1 + 2 + 2 + 2 + 32 + 8 + 32 + 4;
    constexpr std::size_t kEvidenceFixed = 32 + 32 + 8 + 2 + 2 + 32;
    const std::size_t length_offset = kEnvelopeHeader + kEvidenceFixed;
    for (int i = 0; i < 4; ++i) bytes[length_offset + static_cast<std::size_t>(i)] = 0xFF;
    EXPECT_EQ(std::get<CodecError>(decode_security_message(bytes)), CodecError::LengthTooLarge);

    // Encoding refuses a platform bundle above the wire bound.
    std::get<AttestationEvidence>(message.body).platform.ima_log =
        std::string(constants::kMaxPlatformEvidenceWireBytes + 1, 'x');
    EXPECT_TRUE(encode_security_message(message).empty());

    auto dkg = envelope(SecurityMessageKind::DkgBroadcast, dkg_message(DkgRound::Round1Broadcast));
    std::get<DkgMessage>(dkg.body).payload.assign(constants::kMaxDkgPayloadBytes + 1, 0x00);
    EXPECT_TRUE(encode_security_message(dkg).empty());
}

TEST(SecurityCodec, DkgRoundAndKindMustAgree) {
    auto pairwise_kind_broadcast_body =
        envelope(SecurityMessageKind::DkgPairwise, dkg_message(DkgRound::Round1Broadcast));
    EXPECT_TRUE(encode_security_message(pairwise_kind_broadcast_body).empty());

    auto bytes = encode_security_message(
        envelope(SecurityMessageKind::DkgBroadcast, dkg_message(DkgRound::Round1Broadcast)));
    ASSERT_FALSE(bytes.empty());
    // Patch the envelope kind to pairwise; the body still says round 1.
    bytes[1] = static_cast<uint8_t>(SecurityMessageKind::DkgPairwise);
    EXPECT_EQ(std::get<CodecError>(decode_security_message(bytes)), CodecError::KindMismatch);

    // An invalid round value is a bad value, not a broadcast.
    auto invalid = dkg_message(DkgRound::Round1Broadcast);
    invalid.round = static_cast<DkgRound>(3);
    EXPECT_FALSE(kind_of(SecurityBody{invalid}).has_value());
}

TEST(SecurityCodec, FoundingMemberCountIsBounded) {
    GenesisFounding founding;
    for (std::size_t i = 0; i <= constants::kMaxActiveTier1; ++i) {
        founding.members.emplace_back(node(static_cast<uint8_t>(i)), nexus::crypto::Ed25519PublicKey{});
    }
    EXPECT_TRUE(encode_security_message(envelope(SecurityMessageKind::GenesisFounding, founding)).empty());
}

TEST(SecurityCodec, KindMustMatchBody) {
    auto mismatched = envelope(SecurityMessageKind::HotStuffVote, proposal_message());
    EXPECT_TRUE(encode_security_message(mismatched).empty());
}

TEST(SecurityCodec, EmptyPlatformBundleDecodesToEmptyEvidence) {
    AttestationEvidence e;
    e.node_id = node(0x03);
    auto message = envelope(SecurityMessageKind::AttestationEvidence, e);
    const auto bytes = encode_security_message(message);
    ASSERT_FALSE(bytes.empty());
    const auto decoded = decode_security_message(bytes);
    ASSERT_TRUE(std::holds_alternative<SecurityMessage>(decoded));
    EXPECT_TRUE(std::get<AttestationEvidence>(std::get<SecurityMessage>(decoded).body)
                    .platform.hcl_blob.empty());
}

TEST(SecurityCodec, SingleByteCorruptionNeverCrashesAndNeverSilentlyReinterprets) {
    for (const auto& message : all_kinds()) {
        const auto bytes = encode_security_message(message);
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            auto flipped = bytes;
            flipped[i] ^= 0x01;
            const auto decoded = decode_security_message(flipped);
            if (!std::holds_alternative<SecurityMessage>(decoded)) {
                continue;
            }
            const auto re_encoded = encode_security_message(std::get<SecurityMessage>(decoded));
            if (message.kind == SecurityMessageKind::AttestationEvidence) {
                // The platform bundle is JSON and not byte-canonical. The
                // property that matters is idempotence: the verifier's digest
                // over the re-encoded bundle is stable, so a signature either
                // still covers the same content or fails.
                const auto again = decode_security_message(re_encoded);
                ASSERT_TRUE(std::holds_alternative<SecurityMessage>(again));
                EXPECT_EQ(encode_security_message(std::get<SecurityMessage>(again)), re_encoded)
                    << "byte " << i;
                continue;
            }
            // Every other kind re-encodes to exactly the bytes it came from:
            // no field is silently normalized.
            EXPECT_EQ(re_encoded, flipped)
                << "kind " << static_cast<int>(message.kind) << " byte " << i;
        }
    }
}

}  // namespace
