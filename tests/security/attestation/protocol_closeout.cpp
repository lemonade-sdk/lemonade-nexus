#include <gtest/gtest.h>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationService.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationState.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationTransfer.hpp>
#include <LemonadeNexus/Security/Attestation/SvsmAkEnrollment.hpp>
#include <LemonadeNexus/Security/MeasurementIma.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Transport/SecurityCodec.hpp>

#include "support/tpm_quote_fixtures.hpp"

#include <openssl/evp.h>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace {

using namespace nexus::security;
namespace crypto = nexus::crypto;

template <typename T>
T filled(uint8_t value) {
    T out{};
    out.fill(value);
    return out;
}

AttestationChallenge challenge_for(const AttestationEvidence& evidence) {
    AttestationChallenge c;
    c.network_id = evidence.network_id;
    c.node_id = evidence.node_id;
    c.node_key = evidence.node_id.bytes;
    c.incarnation = evidence.incarnation;
    c.epoch = evidence.epoch;
    c.security_ruleset = evidence.security_ruleset;
    c.consensus_ruleset = evidence.consensus_ruleset;
    c.profile_id = evidence.profile_id;
    c.profile_ruleset = evidence.profile_ruleset;
    c.purpose = evidence.purpose;
    c.context_digest = evidence.context_digest;
    c.ima_mode = evidence.ima_mode;
    return c;
}

AttestationEvidence evidence_with_log(std::size_t bytes,
                                      ImaEvidenceMode mode = ImaEvidenceMode::Full) {
    AttestationEvidence e;
    e.network_id = filled<NetworkId>(0x11);
    e.node_id.bytes = filled<crypto::Ed25519PublicKey>(0x22);
    e.incarnation = 3;
    e.epoch = 7;
    e.security_ruleset = constants::kSecurityRulesetVersion;
    e.consensus_ruleset = constants::kConsensusRulesetVersion;
    e.profile_id = AttestationProfileId::SnpSvsmVtpm;
    e.profile_ruleset = kAttestationProfileRulesetVersion;
    e.purpose = AttestationPurpose::Eligibility;
    e.context_digest = filled<Digest>(0x33);
    e.ima_mode = mode;
    SnpSvsmVtpmEvidence platform;
    platform.ima_binary_log.assign(bytes, 0x5a);
    e.ima_bytes = bytes;
    e.ima_digest = raw_ima_digest(platform.ima_binary_log);
    e.platform = std::move(platform);
    AttestationChallenge c = challenge_for(e);
    if (mode == ImaEvidenceMode::Resume) {
        c.ima_checkpoint_digest = filled<Digest>(0x44);
        c.ima_prior_event_count = 9;
        c.ima_prior_pcr10 = filled<Digest>(0x55);
        c.ima_checkpoint_paths = {{"/usr/bin/nexus-attestd", std::string(64, 'a')}};
    }
    e.challenge_digest = challenge_digest(c);
    return e;
}

using nexus_test::binary_entry;

TEST(AttestationTransfer, CarriesTheMeasured2323190ByteFullLogInBoundedChunks) {
    auto evidence = evidence_with_log(2'323'190);
    const auto transfer = make_evidence_transfer(evidence);
    ASSERT_TRUE(transfer);
    EXPECT_LE(transfer->start.total_transfer_bytes,
              constants::kMaxFullEvidenceTransferBytes);
    EXPECT_EQ(transfer->chunks.size(), 48u);
    EXPECT_TRUE(std::all_of(transfer->chunks.begin(), transfer->chunks.end(),
        [](const auto& c) { return c.bytes.size() <= constants::kMaxEvidenceChunkBytes; }));

    auto live = challenge_for(evidence);
    evidence.challenge_digest = challenge_digest(live);
    const auto exact = make_evidence_transfer(evidence);
    ASSERT_TRUE(exact);
    AttestationTransferReceiver receiver;
    EXPECT_EQ(receiver.begin(evidence.node_id, exact->start, live, 100).failure,
              EvidenceTransferFailure::None);
    for (const auto& chunk : exact->chunks)
        EXPECT_EQ(receiver.chunk(evidence.node_id, chunk, 101).failure,
                  EvidenceTransferFailure::None);
    const auto complete = receiver.end(evidence.node_id, exact->end, 102);
    ASSERT_TRUE(complete.ok());
    EXPECT_EQ(svsm_evidence(complete.evidence->platform).ima_binary_log,
              svsm_evidence(evidence.platform).ima_binary_log);
}

TEST(AttestationTransfer, RejectsBoundsOrderingIdentityAndCommitmentMutations) {
    auto evidence = evidence_with_log(constants::kMaxEvidenceChunkBytes + 9);
    auto live = challenge_for(evidence);
    evidence.challenge_digest = challenge_digest(live);
    const auto transfer = make_evidence_transfer(evidence);
    ASSERT_TRUE(transfer);

    AttestationTransferReceiver receiver;
    auto oversized = transfer->start;
    oversized.total_transfer_bytes = constants::kMaxFullEvidenceTransferBytes + 1;
    EXPECT_EQ(receiver.begin(evidence.node_id, oversized, live, 0).failure,
              EvidenceTransferFailure::DeclaredTotalTooLarge);
    auto too_many = transfer->start;
    too_many.total_chunks = constants::kMaxEvidenceTransferChunks + 1;
    EXPECT_EQ(receiver.begin(evidence.node_id, too_many, live, 0).failure,
              EvidenceTransferFailure::TooManyChunks);
    auto bad_id = transfer->start;
    bad_id.transfer_id[0] ^= 1;
    EXPECT_EQ(receiver.begin(evidence.node_id, bad_id, live, 0).failure,
              EvidenceTransferFailure::BadTransferId);
    auto wrong_challenge = transfer->start;
    wrong_challenge.challenge_digest[0] ^= 1;
    EXPECT_EQ(receiver.begin(evidence.node_id, wrong_challenge, live, 0).failure,
              EvidenceTransferFailure::WrongChallenge);
    NodeId stranger = evidence.node_id;
    stranger.bytes[0] ^= 1;
    EXPECT_EQ(receiver.begin(stranger, transfer->start, live, 0).failure,
              EvidenceTransferFailure::WrongSender);
    auto wrong_profile = transfer->start;
    wrong_profile.evidence.profile_id = AttestationProfileId::AzureSnpVtpm;
    EXPECT_EQ(receiver.begin(evidence.node_id, wrong_profile, live, 0).failure,
              EvidenceTransferFailure::WrongProfile);
    EXPECT_EQ(receiver.live_transfers(), 0u);

    // Resent pieces are ignored; out-of-order chunks wait for their turn; a
    // Start for a DIFFERENT transfer while one is live is still refused.
    ASSERT_EQ(receiver.begin(evidence.node_id, transfer->start, live, 10).failure,
              EvidenceTransferFailure::None);
    EXPECT_EQ(receiver.begin(evidence.node_id, transfer->start, live, 10).failure,
              EvidenceTransferFailure::None);
    auto renamed = transfer->start;
    renamed.transfer_id[0] ^= 1;
    EXPECT_EQ(receiver.begin(evidence.node_id, renamed, live, 10).failure,
              EvidenceTransferFailure::DuplicateStart);
    EXPECT_EQ(receiver.chunk(evidence.node_id, transfer->chunks[1], 11).failure,
              EvidenceTransferFailure::None);
    EXPECT_EQ(receiver.chunk(evidence.node_id, transfer->chunks[0], 12).failure,
              EvidenceTransferFailure::None);
    EXPECT_EQ(receiver.chunk(evidence.node_id, transfer->chunks[0], 12).failure,
              EvidenceTransferFailure::None);
    ASSERT_TRUE(receiver.end(evidence.node_id, transfer->end, 13).ok());

    // An End ahead of its Start is held and the transfer completes once the
    // missing pieces arrive, in any order.
    EXPECT_EQ(receiver.end(evidence.node_id, transfer->end, 20).failure,
              EvidenceTransferFailure::None);
    EXPECT_EQ(receiver.begin(evidence.node_id, transfer->start, live, 21).failure,
              EvidenceTransferFailure::None);
    EXPECT_EQ(receiver.chunk(evidence.node_id, transfer->chunks[0], 22).failure,
              EvidenceTransferFailure::None);
    ASSERT_TRUE(receiver.chunk(evidence.node_id, transfer->chunks[1], 23).ok());

    // Size violations are refused without killing the transfer.
    ASSERT_EQ(receiver.begin(evidence.node_id, transfer->start, live, 40).failure,
              EvidenceTransferFailure::None);
    auto extra = transfer->chunks.back();
    for (std::size_t i = 0; i + 1 < transfer->chunks.size(); ++i)
        ASSERT_EQ(receiver.chunk(evidence.node_id, transfer->chunks[i], 41).failure,
                  EvidenceTransferFailure::None);
    extra.bytes.push_back(0);
    EXPECT_EQ(receiver.chunk(evidence.node_id, extra, 41).failure,
              EvidenceTransferFailure::ExtraBytes);
    EXPECT_EQ(receiver.chunk(evidence.node_id, transfer->chunks.back(), 42).failure,
              EvidenceTransferFailure::None);
    auto bad_end = transfer->end;
    bad_end.ima_digest[0] ^= 1;
    EXPECT_EQ(receiver.end(evidence.node_id, bad_end, 43).failure,
              EvidenceTransferFailure::Malformed);
    EXPECT_TRUE(receiver.end(evidence.node_id, transfer->end, 44).ok());

    ASSERT_EQ(receiver.begin(evidence.node_id, transfer->start, live, 100).failure,
              EvidenceTransferFailure::None);
    EXPECT_EQ(receiver.expire(100 + constants::kEvidenceTransferDeadlineMs), 1u);
    EXPECT_EQ(receiver.live_transfers(), 0u);
}

TEST(AttestationTransfer, ResumeHasItsOwnSmallerCap) {
    EXPECT_FALSE(make_evidence_transfer(evidence_with_log(
        constants::kMaxResumeImaSuffixBytes + 1, ImaEvidenceMode::Resume)));
    EXPECT_TRUE(make_evidence_transfer(evidence_with_log(
        constants::kMaxResumeImaSuffixBytes, ImaEvidenceMode::Resume)));
}

TEST(AttestationTransfer, GlobalConcurrencyAndLateMessagesStayBounded) {
    AttestationTransferReceiver receiver;
    std::vector<AttestationEvidenceTransfer> transfers;
    transfers.reserve(constants::kMaxConcurrentEvidenceTransfers + 1);
    for (std::size_t i = 0; i <= constants::kMaxConcurrentEvidenceTransfers; ++i) {
        auto evidence = evidence_with_log(32);
        evidence.node_id.bytes.fill(static_cast<uint8_t>(0x20 + i));
        auto live = challenge_for(evidence);
        evidence.challenge_digest = challenge_digest(live);
        auto transfer = make_evidence_transfer(evidence);
        ASSERT_TRUE(transfer);
        transfers.push_back(std::move(*transfer));
        const auto result = receiver.begin(evidence.node_id, transfers.back().start, live, 0);
        EXPECT_EQ(result.failure, i < constants::kMaxConcurrentEvidenceTransfers
                                      ? EvidenceTransferFailure::None
                                      : EvidenceTransferFailure::ConcurrentLimit);
    }
    EXPECT_EQ(receiver.live_transfers(), constants::kMaxConcurrentEvidenceTransfers);

    const auto& first = transfers.front();
    const NodeId sender = first.start.evidence.node_id;
    for (const auto& chunk : first.chunks)
        ASSERT_EQ(receiver.chunk(sender, chunk, 1).failure, EvidenceTransferFailure::None);
    ASSERT_TRUE(receiver.end(sender, first.end, 2).ok());
    // Late copies after completion are held as early pieces, never delivered
    // twice.
    EXPECT_FALSE(receiver.end(sender, first.end, 3).ok());
    EXPECT_FALSE(receiver.chunk(sender, first.chunks.front(), 3).ok());
}

TEST(AttestationTransfer, ExactChunkCommitmentsRejectMutationAndForeignRouting) {
    auto evidence = evidence_with_log(constants::kMaxEvidenceChunkBytes + 17);
    auto live = challenge_for(evidence);
    evidence.challenge_digest = challenge_digest(live);
    const auto transfer = make_evidence_transfer(evidence);
    ASSERT_TRUE(transfer);

    // A tampered chunk passes the size gate but the digest refuses the bundle.
    AttestationTransferReceiver receiver;
    ASSERT_EQ(receiver.begin(evidence.node_id, transfer->start, live, 0).failure,
              EvidenceTransferFailure::None);
    auto mutated = transfer->chunks;
    mutated.front().bytes[0] ^= 1;
    for (const auto& chunk : mutated)
        ASSERT_EQ(receiver.chunk(evidence.node_id, chunk, 2).failure,
                  EvidenceTransferFailure::None);
    EXPECT_EQ(receiver.end(evidence.node_id, transfer->end, 3).failure,
              EvidenceTransferFailure::WrongEvidenceHash);

    // Pieces routed under a stranger or foreign ids never touch the live
    // transfer, and an intact replay still completes it.
    ASSERT_EQ(receiver.begin(evidence.node_id, transfer->start, live, 10).failure,
              EvidenceTransferFailure::None);
    NodeId stranger = evidence.node_id;
    stranger.bytes[0] ^= 1;
    EXPECT_FALSE(receiver.chunk(stranger, transfer->chunks.front(), 11).ok());
    auto foreign_id = transfer->chunks.front();
    foreign_id.transfer_id[0] ^= 1;
    EXPECT_FALSE(receiver.chunk(evidence.node_id, foreign_id, 11).ok());
    auto foreign_challenge = transfer->chunks.front();
    foreign_challenge.challenge_digest[0] ^= 1;
    EXPECT_FALSE(receiver.chunk(evidence.node_id, foreign_challenge, 11).ok());
    EXPECT_EQ(receiver.live_transfers(), 1u);
    for (const auto& chunk : transfer->chunks)
        ASSERT_EQ(receiver.chunk(evidence.node_id, chunk, 12).failure,
                  EvidenceTransferFailure::None);
    EXPECT_TRUE(receiver.end(evidence.node_id, transfer->end, 13).ok());

    ASSERT_EQ(receiver.begin(evidence.node_id, transfer->start, live, 20).failure,
              EvidenceTransferFailure::None);
    EXPECT_EQ(receiver.expire(20 + constants::kEvidenceTransferDeadlineMs), 1u);
    EXPECT_FALSE(receiver.end(evidence.node_id, transfer->end,
                              21 + constants::kEvidenceTransferDeadlineMs).ok());
}

TEST(ImaCheckpoint, FullThenResumePreservesAndUpdatesLastPathState) {
    auto first = binary_entry("/usr/bin/nexus-attestd", 0x11);
    auto second = binary_entry("/usr/bin/lemonade-nexus", 0x22);
    std::vector<uint8_t> full = first;
    full.insert(full.end(), second.begin(), second.end());
    const auto parsed = parse_ima_binary(full);
    ASSERT_TRUE(parsed);
    std::array<uint8_t, 32> zero{};
    const auto checkpoint = replay_ima_binary_from(*parsed, 0, zero);
    ASSERT_TRUE(checkpoint);
    EXPECT_EQ(checkpoint->event_count, 2u);

    auto update = binary_entry("/usr/bin/nexus-attestd", 0x33);
    const auto suffix = parse_ima_binary(update);
    ASSERT_TRUE(suffix);
    const auto resumed = replay_ima_binary_from(*suffix, checkpoint->event_count,
                                                checkpoint->pcr10, checkpoint->paths);
    ASSERT_TRUE(resumed);
    EXPECT_EQ(resumed->event_count, 3u);
    const auto attestd = std::find_if(resumed->paths.begin(), resumed->paths.end(),
        [](const auto& path) { return path.path == "/usr/bin/nexus-attestd"; });
    ASSERT_NE(attestd, resumed->paths.end());
    EXPECT_EQ(attestd->sha256, std::string(64, '3'));
    EXPECT_NE(resumed->pcr10, checkpoint->pcr10);

    auto wrong_pcr = checkpoint->pcr10;
    wrong_pcr[0] ^= 1;
    EXPECT_NE(replay_ima_binary_from(*suffix, checkpoint->event_count, wrong_pcr,
                                    checkpoint->paths)->pcr10,
              resumed->pcr10);
    EXPECT_FALSE(ima_binary_suffix_after_checkpoint(full, 1, checkpoint->pcr10));
    EXPECT_TRUE(ima_binary_suffix_after_checkpoint(full, 2, checkpoint->pcr10));
}

TEST(ImaCheckpoint, ResumeRefusesWrongPositionMutationReorderingAndRebootPrefix) {
    const auto first = binary_entry("/usr/bin/nexus-attestd", 0x11);
    const auto second = binary_entry("/usr/bin/lemonade-nexus", 0x22);
    std::vector<uint8_t> prefix = first;
    prefix.insert(prefix.end(), second.begin(), second.end());
    const auto parsed_prefix = parse_ima_binary(prefix);
    ASSERT_TRUE(parsed_prefix);
    std::array<uint8_t, 32> zero{};
    const auto prior = replay_ima_binary_from(*parsed_prefix, 0, zero);
    ASSERT_TRUE(prior);

    const auto unrelated = binary_entry("/usr/lib/libcrypto.so", 0x33);
    const auto required_update = binary_entry("/usr/bin/nexus-attestd", 0x44);
    std::vector<uint8_t> suffix = unrelated;
    suffix.insert(suffix.end(), required_update.begin(), required_update.end());
    const auto parsed_suffix = parse_ima_binary(suffix);
    ASSERT_TRUE(parsed_suffix);
    const auto expected = replay_ima_binary_from(*parsed_suffix, prior->event_count,
                                                 prior->pcr10, prior->paths);
    ASSERT_TRUE(expected);

    const auto only_unrelated = parse_ima_binary(unrelated);
    ASSERT_TRUE(only_unrelated);
    const auto preserved = replay_ima_binary_from(*only_unrelated, prior->event_count,
                                                  prior->pcr10, prior->paths);
    ASSERT_TRUE(preserved);
    const auto before = std::find_if(prior->paths.begin(), prior->paths.end(),
        [](const auto& p) { return p.path == "/usr/bin/nexus-attestd"; });
    const auto after = std::find_if(preserved->paths.begin(), preserved->paths.end(),
        [](const auto& p) { return p.path == "/usr/bin/nexus-attestd"; });
    ASSERT_NE(before, prior->paths.end());
    ASSERT_NE(after, preserved->paths.end());
    EXPECT_EQ(before->sha256, after->sha256);

    auto mutated = suffix;
    mutated.back() ^= 1;
    const auto parsed_mutated = parse_ima_binary(mutated);
    EXPECT_TRUE(!parsed_mutated ||
                replay_ima_binary_from(*parsed_mutated, prior->event_count,
                                       prior->pcr10, prior->paths)->pcr10 != expected->pcr10);
    std::vector<uint8_t> reordered = required_update;
    reordered.insert(reordered.end(), unrelated.begin(), unrelated.end());
    const auto parsed_reordered = parse_ima_binary(reordered);
    ASSERT_TRUE(parsed_reordered);
    EXPECT_NE(replay_ima_binary_from(*parsed_reordered, prior->event_count,
                                    prior->pcr10, prior->paths)->pcr10,
              expected->pcr10);
    EXPECT_NE(preserved->pcr10, expected->pcr10);  // missing required-update event

    EXPECT_FALSE(ima_binary_suffix_after_checkpoint(prefix, prior->event_count + 1,
                                                    prior->pcr10));
    auto wrong_pcr = prior->pcr10;
    wrong_pcr[0] ^= 1;
    EXPECT_FALSE(ima_binary_suffix_after_checkpoint(prefix, prior->event_count, wrong_pcr));
    auto rebooted = binary_entry("/usr/bin/nexus-attestd", 0x99);
    rebooted.insert(rebooted.end(), second.begin(), second.end());
    EXPECT_FALSE(ima_binary_suffix_after_checkpoint(rebooted, prior->event_count,
                                                    prior->pcr10));
}

TEST(AttestationState, StoresAreStrictBoundedSeparateAndCorruptionFailsClosed) {
    const auto root = std::filesystem::temp_directory_path() /
                      "nexus-protocol-closeout-state-test";
    std::filesystem::remove_all(root);
    AttestationCheckpoint checkpoint;
    checkpoint.network_id = filled<NetworkId>(1);
    checkpoint.node_id.bytes = filled<crypto::Ed25519PublicKey>(2);
    checkpoint.incarnation = 3;
    checkpoint.profile_id = AttestationProfileId::SnpSvsmVtpm;
    checkpoint.profile_ruleset = kAttestationProfileRulesetVersion;
    checkpoint.policy_digest = filled<Digest>(4);
    checkpoint.launch_measurement = filled<std::array<uint8_t, 48>>(5);
    checkpoint.ek_name = {0, 0x0b, 1};
    checkpoint.ak_name = {0, 0x0b, 2};
    checkpoint.ima_bank = kTpmAlgSha256;
    checkpoint.event_count = 7;
    checkpoint.pcr10 = filled<Digest>(6);
    checkpoint.required_paths = {{"/usr/bin/nexus-attestd", std::string(64, 'a')}};
    checkpoint.previous_evidence_digest = filled<Digest>(7);
    AttestationCheckpointStore checkpoints(root / "checkpoints");
    ASSERT_TRUE(checkpoints.store(checkpoint));
    EXPECT_TRUE(std::holds_alternative<AttestationCheckpoint>(checkpoints.load(
        checkpoint.network_id, checkpoint.node_id, checkpoint.incarnation,
        checkpoint.profile_id)));

    const std::vector<uint8_t> spki{1, 2, 3, 4};
    SvsmAkActivationRecord activation;
    activation.network_id = checkpoint.network_id;
    activation.node_id = checkpoint.node_id;
    activation.node_key = checkpoint.node_id.bytes;
    activation.incarnation = checkpoint.incarnation;
    activation.profile_id = checkpoint.profile_id;
    activation.profile_ruleset = checkpoint.profile_ruleset;
    activation.ek_name = checkpoint.ek_name;
    activation.ak_name = checkpoint.ak_name;
    activation.ak_spki_b64 = crypto::to_base64(spki);
    activation.ak_spki_digest = raw_ima_digest(spki);
    activation.activation_receipt = filled<Digest>(8);
    activation.enrollment_evidence_digest = filled<Digest>(9);
    SvsmActivationStore activations(root / "activations");
    ASSERT_TRUE(activations.store(activation));
    EXPECT_TRUE(std::holds_alternative<SvsmAkActivationRecord>(activations.load(
        activation.network_id, activation.node_id, activation.incarnation,
        activation.profile_id)));

    NetworkId other_network = activation.network_id;
    other_network[0] ^= 1;
    NodeId other_node = activation.node_id;
    other_node.bytes[0] ^= 1;
    EXPECT_EQ(std::get<AttestationStateLoadFailure>(activations.load(
                  other_network, activation.node_id, activation.incarnation,
                  activation.profile_id)),
              AttestationStateLoadFailure::Absent);
    EXPECT_EQ(std::get<AttestationStateLoadFailure>(activations.load(
                  activation.network_id, other_node, activation.incarnation,
                  activation.profile_id)),
              AttestationStateLoadFailure::Absent);
    EXPECT_EQ(std::get<AttestationStateLoadFailure>(activations.load(
                  activation.network_id, activation.node_id,
                  activation.incarnation + 1, activation.profile_id)),
              AttestationStateLoadFailure::Absent);

    std::ofstream(root / "checkpoints" / "ima-checkpoints.json", std::ios::trunc)
        << "{corrupt";
    EXPECT_EQ(std::get<AttestationStateLoadFailure>(checkpoints.load(
                  checkpoint.network_id, checkpoint.node_id, checkpoint.incarnation,
                  checkpoint.profile_id)),
              AttestationStateLoadFailure::Corrupt);
    EXPECT_TRUE(std::holds_alternative<SvsmAkActivationRecord>(activations.load(
        activation.network_id, activation.node_id, activation.incarnation,
        activation.profile_id)));
    std::ofstream(root / "activations" / "svsm-ak-activations.json", std::ios::trunc)
        << "{corrupt";
    EXPECT_EQ(std::get<AttestationStateLoadFailure>(activations.load(
                  activation.network_id, activation.node_id, activation.incarnation,
                  activation.profile_id)),
              AttestationStateLoadFailure::Corrupt);
    std::filesystem::remove_all(root);
}

TEST(SvsmActivation, CanonicalOfferAndResponseBindEverySecurityContextField) {
    SvsmAkActivationOfferMessage offer;
    offer.network_id = filled<NetworkId>(1);
    offer.subject_node.bytes = filled<crypto::Ed25519PublicKey>(2);
    offer.subject_key = offer.subject_node.bytes;
    offer.incarnation = 3;
    offer.epoch = 4;
    offer.profile_id = AttestationProfileId::SnpSvsmVtpm;
    offer.profile_ruleset = kAttestationProfileRulesetVersion;
    offer.observer.bytes = filled<crypto::Ed25519PublicKey>(5);
    offer.enrollment_challenge_digest = filled<Digest>(6);
    offer.verifier_nonce = filled<Nonce>(7);
    offer.ek_public = {8, 9};
    offer.ak_public = {10, 11};
    offer.ek_name = {0, 0x0b, 12};
    offer.ak_name = {0, 0x0b, 13};
    offer.ak_spki_digest = filled<Digest>(14);
    offer.activation.credential_blob = {15};
    offer.activation.encrypted_secret = {16};
    const Digest baseline = svsm_ak_activation_offer_context(offer);
    auto expect_change = [&](auto mutate) {
        auto changed = offer;
        mutate(changed);
        EXPECT_NE(svsm_ak_activation_offer_context(changed), baseline);
    };
    expect_change([](auto& o) { o.network_id[0] ^= 1; });
    expect_change([](auto& o) { o.subject_node.bytes[0] ^= 1; });
    expect_change([](auto& o) { o.subject_key[0] ^= 1; });
    expect_change([](auto& o) { o.incarnation += 1; });
    expect_change([](auto& o) { o.epoch += 1; });
    expect_change([](auto& o) { o.profile_ruleset += 1; });
    expect_change([](auto& o) { o.observer.bytes[0] ^= 1; });
    expect_change([](auto& o) { o.enrollment_challenge_digest[0] ^= 1; });
    expect_change([](auto& o) { o.verifier_nonce[0] ^= 1; });
    expect_change([](auto& o) { o.ek_public[0] ^= 1; });
    expect_change([](auto& o) { o.ak_public[0] ^= 1; });
    expect_change([](auto& o) { o.ek_name[0] ^= 1; });
    expect_change([](auto& o) { o.ak_name[0] ^= 1; });
    expect_change([](auto& o) { o.ak_spki_digest[0] ^= 1; });
    expect_change([](auto& o) { o.activation.credential_blob[0] ^= 1; });
    expect_change([](auto& o) { o.activation.encrypted_secret[0] ^= 1; });

    SvsmAkActivationResponseMessage response;
    response.network_id = offer.network_id;
    response.subject_node = offer.subject_node;
    response.incarnation = offer.incarnation;
    response.epoch = offer.epoch;
    response.profile_id = offer.profile_id;
    response.profile_ruleset = offer.profile_ruleset;
    response.observer = offer.observer;
    response.activation_context = baseline;
    response.activated_secret = {17};
    const Digest response_baseline = svsm_ak_activation_response_digest(response);
    response.activated_secret[0] ^= 1;
    EXPECT_NE(svsm_ak_activation_response_digest(response), response_baseline);
}

TEST(SvsmActivation, LiveOfferRejectsEveryContextMutationAndConsumesExactlyOnce) {
    crypto::Ed25519PublicKey public_key{};
    crypto::Ed25519PrivateKey secret_key{};
    ASSERT_EQ(crypto_sign_keypair(public_key.data(), secret_key.data()), 0);

    SvsmAkActivationChallenge challenge;
    challenge.expected_secret = {0x31, 0x32, 0x33, 0x34};
    challenge.ek_name = {0, 0x0b, 0x41};
    challenge.ak_name = {0, 0x0b, 0x42};
    SvsmAkActivationOfferMessage offer;
    offer.network_id = filled<NetworkId>(1);
    offer.subject_node.bytes = filled<crypto::Ed25519PublicKey>(2);
    offer.subject_key = public_key;
    offer.incarnation = 3;
    offer.epoch = 4;
    offer.profile_id = AttestationProfileId::SnpSvsmVtpm;
    offer.profile_ruleset = kAttestationProfileRulesetVersion;
    offer.observer.bytes = filled<crypto::Ed25519PublicKey>(5);
    offer.enrollment_challenge_digest = filled<Digest>(6);
    offer.verifier_nonce = filled<Nonce>(7);
    offer.ek_public = {8, 9};
    offer.ak_public = {10, 11};
    offer.ek_name = challenge.ek_name;
    offer.ak_name = challenge.ak_name;
    offer.ak_spki_digest = filled<Digest>(14);
    offer.activation.credential_blob = {15};
    offer.activation.encrypted_secret = {16};
    offer.activation.enrollment_context = svsm_ak_activation_offer_context(offer);

    auto signed_response = [&](const SvsmAkActivationOfferMessage& source) {
        SvsmAkActivationResponseMessage response;
        response.network_id = source.network_id;
        response.subject_node = source.subject_node;
        response.incarnation = source.incarnation;
        response.epoch = source.epoch;
        response.profile_id = source.profile_id;
        response.profile_ruleset = source.profile_ruleset;
        response.observer = source.observer;
        response.activation_context = source.activation.enrollment_context;
        response.activated_secret = challenge.expected_secret;
        const auto digest = svsm_ak_activation_response_digest(response);
        EXPECT_EQ(crypto_sign_detached(response.identity_signature.data(), nullptr,
                                       digest.data(), digest.size(), secret_key.data()), 0);
        return response;
    };
    auto resign = [&](SvsmAkActivationResponseMessage response) {
        const auto digest = svsm_ak_activation_response_digest(response);
        EXPECT_EQ(crypto_sign_detached(response.identity_signature.data(), nullptr,
                                       digest.data(), digest.size(), secret_key.data()), 0);
        return response;
    };

    SvsmAkActivationExchange exchange(challenge, offer);
    const auto valid = signed_response(offer);
    {
        auto wrong = valid; wrong.network_id[0] ^= 1;
        EXPECT_FALSE(exchange.complete(resign(wrong)));
    }
    {
        auto wrong = valid; wrong.subject_node.bytes[0] ^= 1;
        EXPECT_FALSE(exchange.complete(resign(wrong)));
    }
    {
        auto wrong = valid; wrong.incarnation += 1;
        EXPECT_FALSE(exchange.complete(resign(wrong)));
    }
    {
        auto wrong = valid; wrong.profile_ruleset += 1;
        EXPECT_FALSE(exchange.complete(resign(wrong)));
    }
    {
        auto wrong = valid; wrong.observer.bytes[0] ^= 1;
        EXPECT_FALSE(exchange.complete(resign(wrong)));
    }
    {
        auto wrong = valid; wrong.activated_secret[0] ^= 1;
        EXPECT_FALSE(exchange.complete(resign(wrong)));
    }
    {
        auto wrong = valid; wrong.identity_signature[0] ^= 1;
        EXPECT_FALSE(exchange.complete(wrong));
    }
    // A response derived from a different EK or AK carries a different
    // offer context, even if the subject legitimately signs it.
    for (bool change_ek : {true, false}) {
        auto rotated = offer;
        (change_ek ? rotated.ek_name : rotated.ak_name)[2] ^= 1;
        rotated.activation.enrollment_context = svsm_ak_activation_offer_context(rotated);
        EXPECT_FALSE(exchange.complete(signed_response(rotated)));
    }
    EXPECT_FALSE(exchange.consumed());
    EXPECT_TRUE(exchange.complete(valid));
    EXPECT_TRUE(exchange.consumed());
    EXPECT_FALSE(exchange.complete(valid));

    // No live offer at the service boundary also rejects the response.
    AttestationService service(offer.network_id, linux_attestation_profile_v2_svsm());
    EXPECT_FALSE(service.receive_activation_response(valid));
}

TEST(SecurityCodec, RoundTripsCheckpointTransferAndActivationMessages) {
    auto evidence = evidence_with_log(10);
    auto challenge = challenge_for(evidence);
    challenge.ima_mode = ImaEvidenceMode::Resume;
    challenge.ima_checkpoint_digest = filled<Digest>(1);
    challenge.ima_prior_event_count = 3;
    challenge.ima_prior_pcr10 = filled<Digest>(2);
    challenge.ima_checkpoint_paths = {{"/usr/bin/nexus-attestd", std::string(64, 'a')}};

    SecurityMessage message;
    message.kind = SecurityMessageKind::AttestationChallenge;
    message.security_ruleset = constants::kSecurityRulesetVersion;
    message.consensus_ruleset = constants::kConsensusRulesetVersion;
    message.network_id = challenge.network_id;
    message.epoch = challenge.epoch;
    message.sender = evidence.node_id;
    message.body = challenge;
    const auto bytes = encode_security_message(message);
    ASSERT_FALSE(bytes.empty());
    const auto decoded = decode_security_message(bytes);
    ASSERT_TRUE(std::holds_alternative<SecurityMessage>(decoded));
    EXPECT_EQ(std::get<AttestationChallenge>(std::get<SecurityMessage>(decoded).body)
                  .ima_checkpoint_paths,
              challenge.ima_checkpoint_paths);

    SvsmAkActivationResponseMessage response;
    response.network_id = message.network_id;
    response.subject_node = evidence.node_id;
    response.epoch = evidence.epoch;
    response.incarnation = evidence.incarnation;
    response.profile_id = AttestationProfileId::SnpSvsmVtpm;
    response.profile_ruleset = kAttestationProfileRulesetVersion;
    response.observer.bytes = filled<crypto::Ed25519PublicKey>(0x77);
    response.activation_context = filled<Digest>(3);
    response.activated_secret = {1, 2, 3};
    message.kind = SecurityMessageKind::SvsmAkActivationResponse;
    message.body = response;
    EXPECT_TRUE(std::holds_alternative<SecurityMessage>(
        decode_security_message(encode_security_message(message))));
}

}  // namespace
