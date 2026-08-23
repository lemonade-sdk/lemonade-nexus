#include "hotstuff_harness.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <variant>

namespace {

using namespace hotstuff_test;

using VoteResult = std::variant<std::monostate, QuorumCertificate, ConsensusFailure>;
using TimeoutResult = std::variant<std::monostate, TimeoutCertificate, ConsensusFailure>;

// The leader side. self is members[1], the leader of view 1.
class HotStuffVotes : public ::testing::Test {
protected:
    void SetUp() override {
        service.emplace(harness.config_for(1), clone_key(harness.keys[1]), store);
    }

    Harness harness{4};
    RecordingStore store;
    std::optional<HotStuffService> service;
    const Digest digest = filled_digest(0x99);
};

TEST_F(HotStuffVotes, LeaderProposesVotesAndFormsQcAtExactQuorum) {
    const auto made = service->make_proposal(filled_digest(0x50), filled_digest(0x51),
                                             filled_digest(0x52));
    ASSERT_TRUE(std::holds_alternative<Proposal>(made));
    const auto& proposal = std::get<Proposal>(made);
    EXPECT_EQ(proposal.view, 1u);
    EXPECT_EQ(proposal.height, 1u);
    EXPECT_EQ(proposal.leader, harness.members[1]);
    EXPECT_EQ(proposal.parent_digest, test_genesis());
    EXPECT_EQ(proposal.justify_qc_digest, nexus::security::qc_digest(harness.genesis_qc()));
    EXPECT_EQ(proposal.epoch, kEpoch);
    EXPECT_EQ(proposal.timestamp_hint, 0u);

    // The leader votes on its own proposal through the normal path.
    const auto own = service->receive_proposal(proposal, harness.genesis_qc());
    ASSERT_TRUE(own.vote.has_value());
    EXPECT_TRUE(std::holds_alternative<std::monostate>(service->receive_vote(*own.vote)));

    const auto proposal_hash = nexus::security::proposal_digest(proposal);
    EXPECT_TRUE(std::holds_alternative<std::monostate>(
        service->receive_vote(harness.make_vote(0, 1, 1, proposal_hash))));

    const auto third = service->receive_vote(harness.make_vote(2, 1, 1, proposal_hash));
    ASSERT_TRUE(std::holds_alternative<QuorumCertificate>(third));
    const auto& qc = std::get<QuorumCertificate>(third);
    EXPECT_EQ(qc.qc_format_version, constants::kQcFormatVersion);
    EXPECT_EQ(qc.view, 1u);
    EXPECT_EQ(qc.height, 1u);
    EXPECT_EQ(qc.proposal_digest, proposal_hash);
    ASSERT_EQ(qc.signers.size(), 3u);
    EXPECT_EQ(qc.signers[0].node_id, harness.members[0]);
    EXPECT_EQ(qc.signers[1].node_id, harness.members[1]);
    EXPECT_EQ(qc.signers[2].node_id, harness.members[2]);
    EXPECT_EQ(nexus::security::validate_quorum_certificate(qc, harness.validation_context(),
                                                           harness.vote_keys),
              std::nullopt);

    EXPECT_EQ(service->current_view(), 2u);
    EXPECT_EQ(service->state().high_qc.view, 1u);
    EXPECT_EQ(service->state().high_qc.proposal_digest, proposal_hash);

    // The next view has another leader.
    EXPECT_EQ(std::get<ConsensusFailure>(service->make_proposal(digest, digest, digest)),
              ConsensusFailure::NotLeader);
}

TEST_F(HotStuffVotes, VotesForUnknownProposalStillFormQc) {
    EXPECT_TRUE(std::holds_alternative<std::monostate>(
        service->receive_vote(harness.make_vote(0, 5, 3, digest))));
    EXPECT_TRUE(std::holds_alternative<std::monostate>(
        service->receive_vote(harness.make_vote(1, 5, 3, digest))));
    const auto third = service->receive_vote(harness.make_vote(2, 5, 3, digest));
    ASSERT_TRUE(std::holds_alternative<QuorumCertificate>(third));
    EXPECT_EQ(std::get<QuorumCertificate>(third).proposal_digest, digest);
    EXPECT_EQ(std::get<QuorumCertificate>(third).height, 3u);
    EXPECT_EQ(service->current_view(), 6u);

    // A fourth vote does not form a second certificate.
    EXPECT_TRUE(std::holds_alternative<std::monostate>(
        service->receive_vote(harness.make_vote(3, 5, 3, digest))));
}

TEST_F(HotStuffVotes, DuplicateSameDigestVoteIsIdempotent) {
    const auto first = harness.make_vote(0, 5, 3, digest);
    EXPECT_TRUE(std::holds_alternative<std::monostate>(service->receive_vote(first)));
    EXPECT_TRUE(std::holds_alternative<std::monostate>(service->receive_vote(first)));
    EXPECT_TRUE(std::holds_alternative<std::monostate>(
        service->receive_vote(harness.make_vote(1, 5, 3, digest))));
    // Two distinct voters so far: the duplicate did not count.
    EXPECT_TRUE(std::holds_alternative<std::monostate>(service->receive_vote(first)));
    EXPECT_TRUE(std::holds_alternative<QuorumCertificate>(
        service->receive_vote(harness.make_vote(2, 5, 3, digest))));
    EXPECT_TRUE(service->equivocation_evidence().empty());
}

TEST_F(HotStuffVotes, ConflictingVoteIsEvidenceAndCountsOnce) {
    const Digest other = filled_digest(0x77);
    EXPECT_TRUE(std::holds_alternative<std::monostate>(
        service->receive_vote(harness.make_vote(0, 5, 3, digest))));

    const auto conflict = service->receive_vote(harness.make_vote(0, 5, 3, other));
    ASSERT_TRUE(std::holds_alternative<ConsensusFailure>(conflict));
    EXPECT_EQ(std::get<ConsensusFailure>(conflict), ConsensusFailure::DuplicateSigner);

    const auto& evidence = service->equivocation_evidence();
    ASSERT_EQ(evidence.size(), 1u);
    EXPECT_EQ(evidence[0].node, harness.members[0]);
    EXPECT_EQ(evidence[0].view, 5u);
    EXPECT_EQ(evidence[0].first, digest);
    EXPECT_EQ(evidence[0].second, other);
    EXPECT_TRUE(evidence[0].is_vote);

    // The first vote stays and counts once; the conflict counts for nothing.
    EXPECT_TRUE(std::holds_alternative<std::monostate>(
        service->receive_vote(harness.make_vote(1, 5, 3, digest))));
    const auto formed = service->receive_vote(harness.make_vote(2, 5, 3, digest));
    ASSERT_TRUE(std::holds_alternative<QuorumCertificate>(formed));
    ASSERT_EQ(std::get<QuorumCertificate>(formed).signers.size(), 3u);
    EXPECT_EQ(std::get<QuorumCertificate>(formed).signers[0].node_id, harness.members[0]);

    // The other digest has one honest supporter at most; no certificate.
    EXPECT_TRUE(std::holds_alternative<std::monostate>(
        service->receive_vote(harness.make_vote(3, 5, 3, other))));
    EXPECT_EQ(service->equivocation_evidence().size(), 1u);
}

TEST_F(HotStuffVotes, RejectsInvalidSignatureAndUnknownVoter) {
    auto tampered = harness.make_vote(0, 5, 3, digest);
    tampered.signature[0] ^= 0xFF;
    const auto bad = service->receive_vote(tampered);
    ASSERT_TRUE(std::holds_alternative<ConsensusFailure>(bad));
    EXPECT_EQ(std::get<ConsensusFailure>(bad), ConsensusFailure::InvalidSignature);

    auto stranger = harness.make_vote(0, 5, 3, digest);
    stranger.voter = filled_node(0xEE);
    const auto unknown = service->receive_vote(stranger);
    ASSERT_TRUE(std::holds_alternative<ConsensusFailure>(unknown));
    EXPECT_EQ(std::get<ConsensusFailure>(unknown), ConsensusFailure::UnknownSigner);

    auto wrong_epoch = harness.make_vote(0, 5, 3, digest);
    wrong_epoch.epoch += 1;
    EXPECT_EQ(std::get<ConsensusFailure>(service->receive_vote(wrong_epoch)),
              ConsensusFailure::EpochMismatch);

    auto wrong_network = harness.make_vote(0, 5, 3, digest);
    wrong_network.network_id[0] ^= 0xFF;
    EXPECT_EQ(std::get<ConsensusFailure>(service->receive_vote(wrong_network)),
              ConsensusFailure::NetworkMismatch);

    auto wrong_ruleset = harness.make_vote(0, 5, 3, digest);
    wrong_ruleset.consensus_ruleset += 1;
    EXPECT_EQ(std::get<ConsensusFailure>(service->receive_vote(wrong_ruleset)),
              ConsensusFailure::RulesetMismatch);

    // None of them counted.
    EXPECT_TRUE(std::holds_alternative<std::monostate>(
        service->receive_vote(harness.make_vote(0, 5, 3, digest))));
    EXPECT_TRUE(std::holds_alternative<std::monostate>(
        service->receive_vote(harness.make_vote(1, 5, 3, digest))));
    EXPECT_TRUE(std::holds_alternative<QuorumCertificate>(
        service->receive_vote(harness.make_vote(2, 5, 3, digest))));
}

TEST_F(HotStuffVotes, TimeoutCertificateCarriesEachSignersOwnHighQc) {
    const auto t0 = harness.make_timeout(0, 3, filled_digest(0x60));
    const auto t2 = harness.make_timeout(2, 3, filled_digest(0x62));
    const auto t3 = harness.make_timeout(3, 3, filled_digest(0x63));

    EXPECT_TRUE(std::holds_alternative<std::monostate>(service->receive_timeout(t0)));
    EXPECT_TRUE(std::holds_alternative<std::monostate>(service->receive_timeout(t2)));
    EXPECT_EQ(service->current_view(), 1u);

    const auto formed = service->receive_timeout(t3);
    ASSERT_TRUE(std::holds_alternative<TimeoutCertificate>(formed));
    const auto& tc = std::get<TimeoutCertificate>(formed);
    EXPECT_EQ(tc.view, 3u);
    EXPECT_EQ(tc.epoch, kEpoch);
    ASSERT_EQ(tc.signers.size(), 3u);
    EXPECT_EQ(tc.signers[0].node_id, harness.members[0]);
    EXPECT_EQ(tc.signers[0].high_qc_digest, filled_digest(0x60));
    EXPECT_EQ(tc.signers[1].node_id, harness.members[2]);
    EXPECT_EQ(tc.signers[1].high_qc_digest, filled_digest(0x62));
    EXPECT_EQ(tc.signers[2].node_id, harness.members[3]);
    EXPECT_EQ(tc.signers[2].high_qc_digest, filled_digest(0x63));
    EXPECT_EQ(nexus::security::validate_timeout_certificate(tc, harness.validation_context(),
                                                            harness.vote_keys),
              std::nullopt);
    EXPECT_EQ(service->current_view(), 4u);
}

TEST_F(HotStuffVotes, SecondTimeoutFromOneNodeDoesNotCount) {
    EXPECT_TRUE(std::holds_alternative<std::monostate>(
        service->receive_timeout(harness.make_timeout(0, 3, filled_digest(0x60)))));
    // A refreshed claim from the same node: not counted, not evidence.
    EXPECT_TRUE(std::holds_alternative<std::monostate>(
        service->receive_timeout(harness.make_timeout(0, 3, filled_digest(0x61)))));
    EXPECT_TRUE(std::holds_alternative<std::monostate>(
        service->receive_timeout(harness.make_timeout(2, 3, filled_digest(0x62)))));
    EXPECT_EQ(service->current_view(), 1u);

    const auto formed = service->receive_timeout(harness.make_timeout(3, 3, filled_digest(0x63)));
    ASSERT_TRUE(std::holds_alternative<TimeoutCertificate>(formed));
    const auto& tc = std::get<TimeoutCertificate>(formed);
    ASSERT_EQ(tc.signers.size(), 3u);
    EXPECT_EQ(tc.signers[0].high_qc_digest, filled_digest(0x60));
    EXPECT_TRUE(service->equivocation_evidence().empty());

    auto tampered = harness.make_timeout(1, 4, filled_digest(0x64));
    tampered.signature[0] ^= 0xFF;
    EXPECT_EQ(std::get<ConsensusFailure>(service->receive_timeout(tampered)),
              ConsensusFailure::InvalidSignature);
}

TEST_F(HotStuffVotes, OwnTimeoutVoteRoundTrips) {
    const auto own = service->make_timeout_vote();
    EXPECT_EQ(own.view, service->current_view());
    EXPECT_EQ(own.voter, harness.members[1]);
    EXPECT_EQ(own.high_qc_digest, nexus::security::qc_digest(harness.genesis_qc()));
    EXPECT_TRUE(nexus::security::verify_digest(
        harness.keys[1].public_key, nexus::security::timeout_vote_signing_digest(own),
        own.signature));

    EXPECT_TRUE(std::holds_alternative<std::monostate>(service->receive_timeout(own)));
    EXPECT_TRUE(std::holds_alternative<std::monostate>(
        service->receive_timeout(harness.make_timeout(0, own.view, filled_digest(0x60)))));
    const auto formed =
        service->receive_timeout(harness.make_timeout(2, own.view, filled_digest(0x62)));
    ASSERT_TRUE(std::holds_alternative<TimeoutCertificate>(formed));
    const auto& tc = std::get<TimeoutCertificate>(formed);
    ASSERT_EQ(tc.signers.size(), 3u);
    EXPECT_EQ(tc.signers[1].node_id, harness.members[1]);
    EXPECT_EQ(tc.signers[1].high_qc_digest, own.high_qc_digest);
    EXPECT_EQ(service->current_view(), own.view + 1);
}

}  // namespace

TEST_F(HotStuffVotes, VotesOutsideTheViewWindowAreRefusedBeforeSignatureWork) {
    const auto far_digest = hotstuff_test::filled_digest(0x77);
    const nexus::security::View far_view =
        service->current_view() + nexus::security::constants::kMaxFutureViewDistance + 1;
    const auto too_far = service->receive_vote(harness.make_vote(0, far_view, 3, far_digest));
    ASSERT_TRUE(std::holds_alternative<nexus::security::ConsensusFailure>(too_far));
    EXPECT_EQ(std::get<nexus::security::ConsensusFailure>(too_far),
              nexus::security::ConsensusFailure::ViewTooFar);

    // The edge of the window is still inside it.
    const auto edge = service->receive_vote(harness.make_vote(0, far_view - 1, 3, far_digest));
    EXPECT_TRUE(std::holds_alternative<std::monostate>(edge));
}
