#include "hotstuff_harness.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

namespace {

using namespace hotstuff_test;

// One replica among N = 4 (quorum 3). self is members[0], the leader of
// every view that is a multiple of four.
class HotStuffSafety : public ::testing::Test {
protected:
    void make_service(std::size_t self_index) {
        service.emplace(harness.config_for(self_index), clone_key(harness.keys[self_index]),
                        store);
    }

    [[nodiscard]] ProposalResult feed(const Block& block) {
        return service->receive_proposal(block.proposal, block.justify);
    }

    Harness harness{4};
    RecordingStore store;
    std::optional<HotStuffService> service;
};

TEST_F(HotStuffSafety, HappyChainVotesLocksAndCommits) {
    make_service(0);
    ASSERT_TRUE(service->synced());
    const auto chain = harness.build_chain(4);

    // b1 over genesis: vote, nothing to lock or commit.
    const auto r1 = feed(chain[0]);
    ASSERT_FALSE(r1.rejected.has_value());
    ASSERT_TRUE(r1.vote.has_value());
    EXPECT_EQ(r1.vote->view, 1u);
    EXPECT_EQ(r1.vote->height, 1u);
    EXPECT_EQ(r1.vote->proposal_digest, chain[0].digest);
    EXPECT_EQ(r1.vote->voter, harness.members[0]);
    EXPECT_TRUE(nexus::security::verify_digest(harness.keys[0].public_key,
                                               nexus::security::vote_signing_digest(*r1.vote),
                                               r1.vote->signature));
    EXPECT_TRUE(r1.commits.empty());
    EXPECT_EQ(service->state().locked_qc.view, 0u);
    EXPECT_EQ(service->state().high_qc.view, 0u);

    // b2: high_qc becomes the QC over b1; the lock stays at genesis.
    const auto r2 = feed(chain[1]);
    ASSERT_FALSE(r2.rejected.has_value());
    ASSERT_TRUE(r2.vote.has_value());
    EXPECT_EQ(r2.vote->view, 2u);
    EXPECT_TRUE(r2.commits.empty());
    EXPECT_EQ(service->state().high_qc.view, 1u);
    EXPECT_EQ(service->state().locked_qc.view, 0u);

    // b3: two-chain b1 <- b2 complete, lock on the QC over b1.
    const auto r3 = feed(chain[2]);
    ASSERT_FALSE(r3.rejected.has_value());
    ASSERT_TRUE(r3.vote.has_value());
    EXPECT_EQ(r3.vote->view, 3u);
    EXPECT_TRUE(r3.commits.empty());
    EXPECT_EQ(service->state().locked_qc.view, 1u);
    EXPECT_EQ(service->state().locked_qc.proposal_digest, chain[0].digest);

    // b4: three-chain b1 <- b2 <- b3 complete, commit b1 exactly now.
    const auto r4 = feed(chain[3]);
    ASSERT_FALSE(r4.rejected.has_value());
    ASSERT_TRUE(r4.vote.has_value());
    EXPECT_EQ(r4.vote->view, 4u);
    ASSERT_EQ(r4.commits.size(), 1u);
    EXPECT_EQ(r4.commits[0].epoch, kEpoch);
    EXPECT_EQ(r4.commits[0].height, 1u);
    EXPECT_EQ(r4.commits[0].view, 1u);
    EXPECT_EQ(r4.commits[0].proposal_digest, chain[0].digest);
    EXPECT_EQ(r4.commits[0].proposed_state_root, chain[0].proposal.proposed_state_root);
    EXPECT_EQ(r4.commits[0].qc_digest, nexus::security::qc_digest(chain[1].justify));
    EXPECT_EQ(service->state().locked_qc.view, 2u);
    EXPECT_EQ(service->state().high_qc.view, 3u);
    EXPECT_EQ(service->state().last_voted_view, 4u);
    EXPECT_EQ(service->current_view(), 4u);

    // Every vote had its state on disk first, with the new view inside.
    ASSERT_EQ(store.calls.size(), 4u);
    for (std::size_t i = 0; i < store.calls.size(); ++i) {
        EXPECT_TRUE(store.calls[i].accepted);
        EXPECT_EQ(store.calls[i].state.last_voted_view, i + 1);
        EXPECT_EQ(store.calls[i].state.epoch, kEpoch);
    }
    ASSERT_EQ(store.commits.size(), 1u);
    EXPECT_EQ(store.commits[0].height, 1u);
    EXPECT_TRUE(service->equivocation_evidence().empty());
}

TEST_F(HotStuffSafety, LongerChainCommitsInOrder) {
    make_service(0);
    const auto chain = harness.build_chain(6);
    for (std::size_t i = 0; i < 4; ++i) {
        ASSERT_TRUE(feed(chain[i]).vote.has_value());
    }
    const auto r5 = feed(chain[4]);
    ASSERT_EQ(r5.commits.size(), 1u);
    EXPECT_EQ(r5.commits[0].height, 2u);
    EXPECT_EQ(r5.commits[0].proposal_digest, chain[1].digest);

    const auto r6 = feed(chain[5]);
    ASSERT_EQ(r6.commits.size(), 1u);
    EXPECT_EQ(r6.commits[0].height, 3u);
    EXPECT_EQ(r6.commits[0].proposal_digest, chain[2].digest);
    ASSERT_EQ(store.commits.size(), 3u);
    EXPECT_EQ(store.commits.back().height, 3u);
}

TEST_F(HotStuffSafety, ReplayNeverVotesTwice) {
    make_service(0);
    const auto chain = harness.build_chain(3);
    ASSERT_TRUE(feed(chain[0]).vote.has_value());
    ASSERT_TRUE(feed(chain[1]).vote.has_value());

    // Same view again while the view is still current: withheld, not an error.
    const auto replay = feed(chain[1]);
    EXPECT_FALSE(replay.vote.has_value());
    EXPECT_FALSE(replay.rejected.has_value());
    EXPECT_TRUE(replay.safe_node_refused);
    EXPECT_EQ(store.calls.size(), 2u);

    ASSERT_TRUE(feed(chain[2]).vote.has_value());

    // After the view moved on the replay is stale.
    const auto stale = feed(chain[1]);
    EXPECT_FALSE(stale.vote.has_value());
    EXPECT_EQ(stale.rejected, ConsensusFailure::StaleView);
    EXPECT_EQ(store.calls.size(), 3u);
    EXPECT_EQ(service->state().last_voted_view, 3u);
}

TEST_F(HotStuffSafety, SafeNodeRefusesBranchBelowLockAndVotesAboveIt) {
    make_service(0);
    const auto chain = harness.build_chain(4);
    for (const auto& block : chain) {
        ASSERT_TRUE(feed(block).vote.has_value());
    }
    ASSERT_EQ(service->state().locked_qc.view, 2u);

    // A conflicting branch: height 2 at view 5 on top of b1, justified by
    // the QC over b1 (view 1 <= locked view 2). It does not extend b2.
    const Block conflict = harness.make_block(2, 5, chain[0].digest, chain[1].justify, 0x70);
    const auto refused = feed(conflict);
    EXPECT_FALSE(refused.vote.has_value());
    EXPECT_FALSE(refused.rejected.has_value());
    EXPECT_TRUE(refused.safe_node_refused);
    EXPECT_TRUE(refused.commits.empty());
    EXPECT_EQ(service->state().last_voted_view, 4u);
    EXPECT_EQ(service->state().locked_qc.view, 2u);

    // The branch grows a QC of its own at view 5 > locked view 2: the
    // liveness rule allows the vote even though the lock is not extended.
    const Block extension =
        harness.make_block(3, 6, conflict.digest, harness.qc_for(conflict.proposal), 0x80);
    const auto allowed = feed(extension);
    EXPECT_FALSE(allowed.rejected.has_value());
    ASSERT_TRUE(allowed.vote.has_value());
    EXPECT_EQ(allowed.vote->view, 6u);
    EXPECT_FALSE(allowed.safe_node_refused);
    // The lock never regresses to the branch's older QC.
    EXPECT_EQ(service->state().locked_qc.view, 2u);
}

TEST_F(HotStuffSafety, RejectsRulesetNetworkAndEpochMismatch) {
    make_service(0);
    const auto chain = harness.build_chain(1);

    auto security = chain[0].proposal;
    security.security_ruleset += 1;
    const auto r1 = service->receive_proposal(security, chain[0].justify);
    EXPECT_EQ(r1.rejected, ConsensusFailure::RulesetMismatch);
    EXPECT_FALSE(r1.vote.has_value());

    auto consensus = chain[0].proposal;
    consensus.consensus_ruleset += 1;
    EXPECT_EQ(service->receive_proposal(consensus, chain[0].justify).rejected,
              ConsensusFailure::RulesetMismatch);

    auto network = chain[0].proposal;
    network.network_id[0] ^= 0xFF;
    EXPECT_EQ(service->receive_proposal(network, chain[0].justify).rejected,
              ConsensusFailure::NetworkMismatch);

    auto epoch = chain[0].proposal;
    epoch.epoch += 1;
    EXPECT_EQ(service->receive_proposal(epoch, chain[0].justify).rejected,
              ConsensusFailure::EpochMismatch);

    EXPECT_TRUE(store.calls.empty());
}

TEST_F(HotStuffSafety, RejectsViewBeyondFutureDistance) {
    make_service(0);
    const auto chain = harness.build_chain(1);
    auto far = chain[0].proposal;
    far.view = 1 + constants::kMaxFutureViewDistance + 1;
    const auto result = service->receive_proposal(far, chain[0].justify);
    EXPECT_EQ(result.rejected, ConsensusFailure::ViewTooFar);
    EXPECT_FALSE(result.vote.has_value());
}

TEST_F(HotStuffSafety, RejectsWrongLeader) {
    make_service(0);
    const auto chain = harness.build_chain(1);
    auto wrong = chain[0].proposal;
    wrong.leader = harness.members[2];
    const auto result = service->receive_proposal(wrong, chain[0].justify);
    EXPECT_EQ(result.rejected, ConsensusFailure::WrongLeader);
    EXPECT_FALSE(result.vote.has_value());
}

TEST_F(HotStuffSafety, RejectsJustifyDigestMismatch) {
    make_service(0);
    const auto chain = harness.build_chain(1);
    auto tampered = chain[0].proposal;
    tampered.justify_qc_digest[0] ^= 0xFF;
    const auto result = service->receive_proposal(tampered, chain[0].justify);
    EXPECT_EQ(result.rejected, ConsensusFailure::JustifyInvalid);
    EXPECT_FALSE(result.vote.has_value());
}

TEST_F(HotStuffSafety, RejectsParentThatIsNotTheJustifiedBlock) {
    make_service(0);
    const auto chain = harness.build_chain(1);
    auto detached = chain[0].proposal;
    detached.parent_digest[0] ^= 0xFF;
    const auto result = service->receive_proposal(detached, chain[0].justify);
    EXPECT_EQ(result.rejected, ConsensusFailure::ParentQcMismatch);
    EXPECT_FALSE(result.vote.has_value());
}

TEST_F(HotStuffSafety, RejectsTamperedJustifySignature) {
    make_service(0);
    const auto chain = harness.build_chain(1);
    ASSERT_TRUE(feed(chain[0]).vote.has_value());

    auto tampered = harness.qc_for(chain[0].proposal);
    tampered.signers[1].signature[0] ^= 0xFF;
    const Block b2 = harness.make_block(2, 2, chain[0].digest, tampered, 0x60);
    const auto result = feed(b2);
    EXPECT_EQ(result.rejected, ConsensusFailure::JustifyInvalid);
    EXPECT_FALSE(result.vote.has_value());
    EXPECT_EQ(service->state().high_qc.view, 0u);
}

TEST_F(HotStuffSafety, RejectsEmptySignerCertificateThatIsNotGenesis) {
    make_service(0);
    const auto chain = harness.build_chain(1);
    ASSERT_TRUE(feed(chain[0]).vote.has_value());

    // An unsigned QC over b1.
    auto unsigned_qc = harness.qc_for(chain[0].proposal);
    unsigned_qc.signers.clear();
    const Block b2 = harness.make_block(2, 2, chain[0].digest, unsigned_qc, 0x60);
    EXPECT_EQ(feed(b2).rejected, ConsensusFailure::JustifyInvalid);

    // A genesis-shaped QC that names another block.
    auto fake_genesis = harness.genesis_qc();
    fake_genesis.proposal_digest = filled_digest(0x99);
    const Block orphan = harness.make_block(1, 2, fake_genesis.proposal_digest, fake_genesis, 0x60);
    EXPECT_EQ(feed(orphan).rejected, ConsensusFailure::JustifyInvalid);

    // A genesis-shaped QC with a wrong header field.
    auto wrong_height = harness.genesis_qc();
    wrong_height.height = 1;
    const Block bad_header = harness.make_block(1, 2, test_genesis(), wrong_height, 0x60);
    EXPECT_EQ(feed(bad_header).rejected, ConsensusFailure::JustifyInvalid);

    EXPECT_EQ(store.calls.size(), 1u);
}

TEST_F(HotStuffSafety, RejectsUnknownParent) {
    make_service(0);
    const auto chain = harness.build_chain(2);
    // b2 without b1: the justify is valid but the parent is unknown.
    const auto result = feed(chain[1]);
    EXPECT_EQ(result.rejected, ConsensusFailure::MissingParent);
    EXPECT_FALSE(result.vote.has_value());
    // A valid QC still advances high_qc.
    EXPECT_EQ(service->state().high_qc.view, 1u);
}

TEST_F(HotStuffSafety, RejectsWrongHeight) {
    make_service(0);
    const auto chain = harness.build_chain(1);
    auto wrong = chain[0].proposal;
    wrong.height = 2;
    EXPECT_EQ(service->receive_proposal(wrong, chain[0].justify).rejected,
              ConsensusFailure::ParentQcMismatch);
}

TEST_F(HotStuffSafety, EquivocatingLeaderProducesEvidence) {
    make_service(0);
    const auto chain = harness.build_chain(2);
    ASSERT_TRUE(feed(chain[0]).vote.has_value());
    ASSERT_TRUE(feed(chain[1]).vote.has_value());

    // A second, different proposal for view 2 from the same leader.
    const Block other = harness.make_block(2, 2, chain[0].digest, chain[1].justify, 0x90);
    ASSERT_NE(other.digest, chain[1].digest);
    const auto result = feed(other);
    EXPECT_EQ(result.rejected, ConsensusFailure::Equivocation);
    EXPECT_FALSE(result.vote.has_value());

    const auto& evidence = service->equivocation_evidence();
    ASSERT_EQ(evidence.size(), 1u);
    EXPECT_EQ(evidence[0].node, harness.members[2]);
    EXPECT_EQ(evidence[0].view, 2u);
    EXPECT_EQ(evidence[0].first, chain[1].digest);
    EXPECT_EQ(evidence[0].second, other.digest);
    EXPECT_FALSE(evidence[0].is_vote);
}

TEST_F(HotStuffSafety, StoreRefusalWithholdsVoteAndDoesNotBurnTheView) {
    make_service(0);
    const auto chain = harness.build_chain(1);

    store.fail_store_before_vote = true;
    const auto refused = feed(chain[0]);
    EXPECT_EQ(refused.rejected, ConsensusFailure::StorageRejected);
    EXPECT_FALSE(refused.vote.has_value());
    ASSERT_EQ(store.calls.size(), 1u);
    EXPECT_FALSE(store.calls[0].accepted);
    EXPECT_EQ(store.calls[0].state.last_voted_view, 1u);
    // The view is not treated as voted.
    EXPECT_EQ(service->state().last_voted_view, 0u);

    // With a working store the same proposal votes exactly once.
    store.fail_store_before_vote = false;
    const auto voted = feed(chain[0]);
    EXPECT_FALSE(voted.rejected.has_value());
    ASSERT_TRUE(voted.vote.has_value());
    EXPECT_EQ(voted.vote->view, 1u);
    ASSERT_EQ(store.calls.size(), 2u);
    EXPECT_TRUE(store.calls[1].accepted);
    EXPECT_EQ(store.calls[1].state.last_voted_view, 1u);
    EXPECT_EQ(store.calls[1].state.high_qc.view, 0u);
    EXPECT_EQ(store.calls[1].state.locked_qc.view, 0u);
    EXPECT_EQ(store.calls[1].state.consensus_ruleset, constants::kConsensusRulesetVersion);
    EXPECT_EQ(service->state().last_voted_view, 1u);

    // And never again for that view.
    const auto again = feed(chain[0]);
    EXPECT_FALSE(again.vote.has_value());
    EXPECT_EQ(store.calls.size(), 2u);
}

TEST_F(HotStuffSafety, StoredStateMatchesVoteAtEveryStep) {
    make_service(0);
    const auto chain = harness.build_chain(4);
    for (const auto& block : chain) {
        const auto result = feed(block);
        ASSERT_TRUE(result.vote.has_value());
        // The store call for this vote is the last one made, and it already
        // holds the voted view together with the QCs in force at vote time.
        ASSERT_FALSE(store.calls.empty());
        const auto& call = store.calls.back();
        EXPECT_TRUE(call.accepted);
        EXPECT_EQ(call.state.last_voted_view, result.vote->view);
        EXPECT_EQ(call.state.high_qc.view, service->state().high_qc.view);
        EXPECT_EQ(call.state.locked_qc.view, service->state().locked_qc.view);
    }
}

TEST_F(HotStuffSafety, AdoptCertifiedBlocksAnchorOnceAndRebuildChainState) {
    make_service(0);
    const auto chain = harness.build_chain(5);
    std::vector<ConsensusCommit> commits;

    // A tampered certificate never anchors, and the anchor is not consumed.
    auto forged = harness.qc_for(chain[1].proposal);
    forged.signers[0].signature[0] ^= 1;
    EXPECT_EQ(service->adopt_certified_block(chain[1].proposal, chain[1].justify, forged, commits),
              ConsensusFailure::JustifyInvalid);

    // b2 anchors parentless on the empty chain with its valid certificate.
    EXPECT_EQ(service->adopt_certified_block(chain[1].proposal, chain[1].justify,
                                             harness.qc_for(chain[1].proposal), commits),
              std::nullopt);

    // Exactly one anchor: a second parentless block is refused.
    EXPECT_EQ(service->adopt_certified_block(chain[3].proposal, chain[3].justify,
                                             harness.qc_for(chain[3].proposal), commits),
              ConsensusFailure::MissingParent);

    // The blocks above the anchor link normally; the three-chain commits b2.
    EXPECT_EQ(service->adopt_certified_block(chain[2].proposal, chain[2].justify,
                                             harness.qc_for(chain[2].proposal), commits),
              std::nullopt);
    EXPECT_EQ(service->adopt_certified_block(chain[3].proposal, chain[3].justify,
                                             harness.qc_for(chain[3].proposal), commits),
              std::nullopt);
    ASSERT_FALSE(commits.empty());
    EXPECT_EQ(commits.back().height, 2u);
    EXPECT_EQ(commits.back().proposal_digest, chain[1].digest);
    EXPECT_EQ(service->state().high_qc.view, 4u);

    // Adoption never voted; a live proposal above the adopted views does.
    const auto r5 = feed(chain[4]);
    ASSERT_FALSE(r5.rejected.has_value());
    ASSERT_TRUE(r5.vote.has_value());
    EXPECT_EQ(r5.vote->view, 5u);

    // The sync answer this replica would give: the chain above the committed
    // height, ending at the block the high certificate certifies.
    const auto out = service->uncommitted_chain();
    ASSERT_EQ(out.size(), 2u);
    EXPECT_EQ(nexus::security::proposal_digest(out.front().first), chain[2].digest);
    EXPECT_EQ(nexus::security::proposal_digest(out.back().first), chain[3].digest);
}


// --- A handoff must be agreed, not announced -----------------------------------
//
// A proposal carries its transition only as a digest, so consensus cannot read
// it. A replica that votes anyway authorizes a handoff it never evaluated: the
// commit then means different things on different nodes, and only the proposer
// activates. That splits the mesh across two epochs. These pin the refusal.

class HotStuffTransitions : public ::testing::Test {
protected:
    /// A replica whose view of a pending transition is exactly `validator`.
    void make_service(std::size_t self_index,
                      std::function<bool(const Digest&)> validator) {
        auto config = harness.config_for(self_index);
        config.transition_validator = std::move(validator);
        service.emplace(std::move(config), clone_key(harness.keys[self_index]), store);
    }

    Harness harness{4};
    RecordingStore store;
    std::optional<HotStuffService> service;
};

TEST_F(HotStuffTransitions, ProposalCarryingAnUnknownTransitionIsRefused) {
    // This replica has arrived at no transition at all.
    make_service(1, [](const Digest&) { return false; });
    const auto chain = harness.build_chain(1);
    const auto result = service->receive_proposal(chain[0].proposal, chain[0].justify);
    EXPECT_EQ(result.rejected, ConsensusFailure::TransitionUnknown);
    EXPECT_FALSE(result.vote.has_value());
}

TEST_F(HotStuffTransitions, AReplicaWithNoValidatorRefusesEveryTransition) {
    make_service(1, nullptr);   // nothing can be evaluated
    const auto chain = harness.build_chain(1);
    EXPECT_EQ(service->receive_proposal(chain[0].proposal, chain[0].justify).rejected,
              ConsensusFailure::TransitionUnknown);
}

// An ordinary block carries no transition, so the rule does not touch it: it
// still votes on a replica that can evaluate nothing.
TEST_F(HotStuffTransitions, AnOrdinaryBlockNeedsNoValidator) {
    make_service(1, nullptr);
    auto chain = harness.build_chain(1);
    chain[0].proposal.transitions_digest = Digest{};
    const auto result = service->receive_proposal(chain[0].proposal, chain[0].justify);
    EXPECT_NE(result.rejected, ConsensusFailure::TransitionUnknown);
}

// The positive control: the same proposal a replica DOES recognise is voted
// for, so the refusals above are the rule and not a broken proposal.
TEST_F(HotStuffTransitions, ARecognisedTransitionIsVotedFor) {
    const auto chain = harness.build_chain(1);
    const Digest expected = chain[0].proposal.transitions_digest;
    make_service(1, [expected](const Digest& d) { return d == expected; });

    const auto result = service->receive_proposal(chain[0].proposal, chain[0].justify);
    ASSERT_FALSE(result.rejected.has_value());
    ASSERT_TRUE(result.vote.has_value());
}

}  // namespace
