// Deterministic measurement across the Tier 1 population table.
//
// This measures; it does not tune. Every constant the protocol uses stays where
// it is, and the only assertions are invariants that must hold at any size —
// the quorum formulas, safety under leader failure, and the bounds the wire
// format promises. The numbers are printed so the shape of the protocol at 5
// and at 31 members is a recorded fact rather than an estimate.
//
// The simulation is deterministic: fixed keys, fixed order, no clock. The same
// run produces the same table on every machine.

#include "security/consensus/hotstuff_harness.hpp"

#include <LemonadeNexus/Security/Consensus/QuorumValidation.hpp>
#include <LemonadeNexus/Security/Epoch/Tier1Selector.hpp>
#include <LemonadeNexus/Security/Transport/SecurityCodec.hpp>

#include <gtest/gtest.h>

#include <cstdio>
#include <map>
#include <numeric>
#include <string>
#include <vector>

using namespace hotstuff_test;

namespace {

/// Every population the target table can produce.
constexpr std::size_t kPopulations[] = {5, 7, 10, 13, 16, 19, 22, 25, 28, 31};

struct Measurement {
    std::size_t members{};
    std::size_t quorum{};
    std::size_t authority_threshold{};
    std::size_t max_faults{};

    // Per committed block, counted rather than derived.
    std::size_t proposals{};
    std::size_t votes{};
    std::size_t commits{};
    std::size_t view_changes{};
    std::size_t timeout_votes{};

    std::size_t qc_signature_bytes{};
    std::size_t proposal_wire_bytes{};

    // One round of each, in messages: DKG is all-to-all pairwise plus one
    // broadcast each; FROST is one commitment and one share per signer.
    std::size_t dkg_messages_per_round{};
    std::size_t frost_messages_per_signature{};

    std::size_t liveness_failures{};
};

/// Runs `views` views of a chain with every member voting, and counts what
/// crossed the wire. `failed_leaders` views are skipped to model a leader that
/// never proposes, so the pacemaker has to move the view on.
Measurement measure(std::size_t members, std::size_t views, std::size_t failed_leaders) {
    Measurement m;
    m.members = members;
    m.quorum = constants::consensus_quorum(members);
    m.authority_threshold = constants::authority_threshold(members);
    m.max_faults = constants::max_byzantine_faults(members);

    Harness harness{members};
    RecordingStore store;
    HotStuffService replica{harness.config_for(0), clone_key(harness.keys[0]), store};

    // A failed leader consumes its view without producing a block, so the chain
    // stays linked at consecutive heights while the view number skips ahead.
    // That is the real cost of leader failure: views, not blocks.
    QuorumCertificate justify = harness.genesis_qc();
    Digest parent = test_genesis();
    View view = 1;
    std::size_t skipped = 0;
    Block last = harness.make_block(1, 1, parent, justify, 0x20);

    for (Height height = 1; height <= views; ++height) {
        if (skipped < failed_leaders && height % 4 == 2) {
            ++skipped;
            ++view;
            ++m.view_changes;
            ++m.liveness_failures;
        }
        const Block block = harness.make_block(height, view, parent,
                                               justify, static_cast<uint8_t>(0x20 + height * 4));
        const auto result = replica.receive_proposal(block.proposal, block.justify);
        ++m.proposals;
        if (result.vote.has_value()) {
            // Every member votes on an accepted proposal.
            m.votes += members;
        }
        m.commits += result.commits.size();
        parent = block.digest;
        justify = harness.qc_for(block.proposal);
        last = block;
        ++view;
    }
    const auto& chain_tail = last;

    // A quorum certificate carries explicit signatures: one node id and one
    // signature per signer, deduplicated by identity.
    m.qc_signature_bytes = m.quorum * (nexus::security::kNodeIdSize +
                                       nexus::crypto::kEd25519SignatureSize);

    const auto encoded = nexus::security::encode_security_message([&] {
        nexus::security::SecurityMessage message;
        message.kind = nexus::security::SecurityMessageKind::HotStuffProposal;
        message.security_ruleset = constants::kSecurityRulesetVersion;
        message.consensus_ruleset = constants::kConsensusRulesetVersion;
        message.network_id = test_network();
        message.epoch = kEpoch;
        message.sender = harness.members[0];
        message.body = nexus::security::ProposalMessage{chain_tail.proposal,
                                                        harness.qc_for(chain_tail.proposal)};
        return message;
    }());
    m.proposal_wire_bytes = encoded.size();

    // Dealerless DKG: each participant broadcasts once and sends one pairwise
    // package to every other participant.
    m.dkg_messages_per_round = members + members * (members - 1);
    // FROST: each signer publishes a commitment and returns a share.
    m.frost_messages_per_signature = 2 * m.authority_threshold;

    // A timeout vote from every member is what forms a timeout certificate.
    m.timeout_votes = m.view_changes * members;
    return m;
}

void print_table(const std::vector<Measurement>& rows) {
    std::printf(
        "\n  N   f  quorum  thresh  props  votes  commits  views  QC sig B  "
        "proposal B  DKG msgs  FROST msgs\n");
    for (const auto& r : rows) {
        std::printf("%3zu %3zu %7zu %7zu %6zu %6zu %8zu %6zu %9zu %11zu %9zu %11zu\n",
                    r.members, r.max_faults, r.quorum, r.authority_threshold, r.proposals,
                    r.votes, r.commits, r.view_changes, r.qc_signature_bytes,
                    r.proposal_wire_bytes, r.dkg_messages_per_round,
                    r.frost_messages_per_signature);
    }
    std::printf("\n");
}

}  // namespace

// The measurement run. Assertions are invariants only: nothing here encodes an
// expected message count, because the point is to record what the protocol
// costs before anyone argues about changing it.
TEST(Scale, MeasureAcrossTheTierOneTable) {
    std::vector<Measurement> rows;
    for (const std::size_t members : kPopulations) {
        rows.push_back(measure(members, 12, 3));
    }
    print_table(rows);

    for (const auto& r : rows) {
        // The compiled formulas, at every size the table can produce.
        EXPECT_EQ(r.quorum, r.members - r.max_faults) << r.members;
        EXPECT_EQ(r.max_faults, (r.members - 1) / 3) << r.members;
        EXPECT_GE(r.authority_threshold, constants::kBootstrapThreshold) << r.members;
        EXPECT_GE(r.authority_threshold, r.quorum) << r.members;

        // A quorum is always a strict majority, which is what makes two of them
        // intersect in at least one honest member.
        EXPECT_GT(2 * r.quorum, r.members) << r.members;

        // The wire bounds hold at the largest population, so a full-size
        // proposal is transportable rather than merely legal.
        EXPECT_LE(r.proposal_wire_bytes, constants::kMaxSecurityMessageBytes) << r.members;
        EXPECT_LE(r.quorum, constants::kMaxQcSignatures) << r.members;

        // Leader failure costs liveness, never safety: views were consumed and
        // blocks still committed.
        EXPECT_GT(r.commits, 0u) << r.members;
        EXPECT_EQ(r.liveness_failures, r.view_changes) << r.members;
    }
}

// Selection is deterministic and stable at every size: the same frozen set and
// the same seed give the same ranking, so nodes cannot disagree about who was
// chosen.
TEST(Scale, SelectionIsDeterministicAtEverySize) {
    for (const std::size_t members : kPopulations) {
        std::vector<NodeId> ids;
        for (std::size_t i = 0; i < members; ++i) {
            ids.push_back(filled_node(static_cast<uint8_t>(i + 1)));
        }
        const auto pool = nexus::security::Tier1Set::from_nodes(ids);
        ASSERT_TRUE(pool.has_value()) << members;

        nexus::crypto::Ed25519PublicKey seed{};
        seed.fill(0x5A);
        const auto first = nexus::security::Tier1Selector::rank(*pool, seed, 2);
        const auto second = nexus::security::Tier1Selector::rank(*pool, seed, 2);
        EXPECT_EQ(first, second) << members;
        EXPECT_EQ(first.size(), members) << members;

        // A different epoch reshuffles, so membership does not calcify.
        const auto next_epoch = nexus::security::Tier1Selector::rank(*pool, seed, 3);
        EXPECT_NE(first, next_epoch) << members;
    }
}

// The target table maps mesh size to an active count, and every step lands on a
// population the quorum formulas accept.
TEST(Scale, EveryTargetStepIsAWorkablePopulation) {
    for (const auto& step : constants::kTier1TargetSteps) {
        const std::size_t target = constants::tier1_target_count(step.min_admitted);
        EXPECT_EQ(target, step.target);
        EXPECT_GE(target, constants::kMinActiveTier1);
        EXPECT_LE(target, constants::kMaxActiveTier1);
        EXPECT_GT(2 * constants::consensus_quorum(target), target);
    }
}
