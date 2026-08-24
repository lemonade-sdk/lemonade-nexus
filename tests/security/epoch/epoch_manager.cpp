#include <LemonadeNexus/Security/Epoch/EpochManager.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>

#include <algorithm>

using nexus::security::AttestationFailure;
using nexus::security::AttestationVerdict;
using nexus::security::Digest;
using nexus::security::EpochManager;
using nexus::security::EpochState;
using nexus::security::EpochTransitionFailure;
using nexus::security::EpochTransitionPhase;
using nexus::security::make_epoch_state;
using nexus::security::NetworkId;
using nexus::security::NodeId;
using nexus::security::Tier1Set;

namespace constants = nexus::security::constants;

namespace {

NodeId node(uint8_t byte) {
    NodeId id;
    id.bytes.fill(byte);
    return id;
}

nexus::crypto::Ed25519PublicKey key(uint8_t byte) {
    nexus::crypto::Ed25519PublicKey value{};
    value.fill(byte);
    return value;
}

AttestationVerdict passing(const NodeId& id, nexus::security::EpochId epoch) {
    AttestationVerdict verdict;
    verdict.node_id = id;
    verdict.epoch = epoch;
    verdict.passed = true;
    verdict.evidence_digest.fill(id.bytes[0]);
    return verdict;
}

AttestationVerdict failing(const NodeId& id, nexus::security::EpochId epoch) {
    AttestationVerdict verdict;
    verdict.node_id = id;
    verdict.epoch = epoch;
    verdict.passed = false;
    verdict.failure = AttestationFailure::SnpInvalid;
    return verdict;
}

struct EpochManagerFixture : ::testing::Test {
    void SetUp() override {
        network.fill(0x0F);
        std::vector<NodeId> founders;
        for (uint8_t i = 1; i <= 5; ++i) {
            founders.push_back(node(i));
        }
        Digest root;
        root.fill(0x01);
        EpochState initial = make_epoch_state(1, network, *Tier1Set::from_nodes(founders),
                                              key(0xA0), root);
        std::map<NodeId, nexus::crypto::Ed25519PublicKey> vote_keys;
        for (const auto& member : founders) {
            vote_keys[member] = key(member.bytes[0]);
        }
        manager.emplace(std::move(initial), std::move(vote_keys));

        std::vector<NodeId> pool;
        for (uint8_t i = 1; i <= 7; ++i) {
            pool.push_back(node(i));
        }
        eligible.emplace(*Tier1Set::from_nodes(pool));
    }

    void drive_to_phase(EpochTransitionPhase target) {
        ASSERT_TRUE(manager->prepare_next_epoch(*eligible, 6));
        if (target == EpochTransitionPhase::Attesting) return;
        for (const auto& member : manager->transition()->selected_members) {
            ASSERT_TRUE(manager->record_final_attestation(passing(member, 2)));
        }
        if (target == EpochTransitionPhase::GeneratingVoteKeys) return;
        for (const auto& member : manager->transition()->selected_members) {
            ASSERT_TRUE(manager->record_vote_key(member, key(0x80 + member.bytes[0])));
        }
        if (target == EpochTransitionPhase::GeneratingAuthorityKey) return;
        Digest transcript;
        transcript.fill(0x77);
        ASSERT_TRUE(manager->record_dkg_result(key(0xB1), transcript));
    }

    NetworkId network{};
    std::optional<EpochManager> manager;
    std::optional<Tier1Set> eligible;
};

TEST_F(EpochManagerFixture, HappyPathThroughActivation) {
    drive_to_phase(EpochTransitionPhase::Ready);
    ASSERT_EQ(manager->transition()->phase, EpochTransitionPhase::Ready);
    EXPECT_EQ(manager->transition()->selected_members.size(), 5u);
    EXPECT_EQ(manager->transition()->next_consensus_quorum, 4u);
    EXPECT_EQ(manager->transition()->next_authority_threshold, 5u);
    EXPECT_FALSE(manager->target_shortfall());
    EXPECT_FALSE(manager->reserve_shortfall());

    // No activation without the finalized handoff authorization.
    EXPECT_FALSE(manager->activate_next_epoch().has_value());

    Digest certificate;
    certificate.fill(0x99);
    ASSERT_TRUE(manager->record_handoff_authorization(certificate));

    const auto next = manager->activate_next_epoch();
    ASSERT_TRUE(next.has_value());
    EXPECT_EQ(next->id, 2u);
    EXPECT_EQ(next->authority_public_key, key(0xB1));
    EXPECT_EQ(next->tier1_members.digest(), next->participant_set_digest);
    EXPECT_EQ(manager->current().id, 2u);
    EXPECT_EQ(manager->current_vote_keys().size(), 5u);
    EXPECT_EQ(manager->transition(), nullptr);
    EXPECT_FALSE(manager->activate_next_epoch().has_value());
}

TEST_F(EpochManagerFixture, FailedFinalAttestationPullsNextRankedCandidate) {
    drive_to_phase(EpochTransitionPhase::Attesting);
    const auto original = manager->transition()->selected_members;
    const NodeId failed = original.front();

    ASSERT_TRUE(manager->record_final_attestation(failing(failed, 2)));
    const auto& replaced = manager->transition()->selected_members;
    ASSERT_EQ(replaced.size(), 5u);
    EXPECT_EQ(std::find(replaced.begin(), replaced.end(), failed), replaced.end());
    EXPECT_EQ(manager->transition()->phase, EpochTransitionPhase::Attesting);

    // The removed member cannot re-enter through a later passing verdict.
    EXPECT_FALSE(manager->record_final_attestation(passing(failed, 2)));
}

TEST_F(EpochManagerFixture, SilentDkgParticipantReplacementRestartsDkg) {
    drive_to_phase(EpochTransitionPhase::Ready);
    const NodeId silent = manager->transition()->selected_members.front();

    ASSERT_TRUE(manager->replace_participant(silent, EpochTransitionFailure::HandoffTimeout));
    constexpr nexus::crypto::Ed25519PublicKey kZero{};
    EXPECT_EQ(manager->transition()->next_authority_key, kZero);
    EXPECT_EQ(manager->transition()->phase, EpochTransitionPhase::Attesting);
    EXPECT_FALSE(manager->activate_next_epoch().has_value());
}

TEST_F(EpochManagerFixture, ExhaustedReplacementsBelowMinimumAborts) {
    std::vector<NodeId> tight_pool;
    for (uint8_t i = 1; i <= 5; ++i) {
        tight_pool.push_back(node(i));
    }
    const auto tight = Tier1Set::from_nodes(tight_pool);
    ASSERT_TRUE(manager->prepare_next_epoch(*tight, 6));
    const NodeId failed = manager->transition()->selected_members.front();

    ASSERT_TRUE(manager->record_final_attestation(failing(failed, 2)));
    EXPECT_EQ(manager->transition()->phase, EpochTransitionPhase::Aborted);
    EXPECT_EQ(manager->transition()->failure,
              EpochTransitionFailure::EligiblePoolBelowMinimum);

    // The old epoch stays authoritative, and a new prepare may start over.
    EXPECT_EQ(manager->current().id, 1u);
    EXPECT_TRUE(manager->prepare_next_epoch(*eligible, 6));
}

TEST_F(EpochManagerFixture, GuardsRefuseOutOfOrderInput) {
    // Nothing is recordable before prepare.
    EXPECT_FALSE(manager->record_final_attestation(passing(node(1), 1)));
    EXPECT_FALSE(manager->record_vote_key(node(1), key(0x81)));
    EXPECT_FALSE(manager->record_dkg_result(key(0xB1), Digest{}));

    drive_to_phase(EpochTransitionPhase::Attesting);
    EXPECT_FALSE(manager->prepare_next_epoch(*eligible, 6));

    // Wrong challenge epoch, unknown node, zero inputs.
    const NodeId member = manager->transition()->selected_members.front();
    EXPECT_FALSE(manager->record_final_attestation(passing(member, 1)));
    EXPECT_FALSE(manager->record_final_attestation(passing(node(0xEE), 2)));
    EXPECT_FALSE(manager->record_vote_key(member, nexus::crypto::Ed25519PublicKey{}));

    // DKG result only lands in its phase, and only with real values.
    EXPECT_FALSE(manager->record_dkg_result(key(0xB1), Digest{}));
}

TEST_F(EpochManagerFixture, VoteKeyRulesHold) {
    drive_to_phase(EpochTransitionPhase::GeneratingVoteKeys);
    const NodeId member = manager->transition()->selected_members.front();

    ASSERT_TRUE(manager->record_vote_key(member, key(0x81)));
    EXPECT_TRUE(manager->record_vote_key(member, key(0x81)));
    EXPECT_FALSE(manager->record_vote_key(member, key(0x82)));
}

TEST_F(EpochManagerFixture, DkgResultRequiresItsPhaseAndRealValues) {
    drive_to_phase(EpochTransitionPhase::GeneratingAuthorityKey);
    Digest transcript;
    transcript.fill(0x77);
    EXPECT_FALSE(manager->record_dkg_result(nexus::crypto::Ed25519PublicKey{}, transcript));
    EXPECT_FALSE(manager->record_dkg_result(key(0xB1), Digest{}));
    ASSERT_TRUE(manager->record_dkg_result(key(0xB1), transcript));
    EXPECT_EQ(manager->transition()->phase, EpochTransitionPhase::Ready);

    // A second DKG result cannot overwrite a Ready transition.
    EXPECT_FALSE(manager->record_dkg_result(key(0xB2), transcript));
}

TEST_F(EpochManagerFixture, AuthorizationRequiresReadyAndRealDigest) {
    drive_to_phase(EpochTransitionPhase::GeneratingAuthorityKey);
    Digest certificate;
    certificate.fill(0x99);
    EXPECT_FALSE(manager->record_handoff_authorization(certificate));

    Digest transcript;
    transcript.fill(0x77);
    ASSERT_TRUE(manager->record_dkg_result(key(0xB1), transcript));
    EXPECT_FALSE(manager->record_handoff_authorization(Digest{}));
    EXPECT_TRUE(manager->record_handoff_authorization(certificate));
}

TEST_F(EpochManagerFixture, PreQuorumPoolRefusesTransition) {
    std::vector<NodeId> tiny;
    for (uint8_t i = 1; i <= 4; ++i) {
        tiny.push_back(node(i));
    }
    EXPECT_FALSE(manager->prepare_next_epoch(*Tier1Set::from_nodes(tiny), 6));
    EXPECT_EQ(manager->transition(), nullptr);
}

TEST_F(EpochManagerFixture, ShortfallsAreRecordedNotRepaired) {
    // Admitted 30 wants 10; only 7 eligible: the target shrinks, the quorum
    // math uses the real selected count, and both shortfalls are recorded.
    ASSERT_TRUE(manager->prepare_next_epoch(*eligible, 30));
    EXPECT_EQ(manager->transition()->selected_members.size(), 7u);
    EXPECT_EQ(manager->transition()->next_consensus_quorum, 5u);
    EXPECT_EQ(manager->transition()->next_authority_threshold, 5u);
    EXPECT_TRUE(manager->target_shortfall());
    EXPECT_TRUE(manager->reserve_shortfall());
}

}  // namespace
