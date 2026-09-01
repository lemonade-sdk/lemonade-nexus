// The happy paths of the lifecycle driver over the wire: Genesis to Epoch 1,
// tick-paced finality, the timed handoff, restart sync, and corrupt state.
//
// eligibility_path.cpp drives the same mesh through the live eligibility rules.

#include "support/lifecycle_mesh.hpp"

namespace lifecycle_test {
namespace {

TEST_F(DriverMesh, GenesisToEpochOneOverTheWire) {
    bootstrap();

    // The bootstrap certificate is durable on every founder and on Genesis.
    for (Node* founder : founders) {
        EXPECT_TRUE(std::holds_alternative<BootstrapCertificate>(
            founder->store->load_bootstrap()));
        EXPECT_TRUE(std::holds_alternative<StoredEpoch>(founder->store->load_epoch()));
        const auto history = founder->store->load_authority_history();
        ASSERT_TRUE(std::holds_alternative<std::vector<EpochAuthorityRecord>>(history));
        EXPECT_EQ(std::get<std::vector<EpochAuthorityRecord>>(history).size(), 1u);
    }
    EXPECT_TRUE(std::holds_alternative<BootstrapCertificate>(
        genesis_node->store->load_bootstrap()));

    // Every founder holds the same group key and a live share.
    const auto group = founders[0]->runtime->authority().group_public_key();
    ASSERT_TRUE(group.has_value());
    for (Node* founder : founders) {
        EXPECT_EQ(*founder->runtime->authority().group_public_key(), *group);
        EXPECT_EQ(*founder->runtime->authority().key_epoch(), 1u);
    }
}

TEST_F(DriverMesh, TickPacedConsensusCommits) {
    bootstrap();
    run_until_committed(3);
    for (Node* founder : founders) {
        EXPECT_GE(founder->driver->last_committed_height(), 3u);
    }
}

TEST_F(DriverMesh, TimedHandoffRotatesToEpochTwo) {
    bootstrap();
    run_until_committed(1);
    const auto epoch_one_group = *founders[0]->runtime->authority().group_public_key();

    // The mesh observes itself, the epoch ages past the compiled target, and
    // the finalized eligibility state releases the pool the transition freezes.
    prepare_handoff();
    for (Node* founder : founders) {
        ASSERT_NE(founder->runtime->epochs()->transition(), nullptr);
        ASSERT_EQ(founder->runtime->epochs()->transition()->to_epoch, 2u);
    }

    // Injected final verdicts for the target epoch, binding epoch-2 vote keys
    // and the committed plan's exact attestation context.
    for (Node* member : founders) {
        const auto vote_key = member->driver->vote_key_for_epoch(2);
        ASSERT_TRUE(vote_key.has_value());
        for (Node* founder : founders) {
            founder->driver->on_attestation_verdict(final_verdict(latest_plan(), member->id),
                                                    evidence_for(member->id, *vote_key));
        }
    }
    // The readiness set must commit before any DKG starts, so the ceremony is
    // tick-paced now: readiness commit -> DKG over the wire -> Ready.
    mesh.pump();
    for (int i = 0; i < 200; ++i) {
        step(1);
        const bool ready = std::all_of(founders.begin(), founders.end(), [](Node* f) {
            return f->runtime->epochs() != nullptr &&
                   f->runtime->epochs()->transition() != nullptr &&
                   f->runtime->epochs()->transition()->phase == EpochTransitionPhase::Ready;
        });
        if (ready) break;
    }
    for (Node* founder : founders) {
        ASSERT_NE(founder->runtime->epochs()->transition(), nullptr);
        EXPECT_EQ(founder->runtime->epochs()->transition()->phase, EpochTransitionPhase::Ready);
    }

    // The next committed block carries the handoff and activates Epoch 2.
    for (int step = 0; step < 200; ++step) {
        mesh.now_ms += 200;
        for (Node* founder : founders) founder->driver->tick(mesh.now_ms);
        mesh.pump();
        const bool rotated = std::all_of(founders.begin(), founders.end(), [](Node* f) {
            return f->driver->current_epoch() == 2u;
        });
        if (rotated) break;
    }
    for (Node* founder : founders) {
        ASSERT_EQ(founder->driver->current_epoch(), 2u);
        EXPECT_EQ(*founder->runtime->authority().key_epoch(), 2u);
        EXPECT_NE(*founder->runtime->authority().group_public_key(), epoch_one_group);
        ASSERT_NE(founder->runtime->consensus(), nullptr);
        EXPECT_TRUE(founder->runtime->consensus()->usable());
        const auto history = founder->store->load_authority_history();
        ASSERT_TRUE(std::holds_alternative<std::vector<EpochAuthorityRecord>>(history));
        EXPECT_EQ(std::get<std::vector<EpochAuthorityRecord>>(history).size(), 2u);
    }

    // Epoch 2 keeps committing under the new vote keys.
    const Height before = founders[0]->driver->last_committed_height();
    run_until_committed(before + 1);
}

TEST_F(DriverMesh, RestartSyncsToACertifiedFloorBeforeVoting) {
    bootstrap();
    run_until_committed(2);
    Node* victim = founders[0];
    const Height committed_before = victim->driver->last_committed_height();

    restart_node(*victim);
    victim->driver->start(mesh.now_ms);

    // The stored epoch and safety state came back; voting stays blocked
    // until quorum-certified state sets the view floor.
    ASSERT_EQ(victim->driver->phase(), DriverPhase::Syncing);
    ASSERT_NE(victim->runtime->consensus(), nullptr);
    EXPECT_TRUE(victim->runtime->consensus()->usable());
    EXPECT_FALSE(victim->runtime->consensus()->synced());
    EXPECT_EQ(victim->driver->current_epoch(), 1u);

    // The sync request went out during start; the answers carry validated
    // certificates and finish the sync.
    mesh.pump();
    EXPECT_EQ(victim->driver->phase(), DriverPhase::Active);
    EXPECT_TRUE(victim->runtime->consensus()->synced());

    // The mesh keeps committing with the restarted member voting again.
    run_until_committed(committed_before + 2);
    EXPECT_GE(victim->driver->last_committed_height(), committed_before + 2);
}

TEST_F(DriverMesh, CorruptEpochStateFailsClosed) {
    bootstrap();
    Node* victim = founders[0];
    restart_node(*victim);
    {
        std::ofstream out(victim->store->directory() / "epoch-current.json");
        out << "{corrupt";
    }
    victim->driver->start(mesh.now_ms);
    EXPECT_EQ(victim->driver->phase(), DriverPhase::Failed);
    EXPECT_EQ(victim->runtime->epochs(), nullptr);

    // A failed driver does nothing on tick and answers no protocol traffic.
    victim->driver->tick(mesh.now_ms + 1000);
    EXPECT_EQ(victim->driver->phase(), DriverPhase::Failed);
}

}  // namespace
}  // namespace lifecycle_test
