// The live eligibility path, end to end on the driver mesh.
//
// Every test here asks the same question from a different angle: what does it
// take to become eligible for the next epoch, and what cannot produce it. The
// answers all reduce to one rule — a pool is released only when a quorum
// finalized the eligibility state and this node's own recomputation still
// reproduces it.

#include "support/lifecycle_mesh.hpp"

namespace lifecycle_test {
namespace {

struct EligibilityPath : DriverMesh {};

// A node that verifies every peer itself is still one observer. Its statements
// are published and counted, and they never reach the quorum alone, so nothing
// becomes eligible and no epoch rotates.
TEST_F(EligibilityPath, LocalAttestationAloneCannotCreateEligibility) {
    bootstrap();
    run_until_committed(2);

    Node* lone = founders[0];
    for (uint8_t round = 1; round <= constants::kMinContinuityObservations; ++round) {
        for (Node* member : founders) {
            if (member == lone) continue;
            lone->driver->on_attestation_verdict(
                eligibility_verdict(network, member->id, 1, round),
                evidence_for(member->id, *member->driver->vote_key_for_epoch(1)));
        }
        mesh.pump();
        step(4);
    }

    // One observer's word is recorded and counts for exactly one.
    for (Node* member : founders) {
        if (member == lone) continue;
        const auto evidence = eligibility_of(*lone).ledger().evaluate(
            member->id, 1, eligibility_of(*lone).context());
        EXPECT_EQ(evidence.continuity_observers, 1u);
        EXPECT_LT(evidence.continuity_observers, evidence.quorum_required);
        EXPECT_FALSE(evidence.uptime_valid);
        EXPECT_FALSE(eligible_in(*lone, member->id, 2));
    }

    // The epoch ages out and nothing rotates. The mesh may well agree on this
    // state and finalize it — what it finalizes is that nobody qualifies.
    mesh.now_ms += constants::kTargetEpochSeconds * 1000;
    step(40);
    for (Node* founder : founders) {
        EXPECT_TRUE(eligible_nodes(eligibility_of(*founder).compute_state(2)).empty());
        const auto pool = eligibility_of(*founder).frozen_pool(2);
        EXPECT_TRUE(!pool.has_value() || pool->size() == 0);
        EXPECT_EQ(founder->runtime->epochs()->transition(), nullptr);
        EXPECT_EQ(founder->driver->current_epoch(), 1u);
    }
}

// The positive control. A quorum of observers makes the facts, HotStuff
// finalizes the state they agree on, and the frozen pool comes out of that
// state rather than out of any node's own view.
TEST_F(EligibilityPath, QuorumObservationsCreateAFinalizedPool) {
    bootstrap();
    run_until_committed(1);
    prepare_handoff();

    const Digest agreed = commitment_of(*founders[0], 2);
    for (Node* founder : founders) {
        // Every honest node computed the same state...
        EXPECT_EQ(commitment_of(*founder, 2), agreed);

        // ...consensus finalized exactly that state...
        const auto* finalized = eligibility_of(*founder).finalized();
        ASSERT_NE(finalized, nullptr);
        EXPECT_EQ(finalized->commitment, agreed);
        EXPECT_EQ(finalized->next_epoch, 2u);
        EXPECT_NE(finalized->consensus_reference, Digest{});

        // ...and the pool the transition froze is the one that state named.
        const auto pool = eligibility_of(*founder).frozen_pool(2);
        ASSERT_TRUE(pool.has_value());
        EXPECT_EQ(pool->size(), kFounders);
        ASSERT_NE(founder->runtime->epochs()->transition(), nullptr);
        EXPECT_EQ(founder->runtime->epochs()->transition()->to_epoch, 2u);
    }

    // Both mesh facts came from the mesh, for every member.
    for (Node* subject : founders) {
        const auto evidence = eligibility_of(*founders[0]).ledger().evaluate(
            subject->id, 1, eligibility_of(*founders[0]).context());
        EXPECT_TRUE(evidence.uptime_valid) << "continuity";
        EXPECT_TRUE(evidence.mesh_health_valid) << "participation";
        EXPECT_GE(evidence.participation_observers, evidence.quorum_required);
    }
}

// Rolling a node's durable observations back to an earlier point inside the
// SAME epoch costs it availability and gives it nothing. Its recomputation no
// longer reproduces what the mesh finalized, so no pool is released and it
// cannot prepare a transition of its own.
TEST_F(EligibilityPath, SameEpochRollbackCannotRestoreAuthority) {
    bootstrap();
    run_until_committed(1);

    Node* victim = founders[0];
    const fs::path observations =
        victim->dir / "security" / "eligibility" / "observations-1.json";

    // A snapshot from one round in, when continuity was still short.
    reattest_round(1);
    step(6);
    ASSERT_TRUE(fs::exists(observations));
    const fs::path snapshot = root / "rolled-back.json";
    fs::copy_file(observations, snapshot, fs::copy_options::overwrite_existing);

    // The mesh goes on to finalize the complete state and freeze a pool.
    reattest_round(2);
    step(6);
    mesh.now_ms += constants::kTargetEpochSeconds * 1000;
    for (int i = 0; i < 120 && founders[1]->runtime->epochs()->transition() == nullptr; ++i) {
        step(1);
    }
    ASSERT_NE(founders[1]->runtime->epochs()->transition(), nullptr);
    const Digest finalized = commitment_of(*founders[1], 2);

    // Now the rollback, and a restart on top of it.
    fs::copy_file(snapshot, observations, fs::copy_options::overwrite_existing);
    restart_node(*victim);
    victim->driver->start(mesh.now_ms);
    mesh.pump();
    step(10);

    // The old file restored old observations, so the state it recomputes is a
    // state the mesh has left behind.
    EXPECT_NE(commitment_of(*victim, 2), finalized);
    // Nothing was finalized for it, and nothing is released.
    EXPECT_EQ(eligibility_of(*victim).finalized(), nullptr);
    EXPECT_FALSE(eligibility_of(*victim).frozen_pool(2).has_value());
    EXPECT_EQ(victim->runtime->epochs()->transition(), nullptr);

    // The honest members are untouched by any of it.
    EXPECT_TRUE(eligibility_of(*founders[1]).frozen_pool(2).has_value());
    EXPECT_EQ(founders[1]->runtime->epochs()->current().tier1_members.size(), kFounders);
}

// The same restart WITHOUT a rollback is the control: durable observations come
// back, the node syncs, and it reaches the same finalized state as everyone
// else. A restart costs finality, not history.
TEST_F(EligibilityPath, RestartBeforeSelectionRequiresSyncThenRecovers) {
    bootstrap();
    run_until_committed(1);
    reattest_round(1);
    step(6);
    reattest_round(2);
    step(6);

    Node* victim = founders[0];
    const Digest before = commitment_of(*victim, 2);
    ASSERT_NE(eligibility_of(*victim).ledger().size(), 0u);

    restart_node(*victim);
    victim->driver->start(mesh.now_ms);

    // Voting is blocked until a certified floor arrives, and no finality came
    // back off the disk.
    EXPECT_EQ(victim->driver->phase(), DriverPhase::Syncing);
    EXPECT_EQ(eligibility_of(*victim).finalized(), nullptr);
    EXPECT_FALSE(eligibility_of(*victim).frozen_pool(2).has_value());
    // The observations did come back, so the state is the one it had.
    EXPECT_EQ(commitment_of(*victim, 2), before);

    mesh.pump();
    ASSERT_EQ(victim->driver->phase(), DriverPhase::Active);

    // Past the boundary it finalizes with the quorum and gets its pool back.
    mesh.now_ms += constants::kTargetEpochSeconds * 1000;
    for (int i = 0; i < 120 && eligibility_of(*victim).finalized() == nullptr; ++i) {
        step(1);
    }
    ASSERT_NE(eligibility_of(*victim).finalized(), nullptr);
    EXPECT_TRUE(eligibility_of(*victim).frozen_pool(2).has_value());
}

// Two identity-signed bundles naming different incarnations inside one frozen
// epoch is proved misbehavior. Every observer records it independently, the
// finalized state carries it, and the subject is out of the next epoch — while
// the current epoch does not move at all.
TEST_F(EligibilityPath, ObjectiveFaultRemovesNextEpochEligibility) {
    bootstrap();
    run_until_committed(1);
    reattest_round(1);
    step(6);
    reattest_round(2);
    step(6);

    Node* faulted = founders[2];
    const auto before = founders[0]->runtime->epochs()->current();
    for (Node* founder : founders) {
        EXPECT_TRUE(eligible_in(*founder, faulted->id, 2));
    }

    // The subject presents a second incarnation inside the frozen epoch.
    reattest_one(*faulted, 3, 2);
    step(4);

    for (Node* founder : founders) {
        if (founder == faulted) continue;
        const auto& faults = eligibility_of(*founder).ledger().faults();
        const auto entry = faults.find(faulted->id);
        ASSERT_NE(entry, faults.end());
        EXPECT_TRUE(entry->second.contains(ObjectiveFault::DuplicateIncarnation));
        EXPECT_FALSE(eligible_in(*founder, faulted->id, 2));

        // The fault is inside the state consensus commits, not beside it.
        const auto state = eligibility_of(*founder).compute_state(2);
        const auto record = std::find_if(
            state.records.begin(), state.records.end(),
            [&](const EligibilityRecord& r) { return r.subject == faulted->id; });
        ASSERT_NE(record, state.records.end());
        EXPECT_EQ(record->faults, objective_fault_bit(ObjectiveFault::DuplicateIncarnation));
        EXPECT_FALSE(record->mesh_health_valid);
    }

    // The current epoch is frozen: a member that fails now affects the next
    // epoch and nothing about this one.
    for (Node* founder : founders) {
        const auto& current = founder->runtime->epochs()->current();
        EXPECT_EQ(current.tier1_members.size(), before.tier1_members.size());
        EXPECT_TRUE(current.tier1_members.contains(faulted->id));
        EXPECT_EQ(current.consensus_quorum, before.consensus_quorum);
        EXPECT_EQ(current.authority_threshold, before.authority_threshold);
    }

    // And the shrunken pool cannot activate: four is below the compiled
    // minimum, so the epoch holds rather than rotating into an unsafe size.
    mesh.now_ms += constants::kTargetEpochSeconds * 1000;
    step(40);
    for (Node* founder : founders) {
        const auto pool = eligibility_of(*founder).frozen_pool(2);
        if (pool.has_value()) {
            EXPECT_EQ(pool->size(), kFounders - 1);
            EXPECT_FALSE(pool->contains(faulted->id));
        }
        EXPECT_EQ(founder->runtime->epochs()->transition(), nullptr);
        EXPECT_EQ(founder->driver->current_epoch(), 1u);
    }
}

// Deleting the local evidence file changes what one node believes and nothing
// about what the mesh finalized. The node's own view no longer carries the
// fault, and that view has no authority: it can no longer match the quorum, so
// it releases nothing.
TEST_F(EligibilityPath, LocalDeletionOfFaultStateDoesNotRestoreEligibility) {
    bootstrap();
    run_until_committed(1);
    reattest_round(1);
    step(6);
    reattest_round(2);
    step(6);

    Node* faulted = founders[2];
    reattest_one(*faulted, 3, 2);
    step(4);

    Node* victim = founders[0];
    const Digest honest = commitment_of(*founders[1], 2);
    ASSERT_EQ(commitment_of(*victim, 2), honest);

    const fs::path faults = victim->dir / "security" / "eligibility" / "faults.json";
    ASSERT_TRUE(fs::exists(faults));
    fs::remove(faults);
    restart_node(*victim);
    victim->driver->start(mesh.now_ms);
    mesh.pump();
    step(6);

    // Its own view forgot the fault...
    EXPECT_TRUE(eligibility_of(*victim).ledger().faults().find(faulted->id) ==
                eligibility_of(*victim).ledger().faults().end());
    // ...and that is exactly why it now agrees with nobody. The honest members
    // still hold the fault, so the state this node computes cannot be
    // finalized and nothing is released.
    EXPECT_NE(commitment_of(*victim, 2), commitment_of(*founders[1], 2));
    EXPECT_FALSE(eligibility_of(*victim).frozen_pool(2).has_value());
    EXPECT_FALSE(eligible_in(*founders[1], faulted->id, 2));
    EXPECT_FALSE(eligible_in(*founders[3], faulted->id, 2));
}

// Nodes that have not converged on the same facts simply do not finalize.
// Disagreement costs a rotation, never safety: no pool, no transition, and the
// current epoch keeps running until they agree.
TEST_F(EligibilityPath, DisagreementBeforeConsensusIsSafe) {
    bootstrap();
    run_until_committed(1);

    // Two nodes see a peer's transport certificate differently, and differently
    // from each other, so no view of the facts has a quorum behind it.
    mesh.uncertified_for[founders[0]->id].insert(founders[3]->id);
    mesh.uncertified_for[founders[1]->id].insert(founders[4]->id);
    reattest_round(1);
    step(6);
    reattest_round(2);
    step(6);
    EXPECT_NE(commitment_of(*founders[0], 2), commitment_of(*founders[2], 2));
    EXPECT_NE(commitment_of(*founders[1], 2), commitment_of(*founders[2], 2));
    EXPECT_NE(commitment_of(*founders[0], 2), commitment_of(*founders[1], 2));

    mesh.now_ms += constants::kTargetEpochSeconds * 1000;
    step(40);
    for (Node* founder : founders) {
        EXPECT_EQ(eligibility_of(*founder).finalized(), nullptr);
        EXPECT_EQ(founder->runtime->epochs()->transition(), nullptr);
        EXPECT_EQ(founder->driver->current_epoch(), 1u);
        EXPECT_EQ(founder->runtime->epochs()->current().tier1_members.size(), kFounders);
    }

    // Once the disagreement clears they converge and the boundary completes.
    // The pacemaker backed off while nothing could commit, so recovery takes a
    // few view timeouts.
    mesh.uncertified_for.clear();
    EXPECT_EQ(commitment_of(*founders[0], 2), commitment_of(*founders[2], 2));
    for (int i = 0; i < 600; ++i) {
        step(1);
        const bool prepared = std::all_of(founders.begin(), founders.end(), [](Node* f) {
            return f->runtime->epochs()->transition() != nullptr;
        });
        if (prepared) break;
    }
    for (Node* founder : founders) {
        ASSERT_NE(founder->runtime->epochs()->transition(), nullptr);
        EXPECT_NE(eligibility_of(*founder).finalized(), nullptr);
    }
}

// A quorum is a quorum. One node holding different facts does not stop the
// mesh, and it does not get to act on its own view either: the finalized state
// is the one four members agreed on, and the dissenter releases nothing.
TEST_F(EligibilityPath, AMinorityViewNeverBecomesTheMeshView) {
    bootstrap();
    run_until_committed(1);

    Node* dissenter = founders[0];
    mesh.uncertified_for[dissenter->id].insert(founders[3]->id);
    prepare_handoff();

    const Digest quorum_view = commitment_of(*founders[2], 2);
    EXPECT_NE(commitment_of(*dissenter, 2), quorum_view);

    for (Node* founder : founders) {
        if (founder == dissenter) continue;
        const auto* finalized = eligibility_of(*founder).finalized();
        ASSERT_NE(finalized, nullptr);
        EXPECT_EQ(finalized->commitment, quorum_view);
        ASSERT_TRUE(eligibility_of(*founder).frozen_pool(2).has_value());
        EXPECT_NE(founder->runtime->epochs()->transition(), nullptr);
    }
    EXPECT_EQ(eligibility_of(*dissenter).finalized(), nullptr);
    EXPECT_FALSE(eligibility_of(*dissenter).frozen_pool(2).has_value());
    EXPECT_EQ(dissenter->runtime->epochs()->transition(), nullptr);
}

// Once a transition freezes the next set, later observations change nothing
// about it. Health that arrives after the freeze is next-epoch information.
TEST_F(EligibilityPath, HealthAfterTheFreezeWaitsForTheNextEpoch) {
    bootstrap();
    run_until_committed(1);
    prepare_handoff();

    Node* founder = founders[0];
    ASSERT_NE(founder->runtime->epochs()->transition(), nullptr);
    const auto frozen = founder->runtime->epochs()->transition()->selected_members;
    const Digest participant_set = founder->runtime->epochs()->transition()->participant_set_digest;

    // More observations arrive, including a fault that would have excluded a
    // member had it landed before the freeze.
    reattest_round(3);
    step(4);
    reattest_one(*founders[2], 4, 2);
    step(4);

    EXPECT_EQ(founder->runtime->epochs()->transition()->selected_members, frozen);
    EXPECT_EQ(founder->runtime->epochs()->transition()->participant_set_digest, participant_set);
    EXPECT_EQ(founder->driver->current_epoch(), 1u);
    EXPECT_EQ(founder->runtime->epochs()->current().tier1_members.size(), kFounders);
    EXPECT_EQ(founder->runtime->epochs()->current().consensus_quorum,
              constants::consensus_quorum(kFounders));
}

// The activated epoch's numbers are fixed at activation. A member that stops
// attesting, stops participating, or is proved at fault reduces liveness and
// changes no threshold.
TEST_F(EligibilityPath, EpochFreezeSurvivesEveryKindOfMemberFailure) {
    bootstrap();
    run_until_committed(2);

    const auto before = founders[0]->runtime->epochs()->current();
    EXPECT_EQ(before.consensus_quorum, constants::consensus_quorum(kFounders));
    EXPECT_EQ(before.authority_threshold, constants::authority_threshold(kFounders));

    // One member goes silent: no verdicts about it, no observations from it.
    Node* silent = founders[4];
    for (uint8_t round = 1; round <= constants::kMinContinuityObservations; ++round) {
        for (Node* observer : founders) {
            if (observer == silent) continue;
            for (Node* member : founders) {
                if (member == observer || member == silent) continue;
                observer->driver->on_attestation_verdict(
                    eligibility_verdict(network, member->id, 1, round),
                    evidence_for(member->id, *member->driver->vote_key_for_epoch(1)));
            }
        }
        mesh.pump();
        step(6);
    }
    reattest_one(*founders[1], 5, 2);  // and one member is proved at fault
    step(6);

    for (Node* founder : founders) {
        const auto& current = founder->runtime->epochs()->current();
        EXPECT_EQ(current.id, 1u);
        EXPECT_EQ(current.tier1_members.size(), before.tier1_members.size());
        EXPECT_EQ(current.consensus_quorum, before.consensus_quorum);
        EXPECT_EQ(current.authority_threshold, before.authority_threshold);
        EXPECT_TRUE(current.tier1_members.contains(silent->id));
        EXPECT_TRUE(current.tier1_members.contains(founders[1]->id));
    }
    // The chain keeps committing under the unchanged quorum.
    const Height height = founders[0]->driver->last_committed_height();
    run_until_committed(height + 1);
}

// Genesis names who it verified; the founders decide who qualifies. All five
// must sign the same founding eligibility transcript, and the bootstrap
// certificate carries it.
TEST_F(EligibilityPath, GenesisBindsTheFoundingEligibilityTranscript) {
    bootstrap();

    const auto stored = founders[0]->store->load_bootstrap();
    ASSERT_TRUE(std::holds_alternative<BootstrapCertificate>(stored));
    const auto certificate = std::get<BootstrapCertificate>(stored);
    EXPECT_NE(certificate.founding_eligibility_digest, Digest{});

    // Genesis could only copy what the founders agreed on.
    const auto agreed = genesis_node->genesis->founding_eligibility_digest();
    ASSERT_TRUE(agreed.has_value());
    EXPECT_EQ(certificate.founding_eligibility_digest, *agreed);

    // Every founder adopted the same certificate.
    for (Node* founder : founders) {
        const auto theirs = founder->store->load_bootstrap();
        ASSERT_TRUE(std::holds_alternative<BootstrapCertificate>(theirs));
        EXPECT_EQ(std::get<BootstrapCertificate>(theirs).founding_eligibility_digest, *agreed);
    }
}

// One founder that arrives at different founding facts stops the bootstrap.
// The threshold is five and it does not bend to reach agreement.
TEST_F(EligibilityPath, GenesisRefusesAFoundingSetThatDoesNotAgree) {
    // One founder sees another's transport certificate differently, so the
    // founding state it computes is not the one the others compute.
    collect_founding();
    mesh.uncertified_for[founders[0]->id].insert(founders[1]->id);
    run_founding_eligibility();

    for (Node* founder : founders) {
        EXPECT_EQ(founder->driver->phase(), DriverPhase::GenesisEligibility);
        EXPECT_EQ(founder->runtime->epochs(), nullptr);
        EXPECT_TRUE(std::holds_alternative<EpochLoadResult>(founder->store->load_bootstrap()));
    }
    EXPECT_FALSE(genesis_node->genesis->eligibility_agreed());
    EXPECT_FALSE(genesis_node->genesis->finalized());
    EXPECT_FALSE(genesis_node->genesis->founding_eligibility_digest().has_value());
}

}  // namespace
}  // namespace lifecycle_test
