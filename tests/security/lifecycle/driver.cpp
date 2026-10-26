// The happy paths of the lifecycle driver over the wire: Genesis to Epoch 1,
// tick-paced finality, the timed handoff, restart sync, and corrupt state.
//
// eligibility_path.cpp drives the same mesh through the live eligibility rules.

#include "support/lifecycle_mesh.hpp"

#include <algorithm>
#include <map>

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

TEST_F(DriverMesh, RestartedGenesisConsumesASurvivingBootstrap) {
    bootstrap();
    const auto before = genesis_node->store->load_bootstrap();
    ASSERT_TRUE(std::holds_alternative<BootstrapCertificate>(before));
    ASSERT_FALSE(fs::exists(genesis_node->store->directory() / "epoch-current.json"));

    restart_node(*genesis_node);
    genesis_node->driver->start(mesh.now_ms);

    EXPECT_EQ(genesis_node->driver->phase(), DriverPhase::Idle);
    EXPECT_TRUE(genesis_node->genesis->finalized());
    EXPECT_FALSE(genesis_node->genesis->admit_candidate(founders[0]->id));
    const auto after = genesis_node->store->load_bootstrap();
    ASSERT_TRUE(std::holds_alternative<BootstrapCertificate>(after));
    EXPECT_EQ(bootstrap_certificate_signing_digest(std::get<BootstrapCertificate>(after)),
              bootstrap_certificate_signing_digest(std::get<BootstrapCertificate>(before)));
}

TEST_F(DriverMesh, TheFoundingCarriesTheReleaseApprovalCommitmentToEpochOne) {
    Digest release;
    release.fill(0x4C);
    for (auto& node : nodes) {
        node->release_approval_digest = release;
        restart_node(*node);
    }
    bootstrap();
    for (Node* founder : founders) {
        const auto stored = founder->store->load_bootstrap();
        ASSERT_TRUE(std::holds_alternative<BootstrapCertificate>(stored));
        EXPECT_EQ(std::get<BootstrapCertificate>(stored).release_approval_digest, release);
    }
}

TEST_F(DriverMesh, AFounderRunningADifferentReleaseRefusesTheFounding) {
    Digest release;
    release.fill(0x4C);
    for (auto& node : nodes) {
        node->release_approval_digest = release;
        restart_node(*node);
    }
    founders[1]->release_approval_digest.fill(0x4D);
    restart_node(*founders[1]);

    collect_founding();
    // The mismatched founder refused the founding outright; the agreeing
    // founders proceeded into the mutual round.
    EXPECT_EQ(founders[1]->driver->phase(), DriverPhase::Idle);
    EXPECT_EQ(founders[0]->driver->phase(), DriverPhase::GenesisEligibility);
}

// A superseding founding restarts the mutual round, and the restarted round's
// first challenges go out immediately: the superseded round's ask times must
// not rate-limit them for up to two cadence periods.
TEST_F(DriverMesh, ASupersedingFoundingChallengesEveryEdgeImmediately) {
    collect_founding();
    Node* founder = founders[0];
    ASSERT_EQ(founder->driver->phase(), DriverPhase::GenesisEligibility);
    ASSERT_TRUE(mesh.queue.empty());

    // What the anchor sends after re-collecting: the same members and vote
    // keys under a different attestation root (a founder re-attested).
    GenesisFounding superseding;
    superseding.epoch = 1;
    for (Node* member : founders) {
        superseding.members.emplace_back(member->id, *member->driver->vote_key_for_epoch(1));
    }
    superseding.attestation_root.fill(0x77);

    // No time passes, so the superseded round's challenges are still inside
    // the re-ask grace; only a round that cleared its ask times asks now.
    founder->driver->on_genesis_founding(superseding, genesis_node->id);
    EXPECT_EQ(founder->driver->phase(), DriverPhase::GenesisEligibility);
    std::size_t challenges = 0;
    for (const auto& item : mesh.queue) {
        const auto decoded = decode_security_message(item.bytes);
        if (!std::holds_alternative<SecurityMessage>(decoded)) {
            continue;
        }
        if (std::holds_alternative<AttestationChallenge>(
                std::get<SecurityMessage>(decoded).body)) {
            ++challenges;
        }
    }
    EXPECT_EQ(challenges, kFounders - 1);
}

TEST_F(DriverMesh, RestartUnderADifferentReleaseFailsClosed) {
    bootstrap();
    Node* founder = founders[0];
    founder->release_approval_digest.fill(0x4E);
    restart_node(*founder);
    founder->driver->start(mesh.now_ms);
    // The stored certificate commits the bootstrapped selection; a process
    // loading a different approval cannot recover Tier-1 authority under it.
    EXPECT_EQ(founder->driver->phase(), DriverPhase::Failed);
}

TEST_F(DriverMesh, MissingProofsForCachedAuthorityCannotRestartGenesis) {
    bootstrap();
    ASSERT_NE(founders[0]->driver->verified_authority(), nullptr);
    ASSERT_TRUE(
        genesis_node->store->store_authority_anchor(*founders[0]->driver->verified_authority()));
    ASSERT_TRUE(fs::remove(genesis_node->store->directory() / "bootstrap-certificate.json"));

    restart_node(*genesis_node);
    genesis_node->driver->start(mesh.now_ms);

    EXPECT_EQ(genesis_node->driver->phase(), DriverPhase::Idle);
    EXPECT_TRUE(genesis_node->genesis->finalized());
    EXPECT_EQ(genesis_node->driver->verified_authority(), nullptr);
    EXPECT_FALSE(genesis_node->genesis->admit_candidate(founders[0]->id));
}

TEST_F(DriverMesh, AuthenticatedChainBaseRestoresGenesisAuthorityState) {
    bootstrap();
    using ChainBase = std::vector<std::pair<NodeId, nexus::crypto::Ed25519PublicKey>>;
    const auto base = founders[0]->store->load_chain_base();
    ASSERT_TRUE(std::holds_alternative<ChainBase>(base));
    ASSERT_TRUE(genesis_node->store->store_chain_base(std::get<ChainBase>(base)));

    restart_node(*genesis_node);
    genesis_node->driver->start(mesh.now_ms);

    EXPECT_EQ(genesis_node->driver->phase(), DriverPhase::Idle);
    EXPECT_TRUE(genesis_node->genesis->finalized());
    ASSERT_NE(genesis_node->driver->verified_authority(), nullptr);
    EXPECT_EQ(genesis_node->driver->verified_authority()->epoch, 1u);
}

TEST_F(DriverMesh, RecomputedDigestCannotAuthenticateFabricatedHigherAuthority) {
    bootstrap();
    using ChainBase = std::vector<std::pair<NodeId, nexus::crypto::Ed25519PublicKey>>;
    const auto base = founders[0]->store->load_chain_base();
    ASSERT_TRUE(std::holds_alternative<ChainBase>(base));
    ASSERT_TRUE(genesis_node->store->store_chain_base(std::get<ChainBase>(base)));

    ASSERT_NE(founders[0]->driver->verified_authority(), nullptr);
    const auto genuine = *founders[0]->driver->verified_authority();
    auto fabricated = genuine;
    fabricated.epoch = 2;
    fabricated.key_generation = 2;
    fabricated.previous_anchor = genuine.anchor_digest;
    fabricated.anchor_digest.fill(0xA5);
    fabricated.checkpoint.fill(0x5A);
    fabricated.group_public_key[0] ^= 0x80;
    for (auto& [node, key] : fabricated.vote_keys) {
        key[0] ^= 0x40;
    }
    ASSERT_TRUE(genesis_node->store->store_authority_anchor(fabricated));

    restart_node(*genesis_node);
    genesis_node->driver->start(mesh.now_ms);

    ASSERT_NE(genesis_node->driver->verified_authority(), nullptr);
    EXPECT_EQ(genesis_node->driver->verified_authority()->epoch, 1u);
    EXPECT_EQ(verified_epoch_authority_digest(*genesis_node->driver->verified_authority()),
              verified_epoch_authority_digest(genuine));
    EXPECT_EQ(genesis_node->driver->phase(), DriverPhase::Idle);
    EXPECT_TRUE(genesis_node->genesis->finalized());
}

TEST_F(DriverMesh, RecomputedDigestCannotAuthenticateModifiedAuthorityKeys) {
    bootstrap();
    using ChainBase = std::vector<std::pair<NodeId, nexus::crypto::Ed25519PublicKey>>;
    const auto base = founders[0]->store->load_chain_base();
    ASSERT_TRUE(std::holds_alternative<ChainBase>(base));
    ASSERT_TRUE(genesis_node->store->store_chain_base(std::get<ChainBase>(base)));

    ASSERT_NE(founders[0]->driver->verified_authority(), nullptr);
    auto fabricated = *founders[0]->driver->verified_authority();
    fabricated.group_public_key[0] ^= 0x80;
    for (auto& [node, key] : fabricated.vote_keys) {
        key[0] ^= 0x40;
    }
    ASSERT_TRUE(genesis_node->store->store_authority_anchor(fabricated));

    restart_node(*genesis_node);
    genesis_node->driver->start(mesh.now_ms);

    EXPECT_EQ(genesis_node->driver->phase(), DriverPhase::Failed);
    EXPECT_EQ(genesis_node->driver->verified_authority(), nullptr);
    EXPECT_TRUE(genesis_node->genesis->finalized());
    EXPECT_FALSE(genesis_node->genesis->admit_candidate(founders[0]->id));
}

TEST_F(DriverMesh, AgreeingForgedAuthorityAndEpochFailAgainstProofChain) {
    bootstrap();
    Node& victim = *founders[0];
    ASSERT_NE(victim.driver->verified_authority(), nullptr);
    auto fabricated = *victim.driver->verified_authority();
    for (auto& [node, key] : fabricated.vote_keys) {
        key[0] ^= 0x40;
    }
    auto members = Tier1Set::from_nodes(fabricated.members);
    ASSERT_TRUE(members.has_value());
    StoredEpoch epoch{make_epoch_state(fabricated.epoch, fabricated.network_id,
                                       std::move(*members), fabricated.group_public_key,
                                       fabricated.attestation_root),
                      fabricated.vote_keys, fabricated.checkpoint};
    ASSERT_TRUE(victim.store->store_authority_anchor(fabricated));
    ASSERT_TRUE(victim.store->store_epoch(epoch));

    restart_node(victim);
    victim.driver->start(mesh.now_ms);

    EXPECT_EQ(victim.driver->verified_authority(), nullptr);
    EXPECT_EQ(victim.driver->phase(), DriverPhase::Failed);
    EXPECT_FALSE(victim.driver->current_epoch().has_value());
    EXPECT_FALSE(victim.driver->is_tier1_member());
}

TEST_F(DriverMesh, FormerGenesisRecoversThroughTheAuthorityChain) {
    bootstrap();
    restart_node(*genesis_node);
    genesis_node->driver->start(mesh.now_ms);
    ASSERT_EQ(genesis_node->driver->phase(), DriverPhase::Idle);
    ASSERT_EQ(genesis_node->driver->verified_authority(), nullptr);

    mesh.now_ms += 2001;
    genesis_node->driver->tick(mesh.now_ms);
    mesh.pump();

    ASSERT_NE(genesis_node->driver->verified_authority(), nullptr);
    EXPECT_EQ(genesis_node->driver->verified_authority()->epoch, 1u);
    EXPECT_EQ(genesis_node->driver->phase(), DriverPhase::Idle);
    EXPECT_TRUE(genesis_node->genesis->finalized());
}

TEST_F(DriverMesh, CorruptGenesisStateFailsClosedAtTheSigner) {
    bootstrap();
    restart_node(*genesis_node);
    {
        std::ofstream out(genesis_node->store->directory() / "bootstrap-certificate.json",
                          std::ios::trunc);
        out << "{corrupt";
    }

    genesis_node->driver->start(mesh.now_ms);

    EXPECT_EQ(genesis_node->driver->phase(), DriverPhase::Failed);
    EXPECT_TRUE(genesis_node->genesis->finalized());
    EXPECT_FALSE(genesis_node->genesis->admit_candidate(founders[0]->id));
}

TEST_F(DriverMesh, ContradictoryGenesisStateFailsClosedAtTheSigner) {
    bootstrap();
    ASSERT_NE(founders[0]->driver->verified_authority(), nullptr);
    auto contradictory = *founders[0]->driver->verified_authority();
    contradictory.network_id[0] ^= 0x01;
    ASSERT_TRUE(genesis_node->store->store_authority_anchor(contradictory));

    restart_node(*genesis_node);
    genesis_node->driver->start(mesh.now_ms);

    EXPECT_EQ(genesis_node->driver->phase(), DriverPhase::Failed);
    EXPECT_TRUE(genesis_node->genesis->finalized());
    EXPECT_FALSE(genesis_node->genesis->admit_candidate(founders[0]->id));
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

// Production incident: readiness and the handoff were derived from each
// member's own evidence digests. Every member verifies different evidence
// (its own challenge nonce), so no replica ever arrived at the leader's
// readiness digest, nothing committed, and every boundary was abandoned.
TEST_F(DriverMesh, HandoffCommitsWhenEveryMemberVerifiedDifferentEvidence) {
    bootstrap();
    run_until_committed(1);
    prepare_handoff();
    for (Node* founder : founders) {
        ASSERT_NE(founder->runtime->epochs()->transition(), nullptr);
    }
    for (Node* member : founders) {
        const auto vote_key = member->driver->vote_key_for_epoch(2);
        ASSERT_TRUE(vote_key.has_value());
        for (Node* founder : founders) {
            const auto verdict = seen_by(final_verdict(latest_plan(), member->id), founder->id);
            founder->driver->on_attestation_verdict(verdict, evidence_for(member->id, *vote_key));
        }
    }
    mesh.pump();
    for (int i = 0; i < 600; ++i) {
        step(1);
        if (std::all_of(founders.begin(), founders.end(),
                        [](Node* f) { return f->driver->current_epoch() == 2u; })) {
            break;
        }
    }
    for (Node* founder : founders) {
        EXPECT_EQ(founder->driver->current_epoch(), 2u);
    }
    // Every member holds the same finalized authority, whose attestation root
    // no single verifier's evidence could have produced.
    const auto* first = founders[0]->driver->verified_authority();
    ASSERT_NE(first, nullptr);
    for (Node* founder : founders) {
        const auto* authority = founder->driver->verified_authority();
        ASSERT_NE(authority, nullptr);
        EXPECT_EQ(authority->epoch, 2u);
        EXPECT_EQ(authority->attestation_root, first->attestation_root);
    }
}

// The announcement is a hint, not authority — but the hint must not be wrong:
// its authority record carries the announced epoch's real DKG transcript digest,
// not an all-zero placeholder, so a verifier comparing canonical digests over
// the announcement sees the transcript the epoch was actually built on.
TEST_F(DriverMesh, EpochAnnouncementCarriesTheRealDkgTranscriptDigest) {
    bootstrap();
    run_until_committed(1);
    prepare_handoff();

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
    }

    // What every honest node derived for the announced epoch: the digest the
    // driver persisted with the epoch's authority record, straight from the
    // store the activation path writes through.
    const auto history = founders.front()->store->load_authority_history();
    ASSERT_TRUE(std::holds_alternative<std::vector<EpochAuthorityRecord>>(history));
    const auto& records = std::get<std::vector<EpochAuthorityRecord>>(history);
    ASSERT_EQ(records.size(), 2u);
    ASSERT_EQ(records.back().epoch, 2u);
    const Digest transcript = records.back().dkg_transcript_digest;
    ASSERT_NE(transcript, Digest{});

    // And what left the mesh for it: the announcement the driver broadcast
    // when the epoch activated.
    ASSERT_FALSE(mesh.captured_announcements.empty());
    const auto found =
        std::find_if(mesh.captured_announcements.begin(), mesh.captured_announcements.end(),
                     [](const EpochAnnouncement& a) { return a.authority.epoch == 2u; });
    ASSERT_NE(found, mesh.captured_announcements.end());
    const EpochAnnouncement& announcement = *found;
    EXPECT_EQ(announcement.authority.dkg_transcript_digest, transcript);
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

// A rolling restart: members restart one after another, and each one must
// vote and commit again before the next one goes down. A proposal that
// arrives while a member syncs is refused, so the member resumes one block
// behind the chain; it must catch up instead of refusing every later proposal
// as parentless.
TEST_F(DriverMesh, SequentialRestartsKeepEveryMemberCommitting) {
    bootstrap();
    run_until_committed(2);
    ASSERT_FALSE(HasFatalFailure());
    for (std::size_t i = 0; i < 3; ++i) {
        Node* victim = founders[i];
        Height highest = 0;
        for (Node* founder : founders) {
            highest = std::max(highest, founder->driver->last_committed_height());
        }
        restart_node(*victim);
        victim->driver->start(mesh.now_ms);
        ASSERT_EQ(victim->driver->phase(), DriverPhase::Syncing);

        // With every member voting, the chain commits about once per step.
        // The bound leaves room for several timed-out views.
        run_until_committed(highest + 3, 100);
        ASSERT_FALSE(HasFatalFailure()) << "member " << i << " did not commit again";
        ASSERT_EQ(victim->driver->phase(), DriverPhase::Active);
        const View floor = victim->runtime->consensus()->state().last_voted_view;
        run_until_committed(highest + 6, 100);
        ASSERT_FALSE(HasFatalFailure()) << "member " << i << " stalled after its restart";
        EXPECT_GT(victim->runtime->consensus()->state().last_voted_view, floor)
            << "member " << i << " stopped voting after its restart";
    }
}

// Stops every Tier 1 member at the same moment and starts them again from
// their directories. Messages in flight to the old processes are lost.
void restart_committee_at_once(DriverMeshBase& fixture) {
    fixture.mesh.queue.clear();
    for (Node* member : fixture.founders) {
        fixture.restart_node(*member);
    }
    for (Node* member : fixture.founders) {
        member->driver->start(fixture.mesh.now_ms);
        ASSERT_EQ(member->driver->phase(), DriverPhase::Syncing);
        ASSERT_NE(member->runtime->consensus(), nullptr);
        ASSERT_TRUE(member->runtime->consensus()->usable()) << "the stored safety state loads";
        ASSERT_GT(member->runtime->consensus()->state().last_voted_view, 0u);
    }
}

[[nodiscard]] Height highest_commit(const std::vector<Node*>& members) {
    Height highest = 0;
    for (Node* member : members) {
        highest = std::max(highest, member->driver->last_committed_height());
    }
    return highest;
}

// Production incident: the consensus store kept the high certificate but not
// the block it certifies. After all five members restarted together, no
// member held that block, no leader could propose on it, and Epoch 1
// consensus stopped for good.
TEST_F(DriverMesh, EveryMemberRestartedAtOnceCommitsAgain) {
    bootstrap();
    run_until_committed(3);
    ASSERT_FALSE(HasFatalFailure());

    for (int round = 0; round < 2; ++round) {
        const Height before = highest_commit(founders);
        std::map<NodeId, View> voted;
        for (Node* member : founders) {
            voted[member->id] = member->runtime->consensus()->state().last_voted_view;
        }
        restart_committee_at_once(*this);
        ASSERT_FALSE(HasFatalFailure());

        run_until_committed(before + 3, 400);
        ASSERT_FALSE(HasFatalFailure()) << "round " << round << ": no commit after the restart";
        for (Node* member : founders) {
            EXPECT_EQ(member->driver->phase(), DriverPhase::Active);
            EXPECT_EQ(member->driver->current_epoch(), 1u);
            EXPECT_GT(member->runtime->consensus()->state().last_voted_view, voted[member->id])
                << "round " << round << ": a member did not vote again";
        }
    }
}

// The fleet runs with consensus state from the binary that stored no blocks.
// The new binary loads that state in place. Installed one member at a time,
// each member takes the blocks from its running peers through restart sync
// and stores them with its next vote. After that, a restart of the whole
// committee at once recovers.
TEST_F(DriverMesh, StateWithoutStoredBlocksLoadsAndThenSurvivesAFullRestart) {
    bootstrap();
    run_until_committed(3);
    ASSERT_FALSE(HasFatalFailure());

    const auto drop_stored_blocks = [](Node& member) {
        std::size_t removed = 0;
        for (const auto& entry : fs::directory_iterator(member.dir / "consensus")) {
            if (entry.path().filename().string().starts_with("hotstuff-chain-")) {
                fs::remove(entry.path());
                ++removed;
            }
        }
        return removed;
    };

    for (Node* member : founders) {
        const Height before = highest_commit(founders);
        restart_node(*member);
        (void)drop_stored_blocks(*member);
        member->driver->start(mesh.now_ms);
        ASSERT_EQ(member->driver->phase(), DriverPhase::Syncing);
        ASSERT_TRUE(member->runtime->consensus()->usable()) << "the old safety state loads";
        run_until_committed(before + 3, 200);
        ASSERT_FALSE(HasFatalFailure());
        ASSERT_EQ(member->driver->phase(), DriverPhase::Active);
    }

    const Height before = highest_commit(founders);
    restart_committee_at_once(*this);
    ASSERT_FALSE(HasFatalFailure());
    run_until_committed(before + 3, 400);
    ASSERT_FALSE(HasFatalFailure()) << "no commit after the full restart";
}

// The recovery install: every server gets the fixed binary and keeps its Epoch 1
// state (epoch record, authority chain, consensus and eligibility stores). The
// Tier 1 members restart one at a time, each rejoining before the next goes
// down: state from a release that stored no blocks names a certificate whose
// block only the running peers hold (see
// StateWithoutStoredBlocksLoadsAndThenSurvivesAFullRestart). Afterwards the
// next boundary hands off to Epoch 2, with each member holding different
// evidence for every node, as production verifiers do.
TEST_F(DriverMesh, ACommitteeRestartedOneAtATimeOnItsStateHandsOffToEpochTwo) {
    bootstrap();
    run_until_committed(2);
    ASSERT_FALSE(HasFatalFailure());

    for (Node* member : founders) {
        Height highest = 0;
        for (Node* founder : founders) {
            highest = std::max(highest, founder->driver->last_committed_height());
        }
        restart_node(*member);
        member->driver->start(mesh.now_ms);
        ASSERT_EQ(member->driver->current_epoch(), 1u) << "the kept epoch record";
        run_until_committed(highest + 3, 200);
        ASSERT_FALSE(HasFatalFailure());
        ASSERT_EQ(member->driver->phase(), DriverPhase::Active);
    }

    prepare_handoff();
    for (Node* founder : founders) {
        ASSERT_NE(founder->runtime->epochs()->transition(), nullptr);
    }
    final_attest_subjects(0x70, founders, founders);
    for (int i = 0; i < 600; ++i) {
        step(1);
        if (std::all_of(founders.begin(), founders.end(),
                        [](Node* f) { return f->driver->current_epoch() == 2u; })) {
            break;
        }
    }
    for (Node* founder : founders) {
        EXPECT_EQ(founder->driver->current_epoch(), 2u);
    }
}

// A running member cut off for longer than one sync reply covers. The rest of
// the committee keeps committing; after the partition heals the member must
// fetch the missing certified blocks page by page and vote again, without a
// restart.
TEST_F(DriverMesh, AMemberPartitionedPastTheSyncWindowRejoinsWithoutARestart) {
    bootstrap();
    run_until_committed(2);
    ASSERT_FALSE(HasFatalFailure());
    Node* victim = founders.back();
    std::vector<Node*> majority(founders.begin(), founders.end() - 1);
    const Height cut_at = victim->driver->last_committed_height();
    const View voted_before = victim->runtime->consensus()->state().last_voted_view;

    // The victim keeps running during the partition: it ticks, times out,
    // and sends, but no message reaches it or leaves it.
    mesh.offline.insert(victim->id);
    const Height target = cut_at + 4 * constants::kMaxSyncChainBlocks;
    for (int i = 0; i < 4000 && majority.front()->driver->last_committed_height() < target;
         ++i) {
        step(1, founders);
    }
    ASSERT_GE(majority.front()->driver->last_committed_height(), target)
        << "the majority did not commit through the partition";
    // Its own last proposal can still commit locally; it stays far behind.
    EXPECT_LE(victim->driver->last_committed_height(), cut_at + 1);
    EXPECT_EQ(victim->driver->phase(), DriverPhase::Active);

    mesh.offline.erase(victim->id);
    const Height healed_at = majority.front()->driver->last_committed_height();
    run_until_committed(healed_at + 3, 400);
    ASSERT_FALSE(HasFatalFailure()) << "the member did not catch up after the partition";
    EXPECT_EQ(victim->driver->phase(), DriverPhase::Active);
    EXPECT_GT(victim->runtime->consensus()->state().last_voted_view, voted_before);

    // It votes again: the chain commits with it as a working member.
    const View floor = victim->runtime->consensus()->state().last_voted_view;
    run_until_committed(healed_at + 6, 200);
    ASSERT_FALSE(HasFatalFailure());
    EXPECT_GT(victim->runtime->consensus()->state().last_voted_view, floor)
        << "the member stopped voting after it caught up";
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


// The epoch-established hook fires exactly when finalized authority appears:
// each founder on entry into Active, the anchor at certificate issuance.
TEST_F(DriverMesh, EpochEstablishmentFiresOnActivationAndIssuance) {
    int anchor_fired = 0;
    genesis_node->driver->set_epoch_established_callback([&] { ++anchor_fired; });
    std::vector<int> founder_fired(founders.size(), 0);
    for (size_t i = 0; i < founders.size(); ++i) {
        founders[i]->driver->set_epoch_established_callback(
            [&founder_fired, i] { ++founder_fired[i]; });
    }

    bootstrap();

    EXPECT_EQ(anchor_fired, 1);
    for (int fired : founder_fired) EXPECT_EQ(fired, 1);
}

}  // namespace
}  // namespace lifecycle_test
