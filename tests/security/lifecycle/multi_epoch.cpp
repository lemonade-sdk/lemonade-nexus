// Repeated Tier 2 promotion, late joining, and stale-state recovery across
// four real epoch rotations.
//
// Everything runs on the production path: eligibility, selection, the
// finalized plan, pending adoption, plan-bound final attestation, vote-key
// registration, readiness, the fresh DKG, the finalized handoff, activation,
// and the verified handoff chain that late joiners walk from the pinned
// Genesis anchor. No test-only role injection exists; verdicts are injected
// through the driver's own event entry point because the attestation
// verifier's positive path needs a confidential VM.

#include "support/rotation.hpp"

#include <algorithm>

namespace lifecycle_test {
namespace {

struct MultiEpochMesh : RotatingMeshBase {
    MultiEpochMesh() : RotatingMeshBase(5) {}

    struct MissedActivation {
        Node* stale = nullptr;
        std::vector<Node*> members;
    };

    /// Runs the 1 -> 2 boundary with every founder and one reserve in the
    /// pool. A founder that the first attempt selects verifies none of the
    /// final attestations: its own challenges are lost and no verdict reaches
    /// it. It then cannot form the readiness set the others commit, so it
    /// never joins the ceremony. The mesh waits out the DKG stall window,
    /// excludes it, and activates Epoch 2 under a replacement attempt. The
    /// stale member stays online and ticking the whole time. With
    /// `lose_handoff_proofs`, no handoff proof reaches it either.
    MissedActivation activate_without_one(Node* candidate, bool lose_handoff_proofs) {
        MissedActivation out;
        std::vector<Node*> pool = founders;
        pool.push_back(candidate);
        observe(founders, pool, 1);
        run_to_plan(founders);
        const auto selected = selected_nodes(*founders.front());
        for (Node* node : selected) {
            if (node != founders.front() &&
                std::find(founders.begin(), founders.end(), node) != founders.end()) {
                out.stale = node;
                break;
            }
        }
        if (out.stale == nullptr) {
            ADD_FAILURE() << "the first attempt selected no second founder";
            return out;
        }
        Node* stale = out.stale;
        std::erase_if(mesh.captured_final_challenges,
                      [stale](const auto& entry) { return entry.first == stale->id; });
        mesh.drop_if = [stale, lose_handoff_proofs](const Queued& item,
                                                    const SecurityMessage& message) {
            if (item.from == stale->id && message.kind == SecurityMessageKind::AttestationChallenge) {
                return true;
            }
            return lose_handoff_proofs && item.to == stale->id &&
                   message.kind == SecurityMessageKind::EpochHandoffProof;
        };
        std::vector<Node*> observers;
        for (Node* founder : founders) {
            if (founder != stale) observers.push_back(founder);
        }

        wait_for_keys(founders, selected, 2);
        final_attest_subjects(9, selected, observers);
        const std::size_t ready_before = mesh.captured_readiness.size();
        for (int i = 0; i < 900 && mesh.captured_readiness.size() == ready_before; ++i) {
            step(1, with_candidates(founders, selected));
        }
        if (mesh.captured_readiness.size() == ready_before) {
            ADD_FAILURE() << "readiness never finalized";
            return out;
        }
        EXPECT_EQ(stale->runtime->authority().dkg(), nullptr)
            << "the stale member must miss the ceremony";

        const std::size_t plans_before = mesh.captured_plans.size();
        mesh.now_ms += (constants::kDkgStallSeconds + 5) * 1000;
        for (int i = 0; i < 900 && mesh.captured_plans.size() == plans_before; ++i) {
            step(1, with_candidates(founders, selected));
            answer_final_challenges();
        }
        if (mesh.captured_plans.size() == plans_before) {
            ADD_FAILURE() << "no replacement plan committed";
            return out;
        }
        const NextEpochPlan& replacement = latest_plan();
        EXPECT_TRUE(std::find(replacement.selected.begin(), replacement.selected.end(),
                              stale->id) == replacement.selected.end())
            << "the silent member survived into the replacement attempt";

        out.members = selected_nodes(*founders.front());
        wait_for_keys(founders, out.members, 2);
        final_attest_subjects(11, out.members, observers);
        run_to_activation(founders, out.members, 2);
        return out;
    }
};

// An idle Tier 2 reserve, holding only the pinned anchor, walks to the chain
// head on its own cadence: the base page carries Epoch 1 under the Genesis
// signature, and each later page carries verified handoff links.
TEST_F(MultiEpochMesh, AnIdleReserveWalksToTheChainHead) {
    bootstrap();
    run_until_committed(1);
    introduce_reserves();
    Node* reserve = reserves[0];
    for (int i = 0; i < 40; ++i) {
        step(1, founders);
        reserve->driver->tick(mesh.now_ms);
        mesh.pump();
        if (reserve->driver->verified_authority() != nullptr) break;
    }
    ASSERT_NE(reserve->driver->verified_authority(), nullptr);
    EXPECT_EQ(reserve->driver->verified_authority()->epoch, 1u);
    EXPECT_EQ(reserve->driver->verified_authority()->members,
              founders.front()->runtime->epochs()->current().tier1_members.members());
    // Verification is knowledge, not authority.
    EXPECT_EQ(reserve->runtime->epochs(), nullptr);
    EXPECT_FALSE(reserve->driver->is_tier1_member());
}

TEST_F(MultiEpochMesh, RestartAuthenticatesCompleteProofChainBeforeRestoringEpoch) {
    bootstrap();
    run_until_committed(1);
    const auto members = rotate(founders, founders, 1);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    ASSERT_FALSE(members.empty());
    Node& victim = *members.front();
    ASSERT_EQ(victim.driver->current_epoch(), 2u);

    restart_node(victim);
    victim.driver->start(mesh.now_ms);

    ASSERT_NE(victim.driver->verified_authority(), nullptr);
    EXPECT_EQ(victim.driver->verified_authority()->epoch, 2u);
    EXPECT_EQ(victim.driver->current_epoch(), 2u);
    EXPECT_TRUE(victim.driver->is_tier1_member());
    EXPECT_NE(victim.driver->phase(), DriverPhase::Failed);
}

// Four rotations, three promotions, one late joiner, one stale-state
// recovery — one continuous scenario on one mesh.
TEST_F(MultiEpochMesh, RepeatedPromotionAndLateJoiningAcrossFourEpochs) {
    Node* reserve_f = reserves[0];
    Node* reserve_g = reserves[1];
    Node* reserve_h = reserves[2];
    Node* late_joiner = reserves[4];

    // The late joiner does not exist for the mesh yet: it first appears
    // during epoch 4, holding only the pinned Genesis anchor and its
    // identity.
    mesh.offline.insert(late_joiner->id);

    bootstrap();
    run_until_committed(1);
    introduce_reserves();

    // --- Epoch 1 -> 2: E offline, F promoted. ---
    mesh.offline.insert(founders[4]->id);
    std::vector<Node*> members(founders.begin(), founders.begin() + 4);
    std::vector<Node*> pool = members;
    pool.push_back(reserve_f);
    members = rotate(members, pool, 1);
    EXPECT_EQ(ids_of(members), ids_of(pool));
    EXPECT_TRUE(reserve_f->driver->is_tier1_member());
    EXPECT_EQ(reserve_f->driver->current_epoch(), 2u);
    // The young epoch does some work before anyone drops out, so every member
    // holds real consensus state from it.
    advance_commit(members);
    advance_commit(members);

    // --- Epoch 2 -> 3: D offline, G promoted via the verified chain. ---
    mesh.offline.insert(founders[3]->id);
    members.erase(std::remove(members.begin(), members.end(), founders[3]), members.end());
    // G was never a member; everything it knows about epoch 2 came from
    // walking Genesis -> 1 -> 2. Its authority must be at the head before the
    // plan can even name it.
    pool = members;
    pool.push_back(reserve_g);
    observe(members, pool, 2);
    ASSERT_NE(reserve_g->driver->verified_authority(), nullptr);
    EXPECT_EQ(reserve_g->driver->verified_authority()->epoch, 2u);
    run_to_plan(members);
    auto selected = selected_nodes(*members.front());
    wait_for_keys(members, selected, 3);
    final_attest_subjects(9, selected, members);
    run_to_activation(members, selected, 3);
    members = selected;
    EXPECT_EQ(ids_of(members), ids_of(pool));
    EXPECT_TRUE(reserve_g->driver->is_tier1_member());

    // The demoted member keeps no role in the new epoch. Offline, it cannot
    // know that yet; the epoch the mesh runs simply does not contain it.
    Node* demoted = founders[3];
    EXPECT_FALSE(members.front()->runtime->epochs()->current().tier1_members.contains(
        demoted->id));

    // --- Epoch 3 -> 4: C offline, H promoted. ---
    mesh.offline.insert(founders[2]->id);
    members.erase(std::remove(members.begin(), members.end(), founders[2]), members.end());
    pool = members;
    pool.push_back(reserve_h);
    members = rotate(members, pool, 3);
    EXPECT_EQ(ids_of(members), ids_of(pool));
    EXPECT_TRUE(reserve_h->driver->is_tier1_member());
    for (Node* member : members) {
        ASSERT_NE(member->driver->verified_authority(), nullptr);
        EXPECT_EQ(member->driver->verified_authority()->epoch, 4u);
    }

    // --- The fresh node appears during epoch 4. ---
    // It holds the pinned anchor, its identity, and ordinary discovery. It
    // must derive the whole authority chain itself before anything else.
    mesh.offline.erase(late_joiner->id);
    late_joiner->driver->start(mesh.now_ms);
    for (Node* member : members) member->driver->on_peer(late_joiner->id, mesh.now_ms);
    for (int i = 0; i < 60 && (late_joiner->driver->verified_authority() == nullptr ||
                               late_joiner->driver->verified_authority()->epoch < 4u);
         ++i) {
        step(1, members);
        late_joiner->driver->tick(mesh.now_ms);
        mesh.pump();
    }
    const auto* walked = late_joiner->driver->verified_authority();
    ASSERT_NE(walked, nullptr);
    EXPECT_EQ(walked->epoch, 4u);
    EXPECT_EQ(walked->members, members.front()->runtime->epochs()->current().tier1_members.members());
    EXPECT_EQ(walked->vote_keys, members.front()->runtime->epochs()->current_vote_keys());

    // Verifying the chain made it a Tier 2 participant and nothing more.
    EXPECT_EQ(late_joiner->driver->phase(), DriverPhase::Idle);
    EXPECT_EQ(late_joiner->runtime->epochs(), nullptr);
    EXPECT_EQ(late_joiner->runtime->consensus(), nullptr);
    EXPECT_FALSE(late_joiner->driver->is_tier1_member());
    EXPECT_FALSE(late_joiner->runtime->authority().key_epoch().has_value());

    // --- Epoch 4 -> 5: H offline, the late joiner qualifies and serves. ---
    mesh.offline.insert(reserve_h->id);
    members.erase(std::remove(members.begin(), members.end(), reserve_h), members.end());
    pool = members;
    pool.push_back(late_joiner);
    members = rotate(members, pool, 4);
    EXPECT_EQ(ids_of(members), ids_of(pool));
    EXPECT_TRUE(late_joiner->driver->is_tier1_member());
    EXPECT_EQ(late_joiner->driver->current_epoch(), 5u);
    EXPECT_EQ(*late_joiner->runtime->authority().key_epoch(), 5u);

    // The new epoch commits under the new membership.
    const Height before = members.front()->driver->last_committed_height();
    for (int i = 0; i < 300; ++i) {
        step(1, members);
        if (members.front()->driver->last_committed_height() > before) break;
    }
    EXPECT_GT(members.front()->driver->last_committed_height(), before);

    // --- Stale-state recovery: the epoch-2 member D restarts at epoch 5. ---
    // Its stored epoch is history. It syncs into silence and walks the chain.
    // The first verified link moves it off its finished epoch, and it walks on
    // as Tier 2: the stale membership yields no vote and no progress, and no
    // second restart is necessary. A later restart keeps it there.
    mesh.offline.erase(demoted->id);
    restart_node(*demoted);
    demoted->driver->start(mesh.now_ms);
    EXPECT_EQ(demoted->driver->phase(), DriverPhase::Syncing);
    for (int i = 0; i < 120; ++i) {
        step(1, members);
        demoted->driver->tick(mesh.now_ms);
        mesh.pump();
        if (demoted->driver->verified_authority() != nullptr &&
            demoted->driver->verified_authority()->epoch == 5u) {
            break;
        }
    }
    ASSERT_NE(demoted->driver->verified_authority(), nullptr);
    EXPECT_EQ(demoted->driver->verified_authority()->epoch, 5u);
    // It never rejoined its dead epoch.
    EXPECT_EQ(demoted->driver->phase(), DriverPhase::Idle);
    EXPECT_EQ(demoted->runtime->epochs(), nullptr);
    EXPECT_FALSE(demoted->driver->is_tier1_member());

    restart_node(*demoted);
    demoted->driver->start(mesh.now_ms);
    EXPECT_EQ(demoted->driver->phase(), DriverPhase::Idle);
    EXPECT_EQ(demoted->runtime->epochs(), nullptr);
    ASSERT_NE(demoted->driver->verified_authority(), nullptr);
    EXPECT_EQ(demoted->driver->verified_authority()->epoch, 5u);
}

// A selected candidate claims readiness and then refuses the ceremony — over
// two successive transitions. Liveness only: the attempt fails on observed
// silence, the deterministic reserve replaces the refuser, a fresh DKG runs,
// and nothing of the failed attempt crosses into the replacement.
TEST_F(MultiEpochMesh, AReadyCandidateThatRefusesTheDkgIsReplaced) {
    bootstrap();
    run_until_committed(1);
    introduce_reserves();

    const auto refusal_rotation = [&](std::vector<Node*> members,
                                      const std::vector<Node*>& candidates,
                                      EpochId from_epoch) -> std::vector<Node*> {
        std::vector<Node*> pool = members;
        pool.insert(pool.end(), candidates.begin(), candidates.end());
        observe(members, pool, from_epoch);
        run_to_plan(members);

        // Whoever selection promoted claims readiness in full: synced state,
        // fresh plan-bound attestation, registered next-epoch key.
        auto selected = selected_nodes(*members.front());
        wait_for_keys(members, selected, from_epoch + 1);
        Node* refuser = nullptr;
        for (Node* node : selected) {
            if (std::find(members.begin(), members.end(), node) == members.end()) {
                refuser = node;
                break;
            }
        }
        if (refuser == nullptr) {
            ADD_FAILURE() << "selection promoted nobody to refuse";
            return members;
        }
        final_attest_subjects(9, selected, members);

        // Readiness can now finalize — and the refuser goes silent. Its
        // round-1 silence is observed identically by every member.
        mesh.offline.insert(refuser->id);
        const std::size_t ready_before = mesh.captured_readiness.size();
        for (int i = 0; i < 900 && mesh.captured_readiness.size() == ready_before; ++i) {
            step(1, members);
        }
        if (mesh.captured_readiness.size() == ready_before) {
            ADD_FAILURE() << "readiness never finalized";
            return members;
        }

        // The ceremony now hangs on the refuser. Past the compiled window the
        // attempt fails and the replacement plan commits.
        const uint32_t plans_before = static_cast<uint32_t>(mesh.captured_plans.size());
        mesh.now_ms += (constants::kDkgStallSeconds + 5) * 1000;
        for (int i = 0; i < 900 && mesh.captured_plans.size() == plans_before; ++i) {
            step(1, members);
        }
        EXPECT_GT(mesh.captured_plans.size(), plans_before) << "no replacement plan committed";

        // The replacement plan is a new attempt that excludes the refuser.
        const NextEpochPlan& replacement = latest_plan();
        EXPECT_GT(replacement.attempt, 0u);
        EXPECT_TRUE(std::find(replacement.selected.begin(), replacement.selected.end(),
                              refuser->id) == replacement.selected.end())
            << "the refuser survived into the replacement attempt";

        auto replacement_selected = selected_nodes(*members.front());
        wait_for_keys(members, replacement_selected, from_epoch + 1);
        final_attest_subjects(11, replacement_selected, members);
        run_to_activation(members, replacement_selected, from_epoch + 1);
        for (Node* node : replacement_selected) {
            EXPECT_EQ(node->driver->current_epoch(), from_epoch + 1);
        }
        EXPECT_NE(refuser->driver->current_epoch(), from_epoch + 1);
        // Silence cost the refuser this boundary and nothing more: it is not
        // objectively provable, so no member records it as a permanent fault.
        for (Node* member : replacement_selected) {
            EXPECT_FALSE(member->driver->eligibility().ledger().faults().contains(refuser->id))
                << "observed silence must never become a permanent objective fault";
        }
        return replacement_selected;
    };

    // Transition one: E offline; F and G qualified; the promoted one refuses
    // and the other replaces it under a fresh plan and a fresh ceremony.
    mesh.offline.insert(founders[4]->id);
    std::vector<Node*> members(founders.begin(), founders.begin() + 4);
    members = refusal_rotation(members, {reserves[0], reserves[1]}, 1);
    EXPECT_EQ(members.front()->driver->current_epoch(), 2u);

    // Transition two: the same attack from a different candidate pair, one
    // epoch later. History does not soften the rule. One incumbent founder
    // drops out first, so the pool holds fewer incumbents than seats and
    // selection MUST promote — the guarantee is structural, not a draw.
    Node* dropped = nullptr;
    for (Node* member : members) {
        if (std::find(founders.begin(), founders.end(), member) != founders.end() &&
            !mesh.offline.contains(member->id)) {
            dropped = member;
            break;
        }
    }
    ASSERT_NE(dropped, nullptr);
    mesh.offline.insert(dropped->id);
    std::vector<Node*> online;
    for (Node* member : members) {
        if (!mesh.offline.contains(member->id)) online.push_back(member);
    }
    members = refusal_rotation(online, {reserves[2], reserves[3]}, 2);
    EXPECT_EQ(members.front()->driver->current_epoch(), 3u);
}

// Lost key-generation datagrams at an epoch boundary are re-sent, so the
// ceremony completes in the first attempt instead of stalling until the
// compiled window replaces it. Before the re-send cadence, only the founding
// DKG re-sent; a transition DKG lost its round-2 packages for good.
TEST_F(MultiEpochMesh, LostTransitionDkgPackagesAreResentWithoutAStall) {
    bootstrap();
    run_until_committed(1);
    introduce_reserves();

    const std::vector<Node*> members(founders.begin(), founders.end());
    std::vector<Node*> pool = members;
    pool.push_back(reserves[0]);
    observe(members, pool, 1);
    run_to_plan(members);
    const auto selected = selected_nodes(*members.front());
    ASSERT_FALSE(selected.empty());
    wait_for_keys(members, selected, 2);

    // Lose a burst of the ceremony's traffic in both rounds.
    mesh.drop_next[SecurityMessageKind::DkgBroadcast] = 6;
    mesh.drop_next[SecurityMessageKind::DkgPairwise] = 10;

    // Every participant ticks, the promoted reserve included, as every
    // production server does: its own re-send cadence must run too.
    std::vector<Node*> participants = members;
    for (Node* node : selected) {
        if (std::find(participants.begin(), participants.end(), node) == participants.end()) {
            participants.push_back(node);
        }
    }
    const uint64_t started_ms = mesh.now_ms;
    bool activated = false;
    for (int i = 0; i < 2500 && !activated; ++i) {
        step(1, participants);
        answer_final_challenges();
        activated = std::all_of(selected.begin(), selected.end(), [](Node* n) {
            return n->driver->current_epoch() == 2u;
        });
    }
    ASSERT_TRUE(activated) << "epoch 2 did not activate";
    EXPECT_EQ(mesh.drop_next[SecurityMessageKind::DkgBroadcast], 0) << "nothing was lost";
    EXPECT_EQ(mesh.drop_next[SecurityMessageKind::DkgPairwise], 0) << "nothing was lost";
    EXPECT_LT(mesh.now_ms - started_ms, constants::kDkgStallSeconds * 1000)
        << "the ceremony waited out the stall window";
    EXPECT_EQ(latest_plan().attempt, 0u) << "a replacement attempt ran";
}

// The founding ceremony survives lost key-generation packages too. A founder
// that finished used to fall silent at once, so a slower founder missing one
// of its packages waited out the stall window and the founding split (seen
// on r17). Finished founders keep re-sending until Epoch 1 activates.
TEST_F(MultiEpochMesh, LostFoundingDkgPackagesAreResentWithoutAStall) {
    collect_founding();
    mesh.drop_next[SecurityMessageKind::DkgBroadcast] = 4;
    mesh.drop_next[SecurityMessageKind::DkgPairwise] = 8;
    run_founding_eligibility();

    std::vector<Node*> online = founders;
    online.push_back(genesis_node);
    const uint64_t started_ms = mesh.now_ms;
    bool active = false;
    for (int i = 0; i < 1400 && !active; ++i) {
        step(1, online);
        active = std::all_of(founders.begin(), founders.end(), [](Node* n) {
            return n->driver->phase() == DriverPhase::Active && n->driver->current_epoch() == 1u;
        });
    }
    ASSERT_TRUE(active) << "Epoch 1 did not activate";
    EXPECT_EQ(mesh.drop_next[SecurityMessageKind::DkgBroadcast], 0) << "nothing was lost";
    EXPECT_EQ(mesh.drop_next[SecurityMessageKind::DkgPairwise], 0) << "nothing was lost";
    EXPECT_LT(mesh.now_ms - started_ms, constants::kDkgStallSeconds * 1000)
        << "the founding waited out the stall window";
}

// A boundary that outlives the final-attestation freshness window renews the
// exchange instead of deadlocking: the members re-challenge exactly the
// nodes whose proof aged out, the answers arrive through the ordinary
// verifier path, and the handoff completes.
TEST_F(MultiEpochMesh, AStalledBoundaryRenewsItsFinalAttestation) {
    bootstrap();
    run_until_committed(1);
    introduce_reserves();

    mesh.offline.insert(founders[4]->id);
    std::vector<Node*> members(founders.begin(), founders.begin() + 4);
    std::vector<Node*> pool = members;
    pool.push_back(reserves[0]);
    observe(members, pool, 1);
    run_to_plan(members);
    const auto selected = selected_nodes(*members.front());
    wait_for_keys(members, selected, 2);

    // The boundary outlives the freshness window twice over: each jump
    // stales every attestation answered so far, and each recovery runs the
    // renewal exchange again. The per-purpose budget must carry all of it —
    // one initial round plus one renewal per window is exactly the load the
    // derived final-attest bound is sized for.
    for (int window = 0; window < 2; ++window) {
        mesh.now_ms += (constants::kFinalAttestMaxAgeSeconds + 10) * 1000;
        for (int i = 0; i < 40; ++i) {
            step(1, members);
            answer_final_challenges();
        }
    }
    for (Node* member : members) {
        for (Node* subject : selected) {
            EXPECT_LE(member->runtime->attestation().final_attempts(
                          subject->id,
                          SecurityDriver::plan_attest_context(latest_plan(), subject->id)),
                      constants::kMaxFinalAttestAttemptsPerPlan)
                << "renewal stays inside the attempt's own budget";
        }
    }

    run_to_activation(members, selected, 2);
    for (Node* node : selected) {
        EXPECT_EQ(node->driver->current_epoch(), 2u);
    }
}

// A boundary that outlives a whole target epoch still recovers: the truant
// candidate exhausts its attempt's bounded final-attestation budget, the
// attempt fails deterministically, the old epoch stays authoritative, and
// the replacement attempt — with its own fresh budget — activates. No
// wall-clock horizon wedges the mesh, and no constant is raised to fake one.
TEST_F(MultiEpochMesh, ABoundaryOutlivingTheTargetEpochStillActivates) {
    bootstrap();
    run_until_committed(1);
    introduce_reserves();

    mesh.offline.insert(founders[4]->id);
    std::vector<Node*> members(founders.begin(), founders.begin() + 4);
    std::vector<Node*> pool = members;
    pool.push_back(reserves[0]);
    pool.push_back(reserves[1]);
    observe(members, pool, 1);
    run_to_plan(members);
    const uint64_t plan_committed_ms = mesh.now_ms;

    // The promoted candidate vanishes before it syncs: this attempt can
    // never complete, and only budget exhaustion may end it.
    auto selected = selected_nodes(*members.front());
    Node* truant = nullptr;
    for (Node* node : selected) {
        if (std::find(members.begin(), members.end(), node) == members.end()) {
            truant = node;
            break;
        }
    }
    ASSERT_NE(truant, nullptr);
    mesh.offline.insert(truant->id);
    const uint32_t attempt_before = latest_plan().attempt;

    // Freshness window after freshness window passes — far beyond one target
    // epoch in total — with every reachable node renewing honestly.
    const uint32_t plans_before = static_cast<uint32_t>(mesh.captured_plans.size());
    for (int window = 0; window < 5 && mesh.captured_plans.size() == plans_before;
         ++window) {
        mesh.now_ms += 1000 * 1000;
        for (int i = 0; i < 60; ++i) {
            step(1, members);
            answer_final_challenges();
            if (mesh.captured_plans.size() != plans_before) break;
        }
    }
    ASSERT_GT(mesh.captured_plans.size(), plans_before)
        << "budget exhaustion must fail the attempt and commit a replacement";
    EXPECT_GT(latest_plan().attempt, attempt_before);
    EXPECT_TRUE(std::find(latest_plan().selected.begin(), latest_plan().selected.end(),
                          truant->id) == latest_plan().selected.end())
        << "the never-fulfilled candidate is out of the replacement attempt";

    // The replacement attempt completes on its own fresh budget.
    selected = selected_nodes(*members.front());
    wait_for_keys(members, selected, 2);
    run_to_activation(members, selected, 2);
    for (Node* node : selected) {
        EXPECT_EQ(node->driver->current_epoch(), 2u);
    }
    EXPECT_GT(mesh.now_ms - plan_committed_ms, constants::kTargetEpochSeconds * 1000)
        << "the boundary genuinely outlived a full target epoch";

    // Exhaustion was an attempt outcome, never a fault: the truant keeps a
    // clean ledger everywhere.
    for (Node* member : members) {
        EXPECT_FALSE(member->driver->eligibility().ledger().faults().contains(truant->id));
    }
}

// A current member misses one boundary stage and the mesh activates the next
// epoch without it. Its own commit of the handoff can never activate it,
// because it never prepared that handoff. The broadcast handoff proof,
// verified under its own epoch's frozen keys, moves it off the finished epoch
// to the role a restart would give it: Tier 2, holding the verified chain.
TEST_F(MultiEpochMesh, AMemberThatMissedTheActivationContinuesAsTierTwo) {
    bootstrap();
    run_until_committed(1);
    introduce_reserves();

    const auto [stale, members] = activate_without_one(reserves[0], false);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    ASSERT_NE(stale, nullptr);
    ASSERT_FALSE(members.empty());

    // The proof arrived with the commit; no chain request was necessary.
    EXPECT_EQ(stale->driver->phase(), DriverPhase::Idle);
    EXPECT_EQ(stale->runtime->epochs(), nullptr);
    EXPECT_EQ(stale->runtime->consensus(), nullptr);
    EXPECT_FALSE(stale->runtime->authority().key_epoch().has_value());
    EXPECT_FALSE(stale->driver->is_tier1_member());
    ASSERT_NE(stale->driver->verified_authority(), nullptr);
    EXPECT_EQ(stale->driver->verified_authority()->epoch, 2u);
    EXPECT_EQ(stale->driver->verified_authority()->members,
              members.front()->runtime->epochs()->current().tier1_members.members());

    // The followed link is durable: a restart keeps the node on the verified
    // chain as Tier 2 and never resumes the finished epoch.
    restart_node(*stale);
    stale->driver->start(mesh.now_ms);
    EXPECT_EQ(stale->driver->phase(), DriverPhase::Idle);
    EXPECT_EQ(stale->runtime->epochs(), nullptr);
    ASSERT_NE(stale->driver->verified_authority(), nullptr);
    EXPECT_EQ(stale->driver->verified_authority()->epoch, 2u);

    // Epoch 2 keeps committing under its own membership.
    const Height before = members.front()->driver->last_committed_height();
    advance_commit(with_candidates(founders, members));
    EXPECT_GT(members.front()->driver->last_committed_height(), before);
}

// The same miss, with every handoff proof to the stale member lost. A proof
// that does not verify moves nothing. The announcement of Epoch 2 is a hint
// only; the stale member acts on it by asking for the authority chain, and
// the verified page moves it off the finished epoch.
TEST_F(MultiEpochMesh, AMemberThatLostTheHandoffProofsFollowsTheVerifiedChain) {
    bootstrap();
    run_until_committed(1);
    introduce_reserves();

    const auto [stale, members] = activate_without_one(reserves[0], true);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    ASSERT_NE(stale, nullptr);
    ASSERT_FALSE(members.empty());
    ASSERT_FALSE(mesh.captured_handoffs.empty());
    ASSERT_EQ(stale->driver->current_epoch(), 1u) << "no proof reached the stale member yet";

    // Hostile copies of the genuine proof: a membership the commit never
    // certified, and a certificate without its quorum. Neither changes state.
    const EpochHandoffProofMsg genuine = mesh.captured_handoffs.back();
    EpochHandoffProofMsg widened = genuine;
    widened.handoff.members.push_back(stale->id);
    stale->driver->on_epoch_handoff_proof(widened);
    EpochHandoffProofMsg unsigned_proof = genuine;
    unsigned_proof.proof.certifying.signers.resize(1);
    stale->driver->on_epoch_handoff_proof(unsigned_proof);
    AuthorityChainPage forged_page;
    forged_page.links.push_back(unsigned_proof);
    stale->driver->on_authority_chain_page(forged_page, founders[0]->id);
    EXPECT_EQ(stale->driver->current_epoch(), 1u);
    EXPECT_EQ(stale->driver->phase(), DriverPhase::Active);
    ASSERT_NE(stale->driver->verified_authority(), nullptr);
    EXPECT_EQ(stale->driver->verified_authority()->epoch, 1u);

    for (int i = 0; i < 60 && stale->runtime->epochs() != nullptr; ++i) {
        step(1, with_candidates(founders, members));
    }
    EXPECT_EQ(stale->driver->phase(), DriverPhase::Idle);
    EXPECT_EQ(stale->runtime->epochs(), nullptr);
    EXPECT_FALSE(stale->driver->is_tier1_member());
    ASSERT_NE(stale->driver->verified_authority(), nullptr);
    EXPECT_EQ(stale->driver->verified_authority()->epoch, 2u);
}

// A selected member holds its DKG outcome and is ready for the handoff, but
// its consensus traffic is lost while the others commit it. The others leave
// Epoch 1, so its own commit can never come. The announcement of Epoch 2
// makes it ask for the authority chain, and the verified link activates it as
// the member the handoff names. It then votes in Epoch 2.
TEST_F(MultiEpochMesh, ASelectedMemberThatMissedTheHandoffCommitJoinsItsEpoch) {
    bootstrap();
    run_until_committed(1);

    observe(founders, founders, 1);
    run_to_plan(founders);
    const auto selected = selected_nodes(*founders.front());
    ASSERT_EQ(selected.size(), founders.size());
    wait_for_keys(founders, selected, 2);

    Node* late = founders[1];
    const auto ready = [late] {
        const EpochManager* epochs = late->runtime->epochs();
        return epochs != nullptr && epochs->transition() != nullptr &&
               epochs->transition()->phase == EpochTransitionPhase::Ready;
    };
    for (int i = 0; i < 900 && !ready(); ++i) {
        step(1);
        answer_final_challenges();
    }
    ASSERT_TRUE(ready()) << "the member never held the DKG outcome";
    mesh.drop_if = [late](const Queued& item, const SecurityMessage& message) {
        const bool consensus = message.kind == SecurityMessageKind::HotStuffProposal ||
                               message.kind == SecurityMessageKind::HotStuffVote ||
                               message.kind == SecurityMessageKind::HotStuffTimeout;
        return consensus && (item.to == late->id || item.from == late->id);
    };

    std::vector<Node*> others;
    for (Node* founder : founders) {
        if (founder != late) others.push_back(founder);
    }
    run_to_activation(founders, others, 2);
    ASSERT_EQ(late->driver->current_epoch(), 1u) << "the member's own commit cannot have come";

    for (int i = 0; i < 60 && late->driver->current_epoch() != 2u; ++i) {
        step(1);
    }
    EXPECT_EQ(late->driver->current_epoch(), 2u);
    EXPECT_EQ(late->driver->phase(), DriverPhase::Active);
    EXPECT_TRUE(late->driver->is_tier1_member());
    ASSERT_TRUE(late->runtime->authority().key_epoch().has_value());
    EXPECT_EQ(*late->runtime->authority().key_epoch(), 2u);
    ASSERT_NE(late->driver->verified_authority(), nullptr);
    EXPECT_EQ(late->driver->verified_authority()->epoch, 2u);

    // Its consensus traffic flows again, and it commits with Epoch 2.
    mesh.drop_if = nullptr;
    const Height before = late->driver->last_committed_height();
    for (int i = 0; i < 800 && late->driver->last_committed_height() <= before; ++i) {
        step(1);
    }
    EXPECT_GT(late->driver->last_committed_height(), before);
}

// A modified anchor record never loads: the driver fails closed rather than
// resuming from state it cannot bind to its own digest.
TEST_F(MultiEpochMesh, ATamperedAnchorRecordFailsClosed) {
    bootstrap();
    run_until_committed(1);

    Node* member = founders[0];
    const fs::path anchor_file = member->dir / "security" / "authority-anchor.json";
    ASSERT_TRUE(fs::exists(anchor_file));
    // Flip one byte of the stored record.
    std::string text;
    {
        std::ifstream in(anchor_file);
        std::ostringstream buffer;
        buffer << in.rdbuf();
        text = buffer.str();
    }
    const auto pos = text.find("\"epoch\":1");
    ASSERT_NE(pos, std::string::npos);
    text.replace(pos, 9, "\"epoch\":2");
    {
        std::ofstream out(anchor_file, std::ios::trunc);
        out << text;
    }

    restart_node(*member);
    member->driver->start(mesh.now_ms);
    EXPECT_EQ(member->driver->phase(), DriverPhase::Failed);
}

// A member restarted at the boundary — a rolling release — resets its own
// epoch clock, so by that clock the epoch is young while every other member's
// says it is due. The aged members commit the eligibility state and the plan
// without waiting for it. It recognizes both commits from its own persisted
// facts, holds the plan, votes the readiness set and runs the ceremony. The
// alternative is what a fleet saw: its silence fails the attempt, its
// exclusion leaves a five-node pool unable to fill five seats, and the epoch
// holds for as long as the processes live.
TEST_F(MultiEpochMesh, AMemberRestartedAtTheBoundaryFollowsTheCommittedStages) {
    bootstrap();
    run_until_committed(1);
    observe(founders, founders, 1);

    mesh.now_ms += constants::kTargetEpochSeconds * 1000;
    Node* restarted = founders[2];
    // Observation writes are coalesced to one per second, so the verdicts
    // from `observe` may still wait for a tick. Flush them: this scenario is
    // a rolling release, where the service stops cleanly, and the restarted
    // member has to rebuild the state the mesh already agreed on from its
    // own durable facts.
    restarted->driver->flush_durable_state();
    restart_node(*restarted);
    restarted->driver->start(mesh.now_ms);
    for (int i = 0; i < 200 && restarted->driver->phase() != DriverPhase::Active; ++i) {
        step(1);
    }
    ASSERT_EQ(restarted->driver->phase(), DriverPhase::Active);
    ASSERT_EQ(restarted->driver->current_epoch(), 1u);

    const auto planned = [&] {
        return std::all_of(founders.begin(), founders.end(), [](Node* member) {
            const auto* transition = member->runtime->epochs()->transition();
            return transition != nullptr &&
                   transition->phase != EpochTransitionPhase::Aborted;
        });
    };
    for (int i = 0; i < 2500 && !planned(); ++i) {
        step(1);
    }
    ASSERT_TRUE(planned()) << "the restarted member never recognized the committed stages";
    const auto selected = selected_nodes(*founders.front());
    ASSERT_EQ(ids_of(selected), ids_of(founders));
    EXPECT_EQ(latest_plan().attempt, 0u);

    wait_for_keys(founders, selected, 2);
    run_to_activation(founders, selected, 2);
    EXPECT_EQ(restarted->driver->current_epoch(), 2u);
    EXPECT_TRUE(restarted->driver->is_tier1_member());
    EXPECT_EQ(latest_plan().attempt, 0u) << "the restart cost no attempt";
}

// A member the boundary leaves out voted the handoff that ended its epoch.
// It keeps no state of an epoch it holds no role in: it continues as Tier 2
// on the verified authority, a restart keeps it there, and the next plan
// that names it finds a node able to adopt and serve.
TEST_F(MultiEpochMesh, AMemberLeftOutAtActivationContinuesAsTierTwoAndIsReadmitted) {
    bootstrap();
    run_until_committed(1);
    introduce_reserves();

    // Seven eligible, five seats: selection leaves two online nodes out.
    std::vector<Node*> pool = founders;
    pool.push_back(reserves[0]);
    pool.push_back(reserves[1]);
    std::vector<Node*> members = rotate(founders, pool, 1);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    Node* left_out = nullptr;
    for (Node* founder : founders) {
        if (std::find(members.begin(), members.end(), founder) == members.end()) {
            left_out = founder;
            break;
        }
    }
    ASSERT_NE(left_out, nullptr) << "selection kept every founder; the scenario needs one out";

    EXPECT_EQ(left_out->driver->phase(), DriverPhase::Idle);
    EXPECT_EQ(left_out->runtime->epochs(), nullptr);
    EXPECT_EQ(left_out->runtime->consensus(), nullptr);
    EXPECT_FALSE(left_out->driver->is_tier1_member());
    ASSERT_NE(left_out->driver->verified_authority(), nullptr);
    EXPECT_EQ(left_out->driver->verified_authority()->epoch, 2u);
    EXPECT_EQ(left_out->driver->verified_authority()->members,
              members.front()->runtime->epochs()->current().tier1_members.members());

    restart_node(*left_out);
    left_out->driver->start(mesh.now_ms);
    EXPECT_EQ(left_out->driver->phase(), DriverPhase::Idle);
    EXPECT_EQ(left_out->runtime->epochs(), nullptr);
    ASSERT_NE(left_out->driver->verified_authority(), nullptr);
    EXPECT_EQ(left_out->driver->verified_authority()->epoch, 2u);

    // Next boundary: one member rests, so the pool is exactly the five seats
    // and the plan must name the node that was left out.
    Node* resting = members.back();
    mesh.offline.insert(resting->id);
    members.erase(std::remove(members.begin(), members.end(), resting), members.end());
    for (Node* member : members) member->driver->on_peer(left_out->id, mesh.now_ms);
    pool = members;
    pool.push_back(left_out);
    members = rotate(members, pool, 2);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    EXPECT_EQ(ids_of(members), ids_of(pool));
    EXPECT_TRUE(left_out->driver->is_tier1_member());
    EXPECT_EQ(left_out->driver->current_epoch(), 3u);
    ASSERT_TRUE(left_out->runtime->authority().key_epoch().has_value());
    EXPECT_EQ(*left_out->runtime->authority().key_epoch(), 3u);
}

// A stored epoch that names this node in no role — what an earlier release
// wrote for a node an activation left out — is not resumed. The node starts
// as Tier 2 on its verified authority, so a plan can name and adopt it.
TEST_F(MultiEpochMesh, AStoredEpochWithoutARoleRestartsAsTierTwo) {
    bootstrap();
    run_until_committed(1);
    introduce_reserves();
    const auto members = rotate(founders, founders, 1);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());

    // The reserve walks the verified chain to the head, so the stored epoch
    // it is about to hold authenticates against its own proof chain.
    Node* reserve = reserves[0];
    for (int i = 0; i < 80; ++i) {
        step(1, members);
        reserve->driver->tick(mesh.now_ms);
        mesh.pump();
        if (reserve->driver->verified_authority() != nullptr &&
            reserve->driver->verified_authority()->epoch == 2u) {
            break;
        }
    }
    ASSERT_NE(reserve->driver->verified_authority(), nullptr);
    ASSERT_EQ(reserve->driver->verified_authority()->epoch, 2u);

    fs::copy_file(members.front()->store->directory() / "epoch-current.json",
                  reserve->store->directory() / "epoch-current.json",
                  fs::copy_options::overwrite_existing);
    restart_node(*reserve);
    reserve->driver->start(mesh.now_ms);
    EXPECT_EQ(reserve->driver->phase(), DriverPhase::Idle);
    EXPECT_EQ(reserve->runtime->epochs(), nullptr);
    EXPECT_FALSE(reserve->driver->is_tier1_member());
    ASSERT_NE(reserve->driver->verified_authority(), nullptr);
    EXPECT_EQ(reserve->driver->verified_authority()->epoch, 2u);
}

}  // namespace
}  // namespace lifecycle_test
