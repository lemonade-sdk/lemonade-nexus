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

#include "support/lifecycle_mesh.hpp"

namespace lifecycle_test {
namespace {

struct MultiEpochMesh : DriverMeshBase {
    MultiEpochMesh() : DriverMeshBase(5) {}

    /// Continuity and participation for `pool` under the current members.
    /// Every current member first learns the reachable reserves: a member
    /// promoted last epoch challenges candidates exactly like a founder.
    void observe(const std::vector<Node*>& members, const std::vector<Node*>& pool,
                 EpochId epoch) {
        for (Node* member : members) {
            for (Node* reserve : reserves) {
                if (!mesh.offline.contains(reserve->id)) {
                    member->driver->on_peer(reserve->id, mesh.now_ms);
                }
            }
        }
        for (uint8_t round = 1; round <= constants::kMinContinuityObservations; ++round) {
            run_reattest_cadence(round, pool, members, epoch);
        }
        // Participation witnessing accumulates one leader rotation at a time;
        // a real epoch has an hour of views, the compressed one gets commits
        // until every pool subject met its witness bar on every member.
        for (int i = 0; i < 40; ++i) {
            bool complete = true;
            for (Node* member : members) {
                const auto& service = member->driver->eligibility();
                for (Node* subject : pool) {
                    if (subject == member) continue;
                    const auto evidence =
                        service.ledger().evaluate(subject->id, 1, service.context());
                    if (!evidence.mesh_health_valid || !evidence.uptime_valid) {
                        complete = false;
                        break;
                    }
                }
                if (!complete) break;
            }
            if (complete) return;
            advance_commit(members);
        }
    }

    /// Ages the epoch and steps until every online member opened a transition.
    void run_to_plan(const std::vector<Node*>& members, int max_steps = 1500) {
        mesh.now_ms += constants::kTargetEpochSeconds * 1000;
        for (int i = 0; i < max_steps; ++i) {
            step(1, members);
            const bool planned = std::all_of(members.begin(), members.end(), [](Node* m) {
                return m->runtime->epochs() != nullptr &&
                       m->runtime->epochs()->transition() != nullptr &&
                       m->runtime->epochs()->transition()->phase !=
                           EpochTransitionPhase::Aborted;
            });
            if (planned) return;
        }
        FAIL() << "no plan committed within " << max_steps << " steps";
    }

    [[nodiscard]] std::vector<Node*> selected_nodes(const Node& member) const {
        std::vector<Node*> out;
        if (member.runtime->epochs() == nullptr) {
            ADD_FAILURE() << "member holds no epoch state";
            return out;
        }
        const auto* transition = member.runtime->epochs()->transition();
        EXPECT_NE(transition, nullptr);
        if (transition != nullptr) {
            for (const auto& id : transition->selected_members) {
                out.push_back(mesh.nodes.at(id));
            }
        }
        return out;
    }

    /// Steps until every selected node can present its next-epoch vote key,
    /// which for an outside candidate means its state sync completed.
    void wait_for_keys(const std::vector<Node*>& members, const std::vector<Node*>& selected,
                       EpochId target, int max_steps = 600) {
        for (int i = 0; i < max_steps; ++i) {
            step(1, members);
            const bool keyed = std::all_of(selected.begin(), selected.end(), [&](Node* node) {
                return mesh.offline.contains(node->id) ||
                       node->driver->vote_key_for_epoch(target).has_value();
            });
            if (keyed) return;
        }
        FAIL() << "selected nodes could not register keys within " << max_steps << " steps";
    }

    void run_to_activation(const std::vector<Node*>& members,
                           const std::vector<Node*>& expect_active, EpochId target,
                           int max_steps = 1500) {
        for (int i = 0; i < max_steps; ++i) {
            step(1, members);
            const bool active =
                std::all_of(expect_active.begin(), expect_active.end(), [&](Node* n) {
                    return n->driver->current_epoch() == target;
                });
            if (active) return;
        }
        FAIL() << "epoch " << target << " did not activate within " << max_steps << " steps";
    }

    /// One full rotation on the production path. `pool` is who the mesh
    /// observes this epoch; selection decides from there. Returns the new
    /// member set.
    std::vector<Node*> rotate(const std::vector<Node*>& members, const std::vector<Node*>& pool,
                              EpochId from_epoch) {
        observe(members, pool, from_epoch);
        run_to_plan(members);
        const auto selected = selected_nodes(*members.front());
        if (::testing::Test::HasFatalFailure() || selected.empty()) {
            return members;  // The failure is recorded; do not compound it.
        }
        wait_for_keys(members, selected, from_epoch + 1);
        if (::testing::Test::HasFatalFailure()) {
            return members;
        }
        final_attest_subjects(9, selected, members);
        run_to_activation(members, selected, from_epoch + 1);
        return selected;
    }

    [[nodiscard]] static std::vector<NodeId> ids_of(const std::vector<Node*>& nodes_in) {
        std::vector<NodeId> ids;
        for (const Node* node : nodes_in) ids.push_back(node->id);
        std::sort(ids.begin(), ids.end());
        return ids;
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
    // Its stored epoch is history. First run: it syncs into silence, walks
    // the chain, and advances only its ANCHOR — the stale membership yields
    // no vote and no progress. Second run: the advanced anchor supersedes the
    // stored epoch and it resumes as Tier 2.
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
    // Still only availability lost: it never rejoined its dead epoch.
    EXPECT_EQ(demoted->driver->phase(), DriverPhase::Syncing);

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
        return replacement_selected;
    };

    // Transition one: E offline; F and G qualified; the promoted one refuses
    // and the other replaces it under a fresh plan and a fresh ceremony.
    mesh.offline.insert(founders[4]->id);
    std::vector<Node*> members(founders.begin(), founders.begin() + 4);
    members = refusal_rotation(members, {reserves[0], reserves[1]}, 1);
    EXPECT_EQ(members.front()->driver->current_epoch(), 2u);

    // Transition two: the same attack from a different candidate pair, one
    // epoch later. History does not soften the rule.
    std::vector<Node*> online;
    for (Node* member : members) {
        if (!mesh.offline.contains(member->id)) online.push_back(member);
    }
    members = refusal_rotation(online, {reserves[2], reserves[3]}, 2);
    EXPECT_EQ(members.front()->driver->current_epoch(), 3u);
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

}  // namespace
}  // namespace lifecycle_test
