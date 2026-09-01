// Tier 2 to Tier 1, end to end on the production path.
//
// The whole ladder: certificate, platform eligibility, continuity,
// participation, finalized eligibility, deterministic selection, the finalized
// plan, the pending state, security-state sync, fresh final attestation, the
// next-epoch vote key, finalized readiness, the DKG, the finalized handoff, and
// activation. Every rung is a verified proof; no rung grants anything before
// the last one.

#include "support/lifecycle_mesh.hpp"

namespace lifecycle_test {
namespace {

struct AdoptionPath : DriverMesh {
    /// Drives the mesh with `online` members observing `subjects` until both
    /// facts hold for all of them.
    void observe_online(const std::vector<Node*>& online, const std::vector<Node*>& subjects) {
        for (uint8_t round = 1; round <= constants::kMinContinuityObservations; ++round) {
            run_reattest_cadence(round, subjects, online);
        }
    }

    /// Steps until every online member finalized the eligibility state and
    /// committed the plan for the next epoch.
    void run_to_plan(const std::vector<Node*>& online, int max_steps = 900) {
        mesh.now_ms += constants::kTargetEpochSeconds * 1000;
        for (int i = 0; i < max_steps; ++i) {
            step(1, online);
            const bool planned = std::all_of(online.begin(), online.end(), [](Node* f) {
                return f->runtime->epochs() != nullptr &&
                       f->runtime->epochs()->transition() != nullptr;
            });
            if (planned) return;
        }
        FAIL() << "no plan committed within " << max_steps << " steps";
    }

    /// The next-epoch members outside the current set, per the committed plan.
    [[nodiscard]] std::vector<Node*> newcomers(const Node& member) const {
        std::vector<Node*> outside;
        const auto* transition = member.runtime->epochs()->transition();
        if (transition == nullptr) {
            return outside;
        }
        const auto& current = member.runtime->epochs()->current().tier1_members;
        for (const auto& node : transition->selected_members) {
            if (!current.contains(node)) {
                outside.push_back(mesh.nodes.at(node));
            }
        }
        return outside;
    }

    /// Injects the fresh final-attestation verdicts for every selected node,
    /// into every online member. Candidates must have created their next-epoch
    /// keys already, which requires their state sync to have completed.
    void inject_final_verdicts(const std::vector<Node*>& online, EpochId target,
                               uint8_t round = 9) {
        const auto* transition = online.front()->runtime->epochs()->transition();
        ASSERT_NE(transition, nullptr);
        for (const auto& id : transition->selected_members) {
            Node* selected = mesh.nodes.at(id);
            const auto vote_key = selected->driver->vote_key_for_epoch(target);
            ASSERT_TRUE(vote_key.has_value())
                << "selected node cannot register a key yet";
            for (Node* member : online) {
                member->driver->on_attestation_verdict(
                    final_verdict(latest_plan(), id, round),
                    evidence_for(id, *vote_key));
            }
        }
        mesh.pump();
    }

    /// Steps until every node in `expect_active` runs the target epoch.
    void run_to_activation(const std::vector<Node*>& online,
                           const std::vector<Node*>& expect_active, EpochId target,
                           int max_steps = 900) {
        for (int i = 0; i < max_steps; ++i) {
            step(1, online);
            const bool active =
                std::all_of(expect_active.begin(), expect_active.end(), [&](Node* n) {
                    return n->driver->current_epoch() == target;
                });
            if (active) return;
        }
        FAIL() << "epoch " << target << " did not activate within " << max_steps << " steps";
    }
};

// The scenario the milestone exists for: A B C D E with E offline, reserves F
// and G. The current epoch keeps its five seats and its quorum of four; the
// finalized pool replaces E; a reserve walks the whole ladder and serves in
// epoch 2.
TEST_F(AdoptionPath, AReserveReplacesAnOfflineMemberEndToEnd) {
    bootstrap();
    run_until_committed(1);
    introduce_reserves();

    Node* offline = founders[4];
    mesh.offline.insert(offline->id);
    std::vector<Node*> online(founders.begin(), founders.begin() + 4);
    const auto frozen_before = founders[0]->runtime->epochs()->current();

    // The mesh observes itself without E: members and reserves prove their
    // facts; E, unseen, proves nothing.
    std::vector<Node*> subjects = online;
    subjects.insert(subjects.end(), reserves.begin(), reserves.end());
    observe_online(online, subjects);

    // Eligibility finalizes and the plan commits, replacing E from the ranked
    // pool. The current epoch is untouched: five seats, quorum four.
    run_to_plan(online);
    const auto* transition = founders[0]->runtime->epochs()->transition();
    ASSERT_NE(transition, nullptr);
    EXPECT_EQ(transition->to_epoch, 2u);
    EXPECT_EQ(transition->selected_members.size(), constants::kMinActiveTier1);
    EXPECT_TRUE(std::find(transition->selected_members.begin(),
                          transition->selected_members.end(),
                          offline->id) == transition->selected_members.end())
        << "an unseen member cannot be selected";
    for (Node* member : online) {
        const auto& current = member->runtime->epochs()->current();
        EXPECT_EQ(current.tier1_members.size(), frozen_before.tier1_members.size());
        EXPECT_TRUE(current.tier1_members.contains(offline->id));
        EXPECT_EQ(current.consensus_quorum, frozen_before.consensus_quorum);
        EXPECT_EQ(current.authority_threshold, frozen_before.authority_threshold);
    }

    // At least one newcomer is in the plan (four incumbents remain for five
    // seats). Every newcomer verified the plan proof and entered the pending
    // state — permission to prepare and nothing else.
    const auto outside = newcomers(*founders[0]);
    ASSERT_FALSE(outside.empty());
    step(6, online);
    for (Node* candidate : outside) {
        EXPECT_EQ(candidate->driver->phase(), DriverPhase::PendingNextEpoch);
        EXPECT_EQ(candidate->runtime->epochs(), nullptr);
        EXPECT_EQ(candidate->runtime->consensus(), nullptr);
        EXPECT_FALSE(candidate->runtime->authority().group_public_key().has_value());
        EXPECT_FALSE(candidate->driver->is_tier1_member());
    }

    // Pending includes synced: the candidates asked for certified state, and
    // their sync responses cleared the plan checkpoint, so their next-epoch
    // keys exist now — the gate in vote_key_for_epoch has opened.
    for (Node* candidate : outside) {
        ASSERT_TRUE(candidate->driver->vote_key_for_epoch(2).has_value())
            << "the candidate synced and may create its key";
    }

    // Fresh final attestations for the whole selected set, readiness commits,
    // the DKG runs with the candidates participating, the handoff commits, and
    // epoch 2 activates everywhere it should.
    inject_final_verdicts(online, 2);
    std::vector<Node*> expect_active;
    for (const auto& id : transition->selected_members) {
        expect_active.push_back(mesh.nodes.at(id));
    }
    run_to_activation(online, expect_active, 2);

    for (Node* candidate : outside) {
        EXPECT_EQ(candidate->driver->phase(), DriverPhase::Active);
        EXPECT_EQ(candidate->driver->current_epoch(), 2u);
        EXPECT_TRUE(candidate->driver->is_tier1_member());
        ASSERT_NE(candidate->runtime->consensus(), nullptr);
        EXPECT_TRUE(candidate->runtime->consensus()->usable());
        EXPECT_TRUE(candidate->runtime->consensus()->synced());
        EXPECT_EQ(*candidate->runtime->authority().key_epoch(), 2u);
    }
    // E stayed in epoch 1: it was offline, not expelled mid-epoch.
    EXPECT_NE(offline->driver->current_epoch(), 2u);

    // The new epoch commits with the newcomers voting: the chain moves under
    // the new membership.
    std::vector<Node*> epoch_two_online;
    for (Node* node : expect_active) {
        epoch_two_online.push_back(node);
    }
    const Height before = epoch_two_online.front()->driver->last_committed_height();
    for (int i = 0; i < 300; ++i) {
        step(1, epoch_two_online);
        if (epoch_two_online.front()->driver->last_committed_height() > before) break;
    }
    EXPECT_GT(epoch_two_online.front()->driver->last_committed_height(), before);
}

// The zero-trust ladder, pinned rung by rung on one candidate: before the
// finalized handoff proof arrives, nothing the candidate holds is authority.
TEST_F(AdoptionPath, NothingBeforeTheHandoffGrantsAuthority) {
    bootstrap();
    run_until_committed(1);
    introduce_reserves();

    Node* offline = founders[4];
    mesh.offline.insert(offline->id);
    std::vector<Node*> online(founders.begin(), founders.begin() + 4);
    std::vector<Node*> subjects = online;
    subjects.insert(subjects.end(), reserves.begin(), reserves.end());
    observe_online(online, subjects);
    run_to_plan(online);
    const auto outside = newcomers(*founders[0]);
    ASSERT_FALSE(outside.empty());
    step(6, online);
    Node* candidate = outside.front();
    ASSERT_EQ(candidate->driver->phase(), DriverPhase::PendingNextEpoch);

    // Pending, synced, key created — and still: no epoch, no replica, no
    // authority key, no share, no membership. A forged vote from it is an
    // unknown signer.
    EXPECT_EQ(candidate->runtime->epochs(), nullptr);
    EXPECT_EQ(candidate->runtime->consensus(), nullptr);
    EXPECT_FALSE(candidate->runtime->authority().group_public_key().has_value());
    EXPECT_FALSE(candidate->runtime->authority().key_epoch().has_value());

    Vote forged;
    forged.consensus_ruleset = constants::kConsensusRulesetVersion;
    forged.network_id = network;
    forged.epoch = 1;
    forged.height = founders[0]->driver->last_committed_height() + 1;
    forged.view = founders[0]->runtime->consensus()->current_view();
    forged.proposal_digest.fill(0x5A);
    forged.voter = candidate->id;
    const auto outcome = founders[0]->runtime->consensus()->receive_vote(forged);
    ASSERT_TRUE(std::holds_alternative<ConsensusFailure>(outcome));
    EXPECT_EQ(std::get<ConsensusFailure>(outcome), ConsensusFailure::UnknownSigner);

    // After readiness and the DKG complete, the candidate holds a share it
    // prepared — still unusable: key_epoch stays empty until activation.
    inject_final_verdicts(online, 2);
    for (int i = 0; i < 300; ++i) {
        step(1, online);
        if (candidate->driver->current_epoch() == 2u) break;
        // While still pending, the prepared material confers nothing.
        EXPECT_FALSE(candidate->driver->is_tier1_member());
        EXPECT_FALSE(candidate->runtime->authority().key_epoch().has_value());
    }
    EXPECT_EQ(candidate->driver->current_epoch(), 2u);
    EXPECT_EQ(*candidate->runtime->authority().key_epoch(), 2u);
}

}  // namespace
}  // namespace lifecycle_test
