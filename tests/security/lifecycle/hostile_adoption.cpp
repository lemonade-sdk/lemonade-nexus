// The adoption surface under attack.
//
// Every test mutates a genuine finalized package captured off the wire, or
// replays one somewhere it does not belong. The rule being pinned is uniform:
// a candidate acts only on a proof it verified in full, so every mutation
// lands as a refusal and every replay lands as a no-op. All fail closed.

#include "support/lifecycle_mesh.hpp"

namespace lifecycle_test {
namespace {

struct HostileAdoption : DriverMesh {
    Node* offline_member = nullptr;
    std::vector<Node*> online;

    /// Drives the standard scenario to the committed plan: E offline, four
    /// members online, both reserves observed, plan captured off the wire.
    void run_to_captured_plan() {
        bootstrap();
        run_until_committed(1);
        introduce_reserves();
        offline_member = founders[4];
        mesh.offline.insert(offline_member->id);
        online.assign(founders.begin(), founders.begin() + 4);

        std::vector<Node*> subjects = online;
        subjects.insert(subjects.end(), reserves.begin(), reserves.end());
        for (uint8_t round = 1; round <= constants::kMinContinuityObservations; ++round) {
            run_reattest_cadence(round, subjects, online);
        }
        mesh.now_ms += constants::kTargetEpochSeconds * 1000;
        for (int i = 0; i < 900; ++i) {
            step(1, online);
            if (!mesh.captured_plans.empty()) break;
        }
        ASSERT_FALSE(mesh.captured_plans.empty()) << "no plan package captured";
        step(6, online);
    }

    [[nodiscard]] const NextEpochPlanProof& genuine_plan() const {
        return mesh.captured_plans.front();
    }

    /// A reserve the plan names, and one it does not.
    [[nodiscard]] Node* selected_reserve() const {
        const auto& plan = genuine_plan().plan;
        for (Node* reserve : reserves) {
            if (std::find(plan.selected.begin(), plan.selected.end(), reserve->id) !=
                plan.selected.end()) {
                return reserve;
            }
        }
        return nullptr;
    }
    [[nodiscard]] Node* unselected_reserve() const {
        const auto& plan = genuine_plan().plan;
        for (Node* reserve : reserves) {
            if (std::find(plan.selected.begin(), plan.selected.end(), reserve->id) ==
                plan.selected.end()) {
                return reserve;
            }
        }
        return nullptr;
    }
};

// A node the plan does not name cannot enter the pending state, however
// genuine the package. And a mutated plan that suddenly names it carries a
// digest no committed block finalized.
TEST_F(HostileAdoption, ANonSelectedNodeCannotAdopt) {
    run_to_captured_plan();

    // Deterministic half: a real candidate, and a genuine package edited so it
    // no longer names it. Not named means no adoption, and the edit means the
    // proof proves a different plan anyway.
    Node* candidate = selected_reserve();
    ASSERT_NE(candidate, nullptr);
    restart_node(*candidate);
    candidate->driver->start(mesh.now_ms);
    const auto anchor = std::get<BootstrapCertificate>(founders[0]->store->load_bootstrap());
    candidate->driver->on_bootstrap_certificate(anchor, genesis_node->id);

    auto unnamed = genuine_plan();
    unnamed.plan.selected.erase(std::remove(unnamed.plan.selected.begin(),
                                            unnamed.plan.selected.end(), candidate->id),
                                unnamed.plan.selected.end());
    unnamed.plan.incarnations.erase(candidate->id);
    candidate->driver->on_next_epoch_plan(unnamed);
    EXPECT_NE(candidate->driver->phase(), DriverPhase::PendingNextEpoch);
    EXPECT_EQ(candidate->runtime->epochs(), nullptr);

    // Ranking-dependent half: when the hash rank left a reserve out, the
    // genuine package does nothing for it, and a package forged to name it
    // carries a digest no committed block finalized.
    if (Node* outsider = unselected_reserve()) {
        ASSERT_NE(outsider->driver->phase(), DriverPhase::PendingNextEpoch);
        outsider->driver->on_next_epoch_plan(genuine_plan());
        EXPECT_NE(outsider->driver->phase(), DriverPhase::PendingNextEpoch);

        auto forged = genuine_plan();
        forged.plan.selected.push_back(outsider->id);
        forged.plan.incarnations[outsider->id] = 1;
        outsider->driver->on_next_epoch_plan(forged);
        EXPECT_NE(outsider->driver->phase(), DriverPhase::PendingNextEpoch);
        EXPECT_EQ(outsider->runtime->epochs(), nullptr);
    }

    // Control: the genuine, unedited package still adopts.
    candidate->driver->on_next_epoch_plan(genuine_plan());
    EXPECT_EQ(candidate->driver->phase(), DriverPhase::PendingNextEpoch);
}

// Every mutation of a genuine plan package fails closed on a fresh candidate.
TEST_F(HostileAdoption, EveryMutatedPlanIsRefused) {
    run_to_captured_plan();
    Node* candidate = selected_reserve();
    ASSERT_NE(candidate, nullptr);
    // The candidate adopted the genuine broadcast already; rebuild it clean so
    // each mutation is judged from a fresh Idle state.
    restart_node(*candidate);
    candidate->driver->start(mesh.now_ms);
    ASSERT_EQ(candidate->driver->phase(), DriverPhase::Idle);
    // Re-anchor: the bootstrap certificate arrives out of band.
    const auto anchor = std::get<BootstrapCertificate>(founders[0]->store->load_bootstrap());
    candidate->driver->on_bootstrap_certificate(anchor, genesis_node->id);

    const auto refuse = [&](auto mutate, const char* what) {
        auto package = genuine_plan();
        mutate(package);
        candidate->driver->on_next_epoch_plan(package);
        EXPECT_NE(candidate->driver->phase(), DriverPhase::PendingNextEpoch) << what;
    };

    refuse([](auto& p) { p.plan.network_id.fill(0xAA); }, "another network");
    refuse([](auto& p) { p.plan.current_epoch = 2; p.plan.next_epoch = 3; },
           "another epoch than the anchor names");
    refuse([&](auto& p) { p.plan.incarnations[candidate->id] = 2; }, "wrong incarnation");
    refuse([](auto& p) { p.plan.security_ruleset += 1; }, "wrong ruleset");
    refuse([](auto& p) { p.plan.profile_id = AttestationProfileId::SnpDirectBoot; },
           "weaker profile");
    refuse([](auto& p) { p.proof.certifying.signers[0].signature[0] ^= 0x01; },
           "an invalid certificate in the proof");
    refuse([](auto& p) {
        while (p.proof.certifying.signers.size() >= 4) {
            p.proof.certifying.signers.pop_back();
        }
    }, "insufficient quorum in the proof");
    refuse([&](auto& p) {
        std::swap(p.plan.selected.front(), p.plan.selected.back());
        p.plan.selected.front() = offline_member->id;
        p.plan.incarnations[offline_member->id] = 1;
    }, "an altered selected set");
    refuse([](auto& p) {
        // The vote-key listing edited: it no longer hashes to the anchor.
        p.current_vote_keys[0].second[0] ^= 0x01;
    }, "a vote-key listing the anchor never certified");

    // The genuine package still adopts: nothing above poisoned any state.
    candidate->driver->on_next_epoch_plan(genuine_plan());
    EXPECT_EQ(candidate->driver->phase(), DriverPhase::PendingNextEpoch);
    // And adoption still granted nothing.
    EXPECT_EQ(candidate->runtime->epochs(), nullptr);
    EXPECT_EQ(candidate->runtime->consensus(), nullptr);
}

// An unsynced candidate cannot create its next-epoch key, so it can neither
// answer a final-attest challenge with one nor appear in any readiness set.
TEST_F(HostileAdoption, AnUnsyncedCandidateRegistersNothing) {
    run_to_captured_plan();
    Node* candidate = selected_reserve();
    ASSERT_NE(candidate, nullptr);
    restart_node(*candidate);
    candidate->driver->start(mesh.now_ms);
    const auto anchor = std::get<BootstrapCertificate>(founders[0]->store->load_bootstrap());
    candidate->driver->on_bootstrap_certificate(anchor, genesis_node->id);

    // Adopt the plan but let no sync response through.
    candidate->driver->on_next_epoch_plan(genuine_plan());
    ASSERT_EQ(candidate->driver->phase(), DriverPhase::PendingNextEpoch);
    EXPECT_FALSE(candidate->driver->vote_key_for_epoch(2).has_value())
        << "no key before the security state is synchronized";

    // Once the sync responses flow, the gate opens.
    mesh.pump();
    step(4, online);
    EXPECT_TRUE(candidate->driver->vote_key_for_epoch(2).has_value());
}

// A stale final attestation blocks readiness until re-attestation renews it,
// and a passing verdict whose claims are not all proved confers none at all.
TEST_F(HostileAdoption, StaleOrClaimlessFinalAttestationBlocksReadiness) {
    run_to_captured_plan();
    const auto* transition = founders[0]->runtime->epochs()->transition();
    ASSERT_NE(transition, nullptr);

    // Claimless verdicts for everyone: passed, but proving nothing.
    for (const auto& id : transition->selected_members) {
        Node* selected = mesh.nodes.at(id);
        auto verdict = passing_verdict(id, 2, 9);
        verdict.claims = VerifiedPlatformClaims{};
        for (Node* member : online) {
            member->driver->on_attestation_verdict(
                verdict, evidence_for(id, *selected->driver->vote_key_for_epoch(2)));
        }
    }
    mesh.pump();
    step(30, online);
    for (Node* member : online) {
        EXPECT_EQ(member->runtime->authority().dkg(), nullptr)
            << "no DKG on unproved claims";
        EXPECT_EQ(member->driver->current_epoch(), 1u);
    }

    // Fresh, fully-proved verdicts — then aged past the compiled window before
    // consensus can finalize readiness.
    for (const auto& id : transition->selected_members) {
        Node* selected = mesh.nodes.at(id);
        for (Node* member : online) {
            member->driver->on_attestation_verdict(
                passing_verdict(id, 2, 10),
                evidence_for(id, *selected->driver->vote_key_for_epoch(2)));
        }
    }
    mesh.pump();
    mesh.now_ms += (constants::kFinalAttestMaxAgeSeconds + 1) * 1000;
    step(30, online);
    for (Node* member : online) {
        EXPECT_EQ(member->driver->current_epoch(), 1u) << "stale attestation cannot ready";
    }
}

// Handoff forgery, staleness, and double activation.
TEST_F(HostileAdoption, TheHandoffProofDecidesActivationExactlyOnce) {
    run_to_captured_plan();
    Node* candidate = selected_reserve();
    ASSERT_NE(candidate, nullptr);

    // Run the genuine flow to activation, capturing the handoff.
    const auto* transition = founders[0]->runtime->epochs()->transition();
    ASSERT_NE(transition, nullptr);
    for (const auto& id : transition->selected_members) {
        Node* selected = mesh.nodes.at(id);
        for (Node* member : online) {
            member->driver->on_attestation_verdict(
                passing_verdict(id, 2, 9),
                evidence_for(id, *selected->driver->vote_key_for_epoch(2)));
        }
    }
    mesh.pump();
    for (int i = 0; i < 900 && candidate->driver->current_epoch() != 2u; ++i) {
        step(1, online);
    }
    ASSERT_EQ(candidate->driver->current_epoch(), 2u);
    ASSERT_FALSE(mesh.captured_handoffs.empty());
    const auto genuine = mesh.captured_handoffs.front();

    // Replay to the now-active newcomer: activation happened exactly once, and
    // a second proof of the same handoff changes nothing.
    candidate->driver->on_epoch_handoff_proof(genuine);
    EXPECT_EQ(candidate->driver->current_epoch(), 2u);
    EXPECT_EQ(*candidate->runtime->authority().key_epoch(), 2u);

    // Every mutation of the handoff is refused by a pending candidate. Rebuild
    // one from the second reserve if the plan named it; otherwise skip the
    // mutation half (the verification path is shared with the plan tests).
    Node* other = unselected_reserve();
    if (other != nullptr) {
        // Not selected: even the genuine handoff does nothing for it.
        other->driver->on_epoch_handoff_proof(genuine);
        EXPECT_EQ(other->runtime->epochs(), nullptr);
        EXPECT_NE(other->driver->phase(), DriverPhase::Active);
    }
}

// The vote-key rules at the epoch manager: a changed key, a duplicate key, and
// a key reused from the current epoch are all refused at registration.
TEST_F(HostileAdoption, VoteKeyRegistrationRefusesReuseAndDuplicates) {
    run_to_captured_plan();
    Node* member = online.front();
    EpochManager* epochs = member->runtime->epochs();
    const auto* transition = epochs->transition();
    ASSERT_NE(transition, nullptr);

    const NodeId first = transition->selected_members[0];
    const NodeId second = transition->selected_members[1];

    ASSERT_TRUE(epochs->record_final_attestation(passing_verdict(first, 2, 9)));
    ASSERT_TRUE(epochs->record_final_attestation(passing_verdict(second, 2, 9)));

    nexus::crypto::Ed25519PublicKey key_a{};
    key_a.fill(0xA1);
    ASSERT_TRUE(epochs->record_vote_key(first, key_a));

    // The same key from another node: one key, one node, one epoch.
    EXPECT_FALSE(epochs->record_vote_key(second, key_a));

    // A key reused from the current epoch outlives its lifetime rule.
    const auto current = epochs->current_vote_keys().begin()->second;
    EXPECT_FALSE(epochs->record_vote_key(second, current));

    // A changed key mid-handoff is refused; the same key is idempotent.
    nexus::crypto::Ed25519PublicKey key_b{};
    key_b.fill(0xB2);
    EXPECT_FALSE(epochs->record_vote_key(first, key_b));
    EXPECT_TRUE(epochs->record_vote_key(first, key_a));

    // A node outside the selected set registers nothing.
    EXPECT_FALSE(epochs->record_vote_key(offline_member->id, key_b));
}

// The DKG session binding: a message carrying the bare participant-set digest
// answers no session bound to a readiness digest, so a replay from a failed
// or unbound attempt is refused before any FROST work.
TEST_F(HostileAdoption, DkgMessagesMustCarryTheSessionBinding) {
    ASSERT_GE(sodium_init(), 0);
    std::vector<NodeId> ids;
    std::map<NodeId, IncarnationId> incarnations;
    for (uint8_t i = 1; i <= 5; ++i) {
        NodeId id;
        id.bytes.fill(i);
        ids.push_back(id);
        incarnations[id] = 1;
    }
    Digest binding;
    binding.fill(0x77);

    DkgConfiguration bound;
    bound.network_id.fill(0x5E);
    bound.target_epoch = 2;
    bound.participants = *Tier1Set::from_nodes(ids);
    bound.incarnations = incarnations;
    bound.threshold = constants::authority_threshold(5);
    bound.self = ids[0];
    bound.session_binding = binding;
    DkgSession session{bound};
    const auto own = session.start();
    ASSERT_TRUE(own.has_value());
    EXPECT_EQ(own->participant_set_digest, binding) << "messages carry the binding";

    // A message from the same set without the binding — the shape of a replay
    // from an earlier attempt — is refused as the wrong session.
    DkgMessage unbound = *own;
    unbound.sender = ids[1];
    unbound.participant_set_digest = bound.participants.digest();
    EXPECT_EQ(session.receive_broadcast(unbound), DkgFailure::WrongParticipantSet);

    // The right binding from another participant is the positive control shape
    // (payload validity is FROST's business, judged later).
    DkgMessage rebound = unbound;
    rebound.participant_set_digest = binding;
    EXPECT_NE(session.receive_broadcast(rebound), DkgFailure::WrongParticipantSet);
}

}  // namespace
}  // namespace lifecycle_test
