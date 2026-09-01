// Tier 2 on the live path: what an authenticated server that holds no epoch
// role can prove, what it still cannot do, and what happens to the mesh when a
// current member goes away.
//
// Joining the mesh is easy and gaining authority is hard. These tests pin both
// halves of that: a reserve can accumulate every fact Tier 1 eligibility needs
// without ever being Tier 1, and it gains nothing at all until a finalized
// eligibility state and a deterministic selection say so.

#include "support/lifecycle_mesh.hpp"

namespace lifecycle_test {
namespace {

struct Tier2Path : DriverMesh {
    /// Drives the mesh until every named subject holds both mesh facts on
    /// every current member. Reserves prove participation by answering the
    /// challenge-response; members prove it by voting.
    void observe(const std::vector<Node*>& subjects) {
        for (uint8_t round = 1; round <= constants::kMinContinuityObservations; ++round) {
            run_reattest_cadence(round, subjects);
        }
    }

    [[nodiscard]] MeshFactEvidence evidence_for_subject(const Node& observer,
                                                        const Node& subject) const {
        const auto& service = eligibility_of(observer);
        return service.ledger().evaluate(
            subject.id,
            service.ledger().quorum_incarnation(subject.id, service.context()).value_or(1),
            service.context());
    }
};

// A reserve is an ordinary authenticated server. It can be seen, attested and
// challenged, and every fact Tier 1 needs can be established about it — by the
// current committee, never by itself.
TEST_F(Tier2Path, AReserveCanProveEveryFactWithoutBeingTierOne) {
    bootstrap();
    run_until_committed(1);
    introduce_reserves();

    std::vector<Node*> subjects = founders;
    subjects.insert(subjects.end(), reserves.begin(), reserves.end());
    observe(subjects);

    for (Node* reserve : reserves) {
        // It is not in the committee, so it faces the full quorum of witnesses.
        const auto evidence = evidence_for_subject(*founders[0], *reserve);
        EXPECT_EQ(evidence.quorum_required, constants::consensus_quorum(kFounders));
        EXPECT_TRUE(evidence.uptime_valid) << "continuity";
        EXPECT_TRUE(evidence.mesh_health_valid) << "participation";
        EXPECT_GE(evidence.claim_observers, evidence.quorum_required);

        // Which makes it eligible, on every honest member, identically.
        for (Node* founder : founders) {
            EXPECT_TRUE(eligible_in(*founder, reserve->id, 2));
        }
    }

    // And every member still agrees on one state.
    const Digest agreed = commitment_of(*founders[0], 2);
    for (Node* founder : founders) {
        EXPECT_EQ(commitment_of(*founder, 2), agreed);
    }
}

// The participation half specifically: a reserve holds no epoch vote key and
// cannot produce a HotStuff vote, so the vote-based emitter can never speak for
// it. The challenge-response is what fills the gap, and it is a real exchange
// over the wire rather than a packet count.
TEST_F(Tier2Path, ParticipationForANonVoterComesFromTheSignedExchange) {
    bootstrap();
    run_until_committed(1);
    introduce_reserves();

    Node* reserve = reserves[0];
    ASSERT_EQ(reserve->runtime->consensus(), nullptr) << "a reserve runs no replica";
    ASSERT_FALSE(reserve->driver->vote_key_for_epoch(1).has_value() &&
                 founders[0]->runtime->epochs()->current_vote_keys().contains(reserve->id))
        << "and holds no registered epoch vote key";

    // Before the cadence runs, nobody has said anything about it.
    EXPECT_EQ(evidence_for_subject(*founders[0], *reserve).participation_observers, 0u);

    run_reattest_cadence(1, {reserve});
    const auto evidence = evidence_for_subject(*founders[0], *reserve);
    EXPECT_EQ(evidence.participation_observers, kFounders)
        << "every member challenged it and verified the answer";

    // A member's own participation still comes from its votes, unchanged.
    const auto member = evidence_for_subject(*founders[0], *founders[1]);
    EXPECT_GT(member.participation_observers, 0u);
}

// The zero-trust boundary. Proving participation is evidence and not a role: a
// reserve that has proved everything still holds no consensus, no authority
// key, no epoch state, and no membership, and the mesh refuses anything it
// tries to do with those.
TEST_F(Tier2Path, ProvingParticipationGrantsNoAuthority) {
    bootstrap();
    run_until_committed(1);
    introduce_reserves();
    std::vector<Node*> subjects = founders;
    subjects.insert(subjects.end(), reserves.begin(), reserves.end());
    observe(subjects);

    Node* reserve = reserves[0];
    ASSERT_TRUE(eligible_in(*founders[0], reserve->id, 2)) << "it did prove every fact";

    // No epoch role of any kind.
    EXPECT_EQ(reserve->runtime->epochs(), nullptr);
    EXPECT_EQ(reserve->runtime->consensus(), nullptr);
    EXPECT_FALSE(reserve->runtime->authority().group_public_key().has_value());
    EXPECT_FALSE(reserve->runtime->authority().key_epoch().has_value());
    EXPECT_EQ(reserve->runtime->authority().dkg(), nullptr);
    EXPECT_FALSE(reserve->driver->is_tier1_member());
    EXPECT_FALSE(reserve->driver->current_epoch().has_value());
    EXPECT_EQ(reserve->driver->phase(), DriverPhase::Idle);

    // It is not in the frozen membership, so it is not an observer either: an
    // observation it signs is refused by every member.
    for (Node* founder : founders) {
        const auto& members = founder->runtime->epochs()->current().tier1_members;
        EXPECT_FALSE(members.contains(reserve->id));
        EXPECT_FALSE(founder->runtime->epochs()->current_vote_keys().contains(reserve->id));
    }
    EXPECT_FALSE(eligibility_of(*reserve).is_observer());

    // A vote forged under its identity is an unknown signer, not a vote.
    Vote forged;
    forged.consensus_ruleset = constants::kConsensusRulesetVersion;
    forged.network_id = network;
    forged.epoch = 1;
    forged.height = founders[0]->driver->last_committed_height() + 1;
    forged.view = founders[0]->runtime->consensus()->current_view();
    forged.proposal_digest.fill(0x5A);
    forged.voter = reserve->id;
    const auto outcome = founders[0]->runtime->consensus()->receive_vote(forged);
    ASSERT_TRUE(std::holds_alternative<ConsensusFailure>(outcome));
    EXPECT_EQ(std::get<ConsensusFailure>(outcome), ConsensusFailure::UnknownSigner);

    // The current epoch's numbers never moved for any of this.
    const auto& current = founders[0]->runtime->epochs()->current();
    EXPECT_EQ(current.tier1_members.size(), kFounders);
    EXPECT_EQ(current.consensus_quorum, constants::consensus_quorum(kFounders));
    EXPECT_EQ(current.authority_threshold, constants::authority_threshold(kFounders));
}

// A transport certificate makes a peer reachable. On its own it makes nothing
// else: with no platform claims and no mesh observations behind it, the node
// is ineligible and holds no authority.
TEST_F(Tier2Path, ACertificateAloneCreatesNoEligibility) {
    bootstrap();
    run_until_committed(1);
    introduce_reserves();

    Node* reserve = reserves[0];
    // Certified, and nothing more: no attestation, no observations.
    ASSERT_FALSE(mesh.uncertified.contains(reserve->id));
    const auto state = eligibility_of(*founders[0]).compute_state(2);
    const auto record = std::find_if(
        state.records.begin(), state.records.end(),
        [&](const EligibilityRecord& r) { return r.subject == reserve->id; });
    if (record != state.records.end()) {
        EXPECT_TRUE(record->certificate_valid);
        EXPECT_FALSE(record->uptime_valid);
        EXPECT_FALSE(record->mesh_health_valid);
        EXPECT_EQ(record->platform_claims, Digest{});
        EXPECT_FALSE(record->eligible);
    }
    EXPECT_FALSE(eligible_in(*founders[0], reserve->id, 2));
    EXPECT_EQ(reserve->runtime->epochs(), nullptr);

    // And losing the certificate takes eligibility away from a node that has
    // everything else, which is the other half of the same statement.
    std::vector<Node*> subjects = founders;
    subjects.insert(subjects.end(), reserves.begin(), reserves.end());
    observe(subjects);
    ASSERT_TRUE(eligible_in(*founders[0], reserve->id, 2));
    mesh.uncertified.insert(reserve->id);
    EXPECT_FALSE(eligible_in(*founders[0], reserve->id, 2));
}

// N = 5 with one member offline. Four is still a HotStuff quorum, so the mesh
// must keep committing and the four that remain must not all become ineligible
// merely because the fifth is gone.
TEST_F(Tier2Path, OneOfflineMemberDoesNotDenyTheRestAtFive) {
    bootstrap();
    run_until_committed(2);
    introduce_reserves();

    Node* offline = founders[4];
    std::vector<Node*> online(founders.begin(), founders.begin() + 4);
    const auto before = founders[0]->runtime->epochs()->current();

    // The offline member neither observes nor is observed. Everything else
    // continues, reserves included.
    std::vector<Node*> subjects = online;
    subjects.insert(subjects.end(), reserves.begin(), reserves.end());
    for (uint8_t round = 1; round <= constants::kMinContinuityObservations; ++round) {
        run_reattest_cadence(round, subjects, online);
    }

    // The chain still commits with four members.
    const Height height = founders[0]->driver->last_committed_height();
    advance_commit(online);
    EXPECT_GT(founders[0]->driver->last_committed_height(), height);

    // The four that stayed are each seen by the other three, which is exactly
    // the bar for a current member.
    for (Node* subject : online) {
        const auto evidence = evidence_for_subject(*founders[0], *subject);
        EXPECT_EQ(evidence.quorum_required, constants::consensus_quorum(kFounders) - 1);
        EXPECT_EQ(evidence.continuity_observers, 3u) << "the three other online members";
        EXPECT_TRUE(evidence.uptime_valid);
        EXPECT_TRUE(evidence.mesh_health_valid);
        EXPECT_TRUE(eligible_in(*founders[0], subject->id, 2));
    }

    // The reserves face the full quorum, and because they spend no witness on
    // themselves the four members still online are exactly enough.
    for (Node* reserve : reserves) {
        const auto evidence = evidence_for_subject(*founders[0], *reserve);
        EXPECT_EQ(evidence.quorum_required, constants::consensus_quorum(kFounders));
        EXPECT_EQ(evidence.continuity_observers, 4u);
        EXPECT_TRUE(evidence.uptime_valid);
    }

    // The offline member is out of the next epoch and untouched in this one.
    EXPECT_FALSE(eligible_in(*founders[0], offline->id, 2));
    for (Node* founder : online) {
        const auto& current = founder->runtime->epochs()->current();
        EXPECT_EQ(current.tier1_members.size(), before.tier1_members.size());
        EXPECT_TRUE(current.tier1_members.contains(offline->id));
        EXPECT_EQ(current.consensus_quorum, before.consensus_quorum);
        EXPECT_EQ(current.authority_threshold, before.authority_threshold);
    }

    // A workable pool still exists, and it is the same one everywhere.
    const auto pool = eligible_nodes(eligibility_of(*founders[0]).compute_state(2));
    EXPECT_GE(pool.size(), constants::kMinActiveTier1);
    for (Node* founder : online) {
        EXPECT_EQ(eligible_nodes(eligibility_of(*founder).compute_state(2)), pool);
    }
}

// Three members are below the witness bar for a current member as well, so a
// minority cannot manufacture a state the mesh would have to act on. Safety is
// preserved; liveness is not available.
TEST_F(Tier2Path, ThreeRemainingMembersManufactureNothing) {
    bootstrap();
    run_until_committed(2);

    std::vector<Node*> online(founders.begin(), founders.begin() + 3);
    for (uint8_t round = 1; round <= constants::kMinContinuityObservations; ++round) {
        attest_subjects(round, online, online);
        advance_commit(online, 40);
    }

    // Three members are below the consensus quorum, so the chain stops once the
    // blocks already in flight drain. The bar is out of reach either way: two
    // witnesses are one short of it, and an observer with no newer finalized
    // state to point at has nothing further to say.
    for (Node* subject : online) {
        const auto evidence = evidence_for_subject(*founders[0], *subject);
        EXPECT_EQ(evidence.quorum_required, constants::consensus_quorum(kFounders) - 1);
        EXPECT_LT(evidence.continuity_observers, evidence.quorum_required);
        EXPECT_FALSE(evidence.uptime_valid);
        EXPECT_FALSE(eligible_in(*founders[0], subject->id, 2));
    }

    // Nothing rotates, and nothing about the current epoch changes.
    mesh.now_ms += constants::kTargetEpochSeconds * 1000;
    step(60, online);
    for (Node* founder : online) {
        EXPECT_EQ(founder->runtime->epochs()->transition(), nullptr);
        EXPECT_EQ(founder->driver->current_epoch(), 1u);
        EXPECT_EQ(founder->runtime->epochs()->current().tier1_members.size(), kFounders);
        EXPECT_EQ(founder->runtime->epochs()->current().consensus_quorum,
                  constants::consensus_quorum(kFounders));
    }
}

// Reserve replacement: two members are proved at fault, so the finalized pool
// is three members plus both reserves. Selection is deterministic and takes the
// whole pool, which is how a Tier 2 server enters the next epoch's set.
TEST_F(Tier2Path, AFinalizedPoolCanReplaceFailedMembersWithReserves) {
    bootstrap();
    run_until_committed(1);
    introduce_reserves();
    std::vector<Node*> subjects = founders;
    subjects.insert(subjects.end(), reserves.begin(), reserves.end());
    observe(subjects);

    // Two members present a second incarnation inside the frozen epoch.
    reattest_one(*founders[3], 7, 2);
    reattest_one(*founders[4], 8, 2);
    step(6);

    const auto pool = eligible_nodes(eligibility_of(*founders[0]).compute_state(2));
    ASSERT_EQ(pool.size(), kFounders - 2 + kReserves);
    for (Node* reserve : reserves) {
        EXPECT_TRUE(std::find(pool.begin(), pool.end(), reserve->id) != pool.end())
            << "a reserve is in the finalized pool";
    }
    EXPECT_FALSE(std::find(pool.begin(), pool.end(), founders[3]->id) != pool.end());
    EXPECT_FALSE(std::find(pool.begin(), pool.end(), founders[4]->id) != pool.end());

    // Every honest member computes that same pool, so the selection that
    // follows is the same everywhere.
    for (Node* founder : founders) {
        EXPECT_EQ(eligible_nodes(eligibility_of(*founder).compute_state(2)), pool);
    }

    // The faulted members keep their current-epoch seats until the boundary.
    for (Node* founder : founders) {
        const auto& current = founder->runtime->epochs()->current();
        EXPECT_EQ(current.tier1_members.size(), kFounders);
        EXPECT_TRUE(current.tier1_members.contains(founders[3]->id));
        EXPECT_EQ(current.consensus_quorum, constants::consensus_quorum(kFounders));
    }
}

// The Genesis founding round attests under epoch 0, so it spends none of
// Epoch 1's per-node attestation budget, and epoch-0 evidence answers no
// Epoch 1 challenge.
TEST_F(Tier2Path, GenesisRoundsDoNotSpendEpochOneBudget) {
    bootstrap();

    // Every founder challenged every other one twice during the founding round.
    for (Node* observer : founders) {
        for (Node* subject : founders) {
            if (observer == subject) continue;
            EXPECT_EQ(observer->runtime->attestation().attempts(subject->id, 0),
                      constants::kMinContinuityObservations)
                << "the founding round is epoch-0 work";
            EXPECT_EQ(observer->runtime->attestation().attempts(subject->id, 1), 0u)
                << "and left Epoch 1's budget untouched";
        }
    }

    // The full Epoch 1 cadence still fits: an epoch is four re-attestation
    // intervals and the budget is four attempts.
    Node* observer = founders[0];
    Node* subject = founders[1];
    nexus::crypto::Ed25519PublicKey key{};
    key = subject->id.bytes;
    for (uint32_t i = 0; i < constants::kMaxTier1AttestAttemptsPerEpoch; ++i) {
        EXPECT_TRUE(observer->runtime->attestation().create_challenge(subject->id, key, 1, 1, AttestationPurpose::Eligibility))
            << "attempt " << i;
    }
    EXPECT_FALSE(observer->runtime->attestation().create_challenge(subject->id, key, 1, 1, AttestationPurpose::Eligibility))
        << "and the budget is a real bound";

    // Epoch-0 evidence cannot answer an Epoch 1 challenge: the epoch is inside
    // the challenge digest the prover has to bind.
    const auto epoch_zero =
        founders[2]->runtime->attestation().create_challenge(subject->id, key, 1, 0, AttestationPurpose::Eligibility);
    const auto epoch_one =
        founders[3]->runtime->attestation().create_challenge(subject->id, key, 1, 1, AttestationPurpose::Eligibility);
    ASSERT_TRUE(epoch_zero.has_value() && epoch_one.has_value());
    EXPECT_NE(challenge_digest(*epoch_zero), challenge_digest(*epoch_one));
}

}  // namespace
}  // namespace lifecycle_test
