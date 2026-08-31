// The eligibility service: what a node will sign, what it will accept, and
// what it will release.
//
// The ledger tests pin the counting rules. These pin the layer above them —
// the checks a node runs before it signs a statement about a peer, and the one
// rule that governs the pool: it is released only when a quorum finalized a
// state this node still recomputes.

#include <LemonadeNexus/Security/Eligibility/EligibilityService.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <filesystem>
#include <fstream>
#include <memory>
#include <unistd.h>
#include <vector>

using namespace nexus::security;
namespace constants = nexus::security::constants;
namespace fs = std::filesystem;

namespace {

constexpr std::size_t kMembers = 5;
constexpr EpochId kEpoch = 1;
constexpr EpochId kNext = 2;

VerifiedPlatformClaims complete_claims() {
    VerifiedPlatformClaims claims;
    claims.profile_id = kTier1AttestationProfileId;
    claims.profile_ruleset = kAttestationProfileRulesetVersion;
    claims.hardware_confidentiality_valid = true;
    claims.platform_identity_valid = true;
    claims.evidence_freshness_valid = true;
    claims.node_identity_binding_valid = true;
    claims.incarnation_binding_valid = true;
    claims.epoch_binding_valid = true;
    claims.security_ruleset_binding_valid = true;
    claims.boot_integrity_valid = true;
    claims.tcb_valid = true;
    claims.attestation_profile_valid = true;
    claims.ima_anchored = true;
    claims.binary_approved = true;
    claims.runtime_profile_enforced = true;
    claims.runtime_integrity_valid = true;
    return claims;
}

struct ServiceMesh : ::testing::Test {
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        root = fs::temp_directory_path() / ("nexus_elig_svc_" + std::to_string(::getpid()));
        fs::remove_all(root);
        network.fill(0x5E);

        for (std::size_t i = 0; i < kMembers; ++i) {
            nexus::crypto::Ed25519Keypair key;
            crypto_sign_keypair(key.public_key.data(), key.private_key.data());
            NodeId id;
            id.bytes = key.public_key;
            keys.push_back(key);
            ids.push_back(id);
        }
        for (std::size_t i = 0; i < kMembers; ++i) {
            build(i);
        }
    }

    void build(std::size_t index) {
        auto service = std::make_unique<EligibilityService>(
            network, ids[index], keys[index], directory_of(index));
        service->set_certificate_source([](const NodeId&) { return true; });
        if (services.size() > index) {
            services[index] = std::move(service);
        } else {
            services.push_back(std::move(service));
        }
        ASSERT_NE(services[index]->enter_epoch(kEpoch, ids), EligibilityRestore::Corrupt);
    }

    [[nodiscard]] fs::path directory_of(std::size_t index) const {
        return root / ("node" + std::to_string(index));
    }

    void TearDown() override { fs::remove_all(root); }

    [[nodiscard]] AttestationVerdict verdict_for(const NodeId& subject, uint8_t round,
                                                 IncarnationId incarnation = 1) const {
        AttestationVerdict verdict;
        verdict.node_id = subject;
        verdict.epoch = kEpoch;
        verdict.incarnation = incarnation;
        verdict.passed = true;
        verdict.claims = complete_claims();
        verdict.evidence_digest.fill(subject.bytes[0]);
        verdict.evidence_digest[0] = static_cast<uint8_t>(0xA0 + round);
        verdict.evidence_digest[1] = static_cast<uint8_t>(incarnation);
        return verdict;
    }

    [[nodiscard]] ParticipationProof proof_for(const NodeId& subject, Height subject_height,
                                               IncarnationId incarnation = 1) const {
        ParticipationProof proof;
        proof.network_id = network;
        proof.epoch = kEpoch;
        proof.consensus_ruleset = constants::kConsensusRulesetVersion;
        proof.subject = subject;
        proof.incarnation = incarnation;
        proof.subject_height = subject_height;
        return proof;
    }

    [[nodiscard]] Digest reference(uint8_t byte) const {
        Digest digest;
        digest.fill(byte);
        return digest;
    }

    /// Publishes one observation to every other member, as the router would.
    void publish(const EligibilityObservation& observation) {
        for (auto& service : services) {
            (void)service->accept(observation);
        }
    }

    /// One attestation round across `observers` of `subjects`.
    void attest_round(uint8_t round, const std::vector<std::size_t>& observers,
                      const std::vector<std::size_t>& subjects) {
        for (const std::size_t i : observers) {
            for (const std::size_t j : subjects) {
                if (i == j) continue;
                services[i]->record_verdict(verdict_for(ids[j], round));
                auto observation =
                    services[i]->observe_attestation(ids[j], round, reference(round));
                ASSERT_TRUE(observation.has_value());
                publish(*observation);
            }
        }
    }

    void participate_round(Height height, const std::vector<std::size_t>& observers,
                           const std::vector<std::size_t>& subjects) {
        for (const std::size_t i : observers) {
            for (const std::size_t j : subjects) {
                if (i == j) continue;
                auto observation = services[i]->observe_participation(
                    proof_for(ids[j], height), height, reference(static_cast<uint8_t>(height)));
                ASSERT_TRUE(observation.has_value());
                publish(*observation);
            }
        }
    }

    [[nodiscard]] std::vector<std::size_t> everyone() const {
        std::vector<std::size_t> all(kMembers);
        for (std::size_t i = 0; i < kMembers; ++i) all[i] = i;
        return all;
    }

    /// Drives the full mesh to the point where every member holds both facts.
    void observe_everything() {
        for (uint8_t round = 1; round <= constants::kMinContinuityObservations; ++round) {
            attest_round(round, everyone(), everyone());
        }
        participate_round(9, everyone(), everyone());
    }

    fs::path root;
    NetworkId network{};
    std::vector<nexus::crypto::Ed25519Keypair> keys;
    std::vector<NodeId> ids;
    std::vector<std::unique_ptr<EligibilityService>> services;
};

// --- What a node will sign ---------------------------------------------------

// The subject must be at or above the observer's own finalized floor. Below it
// the observer is looking at a node that has not caught up, which proves the
// opposite of what a participation observation asserts.
TEST_F(ServiceMesh, ParticipationBelowTheObserverFloorIsRefused) {
    EXPECT_FALSE(services[0]->observe_participation(proof_for(ids[1], 4), 5, reference(1)));
    EXPECT_TRUE(services[0]->observe_participation(proof_for(ids[1], 5), 5, reference(1)));
}

// And not implausibly beyond it either: a height nobody could have reached is
// a future state reference, not evidence of anything.
TEST_F(ServiceMesh, ParticipationFromAnImpossibleFutureIsRefused) {
    const Height floor = 5;
    EXPECT_FALSE(services[0]->observe_participation(
        proof_for(ids[1], floor + constants::kMaxFutureViewDistance + 1), floor, reference(1)));
    EXPECT_TRUE(services[0]->observe_participation(
        proof_for(ids[1], floor + constants::kMaxFutureViewDistance), floor, reference(1)));
}

// Every binding is checked before anything is signed.
TEST_F(ServiceMesh, ParticipationRefusesEveryMismatchedBinding) {
    auto wrong_network = proof_for(ids[1], 5);
    wrong_network.network_id.fill(0xAA);
    EXPECT_FALSE(services[0]->observe_participation(wrong_network, 5, reference(1)));

    auto wrong_epoch = proof_for(ids[1], 5);
    wrong_epoch.epoch = kEpoch + 1;
    EXPECT_FALSE(services[0]->observe_participation(wrong_epoch, 5, reference(1)));

    auto wrong_ruleset = proof_for(ids[1], 5);
    wrong_ruleset.consensus_ruleset = constants::kConsensusRulesetVersion + 1;
    EXPECT_FALSE(services[0]->observe_participation(wrong_ruleset, 5, reference(1)));

    auto wrong_incarnation = proof_for(ids[1], 5, 7);
    EXPECT_FALSE(services[0]->observe_participation(wrong_incarnation, 5, reference(1)));

    // A subject outside the committee is fine — that is a Tier 2 candidate,
    // and it has to be able to prove participation before it is selected.
    NodeId outsider;
    outsider.bytes.fill(0x99);
    EXPECT_TRUE(services[0]->observe_participation(proof_for(outsider, 5), 5, reference(1)));

    // A node cannot say that it participated correctly.
    EXPECT_FALSE(services[0]->observe_participation(proof_for(ids[0], 5), 5, reference(1)));

    EXPECT_TRUE(services[0]->observe_participation(proof_for(ids[1], 5), 5, reference(1)));
}

// An observer signs claims only for evidence its own verifier produced. There
// is no parameter to pass a claim set in, so a fabricated or relayed one has no
// way to reach the wire: with nothing recorded there is nothing to sign.
TEST_F(ServiceMesh, AnObserverSignsOnlyClaimsItVerifiedItself) {
    EXPECT_FALSE(services[0]->observe_attestation(ids[1], 1, reference(1)));

    // A failing verdict is not recorded, so it still leaves nothing to sign.
    auto failed = verdict_for(ids[1], 1);
    failed.passed = false;
    services[0]->record_verdict(failed);
    EXPECT_FALSE(services[0]->observe_attestation(ids[1], 1, reference(1)));

    // A passing verdict with no evidence behind it proves no attestation ran.
    auto empty = verdict_for(ids[1], 1);
    empty.evidence_digest = Digest{};
    services[0]->record_verdict(empty);
    EXPECT_FALSE(services[0]->observe_attestation(ids[1], 1, reference(1)));

    // A node never witnesses itself, however much it verified.
    services[0]->record_verdict(verdict_for(ids[0], 1));
    EXPECT_FALSE(services[0]->observe_attestation(ids[0], 1, reference(1)));

    services[0]->record_verdict(verdict_for(ids[1], 1));
    const auto observation = services[0]->observe_attestation(ids[1], 1, reference(1));
    ASSERT_TRUE(observation.has_value());
    // The signed claims are the ones the verifier produced, byte for byte.
    EXPECT_EQ(platform_claims_digest(observation->claims),
              platform_claims_digest(complete_claims()));
}

// --- What a node will accept -------------------------------------------------

// A cloned member speaks with one identity however many copies are running.
// The ledger keys on that identity, so the clone counts once.
TEST_F(ServiceMesh, AClonedObserverCountsOnce) {
    // The clone re-signs the same statements at higher heights, as a second
    // copy of the same node genuinely would.
    for (uint8_t round = 1; round <= constants::kMinContinuityObservations; ++round) {
        attest_round(round, {0}, {2});
    }
    for (uint8_t round = 3; round <= 2 + constants::kMinContinuityObservations; ++round) {
        attest_round(round, {0}, {2});
    }
    participate_round(9, {0}, {2});
    participate_round(10, {0}, {2});

    const auto evidence =
        services[1]->ledger().evaluate(ids[2], 1, services[1]->context());
    EXPECT_EQ(evidence.continuity_observers, 1u);
    EXPECT_EQ(evidence.participation_observers, 1u);
    EXPECT_FALSE(evidence.uptime_valid);
    EXPECT_FALSE(evidence.mesh_health_valid);
}

// An observation replayed under another subject or another network is a
// different statement, and the signature no longer covers it.
TEST_F(ServiceMesh, ReplayUnderAnotherSubjectOrNetworkIsRefused) {
    services[0]->record_verdict(verdict_for(ids[1], 1));
    auto observation = services[0]->observe_attestation(ids[1], 1, reference(1));
    ASSERT_TRUE(observation.has_value());

    auto moved = *observation;
    moved.subject = ids[2];
    EXPECT_EQ(services[3]->accept(moved), ObservationOutcome::SignatureInvalid);

    auto foreign = *observation;
    foreign.network_id.fill(0xAA);
    EXPECT_EQ(services[3]->accept(foreign), ObservationOutcome::WrongNetwork);

    auto later_epoch = *observation;
    later_epoch.epoch = kEpoch + 1;
    EXPECT_EQ(services[3]->accept(later_epoch), ObservationOutcome::WrongEpoch);

    // Re-attributed to a node outside the set, which is caught before the
    // signature is even worth checking.
    auto outsider = *observation;
    outsider.observer.bytes.fill(0x99);
    EXPECT_EQ(services[3]->accept(outsider), ObservationOutcome::ObserverNotInTier1);

    EXPECT_EQ(services[3]->accept(*observation), ObservationOutcome::Accepted);
}

// --- Claim provenance --------------------------------------------------------

// A claim set is only ever as good as the observer that signed it. Every way of
// moving one somewhere it was not verified breaks the signature, and the
// binding covers the subject, incarnation, epoch, network, evidence digest,
// profile and every claim bit.
TEST_F(ServiceMesh, ClaimsCannotBeMovedOffTheObservationThatCarriesThem) {
    services[0]->record_verdict(verdict_for(ids[1], 1));
    const auto signed_by_zero = services[0]->observe_attestation(ids[1], 1, reference(1));
    ASSERT_TRUE(signed_by_zero.has_value());

    // Fabricated claims under a valid observer signature: changing them leaves
    // the signature over the old ones, so the statement no longer verifies.
    auto fabricated = *signed_by_zero;
    fabricated.claims.tcb_valid = false;
    EXPECT_EQ(services[2]->accept(fabricated), ObservationOutcome::SignatureInvalid);

    // Copied onto another node.
    auto other_subject = *signed_by_zero;
    other_subject.subject = ids[3];
    EXPECT_EQ(services[2]->accept(other_subject), ObservationOutcome::SignatureInvalid);

    // Copied onto another incarnation.
    auto other_incarnation = *signed_by_zero;
    other_incarnation.subject_incarnation = 2;
    EXPECT_EQ(services[2]->accept(other_incarnation), ObservationOutcome::SignatureInvalid);

    // Copied onto another network.
    auto other_network = *signed_by_zero;
    other_network.network_id.fill(0xAA);
    EXPECT_EQ(services[2]->accept(other_network), ObservationOutcome::WrongNetwork);

    // The same evidence digest with altered claims.
    auto altered = *signed_by_zero;
    altered.claims.profile_ruleset += 1;
    EXPECT_EQ(altered.attestation_digest, signed_by_zero->attestation_digest);
    EXPECT_EQ(services[2]->accept(altered), ObservationOutcome::SignatureInvalid);

    // Relayed under another observer's identity.
    auto relayed = *signed_by_zero;
    relayed.observer = ids[4];
    EXPECT_EQ(services[2]->accept(relayed), ObservationOutcome::SignatureInvalid);

    EXPECT_EQ(services[2]->accept(*signed_by_zero), ObservationOutcome::Accepted);
}

// A claim set that contradicts its own structure is a bug rather than a proof,
// and a participation observation carries no platform claims at all.
TEST_F(ServiceMesh, StructurallyImpossibleClaimsAreRefused) {
    services[0]->record_verdict(verdict_for(ids[1], 1));
    auto observation = services[0]->observe_attestation(ids[1], 1, reference(1));
    ASSERT_TRUE(observation.has_value());

    // Runtime integrity without its three steps behind it.
    auto inconsistent = *observation;
    inconsistent.claims.ima_anchored = false;
    inconsistent = sign_observation(inconsistent, keys[0]);
    EXPECT_EQ(services[2]->accept(inconsistent), ObservationOutcome::MalformedForKind);

    // Claims with no provider naming itself.
    auto anonymous = *observation;
    anonymous.claims.profile_id = AttestationProfileId::Unknown;
    anonymous = sign_observation(anonymous, keys[0]);
    EXPECT_EQ(services[2]->accept(anonymous), ObservationOutcome::MalformedForKind);

    // A vote proves participation and nothing about hardware.
    auto participation = *observation;
    participation.kind = ObservationKind::Participation;
    participation.attestation_digest = Digest{};
    participation = sign_observation(participation, keys[0]);
    EXPECT_EQ(services[2]->accept(participation), ObservationOutcome::MalformedForKind);
}

// --- The Tier 2 participation exchange ---------------------------------------

// The answer must be to a challenge this observer issued, under the subject's
// own identity key, naming the finalized state the challenge named.
TEST_F(ServiceMesh, AParticipationResponseIsBoundToItsChallenge) {
    ParticipationChallenge challenge;
    challenge.network_id = network;
    challenge.epoch = kEpoch;
    challenge.security_ruleset = constants::kSecurityRulesetVersion;
    challenge.consensus_ruleset = constants::kConsensusRulesetVersion;
    challenge.node_id = ids[1];
    challenge.incarnation = 1;
    challenge.nonce.fill(0x2B);
    challenge.anchor_height = 12;
    challenge.anchor_state = reference(0xC0);
    challenge.observer = ids[0];

    const auto answer = answer_participation_challenge(challenge, keys[1]);
    EXPECT_EQ(verify_participation_response(answer, challenge), ParticipationFailure::None);

    // Answered by the wrong node.
    const auto impostor = answer_participation_challenge(challenge, keys[2]);
    EXPECT_EQ(verify_participation_response(impostor, challenge),
              ParticipationFailure::IdentityMismatch);

    // A fresh nonce is a different challenge, so an old answer does not fit it.
    auto replayed = challenge;
    replayed.nonce.fill(0x2C);
    EXPECT_EQ(verify_participation_response(answer, replayed),
              ParticipationFailure::ChallengeMismatch);

    // Every binding, one at a time.
    const auto broken = [&](auto mutate) {
        auto response = answer;
        mutate(response);
        return verify_participation_response(response, challenge);
    };
    EXPECT_EQ(broken([](auto& r) { r.network_id.fill(0xAA); }),
              ParticipationFailure::NetworkMismatch);
    EXPECT_EQ(broken([](auto& r) { r.epoch += 1; }), ParticipationFailure::EpochMismatch);
    EXPECT_EQ(broken([](auto& r) { r.security_ruleset += 1; }),
              ParticipationFailure::RulesetMismatch);
    EXPECT_EQ(broken([](auto& r) { r.incarnation += 1; }),
              ParticipationFailure::IncarnationMismatch);
    EXPECT_EQ(broken([](auto& r) { r.anchor_height += 1; }),
              ParticipationFailure::AnchorMismatch);
    EXPECT_EQ(broken([this](auto& r) { r.anchor_state = reference(0xC1); }),
              ParticipationFailure::AnchorMismatch);
    EXPECT_EQ(broken([](auto& r) { r.identity_signature[0] ^= 0x01; }),
              ParticipationFailure::SignatureInvalid);

    // The service will only act on a challenge it issued itself, anchored to
    // state it holds.
    EXPECT_TRUE(services[0]->observe_participation_response(answer, challenge, 12,
                                                            reference(0xC0)));
    EXPECT_FALSE(services[2]->observe_participation_response(answer, challenge, 12,
                                                             reference(0xC0)))
        << "the challenge names another observer";
    EXPECT_FALSE(services[0]->observe_participation_response(answer, challenge, 13,
                                                             reference(0xC0)))
        << "anchored to state this observer does not hold";
}

// --- What a node will release ------------------------------------------------

// One observer never makes a fact, however much it says.
TEST_F(ServiceMesh, OneObserverCannotMakeEitherFact) {
    for (uint8_t round = 1; round <= constants::kMinContinuityObservations; ++round) {
        attest_round(round, {0}, everyone());
    }
    participate_round(9, {0}, everyone());

    for (std::size_t j = 1; j < kMembers; ++j) {
        const auto evidence = services[j]->ledger().evaluate(ids[j], 1, services[j]->context());
        EXPECT_LT(evidence.continuity_observers, evidence.quorum_required);
        EXPECT_FALSE(evidence.uptime_valid);
        EXPECT_FALSE(evidence.mesh_health_valid);
    }
    EXPECT_TRUE(eligible_nodes(services[0]->compute_state(kNext)).empty());
}

// With the quorum behind them both facts hold, every member computes the same
// state, and the policy — not the service — decides eligibility.
TEST_F(ServiceMesh, AQuorumOfObserversMakesTheFactsAndOneState) {
    observe_everything();

    const Digest agreed = eligibility_commitment_digest(services[0]->compute_state(kNext));
    for (auto& service : services) {
        EXPECT_EQ(eligibility_commitment_digest(service->compute_state(kNext)), agreed);
    }
    const auto state = services[0]->compute_state(kNext);
    EXPECT_EQ(state.records.size(), kMembers);
    EXPECT_EQ(eligible_nodes(state).size(), kMembers);
    for (const auto& record : state.records) {
        EXPECT_TRUE(record.uptime_valid);
        EXPECT_TRUE(record.mesh_health_valid);
        EXPECT_TRUE(record.certificate_valid);
        EXPECT_NE(record.platform_claims, Digest{});
        EXPECT_EQ(record.faults, 0u);
        EXPECT_TRUE(record.eligible);
    }
}

// The platform half is a quorum fact too. Observers that disagree about what
// they verified leave the claims unproved, and an unproved platform is not a
// smaller platform.
TEST_F(ServiceMesh, PlatformClaimsNeedAQuorumToo) {
    observe_everything();
    ASSERT_TRUE(eligible_nodes(services[0]->compute_state(kNext)).size() == kMembers);

    // Two observers now report a subject whose runtime integrity did not hold.
    VerifiedPlatformClaims partial = complete_claims();
    partial.runtime_profile_enforced = false;
    partial.runtime_integrity_valid = false;
    for (const std::size_t i : {1u, 2u}) {
        auto verdict = verdict_for(ids[0], 5);
        verdict.claims = partial;
        services[i]->record_verdict(verdict);
        auto observation = services[i]->observe_attestation(ids[0], 20, reference(20));
        ASSERT_TRUE(observation.has_value());
        publish(*observation);
    }

    // Three observers hold the complete set and two hold the partial one, so
    // neither reaches the quorum of four.
    const auto evidence = services[3]->ledger().evaluate(ids[0], 1, services[3]->context());
    EXPECT_EQ(evidence.claim_observers, 0u);
    EXPECT_EQ(platform_claims_digest(evidence.platform_claims), Digest{});
    EXPECT_FALSE(eligible_nodes(services[3]->compute_state(kNext)).empty());
    const auto state = services[3]->compute_state(kNext);
    const auto record = std::find_if(state.records.begin(), state.records.end(),
                                     [&](const EligibilityRecord& r) { return r.subject == ids[0]; });
    ASSERT_NE(record, state.records.end());
    EXPECT_FALSE(record->eligible);
}

// No finalized state, no pool. The facts alone release nothing.
TEST_F(ServiceMesh, FinalizationIsRequiredBeforeAnyPool) {
    observe_everything();
    EXPECT_EQ(services[0]->finalized(), nullptr);
    EXPECT_FALSE(services[0]->frozen_pool(kNext).has_value());

    const Digest commitment = eligibility_commitment_digest(services[0]->compute_state(kNext));
    services[0]->finalize({.commitment = commitment,
                           .consensus_reference = reference(0xC0),
                           .height = 12,
                           .state_root = reference(0xC1),
                           .next_epoch = kNext});
    const auto pool = services[0]->frozen_pool(kNext);
    ASSERT_TRUE(pool.has_value());
    EXPECT_EQ(pool->size(), kMembers);

    // A finalization for another boundary answers a question nobody asked.
    EXPECT_FALSE(services[0]->frozen_pool(kNext + 1).has_value());
}

// Once the state moves, the old finalization no longer describes it, and the
// pool stops. That is what makes a rolled-back or edited local state useless:
// it cannot reproduce the digest a quorum committed.
TEST_F(ServiceMesh, AStateThatNoLongerMatchesReleasesNothing) {
    observe_everything();
    const Digest commitment = eligibility_commitment_digest(services[0]->compute_state(kNext));
    services[0]->finalize({.commitment = commitment,
                           .consensus_reference = reference(0xC0),
                           .height = 12,
                           .state_root = reference(0xC1),
                           .next_epoch = kNext});
    ASSERT_TRUE(services[0]->frozen_pool(kNext).has_value());

    services[0]->record_fault(ids[3], ObjectiveFault::Equivocation);
    EXPECT_NE(eligibility_commitment_digest(services[0]->compute_state(kNext)), commitment);
    EXPECT_FALSE(services[0]->frozen_pool(kNext).has_value());
}

// A proved fault denies mesh health for that subject and survives a restart:
// there is no transition back and no file to remove that recreates one.
TEST_F(ServiceMesh, AFaultDeniesEligibilityAndOutlivesARestart) {
    observe_everything();
    services[0]->record_fault(ids[3], ObjectiveFault::Equivocation);
    EXPECT_FALSE(services[0]->compute_state(kNext).records.empty());

    const auto faulted = [this](const EligibilityService& service) {
        const auto state = service.compute_state(kNext);
        const auto record =
            std::find_if(state.records.begin(), state.records.end(),
                         [&](const EligibilityRecord& r) { return r.subject == ids[3]; });
        return record != state.records.end() && record->faults != 0 && !record->eligible;
    };
    EXPECT_TRUE(faulted(*services[0]));

    build(0);  // restart
    EXPECT_TRUE(faulted(*services[0]));
    const auto& faults = services[0]->ledger().faults();
    ASSERT_NE(faults.find(ids[3]), faults.end());
    EXPECT_TRUE(faults.at(ids[3]).contains(ObjectiveFault::Equivocation));
}

// A restart brings observations back so the node can keep contributing. It does
// not bring finality back: that has to be reached again through the mesh.
TEST_F(ServiceMesh, RestartRestoresObservationsButNeverFinality) {
    observe_everything();
    const Digest before = eligibility_commitment_digest(services[0]->compute_state(kNext));
    services[0]->finalize({.commitment = before,
                           .consensus_reference = reference(0xC0),
                           .height = 12,
                           .state_root = reference(0xC1),
                           .next_epoch = kNext});
    ASSERT_TRUE(services[0]->frozen_pool(kNext).has_value());
    const std::size_t held = services[0]->ledger().size();

    build(0);
    EXPECT_EQ(services[0]->ledger().size(), held);
    EXPECT_EQ(eligibility_commitment_digest(services[0]->compute_state(kNext)), before);
    EXPECT_EQ(services[0]->finalized(), nullptr);
    EXPECT_FALSE(services[0]->frozen_pool(kNext).has_value());
}

// Damaged durable state is reported as damaged. A node must never read lost
// eligibility history as a clean slate.
TEST_F(ServiceMesh, CorruptDurableStateIsReportedAsCorrupt) {
    observe_everything();
    {
        std::ofstream out(directory_of(0) / "observations-1.json");
        out << "{not json";
    }
    EligibilityService reopened(network, ids[0], keys[0], directory_of(0));
    EXPECT_EQ(reopened.enter_epoch(kEpoch, ids), EligibilityRestore::Corrupt);

    {
        std::ofstream out(directory_of(1) / "faults.json");
        out << "{\"format\":1,\"faults\":\"nonsense\"}";
    }
    EligibilityService second(network, ids[1], keys[1], directory_of(1));
    EXPECT_EQ(second.enter_epoch(kEpoch, ids), EligibilityRestore::Corrupt);
}

// The Genesis context: the founding set observes itself, so the bar is every
// other founder. The bootstrap threshold does not move.
TEST_F(ServiceMesh, TheGenesisContextRequiresEveryOtherFounder) {
    for (std::size_t i = 0; i < kMembers; ++i) {
        ASSERT_NE(services[i]->enter_genesis(ids), EligibilityRestore::Corrupt);
        // The committee is the whole founding set; self-exclusion puts each
        // founder's bar at every other founder.
        EXPECT_EQ(services[i]->context().quorum, kMembers);
        EXPECT_EQ(witness_threshold(services[i]->context(), ids[i]), kMembers - 1);
        EXPECT_EQ(services[i]->context().epoch, 0u);
    }
    EXPECT_FALSE(services[0]->mutual_round_complete());
}

}  // namespace
