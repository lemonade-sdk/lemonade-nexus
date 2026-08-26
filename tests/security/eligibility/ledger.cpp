// The two mesh facts, and what it takes to make one.
//
// Every test here is about the same property: no single node can create a mesh
// fact about another. Observers are Byzantine, so the ledger counts distinct
// signed statements from the current Tier 1 set and nothing else.

#include <LemonadeNexus/Security/Eligibility/EligibilityLedger.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <array>
#include <string>
#include <vector>

namespace constants = nexus::security::constants;

using nexus::security::Digest;
using nexus::security::EligibilityLedger;
using nexus::security::EligibilityObservation;
using nexus::security::EpochId;
using nexus::security::Height;
using nexus::security::IncarnationId;
using nexus::security::MeshFactContext;
using nexus::security::NetworkId;
using nexus::security::NodeId;
using nexus::security::ObjectiveFault;
using nexus::security::ObservationKind;
using nexus::security::ObservationOutcome;
using nexus::security::established_fact_context;
using nexus::security::genesis_fact_context;
using nexus::security::sign_observation;

namespace {

constexpr EpochId kEpoch = 7;

NetworkId network() {
    NetworkId id{};
    id.fill(0xA0);
    return id;
}

Digest digest(uint8_t seed) {
    Digest d{};
    d.fill(seed);
    return d;
}

/// A node whose identity key is real: observations are signed under it, so a
/// forged observer identity cannot verify.
struct Node {
    nexus::crypto::Ed25519Keypair identity;
    NodeId id;
};

Node make_node() {
    Node node;
    crypto_sign_keypair(node.identity.public_key.data(), node.identity.private_key.data());
    node.id.bytes = node.identity.public_key;
    return node;
}

class LedgerTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        for (int i = 0; i < 5; ++i) {
            members_.push_back(make_node());
        }
        candidate_ = make_node();
        std::vector<NodeId> ids;
        for (const auto& member : members_) ids.push_back(member.id);
        context_ = established_fact_context(network(), kEpoch, ids);
    }

    [[nodiscard]] EligibilityObservation attestation(const Node& observer, const Node& subject,
                                                      uint8_t attestation_seed, Height height,
                                                      IncarnationId incarnation = 1) const {
        EligibilityObservation observation;
        observation.network_id = network();
        observation.epoch = kEpoch;
        observation.subject = subject.id;
        observation.subject_incarnation = incarnation;
        observation.kind = ObservationKind::Attestation;
        observation.attestation_digest = digest(attestation_seed);
        observation.height = height;
        observation.state_reference = digest(0xC0);
        return sign_observation(observation, observer.identity);
    }

    [[nodiscard]] EligibilityObservation participation(const Node& observer, const Node& subject,
                                                        Height height,
                                                        IncarnationId incarnation = 1) const {
        EligibilityObservation observation;
        observation.network_id = network();
        observation.epoch = kEpoch;
        observation.subject = subject.id;
        observation.subject_incarnation = incarnation;
        observation.kind = ObservationKind::Participation;
        observation.height = height;
        observation.state_reference = digest(0xC0);
        return sign_observation(observation, observer.identity);
    }

    /// Continuity from `count` observers: each sees two distinct attestations.
    void give_continuity(std::size_t count, IncarnationId incarnation = 1) {
        for (std::size_t i = 0; i < count; ++i) {
            EXPECT_EQ(ledger_.record(attestation(members_[i], candidate_, 0x10, 100, incarnation),
                                     context_),
                      ObservationOutcome::Accepted);
            EXPECT_EQ(ledger_.record(attestation(members_[i], candidate_, 0x11, 200, incarnation),
                                     context_),
                      ObservationOutcome::Accepted);
        }
    }

    void give_participation(std::size_t count, IncarnationId incarnation = 1) {
        for (std::size_t i = 0; i < count; ++i) {
            EXPECT_EQ(ledger_.record(participation(members_[i], candidate_, 300, incarnation),
                                     context_),
                      ObservationOutcome::Accepted);
        }
    }

    std::vector<Node> members_;
    Node candidate_;
    MeshFactContext context_;
    EligibilityLedger ledger_;
};

}  // namespace

// --- quorum ---------------------------------------------------------------

TEST_F(LedgerTest, TheQuorumIsTheCompiledConsensusQuorum) {
    EXPECT_EQ(context_.quorum, constants::consensus_quorum(5));
    EXPECT_EQ(context_.quorum, 4u);
}

TEST_F(LedgerTest, AQuorumOfObserversMakesBothFacts) {
    give_continuity(context_.quorum);
    give_participation(context_.quorum);

    const auto evidence = ledger_.evaluate(candidate_.id, 1, context_);
    EXPECT_TRUE(evidence.uptime_valid);
    EXPECT_TRUE(evidence.mesh_health_valid);
    EXPECT_EQ(evidence.continuity_observers, context_.quorum);
    EXPECT_EQ(evidence.participation_observers, context_.quorum);
}

// The headline rule: one observer cannot create either fact, however many
// statements it signs.
TEST_F(LedgerTest, OneObserverCannotMakeAFact) {
    for (uint8_t seed = 0x20; seed < 0x28; ++seed) {
        (void)ledger_.record(attestation(members_[0], candidate_, seed, 100 + seed), context_);
    }
    (void)ledger_.record(participation(members_[0], candidate_, 400), context_);

    const auto evidence = ledger_.evaluate(candidate_.id, 1, context_);
    EXPECT_FALSE(evidence.uptime_valid);
    EXPECT_FALSE(evidence.mesh_health_valid);
    EXPECT_EQ(evidence.continuity_observers, 1u);
}

TEST_F(LedgerTest, OneShortOfQuorumIsNotEnough) {
    give_continuity(context_.quorum - 1);
    give_participation(context_.quorum - 1);

    const auto evidence = ledger_.evaluate(candidate_.id, 1, context_);
    EXPECT_FALSE(evidence.uptime_valid);
    EXPECT_FALSE(evidence.mesh_health_valid);
}

// --- continuity -----------------------------------------------------------

// One attestation is a sighting, not continuity. The second must be a distinct
// round, which a distinct challenge digest is what proves.
TEST_F(LedgerTest, ContinuityNeedsTwoDistinctAttestationsPerObserver) {
    for (std::size_t i = 0; i < context_.quorum; ++i) {
        EXPECT_EQ(ledger_.record(attestation(members_[i], candidate_, 0x10, 100), context_),
                  ObservationOutcome::Accepted);
    }
    EXPECT_FALSE(ledger_.evaluate(candidate_.id, 1, context_).uptime_valid);

    // Re-sending the SAME attestation at a greater height adds no round.
    for (std::size_t i = 0; i < context_.quorum; ++i) {
        EXPECT_EQ(ledger_.record(attestation(members_[i], candidate_, 0x10, 150), context_),
                  ObservationOutcome::Accepted);
    }
    EXPECT_FALSE(ledger_.evaluate(candidate_.id, 1, context_).uptime_valid);

    for (std::size_t i = 0; i < context_.quorum; ++i) {
        EXPECT_EQ(ledger_.record(attestation(members_[i], candidate_, 0x11, 200), context_),
                  ObservationOutcome::Accepted);
    }
    EXPECT_TRUE(ledger_.evaluate(candidate_.id, 1, context_).uptime_valid);
}

TEST_F(LedgerTest, ContinuityDoesNotCarryAcrossIncarnations) {
    give_continuity(context_.quorum, 1);
    ASSERT_TRUE(ledger_.evaluate(candidate_.id, 1, context_).uptime_valid);

    // The candidate restarts. A different incarnation is a different live node,
    // so the history it accumulated does not transfer.
    EXPECT_FALSE(ledger_.evaluate(candidate_.id, 2, context_).uptime_valid);

    for (std::size_t i = 0; i < context_.quorum; ++i) {
        EXPECT_EQ(ledger_.record(attestation(members_[i], candidate_, 0x30, 300, 2), context_),
                  ObservationOutcome::Accepted);
    }
    // One round at the new incarnation is not continuity either.
    EXPECT_FALSE(ledger_.evaluate(candidate_.id, 2, context_).uptime_valid);
    // And the old incarnation's history is gone, not merely shadowed.
    EXPECT_FALSE(ledger_.evaluate(candidate_.id, 1, context_).uptime_valid);
}

// --- who may observe ------------------------------------------------------

TEST_F(LedgerTest, AnObserverOutsideTheTierOneSetIsRefused) {
    const Node outsider = make_node();
    EXPECT_EQ(ledger_.record(attestation(outsider, candidate_, 0x10, 100), context_),
              ObservationOutcome::ObserverNotInTier1);
}

TEST_F(LedgerTest, ANodeCannotObserveItself) {
    EXPECT_EQ(ledger_.record(attestation(members_[0], members_[0], 0x10, 100), context_),
              ObservationOutcome::SelfObservation);
}

// A statement signed by anyone other than the observer it names does not
// verify: a node identity is its identity key, so there is no key to borrow.
TEST_F(LedgerTest, AnObservationCannotBeSignedByAnother) {
    EligibilityObservation forged = attestation(members_[0], candidate_, 0x10, 100);
    forged.observer = members_[1].id;
    EXPECT_EQ(ledger_.record(forged, context_), ObservationOutcome::SignatureInvalid);
}

TEST_F(LedgerTest, TamperedFieldsBreakTheSignature) {
    const EligibilityObservation good = attestation(members_[0], candidate_, 0x10, 100);
    ASSERT_EQ(ledger_.record(good, context_), ObservationOutcome::Accepted);

    for (int field = 0; field < 4; ++field) {
        EligibilityObservation tampered = attestation(members_[1], candidate_, 0x10, 100);
        switch (field) {
            case 0: tampered.subject_incarnation += 1; break;
            case 1: tampered.height += 1; break;
            case 2: tampered.attestation_digest[0] ^= 1; break;
            case 3: tampered.state_reference[0] ^= 1; break;
            default: break;
        }
        EXPECT_EQ(ledger_.record(tampered, context_), ObservationOutcome::SignatureInvalid)
            << field;
    }
}

// --- Byzantine observers --------------------------------------------------

// A cloned Tier 1 node shares its identity, and the ledger keys on identity, so
// both copies together still count once.
TEST_F(LedgerTest, ACloneCountsOnce) {
    give_continuity(context_.quorum - 1);
    // The clone speaks with the same identity as members_[0], which already
    // contributed. Its statements land on the same key.
    EXPECT_EQ(ledger_.record(attestation(members_[0], candidate_, 0x40, 500), context_),
              ObservationOutcome::Accepted);
    EXPECT_EQ(ledger_.record(attestation(members_[0], candidate_, 0x41, 600), context_),
              ObservationOutcome::Accepted);

    const auto evidence = ledger_.evaluate(candidate_.id, 1, context_);
    EXPECT_EQ(evidence.continuity_observers, context_.quorum - 1);
    EXPECT_FALSE(evidence.uptime_valid);
}

// An observer that rewinds its height is replaying. Height is quorum-certified
// and monotonic, so a lower one is not a newer view of anything.
TEST_F(LedgerTest, AnObserverCannotRewindItsHeight) {
    EXPECT_EQ(ledger_.record(attestation(members_[0], candidate_, 0x10, 500), context_),
              ObservationOutcome::Accepted);
    EXPECT_EQ(ledger_.record(attestation(members_[0], candidate_, 0x11, 400), context_),
              ObservationOutcome::NotNewerThanHeld);
    EXPECT_EQ(ledger_.record(attestation(members_[0], candidate_, 0x11, 500), context_),
              ObservationOutcome::NotNewerThanHeld);
    EXPECT_FALSE(ledger_.evaluate(candidate_.id, 1, context_).uptime_valid);
}

// Observers that disagree do not average out. The fact needs a quorum saying
// yes; observers that said nothing are simply absent, and safety holds.
TEST_F(LedgerTest, DisagreementDeniesTheFact) {
    give_participation(context_.quorum - 1);
    const auto evidence = ledger_.evaluate(candidate_.id, 1, context_);
    EXPECT_EQ(evidence.participation_observers, context_.quorum - 1);
    EXPECT_FALSE(evidence.mesh_health_valid);
}

// --- faults ---------------------------------------------------------------

TEST_F(LedgerTest, AnyObjectiveFaultDeniesMeshHealth) {
    for (const auto fault : {ObjectiveFault::DuplicateIncarnation,
                             ObjectiveFault::Equivocation,
                             ObjectiveFault::InvalidConsensusBehavior}) {
        EligibilityLedger ledger;
        for (std::size_t i = 0; i < context_.quorum; ++i) {
            EXPECT_EQ(ledger.record(participation(members_[i], candidate_, 300), context_),
                      ObservationOutcome::Accepted);
        }
        ASSERT_TRUE(ledger.evaluate(candidate_.id, 1, context_).mesh_health_valid);

        ledger.record_fault(candidate_.id, fault);
        const auto evidence = ledger.evaluate(candidate_.id, 1, context_);
        EXPECT_TRUE(evidence.fault_recorded);
        EXPECT_FALSE(evidence.mesh_health_valid);
        // Continuity is a separate question: a faulty node may still have been
        // continuously present, and the policy refuses it on health.
    }
}

// --- expiry ---------------------------------------------------------------

TEST_F(LedgerTest, ObservationsFromAnotherEpochAreRefused) {
    EligibilityObservation stale = attestation(members_[0], candidate_, 0x10, 100);
    stale.epoch = kEpoch - 1;
    stale = sign_observation(stale, members_[0].identity);
    EXPECT_EQ(ledger_.record(stale, context_), ObservationOutcome::WrongEpoch);
}

// A node does not stay eligible because it was healthy once. Facts are built
// per epoch and dropped at the boundary, so the mesh has to keep seeing it.
TEST_F(LedgerTest, FactsDoNotSurviveTheEpochBoundary) {
    give_continuity(context_.quorum);
    give_participation(context_.quorum);
    ASSERT_TRUE(ledger_.evaluate(candidate_.id, 1, context_).uptime_valid);

    const MeshFactContext next =
        established_fact_context(network(), kEpoch + 1, context_.observers);
    const auto evidence = ledger_.evaluate(candidate_.id, 1, next);
    EXPECT_FALSE(evidence.uptime_valid);
    EXPECT_FALSE(evidence.mesh_health_valid);

    ledger_.expire_before(kEpoch + 1);
    EXPECT_EQ(ledger_.size(), 0u);
}

TEST_F(LedgerTest, ObservationsFromAnotherNetworkAreRefused) {
    EligibilityObservation elsewhere = attestation(members_[0], candidate_, 0x10, 100);
    elsewhere.network_id.fill(0xB0);
    elsewhere = sign_observation(elsewhere, members_[0].identity);
    EXPECT_EQ(ledger_.record(elsewhere, context_), ObservationOutcome::WrongNetwork);
}

// --- durability -----------------------------------------------------------

TEST_F(LedgerTest, ASnapshotRoundTrips) {
    give_continuity(context_.quorum);
    give_participation(context_.quorum);
    const auto before = ledger_.evaluate(candidate_.id, 1, context_);

    EligibilityLedger restored;
    ASSERT_TRUE(restored.restore(ledger_.snapshot(), context_));
    const auto after = restored.evaluate(candidate_.id, 1, context_);
    EXPECT_EQ(after.uptime_valid, before.uptime_valid);
    EXPECT_EQ(after.mesh_health_valid, before.mesh_health_valid);
    EXPECT_EQ(after.continuity_observers, before.continuity_observers);
}

// Durable state is not trusted state. A restore re-runs every rule, so an
// edited file cannot assert a fact no observer signed.
TEST_F(LedgerTest, ATamperedSnapshotIsRefused) {
    give_continuity(context_.quorum);
    const auto good = ledger_.snapshot();

    {   // A forged signature.
        auto records = good;
        records[0].latest.signature[0] ^= 1;
        EligibilityLedger restored;
        EXPECT_FALSE(restored.restore(records, context_));
        EXPECT_EQ(restored.size(), 0u);
    }
    {   // Continuity claimed with no digests behind it.
        auto records = good;
        records[0].attestations.clear();
        EligibilityLedger restored;
        EXPECT_FALSE(restored.restore(records, context_));
    }
    {   // More digests than the compiled cap.
        auto records = good;
        records[0].attestations.assign(constants::kMaxContinuityAttestations + 1, digest(0x99));
        EligibilityLedger restored;
        EXPECT_FALSE(restored.restore(records, context_));
    }
    {   // An incarnation that disagrees with the statement it came from.
        auto records = good;
        records[0].incarnation += 1;
        EligibilityLedger restored;
        EXPECT_FALSE(restored.restore(records, context_));
    }
    {   // An observer that is no longer in the set.
        auto records = good;
        MeshFactContext smaller = context_;
        smaller.observers.erase(smaller.observers.begin());
        EligibilityLedger restored;
        EXPECT_FALSE(restored.restore(records, smaller));
    }
}

// A restart must not invent history, and it must not lose it either: what was
// durably recorded is exactly what comes back.
TEST_F(LedgerTest, AFreshLedgerHasNoHistory) {
    EligibilityLedger fresh;
    const auto evidence = fresh.evaluate(candidate_.id, 1, context_);
    EXPECT_FALSE(evidence.uptime_valid);
    EXPECT_FALSE(evidence.mesh_health_valid);
}

// --- Genesis --------------------------------------------------------------

TEST(GenesisFacts, EveryFounderMustBeSeenByEveryOther) {
    ASSERT_GE(sodium_init(), 0);
    std::vector<Node> founders;
    for (std::size_t i = 0; i < constants::kBootstrapThreshold; ++i) {
        founders.push_back(make_node());
    }
    std::vector<NodeId> ids;
    for (const auto& founder : founders) ids.push_back(founder.id);
    const MeshFactContext context = genesis_fact_context(network(), ids);

    // Mutual: no node observes itself, so the bar is one less than the set.
    EXPECT_EQ(context.quorum, constants::kBootstrapThreshold - 1);
    EXPECT_EQ(context.epoch, 0u);

    EligibilityLedger ledger;
    const auto observe = [&](const Node& observer, const Node& subject, uint8_t seed,
                             Height height, ObservationKind kind) {
        EligibilityObservation observation;
        observation.network_id = network();
        observation.epoch = 0;
        observation.subject = subject.id;
        observation.subject_incarnation = 1;
        observation.kind = kind;
        if (kind == ObservationKind::Attestation) {
            observation.attestation_digest = digest(seed);
        }
        observation.height = height;
        observation.state_reference = digest(0xC0);
        return ledger.record(sign_observation(observation, observer.identity), context);
    };

    // Every founder attests every other founder twice, and sees it participate.
    for (const auto& observer : founders) {
        for (const auto& subject : founders) {
            if (observer.id == subject.id) continue;
            EXPECT_EQ(observe(observer, subject, 0x10, 1, ObservationKind::Attestation),
                      ObservationOutcome::Accepted);
            EXPECT_EQ(observe(observer, subject, 0x11, 2, ObservationKind::Attestation),
                      ObservationOutcome::Accepted);
            EXPECT_EQ(observe(observer, subject, 0, 3, ObservationKind::Participation),
                      ObservationOutcome::Accepted);
        }
    }

    for (const auto& founder : founders) {
        const auto evidence = ledger.evaluate(founder.id, 1, context);
        EXPECT_TRUE(evidence.uptime_valid);
        EXPECT_TRUE(evidence.mesh_health_valid);
    }
}

// One founder short of mutual is not founding. The bootstrap threshold does
// not bend because a candidate is unavailable.
TEST(GenesisFacts, OneMissingFounderObservationDeniesTheFact) {
    ASSERT_GE(sodium_init(), 0);
    std::vector<Node> founders;
    for (std::size_t i = 0; i < constants::kBootstrapThreshold; ++i) {
        founders.push_back(make_node());
    }
    std::vector<NodeId> ids;
    for (const auto& founder : founders) ids.push_back(founder.id);
    const MeshFactContext context = genesis_fact_context(network(), ids);

    EligibilityLedger ledger;
    // founders[1] never observes founders[0].
    for (std::size_t i = 2; i < founders.size(); ++i) {
        for (const auto seed : {0x10, 0x11}) {
            EligibilityObservation observation;
            observation.network_id = network();
            observation.epoch = 0;
            observation.subject = founders[0].id;
            observation.subject_incarnation = 1;
            observation.kind = ObservationKind::Attestation;
            observation.attestation_digest = digest(static_cast<uint8_t>(seed));
            observation.height = static_cast<Height>(seed);
            observation.state_reference = digest(0xC0);
            EXPECT_EQ(ledger.record(sign_observation(observation, founders[i].identity), context),
                      ObservationOutcome::Accepted);
        }
    }
    const auto evidence = ledger.evaluate(founders[0].id, 1, context);
    EXPECT_EQ(evidence.continuity_observers, constants::kBootstrapThreshold - 2);
    EXPECT_FALSE(evidence.uptime_valid);
}
