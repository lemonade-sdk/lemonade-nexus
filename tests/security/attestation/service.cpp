#include <LemonadeNexus/Security/Attestation/AttestationService.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>

using nexus::security::AttestationEvidence;
using nexus::security::AttestationFailure;
using nexus::security::AttestationPurpose;
using nexus::security::AttestationService;
using nexus::security::LinuxAttestationProfile;
using nexus::security::Nonce;
using nexus::security::NodeId;

namespace constants = nexus::security::constants;

namespace {

NodeId node(uint8_t byte) {
    NodeId id;
    id.bytes.fill(byte);
    return id;
}

nexus::security::NetworkId network(uint8_t byte) {
    nexus::security::NetworkId id{};
    id.fill(byte);
    return id;
}

nexus::crypto::Ed25519PublicKey key(uint8_t byte) {
    nexus::crypto::Ed25519PublicKey value{};
    value.fill(byte);
    return value;
}

TEST(AttestationService, ChallengeBindsPolicyEpochAndIdentity) {
    AttestationService service{network(0xA0), LinuxAttestationProfile{}};
    const auto challenge = service.create_challenge(node(0x01), key(0x11), 3, 9, AttestationPurpose::Eligibility);
    ASSERT_TRUE(challenge.has_value());
    EXPECT_EQ(challenge->policy_digest, service.policy_digest());
    EXPECT_EQ(challenge->node_id, node(0x01));
    EXPECT_EQ(challenge->node_key, key(0x11));
    EXPECT_EQ(challenge->incarnation, 3u);
    EXPECT_EQ(challenge->epoch, 9u);
    EXPECT_EQ(challenge->security_ruleset, constants::kSecurityRulesetVersion);
    EXPECT_NE(challenge->nonce, Nonce{});

    const auto second = service.create_challenge(node(0x01), key(0x11), 3, 9, AttestationPurpose::Eligibility);
    ASSERT_TRUE(second.has_value());
    EXPECT_NE(second->nonce, challenge->nonce);
}

TEST(AttestationService, BudgetBindsToNodeAndEpoch) {
    AttestationService service{network(0xA0), LinuxAttestationProfile{}};
    for (uint32_t i = 0; i < constants::kMaxTier1AttestAttemptsPerEpoch; ++i) {
        EXPECT_TRUE(service.create_challenge(node(0x01), key(0x11), 1, 9, AttestationPurpose::Eligibility).has_value());
    }
    EXPECT_FALSE(service.create_challenge(node(0x01), key(0x11), 1, 9, AttestationPurpose::Eligibility).has_value());
    EXPECT_EQ(service.attempts(node(0x01), 9), constants::kMaxTier1AttestAttemptsPerEpoch);

    // Another node and another epoch have their own budgets.
    EXPECT_TRUE(service.create_challenge(node(0x02), key(0x12), 1, 9, AttestationPurpose::Eligibility).has_value());
    EXPECT_TRUE(service.create_challenge(node(0x01), key(0x11), 1, 10, AttestationPurpose::Eligibility).has_value());
}

TEST(AttestationService, EvidenceWithoutChallengeFails) {
    AttestationService service{network(0xA0), LinuxAttestationProfile{}};
    AttestationEvidence evidence;
    evidence.node_id = node(0x01);
    const auto verdict = service.receive_evidence(evidence);
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::ChallengeMismatch);
    EXPECT_FALSE(service.verdict(node(0x01)).has_value());
}

/// A bundle that answers `challenge` at the protocol fields. The platform half
/// is empty, so the verdict fails later — consumption is what is under test.
AttestationEvidence answer(const nexus::security::AttestationChallenge& challenge) {
    AttestationEvidence evidence;
    evidence.network_id = challenge.network_id;
    evidence.challenge_digest = nexus::security::challenge_digest(challenge);
    evidence.node_id = challenge.node_id;
    evidence.incarnation = challenge.incarnation;
    evidence.epoch = challenge.epoch;
    evidence.security_ruleset = challenge.security_ruleset;
    evidence.consensus_ruleset = challenge.consensus_ruleset;
    evidence.profile_id = challenge.profile_id;
    evidence.profile_ruleset = challenge.profile_ruleset;
    return evidence;
}

TEST(AttestationService, ChallengeIsConsumedByOneAnswer) {
    AttestationService service{network(0xA0), LinuxAttestationProfile{}};
    const auto challenge = service.create_challenge(node(0x01), key(0x11), 1, 9, AttestationPurpose::Eligibility);
    ASSERT_TRUE(challenge.has_value());

    const AttestationEvidence evidence = answer(*challenge);
    const auto first = service.receive_evidence(evidence);
    EXPECT_FALSE(first.passed);
    ASSERT_TRUE(service.verdict(node(0x01)).has_value());
    EXPECT_FALSE(service.verdict(node(0x01))->passed);

    // The same challenge cannot be answered twice.
    const auto second = service.receive_evidence(evidence);
    EXPECT_EQ(second.failure, AttestationFailure::ChallengeMismatch);
}

// A bundle that answers no live challenge must not cancel one. Without this a
// peer could send stale or fabricated evidence for a node, consume that node's
// pending challenge, and the honest answer that follows would find nothing
// outstanding — attestation denial of service by anyone who knows a node ID.
TEST(AttestationService, StaleEvidenceDoesNotConsumeTheLiveChallenge) {
    AttestationService service{network(0xA0), LinuxAttestationProfile{}};
    const auto stale = service.create_challenge(node(0x01), key(0x11), 1, 9, AttestationPurpose::Eligibility);
    ASSERT_TRUE(stale.has_value());
    const AttestationEvidence stale_answer = answer(*stale);

    // A second challenge replaces the first: only the latest is live.
    const auto live = service.create_challenge(node(0x01), key(0x11), 1, 9, AttestationPurpose::Eligibility);
    ASSERT_TRUE(live.has_value());
    ASSERT_NE(live->nonce, stale->nonce);

    EXPECT_EQ(service.receive_evidence(stale_answer).failure,
              AttestationFailure::ChallengeMismatch);
    // No verdict was recorded, and the live challenge is still outstanding.
    EXPECT_FALSE(service.verdict(node(0x01)).has_value());

    const auto verdict = service.receive_evidence(answer(*live));
    EXPECT_NE(verdict.failure, AttestationFailure::ChallengeMismatch);
    EXPECT_TRUE(service.verdict(node(0x01)).has_value());
}

// Two meshes, one node identity, one platform. A bundle built for the first
// mesh must not answer the second, and the answer must be diagnosable as a
// cross-network attempt rather than as a replay.
TEST(AttestationService, EvidenceDoesNotCrossNetworks) {
    AttestationService here{network(0xA0), LinuxAttestationProfile{}};
    AttestationService elsewhere{network(0xB0), LinuxAttestationProfile{}};
    ASSERT_NE(here.network_id(), elsewhere.network_id());

    const auto foreign = elsewhere.create_challenge(node(0x01), key(0x11), 1, 9, AttestationPurpose::Eligibility);
    ASSERT_TRUE(foreign.has_value());
    const AttestationEvidence for_elsewhere = answer(*foreign);

    // Our own challenge is outstanding for the same node, same incarnation,
    // same epoch. Only the network differs.
    const auto ours = here.create_challenge(node(0x01), key(0x11), 1, 9, AttestationPurpose::Eligibility);
    ASSERT_TRUE(ours.has_value());
    EXPECT_EQ(ours->incarnation, foreign->incarnation);
    EXPECT_EQ(ours->epoch, foreign->epoch);

    EXPECT_EQ(here.receive_evidence(for_elsewhere).failure,
              AttestationFailure::ChallengeMismatch);
    // The foreign bundle answered nothing, so it consumed nothing.
    EXPECT_FALSE(here.verdict(node(0x01)).has_value());
    EXPECT_NE(here.receive_evidence(answer(*ours)).failure,
              AttestationFailure::ChallengeMismatch);
}

}  // namespace

// Eligibility and final readiness are budgeted separately, and the final
// bucket is scoped to one plan-bound context: a replacement attempt starts
// fresh, so exhaustion ends an attempt, never an identity's ability to
// attest.
TEST(AttestationService, PurposeBudgetsAreIndependentAndFinalIsPerPlan) {
    AttestationService service(network(0xA0), LinuxAttestationProfile{});
    nexus::security::Digest attempt_zero{};
    attempt_zero.fill(0x77);
    nexus::security::Digest attempt_one{};
    attempt_one.fill(0x78);

    // Spend the whole eligibility budget for (node, epoch 9)...
    for (uint32_t i = 0; i < constants::kMaxTier1AttestAttemptsPerEpoch; ++i) {
        EXPECT_TRUE(service
                        .create_challenge(node(0x01), key(0x11), 1, 9,
                                          nexus::security::AttestationPurpose::Eligibility)
                        .has_value());
    }
    EXPECT_FALSE(service
                     .create_challenge(node(0x01), key(0x11), 1, 9,
                                       nexus::security::AttestationPurpose::Eligibility)
                     .has_value());

    // ...final-readiness challenges under one plan context are unaffected,
    // and bounded by their own per-plan budget.
    for (uint32_t i = 0; i < constants::kMaxFinalAttestAttemptsPerPlan; ++i) {
        EXPECT_TRUE(service
                        .create_challenge(node(0x01), key(0x11), 1, 9,
                                          nexus::security::AttestationPurpose::FinalEpochReadiness,
                                          attempt_zero)
                        .has_value())
            << "final challenge " << i;
    }
    EXPECT_FALSE(service
                     .create_challenge(node(0x01), key(0x11), 1, 9,
                                       nexus::security::AttestationPurpose::FinalEpochReadiness,
                                       attempt_zero)
                     .has_value());

    // A replacement attempt is a new context and a fresh bucket.
    EXPECT_TRUE(service
                    .create_challenge(node(0x01), key(0x11), 1, 9,
                                      nexus::security::AttestationPurpose::FinalEpochReadiness,
                                      attempt_one)
                    .has_value());

    EXPECT_EQ(service.attempts(node(0x01), 9), constants::kMaxTier1AttestAttemptsPerEpoch);
    EXPECT_EQ(service.final_attempts(node(0x01), attempt_zero),
              constants::kMaxFinalAttestAttemptsPerPlan);
    EXPECT_EQ(service.final_attempts(node(0x01), attempt_one), 1u);
}
