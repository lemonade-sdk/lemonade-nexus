#include <LemonadeNexus/Security/Attestation/AttestationService.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>

using nexus::security::AttestationEvidence;
using nexus::security::AttestationFailure;
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

nexus::crypto::Ed25519PublicKey key(uint8_t byte) {
    nexus::crypto::Ed25519PublicKey value{};
    value.fill(byte);
    return value;
}

TEST(AttestationService, ChallengeBindsPolicyEpochAndIdentity) {
    AttestationService service{LinuxAttestationProfile{}};
    const auto challenge = service.create_challenge(node(0x01), key(0x11), 3, 9);
    ASSERT_TRUE(challenge.has_value());
    EXPECT_EQ(challenge->policy_digest, service.policy_digest());
    EXPECT_EQ(challenge->node_id, node(0x01));
    EXPECT_EQ(challenge->node_key, key(0x11));
    EXPECT_EQ(challenge->incarnation, 3u);
    EXPECT_EQ(challenge->epoch, 9u);
    EXPECT_EQ(challenge->security_ruleset, constants::kSecurityRulesetVersion);
    EXPECT_NE(challenge->nonce, Nonce{});

    const auto second = service.create_challenge(node(0x01), key(0x11), 3, 9);
    ASSERT_TRUE(second.has_value());
    EXPECT_NE(second->nonce, challenge->nonce);
}

TEST(AttestationService, BudgetBindsToNodeAndEpoch) {
    AttestationService service{LinuxAttestationProfile{}};
    for (uint32_t i = 0; i < constants::kMaxTier1AttestAttemptsPerEpoch; ++i) {
        EXPECT_TRUE(service.create_challenge(node(0x01), key(0x11), 1, 9).has_value());
    }
    EXPECT_FALSE(service.create_challenge(node(0x01), key(0x11), 1, 9).has_value());
    EXPECT_EQ(service.attempts(node(0x01), 9), constants::kMaxTier1AttestAttemptsPerEpoch);

    // Another node and another epoch have their own budgets.
    EXPECT_TRUE(service.create_challenge(node(0x02), key(0x12), 1, 9).has_value());
    EXPECT_TRUE(service.create_challenge(node(0x01), key(0x11), 1, 10).has_value());
}

TEST(AttestationService, EvidenceWithoutChallengeFails) {
    AttestationService service{LinuxAttestationProfile{}};
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
    AttestationService service{LinuxAttestationProfile{}};
    const auto challenge = service.create_challenge(node(0x01), key(0x11), 1, 9);
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
    AttestationService service{LinuxAttestationProfile{}};
    const auto stale = service.create_challenge(node(0x01), key(0x11), 1, 9);
    ASSERT_TRUE(stale.has_value());
    const AttestationEvidence stale_answer = answer(*stale);

    // A second challenge replaces the first: only the latest is live.
    const auto live = service.create_challenge(node(0x01), key(0x11), 1, 9);
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

}  // namespace
