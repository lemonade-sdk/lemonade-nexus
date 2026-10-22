#include <LemonadeNexus/Security/Attestation/AttestationService.hpp>
#include <LemonadeNexus/Security/EvidenceSnpSvsmVtpm.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include "support/attestation_fixtures.hpp"

#include <gtest/gtest.h>
#include <sodium.h>
#include <spdlog/sinks/base_sink.h>
#include <spdlog/spdlog.h>

#include <filesystem>
#include <memory>
#include <mutex>
#include <unistd.h>
#include <string_view>

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

/// Counts the rate-limited enrollment-refusal warn lines.
struct CountingWarnSink : spdlog::sinks::base_sink<std::mutex> {
    int refusals = 0;

protected:
    void sink_it_(const spdlog::details::log_msg& msg) override {
        const std::string_view text(msg.payload.data(), msg.payload.size());
        if (msg.level == spdlog::level::warn &&
            text.find("enrollment refused") != std::string_view::npos) {
            ++refusals;
        }
    }
    void flush_() override {}
};

struct EnrollmentFixture {
    nexus::crypto::Ed25519PublicKey pub{};
    nexus::crypto::Ed25519PrivateKey priv{};
    NodeId id;

    EnrollmentFixture() {
        EXPECT_GE(sodium_init(), 0);
        crypto_sign_keypair(pub.data(), priv.data());
        id.bytes = pub;
    }

    /// Enrollment evidence that clears every protocol gate; the attested
    /// platform half is garbage, so the identity verification refuses it.
    AttestationEvidence enrollment_answer(
        const nexus::security::AttestationChallenge& challenge) const {
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
        evidence.purpose = challenge.purpose;
        evidence.context_digest = challenge.context_digest;
        evidence.platform = nexus::security::SnpSvsmVtpmEvidence{};
        sign(evidence);
        return evidence;
    }

    void sign(AttestationEvidence& evidence) const {
        const auto digest = nexus::security::evidence_signing_digest(evidence);
        crypto_sign_detached(evidence.identity_signature.data(), nullptr, digest.data(),
                             digest.size(), priv.data());
    }
};

// The silent-refusal bug: a refused enrollment must name its condition so the
// router's drop carries a distinguishing nonzero code, and the refusal string
// must reach warn once per node, not once per retry.
TEST(AttestationService, EnrollmentRefusalIsTypedAndWarnsOncePerNode) {
    using nexus::security::EnrollmentRefusal;
    AttestationService service{network(0xA0), LinuxAttestationProfile{}};
    EnrollmentFixture subject;
    const NodeId observer = node(0x0B);

    // kTier1AttestationProfileId is SnpSvsmVtpm and no activation record
    // exists, so the issued challenge is the deferred enrollment challenge.
    const auto challenge = service.create_challenge(subject.id, subject.pub, 1, 9,
                                                    AttestationPurpose::Eligibility);
    ASSERT_TRUE(challenge.has_value());
    ASSERT_EQ(challenge->purpose, nexus::security::AttestationPurpose::PlatformEnrollment);

    auto sink = std::make_shared<CountingWarnSink>();
    spdlog::set_level(spdlog::level::info);
    spdlog::default_logger()->sinks().push_back(sink);

    // Evidence that answers no live challenge names the gate, not the platform.
    AttestationEvidence stranger = subject.enrollment_answer(*challenge);
    stranger.node_id = node(0x5E);
    EnrollmentRefusal refusal{};
    EXPECT_FALSE(service.receive_enrollment_evidence(stranger, observer, &refusal));
    EXPECT_EQ(refusal, EnrollmentRefusal::ChallengeMismatch);

    // A wrong platform payload shape is its own condition.
    AttestationEvidence with_log = subject.enrollment_answer(*challenge);
    std::get<nexus::security::SnpSvsmVtpmEvidence>(with_log.platform).ima_binary_log = {1};
    subject.sign(with_log);
    EXPECT_FALSE(service.receive_enrollment_evidence(with_log, observer, &refusal));
    EXPECT_EQ(refusal, EnrollmentRefusal::EvidenceMalformed);
    EXPECT_EQ(sink->refusals, 0);

    // The garbage SVSM report passes every gate and fails identity
    // verification: the typed reason distinguishes it, and the refusal string
    // reaches warn.
    const AttestationEvidence evidence = subject.enrollment_answer(*challenge);
    EXPECT_FALSE(service.receive_enrollment_evidence(evidence, observer, &refusal));
    EXPECT_EQ(refusal, EnrollmentRefusal::IdentityRejected);
    EXPECT_EQ(sink->refusals, 1);
    // A refusal does not consume the live challenge.
    EXPECT_TRUE(service.pending_challenge(subject.id).has_value());

    // The same node looping inside the window is counted, not logged again.
    EXPECT_FALSE(service.receive_enrollment_evidence(evidence, observer, &refusal));
    EXPECT_EQ(refusal, EnrollmentRefusal::IdentityRejected);
    EXPECT_EQ(sink->refusals, 1);

    // Another node gets its own first line.
    EnrollmentFixture other;
    const auto other_challenge = service.create_challenge(other.id, other.pub, 1, 9,
                                                          AttestationPurpose::Eligibility);
    ASSERT_TRUE(other_challenge.has_value());
    EXPECT_FALSE(service.receive_enrollment_evidence(
        other.enrollment_answer(*other_challenge), observer, &refusal));
    EXPECT_EQ(refusal, EnrollmentRefusal::IdentityRejected);
    EXPECT_EQ(sink->refusals, 2);

    // The out-parameter is optional: the old shape still refuses.
    EXPECT_FALSE(service.receive_enrollment_evidence(evidence, observer));

    spdlog::default_logger()->sinks().pop_back();
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

// A holder's StorageUnlock challenge lives in its own lane: it cannot cancel a
// member's pending eligibility challenge for the same node, it needs a bound
// context, and its per-epoch budget is separate.
TEST(AttestationService, StorageUnlockChallengesHaveTheirOwnLaneAndBudget) {
    // An enrolled subject: challenges keep their purpose instead of first
    // asking for SVSM enrollment.
    const auto dir = std::filesystem::temp_directory_path() /
                     ("nexus_storage_lane_" + std::to_string(::getpid()));
    std::filesystem::remove_all(dir);
    nexus_test::seed_svsm_activation(network(0xA0), node(0x11), key(0x11),
                                     dir / "svsm-activations");
    AttestationService service(network(0xA0), LinuxAttestationProfile{}, {}, dir);
    nexus::security::Digest context{};
    context.fill(0x33);
    EXPECT_FALSE(service
                     .create_challenge(node(0x11), key(0x11), 1, 9,
                                       AttestationPurpose::StorageUnlock)
                     .has_value());

    const auto eligibility =
        service.create_challenge(node(0x11), key(0x11), 1, 9, AttestationPurpose::Eligibility);
    ASSERT_TRUE(eligibility.has_value());
    const auto unlock = service.create_challenge(node(0x11), key(0x11), 1, 9,
                                                 AttestationPurpose::StorageUnlock, context);
    ASSERT_TRUE(unlock.has_value());
    EXPECT_EQ(unlock->purpose, AttestationPurpose::StorageUnlock);
    EXPECT_EQ(unlock->context_digest, context);
    // Both stay live, each in its own lane.
    const auto mesh_lane = service.pending_challenge(node(0x11));
    const auto storage_lane =
        service.pending_challenge(node(0x11), AttestationPurpose::StorageUnlock);
    ASSERT_TRUE(mesh_lane.has_value());
    ASSERT_TRUE(storage_lane.has_value());
    EXPECT_EQ(nexus::security::challenge_digest(*mesh_lane),
              nexus::security::challenge_digest(*eligibility));
    EXPECT_EQ(nexus::security::challenge_digest(*storage_lane),
              nexus::security::challenge_digest(*unlock));

    // The unlock budget per node and epoch is spent independently.
    for (uint32_t i = 1; i < constants::kStorageUnlocksPerRequesterPerEpoch; ++i) {
        EXPECT_TRUE(service
                        .create_challenge(node(0x11), key(0x11), 1, 9,
                                          AttestationPurpose::StorageUnlock, context)
                        .has_value());
    }
    EXPECT_FALSE(service
                     .create_challenge(node(0x11), key(0x11), 1, 9,
                                       AttestationPurpose::StorageUnlock, context)
                     .has_value());
    EXPECT_EQ(service.attempts(node(0x11), 9), 1u);
    std::filesystem::remove_all(dir);
}
