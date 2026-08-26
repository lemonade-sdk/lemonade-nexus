#include <LemonadeNexus/Security/Attestation/AttestationVerifier.hpp>
#include <LemonadeNexus/Security/Attestation/PlatformEvidenceProducer.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <array>
#include <cstdint>
#include <optional>
#include <utility>

namespace constants = nexus::security::constants;

using nexus::security::AttestationChallenge;
using nexus::security::AttestationEvidence;
using nexus::security::AttestationFailure;
using nexus::security::AttestationVerdict;
using nexus::security::AttestationVerifier;
using nexus::security::Digest;
using nexus::security::EpochId;
using nexus::security::EvidenceProducerSources;
using nexus::security::LinuxAttestationProfile;
using nexus::security::PlatformEvidenceProducer;
using nexus::security::challenge_digest;
using nexus::security::evidence_signing_digest;
using nexus::security::profile_digest;

namespace {

template <std::size_t N>
std::array<uint8_t, N> patterned(uint8_t seed) {
    std::array<uint8_t, N> out{};
    for (std::size_t i = 0; i < N; ++i) {
        out[i] = static_cast<uint8_t>(seed + i);
    }
    return out;
}

constexpr const char* kApprovedBinary =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

class PlatformEvidenceProducerTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        ASSERT_EQ(crypto_sign_keypair(identity_.public_key.data(), identity_.private_key.data()),
                  0);
        nexus::crypto::Ed25519PrivateKey vote_sk{};
        ASSERT_EQ(crypto_sign_keypair(vote_pk_.data(), vote_sk.data()), 0);

        // A COMPLETE profile: examine() refuses everything under an incomplete
        // one, so the binding checks below would otherwise be unreachable.
        profile_ = nexus::security::linux_attestation_profile_v1();
        profile_.snp.min_tcb = {2, 0, 6, 55};
        profile_.snp.expected_measurement_hex = std::string(96, 'a');
        profile_.ima_policy_digest.fill(0x60);
        profile_.approved_binary_sha256 = {kApprovedBinary};
        ASSERT_TRUE(nexus::security::profile_is_complete(profile_));

        challenge_.nonce = patterned<32>(0x01);
        challenge_.node_id.bytes = identity_.public_key;
        challenge_.node_key = identity_.public_key;
        challenge_.incarnation = 3;
        challenge_.epoch = 9;
        challenge_.security_ruleset = constants::kSecurityRulesetVersion;
        challenge_.policy_digest = profile_digest(profile_);
    }

    /// Sources with a vote key for the fixture epoch only.
    [[nodiscard]] EvidenceProducerSources sources() const {
        EvidenceProducerSources out;
        out.identity = identity_;
        // Bound to the epoch the fixture issued, not to a later mutation of
        // the challenge.
        const EpochId key_epoch = challenge_.epoch;
        const auto vote_pk = vote_pk_;
        out.vote_key_for_epoch =
            [key_epoch, vote_pk](EpochId epoch) -> std::optional<nexus::crypto::Ed25519PublicKey> {
            if (epoch == key_epoch) {
                return vote_pk;
            }
            return std::nullopt;
        };
        out.cache_directory = ::testing::TempDir();
        out.nexus_binary_path = "/opt/nexus/bin/nexus";
        return out;
    }

    [[nodiscard]] AttestationVerdict examine(const AttestationEvidence& evidence) const {
        return verifier_.examine(challenge_, evidence, profile_);
    }

    nexus::crypto::Ed25519Keypair identity_;
    nexus::crypto::Ed25519PublicKey vote_pk_{};
    LinuxAttestationProfile profile_;
    AttestationChallenge challenge_;
    AttestationVerifier verifier_;
};

// --- Refusals -----------------------------------------------------------------

TEST_F(PlatformEvidenceProducerTest, ChallengeForAnotherNodeIdIsNotAnswered) {
    PlatformEvidenceProducer producer{sources()};
    challenge_.node_id.bytes[0] ^= 1;
    EXPECT_FALSE(producer.produce(challenge_).has_value());
}

TEST_F(PlatformEvidenceProducerTest, ChallengeForAnotherNodeKeyIsNotAnswered) {
    PlatformEvidenceProducer producer{sources()};
    challenge_.node_key[0] ^= 1;
    EXPECT_FALSE(producer.produce(challenge_).has_value());
}

TEST_F(PlatformEvidenceProducerTest, NoVoteKeyForEpochIsNotAnswered) {
    PlatformEvidenceProducer producer{sources()};
    challenge_.epoch += 1;
    EXPECT_FALSE(producer.produce(challenge_).has_value());
}

TEST_F(PlatformEvidenceProducerTest, NoVoteKeySourceIsNotAnswered) {
    EvidenceProducerSources without_source = sources();
    without_source.vote_key_for_epoch = nullptr;
    PlatformEvidenceProducer producer{std::move(without_source)};
    EXPECT_FALSE(producer.produce(challenge_).has_value());
}

// --- Produced evidence --------------------------------------------------------

TEST_F(PlatformEvidenceProducerTest, EvidenceBindsChallengeIdentityAndVoteKey) {
    PlatformEvidenceProducer producer{sources()};
    const auto evidence = producer.produce(challenge_);
    ASSERT_TRUE(evidence.has_value());

    EXPECT_EQ(evidence->challenge_digest, challenge_digest(challenge_));
    EXPECT_EQ(evidence->node_id, challenge_.node_id);
    EXPECT_EQ(evidence->incarnation, challenge_.incarnation);
    EXPECT_EQ(evidence->security_ruleset, constants::kSecurityRulesetVersion);
    EXPECT_EQ(evidence->consensus_ruleset, constants::kConsensusRulesetVersion);
    EXPECT_EQ(evidence->epoch_vote_key, vote_pk_);

    const Digest digest = evidence_signing_digest(*evidence);
    EXPECT_EQ(crypto_sign_verify_detached(evidence->identity_signature.data(), digest.data(),
                                          digest.size(), identity_.public_key.data()),
              0);
}

TEST_F(PlatformEvidenceProducerTest, VerifierPassesEveryBindingCheck) {
    PlatformEvidenceProducer producer{sources()};
    const auto evidence = producer.produce(challenge_);
    ASSERT_TRUE(evidence.has_value());

    // The binding checks all hold, so only the platform step can fail. The
    // fixture's approved list never matches a real host, so no host passes.
    const auto verdict = examine(*evidence);
    EXPECT_FALSE(verdict.passed);
    EXPECT_NE(verdict.failure, AttestationFailure::ChallengeMismatch);
    EXPECT_NE(verdict.failure, AttestationFailure::IdentityMismatch);
    EXPECT_NE(verdict.failure, AttestationFailure::IdentitySignatureInvalid);
    EXPECT_NE(verdict.failure, AttestationFailure::IncarnationStale);
    EXPECT_NE(verdict.failure, AttestationFailure::RulesetMismatch);
    EXPECT_NE(verdict.failure, AttestationFailure::ProfileIncomplete);
    EXPECT_EQ(verdict.node_id, challenge_.node_id);
    EXPECT_EQ(verdict.epoch, challenge_.epoch);
    EXPECT_EQ(verdict.incarnation, challenge_.incarnation);
    EXPECT_EQ(verdict.evidence_digest, evidence_signing_digest(*evidence));

    const auto again = examine(*evidence);
    EXPECT_EQ(again.passed, verdict.passed);
    EXPECT_EQ(again.failure, verdict.failure);
    EXPECT_EQ(again.evidence_digest, verdict.evidence_digest);

#ifndef LEMONADE_HAVE_TPM_FAPI
    // This build has no platform path: the bundle is empty and the platform
    // chain rejects it as garbage.
    EXPECT_FALSE(producer.platform_available());
    EXPECT_TRUE(evidence->platform.empty());
    EXPECT_EQ(verdict.failure, AttestationFailure::SnpInvalid);
#endif
}

TEST_F(PlatformEvidenceProducerTest, DifferentChallengesYieldDifferentEvidence) {
    PlatformEvidenceProducer producer{sources()};
    const auto first = producer.produce(challenge_);
    ASSERT_TRUE(first.has_value());

    challenge_.nonce = patterned<32>(0x40);
    const auto second = producer.produce(challenge_);
    ASSERT_TRUE(second.has_value());

    EXPECT_NE(first->challenge_digest, second->challenge_digest);
    EXPECT_NE(first->identity_signature, second->identity_signature);
}

TEST_F(PlatformEvidenceProducerTest, TamperedVoteKeyFailsIdentitySignature) {
    PlatformEvidenceProducer producer{sources()};
    auto evidence = producer.produce(challenge_);
    ASSERT_TRUE(evidence.has_value());

    evidence->epoch_vote_key[0] ^= 1;
    EXPECT_EQ(examine(*evidence).failure, AttestationFailure::IdentitySignatureInvalid);
}

}  // namespace
