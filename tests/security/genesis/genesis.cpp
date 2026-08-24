#include <LemonadeNexus/Security/Genesis/BootstrapCertificate.hpp>
#include <LemonadeNexus/Security/Genesis/GenesisService.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

using nexus::security::AttestationFailure;
using nexus::security::AttestationVerdict;
using nexus::security::BootstrapCertificate;
using nexus::security::bootstrap_certificate_signing_digest;
using nexus::security::derive_network_id;
using nexus::security::dkg_transcript_attest_digest;
using nexus::security::Digest;
using nexus::security::GenesisService;
using nexus::security::NetworkId;
using nexus::security::NodeId;
using nexus::security::Tier1Set;
using nexus::security::verify_bootstrap_certificate;

namespace constants = nexus::security::constants;

namespace {

NodeId node(uint8_t byte) {
    NodeId id;
    id.bytes.fill(byte);
    return id;
}

AttestationVerdict verdict_for(const NodeId& id, bool passed) {
    AttestationVerdict verdict;
    verdict.node_id = id;
    verdict.passed = passed;
    verdict.failure = passed ? AttestationFailure::None : AttestationFailure::SnpInvalid;
    return verdict;
}

struct GenesisFixture : ::testing::Test {
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        crypto_sign_keypair(genesis_pub.data(), genesis_priv.data());
        network_id = derive_network_id(genesis_pub, constants::kSecurityRulesetVersion,
                                       constants::kConsensusRulesetVersion);
        service.emplace(network_id);
    }

    void admit_passing(std::size_t count, uint8_t first_byte = 0x10) {
        for (std::size_t i = 0; i < count; ++i) {
            const NodeId id = node(static_cast<uint8_t>(first_byte + i));
            ASSERT_TRUE(service->admit_candidate(id));
            ASSERT_TRUE(service->record_verdict(verdict_for(id, true)));
        }
    }

    struct Founder {
        nexus::crypto::Ed25519PublicKey pub{};
        nexus::crypto::Ed25519PrivateKey priv{};
        NodeId id;
    };

    // Founders with real identity keys, so they can sign transcript attests.
    void admit_real_founders(std::size_t count) {
        for (std::size_t i = 0; i < count; ++i) {
            Founder founder;
            crypto_sign_keypair(founder.pub.data(), founder.priv.data());
            founder.id.bytes = founder.pub;
            ASSERT_TRUE(service->admit_candidate(founder.id));
            ASSERT_TRUE(service->record_verdict(verdict_for(founder.id, true)));
            founders.push_back(founder);
        }
    }

    nexus::security::DkgTranscriptAttest attest_from(const Founder& founder, const Digest& transcript,
                                                     const nexus::crypto::Ed25519PublicKey& group) {
        nexus::security::DkgTranscriptAttest attest;
        attest.epoch = 1;
        attest.participant_set_digest = service->founding_set()->digest();
        attest.transcript_digest = transcript;
        attest.group_public_key = group;
        attest.node = founder.id;
        const Digest digest = dkg_transcript_attest_digest(attest);
        crypto_sign_detached(attest.identity_signature.data(), nullptr, digest.data(),
                             digest.size(), founder.priv.data());
        return attest;
    }

    void attest_all(const Digest& transcript, const nexus::crypto::Ed25519PublicKey& group) {
        for (const auto& founder : founders) {
            ASSERT_TRUE(service->record_transcript_attest(attest_from(founder, transcript, group)));
        }
    }

    std::vector<Founder> founders;

    nexus::crypto::Ed25519PublicKey genesis_pub{};
    nexus::crypto::Ed25519PrivateKey genesis_priv{};
    NetworkId network_id{};
    std::optional<GenesisService> service;
};

TEST_F(GenesisFixture, QuorumNeedsBootstrapThresholdPassingVerdicts) {
    admit_passing(constants::kBootstrapThreshold - 1);
    EXPECT_FALSE(service->quorum_ready());
    EXPECT_FALSE(service->founding_set().has_value());

    const NodeId last = node(0x40);
    ASSERT_TRUE(service->admit_candidate(last));
    EXPECT_FALSE(service->quorum_ready());
    ASSERT_TRUE(service->record_verdict(verdict_for(last, true)));
    EXPECT_TRUE(service->quorum_ready());
}

TEST_F(GenesisFixture, FailedVerdictDoesNotCount) {
    admit_passing(constants::kBootstrapThreshold - 1);
    const NodeId last = node(0x40);
    ASSERT_TRUE(service->admit_candidate(last));
    ASSERT_TRUE(service->record_verdict(verdict_for(last, false)));
    EXPECT_FALSE(service->quorum_ready());

    // A later passing verdict replaces the failed one.
    ASSERT_TRUE(service->record_verdict(verdict_for(last, true)));
    EXPECT_TRUE(service->quorum_ready());
}

TEST_F(GenesisFixture, VerdictForUnknownCandidateRefused) {
    EXPECT_FALSE(service->record_verdict(verdict_for(node(0x99), true)));
}

TEST_F(GenesisFixture, DuplicateCandidateRefused) {
    ASSERT_TRUE(service->admit_candidate(node(0x10)));
    EXPECT_FALSE(service->admit_candidate(node(0x10)));
}

TEST_F(GenesisFixture, FoundingSetTakesLowestQualifyingIdentities) {
    admit_passing(constants::kBootstrapThreshold + 2, 0x20);
    const auto founders = service->founding_set();
    ASSERT_TRUE(founders.has_value());
    ASSERT_EQ(founders->size(), constants::kBootstrapThreshold);

    std::vector<NodeId> expected;
    for (std::size_t i = 0; i < constants::kBootstrapThreshold; ++i) {
        expected.push_back(node(static_cast<uint8_t>(0x20 + i)));
    }
    EXPECT_EQ(founders->members(), expected);
}

TEST_F(GenesisFixture, FinalizeBeforeQuorumRefused) {
    admit_passing(constants::kBootstrapThreshold - 1);
    nexus::crypto::Ed25519PublicKey authority{};
    EXPECT_FALSE(
        service->finalize_epoch_one(authority, Digest{}, Digest{}, genesis_priv).has_value());
    EXPECT_FALSE(service->finalized());
}

TEST_F(GenesisFixture, TranscriptAttestRules) {
    admit_real_founders(constants::kBootstrapThreshold);
    nexus::crypto::Ed25519PublicKey group{};
    group.fill(0x77);
    Digest transcript;
    transcript.fill(0x55);

    // A non-founder, a bad signature, and a wrong epoch are refused.
    Founder outsider;
    crypto_sign_keypair(outsider.pub.data(), outsider.priv.data());
    outsider.id.bytes = outsider.pub;
    EXPECT_FALSE(service->record_transcript_attest(attest_from(outsider, transcript, group)));

    auto forged = attest_from(founders[0], transcript, group);
    forged.identity_signature[0] ^= 0x01;
    EXPECT_FALSE(service->record_transcript_attest(forged));

    auto wrong_epoch = attest_from(founders[0], transcript, group);
    wrong_epoch.epoch = 2;
    EXPECT_FALSE(service->record_transcript_attest(wrong_epoch));

    // Four agreeing founders and one dissenting: no agreement, no certificate.
    for (std::size_t i = 0; i + 1 < founders.size(); ++i) {
        ASSERT_TRUE(service->record_transcript_attest(attest_from(founders[i], transcript, group)));
    }
    Digest other;
    other.fill(0x56);
    ASSERT_TRUE(service->record_transcript_attest(attest_from(founders.back(), other, group)));
    EXPECT_FALSE(service->transcript_agreed());
    EXPECT_FALSE(service->finalize_epoch_one(group, transcript, Digest{}, genesis_priv).has_value());

    // The dissenter re-attests the agreed transcript.
    ASSERT_TRUE(service->record_transcript_attest(attest_from(founders.back(), transcript, group)));
    EXPECT_TRUE(service->transcript_agreed());

    // Genesis signs only what the founders attested.
    nexus::crypto::Ed25519PublicKey other_group{};
    other_group.fill(0x78);
    EXPECT_FALSE(service->finalize_epoch_one(other_group, transcript, Digest{}, genesis_priv).has_value());
    EXPECT_FALSE(service->finalize_epoch_one(group, other, Digest{}, genesis_priv).has_value());
    EXPECT_TRUE(service->finalize_epoch_one(group, transcript, Digest{}, genesis_priv).has_value());
}

TEST_F(GenesisFixture, FinalizeSignsVerifiableCertificateAndEndsAuthority) {
    admit_real_founders(constants::kBootstrapThreshold);

    nexus::crypto::Ed25519PublicKey authority{};
    authority.fill(0x77);
    Digest dkg_digest;
    dkg_digest.fill(0x55);
    Digest attestation_root;
    attestation_root.fill(0x66);
    attest_all(dkg_digest, authority);

    const auto certificate =
        service->finalize_epoch_one(authority, dkg_digest, attestation_root, genesis_priv);
    ASSERT_TRUE(certificate.has_value());

    EXPECT_EQ(certificate->network_id, network_id);
    EXPECT_EQ(certificate->epoch, 1u);
    EXPECT_EQ(certificate->authority_threshold, constants::kBootstrapThreshold);
    EXPECT_EQ(certificate->tier1_set_digest, service->founding_set()->digest());
    EXPECT_TRUE(verify_bootstrap_certificate(*certificate, genesis_pub));

    // A different key must not verify it.
    nexus::crypto::Ed25519PublicKey other_pub{};
    nexus::crypto::Ed25519PrivateKey other_priv{};
    crypto_sign_keypair(other_pub.data(), other_priv.data());
    EXPECT_FALSE(verify_bootstrap_certificate(*certificate, other_pub));

    // Any tampered field must not verify.
    auto tampered = *certificate;
    tampered.authority_threshold += 1;
    EXPECT_FALSE(verify_bootstrap_certificate(tampered, genesis_pub));

    // Genesis authority is over: nothing mutates any more.
    EXPECT_TRUE(service->finalized());
    EXPECT_FALSE(service->admit_candidate(node(0xEE)));
    EXPECT_FALSE(service->record_verdict(verdict_for(founders[0].id, true)));
    EXPECT_FALSE(service->record_transcript_attest(attest_from(founders[0], dkg_digest, authority)));
    EXPECT_FALSE(
        service->finalize_epoch_one(authority, dkg_digest, attestation_root, genesis_priv)
            .has_value());
}

TEST(NetworkId, DerivationIsSensitiveToEveryInput) {
    nexus::crypto::Ed25519PublicKey key_a{};
    key_a.fill(0x01);
    nexus::crypto::Ed25519PublicKey key_b{};
    key_b.fill(0x02);

    const auto base = derive_network_id(key_a, 1, 1);
    EXPECT_EQ(base, derive_network_id(key_a, 1, 1));
    EXPECT_NE(base, derive_network_id(key_b, 1, 1));
    EXPECT_NE(base, derive_network_id(key_a, 2, 1));
    EXPECT_NE(base, derive_network_id(key_a, 1, 2));
}

}  // namespace
