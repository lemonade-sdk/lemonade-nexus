// The production path across the privilege boundary.
//
//   AttestationChallenge -> nexus-attestd -> PlatformEvidenceBundle
//                        -> Nexus assembles + signs -> AttestationVerifier
//
// The daemon half runs in-process here because the split that matters is the
// KEY split, not the socket: the daemon is constructed with no identity, and
// every signature below is produced by PlatformEvidenceProducer. If the daemon
// could sign, these tests could not tell the difference — so they also assert
// the bundle carries no signature and no vote key.

#include <LemonadeNexus/Security/Attestation/AttestationService.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationVerifier.hpp>
#include <LemonadeNexus/Security/Attestation/LinuxAttestationProfile.hpp>
#include <LemonadeNexus/Security/Attestation/PlatformEvidenceProducer.hpp>
#include <LemonadeNexusAttestd/AttestdCodec.hpp>
#include <LemonadeNexusAttestd/AttestdGate.hpp>
#include <LemonadeNexusAttestd/AttestdService.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <optional>
#include <string>

using namespace nexus::security;
namespace attestd = nexus::attestd;
namespace crypto = nexus::crypto;

namespace {

crypto::Ed25519Keypair seeded(uint8_t byte) {
    crypto::Ed25519Keypair kp;
    std::array<uint8_t, crypto_sign_SEEDBYTES> seed{};
    seed.fill(byte);
    crypto_sign_seed_keypair(kp.public_key.data(), kp.private_key.data(), seed.data());
    return kp;
}

NetworkId net(uint8_t b) {
    NetworkId n{};
    n.fill(b);
    return n;
}

/// The daemon, wired in as the producer's platform source. It receives only the
/// nonce and the identity public key, exactly as the socket path would.
PlatformEvidenceSource attestd_source(attestd::AttestdService& daemon,
                                      const AttestationChallenge& challenge,
                                      attestd::Refusal* refusal_out) {
    return [&daemon, challenge, refusal_out](const Digest& nonce,
                                             const crypto::Ed25519PublicKey&) {
        attestd::PlatformEvidenceBundle bundle;
        std::string detail;
        const attestd::Refusal r = daemon.answer(challenge, bundle, &detail);
        if (refusal_out) *refusal_out = r;
        // The producer's nonce and the daemon's derived digest must agree, or
        // the bundle answers a different challenge than the one being signed.
        EXPECT_EQ(bundle.challenge_digest, nonce)
            << "the daemon bound its evidence to a different challenge";
        return bundle.platform;
    };
}

struct AttestdIntegration : ::testing::Test {
    void SetUp() override { ASSERT_GE(sodium_init(), 0); }

    crypto::Ed25519Keypair identity_ = seeded(0x21);
    crypto::Ed25519PublicKey vote_key_ = seeded(0x22).public_key;
    NetworkId network_ = net(0x33);

    LinuxAttestationProfile profile() const { return linux_attestation_profile_v1(); }

    AttestationChallenge challenge_for(AttestationPurpose purpose) {
        AttestationService service(network_, profile());
        NodeId node{};
        node.bytes = identity_.public_key;
        Digest context{};
        if (purpose == AttestationPurpose::FinalEpochReadiness) context.fill(0x44);
        auto c = service.create_challenge(node, identity_.public_key, /*incarnation*/ 3,
                                          /*epoch*/ 9, purpose, context);
        EXPECT_TRUE(c.has_value());
        return c.value_or(AttestationChallenge{});
    }

    /// The whole path: challenge -> daemon -> producer -> signed evidence.
    std::optional<AttestationEvidence> run(const AttestationChallenge& challenge,
                                           attestd::Refusal* refusal = nullptr) {
        attestd::AttestdConfig cfg;  // no identity field exists to set
        attestd::AttestdService daemon{cfg};

        EvidenceProducerSources sources;
        sources.identity = identity_;
        sources.vote_key_for_epoch = [this](EpochId) { return vote_key_; };
        sources.platform_source = attestd_source(daemon, challenge, refusal);
        return PlatformEvidenceProducer(std::move(sources)).produce(challenge);
    }
};

}  // namespace

// --- the boundary ----------------------------------------------------------

TEST_F(AttestdIntegration, TheDaemonReturnsNoSignatureAndNoVoteKey) {
    attestd::AttestdConfig cfg;
    attestd::AttestdService daemon{cfg};
    const auto challenge = challenge_for(AttestationPurpose::Eligibility);

    attestd::PlatformEvidenceBundle bundle;
    std::string detail;
    (void)daemon.answer(challenge, bundle, &detail);

    // The bundle is platform material bound to a digest. Authority is absent by
    // construction: there is no field for either.
    EXPECT_EQ(bundle.challenge_digest, challenge_digest(challenge));
    const std::string wire = attestd::encode_bundle(bundle);
    EXPECT_EQ(wire.find("identity_signature"), std::string::npos);
    EXPECT_EQ(wire.find("epoch_vote_key"), std::string::npos);
}

// --- Eligibility -----------------------------------------------------------

TEST_F(AttestdIntegration, EligibilityEvidenceIsAssembledAndSignedByNexus) {
    const auto challenge = challenge_for(AttestationPurpose::Eligibility);
    const auto evidence = run(challenge);
    ASSERT_TRUE(evidence.has_value());

    EXPECT_EQ(evidence->purpose, AttestationPurpose::Eligibility);
    EXPECT_EQ(evidence->challenge_digest, challenge_digest(challenge));
    EXPECT_EQ(evidence->node_id.bytes, identity_.public_key);

    // Signed by the identity Nexus holds — the daemon never had it.
    const Digest signing = evidence_signing_digest(*evidence);
    EXPECT_EQ(crypto_sign_verify_detached(evidence->identity_signature.data(), signing.data(),
                                          signing.size(), identity_.public_key.data()),
              0);
}

// --- FinalEpochReadiness: the vote key must survive the whole path ----------

TEST_F(AttestdIntegration, FinalReadinessCarriesTheFutureVoteKeyThroughToTheSignature) {
    const auto challenge = challenge_for(AttestationPurpose::FinalEpochReadiness);
    const auto evidence = run(challenge);
    ASSERT_TRUE(evidence.has_value());

    // The regression this exists for: the vote key must not arrive as zero.
    EXPECT_EQ(evidence->epoch_vote_key, vote_key_);
    EXPECT_NE(evidence->epoch_vote_key, crypto::Ed25519PublicKey{});
    EXPECT_EQ(evidence->purpose, AttestationPurpose::FinalEpochReadiness);
    EXPECT_NE(evidence->context_digest, Digest{});

    const Digest signing = evidence_signing_digest(*evidence);
    EXPECT_EQ(crypto_sign_verify_detached(evidence->identity_signature.data(), signing.data(),
                                          signing.size(), identity_.public_key.data()),
              0);
}

TEST_F(AttestdIntegration, MutatingTheVoteKeyBreaksTheIdentitySignature) {
    const auto challenge = challenge_for(AttestationPurpose::FinalEpochReadiness);
    auto evidence = run(challenge);
    ASSERT_TRUE(evidence.has_value());

    const Digest before = evidence_signing_digest(*evidence);
    evidence->epoch_vote_key[0] ^= 0xFF;
    const Digest after = evidence_signing_digest(*evidence);

    // The vote key is inside the signed preimage, so substituting it is not a
    // silent swap: it invalidates the signature the verifier checks.
    EXPECT_NE(before, after);
    EXPECT_NE(crypto_sign_verify_detached(evidence->identity_signature.data(), after.data(),
                                          after.size(), identity_.public_key.data()),
              0);
}

TEST_F(AttestdIntegration, NoVoteKeyMeansNoEvidence) {
    // Nothing is fabricated: an epoch with no vote key yields no bundle at all,
    // rather than one carrying a zero key.
    const auto challenge = challenge_for(AttestationPurpose::FinalEpochReadiness);
    attestd::AttestdConfig cfg;
    attestd::AttestdService daemon{cfg};

    EvidenceProducerSources sources;
    sources.identity = identity_;
    sources.vote_key_for_epoch = [](EpochId) { return std::nullopt; };
    sources.platform_source = attestd_source(daemon, challenge, nullptr);
    EXPECT_FALSE(PlatformEvidenceProducer(std::move(sources)).produce(challenge).has_value());
}

// --- the verifier still decides -------------------------------------------

TEST_F(AttestdIntegration, TheVerifierIsReachedAndStillRefusesAnUnprovenPlatform) {
    const auto challenge = challenge_for(AttestationPurpose::Eligibility);
    const auto evidence = run(challenge);
    ASSERT_TRUE(evidence.has_value());

    // Off a TPM host the platform bundle is empty. The point is that the path
    // reaches the verifier with a well-formed, correctly signed envelope and is
    // refused on the PLATFORM, not on shape — and never accepted.
    const auto verdict = AttestationVerifier(profile()).examine(challenge, *evidence);
    EXPECT_FALSE(verdict.passed);
    EXPECT_NE(verdict.failure, AttestationFailure::IdentitySignatureInvalid);
    EXPECT_NE(verdict.failure, AttestationFailure::ChallengeMismatch);
}
