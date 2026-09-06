// The production chain against real hardware, when there is real hardware.
//
//   challenge -> PlatformEvidenceProducer -> attestd_platform_source
//             -> nexus-attestd -> SNP/vTPM/IMA -> producer signs -> verifier
//
// This is the composition main.cpp assembles, not the daemon's test client:
// nothing here speaks the socket protocol directly. It skips wherever the
// socket is absent, which is every machine except a deployed node — so the
// suite stays hermetic and the deployed node stays checkable.

#include <LemonadeNexus/Security/Attestation/AttestationService.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationVerifier.hpp>
#include <LemonadeNexus/Security/Attestation/LinuxAttestationProfile.hpp>
#include <LemonadeNexus/Security/Attestation/PlatformEvidenceProducer.hpp>
#include <LemonadeNexusAttestd/AttestdClient.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <array>
#include <filesystem>
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

struct AttestdLive : ::testing::Test {
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        std::error_code ec;
        if (!std::filesystem::exists(config_.path, ec)) {
            GTEST_SKIP() << "no nexus-attestd socket at " << config_.path.string();
        }
    }

    attestd::AttestdClientConfig config_;
    crypto::Ed25519Keypair identity_ = seeded(0x51);
    crypto::Ed25519PublicKey vote_key_ = seeded(0x52).public_key;
    NetworkId network_ = [] { NetworkId n{}; n.fill(0x5A); return n; }();

    /// Exactly what main.cpp installs.
    EvidenceProducerSources production_sources() {
        EvidenceProducerSources sources;
        sources.identity = identity_;
        sources.vote_key_for_epoch = [this](EpochId) { return vote_key_; };
        sources.cache_directory = ::testing::TempDir();
        sources.platform_source = attestd::attestd_platform_source(config_);
        return sources;
    }

    AttestationChallenge challenge_for(AttestationPurpose purpose) {
        AttestationService service(network_, linux_attestation_profile_v1());
        NodeId node{};
        node.bytes = identity_.public_key;
        Digest context{};
        if (purpose == AttestationPurpose::FinalEpochReadiness) context.fill(0x44);
        auto c = service.create_challenge(node, identity_.public_key, /*incarnation*/ 11,
                                          /*epoch*/ 4, purpose, context);
        EXPECT_TRUE(c.has_value());
        return c.value_or(AttestationChallenge{});
    }
};

}  // namespace

TEST_F(AttestdLive, TheApplicationPathProducesSignedHardwareBackedEvidence) {
    const auto challenge = challenge_for(AttestationPurpose::Eligibility);
    const auto evidence = PlatformEvidenceProducer(production_sources()).produce(challenge);
    ASSERT_TRUE(evidence.has_value());

    // The daemon answered, over the socket, with real platform material.
    EXPECT_FALSE(evidence->platform.empty()) << "nexus-attestd returned no platform evidence";
    EXPECT_FALSE(evidence->platform.hcl_blob.empty());
    EXPECT_FALSE(evidence->platform.tpms_attest.empty());
    EXPECT_FALSE(evidence->platform.vcek_der.empty());

    // The log it returned is the one the quote covers.
    EXPECT_FALSE(evidence->platform.ima_log.empty());
    EXPECT_FALSE(evidence->platform.binary_sha256.empty())
        << "no IMA measurement: " << evidence->platform.ima_unavailable;

    // Identity and vote key are bound HERE, outside the daemon.
    EXPECT_EQ(evidence->node_id.bytes, identity_.public_key);
    EXPECT_EQ(evidence->epoch_vote_key, vote_key_);
    const Digest signing = evidence_signing_digest(*evidence);
    EXPECT_EQ(crypto_sign_verify_detached(evidence->identity_signature.data(), signing.data(),
                                          signing.size(), identity_.public_key.data()),
              0);
}

TEST_F(AttestdLive, TheEvidenceSizeRefusalDoesNotReturn) {
    // The regression: the daemon used to apply the 56 KiB mesh bound to a local
    // operation and refuse a host whose IMA log had simply grown.
    const auto challenge = challenge_for(AttestationPurpose::Eligibility);
    const auto evidence = PlatformEvidenceProducer(production_sources()).produce(challenge);
    ASSERT_TRUE(evidence.has_value());
    ASSERT_FALSE(evidence->platform.empty()) << "the daemon refused; check its log for the reason";

    const auto encoded = encode_snp_vtpm_evidence(evidence->platform);
    RecordProperty("local_evidence_bytes", static_cast<int>(encoded.size()));
    RecordProperty("ima_log_bytes", static_cast<int>(evidence->platform.ima_log.size()));
    // Whether it fits the mesh is a separate question, decided elsewhere. What
    // matters here is that the LOCAL path delivered it either way.
    EXPECT_LE(encoded.size(), attestd::kMaxLocalFrameBytes * attestd::kMaxLocalChunks);
}

TEST_F(AttestdLive, FinalReadinessCarriesTheVoteKeyThroughRealHardware) {
    const auto challenge = challenge_for(AttestationPurpose::FinalEpochReadiness);
    const auto evidence = PlatformEvidenceProducer(production_sources()).produce(challenge);
    ASSERT_TRUE(evidence.has_value());

    EXPECT_EQ(evidence->purpose, AttestationPurpose::FinalEpochReadiness);
    EXPECT_EQ(evidence->epoch_vote_key, vote_key_);
    EXPECT_NE(evidence->epoch_vote_key, crypto::Ed25519PublicKey{});
    EXPECT_NE(evidence->context_digest, Digest{});
    EXPECT_FALSE(evidence->platform.empty());
}

TEST_F(AttestdLive, TheVerifierReachesTheImaPolicyAndRefusesThere) {
    // A profile pinned FROM this host's own evidence. That is circular as a
    // security argument and is not one: the pins exist so the chain runs past
    // every earlier link and the LAST refusal is the informative one.
    const auto challenge = challenge_for(AttestationPurpose::Eligibility);
    const auto evidence = PlatformEvidenceProducer(production_sources()).produce(challenge);
    ASSERT_TRUE(evidence.has_value());
    ASSERT_FALSE(evidence->platform.empty());

    EvidenceRequirements probe;
    probe.require_ima = false;
    probe.require_revocation_check = false;
    const auto seen = verify_snp_vtpm_evidence(evidence->platform, evidence->challenge_digest,
                                               identity_.public_key, probe);
    RecordProperty("platform_failure", seen.failure);
    ASSERT_TRUE(seen.quote_verified) << "the platform chain failed before the quote: "
                                     << seen.failure;

    auto profile = linux_attestation_profile_v1();
    profile.snp.min_tcb = {1, 0, 1, 1};
    profile.snp.expected_measurement_hex = seen.measurement_hex;
    profile.required_ak_spki_b64 = seen.ak_spki_b64;
    profile.require_endorsement_revocation = false;
    profile.require_no_new_privs = false;
    profile.require_seccomp = false;
    profile.approved_paths = {{evidence->platform.binary_path,
                               {evidence->platform.binary_sha256}}};
    // The one pin the host cannot satisfy: KernelReadback needs
    // CONFIG_IMA_READ_POLICY, and a stock kernel does not publish its policy.
    profile.ima_policy_digest.fill(0x60);
    ASSERT_TRUE(profile_is_complete(profile)) << "the pinned profile is still incomplete";

    auto pinned = challenge;
    pinned.policy_digest = profile_digest(profile);
    const auto refreshed =
        PlatformEvidenceProducer(production_sources()).produce(pinned);
    ASSERT_TRUE(refreshed.has_value());

    const auto verdict = AttestationVerifier(profile).examine(pinned, *refreshed);
    RecordProperty("verdict_failure", static_cast<int>(verdict.failure));
    EXPECT_FALSE(verdict.passed);

    // Everything the host CAN prove must have been proved. These are the
    // failures that must not come back.
    EXPECT_NE(verdict.failure, AttestationFailure::EvidenceOversized);
    EXPECT_NE(verdict.failure, AttestationFailure::TpmQuoteInvalid);
    EXPECT_NE(verdict.failure, AttestationFailure::VtpmBindingInvalid);
    EXPECT_NE(verdict.failure, AttestationFailure::SnpInvalid);
    EXPECT_NE(verdict.failure, AttestationFailure::IdentitySignatureInvalid);
    EXPECT_NE(verdict.failure, AttestationFailure::ChallengeMismatch);
    EXPECT_NE(verdict.failure, AttestationFailure::BinaryMeasurementInvalid);
    EXPECT_NE(verdict.failure, AttestationFailure::ProfileIncomplete);

    // What is left is the IMA policy the kernel will not publish.
    EXPECT_EQ(verdict.failure, AttestationFailure::ImaMeasurementInvalid);
    EXPECT_TRUE(refreshed->platform.ima_policy_sha256.empty())
        << "the kernel published a policy digest; KernelReadback may now be satisfiable";
}
