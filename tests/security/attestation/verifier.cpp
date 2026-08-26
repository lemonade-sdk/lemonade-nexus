#include <LemonadeNexus/Security/Attestation/AttestationVerifier.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <array>
#include <cstdint>
#include <string>

namespace constants = nexus::security::constants;

using nexus::security::AttestationChallenge;
using nexus::security::AttestationEvidence;
using nexus::security::AttestationFailure;
using nexus::security::AttestationVerdict;
using nexus::security::AttestationVerifier;
using nexus::security::Digest;
using nexus::security::EvidenceVerdict;
using nexus::security::LinuxAttestationProfile;
using nexus::security::binary_approved;
using nexus::security::challenge_digest;
using nexus::security::evidence_signing_digest;
using nexus::security::kMaxPlatformEvidenceBytes;
using nexus::security::map_platform_failure;
using nexus::security::platform_evidence_size;
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

class AttestationVerifierTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        ASSERT_EQ(crypto_sign_keypair(node_pk_.data(), node_sk_.data()), 0);

        // A COMPLETE profile: examine() refuses everything under an incomplete
        // one, so every check below would otherwise be unreachable.
        profile_ = nexus::security::linux_attestation_profile_v1();
        profile_.snp.min_tcb = {2, 0, 6, 55};
        profile_.snp.expected_measurement_hex = std::string(96, 'a');
        profile_.ima_policy_digest.fill(0x60);
        profile_.approved_binary_sha256 = {kApprovedBinary};
        ASSERT_TRUE(nexus::security::profile_is_complete(profile_));

        challenge_.nonce = patterned<32>(0x01);
        challenge_.node_id.bytes = patterned<32>(0x02);
        challenge_.node_key = node_pk_;
        challenge_.incarnation = 3;
        challenge_.epoch = 9;
        challenge_.security_ruleset = constants::kSecurityRulesetVersion;
        challenge_.policy_digest = profile_digest(profile_);

        evidence_.challenge_digest = challenge_digest(challenge_);
        evidence_.node_id = challenge_.node_id;
        evidence_.incarnation = challenge_.incarnation;
        evidence_.security_ruleset = constants::kSecurityRulesetVersion;
        evidence_.consensus_ruleset = constants::kConsensusRulesetVersion;
        evidence_.epoch_vote_key = patterned<32>(0x07);
        // The platform bundle stays empty: garbage the platform chain rejects.
        sign_evidence();
    }

    void sign_evidence() {
        const Digest digest = evidence_signing_digest(evidence_);
        ASSERT_EQ(crypto_sign_detached(evidence_.identity_signature.data(), nullptr,
                                       digest.data(), digest.size(), node_sk_.data()),
                  0);
    }

    [[nodiscard]] AttestationVerdict examine() const {
        return verifier_.examine(challenge_, evidence_, profile_);
    }

    nexus::crypto::Ed25519PublicKey node_pk_{};
    nexus::crypto::Ed25519PrivateKey node_sk_{};
    LinuxAttestationProfile profile_;
    AttestationChallenge challenge_;
    AttestationEvidence evidence_;
    AttestationVerifier verifier_;
};

// --- Rejection order: break one link at a time -------------------------------

TEST_F(AttestationVerifierTest, RejectsChallengeForAnotherPolicy) {
    challenge_.policy_digest[0] ^= 1;
    const auto verdict = examine();
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::RulesetMismatch);
}

TEST_F(AttestationVerifierTest, RejectsStaleChallengeRuleset) {
    challenge_.security_ruleset = constants::kSecurityRulesetVersion + 1;
    const auto verdict = examine();
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::RulesetMismatch);
}

TEST_F(AttestationVerifierTest, RejectsStaleEvidenceSecurityRuleset) {
    evidence_.security_ruleset = constants::kSecurityRulesetVersion + 1;
    EXPECT_EQ(examine().failure, AttestationFailure::RulesetMismatch);
}

TEST_F(AttestationVerifierTest, RejectsStaleEvidenceConsensusRuleset) {
    evidence_.consensus_ruleset = constants::kConsensusRulesetVersion + 1;
    EXPECT_EQ(examine().failure, AttestationFailure::RulesetMismatch);
}

TEST_F(AttestationVerifierTest, RejectsMismatchedChallengeDigest) {
    evidence_.challenge_digest[0] ^= 1;
    EXPECT_EQ(examine().failure, AttestationFailure::ChallengeMismatch);
}

TEST_F(AttestationVerifierTest, RejectsEvidenceForAnotherNode) {
    evidence_.node_id.bytes[0] ^= 1;
    EXPECT_EQ(examine().failure, AttestationFailure::IdentityMismatch);
}

TEST_F(AttestationVerifierTest, RejectsStaleIncarnation) {
    evidence_.incarnation += 1;
    EXPECT_EQ(examine().failure, AttestationFailure::IncarnationStale);
}

TEST_F(AttestationVerifierTest, RejectsSignatureFromAnotherKey) {
    nexus::crypto::Ed25519PublicKey other_pk{};
    nexus::crypto::Ed25519PrivateKey other_sk{};
    ASSERT_EQ(crypto_sign_keypair(other_pk.data(), other_sk.data()), 0);

    const Digest digest = evidence_signing_digest(evidence_);
    ASSERT_EQ(crypto_sign_detached(evidence_.identity_signature.data(), nullptr,
                                   digest.data(), digest.size(), other_sk.data()),
              0);
    EXPECT_EQ(examine().failure, AttestationFailure::IdentitySignatureInvalid);
}

TEST_F(AttestationVerifierTest, RejectsUnsignedEvidence) {
    evidence_.identity_signature.fill(0);
    EXPECT_EQ(examine().failure, AttestationFailure::IdentitySignatureInvalid);
}

TEST_F(AttestationVerifierTest, RejectsGarbagePlatformBundle) {
    // Every protocol link holds; the empty platform bundle must fail closed
    // through the mapped platform failure.
    const auto verdict = examine();
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::SnpInvalid);
    EXPECT_EQ(verdict.node_id, challenge_.node_id);
    EXPECT_EQ(verdict.epoch, challenge_.epoch);
    EXPECT_EQ(verdict.incarnation, challenge_.incarnation);
    EXPECT_EQ(verdict.policy_digest, profile_digest(profile_));
    EXPECT_EQ(verdict.evidence_digest, evidence_signing_digest(evidence_));
}

TEST_F(AttestationVerifierTest, PolicyCheckWinsWhenEveryLinkIsBroken) {
    challenge_.policy_digest[0] ^= 1;
    evidence_.challenge_digest[0] ^= 1;
    evidence_.node_id.bytes[0] ^= 1;
    evidence_.incarnation += 1;
    evidence_.identity_signature.fill(0);
    EXPECT_EQ(examine().failure, AttestationFailure::RulesetMismatch);
}

// --- Evidence size bound ------------------------------------------------------

TEST_F(AttestationVerifierTest, RejectsOversizedPlatformBundle) {
    evidence_.platform.ima_log.assign(kMaxPlatformEvidenceBytes + 1, 'a');
    const auto verdict = examine();
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::EvidenceOversized);
    // An oversized bundle is never hashed, so the verdict carries no
    // evidence digest.
    EXPECT_EQ(verdict.evidence_digest, Digest{});
}

TEST_F(AttestationVerifierTest, ExactSizeLimitPassesTheGate) {
    const std::size_t current = platform_evidence_size(evidence_.platform);
    ASSERT_LT(current, kMaxPlatformEvidenceBytes);
    evidence_.platform.ima_log.assign(kMaxPlatformEvidenceBytes - current, 'a');
    ASSERT_EQ(platform_evidence_size(evidence_.platform), kMaxPlatformEvidenceBytes);
    sign_evidence();

    const auto verdict = examine();
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::SnpInvalid);
}

// --- Determinism --------------------------------------------------------------

TEST_F(AttestationVerifierTest, VerdictIsDeterministic) {
    const auto first = examine();
    const auto second = examine();
    EXPECT_EQ(first.node_id, second.node_id);
    EXPECT_EQ(first.epoch, second.epoch);
    EXPECT_EQ(first.incarnation, second.incarnation);
    EXPECT_EQ(first.policy_digest, second.policy_digest);
    EXPECT_EQ(first.evidence_digest, second.evidence_digest);
    EXPECT_EQ(first.passed, second.passed);
    EXPECT_EQ(first.failure, second.failure);
}

// --- Approved binary list -----------------------------------------------------

TEST(BinaryApproved, ListedMeasurementIsApproved) {
    LinuxAttestationProfile profile;
    profile.approved_binary_sha256 = {"aa", "bb"};
    EXPECT_TRUE(binary_approved(profile, "aa"));
    EXPECT_TRUE(binary_approved(profile, "bb"));
}

TEST(BinaryApproved, UnlistedMeasurementIsRejected) {
    LinuxAttestationProfile profile;
    profile.approved_binary_sha256 = {"aa"};
    EXPECT_FALSE(binary_approved(profile, "cc"));
}

TEST(BinaryApproved, EmptyListApprovesNothing) {
    EXPECT_FALSE(binary_approved(LinuxAttestationProfile{}, "aa"));
}

TEST(BinaryApproved, EmptyMeasurementFailsClosedEvenWhenListed) {
    LinuxAttestationProfile profile;
    profile.approved_binary_sha256 = {""};
    EXPECT_FALSE(binary_approved(profile, ""));
}

// --- Platform failure mapping -------------------------------------------------

EvidenceVerdict platform_failure(std::string why, bool quote_verified) {
    EvidenceVerdict verdict;
    verdict.ok = false;
    verdict.quote_verified = quote_verified;
    verdict.failure = std::move(why);
    return verdict;
}

struct MappingCase {
    const char* why;
    bool quote_verified;
    AttestationFailure expected;
};

// Every failure string verify_snp_vtpm_evidence can produce, with the half of
// the chain it belongs to.
const MappingCase kMappingCases[] = {
    // Before the quote held: SNP parse, AMD chain, guest policy.
    {"the attestation blob is malformed or inconsistent", false,
     AttestationFailure::SnpInvalid},
    {"AMD signature check failed: attestation report signature is not valid under the VCEK",
     false, AttestationFailure::SnpInvalid},
    {"platform policy check failed: guest policy allows DEBUG — the hypervisor can read "
     "guest memory",
     false, AttestationFailure::SnpInvalid},
    {"platform policy check failed: guest policy allows a migration agent — the guest can "
     "be moved out of its encryption boundary",
     false, AttestationFailure::SnpInvalid},
    {"platform policy check failed: report was requested at VMPL 2, expected VMPL 0", false,
     AttestationFailure::SnpInvalid},
    {"platform policy check failed: platform TCB [2.0.6.55] is below the required floor "
     "[3.0.8.100]",
     false, AttestationFailure::TcbTooOld},
    {"platform policy check failed: launch measurement 0011223344556677... does not match "
     "the pinned value",
     false, AttestationFailure::SnpInvalid},
    // The enrolled vTPM pin.
    {"the platform binding key does not match the one pinned at enrollment (different "
     "vTPM, or the AK was rotated)",
     false, AttestationFailure::VtpmBindingInvalid},
    // The quote itself.
    {"the quote is not a well-formed TPM2 attestation", false,
     AttestationFailure::TpmQuoteInvalid},
    {"the quote is not signed by HCLAkPub: bad signature", false,
     AttestationFailure::TpmQuoteInvalid},
    {"the quote signature has no readable hash algorithm", false,
     AttestationFailure::TpmQuoteInvalid},
    {"the supplied PCR values are not the ones the quote signed", false,
     AttestationFailure::TpmQuoteInvalid},
    // The quote does not answer the current challenge.
    {"the quote is not bound to this challenge, identity and binary measurement", false,
     AttestationFailure::ChallengeMismatch},
    // A malformed self-claimed measurement, rejected before the quote check.
    {"the claimed binary measurement is not hex", false,
     AttestationFailure::BinaryMeasurementInvalid},
    // After the quote held: IMA replay and the binary measurement.
    {"the platform is verified but its binary is not measured: IMA is not enabled", true,
     AttestationFailure::BinaryMeasurementInvalid},
    {"the IMA measurement log did not parse", true, AttestationFailure::ImaMeasurementInvalid},
    {"the IMA measurement log is empty", true, AttestationFailure::ImaMeasurementInvalid},
    {"the IMA log's template digest width matches no PCR bank", true,
     AttestationFailure::ImaMeasurementInvalid},
    {"the quote does not cover PCR 10 in the bank this IMA log replays into, so the log "
     "is unanchored",
     true, AttestationFailure::ImaMeasurementInvalid},
    {"the IMA log does not replay to the quoted PCR 10 — the log has been edited or "
     "truncated",
     true, AttestationFailure::ImaMeasurementInvalid},
    {"the IMA log carries no measurement of '/opt/nexus'", true,
     AttestationFailure::BinaryMeasurementInvalid},
    {"the claimed binary measurement is not what the kernel recorded for that path", true,
     AttestationFailure::BinaryMeasurementInvalid},
};

TEST(MapPlatformFailure, CoversEveryFailureClassTheChainProduces) {
    for (const auto& mapping_case : kMappingCases) {
        const auto verdict = platform_failure(mapping_case.why, mapping_case.quote_verified);
        EXPECT_EQ(map_platform_failure(verdict), mapping_case.expected) << mapping_case.why;
    }
}

TEST(MapPlatformFailure, PassingVerdictMapsToNone) {
    EvidenceVerdict verdict;
    verdict.ok = true;
    verdict.quote_verified = true;
    EXPECT_EQ(map_platform_failure(verdict), AttestationFailure::None);
}

TEST(MapPlatformFailure, UnknownStringsMapToTheMostSevereOfTheirHalf) {
    EXPECT_EQ(map_platform_failure(platform_failure("some future failure", false)),
              AttestationFailure::SnpInvalid);
    EXPECT_EQ(map_platform_failure(platform_failure("some future failure", true)),
              AttestationFailure::ImaMeasurementInvalid);
}

TEST(MapPlatformFailure, MappingIsDeterministic) {
    const auto verdict = platform_failure(kMappingCases[0].why, kMappingCases[0].quote_verified);
    for (int i = 0; i < 10; ++i) {
        EXPECT_EQ(map_platform_failure(verdict), kMappingCases[0].expected);
    }
}

}  // namespace
