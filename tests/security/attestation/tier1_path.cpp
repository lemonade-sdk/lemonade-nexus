// Rejection paths of AttestationVerifier::examine, end to end.
//
// verifier.cpp mutates single fields of one bundle. This file works with whole
// objects instead: a second challenge, a second identity key, a second profile.
// Each negative case presents evidence that is well formed and correctly signed
// for the object it was built for, so the check under test is the only barrier
// left standing. The final test proves the barrier is real by clearing checks 0
// to 7 and stopping at the platform chain.

#include <LemonadeNexus/Security/Attestation/AttestationVerifier.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

namespace constants = nexus::security::constants;

using nexus::security::AttestationChallenge;
using nexus::security::AttestationEvidence;
using nexus::security::AttestationFailure;
using nexus::security::AttestationVerdict;
using nexus::security::AttestationVerifier;
using nexus::security::Digest;
using nexus::security::LinuxAttestationProfile;
using nexus::security::SecurityRulesetVersion;
using nexus::security::challenge_digest;
using nexus::security::evidence_signing_digest;
using nexus::security::kMaxPlatformEvidenceBytes;
using nexus::security::linux_attestation_profile_v1;
using nexus::security::platform_evidence_size;
using nexus::security::profile_digest;
using nexus::security::profile_is_complete;

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
constexpr const char* kOtherBinary =
    "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100";

constexpr SecurityRulesetVersion kOlderSecurityRuleset =
    static_cast<SecurityRulesetVersion>(constants::kSecurityRulesetVersion - 1);
constexpr nexus::security::ConsensusRulesetVersion kOlderConsensusRuleset =
    static_cast<nexus::security::ConsensusRulesetVersion>(constants::kConsensusRulesetVersion - 1);

/// Every failure map_platform_failure can produce. ChallengeMismatch appears
/// here as well as at step 3: the quote carries the challenge digest as its
/// nonce, so the platform chain rejects a quote bound to another challenge.
bool platform_stage_failure(AttestationFailure failure) {
    switch (failure) {
        case AttestationFailure::ChallengeMismatch:
        case AttestationFailure::SnpInvalid:
        case AttestationFailure::TcbTooOld:
        case AttestationFailure::VtpmBindingInvalid:
        case AttestationFailure::TpmQuoteInvalid:
        case AttestationFailure::ImaMeasurementInvalid:
        case AttestationFailure::BinaryMeasurementInvalid:
            return true;
        default:
            return false;
    }
}

void expect_identical(const AttestationVerdict& first, const AttestationVerdict& second,
                      const char* label) {
    EXPECT_EQ(first.passed, second.passed) << label;
    EXPECT_EQ(first.failure, second.failure) << label;
    EXPECT_EQ(first.node_id, second.node_id) << label;
    EXPECT_EQ(first.epoch, second.epoch) << label;
    EXPECT_EQ(first.incarnation, second.incarnation) << label;
    EXPECT_EQ(first.policy_digest, second.policy_digest) << label;
    EXPECT_EQ(first.evidence_digest, second.evidence_digest) << label;
}

class Tier1PathTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        ASSERT_EQ(crypto_sign_keypair(node_pk_.data(), node_sk_.data()), 0);
        ASSERT_EQ(crypto_sign_keypair(rogue_pk_.data(), rogue_sk_.data()), 0);

        // Step 0 refuses every candidate under an incomplete profile, so the
        // profile must pin everything before any later check is reachable.
        profile_ = linux_attestation_profile_v1();
        profile_.snp.min_tcb = {2, 0, 6, 55};
        profile_.snp.expected_measurement_hex = std::string(96, 'a');
        profile_.ima_policy_digest = patterned<32>(0x60);
        profile_.approved_binary_sha256 = {kApprovedBinary};
        ASSERT_TRUE(profile_is_complete(profile_));

        challenge_ = issue(profile_);
        evidence_ = answer(challenge_);
        sign_with(evidence_, node_sk_);
    }

    /// A challenge the current Tier 1 set would issue for this node under
    /// `profile`.
    [[nodiscard]] AttestationChallenge issue(const LinuxAttestationProfile& profile) const {
        AttestationChallenge challenge;
        challenge.nonce = patterned<32>(0x11);
        challenge.node_id.bytes = patterned<32>(0x22);
        challenge.node_key = node_pk_;
        challenge.incarnation = 4;
        challenge.epoch = 12;
        challenge.security_ruleset = constants::kSecurityRulesetVersion;
        challenge.consensus_ruleset = constants::kConsensusRulesetVersion;
        challenge.profile_id = nexus::security::kTier1AttestationProfileId;
        challenge.profile_ruleset = nexus::security::kAttestationProfileRulesetVersion;
        challenge.policy_digest = profile_digest(profile);
        return challenge;
    }

    /// A bundle that answers `challenge` correctly at every protocol field. The
    /// platform bytes are placeholders: the platform chain rejects them, which
    /// is what makes step 8 the last barrier in the passing-path test.
    [[nodiscard]] static AttestationEvidence answer(const AttestationChallenge& challenge) {
        AttestationEvidence evidence;
        evidence.challenge_digest = challenge_digest(challenge);
        evidence.node_id = challenge.node_id;
        evidence.incarnation = challenge.incarnation;
        evidence.epoch = challenge.epoch;
        evidence.security_ruleset = constants::kSecurityRulesetVersion;
        evidence.consensus_ruleset = constants::kConsensusRulesetVersion;
        evidence.profile_id = challenge.profile_id;
        evidence.profile_ruleset = challenge.profile_ruleset;
        evidence.epoch_vote_key = patterned<32>(0x33);
        evidence.platform.hcl_blob.assign(64, 0xA5);
        evidence.platform.tpms_attest.assign(48, 0x5A);
        evidence.platform.tpm_signature.assign(32, 0x3C);
        evidence.platform.pcr_values.assign(32, 0xC3);
        evidence.platform.ima_log = "10 aa ima-ng sha256:bb /opt/nexus\n";
        evidence.platform.binary_path = "/opt/nexus";
        evidence.platform.binary_sha256 = kApprovedBinary;
        return evidence;
    }

    static void sign_with(AttestationEvidence& evidence,
                          const nexus::crypto::Ed25519PrivateKey& secret_key) {
        const Digest digest = evidence_signing_digest(evidence);
        ASSERT_EQ(crypto_sign_detached(evidence.identity_signature.data(), nullptr, digest.data(),
                                       digest.size(), secret_key.data()),
                  0);
    }

    void sign_evidence() { sign_with(evidence_, node_sk_); }

    [[nodiscard]] AttestationVerdict examine() const {
        return AttestationVerifier(profile_).examine(challenge_, evidence_);
    }

    nexus::crypto::Ed25519PublicKey node_pk_{};
    nexus::crypto::Ed25519PrivateKey node_sk_{};
    nexus::crypto::Ed25519PublicKey rogue_pk_{};
    nexus::crypto::Ed25519PrivateKey rogue_sk_{};
    LinuxAttestationProfile profile_;
    AttestationChallenge challenge_;
    AttestationEvidence evidence_;
};

// --- 0. The profile must be able to decide -------------------------------------

TEST_F(Tier1PathTest, IncompleteProfileRejectsAnOtherwiseFlawlessCandidate) {
    // A profile that pins no launch measurement would accept a guest image it
    // never examined, so it must accept nobody instead. The challenge is
    // re-issued under the gapped profile, so step 1 agrees and step 0 is the
    // only possible cause.
    profile_.snp.expected_measurement_hex.clear();
    ASSERT_FALSE(profile_is_complete(profile_));
    challenge_ = issue(profile_);
    evidence_ = answer(challenge_);
    sign_evidence();

    const auto verdict = examine();
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::ProfileIncomplete);
    EXPECT_NE(verdict.failure, AttestationFailure::RulesetMismatch);
    EXPECT_EQ(verdict.evidence_digest, Digest{});
}

TEST_F(Tier1PathTest, ProfileCompletenessWinsOverEveryOtherFault) {
    profile_.approved_binary_sha256.clear();
    ASSERT_FALSE(profile_is_complete(profile_));

    challenge_.policy_digest = patterned<32>(0x66);
    evidence_.challenge_digest = patterned<32>(0x77);
    evidence_.node_id.bytes = patterned<32>(0x55);
    evidence_.incarnation = challenge_.incarnation - 1;
    evidence_.platform.ima_log.assign(kMaxPlatformEvidenceBytes + 1, 'i');
    evidence_.identity_signature.fill(0);

    EXPECT_EQ(examine().failure, AttestationFailure::ProfileIncomplete);
}

// --- 1. The evidence must answer THIS challenge -------------------------------

TEST_F(Tier1PathTest, EvidenceAnsweringAnEarlierChallengeIsRejected) {
    // A re-issue for the same node in the same epoch. Only the nonce differs,
    // so this is the replay case: an earlier answer must not satisfy a later
    // challenge.
    AttestationChallenge reissued = challenge_;
    reissued.nonce = patterned<32>(0x44);
    ASSERT_NE(challenge_digest(reissued), challenge_digest(challenge_));

    const auto verdict = AttestationVerifier(profile_).examine(reissued, evidence_);
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::ChallengeMismatch);
    // Step 3 returns before step 6 assigns the digest, so the bundle is never
    // hashed.
    EXPECT_EQ(verdict.evidence_digest, Digest{});
}

// --- 2. The identity signature must be under the challenged key ---------------

TEST_F(Tier1PathTest, EvidenceSignedByAnotherKeyIsRejected) {
    ASSERT_NE(rogue_pk_, node_pk_);

    // The bundle is correct in every other respect; only the signer is wrong.
    sign_with(evidence_, rogue_sk_);

    const auto verdict = examine();
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::IdentitySignatureInvalid);
    // The bundle was hashed, so the rejection comes from step 7 and not from an
    // earlier check.
    EXPECT_EQ(verdict.evidence_digest, evidence_signing_digest(evidence_));

    // The same bundle under the challenged key clears step 7.
    sign_evidence();
    EXPECT_TRUE(platform_stage_failure(examine().failure));
}

TEST_F(Tier1PathTest, SubstitutingTheChallengeNodeKeyIsCaughtBeforeTheSignatureCheck) {
    // node_key is bound into challenge_digest. Swapping the key a challenge
    // names therefore invalidates the challenge itself, and a verifier never
    // reaches step 7 with a substituted key.
    challenge_.node_key = rogue_pk_;

    const auto verdict = examine();
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::ChallengeMismatch);
    EXPECT_NE(verdict.failure, AttestationFailure::IdentitySignatureInvalid);
}

// --- 3. An attestation for node A must never authorize node B -----------------

TEST_F(Tier1PathTest, EvidenceCarryingAnotherNodeIdIsRejected) {
    evidence_.node_id.bytes = patterned<32>(0x55);
    ASSERT_NE(evidence_.node_id, challenge_.node_id);
    // The evidence still answers this challenge and is correctly signed, so the
    // identity check is the only barrier.
    sign_evidence();

    const auto verdict = examine();
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::IdentityMismatch);
    // The verdict names the challenged node, never the one the evidence claimed.
    EXPECT_EQ(verdict.node_id, challenge_.node_id);
    EXPECT_EQ(verdict.evidence_digest, Digest{});
}

// --- 4. Only the current incarnation may attest --------------------------------

TEST_F(Tier1PathTest, IncarnationMustMatchExactlyInBothDirections) {
    // The check is equality, not a floor. A restarted node that claims a newer
    // incarnation than the challenge names is rejected exactly like a stale one.
    const uint64_t incarnations[] = {challenge_.incarnation - 1, challenge_.incarnation + 1};
    for (const uint64_t incarnation : incarnations) {
        evidence_ = answer(challenge_);
        evidence_.incarnation = incarnation;
        sign_evidence();

        const auto verdict = examine();
        EXPECT_FALSE(verdict.passed) << incarnation;
        EXPECT_EQ(verdict.failure, AttestationFailure::IncarnationStale) << incarnation;
        EXPECT_EQ(verdict.incarnation, challenge_.incarnation) << incarnation;
        EXPECT_EQ(verdict.evidence_digest, Digest{}) << incarnation;
    }
}

// --- 5. The epoch ---------------------------------------------------------------

TEST_F(Tier1PathTest, EvidenceFromAnotherEpochReportsEpochMismatch) {
    // The evidence names its epoch, and examine() compares it before the
    // challenge digest. A cross-epoch answer is therefore diagnosed as such
    // instead of surfacing as a digest mismatch, which would read as a replay.
    AttestationChallenge next_epoch = challenge_;
    next_epoch.epoch = challenge_.epoch + 1;
    ASSERT_NE(challenge_digest(next_epoch), challenge_digest(challenge_));

    // Evidence for the next epoch, examined against this one.
    AttestationEvidence for_next = answer(next_epoch);
    sign_with(for_next, node_sk_);
    const auto forward = AttestationVerifier(profile_).examine(challenge_, for_next);
    EXPECT_FALSE(forward.passed);
    EXPECT_EQ(forward.failure, AttestationFailure::EpochMismatch);
    // The verdict reports the epoch of the challenge the verifier applied.
    EXPECT_EQ(forward.epoch, challenge_.epoch);

    // The rejection is symmetric: this epoch's answer fails against the next.
    const auto reverse = AttestationVerifier(profile_).examine(next_epoch, evidence_);
    EXPECT_FALSE(reverse.passed);
    EXPECT_EQ(reverse.failure, AttestationFailure::EpochMismatch);
    EXPECT_EQ(reverse.epoch, next_epoch.epoch);
}

// The epoch is inside challenge_digest as well, so an answer that names the
// right epoch but answers a different challenge still fails — one field cannot
// be used to bypass the other.
TEST_F(Tier1PathTest, RightEpochWithTheWrongChallengeStillFails) {
    AttestationChallenge other = challenge_;
    other.nonce[0] ^= 0xFF;
    ASSERT_NE(challenge_digest(other), challenge_digest(challenge_));

    AttestationEvidence for_other = answer(other);
    for_other.epoch = challenge_.epoch;   // correct epoch, wrong challenge
    sign_with(for_other, node_sk_);

    const auto verdict = AttestationVerifier(profile_).examine(challenge_, for_other);
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::ChallengeMismatch);
}

// --- 6. Both sides must run the compiled rulesets --------------------------------

TEST_F(Tier1PathTest, EvidenceOnAnOlderSecurityRulesetIsRejected) {
    evidence_.security_ruleset = kOlderSecurityRuleset;
    // Re-signed, so the rejection is the ruleset check and not a stale
    // signature over the old field value.
    sign_evidence();

    const auto verdict = examine();
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::RulesetMismatch);
    EXPECT_EQ(verdict.evidence_digest, Digest{});
}

TEST_F(Tier1PathTest, EvidenceOnAnOlderConsensusRulesetIsRejected) {
    evidence_.consensus_ruleset = kOlderConsensusRuleset;
    sign_evidence();

    const auto verdict = examine();
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::RulesetMismatch);
    EXPECT_EQ(verdict.evidence_digest, Digest{});
}

TEST_F(Tier1PathTest, ChallengeOnAnOlderSecurityRulesetIsRejected) {
    // The ruleset is bound into challenge_digest as well, so this challenge is
    // also unanswerable. Step 2 runs first, so RulesetMismatch wins.
    challenge_.security_ruleset = kOlderSecurityRuleset;
    evidence_ = answer(challenge_);
    evidence_.security_ruleset = kOlderSecurityRuleset;
    sign_evidence();

    const auto verdict = examine();
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::RulesetMismatch);
}

// --- 7. The challenge must be for THIS compiled policy ---------------------------

TEST_F(Tier1PathTest, ChallengeIssuedUnderAnotherProfileIsRejected) {
    LinuxAttestationProfile other = profile_;
    other.approved_binary_sha256 = {kApprovedBinary, kOtherBinary};
    ASSERT_NE(profile_digest(other), profile_digest(profile_));

    // A complete, correctly signed attempt under the other profile.
    const AttestationChallenge other_challenge = issue(other);
    challenge_ = other_challenge;
    evidence_ = answer(other_challenge);
    sign_evidence();

    const auto verdict = examine();
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::RulesetMismatch);
    // The verdict reports the profile the verifier applied, never the one the
    // challenge claimed.
    EXPECT_EQ(verdict.policy_digest, profile_digest(profile_));
    EXPECT_NE(verdict.policy_digest, challenge_.policy_digest);
}

TEST_F(Tier1PathTest, NoProfileRelaxationSurvivesThePolicyDigestCheck) {
    // A challenge is the only profile input a verifier receives from the
    // network. Every relaxation an attacker might want must therefore die at
    // step 1.
    struct Relaxation {
        const char* name;
        std::function<void(LinuxAttestationProfile&)> apply;
    };
    const Relaxation relaxations[] = {
        {"debug allowed", [](LinuxAttestationProfile& p) { p.snp.require_debug_disabled = false; }},
        {"migration agent allowed",
         [](LinuxAttestationProfile& p) { p.snp.require_no_migration_agent = false; }},
        {"vmpl policy relaxed", [](LinuxAttestationProfile& p) {
             p.snp.vmpl_policy = nexus::security::VmplPolicy::Unconstrained; }},
        {"tcb floor lowered", [](LinuxAttestationProfile& p) { p.snp.min_tcb.microcode -= 1; }},
        {"ima policy not enforced",
         [](LinuxAttestationProfile& p) { p.enforce_ima_policy = false; }},
        {"seccomp not required", [](LinuxAttestationProfile& p) { p.require_seccomp = false; }},
        {"no_new_privs not required",
         [](LinuxAttestationProfile& p) { p.require_no_new_privs = false; }},
        {"extra approved binary",
         [](LinuxAttestationProfile& p) { p.approved_binary_sha256.push_back(kOtherBinary); }},
    };

    for (const auto& relaxation : relaxations) {
        LinuxAttestationProfile relaxed = profile_;
        relaxation.apply(relaxed);
        ASSERT_NE(profile_digest(relaxed), profile_digest(profile_)) << relaxation.name;

        const AttestationChallenge challenge = issue(relaxed);
        AttestationEvidence evidence = answer(challenge);
        sign_with(evidence, node_sk_);

        const auto verdict = AttestationVerifier(profile_).examine(challenge, evidence);
        EXPECT_FALSE(verdict.passed) << relaxation.name;
        EXPECT_EQ(verdict.failure, AttestationFailure::RulesetMismatch) << relaxation.name;
    }
}

// --- 8. The size bound ------------------------------------------------------------

TEST_F(Tier1PathTest, OversizedPlatformEvidenceIsRejectedOnTheSumOfItsFields) {
    // No single field exceeds the cap. The bound covers their total, so a
    // bundle cannot be spread across fields to slip past it.
    evidence_.platform.hcl_blob.assign(2 * 1024 * 1024, 0xAB);
    evidence_.platform.amd_chain_pem.assign(1024 * 1024, 'p');
    evidence_.platform.ima_log.clear();
    const std::size_t without_log = platform_evidence_size(evidence_.platform);
    ASSERT_LT(without_log, kMaxPlatformEvidenceBytes);
    evidence_.platform.ima_log.assign(kMaxPlatformEvidenceBytes - without_log + 1, 'i');
    ASSERT_EQ(platform_evidence_size(evidence_.platform), kMaxPlatformEvidenceBytes + 1);

    const auto verdict = examine();
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::EvidenceOversized);
    // The gate runs before any hash of the bundle, so an oversized bundle costs
    // the verifier nothing.
    EXPECT_EQ(verdict.evidence_digest, Digest{});

    // One byte less and the same bundle reaches the platform stage.
    evidence_.platform.ima_log.pop_back();
    ASSERT_EQ(platform_evidence_size(evidence_.platform), kMaxPlatformEvidenceBytes);
    sign_evidence();
    const auto at_limit = examine();
    EXPECT_FALSE(at_limit.passed);
    EXPECT_TRUE(platform_stage_failure(at_limit.failure))
        << static_cast<int>(at_limit.failure);
}

// --- 9. Rejection ordering ---------------------------------------------------------

TEST_F(Tier1PathTest, RulesetCheckWinsOverChallengeMismatch) {
    ASSERT_NE(patterned<32>(0x66), profile_digest(profile_));
    challenge_.policy_digest = patterned<32>(0x66);
    evidence_.challenge_digest = patterned<32>(0x77);
    EXPECT_EQ(examine().failure, AttestationFailure::RulesetMismatch);
}

TEST_F(Tier1PathTest, ChallengeCheckWinsOverIdentityMismatch) {
    evidence_.challenge_digest = patterned<32>(0x77);
    evidence_.node_id.bytes = patterned<32>(0x55);
    sign_evidence();
    EXPECT_EQ(examine().failure, AttestationFailure::ChallengeMismatch);
}

TEST_F(Tier1PathTest, IdentityCheckWinsOverStaleIncarnation) {
    evidence_.node_id.bytes = patterned<32>(0x55);
    evidence_.incarnation = challenge_.incarnation - 1;
    sign_evidence();
    EXPECT_EQ(examine().failure, AttestationFailure::IdentityMismatch);
}

TEST_F(Tier1PathTest, SizeBoundWinsOverInvalidSignature) {
    // The size gate is what keeps an unauthenticated peer from making the
    // verifier hash megabytes, so it must run before the signature check.
    evidence_.platform.ima_log.assign(kMaxPlatformEvidenceBytes + 1, 'i');
    evidence_.identity_signature.fill(0);
    const auto verdict = examine();
    EXPECT_EQ(verdict.failure, AttestationFailure::EvidenceOversized);
    EXPECT_EQ(verdict.evidence_digest, Digest{});
}

TEST_F(Tier1PathTest, SignatureCheckWinsOverPlatformFailure) {
    sign_with(evidence_, rogue_sk_);
    EXPECT_EQ(examine().failure, AttestationFailure::IdentitySignatureInvalid);
}

TEST_F(Tier1PathTest, RepairingEachLinkExposesExactlyTheNextCheck) {
    // Break every link at once, then repair them one at a time. Each repair
    // must expose the next check and no other, which pins the whole order.
    AttestationChallenge foreign = challenge_;
    foreign.nonce = patterned<32>(0x44);
    ASSERT_NE(patterned<32>(0x66), profile_digest(profile_));

    const LinuxAttestationProfile complete = profile_;
    profile_.snp.expected_measurement_hex.clear();
    challenge_.policy_digest = patterned<32>(0x66);
    evidence_.challenge_digest = challenge_digest(foreign);
    evidence_.node_id.bytes = patterned<32>(0x55);
    evidence_.incarnation = challenge_.incarnation - 1;
    evidence_.platform.ima_log.assign(kMaxPlatformEvidenceBytes + 1, 'i');
    evidence_.identity_signature.fill(0);

    EXPECT_EQ(examine().failure, AttestationFailure::ProfileIncomplete);

    profile_ = complete;
    EXPECT_EQ(examine().failure, AttestationFailure::RulesetMismatch);

    challenge_.policy_digest = profile_digest(profile_);
    EXPECT_EQ(examine().failure, AttestationFailure::ChallengeMismatch);

    evidence_.challenge_digest = challenge_digest(challenge_);
    EXPECT_EQ(examine().failure, AttestationFailure::IdentityMismatch);

    evidence_.node_id = challenge_.node_id;
    EXPECT_EQ(examine().failure, AttestationFailure::IncarnationStale);

    evidence_.incarnation = challenge_.incarnation;
    EXPECT_EQ(examine().failure, AttestationFailure::EvidenceOversized);

    evidence_.platform.ima_log = "10 aa ima-ng sha256:bb /opt/nexus\n";
    EXPECT_EQ(examine().failure, AttestationFailure::IdentitySignatureInvalid);

    sign_evidence();
    const auto verdict = examine();
    EXPECT_FALSE(verdict.passed);
    EXPECT_TRUE(platform_stage_failure(verdict.failure)) << static_cast<int>(verdict.failure);
}

// --- 10. Determinism -----------------------------------------------------------------

TEST_F(Tier1PathTest, EveryRejectionPathIsDeterministic) {
    struct Scenario {
        const char* name;
        AttestationFailure expected;
        std::function<void()> apply;
    };
    const Scenario scenarios[] = {
        {"incomplete profile", AttestationFailure::ProfileIncomplete,
         [this] { profile_.snp.expected_measurement_hex.clear(); }},
        {"challenge for another policy", AttestationFailure::RulesetMismatch,
         [this] { challenge_.policy_digest = patterned<32>(0x66); }},
        {"older evidence security ruleset", AttestationFailure::RulesetMismatch,
         [this] {
             evidence_.security_ruleset = kOlderSecurityRuleset;
             sign_evidence();
         }},
        {"older evidence consensus ruleset", AttestationFailure::RulesetMismatch,
         [this] {
             evidence_.consensus_ruleset = kOlderConsensusRuleset;
             sign_evidence();
         }},
        {"evidence for another challenge", AttestationFailure::ChallengeMismatch,
         [this] {
             AttestationChallenge foreign = challenge_;
             foreign.nonce = patterned<32>(0x44);
             evidence_.challenge_digest = challenge_digest(foreign);
             sign_evidence();
         }},
        {"evidence for another node", AttestationFailure::IdentityMismatch,
         [this] {
             evidence_.node_id.bytes = patterned<32>(0x55);
             sign_evidence();
         }},
        {"stale incarnation", AttestationFailure::IncarnationStale,
         [this] {
             evidence_.incarnation = challenge_.incarnation - 1;
             sign_evidence();
         }},
        {"oversized bundle", AttestationFailure::EvidenceOversized,
         [this] { evidence_.platform.ima_log.assign(kMaxPlatformEvidenceBytes + 1, 'i'); }},
        {"signature from another key", AttestationFailure::IdentitySignatureInvalid,
         [this] { sign_with(evidence_, rogue_sk_); }},
    };

    const LinuxAttestationProfile pristine_profile = profile_;
    const AttestationChallenge pristine_challenge = challenge_;
    const AttestationEvidence pristine_evidence = evidence_;
    for (const auto& scenario : scenarios) {
        profile_ = pristine_profile;
        challenge_ = pristine_challenge;
        evidence_ = pristine_evidence;
        scenario.apply();

        const auto first = examine();
        const auto second = examine();
        EXPECT_FALSE(first.passed) << scenario.name;
        EXPECT_EQ(first.failure, scenario.expected) << scenario.name;
        expect_identical(first, second, scenario.name);
    }
}

// --- The passing path: checks 0 to 7 are satisfiable ----------------------------------

TEST_F(Tier1PathTest, ACorrectBundleClearsEveryProtocolCheckAndStopsAtThePlatformChain) {
    // Without this test the rejections above could all be passing vacuously,
    // because a bundle that fails check 1 also fails every later one.
    ASSERT_TRUE(profile_is_complete(profile_));
    ASSERT_EQ(challenge_.policy_digest, profile_digest(profile_));
    ASSERT_EQ(evidence_.challenge_digest, challenge_digest(challenge_));
    ASSERT_EQ(evidence_.node_id, challenge_.node_id);
    ASSERT_EQ(evidence_.incarnation, challenge_.incarnation);
    ASSERT_LE(platform_evidence_size(evidence_.platform), kMaxPlatformEvidenceBytes);
    const Digest signed_digest = evidence_signing_digest(evidence_);
    ASSERT_EQ(crypto_sign_verify_detached(evidence_.identity_signature.data(),
                                          signed_digest.data(), signed_digest.size(),
                                          challenge_.node_key.data()),
              0);

    const auto verdict = examine();
    EXPECT_FALSE(verdict.passed);

    // Steps 1 to 6 passed: the verdict carries the digest, which examine()
    // assigns only after the size gate.
    EXPECT_EQ(verdict.evidence_digest, signed_digest);
    EXPECT_NE(verdict.evidence_digest, Digest{});

    // Step 7 passed: map_platform_failure cannot produce these codes, so none
    // of the earlier checks reported the failure.
    EXPECT_NE(verdict.failure, AttestationFailure::ProfileIncomplete);
    EXPECT_NE(verdict.failure, AttestationFailure::RulesetMismatch);
    EXPECT_NE(verdict.failure, AttestationFailure::IdentityMismatch);
    EXPECT_NE(verdict.failure, AttestationFailure::IncarnationStale);
    EXPECT_NE(verdict.failure, AttestationFailure::EvidenceOversized);
    EXPECT_NE(verdict.failure, AttestationFailure::IdentitySignatureInvalid);
    EXPECT_NE(verdict.failure, AttestationFailure::None);

    // The platform chain is the sole remaining barrier.
    EXPECT_TRUE(platform_stage_failure(verdict.failure)) << static_cast<int>(verdict.failure);

    // The reported facts describe the challenge and the compiled profile.
    EXPECT_EQ(verdict.node_id, challenge_.node_id);
    EXPECT_EQ(verdict.epoch, challenge_.epoch);
    EXPECT_EQ(verdict.incarnation, challenge_.incarnation);
    EXPECT_EQ(verdict.policy_digest, profile_digest(profile_));

    expect_identical(verdict, examine(), "platform stage");
}

}  // namespace
