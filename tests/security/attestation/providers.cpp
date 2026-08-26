// The provider boundary: dispatch, downgrade, and substitution.
//
// Revision 1.1 lets Nexus accept more than one confidential-computing platform.
// The risk that creates is downgrade: a candidate whose real profile fails
// answering under a weaker one, or a provider quietly setting a required fact
// true because its platform has no equivalent mechanism. Every test here is one
// way that could happen, and every one must fail closed.
//
// The protocol-level rejections shared by all profiles — wrong challenge, wrong
// node, wrong incarnation, wrong epoch — are covered exhaustively in
// tier1_path.cpp. This file covers what only the provider boundary can get
// wrong.

#include <LemonadeNexus/Security/Attestation/AmdRevocationCache.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationVerifier.hpp>
#include <LemonadeNexus/Security/Attestation/Providers/AzureSnpVtpmProvider.hpp>
#include <LemonadeNexus/Security/Attestation/Providers/SnpDirectBootProvider.hpp>
#include <LemonadeNexus/Security/Attestation/Providers/SnpSvsmVtpmProvider.hpp>
#include <LemonadeNexus/Security/EvidenceBinding.hpp>
#include <LemonadeNexus/Security/HclReport.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Policy/Tier1Evidence.hpp>

#include "support/tpm_quote_fixtures.hpp"

#include <gtest/gtest.h>
#include <sodium.h>

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace fs = std::filesystem;
namespace constants = nexus::security::constants;

using nexus::security::AttestationChallenge;
using nexus::security::AttestationEvidence;
using nexus::security::AttestationFailure;
using nexus::security::AttestationProfileId;
using nexus::security::AttestationProfileRuleset;
using nexus::security::AttestationVerdict;
using nexus::security::AttestationVerifier;
using nexus::security::AzureSnpVtpmProvider;
using nexus::security::Digest;
using nexus::security::LinuxAttestationProfile;
using nexus::security::PlatformEvidenceProvider;
using nexus::security::PlatformVerification;
using nexus::security::ProviderSet;
using nexus::security::SnpDirectBootProvider;
using nexus::security::SnpSvsmVtpmProvider;
using nexus::security::Tier1Eligibility;
using nexus::security::Tier1MeshFacts;
using nexus::security::VerifiedPlatformClaims;
using nexus::security::challenge_digest;
using nexus::security::evidence_signing_digest;
using nexus::security::kAttestationProfileRulesetVersion;
using nexus::security::kTier1AttestationProfileId;
using nexus::security::profile_digest;
using nexus::security::profile_is_complete;
using nexus::security::tier1_eligibility;

namespace {

constexpr const char* kApprovedBinary =
    "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

template <std::size_t N>
std::array<uint8_t, N> patterned(uint8_t seed) {
    std::array<uint8_t, N> out{};
    out.fill(seed);
    return out;
}

fs::path fixture_dir() {
    if (const char* d = std::getenv("NEXUS_TEST_FIXTURES")) return fs::path(d);
    return fs::path(NEXUS_TEST_FIXTURE_DIR);
}

std::vector<uint8_t> fixture_bytes(const char* name) {
    std::ifstream f(fixture_dir() / name, std::ios::binary);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

std::string fixture_text(const char* name) {
    std::ifstream f(fixture_dir() / name);
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

/// A provider that returns exactly the claims a test hands it. It stands in for
/// a future platform whose behavior does not exist yet, which is the only way
/// to test what the verifier does with a provider that misbehaves.
class ScriptedProvider final : public PlatformEvidenceProvider {
public:
    ScriptedProvider(AttestationProfileId id, VerifiedPlatformClaims claims,
                     Digest policy = Digest{})
        : id_(id), claims_(claims), policy_(policy) {}

    [[nodiscard]] AttestationProfileId profile_id() const override { return id_; }
    [[nodiscard]] AttestationProfileRuleset profile_ruleset() const override {
        return ruleset_;
    }
    [[nodiscard]] Digest policy_digest() const override { return policy_; }
    [[nodiscard]] bool tier1_capable() const override { return tier1_capable_; }
    [[nodiscard]] std::optional<AttestationFailure> readiness() const override {
        return refusal_;
    }
    [[nodiscard]] PlatformVerification examine(const AttestationChallenge&,
                                                const AttestationEvidence&) const override {
        PlatformVerification result;
        result.claims = claims_;
        result.claims.profile_id = id_;
        result.claims.profile_ruleset = ruleset_;
        return result;
    }

    AttestationProfileRuleset ruleset_ = kAttestationProfileRulesetVersion;
    bool tier1_capable_ = true;
    std::optional<AttestationFailure> refusal_;

private:
    AttestationProfileId id_;
    VerifiedPlatformClaims claims_;
    Digest policy_;
};

/// Everything a platform provider can prove, so a test can remove exactly one.
VerifiedPlatformClaims every_platform_claim() {
    VerifiedPlatformClaims claims;
    claims.hardware_confidentiality_valid = true;
    claims.platform_identity_valid = true;
    claims.evidence_freshness_valid = true;
    claims.boot_integrity_valid = true;
    claims.tcb_valid = true;
    claims.ima_anchored = true;
    claims.binary_approved = true;
    claims.runtime_profile_enforced = true;
    claims.runtime_integrity_valid = true;
    return claims;
}

Tier1MeshFacts complete_facts(const AttestationVerdict& verdict) {
    Tier1MeshFacts facts;
    facts.certificate_valid = true;
    facts.uptime_valid = true;
    facts.mesh_health_valid = true;
    facts.current_epoch = verdict.epoch;
    facts.current_incarnation = verdict.incarnation;
    return facts;
}

class ProviderBoundaryTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        ASSERT_EQ(crypto_sign_keypair(node_pk_.data(), node_sk_.data()), 0);

        // A COMPLETE profile: an incomplete one refuses every candidate before
        // any provider check, so nothing below would be reachable.
        profile_ = nexus::security::linux_attestation_profile_v1();
        profile_.snp.min_tcb = {2, 0, 6, 55};
        profile_.snp.expected_measurement_hex = std::string(96, 'a');
        profile_.ima_policy_digest.fill(0x60);
        profile_.approved_binary_sha256 = {kApprovedBinary};
        ASSERT_TRUE(profile_is_complete(profile_));

        challenge_ = issue(kTier1AttestationProfileId);
        evidence_ = answer(challenge_);
        sign_evidence();
    }

    [[nodiscard]] AttestationChallenge issue(AttestationProfileId id) const {
        AttestationChallenge challenge;
        challenge.network_id = patterned<32>(0xA0);
        challenge.nonce = patterned<32>(0x11);
        challenge.node_id.bytes = patterned<32>(0x22);
        challenge.node_key = node_pk_;
        challenge.incarnation = 4;
        challenge.epoch = 12;
        challenge.security_ruleset = constants::kSecurityRulesetVersion;
        challenge.consensus_ruleset = constants::kConsensusRulesetVersion;
        challenge.profile_id = id;
        challenge.profile_ruleset = kAttestationProfileRulesetVersion;
        challenge.policy_digest = profile_digest(profile_);
        return challenge;
    }

    [[nodiscard]] static AttestationEvidence answer(const AttestationChallenge& challenge) {
        AttestationEvidence evidence;
        evidence.network_id = challenge.network_id;
        evidence.challenge_digest = challenge_digest(challenge);
        evidence.node_id = challenge.node_id;
        evidence.incarnation = challenge.incarnation;
        evidence.epoch = challenge.epoch;
        evidence.security_ruleset = constants::kSecurityRulesetVersion;
        evidence.consensus_ruleset = constants::kConsensusRulesetVersion;
        evidence.profile_id = challenge.profile_id;
        evidence.profile_ruleset = challenge.profile_ruleset;
        evidence.epoch_vote_key = patterned<32>(0x33);
        return evidence;
    }

    void sign_evidence() { sign(evidence_); }

    void sign(AttestationEvidence& evidence) const {
        const Digest digest = evidence_signing_digest(evidence);
        ASSERT_EQ(crypto_sign_detached(evidence.identity_signature.data(), nullptr,
                                       digest.data(), digest.size(), node_sk_.data()),
                  0);
    }

    /// The compiled provider set: what production actually dispatches over.
    [[nodiscard]] AttestationVerdict examine() const {
        return AttestationVerifier(profile_).examine(challenge_, evidence_);
    }

    /// One scripted provider replacing the compiled set.
    [[nodiscard]] AttestationVerdict examine_with(
        std::shared_ptr<PlatformEvidenceProvider> provider) const {
        return AttestationVerifier(ProviderSet{std::move(provider)})
            .examine(challenge_, evidence_);
    }

    nexus::crypto::Ed25519PublicKey node_pk_{};
    nexus::crypto::Ed25519PrivateKey node_sk_{};
    LinuxAttestationProfile profile_;
    AttestationChallenge challenge_;
    AttestationEvidence evidence_;
};

}  // namespace

// --- Dispatch ------------------------------------------------------------------

TEST_F(ProviderBoundaryTest, AnUnknownProfileHasNoProviderAndProvesNothing) {
    challenge_.profile_id = AttestationProfileId::Unknown;
    evidence_.profile_id = AttestationProfileId::Unknown;
    sign_evidence();

    const auto verdict = examine();
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::ProviderUnknown);
    EXPECT_EQ(verdict.claims.profile_id, AttestationProfileId::Unknown);
    EXPECT_EQ(nexus::security::missing_platform_claims(verdict.claims).size(), 11u);
}

TEST_F(ProviderBoundaryTest, ANamedProfileWithNoCompiledProviderIsRefused) {
    // Tdx is a named ID with no provider in this binary. Naming a profile is
    // not the same as implementing one.
    challenge_.profile_id = AttestationProfileId::Tdx;
    evidence_.profile_id = AttestationProfileId::Tdx;
    sign_evidence();

    const auto verdict = examine();
    EXPECT_EQ(verdict.failure, AttestationFailure::ProviderUnknown);
    EXPECT_EQ(tier1_eligibility(verdict, complete_facts(verdict)),
              Tier1Eligibility::Ineligible);
}

TEST_F(ProviderBoundaryTest, AnUnsupportedProviderRefusesBeforeItExaminesAnything) {
    // The SVSM provider is declared but its evidence format is not invented.
    // It must refuse rather than accept under a guessed binding.
    challenge_.profile_id = AttestationProfileId::SnpSvsmVtpm;
    evidence_.profile_id = AttestationProfileId::SnpSvsmVtpm;
    sign_evidence();

    const auto verdict = examine();
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::ProviderUnsupported);
    EXPECT_EQ(nexus::security::missing_platform_claims(verdict.claims).size(), 11u);
}

TEST_F(ProviderBoundaryTest, TheDirectBootProviderIsNotTier1Capable) {
    // Not "unimplemented" — this platform has no protected runtime measurement
    // accumulator, so implementing its evidence format will not change this.
    SnpDirectBootProvider direct;
    EXPECT_FALSE(direct.tier1_capable());
    EXPECT_EQ(direct.readiness(), AttestationFailure::ProviderUnsupported);

    challenge_.profile_id = AttestationProfileId::SnpDirectBoot;
    evidence_.profile_id = AttestationProfileId::SnpDirectBoot;
    sign_evidence();
    EXPECT_EQ(examine().failure, AttestationFailure::ProviderUnsupported);

    // The SVSM provider IS capable once implemented. Capability and permission
    // are separate: readiness still refuses it today.
    SnpSvsmVtpmProvider svsm;
    EXPECT_TRUE(svsm.tier1_capable());
    EXPECT_EQ(svsm.readiness(), AttestationFailure::ProviderUnsupported);
}

TEST_F(ProviderBoundaryTest, AnIncompleteProfileRefusesBeforeAnyEvidenceIsRead) {
    // The shipped profile pins nothing, because the values may only be read
    // from a host that already satisfies the rules.
    AzureSnpVtpmProvider bare{nexus::security::linux_attestation_profile_v1()};
    EXPECT_EQ(bare.readiness(), AttestationFailure::ProfileIncomplete);
    EXPECT_TRUE(bare.tier1_capable());

    LinuxAttestationProfile incomplete = profile_;
    incomplete.approved_binary_sha256.clear();
    ASSERT_FALSE(profile_is_complete(incomplete));
    const auto verdict = AttestationVerifier(incomplete).examine(challenge_, evidence_);
    EXPECT_EQ(verdict.failure, AttestationFailure::ProfileIncomplete);
}

// --- Downgrade and cross-provider substitution ----------------------------------

TEST_F(ProviderBoundaryTest, EvidenceEncodedForProviderAIsRefusedAsProviderB) {
    // The bundle claims a different profile than the challenge named. Nothing
    // about the SNP or vTPM material is even read.
    evidence_.profile_id = AttestationProfileId::SnpSvsmVtpm;
    sign_evidence();

    const auto verdict = examine();
    EXPECT_EQ(verdict.failure, AttestationFailure::ProfileIdMismatch);
}

TEST_F(ProviderBoundaryTest, AProfileDowngradeRequestIsNotHonored) {
    // The downgrade attempt: a candidate whose real profile cannot pass answers
    // under one with weaker requirements. The challenge names the profile, so
    // the answer is refused rather than re-dispatched to the weaker provider.
    for (const auto weaker : {AttestationProfileId::SnpDirectBoot,
                              AttestationProfileId::Tdx,
                              AttestationProfileId::Unknown}) {
        evidence_ = answer(challenge_);
        evidence_.profile_id = weaker;
        sign_evidence();
        const auto verdict = examine();
        EXPECT_EQ(verdict.failure, AttestationFailure::ProfileIdMismatch)
            << static_cast<int>(weaker);
        EXPECT_FALSE(verdict.passed);
    }
}

TEST_F(ProviderBoundaryTest, AnotherProfileRulesetIsRefusedOnEitherSide) {
    {   // The challenge asks for rules this binary does not run.
        auto other = challenge_;
        other.profile_ruleset = kAttestationProfileRulesetVersion + 1;
        auto reply = answer(other);
        sign(reply);
        const auto verdict = AttestationVerifier(profile_).examine(other, reply);
        EXPECT_EQ(verdict.failure, AttestationFailure::ProfileRulesetMismatch);
    }
    {   // The bundle answers under rules this binary does not run.
        evidence_.profile_ruleset = kAttestationProfileRulesetVersion + 1;
        sign_evidence();
        EXPECT_EQ(examine().failure, AttestationFailure::ProfileRulesetMismatch);
    }
}

// The profile identity is inside the challenge digest, so a relabelled bundle
// cannot be made to answer: changing the label changes what it had to commit to.
TEST_F(ProviderBoundaryTest, TheProfileIdentityIsBoundIntoTheChallengeDigest) {
    const Digest base = challenge_digest(challenge_);
    for (const auto id : {AttestationProfileId::SnpSvsmVtpm,
                          AttestationProfileId::SnpDirectBoot,
                          AttestationProfileId::Unknown}) {
        auto other = challenge_;
        other.profile_id = id;
        EXPECT_NE(challenge_digest(other), base);
    }
    auto bumped = challenge_;
    bumped.profile_ruleset = kAttestationProfileRulesetVersion + 1;
    EXPECT_NE(challenge_digest(bumped), base);
}

TEST_F(ProviderBoundaryTest, TheProfileIdentityIsBoundIntoTheSignedEvidenceDigest) {
    const Digest base = evidence_signing_digest(evidence_);
    auto relabelled = evidence_;
    relabelled.profile_id = AttestationProfileId::SnpDirectBoot;
    EXPECT_NE(evidence_signing_digest(relabelled), base);

    auto bumped = evidence_;
    bumped.profile_ruleset = kAttestationProfileRulesetVersion + 1;
    EXPECT_NE(evidence_signing_digest(bumped), base);
}

// A whole valid answer to a challenge for one profile, replayed against a
// challenge for another. Re-signing it does not help: the challenge digest it
// carries was computed under the other profile's challenge.
TEST_F(ProviderBoundaryTest, CrossProviderReplayFailsEvenWhenResigned) {
    const AttestationChallenge svsm_challenge = issue(AttestationProfileId::SnpSvsmVtpm);
    AttestationEvidence for_svsm = answer(svsm_challenge);
    sign(for_svsm);

    // Relabelled to the profile this verifier challenged under, and re-signed.
    for_svsm.profile_id = kTier1AttestationProfileId;
    sign(for_svsm);

    const auto verdict = AttestationVerifier(profile_).examine(challenge_, for_svsm);
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::ChallengeMismatch);
}

// --- What a provider may and may not claim --------------------------------------

TEST_F(ProviderBoundaryTest, OneMissingRequiredClaimGivesNoTier1) {
    using Claims = VerifiedPlatformClaims;
    const std::pair<const char*, bool Claims::*> required[] = {
        {"hardware confidentiality", &Claims::hardware_confidentiality_valid},
        {"platform identity", &Claims::platform_identity_valid},
        {"evidence freshness", &Claims::evidence_freshness_valid},
        {"boot integrity", &Claims::boot_integrity_valid},
        {"tcb", &Claims::tcb_valid},
    };
    for (const auto& [label, field] : required) {
        VerifiedPlatformClaims claims = every_platform_claim();
        claims.*field = false;
        const auto verdict = examine_with(std::make_shared<ScriptedProvider>(
            kTier1AttestationProfileId, claims, profile_digest(profile_)));

        // The provider reported no failure, so the verdict passed. The claim it
        // did not prove is still missing, and Tier 1 turns on the claims.
        EXPECT_TRUE(verdict.passed) << label;
        EXPECT_EQ(nexus::security::missing_platform_claims(verdict.claims).size(), 1u) << label;
        EXPECT_EQ(tier1_eligibility(verdict, complete_facts(verdict)),
                  Tier1Eligibility::Ineligible) << label;
    }
}

// The headline rule of Revision 1.1: `passed` is not the Tier 1 decision.
TEST_F(ProviderBoundaryTest, APassingVerdictThatProvedNothingConfersNothing) {
    const auto verdict = examine_with(std::make_shared<ScriptedProvider>(
        kTier1AttestationProfileId, VerifiedPlatformClaims{}, profile_digest(profile_)));

    EXPECT_TRUE(verdict.passed);
    EXPECT_FALSE(nexus::security::all_platform_claims_proved(verdict.claims));
    EXPECT_EQ(tier1_eligibility(verdict, complete_facts(verdict)),
              Tier1Eligibility::Ineligible);
}

// The direct-boot shape: strong boot integrity, no protected runtime
// accumulator. It must not reach Tier 1, and the absence of a TPM is not
// permission to drop the runtime prerequisites.
TEST_F(ProviderBoundaryTest, ProvenBootIntegrityWithoutRuntimeIntegrityIsNotTier1) {
    VerifiedPlatformClaims claims = every_platform_claim();
    claims.ima_anchored = false;
    claims.binary_approved = false;
    claims.runtime_profile_enforced = false;
    claims.runtime_integrity_valid = false;

    const auto verdict = examine_with(std::make_shared<ScriptedProvider>(
        kTier1AttestationProfileId, claims, profile_digest(profile_)));

    EXPECT_TRUE(verdict.claims.boot_integrity_valid);
    EXPECT_TRUE(verdict.claims.hardware_confidentiality_valid);
    EXPECT_FALSE(verdict.claims.runtime_integrity_valid);

    const auto failed = nexus::security::Tier1EligibilityPolicy::failed_prerequisites(
        nexus::security::tier1_evidence_state(verdict, complete_facts(verdict)));
    EXPECT_EQ(failed.size(), 3u);
    EXPECT_EQ(tier1_eligibility(verdict, complete_facts(verdict)),
              Tier1Eligibility::Ineligible);
}

// A provider claiming runtime integrity without the steps that produce it is
// broken. Its whole claim set is refused rather than trusted in part.
TEST_F(ProviderBoundaryTest, AProviderCannotAssertRuntimeIntegrityWithoutItsSteps) {
    VerifiedPlatformClaims claims = every_platform_claim();
    claims.ima_anchored = false;  // runtime_integrity_valid left true

    const auto verdict = examine_with(std::make_shared<ScriptedProvider>(
        kTier1AttestationProfileId, claims, profile_digest(profile_)));

    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::ProviderUnsupported);
    EXPECT_EQ(tier1_eligibility(verdict, complete_facts(verdict)),
              Tier1Eligibility::Ineligible);
}

// A provider that answers for a profile it was not asked about never runs: the
// verifier dispatches on the challenge, not on what a provider volunteers.
TEST_F(ProviderBoundaryTest, AProviderCannotAnswerForAProfileItDoesNotOwn) {
    const auto verdict = examine_with(std::make_shared<ScriptedProvider>(
        AttestationProfileId::Tdx, every_platform_claim(), profile_digest(profile_)));

    EXPECT_EQ(verdict.failure, AttestationFailure::ProviderUnknown);
}

// --- Substitution against real platform material --------------------------------

namespace {

/// The real captured SNP report and AMD material. The quote on top is the
/// test's own: only the real vTPM holds the key for a genuine one.
nexus::security::SnpVtpmEvidence real_platform_bundle() {
    nexus::security::SnpVtpmEvidence bundle;
    bundle.hcl_blob = fixture_bytes("azure_snp_hcl.bin");
    bundle.vcek_der = fixture_bytes("vcek_milan.der");
    bundle.amd_chain_pem = fixture_text("amd_milan_cert_chain.pem");
    bundle.binary_path = "/opt/nexus";
    bundle.binary_sha256 = kApprovedBinary;
    return bundle;
}

/// The launch measurement the captured report actually carries. Read from the
/// fixture rather than transcribed, so pinning it means "this known-good host"
/// and stays right if the fixture is ever recaptured.
std::string captured_measurement_hex() {
    const auto blob = fixture_bytes("azure_snp_hcl.bin");
    const auto parsed = nexus::security::parse_hcl_blob(blob);
    EXPECT_TRUE(parsed.has_value());
    return parsed ? parsed->snp.measurement_hex() : std::string{};
}

/// The profile that matches the captured report, so the chain reaches the quote
/// instead of stopping at a policy mismatch.
LinuxAttestationProfile profile_for_the_captured_host() {
    LinuxAttestationProfile profile = nexus::security::linux_attestation_profile_v1();
    // The TCB the captured report actually carries, so the chain reaches the
    // quote instead of stopping at the floor.
    profile.snp.min_tcb = {4, 0, 28, 222};
    profile.snp.expected_measurement_hex = captured_measurement_hex();
    profile.ima_policy_digest.fill(0x60);
    profile.approved_binary_sha256 = {kApprovedBinary};
    // The captured fixture predates any cached CRL, and revocation is checked
    // right after the AMD signature. Leaving it on here would stop every test
    // below at the same step; the revocation rule has its own tests instead.
    profile.require_endorsement_revocation = false;
    return profile;
}

}  // namespace

// The substitution the whole chain exists to stop. A host-side swtpm, or the
// vTPM of a different guest, produces a structurally perfect quote under a key
// AMD never vouched for. The AK inside the SNP report is the only one that
// counts.
TEST_F(ProviderBoundaryTest, AQuoteFromAnUnvouchedTpmIsRejected) {
    // Everything about the platform is genuine and matches the pin, so the
    // chain reaches the quote. Only the key that signed the quote is wrong.
    LinuxAttestationProfile profile = profile_for_the_captured_host();
    ASSERT_TRUE(profile_is_complete(profile));

    challenge_.policy_digest = profile_digest(profile);
    evidence_ = answer(challenge_);
    evidence_.platform = real_platform_bundle();
    evidence_.platform.binary_sha256.clear();

    auto impostor = nexus_test::gen_rsa_key();
    const auto binding = nexus::security::evidence_binding(
        evidence_.challenge_digest, node_pk_, {});
    evidence_.platform.tpms_attest = nexus_test::build_quote(
        std::vector<uint8_t>(binding.begin(), binding.end()),
        nexus_test::sha256_of({}), {0x00, 0x04, 0x00});
    evidence_.platform.tpm_signature =
        nexus_test::sign_tpmt_rsa(impostor->pkey, evidence_.platform.tpms_attest);
    sign_evidence();

    const auto verdict = AttestationVerifier(profile).examine(challenge_, evidence_);
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::TpmQuoteInvalid);
    // The hardware boundary and its bound AK are genuine, and that is exactly
    // the point: they belong to a vTPM that did not sign this quote.
    EXPECT_TRUE(verdict.claims.hardware_confidentiality_valid);
    EXPECT_TRUE(verdict.claims.platform_identity_valid);
    // The forged quote never becomes fresh evidence, so Tier 1 loses the
    // freshness prerequisite whatever else held.
    EXPECT_FALSE(verdict.claims.evidence_freshness_valid);
    EXPECT_FALSE(verdict.claims.runtime_integrity_valid);
    EXPECT_EQ(tier1_eligibility(verdict, complete_facts(verdict)),
              Tier1Eligibility::Ineligible);
}

// A valid TPM quote with no confidential-compute evidence behind it. Without an
// SNP report there is no hardware boundary and no key AMD vouched for, so a
// quote proves only that some TPM somewhere signed something.
TEST_F(ProviderBoundaryTest, AQuoteWithNoConfidentialBindingIsRejected) {
    LinuxAttestationProfile profile = profile_for_the_captured_host();
    ASSERT_TRUE(profile_is_complete(profile));
    challenge_.policy_digest = profile_digest(profile);
    evidence_ = answer(challenge_);

    auto key = nexus_test::gen_rsa_key();
    const auto binding = nexus::security::evidence_binding(
        evidence_.challenge_digest, node_pk_, {});
    evidence_.platform.tpms_attest = nexus_test::build_quote(
        std::vector<uint8_t>(binding.begin(), binding.end()),
        nexus_test::sha256_of({}), {0x00, 0x04, 0x00});
    evidence_.platform.tpm_signature =
        nexus_test::sign_tpmt_rsa(key->pkey, evidence_.platform.tpms_attest);
    sign_evidence();

    const auto verdict = AttestationVerifier(profile).examine(challenge_, evidence_);
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::SnpInvalid);
    EXPECT_FALSE(verdict.claims.hardware_confidentiality_valid);
    EXPECT_FALSE(verdict.claims.platform_identity_valid);
}

// The launch measurement pin is what separates a genuine bound vTPM from a
// self-signed one. On a native SNP guest the guest itself chooses REPORT_DATA,
// so it could sign a runtime-data blob naming any AK. What it cannot do is
// change the launch measurement AMD signed. That is why the profile must be
// pinned from a host already known good, never from the host being qualified.
TEST_F(ProviderBoundaryTest, TheLaunchMeasurementPinIsCheckedBeforeTheQuote) {
    LinuxAttestationProfile profile = profile_for_the_captured_host();
    profile.snp.expected_measurement_hex = std::string(96, 'f');  // not this host
    ASSERT_TRUE(profile_is_complete(profile));

    challenge_.policy_digest = profile_digest(profile);
    evidence_ = answer(challenge_);
    evidence_.platform = real_platform_bundle();
    sign_evidence();

    const auto verdict = AttestationVerifier(profile).examine(challenge_, evidence_);
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::SnpInvalid);
    EXPECT_FALSE(verdict.claims.hardware_confidentiality_valid);
    // The AMD signature held; only the pinned launch state did not.
    EXPECT_FALSE(verdict.claims.tcb_valid);
}

// --- AMD revocation ------------------------------------------------------------
//
// AMD's signature over an endorsement it has since withdrawn is worth nothing.
// The check runs immediately after the signature and before guest policy, so a
// revoked chain never reaches the parts of the report it vouched for.
//
// amd_milan_crl.der is the real KDS list for Milan, signed by ARK-Milan and
// valid from 2026-08-19 to 2026-10-04. The timestamps below are fixed rather
// than read from the clock, so the accepting and expired branches both stay
// testable after that window closes.

namespace {

/// A profile that demands current revocation data, matching the captured host
/// in every other respect.
LinuxAttestationProfile profile_requiring_revocation() {
    LinuxAttestationProfile profile = profile_for_the_captured_host();
    profile.require_endorsement_revocation = true;
    return profile;
}

constexpr int64_t kInsideCrlWindow  = 1'788'220'800;  // 2026-09-01
constexpr int64_t kBeforeCrlWindow  = 1'785'542'400;  // 2026-08-01
constexpr int64_t kAfterCrlWindow   = 1'793'491'200;  // 2026-11-01

nexus::security::AmdRevocationState revocation(std::vector<std::string> crls, int64_t now) {
    nexus::security::AmdRevocationState state;
    state.crls = std::move(crls);
    state.now_unix = now;
    return state;
}

std::string real_milan_crl() { return fixture_text("amd_milan_crl.der"); }

std::vector<uint8_t> milan_vcek() { return fixture_bytes("vcek_milan.der"); }

}  // namespace

// The accepting path. A genuine AMD-signed list, inside its validity window,
// naming no revoked serial.
TEST(AmdRevocation, AValidCachedListAccepts) {
    const auto result = nexus::security::verify_snp_revocation(
        milan_vcek(), {}, revocation({real_milan_crl()}, kInsideCrlWindow));
    EXPECT_TRUE(result.ok) << result.failure;
}

TEST(AmdRevocation, AnExpiredListIsRefused) {
    const auto result = nexus::security::verify_snp_revocation(
        milan_vcek(), {}, revocation({real_milan_crl()}, kAfterCrlWindow));
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.failure.find("expired"), std::string::npos) << result.failure;
}

TEST(AmdRevocation, AListThatIsNotValidYetIsRefused) {
    const auto result = nexus::security::verify_snp_revocation(
        milan_vcek(), {}, revocation({real_milan_crl()}, kBeforeCrlWindow));
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.failure.find("not valid yet"), std::string::npos) << result.failure;
}

TEST(AmdRevocation, AbsentDataAndAbsentClockBothFailClosed) {
    const auto no_data = nexus::security::verify_snp_revocation(
        milan_vcek(), {}, revocation({}, kInsideCrlWindow));
    EXPECT_FALSE(no_data.ok);
    EXPECT_NE(no_data.failure.find("no cached AMD revocation list"), std::string::npos);

    const auto no_clock = nexus::security::verify_snp_revocation(
        milan_vcek(), {}, revocation({real_milan_crl()}, 0));
    EXPECT_FALSE(no_clock.ok);
    EXPECT_NE(no_clock.failure.find("no trusted clock"), std::string::npos);
}

// The attacker's own list: correctly formed, currently valid, signed by a key
// that is not in this VCEK's AMD chain. Accepting it would let a host supply a
// list that revokes nothing.
TEST(AmdRevocation, AListFromAnotherIssuerIsRefused) {
    const auto result = nexus::security::verify_snp_revocation(
        milan_vcek(), {}, revocation({fixture_text("foreign_crl.pem")}, kInsideCrlWindow));
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.failure.find("no cached revocation list is signed"), std::string::npos)
        << result.failure;
}

TEST(AmdRevocation, MalformedDataIsRefused) {
    for (const char* junk : {"not a crl", "-----BEGIN X509 CRL-----\nAAAA\n", "\x30\x82\xff"}) {
        const auto result = nexus::security::verify_snp_revocation(
            milan_vcek(), {}, revocation({junk}, kInsideCrlWindow));
        EXPECT_FALSE(result.ok) << junk;
    }
}

// A mesh spans silicon generations, so a verifier is handed every list it
// holds. The one that belongs to this VCEK's chain is the one that decides;
// lists for other products cannot verify there, and junk beside a good list
// does not spoil it.
TEST(AmdRevocation, TheListForThisChainIsTheOneUsed) {
    const auto mixed = nexus::security::verify_snp_revocation(
        milan_vcek(), {},
        revocation({fixture_text("foreign_crl.pem"), "not a crl", real_milan_crl()},
                   kInsideCrlWindow));
    EXPECT_TRUE(mixed.ok) << mixed.failure;

    // Without the list for this chain, nothing else in the set helps.
    const auto without = nexus::security::verify_snp_revocation(
        milan_vcek(), {}, revocation({fixture_text("foreign_crl.pem"), "not a crl"},
                                     kInsideCrlWindow));
    EXPECT_FALSE(without.ok);
}

// --- the cache: storage only, no trust decisions --------------------------------

TEST(AmdRevocationCache, StoresAndReloadsWhatItWasGiven) {
    const fs::path root = fs::temp_directory_path() /
                          ("nexus_crl_" + std::to_string(::getpid()));
    fs::remove_all(root);
    nexus::security::AmdRevocationCache cache{root};

    EXPECT_FALSE(cache.load("Milan").has_value());
    EXPECT_TRUE(cache.state(kInsideCrlWindow).crls.empty());

    ASSERT_TRUE(cache.store("Milan", real_milan_crl(), kInsideCrlWindow));
    const auto cached = cache.load("Milan");
    ASSERT_TRUE(cached.has_value());
    EXPECT_EQ(cached->bytes, real_milan_crl());
    EXPECT_EQ(cached->stored_unix, kInsideCrlWindow);

    // What the cache hands a verifier is accepted by it.
    const auto state = cache.state(kInsideCrlWindow);
    ASSERT_EQ(state.crls.size(), 1u);
    EXPECT_TRUE(nexus::security::verify_snp_revocation(milan_vcek(), {}, state).ok);

    fs::remove_all(root);
}

// The cache stores bytes. It does not decide whether they are any good, which
// is what keeps a fetch failure from looking like a cryptographic result.
TEST(AmdRevocationCache, StoresWithoutValidating) {
    const fs::path root = fs::temp_directory_path() /
                          ("nexus_crl_junk_" + std::to_string(::getpid()));
    fs::remove_all(root);
    nexus::security::AmdRevocationCache cache{root};

    EXPECT_TRUE(cache.store("Milan", "not a crl at all", kInsideCrlWindow));
    const auto state = cache.state(kInsideCrlWindow);
    ASSERT_EQ(state.crls.size(), 1u);
    // Stored, and refused by the verifier. Nothing was weakened by caching it.
    EXPECT_FALSE(nexus::security::verify_snp_revocation(milan_vcek(), {}, state).ok);

    // A product with no compiled-in root has no chain to check a list against.
    EXPECT_FALSE(cache.store("Turin", real_milan_crl(), kInsideCrlWindow));
    EXPECT_FALSE(cache.load("Turin").has_value());
    EXPECT_FALSE(cache.store("Milan", "", kInsideCrlWindow));

    fs::remove_all(root);
}

// A refresh that never happens leaves the last good bytes in place. New Tier 1
// attestation fails closed once they expire; nothing here reaches back into an
// epoch that was already frozen, because membership is decided once, at
// selection, and this code runs only when new evidence is examined.
TEST(AmdRevocationCache, AFetchOutageOnlyAffectsNewAttestation) {
    const fs::path root = fs::temp_directory_path() /
                          ("nexus_crl_outage_" + std::to_string(::getpid()));
    fs::remove_all(root);
    nexus::security::AmdRevocationCache cache{root};
    ASSERT_TRUE(cache.store("Milan", real_milan_crl(), kInsideCrlWindow));

    // While the cached list is current, attestation proceeds with no network.
    EXPECT_TRUE(nexus::security::verify_snp_revocation(
                    milan_vcek(), {}, cache.state(kInsideCrlWindow)).ok);

    // The outage continues past the list's own nextUpdate. New attestation now
    // fails closed rather than trusting a list that predates any revocation.
    const auto stale = nexus::security::verify_snp_revocation(
        milan_vcek(), {}, cache.state(kAfterCrlWindow));
    EXPECT_FALSE(stale.ok);
    EXPECT_NE(stale.failure.find("expired"), std::string::npos) << stale.failure;

    fs::remove_all(root);
}

TEST(AmdRevocationCache, TheSourceReadsTheClockItWasGiven) {
    const fs::path root = fs::temp_directory_path() /
                          ("nexus_crl_clock_" + std::to_string(::getpid()));
    fs::remove_all(root);
    nexus::security::AmdRevocationCache cache{root};
    ASSERT_TRUE(cache.store("Milan", real_milan_crl(), kInsideCrlWindow));

    int64_t now = kInsideCrlWindow;
    const auto source = cache.source([&now] { return now; });
    EXPECT_TRUE(nexus::security::verify_snp_revocation(milan_vcek(), {}, source()).ok);
    now = kAfterCrlWindow;
    EXPECT_FALSE(nexus::security::verify_snp_revocation(milan_vcek(), {}, source()).ok);

    // No clock at all fails closed rather than defaulting to "now".
    const auto blind = cache.source({});
    EXPECT_FALSE(nexus::security::verify_snp_revocation(milan_vcek(), {}, blind()).ok);

    fs::remove_all(root);
}

// End to end through a provider: the profile demands revocation, the cache
// supplies a current list, and the chain reaches the quote instead of stopping
// at the revocation gate.
TEST_F(ProviderBoundaryTest, ACurrentCachedListLetsTheChainProceed) {
    const LinuxAttestationProfile profile = profile_requiring_revocation();
    ASSERT_TRUE(profile_is_complete(profile));
    challenge_.policy_digest = profile_digest(profile);
    evidence_ = answer(challenge_);
    evidence_.platform = real_platform_bundle();
    sign_evidence();

    const auto verifier = AttestationVerifier(profile, [] {
        return revocation({real_milan_crl()}, kInsideCrlWindow);
    });
    const auto verdict = verifier.examine(challenge_, evidence_);
    EXPECT_NE(verdict.failure, AttestationFailure::EndorsementRevoked);
    // Revocation passed, so the AMD half of the platform claim is proved. The
    // bundle still fails later, at the quote it has no key for.
    EXPECT_TRUE(verdict.claims.hardware_confidentiality_valid);
    EXPECT_FALSE(verdict.passed);
}

TEST_F(ProviderBoundaryTest, AbsentRevocationDataFailsClosed) {
    const LinuxAttestationProfile profile = profile_requiring_revocation();
    challenge_.policy_digest = profile_digest(profile);
    evidence_ = answer(challenge_);
    evidence_.platform = real_platform_bundle();
    sign_evidence();

    // No source installed at all: the operator cached nothing.
    const auto verdict = AttestationVerifier(profile).examine(challenge_, evidence_);
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::EndorsementRevoked);
    // The AMD signature held; the question of whether AMD stands behind it did
    // not get an answer, and an unanswered question is a refusal.
    EXPECT_FALSE(verdict.claims.hardware_confidentiality_valid);
    EXPECT_EQ(tier1_eligibility(verdict, complete_facts(verdict)),
              Tier1Eligibility::Ineligible);
}

TEST_F(ProviderBoundaryTest, AnExpiredListStopsNewAttestation) {
    const LinuxAttestationProfile profile = profile_requiring_revocation();
    challenge_.policy_digest = profile_digest(profile);
    evidence_ = answer(challenge_);
    evidence_.platform = real_platform_bundle();
    sign_evidence();

    const auto verifier = AttestationVerifier(profile, [] {
        return revocation({real_milan_crl()}, kAfterCrlWindow);
    });
    const auto verdict = verifier.examine(challenge_, evidence_);
    EXPECT_EQ(verdict.failure, AttestationFailure::EndorsementRevoked);
    EXPECT_EQ(tier1_eligibility(verdict, complete_facts(verdict)),
              Tier1Eligibility::Ineligible);
}

// The requirement is compiled into the profile and bound into its digest, so a
// build that dropped it could not answer a challenge issued by one that kept it.
TEST_F(ProviderBoundaryTest, TheRevocationRequirementIsPartOfTheProfileIdentity) {
    LinuxAttestationProfile without = profile_requiring_revocation();
    without.require_endorsement_revocation = false;
    EXPECT_NE(profile_digest(without), profile_digest(profile_requiring_revocation()));

    // The shipped Tier 1 profile demands it.
    EXPECT_TRUE(nexus::security::linux_attestation_profile_v1()
                    .require_endorsement_revocation);
}

// --- tier1_capable() is informational -------------------------------------------
//
// tier1_capable() says a provider's DESIGN can satisfy Tier 1. It is not an
// authorization result, it is not consulted by AttestationVerifier, and it is
// not consulted by Tier1EligibilityPolicy. Only verified claims plus mesh facts
// produce eligibility. These tests pin that so the flag cannot drift into the
// decision path.

TEST_F(ProviderBoundaryTest, ACapableProviderThatIsNotReadyConfersNothing) {
    // The dangerous shape: a provider that could satisfy Tier 1 and would
    // report every claim, but is not ready to decide. Readiness wins.
    for (const auto refusal : {AttestationFailure::ProviderUnsupported,
                               AttestationFailure::ProfileIncomplete}) {
        auto provider = std::make_shared<ScriptedProvider>(
            kTier1AttestationProfileId, every_platform_claim(), profile_digest(profile_));
        provider->tier1_capable_ = true;
        provider->refusal_ = refusal;

        const auto verdict = examine_with(provider);
        ASSERT_TRUE(provider->tier1_capable());
        EXPECT_FALSE(verdict.passed);
        EXPECT_EQ(verdict.failure, refusal);
        // examine() never ran, so no claim was produced.
        EXPECT_EQ(nexus::security::missing_platform_claims(verdict.claims).size(), 11u);
        EXPECT_EQ(tier1_eligibility(verdict, complete_facts(verdict)),
                  Tier1Eligibility::Ineligible);
    }
}

TEST_F(ProviderBoundaryTest, ACapableReadyProviderStillNeedsEveryClaim) {
    VerifiedPlatformClaims claims = every_platform_claim();
    claims.boot_integrity_valid = false;

    auto provider = std::make_shared<ScriptedProvider>(
        kTier1AttestationProfileId, claims, profile_digest(profile_));
    provider->tier1_capable_ = true;
    provider->refusal_.reset();  // ready

    const auto verdict = examine_with(provider);
    ASSERT_TRUE(provider->tier1_capable());
    ASSERT_FALSE(provider->readiness().has_value());
    EXPECT_TRUE(verdict.passed);  // the provider reported no failing step
    EXPECT_EQ(tier1_eligibility(verdict, complete_facts(verdict)),
              Tier1Eligibility::Ineligible);
}

// The flag is not an input to eligibility. A provider that declared itself
// incapable but proved every claim is still eligible, which is why the flag
// must never be relied on as a control: what actually stops a provider is a
// claim it cannot produce. SnpDirectBootProvider is refused because it cannot
// prove runtime integrity, not because of this flag.
TEST_F(ProviderBoundaryTest, EligibilityDoesNotConsultTierOneCapable) {
    auto incapable = std::make_shared<ScriptedProvider>(
        kTier1AttestationProfileId, every_platform_claim(), profile_digest(profile_));
    incapable->tier1_capable_ = false;

    const auto verdict = examine_with(incapable);
    ASSERT_FALSE(incapable->tier1_capable());
    EXPECT_TRUE(nexus::security::all_platform_claims_proved(verdict.claims));
    EXPECT_EQ(tier1_eligibility(verdict, complete_facts(verdict)),
              Tier1Eligibility::Eligible);
}

// Every compiled provider obeys the invariant today: capable or not, none of
// them is ready, so none can produce a claim and none can confer Tier 1.
TEST_F(ProviderBoundaryTest, NoCompiledProviderIsReadyUnderTheShippedProfile) {
    const LinuxAttestationProfile shipped = nexus::security::linux_attestation_profile_v1();
    const auto providers = nexus::security::compiled_providers(shipped);
    ASSERT_EQ(providers.size(), 3u);

    for (const auto& provider : providers) {
        const auto refusal = provider->readiness();
        ASSERT_TRUE(refusal.has_value())
            << nexus::security::attestation_profile_id_name(provider->profile_id());

        auto local = challenge_;
        local.profile_id = provider->profile_id();
        local.policy_digest = provider->policy_digest();
        auto reply = answer(local);
        sign(reply);
        const auto verdict = AttestationVerifier(shipped).examine(local, reply);
        EXPECT_EQ(verdict.failure, *refusal)
            << nexus::security::attestation_profile_id_name(provider->profile_id());
        EXPECT_EQ(tier1_eligibility(verdict, complete_facts(verdict)),
                  Tier1Eligibility::Ineligible);
    }
}
