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
// Every branch here is a refusal. The accepting branch cannot be tested off
// platform: a CRL that this chain accepts must be signed by AMD's own key, and
// the captured fixtures predate any published CRL. A KDS outage still cannot
// shrink a live epoch, because membership is frozen once selected and only NEW
// attestation consults revocation.

namespace {

/// A profile that demands current revocation data, matching the captured host
/// in every other respect.
LinuxAttestationProfile profile_requiring_revocation() {
    LinuxAttestationProfile profile = profile_for_the_captured_host();
    profile.require_endorsement_revocation = true;
    return profile;
}

constexpr int64_t kSomeTimeIn2026 = 1'774'000'000;

}  // namespace

TEST_F(ProviderBoundaryTest, AbsentRevocationDataFailsClosed) {
    const LinuxAttestationProfile profile = profile_requiring_revocation();
    ASSERT_TRUE(profile_is_complete(profile));
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

TEST_F(ProviderBoundaryTest, RevocationWithoutATrustedClockFailsClosed) {
    const LinuxAttestationProfile profile = profile_requiring_revocation();
    challenge_.policy_digest = profile_digest(profile);
    evidence_ = answer(challenge_);
    evidence_.platform = real_platform_bundle();
    sign_evidence();

    // A CRL with no clock to check it against. An expired list would look
    // exactly like a current one, which is what a stale-list replay needs.
    const auto verifier = AttestationVerifier(profile, [] {
        nexus::security::AmdRevocationState state;
        state.crl = fixture_text("foreign_crl.pem");
        state.now_unix = 0;
        return state;
    });
    EXPECT_EQ(verifier.examine(challenge_, evidence_).failure,
              AttestationFailure::EndorsementRevoked);
}

TEST_F(ProviderBoundaryTest, ARevocationListFromAnotherIssuerIsRefused) {
    // The attacker's own CRL: correctly formed, currently valid, and signed by
    // a key that is not in this VCEK's AMD chain. Accepting it would let a host
    // supply a list that revokes nothing.
    const LinuxAttestationProfile profile = profile_requiring_revocation();
    challenge_.policy_digest = profile_digest(profile);
    evidence_ = answer(challenge_);
    evidence_.platform = real_platform_bundle();
    sign_evidence();

    const auto verifier = AttestationVerifier(profile, [] {
        nexus::security::AmdRevocationState state;
        state.crl = fixture_text("foreign_crl.pem");
        state.now_unix = kSomeTimeIn2026;
        return state;
    });
    EXPECT_EQ(verifier.examine(challenge_, evidence_).failure,
              AttestationFailure::EndorsementRevoked);
}

TEST_F(ProviderBoundaryTest, UnparsableRevocationDataIsRefused) {
    const LinuxAttestationProfile profile = profile_requiring_revocation();
    challenge_.policy_digest = profile_digest(profile);
    evidence_ = answer(challenge_);
    evidence_.platform = real_platform_bundle();
    sign_evidence();

    for (const char* junk : {"not a crl", "-----BEGIN X509 CRL-----\nAAAA\n"}) {
        const auto verifier = AttestationVerifier(profile, [junk] {
            nexus::security::AmdRevocationState state;
            state.crl = junk;
            state.now_unix = kSomeTimeIn2026;
            return state;
        });
        EXPECT_EQ(verifier.examine(challenge_, evidence_).failure,
                  AttestationFailure::EndorsementRevoked) << junk;
    }
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

// --- network separation --------------------------------------------------------
//
// Transport authenticates the envelope, but transport authentication is not
// trust. Without network_id inside the signed attestation context, a node
// enrolled in one Nexus network could answer another network's challenge with
// the same identity, the same platform and the same fresh quote.

TEST_F(ProviderBoundaryTest, TheNetworkIsBoundIntoTheChallengeDigest) {
    const Digest base = challenge_digest(challenge_);
    auto elsewhere = challenge_;
    elsewhere.network_id = patterned<32>(0xB0);
    ASSERT_NE(elsewhere.network_id, challenge_.network_id);
    EXPECT_NE(challenge_digest(elsewhere), base);
}

TEST_F(ProviderBoundaryTest, TheNetworkIsBoundIntoTheSignedEvidenceDigest) {
    const Digest base = evidence_signing_digest(evidence_);
    auto elsewhere = evidence_;
    elsewhere.network_id = patterned<32>(0xB0);
    EXPECT_NE(evidence_signing_digest(elsewhere), base);
}

TEST_F(ProviderBoundaryTest, EvidenceForAnotherNetworkIsRejected) {
    evidence_.network_id = patterned<32>(0xB0);
    sign_evidence();

    const auto verdict = examine();
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::NetworkMismatch);
    // Nothing the platform could prove is recorded: the answer was not for us.
    EXPECT_FALSE(verdict.claims.hardware_confidentiality_valid);
    EXPECT_EQ(tier1_eligibility(verdict, complete_facts(verdict)),
              Tier1Eligibility::Ineligible);
}

// The whole point of binding the network: a bundle built correctly for another
// mesh cannot be relabelled into this one, because the challenge it answered
// committed to that mesh's identity. Re-signing does not help.
TEST_F(ProviderBoundaryTest, CrossNetworkReplayFailsEvenWhenResigned) {
    AttestationChallenge foreign = challenge_;
    foreign.network_id = patterned<32>(0xB0);
    AttestationEvidence for_foreign = answer(foreign);
    sign(for_foreign);

    // Straight replay: the bundle still names the other mesh.
    EXPECT_EQ(AttestationVerifier(profile_).examine(challenge_, for_foreign).failure,
              AttestationFailure::NetworkMismatch);

    // Relabelled to this mesh and re-signed. The challenge digest it carries was
    // computed under the other network's challenge, so it answers nothing here.
    for_foreign.network_id = challenge_.network_id;
    sign(for_foreign);
    EXPECT_EQ(AttestationVerifier(profile_).examine(challenge_, for_foreign).failure,
              AttestationFailure::ChallengeMismatch);
}

// Every field of the attestation context is separately bound. Changing any one
// of them changes the digest a quote has to commit to.
TEST_F(ProviderBoundaryTest, TheWholeAttestationContextIsBound) {
    const Digest base = challenge_digest(challenge_);
    struct Case {
        const char* label;
        std::function<void(AttestationChallenge&)> mutate;
    };
    const Case cases[] = {
        {"network_id",       [](AttestationChallenge& c) { c.network_id[0] ^= 1; }},
        {"profile_id",       [](AttestationChallenge& c) {
             c.profile_id = AttestationProfileId::SnpSvsmVtpm; }},
        {"profile_ruleset",  [](AttestationChallenge& c) { c.profile_ruleset += 1; }},
        {"security_ruleset", [](AttestationChallenge& c) { c.security_ruleset += 1; }},
        {"consensus_ruleset",[](AttestationChallenge& c) { c.consensus_ruleset += 1; }},
        {"node_id",          [](AttestationChallenge& c) { c.node_id.bytes[0] ^= 1; }},
        {"node_key",         [](AttestationChallenge& c) { c.node_key[0] ^= 1; }},
        {"incarnation",      [](AttestationChallenge& c) { c.incarnation += 1; }},
        {"epoch",            [](AttestationChallenge& c) { c.epoch += 1; }},
        {"nonce",            [](AttestationChallenge& c) { c.nonce[0] ^= 1; }},
        {"policy_digest",    [](AttestationChallenge& c) { c.policy_digest[0] ^= 1; }},
    };
    for (const auto& entry : cases) {
        AttestationChallenge mutated = challenge_;
        entry.mutate(mutated);
        EXPECT_NE(challenge_digest(mutated), base) << entry.label;
    }
}
