// The attestation purpose and context binding (architecture: final
// attestation binds the exact adoption context).
//
// One fresh platform attestation must answer exactly one question. The
// purpose says which question; the context digest says for which plan,
// attempt, selected set and node. Both live inside the challenge digest —
// the TPM quote's nonce input — and inside the identity-signed evidence, so
// evidence for one context can never satisfy another.

#include <LemonadeNexus/Security/Attestation/AttestationService.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>

#include <array>

using nexus::security::AttestationChallenge;
using nexus::security::AttestationEvidence;
using nexus::security::AttestationFailure;
using nexus::security::AttestationPurpose;
using nexus::security::AttestationService;
using nexus::security::AttestationVerdict;
using nexus::security::Digest;
using nexus::security::LinuxAttestationProfile;
using nexus::security::NodeId;
using nexus::security::challenge_digest;
using nexus::security::eligibility_attestation_context;
using nexus::security::final_readiness_attestation_context;

namespace {

template <std::size_t N>
std::array<uint8_t, N> patterned(uint8_t seed) {
    std::array<uint8_t, N> out{};
    for (std::size_t i = 0; i < N; ++i) {
        out[i] = static_cast<uint8_t>(seed + i);
    }
    return out;
}

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

Digest final_context(uint8_t plan_seed, uint32_t attempt, uint8_t set_seed) {
    return final_readiness_attestation_context(network(0x01), 5, patterned<32>(plan_seed),
                                               attempt, patterned<32>(set_seed), node(0x21), 1);
}

/// An evidence bundle that answers the pending challenge's digest, so any
/// refusal below it is the purpose or context check, never a nonce miss.
AttestationEvidence answering(const AttestationChallenge& challenge) {
    AttestationEvidence evidence;
    evidence.network_id = challenge.network_id;
    evidence.challenge_digest = challenge_digest(challenge);
    evidence.node_id = challenge.node_id;
    evidence.incarnation = challenge.incarnation;
    evidence.epoch = challenge.epoch;
    evidence.security_ruleset = challenge.security_ruleset;
    evidence.consensus_ruleset = challenge.consensus_ruleset;
    evidence.profile_id = challenge.profile_id;
    evidence.profile_ruleset = challenge.profile_ruleset;
    evidence.purpose = challenge.purpose;
    evidence.context_digest = challenge.context_digest;
    return evidence;
}

// A fully pinned profile, so the verifier reaches the purpose and context
// checks instead of refusing at readiness.
LinuxAttestationProfile pinned_profile() {
    LinuxAttestationProfile profile;
    profile.profile_version = 1;
    profile.snp.require_debug_disabled = true;
    profile.snp.require_no_migration_agent = true;
    profile.vmpl_policy = nexus::security::VmplPolicy::RequireVmpl0;
    profile.snp.min_tcb = {2, 0, 6, 55};
    profile.snp.expected_measurement_hex = "aa11";
    profile.required_ak_spki_b64 = "QUsx";
    profile.ima_policy_digest = patterned<32>(0x60);
    profile.enforce_ima_policy = true;
    profile.approved_binary_sha256 = {"01ab"};
    profile.require_no_new_privs = true;
    profile.require_seccomp = true;
    profile.security_ruleset = nexus::security::constants::kSecurityRulesetVersion;
    return profile;
}

struct ContextBinding : ::testing::Test {
    AttestationService service{network(0x01), pinned_profile()};

    std::optional<AttestationChallenge> final_challenge(const Digest& context) {
        return service.create_challenge(node(0x21), key(0x22), 1, 5,
                                        AttestationPurpose::FinalEpochReadiness, context);
    }
};

// The purpose and context sit inside the challenge digest, which is the
// quote's nonce input: two contexts can never produce one quote binding.
TEST_F(ContextBinding, PurposeAndContextEnterTheChallengeDigest) {
    AttestationChallenge challenge;
    challenge.nonce = patterned<32>(0x10);
    const Digest eligibility = challenge_digest(challenge);

    challenge.purpose = AttestationPurpose::FinalEpochReadiness;
    challenge.context_digest = final_context(0x50, 0, 0x60);
    const Digest bound = challenge_digest(challenge);
    EXPECT_NE(bound, eligibility);

    challenge.context_digest = final_context(0x51, 0, 0x60);
    EXPECT_NE(challenge_digest(challenge), bound);
}

// Every input the architecture names changes the final-readiness context.
TEST_F(ContextBinding, EveryContextInputChangesTheDigest) {
    const Digest base = final_context(0x50, 0, 0x60);
    EXPECT_NE(final_context(0x51, 0, 0x60), base);  // another plan
    EXPECT_NE(final_context(0x50, 1, 0x60), base);  // another attempt
    EXPECT_NE(final_context(0x50, 0, 0x61), base);  // another selected set
    // Purpose separates the two context families even over equal fields.
    EXPECT_NE(eligibility_attestation_context(network(0x01), 5, node(0x21), 1), base);
}

// There is no unbound final challenge, and no caller-chosen eligibility
// context to relabel one with.
TEST_F(ContextBinding, TheServiceIssuesNoUnboundOrMislabeledChallenge) {
    EXPECT_FALSE(final_challenge(Digest{}).has_value());
    EXPECT_FALSE(service
                     .create_challenge(node(0x21), key(0x22), 1, 5,
                                       AttestationPurpose::Eligibility, final_context(0x50, 0, 0x60))
                     .has_value());

    const auto ordinary = service.create_challenge(node(0x21), key(0x22), 1, 5,
                                                   AttestationPurpose::Eligibility);
    ASSERT_TRUE(ordinary.has_value());
    EXPECT_EQ(ordinary->context_digest,
              eligibility_attestation_context(network(0x01), 5, node(0x21), 1));
}

// Evidence built for plan A, attempt 0, or one selected set cannot answer a
// challenge bound to plan B, attempt 1, or another set — even when it copies
// the live challenge digest byte for byte.
TEST_F(ContextBinding, EvidenceForOneContextAnswersNoOther) {
    const struct {
        Digest evidence_context;
        const char* what;
    } cases[] = {
        {final_context(0x51, 0, 0x60), "another plan"},
        {final_context(0x50, 1, 0x60), "another attempt"},
        {final_context(0x50, 0, 0x61), "another selected set"},
    };
    for (const auto& c : cases) {
        const auto challenge = final_challenge(final_context(0x50, 0, 0x60));
        ASSERT_TRUE(challenge.has_value());
        AttestationEvidence evidence = answering(*challenge);
        evidence.context_digest = c.evidence_context;
        const AttestationVerdict verdict = service.receive_evidence(evidence);
        EXPECT_FALSE(verdict.passed) << c.what;
        EXPECT_EQ(verdict.failure, AttestationFailure::ContextMismatch) << c.what;
    }
}

// Ordinary eligibility evidence cannot satisfy final readiness.
TEST_F(ContextBinding, EligibilityEvidenceCannotAnswerFinalReadiness) {
    const auto challenge = final_challenge(final_context(0x50, 0, 0x60));
    ASSERT_TRUE(challenge.has_value());
    AttestationEvidence evidence = answering(*challenge);
    evidence.purpose = AttestationPurpose::Eligibility;
    evidence.context_digest = eligibility_attestation_context(network(0x01), 5, node(0x21), 1);
    const AttestationVerdict verdict = service.receive_evidence(evidence);
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::PurposeMismatch);
}

// Final-readiness evidence cannot be relabelled as ordinary eligibility.
TEST_F(ContextBinding, FinalEvidenceCannotAnswerEligibility) {
    const auto challenge = service.create_challenge(node(0x21), key(0x22), 1, 5,
                                                    AttestationPurpose::Eligibility);
    ASSERT_TRUE(challenge.has_value());
    AttestationEvidence evidence = answering(*challenge);
    evidence.purpose = AttestationPurpose::FinalEpochReadiness;
    evidence.context_digest = final_context(0x50, 0, 0x60);
    const AttestationVerdict verdict = service.receive_evidence(evidence);
    EXPECT_FALSE(verdict.passed);
    EXPECT_EQ(verdict.failure, AttestationFailure::PurposeMismatch);
}

}  // namespace
