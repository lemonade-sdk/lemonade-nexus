#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <functional>

using nexus::security::AttestationChallenge;
using nexus::security::AttestationEvidence;
using nexus::security::Digest;
using nexus::security::challenge_digest;
using nexus::security::evidence_signing_digest;

namespace {

template <std::size_t N>
std::array<uint8_t, N> patterned(uint8_t seed) {
    std::array<uint8_t, N> out{};
    for (std::size_t i = 0; i < N; ++i) {
        out[i] = static_cast<uint8_t>(seed + i);
    }
    return out;
}

AttestationChallenge base_challenge() {
    AttestationChallenge challenge;
    challenge.nonce = patterned<32>(0x10);
    challenge.node_id.bytes = patterned<32>(0x20);
    challenge.node_key = patterned<32>(0x30);
    challenge.incarnation = 7;
    challenge.epoch = 42;
    challenge.security_ruleset = 1;
    challenge.policy_digest = patterned<32>(0x40);
    return challenge;
}

AttestationEvidence base_evidence() {
    AttestationEvidence evidence;
    evidence.challenge_digest = challenge_digest(base_challenge());
    evidence.node_id.bytes = patterned<32>(0x20);
    evidence.incarnation = 7;
    evidence.security_ruleset = 1;
    evidence.consensus_ruleset = 1;
    evidence.epoch_vote_key = patterned<32>(0x50);
    evidence.platform.ima_log = "10 aa ima-ng sha256:bb /opt/nexus\n";
    evidence.platform.binary_path = "/opt/nexus";
    evidence.platform.binary_sha256 = "bb";
    return evidence;
}

struct ChallengeMutation {
    const char* name;
    std::function<void(AttestationChallenge&)> apply;
};

const ChallengeMutation kChallengeMutations[] = {
    {"nonce", [](AttestationChallenge& c) { c.nonce[0] ^= 1; }},
    {"node_id", [](AttestationChallenge& c) { c.node_id.bytes[0] ^= 1; }},
    {"node_key", [](AttestationChallenge& c) { c.node_key[0] ^= 1; }},
    {"incarnation", [](AttestationChallenge& c) { c.incarnation += 1; }},
    {"epoch", [](AttestationChallenge& c) { c.epoch += 1; }},
    {"security_ruleset", [](AttestationChallenge& c) { c.security_ruleset += 1; }},
    {"policy_digest", [](AttestationChallenge& c) { c.policy_digest[0] ^= 1; }},
};

struct EvidenceMutation {
    const char* name;
    std::function<void(AttestationEvidence&)> apply;
};

const EvidenceMutation kEvidenceMutations[] = {
    {"challenge_digest", [](AttestationEvidence& e) { e.challenge_digest[0] ^= 1; }},
    {"node_id", [](AttestationEvidence& e) { e.node_id.bytes[0] ^= 1; }},
    {"incarnation", [](AttestationEvidence& e) { e.incarnation += 1; }},
    {"security_ruleset", [](AttestationEvidence& e) { e.security_ruleset += 1; }},
    {"consensus_ruleset", [](AttestationEvidence& e) { e.consensus_ruleset += 1; }},
    {"epoch_vote_key", [](AttestationEvidence& e) { e.epoch_vote_key[0] ^= 1; }},
    {"platform.hcl_blob", [](AttestationEvidence& e) { e.platform.hcl_blob.push_back(1); }},
    {"platform.tpms_attest", [](AttestationEvidence& e) { e.platform.tpms_attest.push_back(1); }},
    {"platform.ima_log", [](AttestationEvidence& e) { e.platform.ima_log += "x"; }},
    {"platform.binary_sha256", [](AttestationEvidence& e) { e.platform.binary_sha256 = "cc"; }},
};

TEST(AttestationChallenge, DigestIsDeterministic) {
    EXPECT_EQ(challenge_digest(base_challenge()), challenge_digest(base_challenge()));
}

TEST(AttestationChallenge, EveryFieldChangesDigest) {
    const Digest base = challenge_digest(base_challenge());
    for (const auto& mutation : kChallengeMutations) {
        AttestationChallenge mutated = base_challenge();
        mutation.apply(mutated);
        EXPECT_NE(challenge_digest(mutated), base) << mutation.name;
    }
}

TEST(AttestationChallenge, IdenticalFieldsGiveIdenticalDigestAcrossInstances) {
    const AttestationChallenge left = base_challenge();
    AttestationChallenge right;
    right.nonce = left.nonce;
    right.node_id = left.node_id;
    right.node_key = left.node_key;
    right.incarnation = left.incarnation;
    right.epoch = left.epoch;
    right.security_ruleset = left.security_ruleset;
    right.policy_digest = left.policy_digest;
    EXPECT_EQ(challenge_digest(left), challenge_digest(right));
}

TEST(AttestationEvidence, SigningDigestIsDeterministic) {
    EXPECT_EQ(evidence_signing_digest(base_evidence()),
              evidence_signing_digest(base_evidence()));
}

TEST(AttestationEvidence, EveryFieldChangesSigningDigest) {
    const Digest base = evidence_signing_digest(base_evidence());
    for (const auto& mutation : kEvidenceMutations) {
        AttestationEvidence mutated = base_evidence();
        mutation.apply(mutated);
        EXPECT_NE(evidence_signing_digest(mutated), base) << mutation.name;
    }
}

TEST(AttestationEvidence, SignatureIsNotPartOfItsOwnPreimage) {
    AttestationEvidence with_signature = base_evidence();
    with_signature.identity_signature.fill(0xAB);
    EXPECT_EQ(evidence_signing_digest(with_signature),
              evidence_signing_digest(base_evidence()));
}

TEST(AttestationDigests, ChallengeAndEvidenceLabelsSeparateDigests) {
    // Both digests live in the same domain; the leading label must keep a
    // challenge preimage from ever colliding with an evidence preimage.
    EXPECT_NE(challenge_digest(base_challenge()),
              evidence_signing_digest(base_evidence()));
}

}  // namespace
