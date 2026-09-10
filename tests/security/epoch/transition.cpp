#include <LemonadeNexus/Security/Epoch/EpochAuthority.hpp>
#include <LemonadeNexus/Security/Epoch/EpochTransition.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <functional>
#include <vector>

namespace constants = nexus::security::constants;

using nexus::crypto::Ed25519PublicKey;
using nexus::security::Digest;
using nexus::security::epoch_authority_digest;
using nexus::security::EpochAuthority;
using nexus::security::EpochTransition;
using nexus::security::EpochTransitionFailure;
using nexus::security::EpochTransitionPhase;
using nexus::security::NodeId;
using nexus::security::ready_for_activation;

namespace {

NodeId make_node(uint8_t value) {
    NodeId node;
    node.bytes.fill(value);
    return node;
}

Digest make_digest(uint8_t value) {
    Digest digest{};
    digest.fill(value);
    return digest;
}

EpochTransition make_ready_transition() {
    EpochTransition transition;
    transition.from_epoch = 41;
    transition.to_epoch = 42;
    transition.phase = EpochTransitionPhase::Ready;
    for (uint8_t i = 1; i <= constants::kMinActiveTier1; ++i) {
        transition.selected_members.push_back(make_node(i));
    }
    transition.participant_set_digest = make_digest(0x11);
    transition.attestation_root = make_digest(0x22);
    transition.dkg_transcript_digest = make_digest(0x33);
    transition.next_authority_key.fill(0x44);
    transition.next_consensus_quorum = 4;
    transition.next_authority_threshold = 5;
    transition.failure = EpochTransitionFailure::None;
    return transition;
}

TEST(EpochTransitionTest, CompleteReadyTransitionActivates) {
    EXPECT_TRUE(ready_for_activation(make_ready_transition()));
}

TEST(EpochTransitionTest, DefaultTransitionDoesNotActivate) {
    EXPECT_FALSE(ready_for_activation(EpochTransition{}));
}

TEST(EpochTransitionTest, EveryNonReadyPhaseIsRejected) {
    constexpr EpochTransitionPhase kOtherPhases[] = {
        EpochTransitionPhase::Selecting,
        EpochTransitionPhase::Attesting,
        EpochTransitionPhase::GeneratingVoteKeys,
        EpochTransitionPhase::GeneratingAuthorityKey,
        EpochTransitionPhase::Finalizing,
        EpochTransitionPhase::Aborted,
    };
    for (const auto phase : kOtherPhases) {
        EpochTransition transition = make_ready_transition();
        transition.phase = phase;
        EXPECT_FALSE(ready_for_activation(transition))
            << "phase=" << static_cast<int>(phase);
    }
}

TEST(EpochTransitionTest, EveryRecordedFailureIsRejected) {
    constexpr EpochTransitionFailure kFailures[] = {
        EpochTransitionFailure::EligiblePoolBelowMinimum,
        EpochTransitionFailure::FinalAttestationFailed,
        EpochTransitionFailure::VoteKeyMissing,
        EpochTransitionFailure::DkgFailed,
        EpochTransitionFailure::ThresholdUnreachable,
        EpochTransitionFailure::HandoffTimeout,
        EpochTransitionFailure::AuthorizationMissing,
    };
    for (const auto failure : kFailures) {
        EpochTransition transition = make_ready_transition();
        transition.failure = failure;
        EXPECT_FALSE(ready_for_activation(transition))
            << "failure=" << static_cast<int>(failure);
    }
}

TEST(EpochTransitionTest, EveryPartialStateIsRejected) {
    struct Disqualifier {
        const char* name;
        std::function<void(EpochTransition&)> apply;
    };
    const Disqualifier kDisqualifiers[] = {
        {"one member below the minimum",
         [](EpochTransition& t) { t.selected_members.pop_back(); }},
        {"no members",
         [](EpochTransition& t) { t.selected_members.clear(); }},
        {"all-zero next authority key",
         [](EpochTransition& t) { t.next_authority_key.fill(0); }},
        {"all-zero dkg transcript digest",
         [](EpochTransition& t) { t.dkg_transcript_digest.fill(0); }},
        {"all-zero participant set digest",
         [](EpochTransition& t) { t.participant_set_digest.fill(0); }},
    };
    for (const auto& disqualifier : kDisqualifiers) {
        EpochTransition transition = make_ready_transition();
        disqualifier.apply(transition);
        EXPECT_FALSE(ready_for_activation(transition)) << disqualifier.name;
    }
}

TEST(EpochTransitionTest, ExactMinimumMemberCountIsTheBoundary) {
    EpochTransition transition = make_ready_transition();
    ASSERT_EQ(transition.selected_members.size(), constants::kMinActiveTier1);
    EXPECT_TRUE(ready_for_activation(transition));

    transition.selected_members.pop_back();
    EXPECT_FALSE(ready_for_activation(transition));
}

EpochAuthority make_authority() {
    EpochAuthority authority;
    authority.network_id = make_digest(0x01);
    authority.epoch = 42;
    authority.key_generation = 42;
    authority.security_ruleset = constants::kSecurityRulesetVersion;
    authority.consensus_ruleset = constants::kConsensusRulesetVersion;
    authority.tier1_set_digest = make_digest(0x02);
    authority.consensus_quorum = 4;
    authority.authority_threshold = 5;
    authority.frost_ciphersuite = "FROST-ED25519-SHA512-v1";
    authority.group_public_key.fill(0x03);
    authority.dkg_transcript_digest = make_digest(0x04);
    authority.attestation_root = make_digest(0x05);
    authority.previous_checkpoint = make_digest(0x06);
    return authority;
}

TEST(EpochAuthorityTest, DigestIsDeterministic) {
    EXPECT_EQ(epoch_authority_digest(make_authority()),
              epoch_authority_digest(make_authority()));
}

TEST(EpochAuthorityTest, DigestCoversEveryField) {
    struct Mutation {
        const char* name;
        std::function<void(EpochAuthority&)> apply;
    };
    const Mutation kMutations[] = {
        {"network_id", [](EpochAuthority& a) { a.network_id.fill(0xFF); }},
        {"epoch", [](EpochAuthority& a) { a.epoch = 43; }},
        {"key_generation", [](EpochAuthority& a) { a.key_generation = 43; }},
        {"security_ruleset", [](EpochAuthority& a) { a.security_ruleset += 1; }},
        {"consensus_ruleset", [](EpochAuthority& a) { a.consensus_ruleset += 1; }},
        {"tier1_set_digest", [](EpochAuthority& a) { a.tier1_set_digest.fill(0xFF); }},
        {"consensus_quorum", [](EpochAuthority& a) { a.consensus_quorum = 5; }},
        {"authority_threshold", [](EpochAuthority& a) { a.authority_threshold = 6; }},
        {"frost_ciphersuite", [](EpochAuthority& a) { a.frost_ciphersuite = "other"; }},
        {"group_public_key", [](EpochAuthority& a) { a.group_public_key.fill(0xFF); }},
        {"dkg_transcript_digest",
         [](EpochAuthority& a) { a.dkg_transcript_digest.fill(0xFF); }},
        {"attestation_root", [](EpochAuthority& a) { a.attestation_root.fill(0xFF); }},
        {"previous_checkpoint",
         [](EpochAuthority& a) { a.previous_checkpoint.fill(0xFF); }},
    };

    const Digest base = epoch_authority_digest(make_authority());
    for (const auto& mutation : kMutations) {
        EpochAuthority mutated = make_authority();
        mutation.apply(mutated);
        EXPECT_NE(epoch_authority_digest(mutated), base) << mutation.name;
    }
}

TEST(EpochAuthorityTest, SwappedDigestFieldsChangeTheDigest) {
    // Two 32-byte fields with exchanged contents must not collide: the
    // canonical encoding fixes each field to its position.
    EpochAuthority swapped = make_authority();
    std::swap(swapped.tier1_set_digest, swapped.dkg_transcript_digest);
    EXPECT_NE(epoch_authority_digest(swapped), epoch_authority_digest(make_authority()));
}

}  // namespace
