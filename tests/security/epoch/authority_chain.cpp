// The verified epoch authority chain: Genesis -> Epoch 1 -> handoff -> Epoch 2.
//
// Real keys, real signatures, real three-chain proofs. Every rejection case
// the walk must fail closed on: gaps, reorders, broken linkage, forged or
// self-certified proofs, reused keys, and tampered records.

#include <LemonadeNexus/Security/Epoch/AuthorityChain.hpp>
#include <LemonadeNexus/Security/Epoch/Tier1Set.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include "support/committee.hpp"

using namespace nexus::security;
using committee_test::Committee;
namespace constants = nexus::security::constants;

namespace {

NetworkId test_network() {
    NetworkId id{};
    id.fill(0x77);
    return id;
}

struct GenesisAnchor {
    nexus::crypto::Ed25519Keypair keypair{};
    BootstrapCertificate certificate;
};

/// A Genesis-signed certificate over one committee, exactly as the one-shot
/// authority would issue it.
GenesisAnchor make_genesis(const Committee& founders) {
    GenesisAnchor anchor;
    crypto_sign_keypair(anchor.keypair.public_key.data(), anchor.keypair.private_key.data());

    BootstrapCertificate& c = anchor.certificate;
    c.network_id = founders.network;
    c.epoch = 1;
    c.tier1_set_digest = Tier1Set::from_nodes(founders.members)->digest();
    c.authority_threshold = constants::authority_threshold(founders.members.size());
    c.authority_public_key.fill(0x91);
    c.dkg_transcript_digest.fill(0xD1);
    c.attestation_root.fill(0xA1);
    c.founding_eligibility_digest.fill(0xE1);
    std::map<NodeId, nexus::crypto::Ed25519PublicKey> keys;
    for (const auto& node : founders.members) {
        keys[node] = founders.pubs.at(node);
    }
    c.vote_key_set_digest = vote_key_set_digest(keys);
    c.security_ruleset = constants::kSecurityRulesetVersion;
    c.consensus_ruleset = constants::kConsensusRulesetVersion;
    const Digest digest = bootstrap_certificate_signing_digest(c);
    crypto_sign_detached(c.genesis_signature.data(), nullptr, digest.data(), digest.size(),
                         anchor.keypair.private_key.data());
    return anchor;
}

std::vector<std::pair<NodeId, nexus::crypto::Ed25519PublicKey>> listing(const Committee& c) {
    std::vector<std::pair<NodeId, nexus::crypto::Ed25519PublicKey>> out;
    for (const auto& node : c.members) {
        out.emplace_back(node, c.pubs.at(node));
    }
    return out;
}

/// The finalized handoff from `previous`'s epoch to `next`'s, with the proof
/// signed by `previous` — the only committee whose signatures mean anything.
EpochHandoff handoff_between(const Committee& next, const Digest& previous_anchor) {
    EpochHandoff handoff;
    handoff.network_id = next.network;
    handoff.from_epoch = next.epoch - 1;
    handoff.to_epoch = next.epoch;
    handoff.plan_digest.fill(static_cast<uint8_t>(0x30 + next.epoch));
    handoff.previous_anchor = previous_anchor;
    handoff.members = next.members;
    for (const auto& node : next.members) {
        handoff.incarnations[node] = 1;
        handoff.vote_keys[node] = next.pubs.at(node);
    }
    handoff.group_public_key.fill(static_cast<uint8_t>(0x90 + next.epoch));
    handoff.dkg_transcript_digest.fill(static_cast<uint8_t>(0xD0 + next.epoch));
    handoff.key_generation = next.epoch;
    handoff.attestation_root.fill(static_cast<uint8_t>(0xA0 + next.epoch));
    handoff.security_ruleset = constants::kSecurityRulesetVersion;
    handoff.consensus_ruleset = constants::kConsensusRulesetVersion;
    return handoff;
}

struct AuthorityChainTest : ::testing::Test {
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        epoch_one = std::make_unique<Committee>(5, 1, test_network(), 1);
        epoch_two = std::make_unique<Committee>(5, 2, test_network(), 3);
        epoch_three = std::make_unique<Committee>(7, 3, test_network(), 2);
        genesis = make_genesis(*epoch_one);
        auto base = verify_epoch_one_authority(genesis.certificate, genesis.keypair.public_key,
                                               listing(*epoch_one));
        ASSERT_TRUE(base.has_value());
        one = *base;
    }

    [[nodiscard]] HandoffChainFailure refusal(const VerifiedEpochAuthority& from,
                                              const EpochHandoff& handoff,
                                              const CommitProof& proof) const {
        const auto result = advance_epoch_authority(from, handoff, proof);
        const auto* failure = std::get_if<HandoffChainFailure>(&result);
        return failure != nullptr ? *failure : HandoffChainFailure::None;
    }

    std::unique_ptr<Committee> epoch_one;
    std::unique_ptr<Committee> epoch_two;
    std::unique_ptr<Committee> epoch_three;
    GenesisAnchor genesis;
    VerifiedEpochAuthority one;
};

TEST_F(AuthorityChainTest, EpochOneDerivesOnlyFromThePinnedCertificate) {
    EXPECT_EQ(one.epoch, 1u);
    EXPECT_EQ(one.members, epoch_one->members);
    EXPECT_EQ(one.consensus_quorum, constants::consensus_quorum(5));
    EXPECT_EQ(one.anchor_digest, bootstrap_certificate_signing_digest(genesis.certificate));
    EXPECT_EQ(one.previous_anchor, Digest{});

    // A listing that differs from what Genesis signed proves nothing.
    auto wrong_member = listing(*epoch_one);
    wrong_member[0].first.bytes.fill(0xEE);
    EXPECT_FALSE(verify_epoch_one_authority(genesis.certificate, genesis.keypair.public_key,
                                            wrong_member)
                     .has_value());
    auto wrong_key = listing(*epoch_one);
    wrong_key[0].second[0] ^= 0x01;
    EXPECT_FALSE(verify_epoch_one_authority(genesis.certificate, genesis.keypair.public_key,
                                            wrong_key)
                     .has_value());

    // A tampered certificate dies on the pinned signature.
    auto tampered = genesis.certificate;
    tampered.authority_threshold -= 1;
    EXPECT_FALSE(
        verify_epoch_one_authority(tampered, genesis.keypair.public_key, listing(*epoch_one))
            .has_value());

    // The wrong pinned key verifies nothing at all.
    nexus::crypto::Ed25519PublicKey other{};
    other.fill(0x55);
    EXPECT_FALSE(
        verify_epoch_one_authority(genesis.certificate, other, listing(*epoch_one)).has_value());
}

TEST_F(AuthorityChainTest, TheChainAdvancesOneVerifiedLinkAtATime) {
    const auto link_two = handoff_between(*epoch_two, one.anchor_digest);
    const auto proof_two = epoch_one->prove(epoch_handoff_digest(link_two));
    const auto advanced = advance_epoch_authority(one, link_two, proof_two);
    const auto* two = std::get_if<VerifiedEpochAuthority>(&advanced);
    ASSERT_NE(two, nullptr);
    EXPECT_EQ(two->epoch, 2u);
    EXPECT_EQ(two->members, epoch_two->members);
    EXPECT_EQ(two->previous_anchor, one.anchor_digest);
    EXPECT_EQ(two->anchor_digest, epoch_handoff_digest(link_two));

    // And on to epoch 3, with a larger committee and the new quorum math.
    const auto link_three = handoff_between(*epoch_three, two->anchor_digest);
    const auto proof_three = epoch_two->prove(epoch_handoff_digest(link_three));
    const auto again = advance_epoch_authority(*two, link_three, proof_three);
    const auto* three = std::get_if<VerifiedEpochAuthority>(&again);
    ASSERT_NE(three, nullptr);
    EXPECT_EQ(three->epoch, 3u);
    EXPECT_EQ(three->consensus_quorum, constants::consensus_quorum(7));
    EXPECT_EQ(three->authority_threshold, constants::authority_threshold(7));

    // Replaying the first link against the advanced authority is a reorder.
    EXPECT_EQ(refusal(*three, link_two, proof_two), HandoffChainFailure::WrongEpochs);
}

TEST_F(AuthorityChainTest, EveryBrokenLinkIsRefusedByName) {
    const auto link = handoff_between(*epoch_two, one.anchor_digest);
    const auto proof = epoch_one->prove(epoch_handoff_digest(link));

    // A gap: a link that skips ahead of the anchor.
    auto gap = handoff_between(*epoch_three, one.anchor_digest);
    gap.from_epoch = 2;
    gap.to_epoch = 3;
    EXPECT_EQ(refusal(one, gap, epoch_one->prove(epoch_handoff_digest(gap))),
              HandoffChainFailure::WrongEpochs);

    // Another network entirely.
    auto foreign = link;
    foreign.network_id[0] ^= 0x01;
    EXPECT_EQ(refusal(one, foreign, epoch_one->prove(epoch_handoff_digest(foreign))),
              HandoffChainFailure::WrongNetwork);

    // Linkage: the predecessor anchor must match exactly.
    auto unchained = link;
    unchained.previous_anchor[0] ^= 0x01;
    EXPECT_EQ(refusal(one, unchained, epoch_one->prove(epoch_handoff_digest(unchained))),
              HandoffChainFailure::LinkageBroken);

    // A fork: same transition, different content, and the honest proof no
    // longer matches the mutated record.
    auto forked = link;
    forked.group_public_key[0] ^= 0x01;
    EXPECT_EQ(refusal(one, forked, proof), HandoffChainFailure::ProofInvalid);

    // Self-certification: a proof signed under the keys the handoff itself
    // introduces verifies under nothing the previous epoch froze.
    EXPECT_EQ(refusal(one, link, epoch_two->prove(epoch_handoff_digest(link))),
              HandoffChainFailure::ProofInvalid);

    // Key hygiene: an introduced vote key repeating a previous epoch's, and a
    // surviving group key, are both one-epoch-lifetime violations.
    auto reused_vote_key = link;
    reused_vote_key.vote_keys[epoch_two->members.front()] =
        one.vote_keys.at(epoch_one->members.front());
    EXPECT_EQ(
        refusal(one, reused_vote_key, epoch_one->prove(epoch_handoff_digest(reused_vote_key))),
        HandoffChainFailure::KeyReuse);
    auto reused_group = link;
    reused_group.group_public_key = one.group_public_key;
    EXPECT_EQ(refusal(one, reused_group, epoch_one->prove(epoch_handoff_digest(reused_group))),
              HandoffChainFailure::KeyReuse);

    // Key generation must be the target epoch.
    auto wrong_generation = link;
    wrong_generation.key_generation = 9;
    EXPECT_EQ(
        refusal(one, wrong_generation, epoch_one->prove(epoch_handoff_digest(wrong_generation))),
        HandoffChainFailure::KeyGenerationInvalid);

    // Membership listings must cover the set exactly.
    auto missing_key = link;
    missing_key.vote_keys.erase(epoch_two->members.front());
    EXPECT_EQ(refusal(one, missing_key, epoch_one->prove(epoch_handoff_digest(missing_key))),
              HandoffChainFailure::MembershipInvalid);

    // Another ruleset is another protocol; this binary refuses to walk it.
    auto other_rules = link;
    other_rules.security_ruleset += 1;
    EXPECT_EQ(refusal(one, other_rules, epoch_one->prove(epoch_handoff_digest(other_rules))),
              HandoffChainFailure::RulesetMismatch);

    // Positive control after all of it: the untouched link still advances.
    EXPECT_TRUE(std::holds_alternative<VerifiedEpochAuthority>(
        advance_epoch_authority(one, link, proof)));
}

TEST_F(AuthorityChainTest, TheAnchorRecordBindsItsOwnDigest) {
    const Digest digest = verified_epoch_authority_digest(one);
    auto mutated = one;
    mutated.consensus_quorum -= 1;
    EXPECT_NE(verified_epoch_authority_digest(mutated), digest);
    mutated = one;
    mutated.anchor_digest[0] ^= 0x01;
    EXPECT_NE(verified_epoch_authority_digest(mutated), digest);
    mutated = one;
    mutated.vote_keys.begin()->second[0] ^= 0x01;
    EXPECT_NE(verified_epoch_authority_digest(mutated), digest);
}

}  // namespace
