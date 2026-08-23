#include <LemonadeNexus/Security/Epoch/EpochState.hpp>
#include <LemonadeNexus/Security/Epoch/Tier1Set.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

namespace constants = nexus::security::constants;

using nexus::crypto::Ed25519PublicKey;
using nexus::security::Digest;
using nexus::security::make_epoch_state;
using nexus::security::NetworkId;
using nexus::security::NodeId;
using nexus::security::Tier1Set;

namespace {

NodeId make_node(uint8_t value) {
    NodeId node;
    node.bytes.fill(value);
    return node;
}

std::vector<NodeId> make_nodes(uint8_t count) {
    std::vector<NodeId> nodes;
    for (uint8_t i = 1; i <= count; ++i) {
        nodes.push_back(make_node(i));
    }
    return nodes;
}

TEST(Tier1SetTest, RejectsDuplicateNodes) {
    std::vector<NodeId> nodes = make_nodes(4);
    nodes.push_back(make_node(2));
    EXPECT_FALSE(Tier1Set::from_nodes(nodes).has_value());
}

TEST(Tier1SetTest, SortsMembersRegardlessOfInsertionOrder) {
    const std::vector<NodeId> forward = make_nodes(6);
    const std::vector<NodeId> reversed(forward.rbegin(), forward.rend());

    const auto set = Tier1Set::from_nodes(reversed);
    ASSERT_TRUE(set.has_value());
    EXPECT_EQ(set->members(), forward);
    EXPECT_EQ(set->size(), forward.size());
}

TEST(Tier1SetTest, ContainsExactMembersOnly) {
    const auto set = Tier1Set::from_nodes(make_nodes(5));
    ASSERT_TRUE(set.has_value());
    for (uint8_t i = 1; i <= 5; ++i) {
        EXPECT_TRUE(set->contains(make_node(i))) << "i=" << int{i};
    }
    EXPECT_FALSE(set->contains(make_node(0)));
    EXPECT_FALSE(set->contains(make_node(6)));
}

TEST(Tier1SetTest, EmptySetIsValidAndEmpty) {
    const auto empty = Tier1Set::from_nodes({});
    ASSERT_TRUE(empty.has_value());
    EXPECT_EQ(empty->size(), 0u);
    EXPECT_FALSE(empty->contains(make_node(1)));
}

TEST(Tier1SetTest, DigestIndependentOfInsertionOrder) {
    const std::vector<NodeId> forward = make_nodes(7);
    const std::vector<NodeId> reversed(forward.rbegin(), forward.rend());

    const auto set_a = Tier1Set::from_nodes(forward);
    const auto set_b = Tier1Set::from_nodes(reversed);
    ASSERT_TRUE(set_a.has_value());
    ASSERT_TRUE(set_b.has_value());
    EXPECT_EQ(set_a->digest(), set_b->digest());
}

TEST(Tier1SetTest, DigestChangesWhenMemberAddedOrRemoved) {
    const auto base = Tier1Set::from_nodes(make_nodes(6));
    const auto grown = Tier1Set::from_nodes(make_nodes(7));
    const auto shrunk = Tier1Set::from_nodes(make_nodes(5));
    ASSERT_TRUE(base.has_value());
    ASSERT_TRUE(grown.has_value());
    ASSERT_TRUE(shrunk.has_value());

    EXPECT_NE(base->digest(), grown->digest());
    EXPECT_NE(base->digest(), shrunk->digest());
    EXPECT_NE(grown->digest(), shrunk->digest());
}

TEST(Tier1SetTest, DigestChangesWhenMembershipDiffersAtSameSize) {
    std::vector<NodeId> other = make_nodes(5);
    other.back() = make_node(0x99);

    const auto set_a = Tier1Set::from_nodes(make_nodes(5));
    const auto set_b = Tier1Set::from_nodes(other);
    ASSERT_TRUE(set_a.has_value());
    ASSERT_TRUE(set_b.has_value());
    EXPECT_NE(set_a->digest(), set_b->digest());
}

struct ThresholdRow {
    uint8_t members;
    std::size_t quorum;
    std::size_t authority;
};

// The exact rows from Security Architecture Final Draft 1.0, sections 9.2
// and 9.3.
constexpr ThresholdRow kRows[] = {
    {5, 4, 5},
    {7, 5, 5},
    {10, 7, 7},
    {31, 21, 21},
};

TEST(EpochStateTest, ThresholdsComeFromFrozenMemberCount) {
    for (const auto& row : kRows) {
        auto set = Tier1Set::from_nodes(make_nodes(row.members));
        ASSERT_TRUE(set.has_value());
        const auto state = make_epoch_state(42, NetworkId{}, std::move(*set),
                                            Ed25519PublicKey{}, Digest{});
        EXPECT_EQ(state.consensus_quorum, row.quorum) << "members=" << int{row.members};
        EXPECT_EQ(state.authority_threshold, row.authority) << "members=" << int{row.members};
    }
}

TEST(EpochStateTest, ParticipantDigestMatchesTier1SetDigest) {
    auto set = Tier1Set::from_nodes(make_nodes(5));
    ASSERT_TRUE(set.has_value());
    const Digest expected = set->digest();

    const auto state = make_epoch_state(42, NetworkId{}, std::move(*set),
                                        Ed25519PublicKey{}, Digest{});
    EXPECT_EQ(state.participant_set_digest, expected);
    EXPECT_EQ(state.tier1_members.digest(), expected);
}

TEST(EpochStateTest, BindsInputsAndCompiledRulesets) {
    auto set = Tier1Set::from_nodes(make_nodes(5));
    ASSERT_TRUE(set.has_value());

    NetworkId network_id{};
    network_id.fill(0x11);
    Ed25519PublicKey authority_key{};
    authority_key.fill(0x22);
    Digest attestation_root{};
    attestation_root.fill(0x33);

    const auto state = make_epoch_state(42, network_id, std::move(*set),
                                        authority_key, attestation_root);
    EXPECT_EQ(state.id, 42u);
    EXPECT_EQ(state.network_id, network_id);
    EXPECT_EQ(state.authority_public_key, authority_key);
    EXPECT_EQ(state.attestation_root, attestation_root);
    EXPECT_EQ(state.security_ruleset, constants::kSecurityRulesetVersion);
    EXPECT_EQ(state.consensus_ruleset, constants::kConsensusRulesetVersion);
}

}  // namespace
