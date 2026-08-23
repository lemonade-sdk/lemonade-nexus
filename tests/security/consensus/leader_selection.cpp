#include <LemonadeNexus/Security/Consensus/LeaderSelection.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <vector>

using nexus::security::Digest;
using nexus::security::LeaderSelection;
using nexus::security::NodeId;

namespace {

[[nodiscard]] Digest filled_digest(uint8_t value) {
    Digest digest{};
    digest.fill(value);
    return digest;
}

[[nodiscard]] std::vector<NodeId> make_members(std::size_t count) {
    std::vector<NodeId> members;
    for (std::size_t i = 0; i < count; ++i) {
        NodeId node{};
        node.bytes.fill(static_cast<uint8_t>(i + 1));
        members.push_back(node);
    }
    return members;
}

TEST(LeaderSelection, OrderIsDeterministic) {
    const auto members = make_members(10);
    const auto checkpoint = filled_digest(0x55);
    EXPECT_EQ(LeaderSelection::order(members, checkpoint, 3),
              LeaderSelection::order(members, checkpoint, 3));
}

TEST(LeaderSelection, OrderIsIndependentOfInputOrder) {
    const auto members = make_members(10);
    auto reversed = members;
    std::reverse(reversed.begin(), reversed.end());
    auto rotated = members;
    std::rotate(rotated.begin(), rotated.begin() + 4, rotated.end());

    const auto checkpoint = filled_digest(0x55);
    const auto expected = LeaderSelection::order(members, checkpoint, 3);
    EXPECT_EQ(LeaderSelection::order(reversed, checkpoint, 3), expected);
    EXPECT_EQ(LeaderSelection::order(rotated, checkpoint, 3), expected);
}

TEST(LeaderSelection, OrderIsAPermutationOfTheMembers) {
    const auto members = make_members(10);
    auto result = LeaderSelection::order(members, filled_digest(0x55), 3);
    ASSERT_EQ(result.size(), members.size());

    auto sorted_members = members;
    std::sort(sorted_members.begin(), sorted_members.end());
    std::sort(result.begin(), result.end());
    EXPECT_EQ(result, sorted_members);
}

TEST(LeaderSelection, DifferentCheckpointsGiveDifferentOrders) {
    const auto members = make_members(10);
    EXPECT_NE(LeaderSelection::order(members, filled_digest(0x55), 3),
              LeaderSelection::order(members, filled_digest(0x56), 3));
}

TEST(LeaderSelection, DifferentEpochsGiveDifferentOrders) {
    const auto members = make_members(10);
    const auto checkpoint = filled_digest(0x55);
    EXPECT_NE(LeaderSelection::order(members, checkpoint, 3),
              LeaderSelection::order(members, checkpoint, 4));
}

TEST(LeaderSelection, SingleMemberIsAlwaysLeader) {
    const auto members = make_members(1);
    const auto order = LeaderSelection::order(members, filled_digest(0x55), 3);
    ASSERT_EQ(order.size(), 1u);
    for (uint64_t view = 0; view < 5; ++view) {
        EXPECT_EQ(LeaderSelection::leader(order, view), members[0]);
    }
}

TEST(LeaderSelection, LeaderRotatesAndWrapsAround) {
    const auto members = make_members(7);
    const auto order = LeaderSelection::order(members, filled_digest(0x55), 3);
    ASSERT_EQ(order.size(), 7u);

    for (uint64_t view = 0; view < 21; ++view) {
        EXPECT_EQ(LeaderSelection::leader(order, view), order[view % 7]) << "view=" << view;
    }
    // A far-future view still maps into the order.
    EXPECT_EQ(LeaderSelection::leader(order, 1000000007ULL), order[1000000007ULL % 7]);
}

TEST(LeaderSelection, EmptyOrderThrows) {
    EXPECT_THROW((void)LeaderSelection::leader({}, 0), std::invalid_argument);
}

}  // namespace
