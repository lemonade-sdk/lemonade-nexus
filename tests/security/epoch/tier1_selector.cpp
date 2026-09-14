#include <LemonadeNexus/Security/Epoch/Tier1Selector.hpp>
#include <LemonadeNexus/Security/Epoch/Tier1Set.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <vector>

using nexus::crypto::Ed25519PublicKey;
using nexus::security::NodeId;
using nexus::security::Tier1Selector;
using nexus::security::Tier1Set;

namespace {

NodeId make_node(uint8_t value) {
    NodeId node;
    node.bytes.fill(value);
    return node;
}

Ed25519PublicKey make_key(uint8_t value) {
    Ed25519PublicKey key{};
    key.fill(value);
    return key;
}

std::vector<NodeId> make_nodes(uint8_t count) {
    std::vector<NodeId> nodes;
    for (uint8_t i = 1; i <= count; ++i) {
        nodes.push_back(make_node(i));
    }
    return nodes;
}

Tier1Set make_pool(uint8_t count) {
    auto pool = Tier1Set::from_nodes(make_nodes(count));
    EXPECT_TRUE(pool.has_value());
    return *pool;
}

constexpr uint8_t kPoolSize = 12;

TEST(Tier1Selector, RankIsDeterministicAcrossCalls) {
    const Tier1Set pool = make_pool(kPoolSize);
    const Ed25519PublicKey key = make_key(0xA1);

    const auto first = Tier1Selector::rank(pool, key, 7);
    const auto second = Tier1Selector::rank(pool, key, 7);
    EXPECT_EQ(first, second);
    EXPECT_EQ(first.size(), pool.size());
}

TEST(Tier1Selector, RankIndependentOfEligibleInsertionOrder) {
    std::vector<NodeId> forward = make_nodes(kPoolSize);
    std::vector<NodeId> reversed(forward.rbegin(), forward.rend());

    const auto pool_a = Tier1Set::from_nodes(forward);
    const auto pool_b = Tier1Set::from_nodes(reversed);
    ASSERT_TRUE(pool_a.has_value());
    ASSERT_TRUE(pool_b.has_value());

    const Ed25519PublicKey key = make_key(0xA1);
    EXPECT_EQ(Tier1Selector::rank(*pool_a, key, 7), Tier1Selector::rank(*pool_b, key, 7));
}

TEST(Tier1Selector, SelectClampsCountToPoolSize) {
    const Tier1Set pool = make_pool(kPoolSize);
    const Ed25519PublicKey key = make_key(0xA1);

    const auto all = Tier1Selector::select(pool, key, 7, pool.size() + 100);
    EXPECT_EQ(all, Tier1Selector::rank(pool, key, 7));
}

TEST(Tier1Selector, SelectZeroCountIsEmpty) {
    const Tier1Set pool = make_pool(kPoolSize);
    EXPECT_TRUE(Tier1Selector::select(pool, make_key(0xA1), 7, 0).empty());
}

TEST(Tier1Selector, EmptyPoolSelectsNothing) {
    const auto empty = Tier1Set::from_nodes({});
    ASSERT_TRUE(empty.has_value());
    EXPECT_TRUE(Tier1Selector::rank(*empty, make_key(0xA1), 7).empty());
    EXPECT_TRUE(Tier1Selector::select(*empty, make_key(0xA1), 7, 5).empty());
}

TEST(Tier1Selector, SelectIsStrictPrefixOfRank) {
    const Tier1Set pool = make_pool(kPoolSize);
    const Ed25519PublicKey key = make_key(0xA1);

    const auto ranked = Tier1Selector::rank(pool, key, 7);
    for (std::size_t count = 0; count <= pool.size(); ++count) {
        const auto selected = Tier1Selector::select(pool, key, 7, count);
        ASSERT_EQ(selected.size(), count);
        EXPECT_TRUE(std::equal(selected.begin(), selected.end(), ranked.begin()))
            << "count=" << count;
    }
}

TEST(Tier1Selector, FailedSelecteeIsReplacedByNextRankedCandidate) {
    // Architecture 8.5: when a selected node fails, the next hash-ranked
    // candidate takes its place. Scores depend only on the seed and the node,
    // so removing one node must not reorder the others.
    const Tier1Set pool = make_pool(kPoolSize);
    const Ed25519PublicKey key = make_key(0xA1);
    const std::size_t count = 5;

    const auto ranked = Tier1Selector::rank(pool, key, 7);
    for (std::size_t k = 0; k < count; ++k) {
        std::vector<NodeId> remaining = make_nodes(kPoolSize);
        std::erase(remaining, ranked[k]);
        const auto reduced = Tier1Set::from_nodes(remaining);
        ASSERT_TRUE(reduced.has_value());

        std::vector<NodeId> expected;
        for (std::size_t i = 0; i < count + 1; ++i) {
            if (i != k) {
                expected.push_back(ranked[i]);
            }
        }
        EXPECT_EQ(Tier1Selector::select(*reduced, key, 7, count), expected) << "k=" << k;
    }
}

TEST(Tier1Selector, DifferentGroupKeyChangesRanking) {
    const Tier1Set pool = make_pool(kPoolSize);
    EXPECT_NE(Tier1Selector::rank(pool, make_key(0xA1), 7),
              Tier1Selector::rank(pool, make_key(0xA2), 7));
}

TEST(Tier1Selector, DifferentNextEpochChangesRanking) {
    const Tier1Set pool = make_pool(kPoolSize);
    const Ed25519PublicKey key = make_key(0xA1);
    EXPECT_NE(Tier1Selector::rank(pool, key, 7), Tier1Selector::rank(pool, key, 8));
}

TEST(Tier1Selector, OutputHasNoDuplicates) {
    const Tier1Set pool = make_pool(kPoolSize);
    auto ranked = Tier1Selector::rank(pool, make_key(0xA1), 7);

    std::sort(ranked.begin(), ranked.end());
    EXPECT_EQ(std::adjacent_find(ranked.begin(), ranked.end()), ranked.end());
    EXPECT_EQ(ranked, pool.members());
}

}  // namespace
