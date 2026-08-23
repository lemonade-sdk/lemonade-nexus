#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Policy/SecurityRuleset.hpp>

#include <gtest/gtest.h>

namespace constants = nexus::security::constants;

namespace {

struct QuorumRow {
    std::size_t n;
    std::size_t faults;
    std::size_t quorum;
    std::size_t authority;
};

// The exact tables from Security Architecture Final Draft 1.0, sections 9.2
// and 9.3.
constexpr QuorumRow kRows[] = {
    {5, 1, 4, 5},   {6, 1, 5, 5},   {7, 2, 5, 5},    {8, 2, 6, 6},
    {9, 2, 7, 7},   {10, 3, 7, 7},  {13, 4, 9, 9},   {16, 5, 11, 11},
    {19, 6, 13, 13}, {22, 7, 15, 15}, {25, 8, 17, 17}, {28, 9, 19, 19},
    {31, 10, 21, 21},
};

TEST(Quorum, MatchesArchitectureTables) {
    for (const auto& row : kRows) {
        EXPECT_EQ(constants::max_byzantine_faults(row.n), row.faults) << "n=" << row.n;
        EXPECT_EQ(constants::consensus_quorum(row.n), row.quorum) << "n=" << row.n;
        EXPECT_EQ(constants::authority_threshold(row.n), row.authority) << "n=" << row.n;
    }
}

TEST(Quorum, FaultFormulaAcrossSmallPopulations) {
    for (std::size_t n = 1; n <= 100; ++n) {
        const std::size_t f = constants::max_byzantine_faults(n);
        EXPECT_EQ(f, (n - 1) / 3) << "n=" << n;
        // Safety: a quorum always contains more than two thirds of the nodes,
        // so two quorums always intersect in at least one honest node.
        EXPECT_GT(2 * constants::consensus_quorum(n), n + f) << "n=" << n;
    }
}

TEST(Quorum, ZeroPopulationDoesNotWrap) {
    EXPECT_EQ(constants::max_byzantine_faults(0), 0u);
    EXPECT_EQ(constants::consensus_quorum(0), 0u);
    EXPECT_EQ(constants::authority_threshold(0), constants::kBootstrapThreshold);
}

TEST(Quorum, AuthorityThresholdNeverBelowBootstrap) {
    for (std::size_t n = 0; n <= 200; ++n) {
        EXPECT_GE(constants::authority_threshold(n), constants::kBootstrapThreshold) << "n=" << n;
        EXPECT_GE(constants::authority_threshold(n), constants::consensus_quorum(n)) << "n=" << n;
    }
}

TEST(Quorum, RulesetMirrorsCompiledConstants) {
    const auto ruleset = nexus::security::compiled_ruleset();
    EXPECT_EQ(ruleset.security_version, constants::kSecurityRulesetVersion);
    EXPECT_EQ(ruleset.consensus_version, constants::kConsensusRulesetVersion);
    for (std::size_t n = 0; n <= 40; ++n) {
        EXPECT_EQ(ruleset.max_byzantine_faults(n), constants::max_byzantine_faults(n));
        EXPECT_EQ(ruleset.consensus_quorum(n), constants::consensus_quorum(n));
        EXPECT_EQ(ruleset.authority_threshold(n), constants::authority_threshold(n));
        EXPECT_EQ(ruleset.tier1_target_count(n), constants::tier1_target_count(n));
    }
}

}  // namespace
