#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Policy/Tier1TargetPolicy.hpp>

#include <gtest/gtest.h>

#include <limits>

namespace constants = nexus::security::constants;
using nexus::security::tier1_target_outcome;

namespace {

struct TargetRow {
    std::size_t admitted;
    std::size_t target;
};

// Every boundary of the compiled step table from section 2.4.
constexpr TargetRow kBoundaries[] = {
    {0, 0},     {4, 0},     {5, 5},     {9, 5},     {10, 7},    {24, 7},
    {25, 10},   {99, 10},   {100, 13},  {249, 13},  {250, 16},  {499, 16},
    {500, 19},  {999, 19},  {1000, 22}, {2499, 22}, {2500, 25}, {4999, 25},
    {5000, 28}, {9999, 28}, {10000, 31},
};

TEST(Tier1Target, StepTableBoundaries) {
    for (const auto& row : kBoundaries) {
        EXPECT_EQ(constants::tier1_target_count(row.admitted), row.target)
            << "admitted=" << row.admitted;
    }
    EXPECT_EQ(constants::tier1_target_count(std::numeric_limits<std::size_t>::max()),
              constants::kMaxActiveTier1);
}

TEST(Tier1Target, TargetNeverExceedsMaximum) {
    for (std::size_t admitted = 0; admitted <= 20000; admitted += 7) {
        EXPECT_LE(constants::tier1_target_count(admitted), constants::kMaxActiveTier1);
    }
}

TEST(Tier1Target, FullPoolMeetsTarget) {
    const auto outcome = tier1_target_outcome(30, 15);
    EXPECT_EQ(outcome.desired, 10u);
    EXPECT_EQ(outcome.active_target, 10u);
    EXPECT_FALSE(outcome.target_shortfall);
    EXPECT_FALSE(outcome.reserve_shortfall);
}

TEST(Tier1Target, ShortPoolShrinksActiveTargetAndRecordsShortfall) {
    const auto outcome = tier1_target_outcome(30, 8);
    EXPECT_EQ(outcome.desired, 10u);
    EXPECT_EQ(outcome.active_target, 8u);
    EXPECT_TRUE(outcome.target_shortfall);
    EXPECT_TRUE(outcome.reserve_shortfall);
}

TEST(Tier1Target, ReserveShortfallAloneKeepsActiveTarget) {
    // Pool meets the target but not target + reserve: the active set is
    // unchanged, only the reserve shortfall is recorded.
    const auto outcome = tier1_target_outcome(30, 11);
    EXPECT_EQ(outcome.desired, 10u);
    EXPECT_EQ(outcome.active_target, 10u);
    EXPECT_FALSE(outcome.target_shortfall);
    EXPECT_TRUE(outcome.reserve_shortfall);
}

TEST(Tier1Target, ReserveBoundaryExact) {
    const auto outcome = tier1_target_outcome(30, 10 + constants::kMinTier1Reserve);
    EXPECT_FALSE(outcome.target_shortfall);
    EXPECT_FALSE(outcome.reserve_shortfall);
}

TEST(Tier1Target, PreQuorumMeshHasZeroTarget) {
    const auto outcome = tier1_target_outcome(4, 4);
    EXPECT_EQ(outcome.desired, 0u);
    EXPECT_EQ(outcome.active_target, 0u);
    EXPECT_FALSE(outcome.target_shortfall);
    EXPECT_FALSE(outcome.reserve_shortfall);
}

}  // namespace
