#include <LemonadeNexus/Core/ServerIdentity.hpp>
#include <LemonadeNexus/Relay/GeoRegion.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <vector>

using namespace nexus::core;

// ===========================================================================
// select_seed_endpoints — pure dedupe / self-exclude / format / ordering
// ===========================================================================

TEST(SeedDiscovery, FormatsIpWithGossipPort) {
    auto eps = select_seed_endpoints({"1.2.3.4"}, "", 9102);
    ASSERT_EQ(eps.size(), 1u);
    EXPECT_EQ(eps[0], "1.2.3.4:9102");
}

TEST(SeedDiscovery, ExcludesOurOwnPublicIp) {
    auto eps = select_seed_endpoints({"10.0.0.1", "10.0.0.2"}, "10.0.0.1", 9102);
    ASSERT_EQ(eps.size(), 1u);
    EXPECT_EQ(eps[0], "10.0.0.2:9102");
}

TEST(SeedDiscovery, DeDuplicatesRepeatedIps) {
    // Same server can appear under both <region>.seip and tierN.<region>.seip.
    auto eps = select_seed_endpoints({"5.5.5.5", "5.5.5.5", "6.6.6.6"}, "", 9102);
    ASSERT_EQ(eps.size(), 2u);
    EXPECT_EQ(eps[0], "5.5.5.5:9102");
    EXPECT_EQ(eps[1], "6.6.6.6:9102");
}

TEST(SeedDiscovery, PreservesPriorityOrder) {
    // Order in = priority order out (tier1@own, tier2@own, tier1@near, ...).
    auto eps = select_seed_endpoints({"1.1.1.1", "2.2.2.2", "3.3.3.3"}, "", 51820);
    ASSERT_EQ(eps.size(), 3u);
    EXPECT_EQ(eps[0], "1.1.1.1:51820");
    EXPECT_EQ(eps[1], "2.2.2.2:51820");
    EXPECT_EQ(eps[2], "3.3.3.3:51820");
}

TEST(SeedDiscovery, SkipsEmptyAndExcludedThenKeepsRest) {
    auto eps = select_seed_endpoints({"", "9.9.9.9", "9.9.9.9", ""}, "9.9.9.9", 9102);
    EXPECT_TRUE(eps.empty());
}

TEST(SeedDiscovery, EmptyInputYieldsEmpty) {
    EXPECT_TRUE(select_seed_endpoints({}, "1.2.3.4", 9102).empty());
}

// ===========================================================================
// Region prioritization that discovery relies on (own region first, by distance)
// ===========================================================================

TEST(SeedDiscovery, OwnRegionSortsFirstThenByDistance) {
    using nexus::relay::GeoRegion;
    std::vector<std::string> codes;
    for (const auto& r : GeoRegion::all_regions()) codes.push_back(r.code);

    auto sorted = GeoRegion::sort_by_distance("us-ca", codes);
    ASSERT_FALSE(sorted.empty());
    EXPECT_EQ(sorted.front(), "us-ca");  // our own region is distance 0 → first

    // A neighboring US region should rank ahead of a far continent.
    auto idx = [&](const std::string& c) {
        return std::distance(sorted.begin(), std::find(sorted.begin(), sorted.end(), c));
    };
    if (std::find(sorted.begin(), sorted.end(), "us-nv") != sorted.end() &&
        std::find(sorted.begin(), sorted.end(), "ap-jp") != sorted.end()) {
        EXPECT_LT(idx("us-nv"), idx("ap-jp"));
    }
}
