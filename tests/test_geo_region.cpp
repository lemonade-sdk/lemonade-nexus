#include <LemonadeNexus/Relay/GeoRegion.hpp>

#include <gtest/gtest.h>

using namespace nexus::relay;

// ===========================================================================
// Haversine distance
// ===========================================================================

TEST(GeoRegion, HaversineKnownDistanceLAtoNY) {
    // Los Angeles to New York: ~3940 km
    GeoCoord la{34.0522, -118.2437};
    GeoCoord ny{40.7128, -74.0060};
    double dist = GeoRegion::haversine_km(la, ny);
    EXPECT_NEAR(dist, 3940.0, 50.0); // ±50 km tolerance
}

TEST(GeoRegion, HaversineKnownDistanceLondonToParis) {
    // London to Paris: ~344 km
    GeoCoord london{51.5074, -0.1278};
    GeoCoord paris{48.8566, 2.3522};
    double dist = GeoRegion::haversine_km(london, paris);
    EXPECT_NEAR(dist, 344.0, 10.0);
}

TEST(GeoRegion, HaversineSamePointIsZero) {
    GeoCoord point{37.7749, -122.4194};
    double dist = GeoRegion::haversine_km(point, point);
    EXPECT_NEAR(dist, 0.0, 0.001);
}

TEST(GeoRegion, HaversineAntipodalPoints) {
    // North pole to south pole: ~20015 km (half circumference)
    GeoCoord north{90.0, 0.0};
    GeoCoord south{-90.0, 0.0};
    double dist = GeoRegion::haversine_km(north, south);
    EXPECT_NEAR(dist, 20015.0, 100.0);
}

// ===========================================================================
// Region lookup
// ===========================================================================

TEST(GeoRegion, LookupValidUSState) {
    auto r = GeoRegion::lookup("us-ca");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->code, "us-ca");
    EXPECT_EQ(r->name, "California");
    EXPECT_NEAR(r->centroid.latitude, 36.1, 1.0);
}

TEST(GeoRegion, LookupValidEuropean) {
    auto r = GeoRegion::lookup("eu-de");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->code, "eu-de");
    EXPECT_EQ(r->name, "Germany");
}

TEST(GeoRegion, LookupValidAsiaPacific) {
    auto r = GeoRegion::lookup("ap-jp");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->name, "Japan");
}

TEST(GeoRegion, LookupCaseInsensitive) {
    auto r = GeoRegion::lookup("US-CA");
    ASSERT_TRUE(r.has_value());
    EXPECT_EQ(r->code, "us-ca");
}

TEST(GeoRegion, LookupUnknown) {
    EXPECT_FALSE(GeoRegion::lookup("xx-zz").has_value());
    EXPECT_FALSE(GeoRegion::lookup("").has_value());
    EXPECT_FALSE(GeoRegion::lookup("invalid").has_value());
}

// ===========================================================================
// is_valid_region
// ===========================================================================

TEST(GeoRegion, IsValidRegionTrue) {
    EXPECT_TRUE(GeoRegion::is_valid_region("us-ca"));
    EXPECT_TRUE(GeoRegion::is_valid_region("eu-gb"));
    EXPECT_TRUE(GeoRegion::is_valid_region("ap-sg"));
    EXPECT_TRUE(GeoRegion::is_valid_region("sa-br"));
    EXPECT_TRUE(GeoRegion::is_valid_region("af-za"));
    EXPECT_TRUE(GeoRegion::is_valid_region("me-ae"));
    EXPECT_TRUE(GeoRegion::is_valid_region("ca-on"));
}

TEST(GeoRegion, IsValidRegionFalse) {
    EXPECT_FALSE(GeoRegion::is_valid_region("xx-zz"));
    EXPECT_FALSE(GeoRegion::is_valid_region(""));
    EXPECT_FALSE(GeoRegion::is_valid_region("us"));
    EXPECT_FALSE(GeoRegion::is_valid_region("relay"));
}

// ===========================================================================
// Distance between regions
// ===========================================================================

TEST(GeoRegion, DistanceBetweenCaliforniaAndNewYork) {
    auto dist = GeoRegion::distance_between_regions("us-ca", "us-ny");
    ASSERT_TRUE(dist.has_value());
    EXPECT_GT(*dist, 3000.0);
    EXPECT_LT(*dist, 5000.0);
}

TEST(GeoRegion, DistanceBetweenUKAndGermany) {
    auto dist = GeoRegion::distance_between_regions("eu-gb", "eu-de");
    ASSERT_TRUE(dist.has_value());
    EXPECT_GT(*dist, 500.0);
    EXPECT_LT(*dist, 1500.0);
}

TEST(GeoRegion, DistanceSameRegionIsSmall) {
    auto dist = GeoRegion::distance_between_regions("us-ca", "us-ca");
    ASSERT_TRUE(dist.has_value());
    EXPECT_NEAR(*dist, 0.0, 0.001);
}

TEST(GeoRegion, DistanceUnknownRegionReturnsNullopt) {
    EXPECT_FALSE(GeoRegion::distance_between_regions("us-ca", "xx-zz").has_value());
    EXPECT_FALSE(GeoRegion::distance_between_regions("xx-zz", "us-ca").has_value());
}

// ===========================================================================
// Find closest region
// ===========================================================================

TEST(GeoRegion, FindClosestRegionByCoord) {
    // San Francisco coordinates should resolve to California
    GeoCoord sf{37.7749, -122.4194};
    auto closest = GeoRegion::find_closest_region(sf);
    ASSERT_TRUE(closest.has_value());
    EXPECT_EQ(closest->code, "us-ca");
}

TEST(GeoRegion, FindClosestRegionByCoordTokyo) {
    // Tokyo should resolve to Japan
    GeoCoord tokyo{35.6762, 139.6503};
    auto closest = GeoRegion::find_closest_region(tokyo);
    ASSERT_TRUE(closest.has_value());
    EXPECT_EQ(closest->code, "ap-jp");
}

TEST(GeoRegion, FindClosestRegionByCode) {
    // Closest to California should be a neighboring western state
    auto closest = GeoRegion::find_closest_region("us-ca");
    ASSERT_TRUE(closest.has_value());
    // Should be Nevada, Arizona, or Oregon (all neighbors)
    EXPECT_TRUE(closest->code == "us-nv" || closest->code == "us-az" ||
                closest->code == "us-or" || closest->code == "us-ut");
}

TEST(GeoRegion, FindClosestRegionUnknownCode) {
    EXPECT_FALSE(GeoRegion::find_closest_region("xx-zz").has_value());
}

// ===========================================================================
// Sort by distance
// ===========================================================================

TEST(GeoRegion, SortByDistanceFromCalifornia) {
    std::vector<std::string> candidates = {"eu-de", "us-ny", "us-or", "ap-jp"};
    auto sorted = GeoRegion::sort_by_distance("us-ca", candidates);

    ASSERT_EQ(sorted.size(), 4u);
    // Oregon should be closest to California
    EXPECT_EQ(sorted[0], "us-or");
    // New York should be next (same continent)
    EXPECT_EQ(sorted[1], "us-ny");
    // Japan and Germany are far, order may vary but both should be after NY
}

TEST(GeoRegion, SortByDistanceUnknownCandidatesGoLast) {
    std::vector<std::string> candidates = {"us-ny", "xx-zz", "us-or"};
    auto sorted = GeoRegion::sort_by_distance("us-ca", candidates);

    ASSERT_EQ(sorted.size(), 3u);
    EXPECT_EQ(sorted[0], "us-or");
    EXPECT_EQ(sorted[1], "us-ny");
    EXPECT_EQ(sorted[2], "xx-zz"); // Unknown goes last
}

TEST(GeoRegion, SortByDistanceUnknownOriginReturnsOriginal) {
    std::vector<std::string> candidates = {"us-ca", "us-ny"};
    auto sorted = GeoRegion::sort_by_distance("xx-zz", candidates);
    EXPECT_EQ(sorted, candidates); // Unchanged
}

// ===========================================================================
// All regions coverage
// ===========================================================================

TEST(GeoRegion, AllRegionsNotEmpty) {
    const auto& regions = GeoRegion::all_regions();
    EXPECT_GT(regions.size(), 50u); // We have 50+ US states + international
}

TEST(GeoRegion, AllUSStatesPresent) {
    // Check a selection of US states
    std::vector<std::string> states = {
        "us-al", "us-ak", "us-az", "us-ca", "us-co", "us-fl", "us-ga",
        "us-hi", "us-il", "us-ny", "us-tx", "us-wa", "us-dc"
    };
    for (const auto& s : states) {
        EXPECT_TRUE(GeoRegion::is_valid_region(s)) << "Missing state: " << s;
    }
}

TEST(GeoRegion, AllContinentsRepresented) {
    EXPECT_TRUE(GeoRegion::is_valid_region("eu-de"));  // Europe
    EXPECT_TRUE(GeoRegion::is_valid_region("ap-jp"));  // Asia Pacific
    EXPECT_TRUE(GeoRegion::is_valid_region("sa-br"));  // South America
    EXPECT_TRUE(GeoRegion::is_valid_region("af-za"));  // Africa
    EXPECT_TRUE(GeoRegion::is_valid_region("me-ae"));  // Middle East
    EXPECT_TRUE(GeoRegion::is_valid_region("ca-on"));  // Canada
}

TEST(GeoRegion, RegionCoordinatesAreSane) {
    for (const auto& r : GeoRegion::all_regions()) {
        EXPECT_GE(r.centroid.latitude, -90.0) << "Bad lat for " << r.code;
        EXPECT_LE(r.centroid.latitude, 90.0) << "Bad lat for " << r.code;
        EXPECT_GE(r.centroid.longitude, -180.0) << "Bad lon for " << r.code;
        EXPECT_LE(r.centroid.longitude, 180.0) << "Bad lon for " << r.code;
        EXPECT_FALSE(r.code.empty());
        EXPECT_FALSE(r.name.empty());
    }
}
