#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::relay {

/// Geographic coordinate (WGS84).
struct GeoCoord {
    double latitude{0.0};   ///< Degrees north (-90 to +90)
    double longitude{0.0};  ///< Degrees east (-180 to +180)
};

/// A named geographic region with a centroid coordinate.
struct RegionInfo {
    std::string code;       ///< Region code (e.g. "us-ca", "eu-de", "ap-jp")
    std::string name;       ///< Human-readable name
    GeoCoord    centroid;   ///< Approximate center of the region
};

/// Geographic region utilities for relay proximity calculations.
///
/// Region codes follow a two-tier scheme:
///   - US states:    "us-<state>" (e.g. "us-ca", "us-ny", "us-tx")
///   - International: "<continent>-<country>" (e.g. "eu-de", "ap-jp", "sa-br")
///
/// Uses the Haversine formula for great-circle distance.
class GeoRegion {
public:
    /// Compute the great-circle distance in kilometers between two coordinates
    /// using the Haversine formula.
    [[nodiscard]] static double haversine_km(const GeoCoord& a, const GeoCoord& b);

    /// Compute the distance in kilometers between two region centroids.
    /// Returns nullopt if either region code is unknown.
    [[nodiscard]] static std::optional<double> distance_between_regions(
        std::string_view region_a, std::string_view region_b);

    /// Find the closest known region to a given coordinate.
    /// Returns nullopt if no regions are registered.
    [[nodiscard]] static std::optional<RegionInfo> find_closest_region(const GeoCoord& coord);

    /// Find the closest known region to a given region code.
    /// Returns nullopt if the input region is unknown.
    [[nodiscard]] static std::optional<RegionInfo> find_closest_region(std::string_view region_code);

    /// Look up a region by its code. Returns nullopt if unknown.
    [[nodiscard]] static std::optional<RegionInfo> lookup(std::string_view code);

    /// Get all known regions.
    [[nodiscard]] static const std::vector<RegionInfo>& all_regions();

    /// Validate a region code.
    [[nodiscard]] static bool is_valid_region(std::string_view code);

    /// Sort a list of region codes by distance from a reference region.
    /// Unknown regions are placed at the end.
    [[nodiscard]] static std::vector<std::string> sort_by_distance(
        std::string_view from_region,
        const std::vector<std::string>& candidates);

private:
    static constexpr double kEarthRadiusKm = 6371.0;
    [[nodiscard]] static double deg_to_rad(double deg);
};

} // namespace nexus::relay
