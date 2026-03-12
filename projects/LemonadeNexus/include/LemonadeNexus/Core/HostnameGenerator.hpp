#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <unordered_set>
#include <vector>

namespace nexus::core {

struct CloudRegion {
    std::string code;
    std::string description;
    double latitude;
    double longitude;
};

class HostnameGenerator {
public:
    /// Detect region via IP geolocation (ip-api.com). Returns region code like "us-east".
    [[nodiscard]] static std::optional<std::string> detect_region();

    /// Map lat/lon to nearest cloud region code.
    [[nodiscard]] static std::string map_to_cloud_region(double lat, double lon);

    /// Generate unique hostname: <region>-<N>, incrementing N to avoid collisions.
    [[nodiscard]] static std::string generate_unique_hostname(
        const std::string& region_code,
        const std::unordered_set<std::string>& existing);

    /// Load persisted hostname from data/identity/hostname.
    [[nodiscard]] static std::optional<std::string> load_persisted_hostname(
        const std::filesystem::path& data_root);

    /// Persist hostname to data/identity/hostname.
    static bool persist_hostname(const std::filesystem::path& data_root,
                                  const std::string& hostname);

    /// Get all cloud regions.
    [[nodiscard]] static const std::vector<CloudRegion>& cloud_regions();
};

} // namespace nexus::core
