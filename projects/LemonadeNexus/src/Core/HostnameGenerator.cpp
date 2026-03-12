#include "LemonadeNexus/Core/HostnameGenerator.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <cmath>
#include <fstream>

namespace nexus::core {

namespace {

constexpr double kPi = 3.14159265358979323846;
constexpr double kEarthRadiusKm = 6371.0;

double to_rad(double deg) { return deg * kPi / 180.0; }

double haversine_km(double lat1, double lon1, double lat2, double lon2) {
    double dlat = to_rad(lat2 - lat1);
    double dlon = to_rad(lon2 - lon1);
    double a = std::sin(dlat / 2) * std::sin(dlat / 2) +
               std::cos(to_rad(lat1)) * std::cos(to_rad(lat2)) *
               std::sin(dlon / 2) * std::sin(dlon / 2);
    return kEarthRadiusKm * 2.0 * std::atan2(std::sqrt(a), std::sqrt(1.0 - a));
}

} // anonymous namespace

const std::vector<CloudRegion>& HostnameGenerator::cloud_regions() {
    static const std::vector<CloudRegion> regions = {
        {"us-east",      "US East (Virginia)",        37.43,  -79.14},
        {"us-west",      "US West (Oregon)",          43.80, -120.55},
        {"us-central",   "US Central (Iowa)",         42.01,  -93.21},
        {"us-south",     "US South (Texas)",          31.05,  -97.56},
        {"ca-central",   "Canada (Montreal)",         45.50,  -73.57},
        {"eu-west",      "EU West (Ireland)",         53.14,   -7.69},
        {"eu-central",   "EU Central (Frankfurt)",    50.11,    8.68},
        {"eu-north",     "EU North (Stockholm)",      59.33,   18.07},
        {"eu-south",     "EU South (Milan)",          45.46,    9.19},
        {"ap-east",      "AP East (Tokyo)",           35.68,  139.69},
        {"ap-south",     "AP South (Mumbai)",         19.08,   72.88},
        {"ap-southeast", "AP Southeast (Singapore)",   1.35,  103.82},
        {"ap-northeast", "AP Northeast (Seoul)",      37.57,  126.98},
        {"me-south",     "Middle East (Bahrain)",     26.07,   50.56},
        {"sa-east",      "South America (Sao Paulo)",-23.55,  -46.63},
        {"af-south",     "Africa (Cape Town)",       -33.92,   18.42},
    };
    return regions;
}

std::string HostnameGenerator::map_to_cloud_region(double lat, double lon) {
    const auto& regions = cloud_regions();
    double best_dist = std::numeric_limits<double>::max();
    std::string best_code = "unknown";
    for (const auto& r : regions) {
        double d = haversine_km(lat, lon, r.latitude, r.longitude);
        if (d < best_dist) {
            best_dist = d;
            best_code = r.code;
        }
    }
    return best_code;
}

std::optional<std::string> HostnameGenerator::detect_region() {
    try {
        httplib::Client cli("http://ip-api.com");
        cli.set_connection_timeout(3, 0);
        cli.set_read_timeout(3, 0);

        auto res = cli.Get("/json");
        if (!res || res->status != 200) {
            spdlog::warn("[HostnameGenerator] geolocation API failed (status: {})",
                         res ? res->status : 0);
            return std::nullopt;
        }

        auto j = nlohmann::json::parse(res->body);
        if (j.value("status", "") != "success") {
            spdlog::warn("[HostnameGenerator] geolocation API returned failure");
            return std::nullopt;
        }

        double lat = j.value("lat", 0.0);
        double lon = j.value("lon", 0.0);
        auto region = map_to_cloud_region(lat, lon);
        spdlog::info("[HostnameGenerator] geolocation: {}, {} ({}) -> region: {}",
                     j.value("city", "?"), j.value("country", "?"),
                     j.value("isp", "?"), region);
        return region;
    } catch (const std::exception& e) {
        spdlog::warn("[HostnameGenerator] geolocation detection failed: {}", e.what());
        return std::nullopt;
    }
}

std::string HostnameGenerator::generate_unique_hostname(
    const std::string& region_code,
    const std::unordered_set<std::string>& existing) {
    for (int suffix = 1; ; ++suffix) {
        auto candidate = region_code + "-" + std::to_string(suffix);
        if (existing.find(candidate) == existing.end()) {
            return candidate;
        }
    }
}

std::optional<std::string> HostnameGenerator::load_persisted_hostname(
    const std::filesystem::path& data_root) {
    auto path = data_root / "identity" / "hostname";
    std::ifstream in(path);
    if (!in.is_open()) return std::nullopt;

    std::string hostname;
    std::getline(in, hostname);
    // Trim whitespace
    while (!hostname.empty() && (hostname.back() == '\n' || hostname.back() == '\r' || hostname.back() == ' '))
        hostname.pop_back();
    if (hostname.empty()) return std::nullopt;
    return hostname;
}

bool HostnameGenerator::persist_hostname(const std::filesystem::path& data_root,
                                          const std::string& hostname) {
    try {
        auto dir = data_root / "identity";
        std::filesystem::create_directories(dir);
        auto path = dir / "hostname";
        std::ofstream out(path);
        if (!out.is_open()) {
            spdlog::warn("[HostnameGenerator] failed to open {} for writing", path.string());
            return false;
        }
        out << hostname << "\n";
        spdlog::info("[HostnameGenerator] persisted hostname '{}' to {}", hostname, path.string());
        return true;
    } catch (const std::exception& e) {
        spdlog::warn("[HostnameGenerator] failed to persist hostname: {}", e.what());
        return false;
    }
}

} // namespace nexus::core
