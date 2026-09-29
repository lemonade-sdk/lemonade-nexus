#pragma once

#include <string>
#include <string_view>

namespace nexus::seip {

/// SEIP DNS naming convention (mirrors docs/DNS-Discovery.md): every
/// discovery record lives under "<...>.seip.<base>" where <base> is the
/// configured dns_base_domain.
///
/// These are PURE CONCATENATION: no lowercasing, trimming, or any other
/// normalization is applied to any part. Callers keep their existing
/// normalization — the zone record keys and TXT contents must remain
/// byte-identical, so normalizing here would silently change what the
/// server answers and what clients query.

/// Per-server SEIP FQDN: "<id>.<region>.seip.<base>".
[[nodiscard]] inline std::string seipFqdn(
    std::string_view id, std::string_view region, std::string_view base) {
    return std::string(id) + "." + std::string(region) + ".seip." +
           std::string(base);
}

/// Tier seed FQDN: "tier<N>.<region>.seip.<base>".
[[nodiscard]] inline std::string tierFqdn(
    int tier, std::string_view region, std::string_view base) {
    return "tier" + std::to_string(tier) + "." + std::string(region) +
           ".seip." + std::string(base);
}

/// Per-server tier FQDN: "<id>.tier<N>.<region>.seip.<base>".
[[nodiscard]] inline std::string memberTierFqdn(
    std::string_view id, int tier, std::string_view region, std::string_view base) {
    return std::string(id) + ".tier" + std::to_string(tier) + "." +
           std::string(region) + ".seip." + std::string(base);
}

/// Private (tunnel) FQDN: "private.<id>.<region>.seip.<base>".
[[nodiscard]] inline std::string privateFqdn(
    std::string_view id, std::string_view region, std::string_view base) {
    return "private." + seipFqdn(id, region, base);
}

/// Backend (backbone) FQDN: "backend.<id>.<region>.seip.<base>".
[[nodiscard]] inline std::string backendFqdn(
    std::string_view id, std::string_view region, std::string_view base) {
    return "backend." + seipFqdn(id, region, base);
}

/// Config TXT FQDN: "_config.<id>.<region>.seip.<base>".
[[nodiscard]] inline std::string configFqdn(
    std::string_view id, std::string_view region, std::string_view base) {
    return "_config." + seipFqdn(id, region, base);
}

} // namespace nexus::seip
