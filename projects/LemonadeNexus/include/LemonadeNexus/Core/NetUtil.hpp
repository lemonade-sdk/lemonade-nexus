#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace nexus::net {

/// Split "host:port" into host and port, splitting on the LAST colon (so an
/// unbracketed IPv6-literal host keeps its colons, matching the rfind-based
/// split_hostport in Core/OnboardingClient.cpp).
///
/// Semantics:
/// - No colon -> {hostport, default_port}.
/// - A colon is present and the port part is empty, contains a non-digit,
///   is not representable, or falls outside [1, 65535] -> std::nullopt
///   (fail closed). The previous std::atoi-based path silently mapped
///   garbage or overflow to 0; this one refuses the input instead.
///
/// @param hostport  "host" or "host:port" (no scheme, no brackets).
/// @param default_port  Port to use when hostport has no colon.
/// @return {host, port}, or std::nullopt on an invalid port part.
[[nodiscard]] inline std::optional<std::pair<std::string, int>>
splitHostPort(std::string_view hostport, int default_port) {
    const auto colon = hostport.rfind(':');
    if (colon == std::string_view::npos)
        return std::pair{std::string(hostport), default_port};

    const std::string_view port_part = hostport.substr(colon + 1);
    if (port_part.empty()) return std::nullopt;

    int port = 0;
    for (const char c : port_part) {
        if (c < '0' || c > '9') return std::nullopt;   // non-numeric, fail closed
        const int digit = c - '0';
        // Overflow-safe accumulate: port stays in [0, 99999] below.
        if (port > 9999 || (port == 9999 && digit > 9)) return std::nullopt;
        port = port * 10 + digit;
    }
    if (port < 1 || port > 65535) return std::nullopt;

    return std::pair{std::string(hostport.substr(0, colon)), port};
}

} // namespace nexus::net
