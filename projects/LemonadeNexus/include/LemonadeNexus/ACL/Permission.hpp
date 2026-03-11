#pragma once

#include <cstdint>

namespace nexus::acl {

/// Bitmask-based permission flags for the Lemonade-Nexus permission tree.
enum class Permission : uint32_t {
    None            = 0,
    Read            = 1 << 0,
    Write           = 1 << 1,
    AddChild        = 1 << 2,
    EditNode        = 1 << 3,
    DeleteNode      = 1 << 4,
    ExpandSubnet    = 1 << 5,
    ConnectPrivate  = 1 << 6,
    ConnectShared   = 1 << 7,
    RelayForward    = 1 << 8,
    StunRespond     = 1 << 9,
    RelayRegister   = 1 << 10,
    AllocateIP      = 1 << 11,
    Admin           = 0xFFFFFFFF,
};

[[nodiscard]] constexpr Permission operator|(Permission a, Permission b) {
    return static_cast<Permission>(
        static_cast<uint32_t>(a) | static_cast<uint32_t>(b));
}

[[nodiscard]] constexpr Permission operator&(Permission a, Permission b) {
    return static_cast<Permission>(
        static_cast<uint32_t>(a) & static_cast<uint32_t>(b));
}

[[nodiscard]] constexpr bool has_permission(Permission granted, Permission required) {
    return (granted & required) == required;
}

} // namespace nexus::acl
