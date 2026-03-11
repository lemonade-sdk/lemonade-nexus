#pragma once

#include <LemonadeNexusSDK/Types.hpp>
#include <LemonadeNexusSDK/Error.hpp>

#include <memory>
#include <string>
#include <utility>

namespace lnsdk {

/// Platform-aware WireGuard tunnel manager.
///
/// On desktop platforms (Linux, macOS, Windows) this class can directly
/// configure and manage a WireGuard tunnel. On mobile platforms (iOS, Android)
/// the OS requires the app to manage the VPN lifecycle via platform-specific
/// APIs (NetworkExtension / VpnService), so this class provides helper methods
/// to generate the WireGuard configuration string that the app passes to its
/// tunnel provider.
class WireGuardTunnel {
public:
    WireGuardTunnel();
    ~WireGuardTunnel();

    // Non-copyable, movable
    WireGuardTunnel(const WireGuardTunnel&) = delete;
    WireGuardTunnel& operator=(const WireGuardTunnel&) = delete;
    WireGuardTunnel(WireGuardTunnel&&) noexcept;
    WireGuardTunnel& operator=(WireGuardTunnel&&) noexcept;

    /// Generate a new WireGuard keypair using libsodium's crypto_scalarmult_base
    /// (Curve25519, compatible with WireGuard).
    /// @return {private_key_base64, public_key_base64}
    static std::pair<std::string, std::string> generate_keypair();

    /// Configure and bring up the WireGuard tunnel.
    /// On mobile platforms this stores the config internally and returns success;
    /// the app must call get_wg_config_string() and pass it to the OS tunnel API.
    StatusResult bring_up(const WireGuardConfig& config);

    /// Tear down the tunnel.
    StatusResult bring_down();

    /// Get current tunnel status.
    TunnelStatus status() const;

    /// Update the server endpoint (for server switching / roaming).
    StatusResult update_endpoint(const std::string& server_pubkey,
                                  const std::string& server_endpoint);

    /// Check if tunnel is active.
    bool is_active() const;

    /// Generate a wg-quick compatible configuration string.
    /// Useful on all platforms, required on iOS/Android where the app must
    /// pass this to the native tunnel provider.
    std::string get_wg_config_string() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace lnsdk
