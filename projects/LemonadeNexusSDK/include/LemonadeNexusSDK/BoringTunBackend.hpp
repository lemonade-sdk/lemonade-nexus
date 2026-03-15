#pragma once

#include <LemonadeNexusSDK/ITunnelBackend.hpp>
#include <LemonadeNexusSDK/Types.hpp>
#include <LemonadeNexusSDK/Error.hpp>

#include <atomic>
#include <memory>
#include <string>
#include <thread>

namespace lnsdk {

/// Userspace WireGuard tunnel using Cloudflare's BoringTun library.
///
/// Creates a platform-native TUN device (utun on macOS, /dev/net/tun on Linux,
/// WinTun on Windows) and runs the WireGuard Noise IK protocol in-process.
/// No external wg-quick or wireguard-go required.
class BoringTunBackend : public ITunnelBackend<BoringTunBackend> {
    friend class ITunnelBackend<BoringTunBackend>;

public:
    BoringTunBackend();
    ~BoringTunBackend();

    BoringTunBackend(const BoringTunBackend&) = delete;
    BoringTunBackend& operator=(const BoringTunBackend&) = delete;

private:
    // ITunnelBackend CRTP
    StatusResult do_bring_up(const WireGuardConfig& config);
    StatusResult do_bring_down();
    TunnelStatus do_status() const;
    StatusResult do_update_endpoint(const std::string& server_pubkey,
                                     const std::string& server_endpoint);
    bool do_is_active() const;

    // Platform-specific TUN device creation
    int create_tun_device(std::string& iface_name_out);
    void configure_tun_address(const std::string& iface, const std::string& tunnel_ip);
    void add_route(const std::string& iface, const std::string& cidr);

    // Packet forwarding threads
    void tun_to_udp_loop();
    void udp_to_tun_loop();
    void timer_loop();

    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace lnsdk
