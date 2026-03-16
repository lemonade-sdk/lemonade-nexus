#pragma once

#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/WireGuard/IWireGuardProvider.hpp>

#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

// Backend selection (compile-time, mutually exclusive):
//   Linux + HAS_EMBEDDABLE_WG      → embeddable wireguard.h C API (kernel netlink)
//   Apple + HAS_WIREGUARDKIT       → wireguard-go via Obj-C++ bridge (userspace utun)
//   Windows + HAS_WIREGUARD_NT     → wireguard-nt kernel driver (wireguard.dll)
//   Other                          → `wg` / `ip` CLI tools (fallback)
#ifdef HAS_EMBEDDABLE_WG
extern "C" {
#include <wireguard.h>
}
#elif defined(__APPLE__) && defined(HAS_WIREGUARDKIT)
#include <LemonadeNexus/WireGuard/WireGuardAppleBridge.h>
#elif defined(_WIN32) && defined(HAS_WIREGUARD_NT)
#include <LemonadeNexus/WireGuard/WireGuardWindowsBridge.h>
#endif

namespace nexus::wireguard {

/// WireGuard management service.
///
/// On Linux with HAS_EMBEDDABLE_WG: uses the embeddable wireguard.h C API
/// for direct netlink-based kernel WireGuard communication (no shell-out).
/// On macOS with HAS_WIREGUARDKIT: uses wireguard-go via Obj-C++ utun bridge.
/// On Windows with HAS_WIREGUARD_NT: uses the wireguard-nt kernel driver
/// via dynamic loading of wireguard.dll.
/// On other platforms: shells out to `wg` and `ip` CLI tools with input
/// validation to prevent command injection.
///
/// Manages a single WireGuard interface (default "wg0"), providing keypair
/// generation, peer management, endpoint updates, config file generation,
/// full interface setup/teardown, and peer synchronization from the
/// permission tree.
///
/// All operations are serialized through a mutex so that concurrent callers
/// do not interleave commands on the same interface.
class WireGuardService : public core::IService<WireGuardService>,
                          public IWireGuardProvider<WireGuardService> {
    friend class core::IService<WireGuardService>;
    friend class IWireGuardProvider<WireGuardService>;

public:
    /// @param interface_name  WireGuard interface name (e.g. "wg0").
    /// @param config_dir      Directory for storing config files (e.g. "data/wireguard").
    explicit WireGuardService(std::string interface_name = "wg0",
                               std::filesystem::path config_dir = "data/wireguard");
    ~WireGuardService();  // defined in .cpp (BoringTunState PIMPL)

    // IService
    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "WireGuardService"; }

    // --- IWireGuardProvider (existing) ---

    [[nodiscard]] WgKeypair do_generate_keypair();
    [[nodiscard]] bool do_set_interface(const WgInterfaceConfig& config);
    [[nodiscard]] bool do_add_peer(const std::string& pubkey,
                                   const std::string& allowed_ips,
                                   const std::string& endpoint);
    [[nodiscard]] bool do_remove_peer(const std::string& pubkey);
    [[nodiscard]] std::vector<WgPeer> do_get_peers();
    [[nodiscard]] bool do_update_endpoint(const std::string& pubkey,
                                          const std::string& new_endpoint);

    // --- IWireGuardProvider (new) ---

    /// Generate a wg-quick compatible configuration string.
    [[nodiscard]] std::string do_generate_config(const WgInterfaceConfig& config,
                                                  const std::vector<WgPeer>& peers);

    /// Create / configure / bring-up the WireGuard interface with peers and routes.
    [[nodiscard]] bool do_setup_interface(const WgInterfaceConfig& config,
                                          const std::vector<WgPeer>& peers);

    /// Bring the interface down and delete it.
    [[nodiscard]] bool do_teardown_interface();

    /// Sync peers from tree nodes: add new, remove stale, update endpoints.
    /// Returns number of changes made, or -1 on error.
    [[nodiscard]] int do_sync_peers_from_tree(const std::vector<TreeNodePeer>& desired_peers);

    /// Write config contents to <config_dir_>/<interface_name_>.conf.
    [[nodiscard]] bool do_save_config(const std::string& config_contents);

    /// Read config from <config_dir_>/<interface_name_>.conf.
    /// Returns empty string if file does not exist.
    [[nodiscard]] std::string do_load_config();

private:
    /// Execute a shell command via popen and return its stdout output.
    /// Returns an empty string on failure.
    [[nodiscard]] std::string run_command(const std::string& cmd) const;

    // --- Input validation helpers (static, no side effects) ---

    /// Validate a base64-encoded WireGuard public key (44 characters, valid base64).
    [[nodiscard]] static bool is_valid_pubkey(const std::string& key);

    /// Validate an endpoint string of the form "ip:port" or "[ipv6]:port".
    [[nodiscard]] static bool is_valid_endpoint(const std::string& ep);

    /// Validate a CIDR-formatted IP (e.g. "10.64.0.1/32" or "10.128.0.0/30").
    [[nodiscard]] static bool is_valid_cidr(const std::string& cidr);

    /// Validate a comma-separated list of CIDR addresses.
    [[nodiscard]] static bool is_valid_allowed_ips(const std::string& allowed_ips);

    /// Validate that an interface name contains only safe characters.
    [[nodiscard]] static bool is_valid_interface_name(const std::string& iface);

    /// Return the full path to the config file.
    [[nodiscard]] std::filesystem::path config_file_path() const;

    std::string           interface_name_;
    std::filesystem::path config_dir_;
    std::mutex            mutex_;

#if defined(__APPLE__) && defined(HAS_WIREGUARDKIT)
    int         tunnel_handle_{-1};  ///< wireguard-go tunnel handle
    int         tunnel_utun_fd_{-1}; ///< utun file descriptor
    std::string utun_name_;          ///< assigned utun interface name (e.g. "utun3")
#elif defined(_WIN32) && defined(HAS_WIREGUARD_NT)
    void*       nt_adapter_{nullptr}; ///< wireguard-nt adapter handle
#endif

    // --- BoringTun userspace fallback (runtime, when CLI tools unavailable) ---
    bool use_boringtun_{false};
    struct BoringTunState;
    std::unique_ptr<BoringTunState> bt_;

    // BoringTun helper methods (defined only in CLI fallback path)
    int  bt_create_tun_device(std::string& iface_name_out);
    void bt_configure_address(const std::string& iface, const std::string& address);
    void bt_add_route(const std::string& iface, const std::string& cidr);
    void bt_tun_to_udp_loop();
    void bt_udp_to_tun_loop();
    void bt_timer_loop();
    void bt_cleanup();
};

} // namespace nexus::wireguard
