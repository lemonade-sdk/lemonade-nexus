#pragma once

#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Boringtun/IBoringtunProvider.hpp>
#include <LemonadeNexus/Boringtun/UserspaceDataplane.hpp>

#include <filesystem>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::boringtun {

/// Mesh management service.
///
/// A thin facade over the fully in-process userspace dataplane
/// (UserspaceDataplane): one UDP socket, per-peer boringtun Noise sessions, and
/// a userspace cryptokey router. There is no kernel network interface and no
/// TUN device, so the server needs no root / CAP_NET_ADMIN and host-level tools
/// (`wg`, `tcpdump`) cannot observe tunnel keys or plaintext.
///
/// The interface name is retained only for config-file naming and log lines —
/// it does not correspond to any kernel device. Callers (GossipService,
/// TreeApiHandler, MeshApiHandler, main) keep using the IBoringtunProvider API
/// unchanged; "setup_interface"/"add_address" now register virtual addresses
/// with the router rather than configuring a kernel device.
///
/// Operations are serialized through a mutex so concurrent callers do not
/// interleave control-plane changes.
class BoringtunService : public core::IService<BoringtunService>,
                          public IBoringtunProvider<BoringtunService> {
    friend class core::IService<BoringtunService>;
    friend class IBoringtunProvider<BoringtunService>;

public:
    /// @param interface_name  Logical name (e.g. "nexus0"); used only for config
    ///                        file naming and logs — no kernel device is created.
    /// @param config_dir      Directory for storing config files (e.g. "data/wireguard").
    explicit BoringtunService(std::string interface_name = "nexus0",
                               std::filesystem::path config_dir = "data/wireguard");
    ~BoringtunService();

    // IService
    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "BoringtunService"; }

    /// Access the underlying dataplane to wire the termination-layer seam
    /// (inbound handler / outbound packet sink) in main.
    [[nodiscard]] UserspaceDataplane& dataplane() { return dataplane_; }

    // --- IBoringtunProvider ---

    [[nodiscard]] BoringtunKeypair do_generate_keypair();
    [[nodiscard]] bool do_set_interface(const BoringtunInterfaceConfig& config);
    [[nodiscard]] bool do_add_peer(const std::string& pubkey,
                                   const std::string& allowed_ips,
                                   const std::string& endpoint);
    [[nodiscard]] bool do_remove_peer(const std::string& pubkey);
    [[nodiscard]] std::vector<BoringtunPeer> do_get_peers();
    [[nodiscard]] bool do_update_endpoint(const std::string& pubkey,
                                          const std::string& new_endpoint);

    [[nodiscard]] std::string do_generate_config(const BoringtunInterfaceConfig& config,
                                                  const std::vector<BoringtunPeer>& peers);
    [[nodiscard]] bool do_setup_interface(const BoringtunInterfaceConfig& config,
                                          const std::vector<BoringtunPeer>& peers);
    [[nodiscard]] bool do_teardown_interface();
    [[nodiscard]] int do_sync_peers_from_tree(const std::vector<TreeNodePeer>& desired_peers);
    [[nodiscard]] bool do_add_address(const std::string& address_cidr);
    [[nodiscard]] bool do_save_config(const std::string& config_contents);
    [[nodiscard]] std::string do_load_config();

private:
    // --- Input validation helpers (static, no side effects) ---
    [[nodiscard]] static bool is_valid_pubkey(const std::string& key);
    [[nodiscard]] static bool is_valid_endpoint(const std::string& ep);
    [[nodiscard]] static bool is_valid_cidr(const std::string& cidr);
    [[nodiscard]] static bool is_valid_allowed_ips(const std::string& allowed_ips);
    [[nodiscard]] static bool is_valid_interface_name(const std::string& iface);

    [[nodiscard]] std::filesystem::path config_file_path() const;

    /// Derive the X25519 public key (base64) from a base64 private key.
    [[nodiscard]] static std::string derive_public_key(const std::string& private_key_b64);

    /// Register the host address of a CIDR as a virtual local IP in the router.
    bool add_local_address(const std::string& address_cidr);

    std::string           interface_name_;
    std::filesystem::path config_dir_;
    std::mutex            mutex_;

    UserspaceDataplane    dataplane_;
    std::string           private_key_b64_;
    std::string           public_key_b64_;
    uint16_t              listen_port_{51940};
};

} // namespace nexus::boringtun
