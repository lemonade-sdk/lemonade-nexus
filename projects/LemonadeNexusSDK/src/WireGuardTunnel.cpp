#include <LemonadeNexusSDK/WireGuardTunnel.hpp>
#include <LemonadeNexusSDK/BoringTunBackend.hpp>

#include <sodium.h>
#include <spdlog/spdlog.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

// Platform detection
#if defined(_WIN32)
#  include <windows.h>
#elif defined(__APPLE__)
#  include <TargetConditionals.h>
#endif

namespace lnsdk {

// ---------------------------------------------------------------------------
// Base64 helpers (WireGuard uses standard base64, not URL-safe)
// ---------------------------------------------------------------------------

static std::string wg_base64_encode(const uint8_t* data, std::size_t len) {
    const std::size_t b64_maxlen = sodium_base64_ENCODED_LEN(len, sodium_base64_VARIANT_ORIGINAL);
    std::string out(b64_maxlen, '\0');
    sodium_bin2base64(out.data(), b64_maxlen, data, len, sodium_base64_VARIANT_ORIGINAL);
    // sodium_bin2base64 null-terminates; trim to actual length
    out.resize(std::strlen(out.c_str()));
    return out;
}

// ---------------------------------------------------------------------------
// PIMPL
// ---------------------------------------------------------------------------

struct WireGuardTunnel::Impl {
    WireGuardConfig          config;
    bool                     active{false};
    bool                     using_boringtun{false}; // true when BoringTun fallback is active
    BoringTunBackend         boringtun;              // userspace fallback
    std::string              iface_name;             // e.g. "wg0", "utun7"
    std::string              config_path;            // temp file path for wg-quick
    mutable std::mutex       mutex;                  // guards active, config, iface_name
    std::vector<MeshPeer>    mesh_peers;             // current mesh peer set

    // Build a wg-quick compatible config string
    std::string build_config_string() const {
        std::ostringstream ss;
        ss << "[Interface]\n";
        ss << "PrivateKey = " << config.private_key << "\n";
        ss << "Address = " << config.tunnel_ip << "\n";
        if (config.listen_port > 0) {
            ss << "ListenPort = " << config.listen_port << "\n";
        }
        if (!config.dns_server.empty()) {
            ss << "DNS = " << config.dns_server << "\n";
        }
        ss << "\n[Peer]\n";
        ss << "PublicKey = " << config.server_public_key << "\n";
        if (!config.server_endpoint.empty()) {
            ss << "Endpoint = " << config.server_endpoint << "\n";
        }
        if (!config.allowed_ips.empty()) {
            ss << "AllowedIPs = ";
            for (std::size_t i = 0; i < config.allowed_ips.size(); ++i) {
                if (i > 0) ss << ", ";
                ss << config.allowed_ips[i];
            }
            ss << "\n";
        } else {
            ss << "AllowedIPs = 10.100.0.0/16\n";
        }
        if (config.keepalive > 0) {
            ss << "PersistentKeepalive = " << config.keepalive << "\n";
        }
        return ss.str();
    }

    // Write config to a temp file, return the path
    std::string write_temp_config() {
        // Use a stable name so we can tear down later
        std::string path;
#if defined(_WIN32)
        char tmp[MAX_PATH];
        GetTempPathA(sizeof(tmp), tmp);
        path = std::string(tmp) + "lnsdk_wg0.conf";
#else
        path = "/tmp/lnsdk_wg0.conf";
#endif
        std::ofstream ofs(path, std::ios::trunc);
        if (!ofs) return {};
        ofs << build_config_string();
        ofs.close();
        config_path = path;
        return path;
    }

    // Execute a command, return {exit_code, stdout}
    static std::pair<int, std::string> exec_cmd(const std::string& cmd) {
        std::string output;
#if defined(_WIN32)
        FILE* pipe = _popen(cmd.c_str(), "r");
#else
        FILE* pipe = popen(cmd.c_str(), "r");
#endif
        if (!pipe) return {-1, ""};
        std::array<char, 256> buf{};
        while (std::fgets(buf.data(), static_cast<int>(buf.size()), pipe)) {
            output += buf.data();
        }
#if defined(_WIN32)
        int rc = _pclose(pipe);
#else
        int rc = pclose(pipe);
#endif
        return {rc, output};
    }

    // Parse "wg show" output for status
    TunnelStatus parse_wg_show(const std::string& output) const {
        TunnelStatus st;
        st.is_up          = active;
        st.tunnel_ip      = config.tunnel_ip;
        st.server_endpoint = config.server_endpoint;

        std::istringstream iss(output);
        std::string line;
        while (std::getline(iss, line)) {
            // Trim leading whitespace
            auto pos = line.find_first_not_of(" \t");
            if (pos == std::string::npos) continue;
            line = line.substr(pos);

            if (line.rfind("latest handshake:", 0) == 0) {
                // "latest handshake: 42 seconds ago"
                // We store approximate epoch — just mark as recent
                auto vpos = line.find(':');
                if (vpos != std::string::npos) {
                    auto start = (vpos + 1 < line.size() && line[vpos + 1] == ' ') ? vpos + 2 : vpos + 1;
                    std::string val = line.substr(start);
                    // Try to parse seconds ago
                    int secs = 0;
                    if (std::sscanf(val.c_str(), "%d", &secs) == 1) {
                        st.last_handshake = static_cast<int64_t>(std::time(nullptr)) - secs;
                    }
                }
            } else if (line.rfind("transfer:", 0) == 0) {
                // "transfer: 1.23 MiB received, 4.56 MiB sent"
                // Parse numeric values
                auto vpos = line.find(':');
                if (vpos != std::string::npos) {
                    auto start = (vpos + 1 < line.size() && line[vpos + 1] == ' ') ? vpos + 2 : vpos + 1;
                    std::string val = line.substr(start);
                    double rx = 0, tx = 0;
                    char rx_unit[16] = {}, tx_unit[16] = {};
                    if (std::sscanf(val.c_str(), "%lf %15s received, %lf %15s sent",
                                    &rx, rx_unit, &tx, tx_unit) >= 2) {
                        auto to_bytes = [](double v, const char* unit) -> uint64_t {
                            std::string u(unit);
                            if (u == "KiB") return static_cast<uint64_t>(v * 1024);
                            if (u == "MiB") return static_cast<uint64_t>(v * 1024 * 1024);
                            if (u == "GiB") return static_cast<uint64_t>(v * 1024 * 1024 * 1024);
                            if (u == "B")   return static_cast<uint64_t>(v);
                            return static_cast<uint64_t>(v);
                        };
                        st.rx_bytes = to_bytes(rx, rx_unit);
                        st.tx_bytes = to_bytes(tx, tx_unit);
                    }
                }
            }
        }
        return st;
    }

    // Build allowed-IPs string for a mesh peer (tunnel_ip + private_subnet)
    static std::string peer_allowed_ips(const MeshPeer& peer) {
        std::string ips;
        if (!peer.tunnel_ip.empty()) {
            // Ensure /32 suffix for point-to-point
            ips = peer.tunnel_ip;
            if (ips.find('/') == std::string::npos) ips += "/32";
        }
        if (!peer.private_subnet.empty()) {
            if (!ips.empty()) ips += ",";
            ips += peer.private_subnet;
        }
        return ips;
    }

    // Parse "wg show <iface> dump" output for multi-peer mesh status.
    // dump format (tab-separated):
    //   Line 1: private-key  public-key  listen-port  fwmark
    //   Per-peer: public-key  preshared-key  endpoint  allowed-ips  latest-handshake  transfer-rx  transfer-tx  persistent-keepalive
    MeshTunnelStatus parse_wg_dump(const std::string& output) const {
        MeshTunnelStatus ms;
        ms.is_up     = active;
        ms.tunnel_ip = config.tunnel_ip;

        std::istringstream iss(output);
        std::string line;
        bool first_line = true;
        while (std::getline(iss, line)) {
            if (first_line) { first_line = false; continue; } // skip interface line

            // Split by tab
            std::vector<std::string> fields;
            std::istringstream lss(line);
            std::string field;
            while (std::getline(lss, field, '\t')) {
                fields.push_back(field);
            }
            if (fields.size() < 8) continue;

            MeshPeer p;
            p.wg_pubkey = fields[0];
            // fields[1] = preshared-key (usually "(none)")
            // fields[2] = endpoint
            if (fields[2] != "(none)") p.endpoint = fields[2];
            // fields[3] = allowed-ips
            p.tunnel_ip = fields[3]; // raw allowed-ips
            // fields[4] = latest-handshake (epoch seconds, 0 = never)
            try { p.last_handshake = static_cast<int64_t>(std::stoull(fields[4])); }
            catch (...) {}
            // fields[5] = transfer-rx (bytes)
            try { p.rx_bytes = std::stoull(fields[5]); }
            catch (...) {}
            // fields[6] = transfer-tx (bytes)
            try { p.tx_bytes = std::stoull(fields[6]); }
            catch (...) {}
            // fields[7] = persistent-keepalive
            if (fields[7] != "off") {
                try { p.keepalive = static_cast<uint16_t>(std::stoul(fields[7])); }
                catch (...) {}
            }

            p.is_online = (p.last_handshake > 0 &&
                           (std::time(nullptr) - p.last_handshake) < 180);

            // Match against known mesh_peers to fill in node_id, hostname
            for (const auto& known : mesh_peers) {
                if (known.wg_pubkey == p.wg_pubkey) {
                    p.node_id  = known.node_id;
                    p.hostname = known.hostname;
                    p.private_subnet = known.private_subnet;
                    break;
                }
            }

            ms.total_rx_bytes += p.rx_bytes;
            ms.total_tx_bytes += p.tx_bytes;
            if (p.is_online) ++ms.online_count;
            ms.peers.push_back(std::move(p));
        }
        ms.peer_count = static_cast<uint32_t>(ms.peers.size());
        return ms;
    }
};

// ---------------------------------------------------------------------------
// Constructor / Destructor / Move
// ---------------------------------------------------------------------------

WireGuardTunnel::WireGuardTunnel()
    : impl_{std::make_unique<Impl>()} {}

WireGuardTunnel::~WireGuardTunnel() {
    if (impl_) {
        bring_down(); // bring_down() safely handles the not-active case
    }
}

WireGuardTunnel::WireGuardTunnel(WireGuardTunnel&&) noexcept = default;
WireGuardTunnel& WireGuardTunnel::operator=(WireGuardTunnel&&) noexcept = default;

// ---------------------------------------------------------------------------
// generate_keypair
// ---------------------------------------------------------------------------

std::pair<std::string, std::string> WireGuardTunnel::generate_keypair() {
    // WireGuard uses Curve25519. libsodium's crypto_scalarmult_base does
    // the same base-point multiplication as wg genkey / wg pubkey.
    uint8_t privkey[32];
    uint8_t pubkey[32];

    // Generate 32 random bytes and clamp per Curve25519 spec
    randombytes_buf(privkey, 32);
    privkey[0]  &= 248;
    privkey[31] &= 127;
    privkey[31] |= 64;

    // Derive public key: pubkey = privkey * G
    crypto_scalarmult_base(pubkey, privkey);

    auto priv_b64 = wg_base64_encode(privkey, 32);
    auto pub_b64  = wg_base64_encode(pubkey, 32);

    sodium_memzero(privkey, 32);

    return {priv_b64, pub_b64};
}

// ---------------------------------------------------------------------------
// get_wg_config_string (works on all platforms)
// ---------------------------------------------------------------------------

std::string WireGuardTunnel::get_wg_config_string() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->build_config_string();
}

// ---------------------------------------------------------------------------
// Platform: Linux (not Android)
// ---------------------------------------------------------------------------

#if defined(__linux__) && !defined(__ANDROID__)

StatusResult WireGuardTunnel::bring_up(const WireGuardConfig& config) {
    std::lock_guard lock(impl_->mutex);
    StatusResult result;
    impl_->config = config;

    auto path = impl_->write_temp_config();
    if (path.empty()) {
        result.error = "failed to write WireGuard config to temp file";
        return result;
    }

    // Try wg-quick first, fall back to BoringTun if not available
    std::string cmd = "wg-quick up " + path + " 2>&1";
    spdlog::info("[WireGuardTunnel] bringing up tunnel (Linux): {}", cmd);

    auto [rc, output] = Impl::exec_cmd(cmd);
    if (rc != 0) {
        spdlog::warn("[WireGuardTunnel] wg-quick not available (rc={}), "
                     "falling back to BoringTun userspace", rc);
        std::remove(path.c_str());

        auto bt_result = impl_->boringtun.bring_up(config);
        if (!bt_result) {
            result.error = "BoringTun fallback failed: " + bt_result.error;
            spdlog::error("[WireGuardTunnel] {}", result.error);
            return result;
        }

        impl_->active = true;
        impl_->using_boringtun = true;
        result.ok = true;
        spdlog::info("[WireGuardTunnel] tunnel up via BoringTun (Linux): ip={}",
                      config.tunnel_ip);
        return result;
    }

    impl_->active = true;
    impl_->using_boringtun = false;
    impl_->iface_name = "lnsdk_wg0";
    result.ok = true;
    spdlog::info("[WireGuardTunnel] tunnel up via wg-quick (Linux): ip={}", config.tunnel_ip);
    return result;
}

StatusResult WireGuardTunnel::bring_down() {
    std::lock_guard lock(impl_->mutex);
    StatusResult result;
    if (!impl_->active) {
        result.error = "tunnel is not active";
        return result;
    }

    if (impl_->using_boringtun) {
        auto bt_result = impl_->boringtun.bring_down();
        impl_->active = false;
        impl_->using_boringtun = false;
        result.ok = bt_result.ok;
        result.error = bt_result.error;
        spdlog::info("[WireGuardTunnel] BoringTun tunnel down (Linux)");
        return result;
    }

    std::string cmd = "wg-quick down " + impl_->config_path + " 2>&1";
    spdlog::info("[WireGuardTunnel] tearing down tunnel: {}", cmd);

    auto [rc, output] = Impl::exec_cmd(cmd);
    if (rc != 0) {
        result.error = "wg-quick down failed (rc=" + std::to_string(rc) + "): " + output;
        spdlog::error("[WireGuardTunnel] {}", result.error);
        return result;
    }

    impl_->active = false;
    std::remove(impl_->config_path.c_str());
    impl_->config_path.clear();

    result.ok = true;
    spdlog::info("[WireGuardTunnel] tunnel down");
    return result;
}

TunnelStatus WireGuardTunnel::status() const {
    std::lock_guard lock(impl_->mutex);
    if (!impl_->active) {
        TunnelStatus st;
        st.is_up = false;
        return st;
    }

    if (impl_->using_boringtun) {
        return impl_->boringtun.status();
    }

    auto [rc, output] = Impl::exec_cmd("wg show " + impl_->iface_name + " 2>&1");
    if (rc != 0) {
        TunnelStatus st;
        st.is_up = false;
        return st;
    }
    return impl_->parse_wg_show(output);
}

StatusResult WireGuardTunnel::update_endpoint(const std::string& server_pubkey,
                                               const std::string& server_endpoint) {
    std::lock_guard lock(impl_->mutex);
    StatusResult result;
    if (!impl_->active) {
        result.error = "tunnel is not active";
        return result;
    }

    if (impl_->using_boringtun) {
        return impl_->boringtun.update_endpoint(server_pubkey, server_endpoint);
    }

    std::string cmd = "wg set " + impl_->iface_name +
                      " peer " + server_pubkey +
                      " endpoint " + server_endpoint + " 2>&1";
    auto [rc, output] = Impl::exec_cmd(cmd);
    if (rc != 0) {
        result.error = "wg set failed: " + output;
        return result;
    }

    impl_->config.server_public_key = server_pubkey;
    impl_->config.server_endpoint   = server_endpoint;
    result.ok = true;
    return result;
}

bool WireGuardTunnel::is_active() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->active;
}

// ---------------------------------------------------------------------------
// Platform: macOS (not iOS)
// ---------------------------------------------------------------------------

#elif defined(__APPLE__) && TARGET_OS_MAC && !TARGET_OS_IPHONE

StatusResult WireGuardTunnel::bring_up(const WireGuardConfig& config) {
    std::lock_guard lock(impl_->mutex);
    StatusResult result;
    impl_->config = config;

    auto path = impl_->write_temp_config();
    if (path.empty()) {
        result.error = "failed to write WireGuard config to temp file";
        return result;
    }

    // macOS: Try wg-quick first, fall back to BoringTun if not available.
    std::string cmd = "wg-quick up " + path + " 2>&1";
    spdlog::info("[WireGuardTunnel] bringing up tunnel (macOS): {}", cmd);

    auto [rc, output] = Impl::exec_cmd(cmd);
    if (rc != 0) {
        spdlog::warn("[WireGuardTunnel] wg-quick not available (rc={}), "
                     "falling back to BoringTun userspace", rc);

        // Clean up temp config — BoringTun doesn't need it
        std::remove(path.c_str());

        auto bt_result = impl_->boringtun.bring_up(config);
        if (!bt_result) {
            result.error = "BoringTun fallback failed: " + bt_result.error;
            spdlog::error("[WireGuardTunnel] {}", result.error);
            return result;
        }

        impl_->active = true;
        impl_->using_boringtun = true;
        result.ok = true;
        spdlog::info("[WireGuardTunnel] tunnel up via BoringTun (macOS): ip={}",
                      config.tunnel_ip);
        return result;
    }

    impl_->active = true;
    impl_->using_boringtun = false;
    impl_->iface_name = "lnsdk_wg0";
    result.ok = true;
    spdlog::info("[WireGuardTunnel] tunnel up via wg-quick (macOS): ip={}", config.tunnel_ip);
    return result;
}

StatusResult WireGuardTunnel::bring_down() {
    std::lock_guard lock(impl_->mutex);
    StatusResult result;
    if (!impl_->active) {
        result.error = "tunnel is not active";
        return result;
    }

    if (impl_->using_boringtun) {
        auto bt_result = impl_->boringtun.bring_down();
        impl_->active = false;
        impl_->using_boringtun = false;
        result.ok = bt_result.ok;
        result.error = bt_result.error;
        spdlog::info("[WireGuardTunnel] BoringTun tunnel down (macOS)");
        return result;
    }

    std::string cmd = "wg-quick down " + impl_->config_path + " 2>&1";
    spdlog::info("[WireGuardTunnel] tearing down tunnel (macOS): {}", cmd);

    auto [rc, output] = Impl::exec_cmd(cmd);
    if (rc != 0) {
        result.error = "wg-quick down failed (rc=" + std::to_string(rc) + "): " + output;
        spdlog::error("[WireGuardTunnel] {}", result.error);
        return result;
    }

    impl_->active = false;
    std::remove(impl_->config_path.c_str());
    impl_->config_path.clear();

    result.ok = true;
    spdlog::info("[WireGuardTunnel] tunnel down (macOS)");
    return result;
}

TunnelStatus WireGuardTunnel::status() const {
    std::lock_guard lock(impl_->mutex);
    if (!impl_->active) {
        TunnelStatus st;
        st.is_up = false;
        return st;
    }

    if (impl_->using_boringtun) {
        return impl_->boringtun.status();
    }

    auto [rc, output] = Impl::exec_cmd("wg show " + impl_->iface_name + " 2>&1");
    if (rc != 0) {
        auto [rc2, output2] = Impl::exec_cmd("wg show 2>&1");
        if (rc2 != 0) {
            TunnelStatus st;
            st.is_up = false;
            return st;
        }
        return impl_->parse_wg_show(output2);
    }
    return impl_->parse_wg_show(output);
}

StatusResult WireGuardTunnel::update_endpoint(const std::string& server_pubkey,
                                               const std::string& server_endpoint) {
    std::lock_guard lock(impl_->mutex);
    StatusResult result;
    if (!impl_->active) {
        result.error = "tunnel is not active";
        return result;
    }

    if (impl_->using_boringtun) {
        return impl_->boringtun.update_endpoint(server_pubkey, server_endpoint);
    }

    std::string cmd = "wg set " + impl_->iface_name +
                      " peer " + server_pubkey +
                      " endpoint " + server_endpoint + " 2>&1";
    auto [rc, output] = Impl::exec_cmd(cmd);
    if (rc != 0) {
        result.error = "wg set failed: " + output;
        return result;
    }

    impl_->config.server_public_key = server_pubkey;
    impl_->config.server_endpoint   = server_endpoint;
    result.ok = true;
    return result;
}

bool WireGuardTunnel::is_active() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->active;
}

// ---------------------------------------------------------------------------
// Platform: Windows
// ---------------------------------------------------------------------------

#elif defined(_WIN32)

StatusResult WireGuardTunnel::bring_up(const WireGuardConfig& config) {
    std::lock_guard lock(impl_->mutex);
    StatusResult result;
    impl_->config = config;

    auto path = impl_->write_temp_config();
    if (path.empty()) {
        result.error = "failed to write WireGuard config to temp file";
        return result;
    }

    // Windows: Use wireguard.exe to install and start a tunnel service.
    // The official WireGuard Windows client exposes /installtunnelservice.
    // Requires the WireGuard Windows client to be installed.
    std::string cmd = "\"C:\\Program Files\\WireGuard\\wireguard.exe\" "
                      "/installtunnelservice \"" + path + "\" 2>&1";
    spdlog::info("[WireGuardTunnel] bringing up tunnel (Windows): {}", cmd);

    auto [rc, output] = Impl::exec_cmd(cmd);
    if (rc != 0) {
        // Fallback: try wg-quick if available (e.g., via WSL or MSYS2)
        cmd = "wg-quick up " + path + " 2>&1";
        auto [rc2, output2] = Impl::exec_cmd(cmd);
        if (rc2 != 0) {
            spdlog::warn("[WireGuardTunnel] wireguard.exe and wg-quick not available, "
                         "falling back to BoringTun userspace");

            // Clean up temp config — BoringTun doesn't need it
            std::remove(path.c_str());

            auto bt_result = impl_->boringtun.bring_up(config);
            if (!bt_result) {
                result.error = "BoringTun fallback failed: " + bt_result.error;
                spdlog::error("[WireGuardTunnel] {}", result.error);
                return result;
            }

            impl_->active = true;
            impl_->using_boringtun = true;
            result.ok = true;
            spdlog::info("[WireGuardTunnel] tunnel up via BoringTun (Windows): ip={}",
                          config.tunnel_ip);
            return result;
        }
    }

    impl_->active = true;
    impl_->using_boringtun = false;
    impl_->iface_name = "lnsdk_wg0";
    result.ok = true;
    spdlog::info("[WireGuardTunnel] tunnel up (Windows): ip={}", config.tunnel_ip);
    return result;
}

StatusResult WireGuardTunnel::bring_down() {
    std::lock_guard lock(impl_->mutex);
    StatusResult result;
    if (!impl_->active) {
        result.error = "tunnel is not active";
        return result;
    }

    if (impl_->using_boringtun) {
        auto bt_result = impl_->boringtun.bring_down();
        impl_->active = false;
        impl_->using_boringtun = false;
        return bt_result;
    }

    // Try uninstalling the tunnel service
    std::string cmd = "\"C:\\Program Files\\WireGuard\\wireguard.exe\" "
                      "/uninstalltunnelservice lnsdk_wg0 2>&1";
    spdlog::info("[WireGuardTunnel] tearing down tunnel (Windows): {}", cmd);

    auto [rc, output] = Impl::exec_cmd(cmd);
    if (rc != 0) {
        // Fallback
        cmd = "wg-quick down " + impl_->config_path + " 2>&1";
        auto [rc2, output2] = Impl::exec_cmd(cmd);
        if (rc2 != 0) {
            result.error = "failed to tear down tunnel: " + output + "; " + output2;
            spdlog::error("[WireGuardTunnel] {}", result.error);
            return result;
        }
    }

    impl_->active = false;
    std::remove(impl_->config_path.c_str());
    impl_->config_path.clear();

    result.ok = true;
    spdlog::info("[WireGuardTunnel] tunnel down (Windows)");
    return result;
}

TunnelStatus WireGuardTunnel::status() const {
    std::lock_guard lock(impl_->mutex);
    if (!impl_->active) {
        TunnelStatus st;
        st.is_up = false;
        return st;
    }

    if (impl_->using_boringtun) {
        return impl_->boringtun.status();
    }

    auto [rc, output] = Impl::exec_cmd("wg show " + impl_->iface_name + " 2>&1");
    if (rc != 0) {
        TunnelStatus st;
        st.is_up = false;
        return st;
    }
    return impl_->parse_wg_show(output);
}

StatusResult WireGuardTunnel::update_endpoint(const std::string& server_pubkey,
                                               const std::string& server_endpoint) {
    std::lock_guard lock(impl_->mutex);
    StatusResult result;
    if (!impl_->active) {
        result.error = "tunnel is not active";
        return result;
    }

    if (impl_->using_boringtun) {
        return impl_->boringtun.update_endpoint(server_pubkey, server_endpoint);
    }

    std::string cmd = "wg set " + impl_->iface_name +
                      " peer " + server_pubkey +
                      " endpoint " + server_endpoint + " 2>&1";
    auto [rc, output] = Impl::exec_cmd(cmd);
    if (rc != 0) {
        result.error = "wg set failed: " + output;
        return result;
    }

    impl_->config.server_public_key = server_pubkey;
    impl_->config.server_endpoint   = server_endpoint;
    result.ok = true;
    return result;
}

bool WireGuardTunnel::is_active() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->active;
}

// ---------------------------------------------------------------------------
// Platform: iOS
// ---------------------------------------------------------------------------

#elif defined(__APPLE__) && TARGET_OS_IPHONE

// iOS cannot directly manage VPN tunnels from a library. The app must use
// NetworkExtension framework (NETunnelProviderManager) in its App Extension.
// The SDK provides config generation; the app handles the NE lifecycle.

StatusResult WireGuardTunnel::bring_up(const WireGuardConfig& config) {
    std::lock_guard lock(impl_->mutex);
    StatusResult result;
    impl_->config = config;
    impl_->active = true; // Mark as "configured" — the app manages the actual tunnel
    result.ok = true;
    spdlog::info("[WireGuardTunnel] (iOS) config stored — app must start NETunnelProviderManager");
    return result;
}

StatusResult WireGuardTunnel::bring_down() {
    std::lock_guard lock(impl_->mutex);
    StatusResult result;
    impl_->active = false;
    result.ok = true;
    spdlog::info("[WireGuardTunnel] (iOS) config cleared — app must stop NETunnelProviderManager");
    return result;
}

TunnelStatus WireGuardTunnel::status() const {
    std::lock_guard lock(impl_->mutex);
    TunnelStatus st;
    st.is_up          = impl_->active;
    st.tunnel_ip      = impl_->config.tunnel_ip;
    st.server_endpoint = impl_->config.server_endpoint;
    // Actual stats must be obtained from NetworkExtension by the app
    return st;
}

StatusResult WireGuardTunnel::update_endpoint(const std::string& server_pubkey,
                                               const std::string& server_endpoint) {
    std::lock_guard lock(impl_->mutex);
    StatusResult result;
    impl_->config.server_public_key = server_pubkey;
    impl_->config.server_endpoint   = server_endpoint;
    result.ok = true;
    spdlog::info("[WireGuardTunnel] (iOS) endpoint updated — app must restart tunnel");
    return result;
}

bool WireGuardTunnel::is_active() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->active;
}

// ---------------------------------------------------------------------------
// Platform: Android
// ---------------------------------------------------------------------------

#elif defined(__ANDROID__)

// Android cannot directly manage VPN tunnels from native code. The app must
// use VpnService + wireguard-android. The SDK provides config generation;
// the Java/Kotlin layer handles the VPN lifecycle.

StatusResult WireGuardTunnel::bring_up(const WireGuardConfig& config) {
    std::lock_guard lock(impl_->mutex);
    StatusResult result;
    impl_->config = config;
    impl_->active = true; // Mark as "configured"
    result.ok = true;
    spdlog::info("[WireGuardTunnel] (Android) config stored — app must start VpnService");
    return result;
}

StatusResult WireGuardTunnel::bring_down() {
    std::lock_guard lock(impl_->mutex);
    StatusResult result;
    impl_->active = false;
    result.ok = true;
    spdlog::info("[WireGuardTunnel] (Android) config cleared — app must stop VpnService");
    return result;
}

TunnelStatus WireGuardTunnel::status() const {
    std::lock_guard lock(impl_->mutex);
    TunnelStatus st;
    st.is_up          = impl_->active;
    st.tunnel_ip      = impl_->config.tunnel_ip;
    st.server_endpoint = impl_->config.server_endpoint;
    // Actual stats must be obtained from VpnService by the app
    return st;
}

StatusResult WireGuardTunnel::update_endpoint(const std::string& server_pubkey,
                                               const std::string& server_endpoint) {
    std::lock_guard lock(impl_->mutex);
    StatusResult result;
    impl_->config.server_public_key = server_pubkey;
    impl_->config.server_endpoint   = server_endpoint;
    result.ok = true;
    spdlog::info("[WireGuardTunnel] (Android) endpoint updated — app must restart tunnel");
    return result;
}

bool WireGuardTunnel::is_active() const {
    std::lock_guard lock(impl_->mutex);
    return impl_->active;
}

// ---------------------------------------------------------------------------
// Fallback: unsupported platform
// ---------------------------------------------------------------------------

#else

StatusResult WireGuardTunnel::bring_up(const WireGuardConfig& config) {
    std::lock_guard lock(impl_->mutex);
    StatusResult result;
    impl_->config = config;
    result.error = "WireGuard tunnel management not supported on this platform";
    spdlog::warn("[WireGuardTunnel] {}", result.error);
    return result;
}

StatusResult WireGuardTunnel::bring_down() {
    std::lock_guard lock(impl_->mutex);
    StatusResult result;
    result.error = "WireGuard tunnel management not supported on this platform";
    return result;
}

TunnelStatus WireGuardTunnel::status() const {
    std::lock_guard lock(impl_->mutex);
    return {};
}

StatusResult WireGuardTunnel::update_endpoint(const std::string& /*server_pubkey*/,
                                               const std::string& /*server_endpoint*/) {
    std::lock_guard lock(impl_->mutex);
    StatusResult result;
    result.error = "WireGuard tunnel management not supported on this platform";
    return result;
}

bool WireGuardTunnel::is_active() const {
    std::lock_guard lock(impl_->mutex);
    return false;
}

#endif

// ---------------------------------------------------------------------------
// Multi-peer mesh methods (platform-independent)
// ---------------------------------------------------------------------------

StatusResult WireGuardTunnel::add_peer(const MeshPeer& peer) {
    std::lock_guard lock(impl_->mutex);
    StatusResult result;

    if (!impl_->active) {
        result.error = "tunnel is not active";
        return result;
    }
    if (peer.wg_pubkey.empty()) {
        result.error = "peer wg_pubkey is required";
        return result;
    }

    // If using BoringTun, delegate
    if (impl_->using_boringtun) {
        result = impl_->boringtun.add_peer(peer);
        if (result) {
            impl_->mesh_peers.push_back(peer);
        }
        return result;
    }

    // wg-quick path: use `wg set` to add the peer
    auto allowed = Impl::peer_allowed_ips(peer);
    if (allowed.empty()) {
        result.error = "peer has no tunnel_ip or private_subnet for allowed-ips";
        return result;
    }

    std::string cmd = "wg set " + impl_->iface_name +
                      " peer " + peer.wg_pubkey +
                      " allowed-ips " + allowed;
    if (!peer.endpoint.empty()) {
        cmd += " endpoint " + peer.endpoint;
    }
    cmd += " persistent-keepalive " + std::to_string(peer.keepalive > 0 ? peer.keepalive : 25);
    cmd += " 2>&1";

    auto [rc, output] = Impl::exec_cmd(cmd);
    if (rc != 0) {
        result.error = "wg set add_peer failed: " + output;
        return result;
    }

    impl_->mesh_peers.push_back(peer);
    result.ok = true;
    spdlog::debug("[WireGuardTunnel] added mesh peer {} ({})",
                   peer.node_id, peer.wg_pubkey.substr(0, 8));
    return result;
}

StatusResult WireGuardTunnel::remove_peer(const std::string& wg_pubkey) {
    std::lock_guard lock(impl_->mutex);
    StatusResult result;

    if (!impl_->active) {
        result.error = "tunnel is not active";
        return result;
    }

    if (impl_->using_boringtun) {
        result = impl_->boringtun.remove_peer(wg_pubkey);
        if (result) {
            std::erase_if(impl_->mesh_peers,
                [&](const MeshPeer& p) { return p.wg_pubkey == wg_pubkey; });
        }
        return result;
    }

    std::string cmd = "wg set " + impl_->iface_name +
                      " peer " + wg_pubkey + " remove 2>&1";
    auto [rc, output] = Impl::exec_cmd(cmd);
    if (rc != 0) {
        result.error = "wg set remove_peer failed: " + output;
        return result;
    }

    std::erase_if(impl_->mesh_peers,
        [&](const MeshPeer& p) { return p.wg_pubkey == wg_pubkey; });
    result.ok = true;
    spdlog::debug("[WireGuardTunnel] removed mesh peer {}", wg_pubkey.substr(0, 8));
    return result;
}

StatusResult WireGuardTunnel::update_peer_endpoint(const std::string& wg_pubkey,
                                                    const std::string& endpoint) {
    std::lock_guard lock(impl_->mutex);
    StatusResult result;

    if (!impl_->active) {
        result.error = "tunnel is not active";
        return result;
    }

    if (impl_->using_boringtun) {
        result = impl_->boringtun.update_peer_endpoint(wg_pubkey, endpoint);
        if (result) {
            for (auto& p : impl_->mesh_peers) {
                if (p.wg_pubkey == wg_pubkey) { p.endpoint = endpoint; break; }
            }
        }
        return result;
    }

    std::string cmd = "wg set " + impl_->iface_name +
                      " peer " + wg_pubkey +
                      " endpoint " + endpoint + " 2>&1";
    auto [rc, output] = Impl::exec_cmd(cmd);
    if (rc != 0) {
        result.error = "wg set update_peer_endpoint failed: " + output;
        return result;
    }

    for (auto& p : impl_->mesh_peers) {
        if (p.wg_pubkey == wg_pubkey) { p.endpoint = endpoint; break; }
    }
    result.ok = true;
    return result;
}

MeshTunnelStatus WireGuardTunnel::mesh_status() const {
    std::lock_guard lock(impl_->mutex);

    if (!impl_->active) {
        MeshTunnelStatus ms;
        ms.is_up = false;
        return ms;
    }

    if (impl_->using_boringtun) {
        return impl_->boringtun.mesh_status();
    }

    // Parse `wg show <iface> dump` for full multi-peer status
    auto [rc, output] = Impl::exec_cmd("wg show " + impl_->iface_name + " dump 2>&1");
    if (rc != 0) {
        MeshTunnelStatus ms;
        ms.is_up = true;
        ms.tunnel_ip = impl_->config.tunnel_ip;
        ms.peers = impl_->mesh_peers; // return cached data
        ms.peer_count = static_cast<uint32_t>(ms.peers.size());
        return ms;
    }
    return impl_->parse_wg_dump(output);
}

StatusResult WireGuardTunnel::sync_peers(const std::vector<MeshPeer>& desired_peers) {
    std::lock_guard lock(impl_->mutex);
    StatusResult result;

    if (!impl_->active) {
        result.error = "tunnel is not active";
        return result;
    }

    if (impl_->using_boringtun) {
        result = impl_->boringtun.sync_peers(desired_peers);
        if (result) impl_->mesh_peers = desired_peers;
        return result;
    }

    // Build sets for diffing
    std::unordered_map<std::string, const MeshPeer*> desired_map;
    for (const auto& p : desired_peers) {
        desired_map[p.wg_pubkey] = &p;
    }

    std::unordered_map<std::string, const MeshPeer*> current_map;
    for (const auto& p : impl_->mesh_peers) {
        current_map[p.wg_pubkey] = &p;
    }

    // Remove peers not in desired set
    for (const auto& [pubkey, _] : current_map) {
        if (!desired_map.contains(pubkey)) {
            std::string cmd = "wg set " + impl_->iface_name +
                              " peer " + pubkey + " remove 2>&1";
            auto [rc, output] = Impl::exec_cmd(cmd);
            if (rc != 0) {
                spdlog::warn("[WireGuardTunnel] sync: failed to remove peer {}: {}",
                              pubkey.substr(0, 8), output);
            }
        }
    }

    // Add or update peers in desired set
    for (const auto& [pubkey, peer_ptr] : desired_map) {
        auto allowed = Impl::peer_allowed_ips(*peer_ptr);
        if (allowed.empty()) continue;

        std::string cmd = "wg set " + impl_->iface_name +
                          " peer " + pubkey +
                          " allowed-ips " + allowed;
        if (!peer_ptr->endpoint.empty()) {
            cmd += " endpoint " + peer_ptr->endpoint;
        }
        cmd += " persistent-keepalive " +
               std::to_string(peer_ptr->keepalive > 0 ? peer_ptr->keepalive : 25);
        cmd += " 2>&1";

        auto [rc, output] = Impl::exec_cmd(cmd);
        if (rc != 0) {
            spdlog::warn("[WireGuardTunnel] sync: failed to set peer {}: {}",
                          pubkey.substr(0, 8), output);
        }
    }

    impl_->mesh_peers = desired_peers;
    result.ok = true;
    spdlog::info("[WireGuardTunnel] synced {} mesh peers", desired_peers.size());
    return result;
}

} // namespace lnsdk
