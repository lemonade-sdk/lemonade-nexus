#include <LemonadeNexusSDK/WireGuardTunnel.hpp>

#include <sodium.h>
#include <spdlog/spdlog.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>

// Platform detection
#if defined(__APPLE__)
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

static std::vector<uint8_t> wg_base64_decode(const std::string& b64) {
    std::vector<uint8_t> out(b64.size()); // over-allocate is fine
    std::size_t bin_len = 0;
    if (sodium_base642bin(out.data(), out.size(), b64.c_str(), b64.size(),
                          nullptr, &bin_len, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0) {
        return {};
    }
    out.resize(bin_len);
    return out;
}

// ---------------------------------------------------------------------------
// PIMPL
// ---------------------------------------------------------------------------

struct WireGuardTunnel::Impl {
    WireGuardConfig config;
    bool            active{false};
    std::string     iface_name;     // e.g. "wg0", "utun7"
    std::string     config_path;    // temp file path for wg-quick

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
                    std::string val = line.substr(vpos + 2);
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
                    std::string val = line.substr(vpos + 2);
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
};

// ---------------------------------------------------------------------------
// Constructor / Destructor / Move
// ---------------------------------------------------------------------------

WireGuardTunnel::WireGuardTunnel()
    : impl_{std::make_unique<Impl>()} {}

WireGuardTunnel::~WireGuardTunnel() {
    if (impl_ && impl_->active) {
        bring_down();
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
    return impl_->build_config_string();
}

// ---------------------------------------------------------------------------
// Platform: Linux (not Android)
// ---------------------------------------------------------------------------

#if defined(__linux__) && !defined(__ANDROID__)

StatusResult WireGuardTunnel::bring_up(const WireGuardConfig& config) {
    StatusResult result;
    impl_->config = config;

    auto path = impl_->write_temp_config();
    if (path.empty()) {
        result.error = "failed to write WireGuard config to temp file";
        return result;
    }

    // Use wg-quick to bring up the interface
    std::string cmd = "wg-quick up " + path + " 2>&1";
    spdlog::info("[WireGuardTunnel] bringing up tunnel: {}", cmd);

    auto [rc, output] = Impl::exec_cmd(cmd);
    if (rc != 0) {
        result.error = "wg-quick up failed (rc=" + std::to_string(rc) + "): " + output;
        spdlog::error("[WireGuardTunnel] {}", result.error);
        return result;
    }

    impl_->active = true;
    impl_->iface_name = "lnsdk_wg0";
    result.ok = true;
    spdlog::info("[WireGuardTunnel] tunnel up: ip={}", config.tunnel_ip);
    return result;
}

StatusResult WireGuardTunnel::bring_down() {
    StatusResult result;
    if (!impl_->active) {
        result.error = "tunnel is not active";
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

    // Clean up temp config
    std::remove(impl_->config_path.c_str());
    impl_->config_path.clear();

    result.ok = true;
    spdlog::info("[WireGuardTunnel] tunnel down");
    return result;
}

TunnelStatus WireGuardTunnel::status() const {
    if (!impl_->active) {
        TunnelStatus st;
        st.is_up = false;
        return st;
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
    StatusResult result;
    if (!impl_->active) {
        result.error = "tunnel is not active";
        return result;
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
    return impl_->active;
}

// ---------------------------------------------------------------------------
// Platform: macOS (not iOS)
// ---------------------------------------------------------------------------

#elif defined(__APPLE__) && TARGET_OS_MAC && !TARGET_OS_IPHONE

StatusResult WireGuardTunnel::bring_up(const WireGuardConfig& config) {
    StatusResult result;
    impl_->config = config;

    auto path = impl_->write_temp_config();
    if (path.empty()) {
        result.error = "failed to write WireGuard config to temp file";
        return result;
    }

    // macOS: Use the WireGuard userspace tools (wireguard-go + wg-quick).
    // brew install wireguard-tools installs both wg-quick and wireguard-go.
    // wg-quick on macOS creates a utun interface and manages routing.
    std::string cmd = "wg-quick up " + path + " 2>&1";
    spdlog::info("[WireGuardTunnel] bringing up tunnel (macOS): {}", cmd);

    auto [rc, output] = Impl::exec_cmd(cmd);
    if (rc != 0) {
        result.error = "wg-quick up failed (rc=" + std::to_string(rc) + "): " + output;
        spdlog::error("[WireGuardTunnel] {}", result.error);
        return result;
    }

    impl_->active = true;
    // wg-quick on macOS typically picks utunN. Parse from output if needed.
    // For now, use a stable name derived from the config file.
    impl_->iface_name = "lnsdk_wg0";
    result.ok = true;
    spdlog::info("[WireGuardTunnel] tunnel up (macOS): ip={}", config.tunnel_ip);
    return result;
}

StatusResult WireGuardTunnel::bring_down() {
    StatusResult result;
    if (!impl_->active) {
        result.error = "tunnel is not active";
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
    if (!impl_->active) {
        TunnelStatus st;
        st.is_up = false;
        return st;
    }

    // On macOS, wg show works with the interface name.
    // wg-quick names the interface from the config file basename.
    auto [rc, output] = Impl::exec_cmd("wg show " + impl_->iface_name + " 2>&1");
    if (rc != 0) {
        // Try the default utun interface
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
    StatusResult result;
    if (!impl_->active) {
        result.error = "tunnel is not active";
        return result;
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
    return impl_->active;
}

// ---------------------------------------------------------------------------
// Platform: Windows
// ---------------------------------------------------------------------------

#elif defined(_WIN32)

StatusResult WireGuardTunnel::bring_up(const WireGuardConfig& config) {
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
            result.error = "wireguard.exe /installtunnelservice failed (rc=" +
                           std::to_string(rc) + "): " + output +
                           "; wg-quick fallback also failed: " + output2;
            spdlog::error("[WireGuardTunnel] {}", result.error);
            return result;
        }
    }

    impl_->active = true;
    impl_->iface_name = "lnsdk_wg0";
    result.ok = true;
    spdlog::info("[WireGuardTunnel] tunnel up (Windows): ip={}", config.tunnel_ip);
    return result;
}

StatusResult WireGuardTunnel::bring_down() {
    StatusResult result;
    if (!impl_->active) {
        result.error = "tunnel is not active";
        return result;
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
    if (!impl_->active) {
        TunnelStatus st;
        st.is_up = false;
        return st;
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
    StatusResult result;
    if (!impl_->active) {
        result.error = "tunnel is not active";
        return result;
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
    StatusResult result;
    impl_->config = config;
    impl_->active = true; // Mark as "configured" — the app manages the actual tunnel
    result.ok = true;
    spdlog::info("[WireGuardTunnel] (iOS) config stored — app must start NETunnelProviderManager");
    return result;
}

StatusResult WireGuardTunnel::bring_down() {
    StatusResult result;
    impl_->active = false;
    result.ok = true;
    spdlog::info("[WireGuardTunnel] (iOS) config cleared — app must stop NETunnelProviderManager");
    return result;
}

TunnelStatus WireGuardTunnel::status() const {
    TunnelStatus st;
    st.is_up          = impl_->active;
    st.tunnel_ip      = impl_->config.tunnel_ip;
    st.server_endpoint = impl_->config.server_endpoint;
    // Actual stats must be obtained from NetworkExtension by the app
    return st;
}

StatusResult WireGuardTunnel::update_endpoint(const std::string& server_pubkey,
                                               const std::string& server_endpoint) {
    StatusResult result;
    impl_->config.server_public_key = server_pubkey;
    impl_->config.server_endpoint   = server_endpoint;
    result.ok = true;
    spdlog::info("[WireGuardTunnel] (iOS) endpoint updated — app must restart tunnel");
    return result;
}

bool WireGuardTunnel::is_active() const {
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
    StatusResult result;
    impl_->config = config;
    impl_->active = true; // Mark as "configured"
    result.ok = true;
    spdlog::info("[WireGuardTunnel] (Android) config stored — app must start VpnService");
    return result;
}

StatusResult WireGuardTunnel::bring_down() {
    StatusResult result;
    impl_->active = false;
    result.ok = true;
    spdlog::info("[WireGuardTunnel] (Android) config cleared — app must stop VpnService");
    return result;
}

TunnelStatus WireGuardTunnel::status() const {
    TunnelStatus st;
    st.is_up          = impl_->active;
    st.tunnel_ip      = impl_->config.tunnel_ip;
    st.server_endpoint = impl_->config.server_endpoint;
    // Actual stats must be obtained from VpnService by the app
    return st;
}

StatusResult WireGuardTunnel::update_endpoint(const std::string& server_pubkey,
                                               const std::string& server_endpoint) {
    StatusResult result;
    impl_->config.server_public_key = server_pubkey;
    impl_->config.server_endpoint   = server_endpoint;
    result.ok = true;
    spdlog::info("[WireGuardTunnel] (Android) endpoint updated — app must restart tunnel");
    return result;
}

bool WireGuardTunnel::is_active() const {
    return impl_->active;
}

// ---------------------------------------------------------------------------
// Fallback: unsupported platform
// ---------------------------------------------------------------------------

#else

StatusResult WireGuardTunnel::bring_up(const WireGuardConfig& config) {
    StatusResult result;
    impl_->config = config;
    result.error = "WireGuard tunnel management not supported on this platform";
    spdlog::warn("[WireGuardTunnel] {}", result.error);
    return result;
}

StatusResult WireGuardTunnel::bring_down() {
    StatusResult result;
    result.error = "WireGuard tunnel management not supported on this platform";
    return result;
}

TunnelStatus WireGuardTunnel::status() const {
    return {};
}

StatusResult WireGuardTunnel::update_endpoint(const std::string& /*server_pubkey*/,
                                               const std::string& /*server_endpoint*/) {
    StatusResult result;
    result.error = "WireGuard tunnel management not supported on this platform";
    return result;
}

bool WireGuardTunnel::is_active() const {
    return false;
}

#endif

} // namespace lnsdk
