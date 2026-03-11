#include <LemonadeNexus/WireGuard/WireGuardService.hpp>

#include <spdlog/spdlog.h>

#include <array>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <regex>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#ifdef HAS_EMBEDDABLE_WG
#include <arpa/inet.h>  // inet_pton, inet_ntop
#elif defined(__APPLE__) && defined(HAS_WIREGUARDKIT)
#include <LemonadeNexus/WireGuard/WireGuardAppleBridge.h>
#elif defined(_WIN32) && defined(HAS_WIREGUARD_NT)
#include <LemonadeNexus/WireGuard/WireGuardWindowsBridge.h>
#endif

namespace nexus::wireguard {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

WireGuardService::WireGuardService(std::string interface_name,
                                     std::filesystem::path config_dir)
    : interface_name_(std::move(interface_name)),
      config_dir_(std::move(config_dir))
{
}

// ---------------------------------------------------------------------------
// IService lifecycle
// ---------------------------------------------------------------------------

void WireGuardService::on_start() {
    // Validate the interface name early
    if (!is_valid_interface_name(interface_name_)) {
        spdlog::error("[{}] invalid interface name '{}' — refusing to start",
                       name(), interface_name_);
        return;
    }

#ifdef HAS_EMBEDDABLE_WG
    spdlog::info("[{}] started (interface: '{}', backend: embeddable-wg-library / netlink)",
                  name(), interface_name_);
#elif defined(__APPLE__) && defined(HAS_WIREGUARDKIT)
    spdlog::info("[{}] started (interface: '{}', backend: wireguard-go / utun, version: {})",
                  name(), interface_name_, wg_apple_version());
#elif defined(_WIN32) && defined(HAS_WIREGUARD_NT)
    spdlog::info("[{}] loading wireguard-nt (will auto-download if not present)...", name());
    if (wg_nt_init() < 0) {
        spdlog::error("[{}] failed to load wireguard.dll (auto-download also failed) — "
                       "check network connectivity or manually place wireguard.dll in the "
                       "application directory", name());
    } else {
        auto driver_ver = wg_nt_get_driver_version();
        spdlog::info("[{}] started (interface: '{}', backend: wireguard-nt, driver: {}.{})",
                      name(), interface_name_,
                      (driver_ver >> 16) & 0xFFFF, driver_ver & 0xFFFF);
    }
#else
    // CLI fallback — verify that the `wg` tool is reachable
    auto version = run_command("wg --version 2>/dev/null");
    if (version.empty()) {
        spdlog::warn("[{}] 'wg' command not found — WireGuard operations will fail "
                      "until wireguard-tools is installed", name());
    } else {
        // Trim trailing newline
        if (!version.empty() && version.back() == '\n') {
            version.pop_back();
        }
        spdlog::info("[{}] started (interface: '{}', backend: CLI, tools: '{}')",
                      name(), interface_name_, version);
    }

    // Verify that the `ip` tool is reachable
    auto ip_version = run_command("ip -V 2>/dev/null");
    if (ip_version.empty()) {
        spdlog::warn("[{}] 'ip' command not found — interface setup/teardown will fail "
                      "until iproute2 is installed", name());
    }
#endif

    // Ensure the config directory exists
    std::error_code ec;
    std::filesystem::create_directories(config_dir_, ec);
    if (ec) {
        spdlog::warn("[{}] failed to create config directory '{}': {}",
                      name(), config_dir_.string(), ec.message());
    }
}

void WireGuardService::on_stop() {
#if defined(__APPLE__) && defined(HAS_WIREGUARDKIT)
    if (tunnel_handle_ >= 0) {
        wg_apple_turn_off(tunnel_handle_);
        tunnel_handle_ = -1;
    }
    if (tunnel_utun_fd_ >= 0) {
        wg_apple_close_utun(tunnel_utun_fd_);
        tunnel_utun_fd_ = -1;
    }
    utun_name_.clear();
#elif defined(_WIN32) && defined(HAS_WIREGUARD_NT)
    if (nt_adapter_) {
        wg_nt_set_adapter_state(nt_adapter_, 0);
        wg_nt_close_adapter(nt_adapter_);
        nt_adapter_ = nullptr;
    }
    wg_nt_deinit();
#endif
    spdlog::info("[{}] stopped", name());
}

// ---------------------------------------------------------------------------
// Input validation helpers
// ---------------------------------------------------------------------------

bool WireGuardService::is_valid_pubkey(const std::string& key) {
    // WireGuard keys are 32 bytes encoded in base64 = 44 characters ending with '='
    if (key.size() != 44) {
        return false;
    }
    // Must be valid base64: [A-Za-z0-9+/] with trailing '='
    static const std::regex base64_re(R"(^[A-Za-z0-9+/]{43}=$)");
    return std::regex_match(key, base64_re);
}

bool WireGuardService::is_valid_endpoint(const std::string& ep) {
    if (ep.empty()) {
        return true; // empty endpoint is acceptable (peer without endpoint)
    }
    // IPv4:port — e.g. "1.2.3.4:51820"
    static const std::regex ipv4_ep_re(
        R"(^(\d{1,3}\.){3}\d{1,3}:\d{1,5}$)");
    // [IPv6]:port — e.g. "[::1]:51820"
    static const std::regex ipv6_ep_re(
        R"(^\[[0-9a-fA-F:]+\]:\d{1,5}$)");
    // hostname:port — e.g. "vpn.example.com:51820"
    static const std::regex host_ep_re(
        R"(^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*:\d{1,5}$)");
    return std::regex_match(ep, ipv4_ep_re) ||
           std::regex_match(ep, ipv6_ep_re) ||
           std::regex_match(ep, host_ep_re);
}

bool WireGuardService::is_valid_cidr(const std::string& cidr) {
    if (cidr.empty()) {
        return false;
    }
    // IPv4 CIDR: "10.64.0.1/32"
    static const std::regex ipv4_cidr_re(
        R"(^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$)");
    // IPv6 CIDR: "fd00::1/128"
    static const std::regex ipv6_cidr_re(
        R"(^[0-9a-fA-F:]+/\d{1,3}$)");
    return std::regex_match(cidr, ipv4_cidr_re) ||
           std::regex_match(cidr, ipv6_cidr_re);
}

bool WireGuardService::is_valid_allowed_ips(const std::string& allowed_ips) {
    if (allowed_ips.empty()) {
        return false;
    }
    // Split on comma (with optional whitespace)
    std::istringstream stream(allowed_ips);
    std::string token;
    while (std::getline(stream, token, ',')) {
        // Trim whitespace
        auto start = token.find_first_not_of(" \t");
        auto end   = token.find_last_not_of(" \t");
        if (start == std::string::npos) {
            return false;
        }
        auto trimmed = token.substr(start, end - start + 1);
        if (!is_valid_cidr(trimmed)) {
            return false;
        }
    }
    return true;
}

bool WireGuardService::is_valid_interface_name(const std::string& iface) {
    if (iface.empty() || iface.size() > 15) {
        return false; // Linux interface names are max 15 chars
    }
    // Only alphanumeric, hyphens, and underscores
    static const std::regex iface_re(R"(^[a-zA-Z0-9_-]+$)");
    return std::regex_match(iface, iface_re);
}

// ---------------------------------------------------------------------------
// Embeddable WireGuard C API helpers (Linux only)
// ---------------------------------------------------------------------------

#ifdef HAS_EMBEDDABLE_WG
namespace {

/// Decode a base64 WireGuard key (44 chars) into a wg_key.
/// Returns true on success.
bool base64_to_wg_key(const std::string& b64, wg_key& out) {
    if (b64.size() != 44) return false;
    wg_key_from_base64(&out, b64.c_str());
    return true;
}

/// Encode a wg_key as a base64 string (44 chars).
std::string wg_key_to_b64(const wg_key& key) {
    wg_key_b64_string b64;
    wg_key_to_base64(b64, key);
    return std::string(b64);
}

/// Parse "ip:port" or "[ipv6]:port" into a sockaddr.
/// Returns true on success.
bool parse_endpoint(const std::string& ep, sockaddr_storage& addr) {
    if (ep.empty()) return false;
    std::memset(&addr, 0, sizeof(addr));

    // Check for [IPv6]:port
    if (ep.front() == '[') {
        auto bracket = ep.find(']');
        if (bracket == std::string::npos) return false;
        auto colon = ep.find(':', bracket);
        if (colon == std::string::npos) return false;

        auto ip_str = ep.substr(1, bracket - 1);
        auto port_str = ep.substr(colon + 1);

        auto* sa6 = reinterpret_cast<sockaddr_in6*>(&addr);
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = htons(static_cast<uint16_t>(std::stoul(port_str)));
        if (inet_pton(AF_INET6, ip_str.c_str(), &sa6->sin6_addr) != 1) return false;
        return true;
    }

    // IPv4:port
    auto colon = ep.rfind(':');
    if (colon == std::string::npos) return false;

    auto ip_str = ep.substr(0, colon);
    auto port_str = ep.substr(colon + 1);

    auto* sa4 = reinterpret_cast<sockaddr_in*>(&addr);
    sa4->sin_family = AF_INET;
    sa4->sin_port = htons(static_cast<uint16_t>(std::stoul(port_str)));
    if (inet_pton(AF_INET, ip_str.c_str(), &sa4->sin_addr) != 1) return false;
    return true;
}

/// Format a sockaddr as "ip:port" string.
std::string format_endpoint(const sockaddr_storage& addr) {
    char buf[INET6_ADDRSTRLEN] = {};
    if (addr.ss_family == AF_INET) {
        auto* sa4 = reinterpret_cast<const sockaddr_in*>(&addr);
        inet_ntop(AF_INET, &sa4->sin_addr, buf, sizeof(buf));
        return std::string(buf) + ":" + std::to_string(ntohs(sa4->sin_port));
    } else if (addr.ss_family == AF_INET6) {
        auto* sa6 = reinterpret_cast<const sockaddr_in6*>(&addr);
        inet_ntop(AF_INET6, &sa6->sin6_addr, buf, sizeof(buf));
        return "[" + std::string(buf) + "]:" + std::to_string(ntohs(sa6->sin6_port));
    }
    return {};
}

/// Parse a CIDR string into an wg_allowedip struct.
/// Returns true on success.
bool parse_cidr_to_allowedip(const std::string& cidr, wg_allowedip& aip) {
    std::memset(&aip, 0, sizeof(aip));
    auto slash = cidr.find('/');
    if (slash == std::string::npos) return false;

    auto ip_str = cidr.substr(0, slash);
    auto prefix_str = cidr.substr(slash + 1);
    aip.cidr = static_cast<uint8_t>(std::stoul(prefix_str));

    // Try IPv4 first
    if (inet_pton(AF_INET, ip_str.c_str(), &aip.ip4) == 1) {
        aip.family = AF_INET;
        return true;
    }
    // Try IPv6
    if (inet_pton(AF_INET6, ip_str.c_str(), &aip.ip6) == 1) {
        aip.family = AF_INET6;
        return true;
    }
    return false;
}

} // anonymous namespace
#endif // HAS_EMBEDDABLE_WG

// ---------------------------------------------------------------------------
// wireguard-go UAPI helpers (Apple only)
// ---------------------------------------------------------------------------

#if defined(__APPLE__) && defined(HAS_WIREGUARDKIT)
namespace {

/// Build a wireguard-go UAPI "set" config string from interface + peer config.
/// See https://www.wireguard.com/xplatform/#configuration-protocol
std::string build_uapi_config(const std::string& private_key,
                               uint16_t listen_port,
                               const std::vector<nexus::wireguard::WgPeer>& peers) {
    std::ostringstream uapi;
    uapi << "private_key=" << private_key << "\n";
    uapi << "listen_port=" << listen_port << "\n";

    for (const auto& peer : peers) {
        uapi << "public_key=" << peer.public_key << "\n";
        if (!peer.endpoint.empty()) {
            uapi << "endpoint=" << peer.endpoint << "\n";
        }
        if (!peer.allowed_ips.empty()) {
            // UAPI expects one allowed_ip per line
            std::istringstream ips(peer.allowed_ips);
            std::string cidr;
            while (std::getline(ips, cidr, ',')) {
                auto start = cidr.find_first_not_of(" \t");
                auto end = cidr.find_last_not_of(" \t");
                if (start != std::string::npos) {
                    uapi << "allowed_ip=" << cidr.substr(start, end - start + 1) << "\n";
                }
            }
        }
        if (peer.persistent_keepalive > 0) {
            uapi << "persistent_keepalive_interval=" << peer.persistent_keepalive << "\n";
        }
    }

    return uapi.str();
}

/// Parse a UAPI "get" response into a vector of WgPeer.
std::vector<nexus::wireguard::WgPeer> parse_uapi_peers(const std::string& config) {
    std::vector<nexus::wireguard::WgPeer> peers;
    nexus::wireguard::WgPeer current;
    bool in_peer = false;

    std::istringstream stream(config);
    std::string line;
    while (std::getline(stream, line)) {
        if (line.empty()) continue;

        auto eq = line.find('=');
        if (eq == std::string::npos) continue;

        auto key = line.substr(0, eq);
        auto value = line.substr(eq + 1);

        if (key == "public_key") {
            if (in_peer) {
                peers.push_back(std::move(current));
                current = {};
            }
            current.public_key = value;
            in_peer = true;
        } else if (key == "endpoint") {
            current.endpoint = value;
        } else if (key == "allowed_ip") {
            if (!current.allowed_ips.empty()) {
                current.allowed_ips += ", ";
            }
            current.allowed_ips += value;
        } else if (key == "last_handshake_time_sec") {
            try { current.last_handshake = std::stoull(value); } catch (...) {}
        } else if (key == "rx_bytes") {
            try { current.rx_bytes = std::stoull(value); } catch (...) {}
        } else if (key == "tx_bytes") {
            try { current.tx_bytes = std::stoull(value); } catch (...) {}
        } else if (key == "persistent_keepalive_interval") {
            try { current.persistent_keepalive = static_cast<uint16_t>(std::stoul(value)); } catch (...) {}
        }
    }
    if (in_peer) {
        peers.push_back(std::move(current));
    }

    return peers;
}

} // anonymous namespace
#endif // __APPLE__ && HAS_WIREGUARDKIT

// ---------------------------------------------------------------------------
// IWireGuardProvider implementation — existing methods
// ---------------------------------------------------------------------------

WgKeypair WireGuardService::do_generate_keypair() {
    std::lock_guard lock(mutex_);

#ifdef HAS_EMBEDDABLE_WG
    // Generate keypair using the embeddable C library
    wg_key private_key_raw, public_key_raw;
    wg_generate_private_key(private_key_raw);
    wg_generate_public_key(public_key_raw, private_key_raw);

    auto priv_b64 = wg_key_to_b64(private_key_raw);
    auto pub_b64 = wg_key_to_b64(public_key_raw);

    spdlog::debug("[{}] generated keypair via embeddable API (pubkey: {})", name(), pub_b64);
    return WgKeypair{
        .public_key  = std::move(pub_b64),
        .private_key = std::move(priv_b64),
    };
#elif defined(__APPLE__) && defined(HAS_WIREGUARDKIT)
    // Use the CLI for key generation (wireguard-go doesn't expose keygen).
    // wg genkey/pubkey are available via wireguard-tools on macOS (brew install wireguard-tools).
    // Fall through to CLI path below.
#endif
#if !defined(HAS_EMBEDDABLE_WG)
    // Generate private key
    auto private_key = run_command("wg genkey 2>/dev/null");
    if (private_key.empty()) {
        spdlog::error("[{}] failed to generate WireGuard private key", name());
        return {};
    }

    // Trim trailing newline
    if (!private_key.empty() && private_key.back() == '\n') {
        private_key.pop_back();
    }

    // Derive public key from private key via temp file (avoid shell interpolation)
    auto tmp_key_path = config_dir_ / ".genkey.tmp";
    {
        std::ofstream ofs(tmp_key_path, std::ios::out | std::ios::trunc);
        if (!ofs) { return {}; }
        ofs << private_key;
        ofs.close();
        std::error_code ec;
        std::filesystem::permissions(tmp_key_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace, ec);
    }
    auto public_key = run_command("wg pubkey < " + tmp_key_path.string() + " 2>/dev/null");
    std::filesystem::remove(tmp_key_path);
    if (public_key.empty()) {
        spdlog::error("[{}] failed to derive WireGuard public key", name());
        return {};
    }

    // Trim trailing newline
    if (!public_key.empty() && public_key.back() == '\n') {
        public_key.pop_back();
    }

    spdlog::debug("[{}] generated keypair (pubkey: {})", name(), public_key);

    return WgKeypair{
        .public_key  = std::move(public_key),
        .private_key = std::move(private_key),
    };
#endif // HAS_EMBEDDABLE_WG
}

bool WireGuardService::do_set_interface(const WgInterfaceConfig& config) {
    std::lock_guard lock(mutex_);

    // Validate the private key (same base64 format as public keys)
    if (!config.private_key.empty() && !is_valid_pubkey(config.private_key)) {
        spdlog::error("[{}] set_interface rejected: invalid private key format", name());
        return false;
    }

#ifdef HAS_EMBEDDABLE_WG
    // Use the embeddable C API for direct kernel configuration
    wg_device dev{};
    std::strncpy(dev.name, interface_name_.c_str(), sizeof(dev.name) - 1);
    dev.flags = static_cast<wg_device_flags>(WGDEVICE_HAS_PRIVATE_KEY | WGDEVICE_HAS_LISTEN_PORT);
    dev.listen_port = config.listen_port;

    if (!config.private_key.empty()) {
        if (!base64_to_wg_key(config.private_key, dev.private_key)) {
            spdlog::error("[{}] set_interface: failed to decode private key", name());
            return false;
        }
    }

    if (wg_set_device(&dev) < 0) {
        spdlog::error("[{}] wg_set_device failed: {}", name(), strerror(errno));
        return false;
    }

    spdlog::info("[{}] configured interface '{}' via embeddable API (listen_port: {}, address: {})",
                  name(), interface_name_, config.listen_port, config.address);
    return true;
#elif defined(__APPLE__) && defined(HAS_WIREGUARDKIT)
    // Use wireguard-go via the Apple bridge.
    // If no tunnel is running, create utun + start tunnel.
    if (tunnel_handle_ < 0) {
        char utun_buf[16] = {};
        tunnel_utun_fd_ = wg_apple_create_utun(utun_buf, sizeof(utun_buf));
        if (tunnel_utun_fd_ < 0) {
            spdlog::error("[{}] failed to create utun device", name());
            return false;
        }
        utun_name_ = utun_buf;

        // Build UAPI config (no peers yet — just interface settings)
        auto uapi = build_uapi_config(config.private_key, config.listen_port, {});

        tunnel_handle_ = wg_apple_turn_on(utun_name_.c_str(), uapi.c_str(), tunnel_utun_fd_);
        if (tunnel_handle_ < 0) {
            spdlog::error("[{}] wg_apple_turn_on failed for '{}'", name(), utun_name_);
            wg_apple_close_utun(tunnel_utun_fd_);
            tunnel_utun_fd_ = -1;
            utun_name_.clear();
            return false;
        }

        // Assign address to the utun interface
        if (!config.address.empty()) {
            if (wg_apple_set_address(utun_name_.c_str(), config.address.c_str()) < 0) {
                spdlog::warn("[{}] failed to assign address '{}' to '{}'",
                              name(), config.address, utun_name_);
            }
        }

        spdlog::info("[{}] configured interface '{}' via wireguard-go (utun: {}, listen_port: {}, address: {})",
                      name(), interface_name_, utun_name_, config.listen_port, config.address);
    } else {
        // Tunnel already running — update config via UAPI
        auto uapi = build_uapi_config(config.private_key, config.listen_port, {});
        auto result = wg_apple_set_config(tunnel_handle_, uapi.c_str());
        if (result != 0) {
            spdlog::error("[{}] wg_apple_set_config failed: {}", name(), result);
            return false;
        }
        spdlog::info("[{}] updated interface config via wireguard-go (listen_port: {}, address: {})",
                      name(), config.listen_port, config.address);
    }
    return true;
#elif defined(_WIN32) && defined(HAS_WIREGUARD_NT)
    // Use wireguard-nt kernel driver
    if (!nt_adapter_) {
        nt_adapter_ = wg_nt_create_adapter(interface_name_.c_str(), "WireGuard");
        if (!nt_adapter_) {
            spdlog::error("[{}] failed to create wireguard-nt adapter '{}'",
                           name(), interface_name_);
            return false;
        }
    }

    if (wg_nt_set_interface(nt_adapter_, config.private_key.c_str(), config.listen_port) < 0) {
        spdlog::error("[{}] wg_nt_set_interface failed for '{}'", name(), interface_name_);
        return false;
    }

    spdlog::info("[{}] configured interface '{}' via wireguard-nt (listen_port: {}, address: {})",
                  name(), interface_name_, config.listen_port, config.address);
    return true;
#else
    // Write private key to a temp file to avoid shell interpolation (command injection)
    auto tmp_key_path = config_dir_ / ".privkey.tmp";
    {
        std::ofstream ofs(tmp_key_path, std::ios::out | std::ios::trunc);
        if (!ofs) {
            spdlog::error("[{}] failed to write temp key file", name());
            return false;
        }
        ofs << config.private_key;
        ofs.close();
        std::error_code ec;
        std::filesystem::permissions(tmp_key_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace, ec);
    }

    // Build the `wg set` command using the temp file
    std::ostringstream cmd;
    cmd << "wg set " << interface_name_
        << " private-key " << tmp_key_path.string()
        << " listen-port " << config.listen_port;

    auto full_cmd = cmd.str() + " 2>&1";

    auto output = run_command(full_cmd);

    // Clean up temp key file
    std::error_code rm_ec;
    std::filesystem::remove(tmp_key_path, rm_ec);

    if (!output.empty()) {
        spdlog::error("[{}] wg set failed: {}", name(), output);
        return false;
    }

    spdlog::info("[{}] configured interface '{}' (listen_port: {}, address: {})",
                  name(), interface_name_, config.listen_port, config.address);
    return true;
#endif // HAS_EMBEDDABLE_WG / HAS_WIREGUARDKIT
}

bool WireGuardService::do_add_peer(const std::string& pubkey,
                                    const std::string& allowed_ips,
                                    const std::string& endpoint) {
    std::lock_guard lock(mutex_);

    // Validate inputs
    if (!is_valid_pubkey(pubkey)) {
        spdlog::error("[{}] add_peer rejected: invalid public key '{}'", name(), pubkey);
        return false;
    }
    if (!is_valid_allowed_ips(allowed_ips)) {
        spdlog::error("[{}] add_peer rejected: invalid allowed_ips '{}'", name(), allowed_ips);
        return false;
    }
    if (!is_valid_endpoint(endpoint)) {
        spdlog::error("[{}] add_peer rejected: invalid endpoint '{}'", name(), endpoint);
        return false;
    }

#ifdef HAS_EMBEDDABLE_WG
    // Use the embeddable C API
    wg_device dev{};
    std::strncpy(dev.name, interface_name_.c_str(), sizeof(dev.name) - 1);

    auto* peer = static_cast<wg_peer*>(calloc(1, sizeof(wg_peer)));
    if (!peer) return false;

    if (!base64_to_wg_key(pubkey, peer->public_key)) {
        free(peer);
        return false;
    }
    peer->flags = static_cast<wg_peer_flags>(WGPEER_HAS_PUBLIC_KEY | WGPEER_REPLACE_ALLOWEDIPS);

    // Parse endpoint
    if (!endpoint.empty()) {
        sockaddr_storage ep_addr{};
        if (parse_endpoint(endpoint, ep_addr)) {
            peer->endpoint.addr = ep_addr;
        }
    }

    // Parse allowed IPs
    wg_allowedip* aip_head = nullptr;
    wg_allowedip* aip_tail = nullptr;
    {
        std::istringstream stream(allowed_ips);
        std::string token;
        while (std::getline(stream, token, ',')) {
            auto start = token.find_first_not_of(" \t");
            auto end = token.find_last_not_of(" \t");
            if (start == std::string::npos) continue;
            auto trimmed = token.substr(start, end - start + 1);

            auto* aip = static_cast<wg_allowedip*>(calloc(1, sizeof(wg_allowedip)));
            if (!aip) continue;
            if (!parse_cidr_to_allowedip(trimmed, *aip)) {
                free(aip);
                continue;
            }
            aip->next_allowedip = nullptr;
            if (!aip_head) {
                aip_head = aip;
                aip_tail = aip;
            } else {
                aip_tail->next_allowedip = aip;
                aip_tail = aip;
            }
        }
    }
    peer->first_allowedip = aip_head;
    peer->last_allowedip = aip_tail;
    peer->next_peer = nullptr;

    dev.first_peer = peer;
    dev.last_peer = peer;

    int ret = wg_set_device(&dev);

    // Free allowed IPs
    wg_allowedip* cur = aip_head;
    while (cur) {
        auto* next = cur->next_allowedip;
        free(cur);
        cur = next;
    }
    free(peer);

    if (ret < 0) {
        spdlog::error("[{}] wg_set_device (add_peer) failed: {}", name(), strerror(errno));
        return false;
    }

    spdlog::info("[{}] added peer {} via embeddable API (allowed_ips: {}, endpoint: {})",
                  name(), pubkey, allowed_ips, endpoint);
    return true;
#elif defined(__APPLE__) && defined(HAS_WIREGUARDKIT)
    if (tunnel_handle_ < 0) {
        spdlog::error("[{}] add_peer: tunnel not running", name());
        return false;
    }

    // Build UAPI "set" command for adding a single peer
    std::ostringstream uapi;
    uapi << "public_key=" << pubkey << "\n";
    if (!endpoint.empty()) {
        uapi << "endpoint=" << endpoint << "\n";
    }
    // UAPI expects one allowed_ip per line
    {
        std::istringstream ips(allowed_ips);
        std::string cidr;
        while (std::getline(ips, cidr, ',')) {
            auto start = cidr.find_first_not_of(" \t");
            auto end = cidr.find_last_not_of(" \t");
            if (start != std::string::npos) {
                uapi << "allowed_ip=" << cidr.substr(start, end - start + 1) << "\n";
            }
        }
    }

    auto result = wg_apple_set_config(tunnel_handle_, uapi.str().c_str());
    if (result != 0) {
        spdlog::error("[{}] add_peer via wireguard-go failed: {}", name(), result);
        return false;
    }

    spdlog::info("[{}] added peer {} via wireguard-go (allowed_ips: {}, endpoint: {})",
                  name(), pubkey, allowed_ips, endpoint);
    return true;
#elif defined(_WIN32) && defined(HAS_WIREGUARD_NT)
    if (!nt_adapter_) {
        spdlog::error("[{}] add_peer: adapter not created", name());
        return false;
    }

    if (wg_nt_add_peer(nt_adapter_, pubkey.c_str(), allowed_ips.c_str(),
                        endpoint.empty() ? nullptr : endpoint.c_str(), 25) < 0) {
        spdlog::error("[{}] wg_nt_add_peer failed for '{}'", name(), pubkey);
        return false;
    }

    spdlog::info("[{}] added peer {} via wireguard-nt (allowed_ips: {}, endpoint: {})",
                  name(), pubkey, allowed_ips, endpoint);
    return true;
#else
    std::ostringstream cmd;
    cmd << "wg set " << interface_name_
        << " peer " << pubkey
        << " allowed-ips " << allowed_ips;

    if (!endpoint.empty()) {
        cmd << " endpoint " << endpoint;
    }

    cmd << " 2>&1";

    auto output = run_command(cmd.str());
    if (!output.empty()) {
        spdlog::error("[{}] add_peer failed: {}", name(), output);
        return false;
    }

    spdlog::info("[{}] added peer {} (allowed_ips: {}, endpoint: {})",
                  name(), pubkey, allowed_ips, endpoint);
    return true;
#endif
}

bool WireGuardService::do_remove_peer(const std::string& pubkey) {
    std::lock_guard lock(mutex_);

    if (!is_valid_pubkey(pubkey)) {
        spdlog::error("[{}] remove_peer rejected: invalid public key '{}'", name(), pubkey);
        return false;
    }

#ifdef HAS_EMBEDDABLE_WG
    wg_device dev{};
    std::strncpy(dev.name, interface_name_.c_str(), sizeof(dev.name) - 1);

    auto* peer = static_cast<wg_peer*>(calloc(1, sizeof(wg_peer)));
    if (!peer) return false;

    if (!base64_to_wg_key(pubkey, peer->public_key)) {
        free(peer);
        return false;
    }
    peer->flags = static_cast<wg_peer_flags>(WGPEER_HAS_PUBLIC_KEY | WGPEER_REMOVE_ME);
    peer->next_peer = nullptr;

    dev.first_peer = peer;
    dev.last_peer = peer;

    int ret = wg_set_device(&dev);
    free(peer);

    if (ret < 0) {
        spdlog::error("[{}] wg_set_device (remove_peer) failed: {}", name(), strerror(errno));
        return false;
    }

    spdlog::info("[{}] removed peer {} via embeddable API", name(), pubkey);
    return true;
#elif defined(__APPLE__) && defined(HAS_WIREGUARDKIT)
    if (tunnel_handle_ < 0) {
        spdlog::error("[{}] remove_peer: tunnel not running", name());
        return false;
    }

    // UAPI: set public_key + remove=true
    std::ostringstream uapi;
    uapi << "public_key=" << pubkey << "\n";
    uapi << "remove=true\n";

    auto result = wg_apple_set_config(tunnel_handle_, uapi.str().c_str());
    if (result != 0) {
        spdlog::error("[{}] remove_peer via wireguard-go failed: {}", name(), result);
        return false;
    }

    spdlog::info("[{}] removed peer {} via wireguard-go", name(), pubkey);
    return true;
#elif defined(_WIN32) && defined(HAS_WIREGUARD_NT)
    if (!nt_adapter_) {
        spdlog::error("[{}] remove_peer: adapter not created", name());
        return false;
    }

    if (wg_nt_remove_peer(nt_adapter_, pubkey.c_str()) < 0) {
        spdlog::error("[{}] wg_nt_remove_peer failed for '{}'", name(), pubkey);
        return false;
    }

    spdlog::info("[{}] removed peer {} via wireguard-nt", name(), pubkey);
    return true;
#else
    std::ostringstream cmd;
    cmd << "wg set " << interface_name_
        << " peer " << pubkey
        << " remove 2>&1";

    auto output = run_command(cmd.str());
    if (!output.empty()) {
        spdlog::error("[{}] remove_peer failed: {}", name(), output);
        return false;
    }

    spdlog::info("[{}] removed peer {}", name(), pubkey);
    return true;
#endif
}

std::vector<WgPeer> WireGuardService::do_get_peers() {
    std::lock_guard lock(mutex_);

#ifdef HAS_EMBEDDABLE_WG
    wg_device* dev = nullptr;
    if (wg_get_device(&dev, interface_name_.c_str()) < 0) {
        spdlog::debug("[{}] wg_get_device failed for '{}'", name(), interface_name_);
        return {};
    }

    std::vector<WgPeer> peers;
    wg_peer* p = nullptr;
    wg_for_each_peer(dev, p) {
        WgPeer peer;
        peer.public_key = wg_key_to_b64(p->public_key);
        peer.endpoint = format_endpoint(p->endpoint.addr);
        peer.last_handshake = static_cast<uint64_t>(p->last_handshake_time.tv_sec);
        peer.rx_bytes = p->rx_bytes;
        peer.tx_bytes = p->tx_bytes;
        peer.persistent_keepalive = p->persistent_keepalive_interval;

        // Build comma-separated allowed IPs
        std::string allowed;
        wg_allowedip* aip = nullptr;
        wg_for_each_allowedip(p, aip) {
            char buf[INET6_ADDRSTRLEN] = {};
            if (aip->family == AF_INET) {
                inet_ntop(AF_INET, &aip->ip4, buf, sizeof(buf));
            } else if (aip->family == AF_INET6) {
                inet_ntop(AF_INET6, &aip->ip6, buf, sizeof(buf));
            }
            if (!allowed.empty()) allowed += ", ";
            allowed += std::string(buf) + "/" + std::to_string(aip->cidr);
        }
        peer.allowed_ips = std::move(allowed);
        peers.push_back(std::move(peer));
    }

    wg_free_device(dev);

    spdlog::debug("[{}] enumerated {} peers on '{}' via embeddable API",
                   name(), peers.size(), interface_name_);
    return peers;
#elif defined(__APPLE__) && defined(HAS_WIREGUARDKIT)
    if (tunnel_handle_ < 0) {
        spdlog::debug("[{}] get_peers: tunnel not running", name());
        return {};
    }

    char* config_str = wg_apple_get_config(tunnel_handle_);
    if (!config_str) {
        spdlog::debug("[{}] wg_apple_get_config returned null", name());
        return {};
    }

    auto peers = parse_uapi_peers(std::string(config_str));
    wg_apple_free_config(config_str);

    spdlog::debug("[{}] enumerated {} peers on '{}' via wireguard-go",
                   name(), peers.size(), utun_name_);
    return peers;
#elif defined(_WIN32) && defined(HAS_WIREGUARD_NT)
    if (!nt_adapter_) {
        spdlog::debug("[{}] get_peers: adapter not created", name());
        return {};
    }

    constexpr int kMaxPeers = 256;
    std::vector<wg_nt_peer_info> nt_peers(kMaxPeers);

    int count = wg_nt_get_peers(nt_adapter_, nt_peers.data(), kMaxPeers);
    if (count < 0) {
        spdlog::debug("[{}] wg_nt_get_peers failed", name());
        return {};
    }

    std::vector<WgPeer> peers;
    peers.reserve(count);
    for (int i = 0; i < count; ++i) {
        WgPeer peer;
        peer.public_key = nt_peers[i].public_key;
        peer.allowed_ips = nt_peers[i].allowed_ips;
        peer.endpoint = nt_peers[i].endpoint;
        // Convert Windows FILETIME (100ns since 1601) to Unix epoch
        // Offset: 116444736000000000 (100ns intervals between 1601 and 1970)
        constexpr uint64_t kWindowsToUnixOffset = 116444736000000000ULL;
        if (nt_peers[i].last_handshake > kWindowsToUnixOffset) {
            peer.last_handshake = (nt_peers[i].last_handshake - kWindowsToUnixOffset) / 10000000ULL;
        }
        peer.rx_bytes = nt_peers[i].rx_bytes;
        peer.tx_bytes = nt_peers[i].tx_bytes;
        peer.persistent_keepalive = nt_peers[i].persistent_keepalive;
        peers.push_back(std::move(peer));
    }

    spdlog::debug("[{}] enumerated {} peers on '{}' via wireguard-nt",
                   name(), peers.size(), interface_name_);
    return peers;
#else
    // `wg show <iface> dump` outputs tab-separated fields:
    //   Line 1 (interface): private-key  public-key  listen-port  fwmark
    //   Line 2+ (peers):    public-key  preshared-key  endpoint  allowed-ips
    //                        latest-handshake  transfer-rx  transfer-tx  persistent-keepalive
    auto output = run_command("wg show " + interface_name_ + " dump 2>/dev/null");
    if (output.empty()) {
        spdlog::debug("[{}] no dump output for interface '{}'", name(), interface_name_);
        return {};
    }

    std::vector<WgPeer> peers;
    std::istringstream stream(output);
    std::string line;
    bool first_line = true;

    while (std::getline(stream, line)) {
        // Skip the first line (interface info)
        if (first_line) {
            first_line = false;
            continue;
        }

        if (line.empty()) {
            continue;
        }

        // Parse tab-separated peer fields
        std::istringstream line_stream(line);
        std::string pub_key, preshared_key, endpoint_str, allowed_ips_str;
        std::string handshake_str, rx_str, tx_str, keepalive_str;

        if (!std::getline(line_stream, pub_key, '\t'))      continue;
        if (!std::getline(line_stream, preshared_key, '\t')) continue;
        if (!std::getline(line_stream, endpoint_str, '\t'))  continue;
        if (!std::getline(line_stream, allowed_ips_str, '\t')) continue;
        if (!std::getline(line_stream, handshake_str, '\t')) continue;
        if (!std::getline(line_stream, rx_str, '\t'))        continue;
        if (!std::getline(line_stream, tx_str, '\t'))        continue;
        // persistent-keepalive may or may not be present
        std::getline(line_stream, keepalive_str, '\t');

        WgPeer peer;
        peer.public_key = pub_key;
        peer.allowed_ips = allowed_ips_str;
        peer.endpoint = (endpoint_str == "(none)") ? "" : endpoint_str;

        try {
            peer.last_handshake = std::stoull(handshake_str);
        } catch (...) {
            peer.last_handshake = 0;
        }

        try {
            peer.rx_bytes = std::stoull(rx_str);
        } catch (...) {
            peer.rx_bytes = 0;
        }

        try {
            peer.tx_bytes = std::stoull(tx_str);
        } catch (...) {
            peer.tx_bytes = 0;
        }

        // Parse persistent keepalive (may be "off" or a number)
        if (!keepalive_str.empty() && keepalive_str != "off") {
            try {
                peer.persistent_keepalive = static_cast<uint16_t>(std::stoul(keepalive_str));
            } catch (...) {
                peer.persistent_keepalive = 0;
            }
        } else {
            peer.persistent_keepalive = 0;
        }

        peers.push_back(std::move(peer));
    }

    spdlog::debug("[{}] enumerated {} peers on '{}'",
                   name(), peers.size(), interface_name_);
    return peers;
#endif // HAS_EMBEDDABLE_WG
}

bool WireGuardService::do_update_endpoint(const std::string& pubkey,
                                            const std::string& new_endpoint) {
    std::lock_guard lock(mutex_);

    if (!is_valid_pubkey(pubkey)) {
        spdlog::error("[{}] update_endpoint rejected: invalid public key '{}'",
                       name(), pubkey);
        return false;
    }
    if (!is_valid_endpoint(new_endpoint)) {
        spdlog::error("[{}] update_endpoint rejected: invalid endpoint '{}'",
                       name(), new_endpoint);
        return false;
    }

#if defined(__APPLE__) && defined(HAS_WIREGUARDKIT)
    if (tunnel_handle_ < 0) {
        spdlog::error("[{}] update_endpoint: tunnel not running", name());
        return false;
    }

    std::ostringstream uapi;
    uapi << "public_key=" << pubkey << "\n";
    uapi << "endpoint=" << new_endpoint << "\n";

    auto result = wg_apple_set_config(tunnel_handle_, uapi.str().c_str());
    if (result != 0) {
        spdlog::error("[{}] update_endpoint via wireguard-go failed: {}", name(), result);
        return false;
    }

    spdlog::info("[{}] updated endpoint for peer {} to {} via wireguard-go",
                  name(), pubkey, new_endpoint);
    return true;
#elif defined(_WIN32) && defined(HAS_WIREGUARD_NT)
    if (!nt_adapter_) {
        spdlog::error("[{}] update_endpoint: adapter not created", name());
        return false;
    }

    // Add peer with UPDATE_ONLY flag — the bridge handles this via add_peer
    // with just the endpoint field set
    if (wg_nt_add_peer(nt_adapter_, pubkey.c_str(), nullptr,
                        new_endpoint.c_str(), 0) < 0) {
        spdlog::error("[{}] update_endpoint via wireguard-nt failed for '{}'", name(), pubkey);
        return false;
    }

    spdlog::info("[{}] updated endpoint for peer {} to {} via wireguard-nt",
                  name(), pubkey, new_endpoint);
    return true;
#else
    std::ostringstream cmd;
    cmd << "wg set " << interface_name_
        << " peer " << pubkey
        << " endpoint " << new_endpoint
        << " 2>&1";

    auto output = run_command(cmd.str());
    if (!output.empty()) {
        spdlog::error("[{}] update_endpoint failed: {}", name(), output);
        return false;
    }

    spdlog::info("[{}] updated endpoint for peer {} to {}",
                  name(), pubkey, new_endpoint);
    return true;
#endif
}

// ---------------------------------------------------------------------------
// IWireGuardProvider implementation — new methods
// ---------------------------------------------------------------------------

std::string WireGuardService::do_generate_config(const WgInterfaceConfig& config,
                                                   const std::vector<WgPeer>& peers) {
    std::ostringstream out;

    // [Interface] section
    out << "[Interface]\n";
    out << "PrivateKey = " << config.private_key << "\n";
    out << "ListenPort = " << config.listen_port << "\n";
    if (!config.address.empty()) {
        out << "Address = " << config.address << "\n";
    }
    if (!config.dns.empty()) {
        out << "DNS = " << config.dns << "\n";
    }

    // [Peer] sections
    for (const auto& peer : peers) {
        out << "\n[Peer]\n";
        out << "PublicKey = " << peer.public_key << "\n";
        if (!peer.allowed_ips.empty()) {
            out << "AllowedIPs = " << peer.allowed_ips << "\n";
        }
        if (!peer.endpoint.empty()) {
            out << "Endpoint = " << peer.endpoint << "\n";
        }
        if (peer.persistent_keepalive > 0) {
            out << "PersistentKeepalive = " << peer.persistent_keepalive << "\n";
        }
    }

    return out.str();
}

bool WireGuardService::do_setup_interface(const WgInterfaceConfig& config,
                                            const std::vector<WgPeer>& peers) {
    std::lock_guard lock(mutex_);

    // Validate the address
    if (!config.address.empty() && !is_valid_cidr(config.address)) {
        spdlog::error("[{}] setup_interface rejected: invalid address '{}'",
                       name(), config.address);
        return false;
    }

#if defined(__APPLE__) && defined(HAS_WIREGUARDKIT)
    // --- macOS: create utun + start wireguard-go + add peers ---

    // Tear down any existing tunnel first
    if (tunnel_handle_ >= 0) {
        wg_apple_turn_off(tunnel_handle_);
        tunnel_handle_ = -1;
    }
    if (tunnel_utun_fd_ >= 0) {
        wg_apple_close_utun(tunnel_utun_fd_);
        tunnel_utun_fd_ = -1;
    }

    // 1. Create utun device
    char utun_buf[16] = {};
    tunnel_utun_fd_ = wg_apple_create_utun(utun_buf, sizeof(utun_buf));
    if (tunnel_utun_fd_ < 0) {
        spdlog::error("[{}] failed to create utun device", name());
        return false;
    }
    utun_name_ = utun_buf;

    // 2. Build full UAPI config with all peers
    auto uapi = build_uapi_config(config.private_key, config.listen_port, peers);

    // 3. Start wireguard-go tunnel
    tunnel_handle_ = wg_apple_turn_on(utun_name_.c_str(), uapi.c_str(), tunnel_utun_fd_);
    if (tunnel_handle_ < 0) {
        spdlog::error("[{}] wg_apple_turn_on failed for '{}'", name(), utun_name_);
        wg_apple_close_utun(tunnel_utun_fd_);
        tunnel_utun_fd_ = -1;
        utun_name_.clear();
        return false;
    }

    // 4. Assign address to the utun interface
    if (!config.address.empty()) {
        if (wg_apple_set_address(utun_name_.c_str(), config.address.c_str()) < 0) {
            spdlog::warn("[{}] failed to assign address '{}' to '{}'",
                          name(), config.address, utun_name_);
        }
    }

    // 5. Add routes for each peer's allowed IPs
    for (const auto& peer : peers) {
        if (!peer.allowed_ips.empty()) {
            std::istringstream ip_stream(peer.allowed_ips);
            std::string cidr;
            while (std::getline(ip_stream, cidr, ',')) {
                auto start = cidr.find_first_not_of(" \t");
                auto end   = cidr.find_last_not_of(" \t");
                if (start == std::string::npos) continue;
                auto trimmed = cidr.substr(start, end - start + 1);
                if (trimmed.ends_with("/32")) continue;
                wg_apple_add_route(trimmed.c_str(), utun_name_.c_str());
            }
        }
    }

    spdlog::info("[{}] interface '{}' (utun: {}) is up via wireguard-go with {} peers configured",
                  name(), interface_name_, utun_name_, peers.size());
    return true;

#elif defined(_WIN32) && defined(HAS_WIREGUARD_NT)
    // --- Windows: create wireguard-nt adapter + configure + bring up ---

    // 1. Create or reuse adapter
    if (!nt_adapter_) {
        nt_adapter_ = wg_nt_create_adapter(interface_name_.c_str(), "WireGuard");
        if (!nt_adapter_) {
            spdlog::error("[{}] failed to create wireguard-nt adapter '{}'",
                           name(), interface_name_);
            return false;
        }
    }

    // 2. Set interface config (private key + listen port)
    if (wg_nt_set_interface(nt_adapter_, config.private_key.c_str(), config.listen_port) < 0) {
        spdlog::error("[{}] wg_nt_set_interface failed for '{}'", name(), interface_name_);
        return false;
    }

    // 3. Add all peers
    for (const auto& peer : peers) {
        if (!is_valid_pubkey(peer.public_key)) {
            spdlog::warn("[{}] setup_interface: skipping peer with invalid pubkey '{}'",
                          name(), peer.public_key);
            continue;
        }

        if (wg_nt_add_peer(nt_adapter_, peer.public_key.c_str(),
                            peer.allowed_ips.empty() ? nullptr : peer.allowed_ips.c_str(),
                            peer.endpoint.empty() ? nullptr : peer.endpoint.c_str(),
                            peer.persistent_keepalive) < 0) {
            spdlog::error("[{}] setup_interface: failed to add peer {} via wireguard-nt",
                           name(), peer.public_key);
        }
    }

    // 4. Assign address via IP Helper API
    if (!config.address.empty()) {
        if (wg_nt_set_address(nt_adapter_, config.address.c_str()) < 0) {
            spdlog::warn("[{}] failed to assign address '{}' to '{}'",
                          name(), config.address, interface_name_);
        }
    }

    // 5. Add routes for each peer's allowed IPs
    for (const auto& peer : peers) {
        if (!peer.allowed_ips.empty()) {
            std::istringstream ip_stream(peer.allowed_ips);
            std::string cidr;
            while (std::getline(ip_stream, cidr, ',')) {
                auto start = cidr.find_first_not_of(" \t");
                auto end   = cidr.find_last_not_of(" \t");
                if (start == std::string::npos) continue;
                auto trimmed = cidr.substr(start, end - start + 1);
                if (trimmed.ends_with("/32")) continue;
                wg_nt_add_route(nt_adapter_, trimmed.c_str());
            }
        }
    }

    // 6. Bring the adapter up
    if (wg_nt_set_adapter_state(nt_adapter_, 1) < 0) {
        spdlog::error("[{}] failed to bring up adapter '{}'", name(), interface_name_);
        return false;
    }

    spdlog::info("[{}] interface '{}' is up via wireguard-nt with {} peers configured",
                  name(), interface_name_, peers.size());
    return true;

#else
    // --- Linux / CLI fallback ---

    // 1. Check if the interface already exists
    {
        auto output = run_command("ip link show " + interface_name_ + " 2>/dev/null");
        if (output.empty()) {
            // Interface does not exist — create it
            auto create_output = run_command(
                "ip link add " + interface_name_ + " type wireguard 2>&1");
            if (!create_output.empty()) {
                spdlog::error("[{}] failed to create interface '{}': {}",
                               name(), interface_name_, create_output);
                return false;
            }
            spdlog::info("[{}] created interface '{}'", name(), interface_name_);
        } else {
            spdlog::debug("[{}] interface '{}' already exists", name(), interface_name_);
        }
    }

    // 2. Set the private key via temp file (avoid shell injection)
    {
        if (!config.private_key.empty() && !is_valid_pubkey(config.private_key)) {
            spdlog::error("[{}] setup_interface rejected: invalid private key format", name());
            return false;
        }
        auto tmp_key_path = config_dir_ / ".privkey.tmp";
        {
            std::ofstream ofs(tmp_key_path, std::ios::out | std::ios::trunc);
            if (!ofs) {
                spdlog::error("[{}] failed to write temp key file", name());
                return false;
            }
            ofs << config.private_key;
            ofs.close();
            std::error_code perm_ec;
            std::filesystem::permissions(tmp_key_path,
                std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                std::filesystem::perm_options::replace, perm_ec);
        }
        auto cmd = "wg set " + interface_name_ +
                   " private-key " + tmp_key_path.string() + " 2>&1";
        auto output = run_command(cmd);
        std::filesystem::remove(tmp_key_path);
        if (!output.empty()) {
            spdlog::error("[{}] failed to set private key on '{}': {}",
                           name(), interface_name_, output);
            return false;
        }
    }

    // 3. Set the listen port
    {
        std::ostringstream cmd;
        cmd << "wg set " << interface_name_
            << " listen-port " << config.listen_port << " 2>&1";
        auto output = run_command(cmd.str());
        if (!output.empty()) {
            spdlog::error("[{}] failed to set listen port on '{}': {}",
                           name(), interface_name_, output);
            return false;
        }
    }

    // 4. Assign the address
    if (!config.address.empty()) {
        // Flush existing addresses first to avoid "RTNETLINK: File exists"
        (void)run_command("ip addr flush dev " + interface_name_ + " 2>/dev/null");

        auto cmd = "ip addr add " + config.address + " dev " + interface_name_ + " 2>&1";
        auto output = run_command(cmd);
        if (!output.empty()) {
            spdlog::error("[{}] failed to assign address '{}' to '{}': {}",
                           name(), config.address, interface_name_, output);
            return false;
        }
    }

    // 5. Bring the interface up
    {
        auto cmd = "ip link set " + interface_name_ + " up 2>&1";
        auto output = run_command(cmd);
        if (!output.empty()) {
            spdlog::error("[{}] failed to bring up '{}': {}",
                           name(), interface_name_, output);
            return false;
        }
    }

    // 6. Add peers and their routes
    for (const auto& peer : peers) {
        if (!is_valid_pubkey(peer.public_key)) {
            spdlog::warn("[{}] setup_interface: skipping peer with invalid pubkey '{}'",
                          name(), peer.public_key);
            continue;
        }

        std::ostringstream cmd;
        cmd << "wg set " << interface_name_
            << " peer " << peer.public_key;

        if (!peer.allowed_ips.empty()) {
            if (!is_valid_allowed_ips(peer.allowed_ips)) {
                spdlog::warn("[{}] setup_interface: skipping peer {} — invalid allowed_ips '{}'",
                              name(), peer.public_key, peer.allowed_ips);
                continue;
            }
            cmd << " allowed-ips " << peer.allowed_ips;
        }

        if (!peer.endpoint.empty()) {
            if (!is_valid_endpoint(peer.endpoint)) {
                spdlog::warn("[{}] setup_interface: skipping peer {} — invalid endpoint '{}'",
                              name(), peer.public_key, peer.endpoint);
                continue;
            }
            cmd << " endpoint " << peer.endpoint;
        }

        if (peer.persistent_keepalive > 0) {
            cmd << " persistent-keepalive " << peer.persistent_keepalive;
        }

        cmd << " 2>&1";
        auto output = run_command(cmd.str());
        if (!output.empty()) {
            spdlog::error("[{}] setup_interface: failed to add peer {}: {}",
                           name(), peer.public_key, output);
            // Continue with other peers rather than aborting
        }

        // Add routes for each allowed IP subnet (skip /32 host routes — the
        // kernel adds those automatically for WireGuard peers)
        if (!peer.allowed_ips.empty()) {
            std::istringstream ip_stream(peer.allowed_ips);
            std::string cidr;
            while (std::getline(ip_stream, cidr, ',')) {
                // Trim whitespace
                auto start = cidr.find_first_not_of(" \t");
                auto end   = cidr.find_last_not_of(" \t");
                if (start == std::string::npos) continue;
                auto trimmed = cidr.substr(start, end - start + 1);

                // Skip /32 host routes — WireGuard handles those
                if (trimmed.ends_with("/32")) continue;

                auto route_cmd = "ip route add " + trimmed +
                                 " dev " + interface_name_ + " 2>/dev/null";
                (void)run_command(route_cmd);
            }
        }
    }

    spdlog::info("[{}] interface '{}' is up with {} peers configured",
                  name(), interface_name_, peers.size());
    return true;
#endif // __APPLE__ && HAS_WIREGUARDKIT
}

bool WireGuardService::do_teardown_interface() {
    std::lock_guard lock(mutex_);

#if defined(__APPLE__) && defined(HAS_WIREGUARDKIT)
    // --- macOS: stop wireguard-go + close utun ---
    if (tunnel_handle_ >= 0) {
        wg_apple_turn_off(tunnel_handle_);
        tunnel_handle_ = -1;
    }
    if (tunnel_utun_fd_ >= 0) {
        wg_apple_close_utun(tunnel_utun_fd_);
        tunnel_utun_fd_ = -1;
    }

    spdlog::info("[{}] interface '{}' (utun: {}) torn down via wireguard-go",
                  name(), interface_name_, utun_name_);
    utun_name_.clear();
    return true;
#elif defined(_WIN32) && defined(HAS_WIREGUARD_NT)
    // --- Windows: bring down + close adapter ---
    if (nt_adapter_) {
        wg_nt_set_adapter_state(nt_adapter_, 0);
        wg_nt_close_adapter(nt_adapter_);
        nt_adapter_ = nullptr;
    }

    spdlog::info("[{}] interface '{}' torn down via wireguard-nt", name(), interface_name_);
    return true;
#else
    // --- Linux / CLI fallback ---

    // 1. Bring the interface down
    {
        auto cmd = "ip link set " + interface_name_ + " down 2>&1";
        auto output = run_command(cmd);
        if (!output.empty()) {
            spdlog::warn("[{}] failed to bring down '{}': {}",
                          name(), interface_name_, output);
            // Continue to try deletion anyway
        }
    }

    // 2. Delete the interface
    {
        auto cmd = "ip link del " + interface_name_ + " 2>&1";
        auto output = run_command(cmd);
        if (!output.empty()) {
            spdlog::error("[{}] failed to delete interface '{}': {}",
                           name(), interface_name_, output);
            return false;
        }
    }

    spdlog::info("[{}] interface '{}' torn down", name(), interface_name_);
    return true;
#endif // __APPLE__ && HAS_WIREGUARDKIT
}

int WireGuardService::do_sync_peers_from_tree(const std::vector<TreeNodePeer>& desired_peers) {
    // Validate all desired peers first
    for (const auto& dp : desired_peers) {
        if (!is_valid_pubkey(dp.public_key)) {
            spdlog::error("[{}] sync_peers_from_tree: invalid pubkey in desired peer '{}'",
                           name(), dp.public_key);
            return -1;
        }
        if (!dp.tunnel_ip.empty() && !is_valid_cidr(dp.tunnel_ip)) {
            spdlog::error("[{}] sync_peers_from_tree: invalid tunnel_ip '{}' for peer '{}'",
                           name(), dp.tunnel_ip, dp.public_key);
            return -1;
        }
        if (!dp.private_subnet.empty() && !is_valid_cidr(dp.private_subnet)) {
            spdlog::error("[{}] sync_peers_from_tree: invalid private_subnet '{}' for peer '{}'",
                           name(), dp.private_subnet, dp.public_key);
            return -1;
        }
        if (!is_valid_endpoint(dp.endpoint)) {
            spdlog::error("[{}] sync_peers_from_tree: invalid endpoint '{}' for peer '{}'",
                           name(), dp.endpoint, dp.public_key);
            return -1;
        }
    }

    // Get current peers (do_get_peers acquires the lock internally)
    auto current_peers = do_get_peers();

    // Build lookup maps
    std::unordered_map<std::string, const WgPeer*> current_map;
    for (const auto& cp : current_peers) {
        current_map[cp.public_key] = &cp;
    }

    std::unordered_set<std::string> desired_keys;
    for (const auto& dp : desired_peers) {
        desired_keys.insert(dp.public_key);
    }

    int changes = 0;

    // Add new peers and update endpoints for existing ones
    for (const auto& dp : desired_peers) {
        // Build allowed IPs from tunnel_ip and private_subnet
        std::string allowed_ips;
        if (!dp.tunnel_ip.empty()) {
            allowed_ips = dp.tunnel_ip;
        }
        if (!dp.private_subnet.empty()) {
            if (!allowed_ips.empty()) {
                allowed_ips += ", ";
            }
            allowed_ips += dp.private_subnet;
        }

        auto it = current_map.find(dp.public_key);
        if (it == current_map.end()) {
            // New peer — add it (do_add_peer acquires the lock internally)
            if (do_add_peer(dp.public_key, allowed_ips, dp.endpoint)) {
                ++changes;
                spdlog::debug("[{}] sync: added peer {}", name(), dp.public_key);
            }
        } else {
            // Existing peer — check if endpoint needs updating
            if (!dp.endpoint.empty() && it->second->endpoint != dp.endpoint) {
                if (do_update_endpoint(dp.public_key, dp.endpoint)) {
                    ++changes;
                    spdlog::debug("[{}] sync: updated endpoint for peer {} to {}",
                                   name(), dp.public_key, dp.endpoint);
                }
            }
        }
    }

    // Remove stale peers (present in current but not in desired)
    for (const auto& cp : current_peers) {
        if (desired_keys.find(cp.public_key) == desired_keys.end()) {
            if (do_remove_peer(cp.public_key)) {
                ++changes;
                spdlog::debug("[{}] sync: removed stale peer {}", name(), cp.public_key);
            }
        }
    }

    spdlog::info("[{}] sync_peers_from_tree: {} changes applied ({} desired, {} current)",
                  name(), changes, desired_peers.size(), current_peers.size());
    return changes;
}

// ---------------------------------------------------------------------------
// Config file persistence
// ---------------------------------------------------------------------------

std::filesystem::path WireGuardService::config_file_path() const {
    return config_dir_ / (interface_name_ + ".conf");
}

bool WireGuardService::do_save_config(const std::string& config_contents) {
    std::lock_guard lock(mutex_);

    auto path = config_file_path();

    // Ensure the directory exists
    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        spdlog::error("[{}] failed to create config directory '{}': {}",
                       name(), path.parent_path().string(), ec.message());
        return false;
    }

    std::ofstream ofs(path, std::ios::out | std::ios::trunc);
    if (!ofs.is_open()) {
        spdlog::error("[{}] failed to open config file for writing: {}",
                       name(), path.string());
        return false;
    }

    ofs << config_contents;
    ofs.close();

    if (ofs.fail()) {
        spdlog::error("[{}] failed to write config file: {}", name(), path.string());
        return false;
    }

    // Set restrictive permissions (0600) — config contains the private key
    std::filesystem::permissions(path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, ec);
    if (ec) {
        spdlog::warn("[{}] failed to set permissions on '{}': {}",
                      name(), path.string(), ec.message());
    }

    spdlog::info("[{}] saved config to '{}'", name(), path.string());
    return true;
}

std::string WireGuardService::do_load_config() {
    std::lock_guard lock(mutex_);

    auto path = config_file_path();

    if (!std::filesystem::exists(path)) {
        spdlog::debug("[{}] no config file found at '{}'", name(), path.string());
        return {};
    }

    std::ifstream ifs(path);
    if (!ifs.is_open()) {
        spdlog::error("[{}] failed to open config file for reading: {}",
                       name(), path.string());
        return {};
    }

    std::ostringstream buf;
    buf << ifs.rdbuf();

    spdlog::info("[{}] loaded config from '{}'", name(), path.string());
    return buf.str();
}

// ---------------------------------------------------------------------------
// Utility
// ---------------------------------------------------------------------------

std::string WireGuardService::run_command(const std::string& cmd) const {
    std::array<char, 4096> buffer{};
    std::string result;

    // NOLINTNEXTLINE(cert-env33-c) — popen is intentional for CLI delegation
    FILE* pipe = popen(cmd.c_str(), "r");
    if (!pipe) {
        // Avoid logging the full command (may contain sensitive key paths)
        spdlog::error("[{}] popen failed", name());
        return {};
    }

    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        result += buffer.data();
    }

    int status = pclose(pipe);
    if (status != 0) {
        // Log only a sanitized summary — don't leak key material or paths
        spdlog::debug("[{}] command exited with status {}", name(), status);
    }

    return result;
}

} // namespace nexus::wireguard
