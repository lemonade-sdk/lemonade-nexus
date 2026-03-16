#include <LemonadeNexus/WireGuard/WireGuardService.hpp>

#include <spdlog/spdlog.h>

#include <array>
#include <cstdio>
#include <cstring>

#ifdef _WIN32
#define popen  _popen
#define pclose _pclose
#endif
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

// BoringTun userspace fallback (compiled only on CLI-fallback platforms)
#if !defined(HAS_EMBEDDABLE_WG) && \
    !(defined(__APPLE__) && defined(HAS_WIREGUARDKIT)) && \
    !(defined(_WIN32) && defined(HAS_WIREGUARD_NT))
#define BORINGTUN_FALLBACK_AVAILABLE 1
#include <boringtun_ffi.h>
#include <sodium.h>            // crypto_box_keypair, sodium_bin2base64
#include <thread>
#include <atomic>
#include <shared_mutex>
#ifdef __linux__
#  include <linux/if_tun.h>
#  include <sys/ioctl.h>
#  include <net/if.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <fcntl.h>
#elif defined(__APPLE__)
#  include <sys/socket.h>
#  include <sys/ioctl.h>
#  include <sys/kern_control.h>
#  include <sys/sys_domain.h>
#  include <net/if_utun.h>
#  include <net/if.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <fcntl.h>
#  include <sys/uio.h>
#endif
#endif // BORINGTUN_FALLBACK_AVAILABLE

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
        // wg not found — fall back to BoringTun userspace WireGuard
        use_boringtun_ = true;
        spdlog::info("[{}] 'wg' not found — using BoringTun userspace fallback", name());
        spdlog::info("[{}] started (interface: '{}', backend: BoringTun/userspace)",
                      name(), interface_name_);
    } else {
        // Trim trailing newline
        if (!version.empty() && version.back() == '\n') {
            version.pop_back();
        }
        spdlog::info("[{}] started (interface: '{}', backend: CLI, tools: '{}')",
                      name(), interface_name_, version);
    }

    // Verify that the `ip` tool is reachable (needed for TUN device config even with BoringTun)
    auto ip_version = run_command("ip -V 2>/dev/null");
    if (ip_version.empty()) {
        if (use_boringtun_) {
            spdlog::warn("[{}] 'ip' command not found — TUN address/route configuration "
                          "may fail (BoringTun still needs iproute2 for TUN setup)", name());
        } else {
            spdlog::warn("[{}] 'ip' command not found — interface setup/teardown will fail "
                          "until iproute2 is installed", name());
        }
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

#ifdef BORINGTUN_FALLBACK_AVAILABLE
    if (bt_) bt_cleanup();
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
    wg_key_from_base64(out, b64.c_str());
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
// BoringTun userspace fallback — state & helpers (multi-peer server mode)
// ---------------------------------------------------------------------------

#ifdef BORINGTUN_FALLBACK_AVAILABLE

struct WireGuardService::BoringTunState {
    struct Cidr {
        uint32_t network;  // host byte order
        uint32_t mask;     // host byte order
    };

    struct Peer {
        Tunn*             tunnel{nullptr};
        std::string       allowed_ips;
        std::vector<Cidr> cidrs;
        sockaddr_in       endpoint{};
        bool              has_endpoint{false};
        uint16_t          persistent_keepalive{25};
    };

    int           tun_fd{-1};
    int           udp_sock{-1};
    std::string   iface_name;
    std::string   private_key;   // base64 Curve25519
    std::string   address;       // e.g. "10.64.0.1/10"
    uint16_t      listen_port{0};

    std::unordered_map<std::string, Peer> peers;   // pubkey → peer
    mutable std::shared_mutex             peer_rwlock;

    std::atomic<bool> running{false};
    std::thread       tun_thread;
    std::thread       udp_thread;
    std::thread       timer_thread;

    /// Parse "10.64.0.0/10" into host-order network + mask.
    static bool parse_cidr(const std::string& cidr_str, Cidr& out) {
        auto slash = cidr_str.find('/');
        if (slash == std::string::npos) return false;
        auto ip_str     = cidr_str.substr(0, slash);
        auto prefix_str = cidr_str.substr(slash + 1);
        int prefix = 0;
        try { prefix = std::stoi(prefix_str); } catch (...) { return false; }
        if (prefix < 0 || prefix > 32) return false;

        in_addr addr{};
        if (inet_pton(AF_INET, ip_str.c_str(), &addr) != 1) return false;

        out.mask    = (prefix == 0) ? 0u : ~((1u << (32 - prefix)) - 1);
        out.network = ntohl(addr.s_addr) & out.mask;
        return true;
    }

    /// Parse comma-separated CIDR list.
    static std::vector<Cidr> parse_allowed_ips(const std::string& allowed_ips) {
        std::vector<Cidr> result;
        std::istringstream stream(allowed_ips);
        std::string token;
        while (std::getline(stream, token, ',')) {
            auto start = token.find_first_not_of(" \t");
            auto end   = token.find_last_not_of(" \t");
            if (start == std::string::npos) continue;
            auto trimmed = token.substr(start, end - start + 1);
            Cidr c{};
            if (parse_cidr(trimmed, c)) result.push_back(c);
        }
        return result;
    }

    /// Find which peer routes a destination IP (host byte order).
    /// Caller must hold at least a shared lock on peer_rwlock.
    Peer* find_peer_for_ip(uint32_t dst_ip) {
        for (auto& [key, peer] : peers) {
            for (const auto& cidr : peer.cidrs) {
                if ((dst_ip & cidr.mask) == cidr.network) {
                    return &peer;
                }
            }
        }
        return nullptr;
    }
};

#else
// Minimal definition so unique_ptr<BoringTunState> can be destroyed on
// platforms that use a specialised backend (embeddable-wg, Apple, Windows).
struct WireGuardService::BoringTunState {};
#endif // BORINGTUN_FALLBACK_AVAILABLE

// Explicit destructor — must appear after BoringTunState is complete.
WireGuardService::~WireGuardService() = default;

// ---------------------------------------------------------------------------
// BoringTun helper methods (only compiled on CLI-fallback platforms)
// ---------------------------------------------------------------------------

#ifdef BORINGTUN_FALLBACK_AVAILABLE

// ── TUN device creation ────────────────────────────────────────────────────

#if defined(__linux__)

int WireGuardService::bt_create_tun_device(std::string& iface_name_out) {
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        spdlog::error("[{}] BoringTun: failed to open /dev/net/tun: {}", name(), strerror(errno));
        return -1;
    }

    struct ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    // Use the WireGuard interface name (e.g. "wg0") instead of auto-numbered
    std::strncpy(ifr.ifr_name, interface_name_.c_str(), IFNAMSIZ - 1);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        spdlog::error("[{}] BoringTun: TUNSETIFF failed: {}", name(), strerror(errno));
        close(fd);
        return -1;
    }

    iface_name_out = ifr.ifr_name;
    spdlog::info("[{}] BoringTun: created TUN device '{}'", name(), iface_name_out);
    return fd;
}

void WireGuardService::bt_configure_address(const std::string& iface,
                                             const std::string& address) {
    auto cmd = "ip addr add " + address + " dev " + iface + " 2>&1";
    auto output = run_command(cmd);
    if (!output.empty()) {
        spdlog::warn("[{}] BoringTun: ip addr add: {}", name(), output);
    }
    cmd = "ip link set " + iface + " up 2>&1";
    output = run_command(cmd);
    if (!output.empty()) {
        spdlog::warn("[{}] BoringTun: ip link set up: {}", name(), output);
    }
}

void WireGuardService::bt_add_route(const std::string& iface, const std::string& cidr) {
    auto cmd = "ip route add " + cidr + " dev " + iface + " 2>/dev/null";
    (void)run_command(cmd);
}

#elif defined(__APPLE__)

int WireGuardService::bt_create_tun_device(std::string& iface_name_out) {
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        spdlog::error("[{}] BoringTun: PF_SYSTEM socket failed: {}", name(), strerror(errno));
        return -1;
    }
    struct ctl_info info{};
    strlcpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name));
    if (ioctl(fd, CTLIOCGINFO, &info) < 0) {
        spdlog::error("[{}] BoringTun: CTLIOCGINFO failed: {}", name(), strerror(errno));
        close(fd);
        return -1;
    }
    struct sockaddr_ctl sc{};
    sc.sc_len     = sizeof(sc);
    sc.sc_family  = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_id      = info.ctl_id;
    sc.sc_unit    = 0;
    if (connect(fd, reinterpret_cast<sockaddr*>(&sc), sizeof(sc)) < 0) {
        spdlog::error("[{}] BoringTun: utun connect failed: {}", name(), strerror(errno));
        close(fd);
        return -1;
    }
    char ifname[IFNAMSIZ]{};
    socklen_t ifname_len = sizeof(ifname);
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len) < 0) {
        spdlog::error("[{}] BoringTun: failed to get utun name: {}", name(), strerror(errno));
        close(fd);
        return -1;
    }
    iface_name_out = ifname;
    spdlog::info("[{}] BoringTun: created TUN device '{}'", name(), iface_name_out);
    return fd;
}

void WireGuardService::bt_configure_address(const std::string& iface,
                                             const std::string& address) {
    auto ip = address;
    auto slash = ip.find('/');
    if (slash != std::string::npos) ip = ip.substr(0, slash);
    auto cmd = "ifconfig " + iface + " inet " + ip + " " + ip + " up";
    (void)run_command(cmd + " 2>&1");
}

void WireGuardService::bt_add_route(const std::string& iface, const std::string& cidr) {
    auto cmd = "route add -net " + cidr + " -interface " + iface + " 2>/dev/null";
    (void)run_command(cmd);
}

#else
// Unsupported platform — stubs
int  WireGuardService::bt_create_tun_device(std::string&) { return -1; }
void WireGuardService::bt_configure_address(const std::string&, const std::string&) {}
void WireGuardService::bt_add_route(const std::string&, const std::string&) {}
#endif

// ── Packet forwarding loops ────────────────────────────────────────────────

void WireGuardService::bt_tun_to_udp_loop() {
    constexpr size_t kBufSize = 65536;
    std::vector<uint8_t> wg_buf(kBufSize);

    spdlog::debug("[{}] BoringTun: TUN→UDP loop started", name());

    while (bt_->running) {
        uint8_t* ip_packet = nullptr;
        uint32_t ip_len    = 0;

#if defined(__APPLE__)
        std::vector<uint8_t> tun_buf(kBufSize);
        auto n = read(bt_->tun_fd, tun_buf.data(), tun_buf.size());
        if (n <= 4) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        ip_packet = tun_buf.data() + 4;  // skip 4-byte AF header
        ip_len    = static_cast<uint32_t>(n - 4);
#elif defined(__linux__)
        std::vector<uint8_t> tun_buf(kBufSize);
        auto n = read(bt_->tun_fd, tun_buf.data(), tun_buf.size());
        if (n <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        ip_packet = tun_buf.data();
        ip_len    = static_cast<uint32_t>(n);
#else
        std::this_thread::sleep_for(std::chrono::seconds(1));
        continue;
#endif

        if (ip_len < 20) continue; // too short for IPv4 header

        // Parse destination IP from IPv4 header (bytes 16–19)
        uint32_t dst_ip_nbo;
        std::memcpy(&dst_ip_nbo, ip_packet + 16, 4);
        uint32_t dst_ip = ntohl(dst_ip_nbo);

        std::shared_lock lock(bt_->peer_rwlock);
        auto* peer = bt_->find_peer_for_ip(dst_ip);
        if (!peer || !peer->tunnel) continue;

        auto r = wireguard_write(peer->tunnel, ip_packet, ip_len,
                                 wg_buf.data(), static_cast<uint32_t>(wg_buf.size()));

        if (r.op == WRITE_TO_NETWORK && r.size > 0 && peer->has_endpoint) {
            sendto(bt_->udp_sock, wg_buf.data(), r.size, 0,
                   reinterpret_cast<const sockaddr*>(&peer->endpoint),
                   sizeof(peer->endpoint));
        }
    }

    spdlog::debug("[{}] BoringTun: TUN→UDP loop stopped", name());
}

void WireGuardService::bt_udp_to_tun_loop() {
    constexpr size_t kBufSize = 65536;
    std::vector<uint8_t> udp_buf(kBufSize);
    std::vector<uint8_t> ip_buf(kBufSize);

    spdlog::debug("[{}] BoringTun: UDP→TUN loop started", name());

    while (bt_->running) {
        sockaddr_in from{};
        socklen_t from_len = sizeof(from);
        auto n = recvfrom(bt_->udp_sock, udp_buf.data(), udp_buf.size(), 0,
                          reinterpret_cast<sockaddr*>(&from), &from_len);
        if (n <= 0) continue; // timeout or error

        std::shared_lock lock(bt_->peer_rwlock);

        // Try each peer's tunnel to decrypt (O(n) but fine for reasonable peer counts)
        for (auto& [key, peer] : bt_->peers) {
            if (!peer.tunnel) continue;

            auto r = wireguard_read(peer.tunnel,
                                    udp_buf.data(), static_cast<uint32_t>(n),
                                    ip_buf.data(), static_cast<uint32_t>(ip_buf.size()));

            if (r.op == WRITE_TO_TUNNEL_IPV4 || r.op == WRITE_TO_TUNNEL_IPV6) {
                // Successfully decrypted — write to TUN
#if defined(__APPLE__)
                uint32_t af = (r.op == WRITE_TO_TUNNEL_IPV4) ? htonl(AF_INET) : htonl(AF_INET6);
                struct iovec iov[2];
                iov[0].iov_base = &af;
                iov[0].iov_len  = 4;
                iov[1].iov_base = ip_buf.data();
                iov[1].iov_len  = r.size;
                writev(bt_->tun_fd, iov, 2);
#elif defined(__linux__)
                (void)write(bt_->tun_fd, ip_buf.data(), r.size);
#endif
                // Update peer endpoint (roaming support)
                peer.endpoint     = from;
                peer.has_endpoint = true;

                // BoringTun may produce follow-up output (handshake + data)
                while (true) {
                    auto r2 = wireguard_read(peer.tunnel,
                                             nullptr, 0,
                                             ip_buf.data(), static_cast<uint32_t>(ip_buf.size()));
                    if (r2.op == WRITE_TO_NETWORK && r2.size > 0) {
                        sendto(bt_->udp_sock, ip_buf.data(), r2.size, 0,
                               reinterpret_cast<const sockaddr*>(&from), sizeof(from));
                    } else {
                        break;
                    }
                }
                break;
            }

            if (r.op == WRITE_TO_NETWORK && r.size > 0) {
                // Handshake response — send back to sender
                sendto(bt_->udp_sock, ip_buf.data(), r.size, 0,
                       reinterpret_cast<const sockaddr*>(&from), sizeof(from));
                // Update peer endpoint
                peer.endpoint     = from;
                peer.has_endpoint = true;

                // Check for follow-up output
                while (true) {
                    auto r2 = wireguard_read(peer.tunnel,
                                             nullptr, 0,
                                             ip_buf.data(), static_cast<uint32_t>(ip_buf.size()));
                    if (r2.op == WRITE_TO_NETWORK && r2.size > 0) {
                        sendto(bt_->udp_sock, ip_buf.data(), r2.size, 0,
                               reinterpret_cast<const sockaddr*>(&from), sizeof(from));
                    } else if (r2.op == WRITE_TO_TUNNEL_IPV4 || r2.op == WRITE_TO_TUNNEL_IPV6) {
#if defined(__APPLE__)
                        uint32_t af2 = (r2.op == WRITE_TO_TUNNEL_IPV4)
                                            ? htonl(AF_INET) : htonl(AF_INET6);
                        struct iovec iov2[2];
                        iov2[0].iov_base = &af2;
                        iov2[0].iov_len  = 4;
                        iov2[1].iov_base = ip_buf.data();
                        iov2[1].iov_len  = r2.size;
                        writev(bt_->tun_fd, iov2, 2);
#elif defined(__linux__)
                        (void)write(bt_->tun_fd, ip_buf.data(), r2.size);
#endif
                    } else {
                        break;
                    }
                }
                break;
            }
            // WIREGUARD_ERROR or WIREGUARD_DONE — try next peer
        }
    }

    spdlog::debug("[{}] BoringTun: UDP→TUN loop stopped", name());
}

void WireGuardService::bt_timer_loop() {
    constexpr size_t kBufSize = 256;
    std::array<uint8_t, kBufSize> buf{};

    spdlog::debug("[{}] BoringTun: timer loop started", name());

    while (bt_->running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));

        std::shared_lock lock(bt_->peer_rwlock);
        for (auto& [key, peer] : bt_->peers) {
            if (!peer.tunnel) continue;

            auto r = wireguard_tick(peer.tunnel, buf.data(), static_cast<uint32_t>(buf.size()));
            if (r.op == WRITE_TO_NETWORK && r.size > 0 && peer.has_endpoint) {
                sendto(bt_->udp_sock, buf.data(), r.size, 0,
                       reinterpret_cast<const sockaddr*>(&peer.endpoint),
                       sizeof(peer.endpoint));
            }
        }
    }

    spdlog::debug("[{}] BoringTun: timer loop stopped", name());
}

// ── Cleanup ────────────────────────────────────────────────────────────────

void WireGuardService::bt_cleanup() {
    if (!bt_) return;

    bt_->running = false;

    if (bt_->tun_thread.joinable())   bt_->tun_thread.join();
    if (bt_->udp_thread.joinable())   bt_->udp_thread.join();
    if (bt_->timer_thread.joinable()) bt_->timer_thread.join();

    {
        std::unique_lock lock(bt_->peer_rwlock);
        for (auto& [key, peer] : bt_->peers) {
            if (peer.tunnel) {
                tunnel_free(peer.tunnel);
                peer.tunnel = nullptr;
            }
        }
        bt_->peers.clear();
    }

    if (bt_->tun_fd >= 0)   { close(bt_->tun_fd);   bt_->tun_fd   = -1; }
    if (bt_->udp_sock >= 0) { close(bt_->udp_sock); bt_->udp_sock = -1; }

    // Remove the TUN device (Linux only — macOS utun is auto-removed on close)
#ifdef __linux__
    if (!bt_->iface_name.empty()) {
        (void)run_command("ip link del " + bt_->iface_name + " 2>/dev/null");
    }
#endif

    bt_.reset();
}

#endif // BORINGTUN_FALLBACK_AVAILABLE

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
#ifdef BORINGTUN_FALLBACK_AVAILABLE
    if (use_boringtun_) {
        // Generate Curve25519 keypair via libsodium (no wg CLI needed)
        unsigned char pk[crypto_box_PUBLICKEYBYTES];
        unsigned char sk[crypto_box_SECRETKEYBYTES];
        crypto_box_keypair(pk, sk);

        // Encode as base64 (WireGuard key format: 44 chars, standard base64)
        char pk_b64[sodium_base64_ENCODED_LEN(crypto_box_PUBLICKEYBYTES,
                                               sodium_base64_VARIANT_ORIGINAL)];
        char sk_b64[sodium_base64_ENCODED_LEN(crypto_box_SECRETKEYBYTES,
                                               sodium_base64_VARIANT_ORIGINAL)];
        sodium_bin2base64(pk_b64, sizeof(pk_b64), pk, crypto_box_PUBLICKEYBYTES,
                          sodium_base64_VARIANT_ORIGINAL);
        sodium_bin2base64(sk_b64, sizeof(sk_b64), sk, crypto_box_SECRETKEYBYTES,
                          sodium_base64_VARIANT_ORIGINAL);

        spdlog::debug("[{}] generated keypair via libsodium (pubkey: {})", name(), pk_b64);
        return WgKeypair{
            .public_key  = std::string(pk_b64),
            .private_key = std::string(sk_b64),
        };
    }
#endif // BORINGTUN_FALLBACK_AVAILABLE

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
#ifdef BORINGTUN_FALLBACK_AVAILABLE
    if (use_boringtun_) {
        // In BoringTun mode, just store the config — actual interface setup
        // happens in do_setup_interface() which creates the TUN + UDP socket.
        if (!bt_) bt_ = std::make_unique<BoringTunState>();
        bt_->private_key = config.private_key;
        bt_->listen_port = config.listen_port;
        bt_->address     = config.address;
        spdlog::info("[{}] configured interface '{}' via BoringTun (listen_port: {}, address: {})",
                      name(), interface_name_, config.listen_port, config.address);
        return true;
    }
#endif // BORINGTUN_FALLBACK_AVAILABLE

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
            std::memcpy(&peer->endpoint.addr, &ep_addr, sizeof(peer->endpoint.addr));
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
#ifdef BORINGTUN_FALLBACK_AVAILABLE
    if (use_boringtun_) {
        if (!bt_) {
            spdlog::error("[{}] add_peer: BoringTun state not initialized", name());
            return false;
        }

        // Create a per-peer BoringTun tunnel (our privkey ↔ peer pubkey)
        Tunn* t = new_tunnel(bt_->private_key.c_str(), pubkey.c_str(), nullptr, 0);
        if (!t) {
            spdlog::error("[{}] BoringTun: new_tunnel failed for peer {}", name(), pubkey);
            return false;
        }

        BoringTunState::Peer peer;
        peer.tunnel      = t;
        peer.allowed_ips = allowed_ips;
        peer.cidrs       = BoringTunState::parse_allowed_ips(allowed_ips);

        // Parse endpoint if provided
        if (!endpoint.empty()) {
            auto colon = endpoint.rfind(':');
            if (colon != std::string::npos) {
                auto host = endpoint.substr(0, colon);
                auto port_str = endpoint.substr(colon + 1);
                std::memset(&peer.endpoint, 0, sizeof(peer.endpoint));
                peer.endpoint.sin_family = AF_INET;
                if (inet_pton(AF_INET, host.c_str(), &peer.endpoint.sin_addr) == 1) {
                    try {
                        peer.endpoint.sin_port = htons(
                            static_cast<uint16_t>(std::stoi(port_str)));
                        peer.has_endpoint = true;
                    } catch (...) {}
                }
            }
        }

        {
            std::unique_lock lock(bt_->peer_rwlock);
            // Remove existing tunnel for this peer if any
            auto it = bt_->peers.find(pubkey);
            if (it != bt_->peers.end()) {
                if (it->second.tunnel) tunnel_free(it->second.tunnel);
                bt_->peers.erase(it);
            }
            bt_->peers.emplace(pubkey, std::move(peer));
        }

        // Force initial handshake if peer has an endpoint
        if (peer.has_endpoint) {
            std::array<uint8_t, 256> buf{};
            auto r = wireguard_force_handshake(t, buf.data(),
                                                static_cast<uint32_t>(buf.size()));
            if (r.op == WRITE_TO_NETWORK && r.size > 0 && bt_->udp_sock >= 0) {
                std::shared_lock lock(bt_->peer_rwlock);
                auto it = bt_->peers.find(pubkey);
                if (it != bt_->peers.end() && it->second.has_endpoint) {
                    sendto(bt_->udp_sock, buf.data(), r.size, 0,
                           reinterpret_cast<const sockaddr*>(&it->second.endpoint),
                           sizeof(it->second.endpoint));
                }
            }
        }

        spdlog::info("[{}] added peer {} via BoringTun (allowed_ips: {}, endpoint: {})",
                      name(), pubkey, allowed_ips, endpoint);
        return true;
    }
#endif // BORINGTUN_FALLBACK_AVAILABLE

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
#ifdef BORINGTUN_FALLBACK_AVAILABLE
    if (use_boringtun_ && bt_) {
        std::unique_lock lock(bt_->peer_rwlock);
        auto it = bt_->peers.find(pubkey);
        if (it != bt_->peers.end()) {
            if (it->second.tunnel) tunnel_free(it->second.tunnel);
            bt_->peers.erase(it);
            spdlog::info("[{}] removed peer {} via BoringTun", name(), pubkey);
            return true;
        }
        spdlog::warn("[{}] remove_peer: peer {} not found in BoringTun state", name(), pubkey);
        return false;
    }
#endif // BORINGTUN_FALLBACK_AVAILABLE

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
        sockaddr_storage ep_storage{};
        std::memcpy(&ep_storage, &p->endpoint.addr, sizeof(p->endpoint.addr));
        peer.endpoint = format_endpoint(ep_storage);
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
#ifdef BORINGTUN_FALLBACK_AVAILABLE
    if (use_boringtun_ && bt_) {
        std::shared_lock lock(bt_->peer_rwlock);
        std::vector<WgPeer> peers;
        peers.reserve(bt_->peers.size());
        for (const auto& [key, p] : bt_->peers) {
            WgPeer peer;
            peer.public_key   = key;
            peer.allowed_ips  = p.allowed_ips;
            peer.persistent_keepalive = p.persistent_keepalive;
            if (p.has_endpoint) {
                char ip_buf[INET_ADDRSTRLEN]{};
                inet_ntop(AF_INET, &p.endpoint.sin_addr, ip_buf, sizeof(ip_buf));
                peer.endpoint = std::string(ip_buf) + ":" +
                                std::to_string(ntohs(p.endpoint.sin_port));
            }
            peers.push_back(std::move(peer));
        }
        spdlog::debug("[{}] enumerated {} peers via BoringTun", name(), peers.size());
        return peers;
    }
#endif // BORINGTUN_FALLBACK_AVAILABLE

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
#ifdef BORINGTUN_FALLBACK_AVAILABLE
    if (use_boringtun_ && bt_) {
        auto colon = new_endpoint.rfind(':');
        if (colon == std::string::npos) {
            spdlog::error("[{}] update_endpoint: invalid endpoint format '{}'",
                           name(), new_endpoint);
            return false;
        }
        auto host = new_endpoint.substr(0, colon);
        auto port_str = new_endpoint.substr(colon + 1);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
            spdlog::error("[{}] update_endpoint: invalid IP '{}'", name(), host);
            return false;
        }
        try {
            addr.sin_port = htons(static_cast<uint16_t>(std::stoi(port_str)));
        } catch (...) {
            spdlog::error("[{}] update_endpoint: invalid port '{}'", name(), port_str);
            return false;
        }

        std::unique_lock lock(bt_->peer_rwlock);
        auto it = bt_->peers.find(pubkey);
        if (it == bt_->peers.end()) {
            spdlog::error("[{}] update_endpoint: peer {} not found", name(), pubkey);
            return false;
        }
        it->second.endpoint     = addr;
        it->second.has_endpoint = true;

        spdlog::info("[{}] updated endpoint for peer {} to {} via BoringTun",
                      name(), pubkey, new_endpoint);
        return true;
    }
#endif // BORINGTUN_FALLBACK_AVAILABLE

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
#ifdef BORINGTUN_FALLBACK_AVAILABLE
    if (use_boringtun_) {
        // --- BoringTun userspace fallback ---

        // Clean up any previous state
        if (bt_) bt_cleanup();
        bt_ = std::make_unique<BoringTunState>();
        bt_->private_key = config.private_key;
        bt_->listen_port = config.listen_port;
        bt_->address     = config.address;

        // 1. Create TUN device
        bt_->tun_fd = bt_create_tun_device(bt_->iface_name);
        if (bt_->tun_fd < 0) {
            spdlog::error("[{}] BoringTun: failed to create TUN device", name());
            bt_.reset();
            return false;
        }

        // 2. Configure address on TUN
        if (!config.address.empty()) {
            bt_configure_address(bt_->iface_name, config.address);
        }

        // 3. Create UDP socket bound to listen port
        bt_->udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (bt_->udp_sock < 0) {
            spdlog::error("[{}] BoringTun: failed to create UDP socket: {}",
                           name(), strerror(errno));
            close(bt_->tun_fd);
            bt_.reset();
            return false;
        }

        // Allow address reuse
        int optval = 1;
        setsockopt(bt_->udp_sock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

        sockaddr_in bind_addr{};
        bind_addr.sin_family      = AF_INET;
        bind_addr.sin_addr.s_addr = INADDR_ANY;
        bind_addr.sin_port        = htons(config.listen_port);
        if (bind(bt_->udp_sock, reinterpret_cast<sockaddr*>(&bind_addr),
                 sizeof(bind_addr)) < 0) {
            spdlog::error("[{}] BoringTun: failed to bind UDP port {}: {}",
                           name(), config.listen_port, strerror(errno));
            close(bt_->udp_sock);
            close(bt_->tun_fd);
            bt_.reset();
            return false;
        }

        // Set receive timeout for clean shutdown
        struct timeval tv{};
        tv.tv_sec = 1;
        setsockopt(bt_->udp_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // Set TUN fd non-blocking
        fcntl(bt_->tun_fd, F_SETFL, O_NONBLOCK);

        // 4. Add initial peers (create per-peer tunnels)
        for (const auto& peer : peers) {
            if (!is_valid_pubkey(peer.public_key)) {
                spdlog::warn("[{}] BoringTun: skipping peer with invalid pubkey '{}'",
                              name(), peer.public_key);
                continue;
            }

            Tunn* t = new_tunnel(config.private_key.c_str(),
                                 peer.public_key.c_str(), nullptr, 0);
            if (!t) {
                spdlog::error("[{}] BoringTun: new_tunnel failed for peer {}",
                               name(), peer.public_key);
                continue;
            }

            BoringTunState::Peer bt_peer;
            bt_peer.tunnel      = t;
            bt_peer.allowed_ips = peer.allowed_ips;
            bt_peer.cidrs       = BoringTunState::parse_allowed_ips(peer.allowed_ips);
            bt_peer.persistent_keepalive = peer.persistent_keepalive;

            // Parse endpoint
            if (!peer.endpoint.empty()) {
                auto colon = peer.endpoint.rfind(':');
                if (colon != std::string::npos) {
                    auto host = peer.endpoint.substr(0, colon);
                    std::memset(&bt_peer.endpoint, 0, sizeof(bt_peer.endpoint));
                    bt_peer.endpoint.sin_family = AF_INET;
                    if (inet_pton(AF_INET, host.c_str(), &bt_peer.endpoint.sin_addr) == 1) {
                        try {
                            bt_peer.endpoint.sin_port = htons(
                                static_cast<uint16_t>(std::stoi(
                                    peer.endpoint.substr(colon + 1))));
                            bt_peer.has_endpoint = true;
                        } catch (...) {}
                    }
                }
            }

            // Add routes for peer's allowed IPs
            if (!peer.allowed_ips.empty()) {
                std::istringstream ip_stream(peer.allowed_ips);
                std::string cidr;
                while (std::getline(ip_stream, cidr, ',')) {
                    auto start = cidr.find_first_not_of(" \t");
                    auto end   = cidr.find_last_not_of(" \t");
                    if (start == std::string::npos) continue;
                    auto trimmed = cidr.substr(start, end - start + 1);
                    if (trimmed.ends_with("/32")) continue;
                    bt_add_route(bt_->iface_name, trimmed);
                }
            }

            bt_->peers.emplace(peer.public_key, std::move(bt_peer));
        }

        // 5. Start packet forwarding threads
        bt_->running = true;
        bt_->tun_thread   = std::thread([this] { bt_tun_to_udp_loop(); });
        bt_->udp_thread   = std::thread([this] { bt_udp_to_tun_loop(); });
        bt_->timer_thread = std::thread([this] { bt_timer_loop(); });

        spdlog::info("[{}] interface '{}' (TUN: {}) is up via BoringTun with {} peers, "
                      "listening on UDP port {}",
                      name(), interface_name_, bt_->iface_name, bt_->peers.size(),
                      config.listen_port);
        return true;
    }
#endif // BORINGTUN_FALLBACK_AVAILABLE

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
#ifdef BORINGTUN_FALLBACK_AVAILABLE
    if (use_boringtun_ && bt_) {
        auto iface = bt_->iface_name;
        bt_cleanup();
        spdlog::info("[{}] interface '{}' (TUN: {}) torn down via BoringTun",
                      name(), interface_name_, iface);
        return true;
    }
#endif // BORINGTUN_FALLBACK_AVAILABLE

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
