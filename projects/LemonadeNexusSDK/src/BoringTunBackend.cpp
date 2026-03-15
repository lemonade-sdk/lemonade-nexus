#include <LemonadeNexusSDK/BoringTunBackend.hpp>
#include <LemonadeNexusSDK/boringtun_ffi.h>

#include <spdlog/spdlog.h>

#include <atomic>
#include <array>
#include <cstring>
#include <thread>
#include <vector>

// Platform includes for TUN device and UDP socket
#if defined(__APPLE__)
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
#elif defined(__linux__)
#  include <linux/if_tun.h>
#  include <sys/socket.h>
#  include <sys/ioctl.h>
#  include <net/if.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <fcntl.h>
#elif defined(_WIN32)
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <LemonadeNexusSDK/wintun.h>
#  pragma comment(lib, "ws2_32.lib")
#  pragma comment(lib, "iphlpapi.lib")
#endif

namespace lnsdk {

// ---------------------------------------------------------------------------
// PIMPL
// ---------------------------------------------------------------------------

struct BoringTunBackend::Impl {
    Tunn*             tunnel{nullptr};
    WireGuardConfig   config;
    std::string       iface_name;
    int               tun_fd{-1};
#if defined(_WIN32)
    SOCKET            udp_sock{INVALID_SOCKET};
#else
    int               udp_fd{-1};
#endif
    sockaddr_in       server_addr{};
    std::atomic<bool> running{false};
    std::thread       tun_to_udp_thread;
    std::thread       udp_to_tun_thread;
    std::thread       timer_thread;

#if defined(_WIN32)
    WintunApi                  wt;
    WINTUN_ADAPTER_HANDLE      wt_adapter{nullptr};
    WINTUN_SESSION_HANDLE      wt_session{nullptr};
    HANDLE                     wt_read_event{nullptr};
#endif
};

BoringTunBackend::BoringTunBackend()
    : impl_{std::make_unique<Impl>()} {}

BoringTunBackend::~BoringTunBackend() {
    if (impl_ && impl_->running) {
        do_bring_down();
    }
}

// ---------------------------------------------------------------------------
// Platform: macOS utun
// ---------------------------------------------------------------------------

#if defined(__APPLE__)

int BoringTunBackend::create_tun_device(std::string& iface_name_out) {
    int fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (fd < 0) {
        spdlog::error("[BoringTun] failed to create PF_SYSTEM socket: {}", strerror(errno));
        return -1;
    }

    struct ctl_info info{};
    strlcpy(info.ctl_name, UTUN_CONTROL_NAME, sizeof(info.ctl_name));
    if (ioctl(fd, CTLIOCGINFO, &info) < 0) {
        spdlog::error("[BoringTun] CTLIOCGINFO failed: {}", strerror(errno));
        close(fd);
        return -1;
    }

    struct sockaddr_ctl sc{};
    sc.sc_len     = sizeof(sc);
    sc.sc_family  = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_id      = info.ctl_id;
    sc.sc_unit    = 0; // Let the system assign utunN

    if (connect(fd, reinterpret_cast<sockaddr*>(&sc), sizeof(sc)) < 0) {
        spdlog::error("[BoringTun] utun connect failed: {}", strerror(errno));
        close(fd);
        return -1;
    }

    // Get the assigned interface name (utunN)
    char ifname[IFNAMSIZ]{};
    socklen_t ifname_len = sizeof(ifname);
    if (getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &ifname_len) < 0) {
        spdlog::error("[BoringTun] failed to get utun name: {}", strerror(errno));
        close(fd);
        return -1;
    }
    iface_name_out = ifname;

    spdlog::info("[BoringTun] created TUN device: {}", iface_name_out);
    return fd;
}

void BoringTunBackend::configure_tun_address(const std::string& iface,
                                              const std::string& tunnel_ip) {
    // Strip CIDR suffix if present (e.g. "10.64.0.1/32" → "10.64.0.1")
    auto ip = tunnel_ip;
    auto slash = ip.find('/');
    if (slash != std::string::npos) ip = ip.substr(0, slash);

    // ifconfig utunN inet <ip> <ip> up
    std::string cmd = "ifconfig " + iface + " inet " + ip + " " + ip + " up";
    spdlog::info("[BoringTun] configuring TUN: {}", cmd);
    system(cmd.c_str());
}

void BoringTunBackend::add_route(const std::string& iface, const std::string& cidr) {
    // route add -net <cidr> -interface <iface>
    std::string cmd = "route add -net " + cidr + " -interface " + iface;
    spdlog::info("[BoringTun] adding route: {}", cmd);
    system(cmd.c_str());
}

// ---------------------------------------------------------------------------
// Platform: Linux TUN
// ---------------------------------------------------------------------------

#elif defined(__linux__)

int BoringTunBackend::create_tun_device(std::string& iface_name_out) {
    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0) {
        spdlog::error("[BoringTun] failed to open /dev/net/tun: {}", strerror(errno));
        return -1;
    }

    struct ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, "lnsdk%d", IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        spdlog::error("[BoringTun] TUNSETIFF failed: {}", strerror(errno));
        close(fd);
        return -1;
    }

    iface_name_out = ifr.ifr_name;
    spdlog::info("[BoringTun] created TUN device: {}", iface_name_out);
    return fd;
}

void BoringTunBackend::configure_tun_address(const std::string& iface,
                                              const std::string& tunnel_ip) {
    auto ip = tunnel_ip;
    auto slash = ip.find('/');
    std::string cidr = "32";
    if (slash != std::string::npos) {
        cidr = ip.substr(slash + 1);
        ip = ip.substr(0, slash);
    }

    std::string cmd = "ip addr add " + ip + "/" + cidr + " dev " + iface;
    spdlog::info("[BoringTun] configuring TUN: {}", cmd);
    system(cmd.c_str());

    cmd = "ip link set " + iface + " up";
    system(cmd.c_str());
}

void BoringTunBackend::add_route(const std::string& iface, const std::string& cidr) {
    std::string cmd = "ip route add " + cidr + " dev " + iface;
    spdlog::info("[BoringTun] adding route: {}", cmd);
    system(cmd.c_str());
}

// ---------------------------------------------------------------------------
// Platform: Windows via WinTun
// ---------------------------------------------------------------------------

#elif defined(_WIN32)

int BoringTunBackend::create_tun_device(std::string& iface_name_out) {
    // Load wintun.dll at runtime
    if (!impl_->wt.load()) {
        spdlog::error("[BoringTun] failed to load wintun.dll — "
                      "ensure wintun.dll is in the executable directory or PATH");
        return -1;
    }

    // Create adapter with a deterministic GUID so repeated runs reuse the same adapter
    static const GUID adapter_guid =
        {0x4c4f4e45, 0x4d4f, 0x4e41, {0x44, 0x45, 0x4e, 0x45, 0x58, 0x55, 0x53, 0x00}};

    impl_->wt_adapter = impl_->wt.CreateAdapter(
        L"LemonadeNexus", L"LemonadeNexus", &adapter_guid);
    if (!impl_->wt_adapter) {
        spdlog::error("[BoringTun] WintunCreateAdapter failed (err={})", GetLastError());
        impl_->wt.unload();
        return -1;
    }

    // Start session with 8 MB ring buffer (must be power of 2, range 0x20000..0x4000000)
    impl_->wt_session = impl_->wt.StartSession(impl_->wt_adapter, 0x800000);
    if (!impl_->wt_session) {
        spdlog::error("[BoringTun] WintunStartSession failed (err={})", GetLastError());
        impl_->wt.CloseAdapter(impl_->wt_adapter);
        impl_->wt_adapter = nullptr;
        impl_->wt.unload();
        return -1;
    }

    impl_->wt_read_event = impl_->wt.GetReadWaitEvent(impl_->wt_session);

    iface_name_out = "LemonadeNexus";
    spdlog::info("[BoringTun] created WinTun adapter: {}", iface_name_out);

    // Return 0 to indicate success (no fd on Windows)
    return 0;
}

void BoringTunBackend::configure_tun_address(const std::string& iface,
                                              const std::string& tunnel_ip) {
    auto ip = tunnel_ip;
    std::string mask = "32";
    auto slash = ip.find('/');
    if (slash != std::string::npos) {
        mask = ip.substr(slash + 1);
        ip = ip.substr(0, slash);
    }

    // netsh interface ip set address "LemonadeNexus" static <ip> <mask>
    std::string cmd = "netsh interface ip set address \"" + iface +
                      "\" static " + ip + " 255.255.255.255";
    spdlog::info("[BoringTun] configuring TUN: {}", cmd);
    system(cmd.c_str());
}

void BoringTunBackend::add_route(const std::string& iface, const std::string& cidr) {
    // Parse CIDR to network + prefix
    auto slash = cidr.find('/');
    if (slash == std::string::npos) return;

    auto network = cidr.substr(0, slash);
    auto prefix = cidr.substr(slash + 1);

    // Convert prefix length to subnet mask
    auto prefix_len = std::stoi(prefix);
    uint32_t mask_val = (prefix_len == 0) ? 0 : ~((1u << (32 - prefix_len)) - 1);
    char mask_str[16];
    snprintf(mask_str, sizeof(mask_str), "%u.%u.%u.%u",
             (mask_val >> 24) & 0xFF, (mask_val >> 16) & 0xFF,
             (mask_val >> 8) & 0xFF, mask_val & 0xFF);

    std::string cmd = "route add " + network + " mask " + mask_str +
                      " 0.0.0.0 if \"" + iface + "\"";
    spdlog::info("[BoringTun] adding route: {}", cmd);
    system(cmd.c_str());
}

#else

int BoringTunBackend::create_tun_device(std::string&) { return -1; }
void BoringTunBackend::configure_tun_address(const std::string&, const std::string&) {}
void BoringTunBackend::add_route(const std::string&, const std::string&) {}

#endif

// ---------------------------------------------------------------------------
// bring_up: create TUN, UDP socket, BoringTun tunnel, start threads
// ---------------------------------------------------------------------------

StatusResult BoringTunBackend::do_bring_up(const WireGuardConfig& config) {
    StatusResult result;
    impl_->config = config;

    // 1. Create the BoringTun tunnel instance
    impl_->tunnel = new_tunnel(
        config.private_key.c_str(),
        config.server_public_key.c_str(),
        nullptr,  // no log callback
        0         // silent
    );
    if (!impl_->tunnel) {
        result.error = "BoringTun: failed to create tunnel (bad keys?)";
        spdlog::error("[BoringTun] {}", result.error);
        return result;
    }

    // 2. Create TUN device
    impl_->tun_fd = create_tun_device(impl_->iface_name);
    if (impl_->tun_fd < 0) {
        result.error = "BoringTun: failed to create TUN device";
        tunnel_free(impl_->tunnel);
        impl_->tunnel = nullptr;
        return result;
    }

    // 3. Configure TUN address and routes
    configure_tun_address(impl_->iface_name, config.tunnel_ip);
    for (const auto& cidr : config.allowed_ips) {
        add_route(impl_->iface_name, cidr);
    }

    // 4. Create UDP socket for WireGuard traffic
#if defined(_WIN32)
    impl_->udp_sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (impl_->udp_sock == INVALID_SOCKET) {
        result.error = "BoringTun: failed to create UDP socket";
        spdlog::error("[BoringTun] {} (WSA err={})", result.error, WSAGetLastError());
        // Tear down WinTun session
        impl_->wt.EndSession(impl_->wt_session);
        impl_->wt.CloseAdapter(impl_->wt_adapter);
        impl_->wt_session = nullptr;
        impl_->wt_adapter = nullptr;
        impl_->wt.unload();
        tunnel_free(impl_->tunnel);
        impl_->tunnel = nullptr;
        return result;
    }
#else
    impl_->udp_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (impl_->udp_fd < 0) {
        result.error = "BoringTun: failed to create UDP socket";
        spdlog::error("[BoringTun] {}", result.error);
        close(impl_->tun_fd);
        tunnel_free(impl_->tunnel);
        impl_->tunnel = nullptr;
        return result;
    }
#endif

    // Parse server endpoint "host:port"
    std::memset(&impl_->server_addr, 0, sizeof(impl_->server_addr));
    impl_->server_addr.sin_family = AF_INET;

    auto colon = config.server_endpoint.rfind(':');
    if (colon != std::string::npos) {
        auto host = config.server_endpoint.substr(0, colon);
        auto port = std::stoi(config.server_endpoint.substr(colon + 1));
        inet_pton(AF_INET, host.c_str(), &impl_->server_addr.sin_addr);
        impl_->server_addr.sin_port = htons(static_cast<uint16_t>(port));
    }

    // Set non-blocking / receive timeout for clean shutdown
#if defined(_WIN32)
    DWORD rcv_timeout = 1000; // 1 second
    setsockopt(impl_->udp_sock, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&rcv_timeout), sizeof(rcv_timeout));
#else
    fcntl(impl_->tun_fd, F_SETFL, O_NONBLOCK);

    struct timeval tv{};
    tv.tv_sec = 1;
    setsockopt(impl_->udp_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif

    // 5. Force initial handshake
    {
        std::array<uint8_t, 256> buf{};
        auto r = wireguard_force_handshake(impl_->tunnel, buf.data(),
                                            static_cast<uint32_t>(buf.size()));
        if (r.op == WRITE_TO_NETWORK && r.size > 0) {
#if defined(_WIN32)
            sendto(impl_->udp_sock, reinterpret_cast<const char*>(buf.data()),
                   static_cast<int>(r.size), 0,
                   reinterpret_cast<sockaddr*>(&impl_->server_addr),
                   sizeof(impl_->server_addr));
#else
            sendto(impl_->udp_fd, buf.data(), r.size, 0,
                   reinterpret_cast<sockaddr*>(&impl_->server_addr),
                   sizeof(impl_->server_addr));
#endif
            spdlog::info("[BoringTun] sent handshake initiation ({} bytes)", r.size);
        }
    }

    // 6. Start packet forwarding threads
    impl_->running = true;
    impl_->tun_to_udp_thread = std::thread([this] { tun_to_udp_loop(); });
    impl_->udp_to_tun_thread = std::thread([this] { udp_to_tun_loop(); });
    impl_->timer_thread      = std::thread([this] { timer_loop(); });

    result.ok = true;
    spdlog::info("[BoringTun] tunnel up: iface={} ip={} endpoint={}",
                  impl_->iface_name, config.tunnel_ip, config.server_endpoint);
    return result;
}

// ---------------------------------------------------------------------------
// bring_down: stop threads, close sockets
// ---------------------------------------------------------------------------

StatusResult BoringTunBackend::do_bring_down() {
    StatusResult result;

    impl_->running = false;

    // Join threads
    if (impl_->tun_to_udp_thread.joinable()) impl_->tun_to_udp_thread.join();
    if (impl_->udp_to_tun_thread.joinable()) impl_->udp_to_tun_thread.join();
    if (impl_->timer_thread.joinable())      impl_->timer_thread.join();

    // Close sockets / WinTun resources
#if defined(_WIN32)
    if (impl_->udp_sock != INVALID_SOCKET) {
        closesocket(impl_->udp_sock);
        impl_->udp_sock = INVALID_SOCKET;
    }
    if (impl_->wt_session) {
        impl_->wt.EndSession(impl_->wt_session);
        impl_->wt_session = nullptr;
    }
    if (impl_->wt_adapter) {
        impl_->wt.CloseAdapter(impl_->wt_adapter);
        impl_->wt_adapter = nullptr;
    }
    impl_->wt_read_event = nullptr;
    impl_->wt.unload();
#else
    if (impl_->tun_fd >= 0) { close(impl_->tun_fd); impl_->tun_fd = -1; }
    if (impl_->udp_fd >= 0) { close(impl_->udp_fd); impl_->udp_fd = -1; }
#endif

    // Free BoringTun tunnel
    if (impl_->tunnel) {
        tunnel_free(impl_->tunnel);
        impl_->tunnel = nullptr;
    }

    result.ok = true;
    spdlog::info("[BoringTun] tunnel down: {}", impl_->iface_name);
    return result;
}

// ---------------------------------------------------------------------------
// status / is_active / update_endpoint
// ---------------------------------------------------------------------------

TunnelStatus BoringTunBackend::do_status() const {
    TunnelStatus st;
    st.is_up           = impl_->running.load();
    st.tunnel_ip       = impl_->config.tunnel_ip;
    st.server_endpoint = impl_->config.server_endpoint;
    return st;
}

bool BoringTunBackend::do_is_active() const {
    return impl_->running.load();
}

StatusResult BoringTunBackend::do_update_endpoint(const std::string& server_pubkey,
                                                    const std::string& server_endpoint) {
    StatusResult result;

    // Update the server address for the UDP socket
    auto colon = server_endpoint.rfind(':');
    if (colon == std::string::npos) {
        result.error = "invalid endpoint format (expected host:port)";
        return result;
    }

    auto host = server_endpoint.substr(0, colon);
    auto port = std::stoi(server_endpoint.substr(colon + 1));

    std::memset(&impl_->server_addr, 0, sizeof(impl_->server_addr));
    impl_->server_addr.sin_family = AF_INET;
    inet_pton(AF_INET, host.c_str(), &impl_->server_addr.sin_addr);
    impl_->server_addr.sin_port = htons(static_cast<uint16_t>(port));

    impl_->config.server_public_key = server_pubkey;
    impl_->config.server_endpoint   = server_endpoint;

    // Force a new handshake with the new endpoint
    if (impl_->tunnel) {
        std::array<uint8_t, 256> buf{};
        auto r = wireguard_force_handshake(impl_->tunnel, buf.data(),
                                            static_cast<uint32_t>(buf.size()));
        if (r.op == WRITE_TO_NETWORK && r.size > 0) {
#if defined(_WIN32)
            sendto(impl_->udp_sock, reinterpret_cast<const char*>(buf.data()),
                   static_cast<int>(r.size), 0,
                   reinterpret_cast<sockaddr*>(&impl_->server_addr),
                   sizeof(impl_->server_addr));
#else
            sendto(impl_->udp_fd, buf.data(), r.size, 0,
                   reinterpret_cast<sockaddr*>(&impl_->server_addr),
                   sizeof(impl_->server_addr));
#endif
        }
    }

    result.ok = true;
    return result;
}

// ---------------------------------------------------------------------------
// Packet forwarding loops
// ---------------------------------------------------------------------------

void BoringTunBackend::tun_to_udp_loop() {
    constexpr size_t kBufSize = 65536;
    std::vector<uint8_t> wg_buf(kBufSize);

    spdlog::debug("[BoringTun] TUN→UDP loop started");

    while (impl_->running) {
        uint8_t* ip_packet = nullptr;
        uint32_t ip_len = 0;

#if defined(_WIN32)
        // Wait for a packet from WinTun (with timeout so we can check running_)
        auto wait_result = WaitForSingleObject(impl_->wt_read_event, 250);
        if (wait_result != WAIT_OBJECT_0) continue;

        DWORD pkt_size = 0;
        BYTE* pkt = impl_->wt.ReceivePacket(impl_->wt_session, &pkt_size);
        if (!pkt) continue;

        ip_packet = pkt;
        ip_len = pkt_size;
#elif defined(__APPLE__)
        // macOS utun prepends a 4-byte AF header
        std::vector<uint8_t> tun_buf(kBufSize);
        auto n = read(impl_->tun_fd, tun_buf.data(), tun_buf.size());
        if (n <= 4) {
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            continue;
        }
        // Skip the 4-byte AF header
        ip_packet = tun_buf.data() + 4;
        ip_len    = static_cast<uint32_t>(n - 4);
#elif defined(__linux__)
        std::vector<uint8_t> tun_buf(kBufSize);
        auto n = read(impl_->tun_fd, tun_buf.data(), tun_buf.size());
        if (n <= 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            continue;
        }
        ip_packet = tun_buf.data();
        ip_len    = static_cast<uint32_t>(n);
#else
        std::this_thread::sleep_for(std::chrono::seconds(1));
        continue;
#endif

        auto r = wireguard_write(impl_->tunnel, ip_packet, ip_len,
                                  wg_buf.data(), static_cast<uint32_t>(wg_buf.size()));

#if defined(_WIN32)
        // Release the WinTun packet after encrypting
        impl_->wt.ReleaseReceivePacket(impl_->wt_session, pkt);
#endif

        if (r.op == WRITE_TO_NETWORK && r.size > 0) {
#if defined(_WIN32)
            sendto(impl_->udp_sock, reinterpret_cast<const char*>(wg_buf.data()),
                   static_cast<int>(r.size), 0,
                   reinterpret_cast<sockaddr*>(&impl_->server_addr),
                   sizeof(impl_->server_addr));
#else
            sendto(impl_->udp_fd, wg_buf.data(), r.size, 0,
                   reinterpret_cast<sockaddr*>(&impl_->server_addr),
                   sizeof(impl_->server_addr));
#endif
        }
    }

    spdlog::debug("[BoringTun] TUN→UDP loop stopped");
}

void BoringTunBackend::udp_to_tun_loop() {
    constexpr size_t kBufSize = 65536;
    std::vector<uint8_t> udp_buf(kBufSize);
    std::vector<uint8_t> ip_buf(kBufSize);

    spdlog::debug("[BoringTun] UDP→TUN loop started");

    while (impl_->running) {
        sockaddr_in from{};
#if defined(_WIN32)
        int from_len = sizeof(from);
        auto n = recvfrom(impl_->udp_sock,
                          reinterpret_cast<char*>(udp_buf.data()),
                          static_cast<int>(udp_buf.size()), 0,
                          reinterpret_cast<sockaddr*>(&from), &from_len);
#else
        socklen_t from_len = sizeof(from);
        auto n = recvfrom(impl_->udp_fd, udp_buf.data(), udp_buf.size(), 0,
                          reinterpret_cast<sockaddr*>(&from), &from_len);
#endif
        if (n <= 0) {
            // Timeout or error — check running flag
            continue;
        }

        auto r = wireguard_read(impl_->tunnel, udp_buf.data(), static_cast<uint32_t>(n),
                                 ip_buf.data(), static_cast<uint32_t>(ip_buf.size()));

        if ((r.op == WRITE_TO_TUNNEL_IPV4 || r.op == WRITE_TO_TUNNEL_IPV6) && r.size > 0) {
#if defined(_WIN32)
            // Write decrypted IP packet into WinTun ring buffer
            BYTE* send_pkt = impl_->wt.AllocateSendPacket(
                impl_->wt_session, static_cast<DWORD>(r.size));
            if (send_pkt) {
                std::memcpy(send_pkt, ip_buf.data(), r.size);
                impl_->wt.SendPacket(impl_->wt_session, send_pkt);
            }
#elif defined(__APPLE__)
            // macOS utun requires a 4-byte AF header prepended
            uint32_t af = (r.op == WRITE_TO_TUNNEL_IPV4) ? htonl(AF_INET) : htonl(AF_INET6);
            struct iovec iov[2];
            iov[0].iov_base = &af;
            iov[0].iov_len  = 4;
            iov[1].iov_base = ip_buf.data();
            iov[1].iov_len  = r.size;
            writev(impl_->tun_fd, iov, 2);
#elif defined(__linux__)
            write(impl_->tun_fd, ip_buf.data(), r.size);
#endif
        } else if (r.op == WRITE_TO_NETWORK && r.size > 0) {
            // Handshake response — send back to server
#if defined(_WIN32)
            sendto(impl_->udp_sock, reinterpret_cast<const char*>(ip_buf.data()),
                   static_cast<int>(r.size), 0,
                   reinterpret_cast<sockaddr*>(&impl_->server_addr),
                   sizeof(impl_->server_addr));
#else
            sendto(impl_->udp_fd, ip_buf.data(), r.size, 0,
                   reinterpret_cast<sockaddr*>(&impl_->server_addr),
                   sizeof(impl_->server_addr));
#endif
        }
    }

    spdlog::debug("[BoringTun] UDP→TUN loop stopped");
}

void BoringTunBackend::timer_loop() {
    constexpr size_t kBufSize = 256;
    std::array<uint8_t, kBufSize> buf{};

    spdlog::debug("[BoringTun] timer loop started");

    while (impl_->running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));

        if (!impl_->tunnel) continue;

        auto r = wireguard_tick(impl_->tunnel, buf.data(), static_cast<uint32_t>(buf.size()));
        if (r.op == WRITE_TO_NETWORK && r.size > 0) {
#if defined(_WIN32)
            sendto(impl_->udp_sock, reinterpret_cast<const char*>(buf.data()),
                   static_cast<int>(r.size), 0,
                   reinterpret_cast<sockaddr*>(&impl_->server_addr),
                   sizeof(impl_->server_addr));
#else
            sendto(impl_->udp_fd, buf.data(), r.size, 0,
                   reinterpret_cast<sockaddr*>(&impl_->server_addr),
                   sizeof(impl_->server_addr));
#endif
        }
    }

    spdlog::debug("[BoringTun] timer loop stopped");
}

} // namespace lnsdk
