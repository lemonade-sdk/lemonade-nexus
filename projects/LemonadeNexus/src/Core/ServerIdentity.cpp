#include <LemonadeNexus/Core/ServerIdentity.hpp>
#include <LemonadeNexus/Core/HostnameGenerator.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Network/SeipNaming.hpp>
#include <LemonadeNexus/Relay/GeoRegion.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <fcntl.h>
#include <unistd.h>
#endif

#include <algorithm>
#include <array>
#include <chrono>
#include <fstream>
#include <random>
#include <set>
#include <thread>
#include <unordered_set>

namespace nexus::core {

std::string resolve_jwt_secret(
    const ServerConfig& config,
    const std::filesystem::path& data_root,
    crypto::SodiumCryptoService& crypto)
{
    std::string jwt_secret_hex = config.jwt_secret;
    if (!jwt_secret_hex.empty()) return jwt_secret_hex;

    const auto jwt_path = data_root / "identity" / "jwt_secret.hex";
    if (std::filesystem::exists(jwt_path)) {
        std::ifstream f(jwt_path);
        std::getline(f, jwt_secret_hex);
        spdlog::info("Loaded JWT secret from {}", jwt_path.string());
    } else {
        std::array<uint8_t, 32> jwt_secret_bytes{};
        crypto.random_bytes(std::span<uint8_t>(jwt_secret_bytes));
        jwt_secret_hex = crypto::to_hex(
            std::span<const uint8_t>(jwt_secret_bytes));
        std::filesystem::create_directories(jwt_path.parent_path());
        std::ofstream f(jwt_path, std::ios::trunc | std::ios::binary);
        f << jwt_secret_hex;
        // The secret is written with the process umask by default; the
        // bootstrap path (scripts/nexus-bootstrap) runs as root with umask 022,
        // which would leave the signing secret world-readable. Force 0600.
        std::error_code perm_ec;
        std::filesystem::permissions(
            jwt_path,
            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
            std::filesystem::perm_options::replace, perm_ec);
        if (perm_ec) {
            spdlog::warn("Could not tighten permissions on {} ({})", jwt_path.string(), perm_ec.message());
        }
        spdlog::info("Generated and persisted JWT secret to {}", jwt_path.string());
    }
    return jwt_secret_hex;
}

std::string resolve_server_node_id(storage::FileStorageService& storage) {
    // Prefer server certificate (from --enroll-server)
    auto cert_env = storage.read_file("identity", "server_cert.json");
    if (cert_env) {
        try {
            auto cert_j = nlohmann::json::parse(cert_env->data);
            auto id = cert_j.value("server_id", "");
            if (!id.empty()) return id;
        } catch (...) {}
    }

    // Fall back to identity pubkey — every server has one after first boot.
    // Derive a stable node ID so IPAM allocations persist across restarts.
    // keypair.pub is raw hex written by KeyWrappingService, not a SignedEnvelope.
    auto pub_path = storage.data_root() / "identity" / "keypair.pub";
    if (std::filesystem::exists(pub_path)) {
        std::ifstream ifs(pub_path);
        std::string hex_str;
        std::getline(ifs, hex_str);
        if (hex_str.size() >= 16) {
            auto node_id = "server-" + hex_str.substr(0, 16);
            spdlog::info("Derived server node ID from identity pubkey: {}", node_id);
            return node_id;
        }
    }

    return {};
}

void resolve_server_hostname(
    ServerConfig& config,
    const std::filesystem::path& data_root,
    gossip::GossipService& gossip)
{
    if (!config.server_hostname.empty()) return;

    auto persisted = HostnameGenerator::load_persisted_hostname(data_root);
    if (persisted) {
        config.server_hostname = *persisted;
        spdlog::info("Loaded server hostname from disk: {}", config.server_hostname);
        return;
    }

    auto region = HostnameGenerator::detect_region();
    std::string region_code = region.value_or("unknown");

    // Gather existing hostnames for collision avoidance
    std::unordered_set<std::string> existing_hostnames;
    for (const auto& peer : gossip.get_peers()) {
        if (!peer.certificate_json.empty()) {
            try {
                auto cert_j = nlohmann::json::parse(peer.certificate_json);
                auto sid = cert_j.value("server_id", "");
                if (!sid.empty()) existing_hostnames.insert(sid);
            } catch (...) {}
        }
    }

    config.server_hostname = HostnameGenerator::generate_unique_hostname(
        region_code, existing_hostnames);

    HostnameGenerator::persist_hostname(data_root, config.server_hostname);
    spdlog::info("Auto-generated server hostname: {} (region: {})",
                  config.server_hostname, region_code);
}

void resolve_server_region(ServerConfig& config,
                            const std::filesystem::path& data_root) {
    if (!config.region.empty()) {
        spdlog::info("Region: configured as '{}'", config.region);
        return;
    }

    // Try loading persisted region
    auto region_path = data_root / "identity" / "region";
    if (std::filesystem::exists(region_path)) {
        std::ifstream ifs(region_path);
        std::string persisted;
        std::getline(ifs, persisted);
        if (!persisted.empty()) {
            config.region = persisted;
            spdlog::info("Region: loaded persisted '{}'", config.region);
            return;
        }
    }

    // Auto-detect via HostnameGenerator (HTTP geo-IP lookup)
    auto detected = HostnameGenerator::detect_region();
    if (detected) {
        config.region = *detected;
        // Persist for stable region across restarts
        std::filesystem::create_directories(region_path.parent_path());
        std::ofstream ofs(region_path);
        ofs << config.region;
        spdlog::info("Region: auto-detected '{}', persisted", config.region);
    } else {
        config.region = "unknown";
        spdlog::warn("Region: auto-detection failed, using 'unknown'. "
                      "Set --region <code> for accurate geo-aware discovery.");
    }
}

std::string resolve_public_ip(const ServerConfig& config) {
    std::string ip = config.public_ip;
    if (ip.empty() && config.bind_address != "0.0.0.0" && !config.bind_address.empty()) {
        ip = config.bind_address;
    }
    if (ip.empty()) {
        try {
            httplib::Client ip_cli("http://api.ipify.org");
            ip_cli.set_connection_timeout(3, 0);
            ip_cli.set_read_timeout(3, 0);
            auto ip_res = ip_cli.Get("/");
            if (ip_res && ip_res->status == 200 && !ip_res->body.empty()) {
                ip = ip_res->body;
                while (!ip.empty() && (ip.back() == '\n' || ip.back() == '\r'))
                    ip.pop_back();
                spdlog::info("DNS: auto-detected public IP: {}", ip);
            }
        } catch (...) {
            spdlog::warn("DNS: failed to auto-detect public IP");
        }
    }
    return ip;
}

bool tcp_connect_check(const std::string& ip, uint16_t port, int timeout_sec) {
    struct addrinfo hints{};
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    if (::getaddrinfo(ip.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 ||
        res == nullptr) {
        return false;
    }

#ifdef _WIN32
    SOCKET fd = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd == INVALID_SOCKET) { ::freeaddrinfo(res); return false; }
    u_long nonblock = 1;
    ::ioctlsocket(fd, FIONBIO, &nonblock);
#else
    int fd = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (fd < 0) { ::freeaddrinfo(res); return false; }
    ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
#endif

    bool ok = false;
    if (::connect(fd, res->ai_addr, static_cast<socklen_t>(res->ai_addrlen)) == 0) {
        ok = true;
    } else {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        struct timeval tv{};
        tv.tv_sec = timeout_sec;
        if (::select(static_cast<int>(fd) + 1, nullptr, &wfds, nullptr, &tv) == 1) {
            int err = 0;
            socklen_t len = sizeof(err);
            ::getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&err), &len);
            ok = (err == 0);
        }
    }

#ifdef _WIN32
    ::closesocket(fd);
#else
    ::close(fd);
#endif
    ::freeaddrinfo(res);
    return ok;
}

std::vector<std::string> resolve_a_records(const std::string& hostname) {
    std::vector<std::string> ips;
    if (hostname.empty()) return ips;

    struct addrinfo hints{};
    hints.ai_family   = AF_INET;     // IPv4 only
    hints.ai_socktype = SOCK_DGRAM;  // hint; we only want addresses

    struct addrinfo* res = nullptr;
    int rc = ::getaddrinfo(hostname.c_str(), nullptr, &hints, &res);
    if (rc != 0 || res == nullptr) return ips;

    for (struct addrinfo* p = res; p != nullptr; p = p->ai_next) {
        if (p->ai_family != AF_INET || p->ai_addr == nullptr) continue;
        auto* sa = reinterpret_cast<struct sockaddr_in*>(p->ai_addr);
        char buf[INET_ADDRSTRLEN] = {0};
        if (::inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf)) != nullptr) {
            std::string ip(buf);
            if (std::find(ips.begin(), ips.end(), ip) == ips.end())
                ips.push_back(std::move(ip));
        }
    }
    ::freeaddrinfo(res);
    return ips;
}

namespace {

/// Read a DNS name (RFC 1035, with compression pointers) starting at `*p`
/// and advance `*p` past the name's wire encoding — the byte after the root
/// label for a literal name, or after the 2-byte pointer for a pointer name
/// (the RR fields that follow start there, NOT after the expanded name).
/// Returns false on truncation, a label longer than 63 octets, or a
/// compression pointer that does not point backward into the message (which
/// also rules out pointer loops). Every byte is bounds-checked against
/// [origin, end).
bool read_dns_name(const uint8_t* origin, const uint8_t* end, const uint8_t*& p,
                   std::string& out) {
    out.clear();
    int pointer_jumps = 0;
    const uint8_t* walk = p;
    for (;;) {
        if (walk >= end) return false;
        const uint8_t len = *walk;
        if ((len & 0xC0) == 0xC0) {                    // compression pointer
            if (walk + 1 >= end) return false;
            if (++pointer_jumps > 16) return false;    // pointer loop guard
            const uint16_t offset =
                static_cast<uint16_t>(((len & 0x3F) << 8) | walk[1]);
            if (origin + offset >= walk) return false; // must point backward
            p = walk + 2;                              // RR continues after pointer
            walk = origin + offset;
            continue;
        }
        ++walk;
        if (len == 0) {                                 // root label: name done
            if (pointer_jumps == 0) p = walk;           // literal name
            return true;
        }
        if (len > 63 || walk + len > end) return false; // bad label / truncated
        out.append(reinterpret_cast<const char*>(walk), len);
        out.push_back('.');
        walk += len;
    }
}

}  // namespace

std::vector<std::string> parse_dns_txt_records(const std::vector<uint8_t>& message) {
    std::vector<std::string> results;
    if (message.size() < 12) return results;

    const uint8_t* origin = message.data();
    const uint8_t* end = origin + message.size();
    const auto rd16 = [](const uint8_t* p) {
        return static_cast<uint16_t>((p[0] << 8) | p[1]);
    };

    const uint16_t flags = rd16(origin + 2);
    if (!(flags & 0x8000)) return results;      // not a response
    if (flags & 0x000F) return results;         // rcode must be NOERROR

    const uint16_t qdcount = rd16(origin + 4);
    const uint16_t ancount = rd16(origin + 6);
    if (qdcount < 1) return results;

    const uint8_t* p = origin + 12;
    std::string name;
    // Skip the question section (name + qtype + qclass).
    for (uint16_t i = 0; i < qdcount; ++i) {
        if (!read_dns_name(origin, end, p, name) || p + 4 > end) return results;
        p += 4;
    }

    for (uint16_t i = 0; i < ancount; ++i) {
        // name, type, class, ttl, rdlength
        if (!read_dns_name(origin, end, p, name) || p + 10 > end) return results;
        const uint16_t rtype = rd16(p);
        p += 2;                     // type
        p += 2;                     // class
        p += 4;                     // ttl
        const uint16_t rdlength = rd16(p);
        p += 2;
        if (p + rdlength > end) return results;

        if (rtype == 16 /* TXT */) {
            std::string txt;
            const uint8_t* r = p;
            const uint8_t* r_end = p + rdlength;
            while (r < r_end) {
                const uint8_t chunk = *r++;
                if (r + chunk > r_end) return results;   // bad chunk: fail closed
                txt.append(reinterpret_cast<const char*>(r), chunk);
                r += chunk;
            }
            if (!txt.empty()) results.push_back(std::move(txt));
        }
        p += rdlength;
    }
    return results;
}

std::vector<uint8_t> build_dns_query(
    const std::string& name, uint16_t qtype, uint16_t id)
{
    std::vector<uint8_t> q;
    q.push_back(static_cast<uint8_t>(id >> 8));
    q.push_back(static_cast<uint8_t>(id & 0xFF));
    q.push_back(0x01); q.push_back(0x00);      // RD
    q.push_back(0x00); q.push_back(0x01);      // QDCOUNT = 1
    q.push_back(0x00); q.push_back(0x00);      // ANCOUNT
    q.push_back(0x00); q.push_back(0x00);      // NSCOUNT
    q.push_back(0x00); q.push_back(0x00);      // ARCOUNT
    std::size_t start = 0;
    for (;;) {
        const auto dot = name.find('.', start);
        const auto stop = (dot == std::string::npos) ? name.size() : dot;
        if (stop - start == 0 || stop - start > 63) return {};  // bad label
        q.push_back(static_cast<uint8_t>(stop - start));
        q.insert(q.end(), name.begin() + start, name.begin() + stop);
        if (dot == std::string::npos) break;
        start = dot + 1;
    }
    q.push_back(0x00);                         // root label
    q.push_back(static_cast<uint8_t>(qtype >> 8));
    q.push_back(static_cast<uint8_t>(qtype & 0xFF));
    q.push_back(0x00); q.push_back(0x01);      // qclass IN
    return q;
}

std::vector<std::string> resolve_txt_records(const std::string& hostname) {
    std::vector<std::string> results;
    if (hostname.empty()) return results;

#ifdef _WIN32
    // No /etc/resolv.conf on Windows; discovery is unavailable (fail closed).
    return results;
#else
    // First IPv4 nameserver from /etc/resolv.conf — the same configuration
    // getaddrinfo uses, which cannot return TXT data.
    std::string resolver;
    {
        std::ifstream f("/etc/resolv.conf");
        std::string line;
        while (resolver.empty() && std::getline(f, line)) {
            const auto comment = line.find_first_of("#;");
            if (comment != std::string::npos) line = line.substr(0, comment);
            const auto start = line.find_first_not_of(" \t");
            if (start == std::string::npos ||
                line.compare(start, 10, "nameserver") != 0) {
                continue;
            }
            std::string word = line.substr(start + 10);
            const auto ws = word.find_first_not_of(" \t");
            if (ws == std::string::npos) continue;
            const auto stop = word.find_first_of(" \t\r\n", ws);
            resolver = word.substr(ws,
                                   stop == std::string::npos ? std::string::npos
                                                             : stop - ws);
        }
    }
    struct sockaddr_in dest{};
    dest.sin_family = AF_INET;
    dest.sin_port = htons(53);
    if (resolver.empty() ||
        inet_pton(AF_INET, resolver.c_str(), &dest.sin_addr) != 1) {
        spdlog::debug("TXT DNS: no usable IPv4 nameserver in /etc/resolv.conf");
        return results;
    }

    // Build the query: random ID + recursion-desired, one TXT/IN question.
    const uint16_t id = static_cast<uint16_t>(std::random_device{}() & 0xFFFF);
    const std::vector<uint8_t> q = build_dns_query(hostname, 16 /* TXT */, id);
    if (q.empty()) return results;             // bad label: fail closed

    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return results;
    struct timeval tv{};
    tv.tv_sec = 2;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    const ssize_t sent =
        ::sendto(fd, q.data(), q.size(), 0,
                 reinterpret_cast<const struct sockaddr*>(&dest), sizeof(dest));
    std::vector<uint8_t> reply(4096);
    const ssize_t n = (sent == static_cast<ssize_t>(q.size()))
        ? ::recv(fd, reply.data(), reply.size(), 0)
        : -1;
    ::close(fd);
    if (n < 2) {
        spdlog::debug("TXT DNS: query for {} timed out or failed", hostname);
        return results;
    }
    reply.resize(static_cast<std::size_t>(n));

    // The reply must echo our random ID, or drop it (fail closed).
    if (static_cast<uint16_t>((reply[0] << 8) | reply[1]) != id) return results;
    return parse_dns_txt_records(reply);
#endif
}

std::vector<std::string> select_seed_endpoints(
    const std::vector<std::string>& candidate_ips,
    const std::string& our_public_ip,
    uint16_t gossip_port)
{
    std::vector<std::string> endpoints;
    std::set<std::string> seen;
    if (!our_public_ip.empty()) seen.insert(our_public_ip);  // never seed ourselves
    for (const auto& ip : candidate_ips) {
        if (ip.empty()) continue;
        if (!seen.insert(ip).second) continue;  // skip self / duplicates
        endpoints.push_back(ip + ":" + std::to_string(gossip_port));
    }
    return endpoints;
}

std::vector<std::string> discover_seed_endpoints(
    const std::string& base_domain,
    const std::string& our_region,
    const std::string& our_public_ip,
    uint16_t gossip_port)
{
    if (base_domain.empty()) return {};

    // Region search order: our own region first, then the nearest regions by
    // great-circle distance. One reachable seed is enough to bootstrap — gossip
    // peer-exchange then spreads the rest of the mesh.
    static constexpr std::size_t kNearbyRegions = 3;  // own + 3 nearest = 4 total

    std::vector<std::string> region_order;
    {
        std::vector<std::string> codes;
        for (const auto& r : relay::GeoRegion::all_regions()) codes.push_back(r.code);
        auto sorted = relay::GeoRegion::sort_by_distance(our_region, codes);
        for (const auto& c : sorted) {
            region_order.push_back(c);
            if (region_order.size() >= kNearbyRegions + 1) break;
        }
        // Always include our own region first, even if GeoRegion doesn't know it.
        if (!our_region.empty() &&
            std::find(region_order.begin(), region_order.end(), our_region) == region_order.end()) {
            region_order.insert(region_order.begin(), our_region);
        }
    }

    // Resolve candidates in priority order: nearest region first, Tier 1 before Tier 2.
    std::vector<std::string> candidate_ips;
    for (const auto& region : region_order) {
        for (int tier : {1, 2}) {
            const std::string host = nexus::seip::tierFqdn(tier, region, base_domain);
            for (const auto& ip : resolve_a_records(host)) {
                spdlog::info("DNS discovery: found tier{} server {} in region '{}'",
                              tier, ip, region);
                candidate_ips.push_back(ip);
            }
        }
    }
    return select_seed_endpoints(candidate_ips, our_public_ip, gossip_port);
}

std::string build_server_fqdn(
    const std::string& server_hostname,
    const std::string& dns_base_domain)
{
    if (server_hostname.empty()) return {};
    return server_hostname + ".srv." + dns_base_domain;
}

std::string resolve_tunnel_ip(
    const std::string& server_node_id,
    const ServerConfig& config,
    ipam::IPAMService& ipam,
    gossip::GossipService& gossip)
{
    if (server_node_id.empty()) return {};

    std::string tunnel_bind_ip;

    if (config.seed_peers.empty()) {
        // Genesis/root server: always use .1 as the gateway address.
        auto server_alloc = ipam.allocate_tunnel_ip(server_node_id);
        (void)server_alloc;
        tunnel_bind_ip = "10.64.0.1";
        spdlog::info("Genesis server -- gateway tunnel IP: {}", tunnel_bind_ip);
    } else {
        // Joining server: check existing allocation or wait for gossip assignment
        auto existing = ipam.get_allocation(server_node_id);
        if (existing && existing->tunnel) {
            tunnel_bind_ip = existing->tunnel->base_network;
        } else {
            spdlog::info("Waiting for tunnel IP assignment from network peers...");
            for (int i = 0; i < 15 && gossip.our_tunnel_ip().empty(); ++i) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            tunnel_bind_ip = gossip.our_tunnel_ip();
            if (tunnel_bind_ip.empty()) {
                spdlog::warn("No tunnel IP received from peers -- self-allocating");
                auto alloc = ipam.allocate_tunnel_ip(server_node_id);
                tunnel_bind_ip = alloc.base_network;
            }
        }
    }

    // Strip CIDR suffix (e.g. "10.64.0.1/32" -> "10.64.0.1")
    if (auto slash = tunnel_bind_ip.find('/'); slash != std::string::npos) {
        tunnel_bind_ip = tunnel_bind_ip.substr(0, slash);
    }
    return tunnel_bind_ip;
}

TlsResolution resolve_tls_cert(
    const std::filesystem::path& data_root,
    const std::string& server_fqdn)
{
    TlsResolution result;

    // The cert is always ACME-issued (public CA on the SEIP FQDN). Resolve THIS
    // FQDN's cert on disk (never another listener's cert); if absent, request it
    // in the background.
    if (!server_fqdn.empty()) {
        const auto acme_cert_dir  = data_root / "certs" / server_fqdn;
        const auto acme_cert_file = acme_cert_dir / "fullchain.pem";
        const auto acme_key_file  = acme_cert_dir / "privkey.pem";

        if (std::filesystem::exists(acme_cert_file) && std::filesystem::exists(acme_key_file)) {
            result.cert_path = acme_cert_file.string();
            result.key_path  = acme_key_file.string();
            spdlog::info("Auto-TLS: using existing ACME cert for {}", server_fqdn);
        } else {
            result.needs_acme_background = true;
            spdlog::info("Auto-TLS: no cert on disk for {} -- will request in background",
                          server_fqdn);
        }
    }
    return result;
}

} // namespace nexus::core
