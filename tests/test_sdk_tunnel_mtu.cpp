// The client measures the largest packet the tunnel to its server carries
// and sizes the netstack to it, so a path that drops full-size packets (a
// corporate tunnel, a carrier with a small MTU) still carries every TLS
// handshake and every segment.

#include <gtest/gtest.h>

#include <LemonadeNexusSDK/BoringtunMesh.hpp>
#include <LemonadeNexusSDK/TunnelMtu.hpp>

#include <sodium.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <set>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#endif

using namespace std::chrono_literals;
namespace mtu = lnsdk::tunnel_mtu;

namespace {

uint16_t internet_checksum(const std::vector<uint8_t>& pkt, size_t from, size_t to) {
    uint32_t sum = 0;
    for (size_t i = from; i + 1 < to; i += 2) sum += (uint32_t{pkt[i]} << 8) | pkt[i + 1];
    if ((to - from) % 2 == 1) sum += uint32_t{pkt[to - 1]} << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

}  // namespace

TEST(TunnelMtu, EchoRequestCarriesValidChecksumsAndItsReplyIsRecognized) {
    const auto pkt = mtu::echo_request(0x0A400002u, 0x0A400001u, 0xBEEF, 7, 1420);
    ASSERT_EQ(pkt.size(), 1420u);
    EXPECT_EQ(pkt[0], 0x45);
    EXPECT_EQ(pkt[9], 1);
    EXPECT_EQ(pkt[20], 8);
    EXPECT_EQ(internet_checksum(pkt, 0, 20), 0) << "IPv4 header checksum";
    EXPECT_EQ(internet_checksum(pkt, 20, pkt.size()), 0) << "ICMP checksum";
    EXPECT_EQ(pkt[12], 10);
    EXPECT_EQ(pkt[19], 1);

    EXPECT_FALSE(mtu::echo_reply_len(pkt, 0xBEEF)) << "a request is not a reply";
    auto reply = pkt;
    reply[20] = 0;
    EXPECT_EQ(mtu::echo_reply_len(reply, 0xBEEF), 1420u);
    EXPECT_FALSE(mtu::echo_reply_len(reply, 0xBEEE)) << "another probe's ident";
    reply.resize(27);
    EXPECT_FALSE(mtu::echo_reply_len(reply, 0xBEEF));
    EXPECT_EQ(mtu::echo_request(1, 2, 3, 4, 10).size(), 28u) << "never shorter than the headers";
}

TEST(TunnelMtu, ChooseTakesTheLargestAnsweredLadderSizeOrTheFailsafe) {
    EXPECT_EQ(mtu::choose({}), mtu::kFailsafe);
    EXPECT_EQ(mtu::choose({1200}), 1200u);
    EXPECT_EQ(mtu::choose({1200, 1280, 1340}), 1340u);
    EXPECT_EQ(mtu::choose({1200, 1340, 1420}), 1420u);
    EXPECT_EQ(mtu::choose({1000}), mtu::kFailsafe) << "a size outside the ladder is not a probe";
}

#ifndef _WIN32

namespace {

/// Forwards UDP datagrams between one client and a server on loopback and
/// drops every datagram larger than `limit` bytes, as a path with a small
/// MTU does.
class DroppingPath {
public:
    DroppingPath(uint16_t server_port, size_t limit) : limit_(limit) {
        sock_ = ::socket(AF_INET, SOCK_DGRAM, 0);
        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::bind(sock_, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) {
            ::close(sock_);
            sock_ = -1;
            return;
        }
        socklen_t len = sizeof addr;
        ::getsockname(sock_, reinterpret_cast<sockaddr*>(&addr), &len);
        port_ = ntohs(addr.sin_port);
        server_ = addr;
        server_.sin_port = htons(server_port);
        timeval tv{};
        tv.tv_usec = 100 * 1000;
        ::setsockopt(sock_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        thread_ = std::thread([this] { run(); });
    }

    ~DroppingPath() {
        stop_ = true;
        if (thread_.joinable()) thread_.join();
        if (sock_ >= 0) ::close(sock_);
    }

    [[nodiscard]] uint16_t port() const { return port_; }
    [[nodiscard]] size_t largest_forwarded() const { return largest_.load(); }

private:
    void run() {
        std::vector<uint8_t> buf(65536);
        sockaddr_in client{};
        bool client_known = false;
        while (!stop_) {
            sockaddr_in from{};
            socklen_t from_len = sizeof from;
            const auto n = ::recvfrom(sock_, buf.data(), buf.size(), 0,
                                      reinterpret_cast<sockaddr*>(&from), &from_len);
            if (n <= 0) continue;
            if (static_cast<size_t>(n) > limit_) continue;
            const bool from_server = from.sin_port == server_.sin_port;
            if (!from_server) {
                client       = from;
                client_known = true;
            } else if (!client_known) {
                continue;
            }
            const sockaddr_in& to = from_server ? client : server_;
            ::sendto(sock_, buf.data(), static_cast<size_t>(n), 0,
                     reinterpret_cast<const sockaddr*>(&to), sizeof to);
            size_t seen = largest_.load();
            while (static_cast<size_t>(n) > seen &&
                   !largest_.compare_exchange_weak(seen, static_cast<size_t>(n))) {
            }
        }
    }

    int                 sock_{-1};
    uint16_t            port_{0};
    size_t              limit_;
    sockaddr_in         server_{};
    std::atomic<bool>   stop_{false};
    std::atomic<size_t> largest_{0};
    std::thread         thread_;
};

struct ProbeOutcome {
    uint32_t mtu{0};
    size_t   largest_forwarded{0};
};

/// A client joins a server through a path that drops datagrams over
/// `limit` bytes and reports the MTU it settled on.
ProbeOutcome probe_through(size_t limit, const std::string& server_tunnel_ip) {
    const auto server_keys = lnsdk::BoringtunMesh::generate_keypair();
    const auto client_keys = lnsdk::BoringtunMesh::generate_keypair();

    lnsdk::BoringtunMesh server;
    lnsdk::BoringtunConfig scfg;
    scfg.private_key = server_keys.first;
    scfg.public_key  = server_keys.second;
    scfg.tunnel_ip   = "10.64.0.1/32";
    scfg.allowed_ips = {"10.64.0.0/10"};
    EXPECT_TRUE(server.start(scfg));
    lnsdk::MeshPeer client_peer;
    client_peer.mesh_pubkey = client_keys.second;
    client_peer.tunnel_ip   = "10.64.0.2/32";
    EXPECT_TRUE(server.sync_peers({client_peer}).ok);

    DroppingPath path(server.bound_port(), limit);
    EXPECT_NE(path.port(), 0);

    lnsdk::BoringtunMesh client;
    lnsdk::BoringtunConfig ccfg;
    ccfg.private_key       = client_keys.first;
    ccfg.public_key        = client_keys.second;
    ccfg.tunnel_ip         = "10.64.0.2/32";
    ccfg.allowed_ips       = {"10.64.0.0/10"};
    ccfg.server_public_key = server_keys.second;
    ccfg.server_endpoint   = "127.0.0.1:" + std::to_string(path.port());
    ccfg.server_tunnel_ip  = server_tunnel_ip;
    EXPECT_TRUE(client.start(ccfg));
    ProbeOutcome outcome{client.tunnel_mtu(), path.largest_forwarded()};
    EXPECT_EQ(client.mesh_status().tunnel_mtu, outcome.mtu);
    client.stop();
    server.stop();
    return outcome;
}

}  // namespace

TEST(TunnelMtu, AClearPathKeepsTheFullMtu) {
    ASSERT_GE(sodium_init(), 0);
    const auto outcome = probe_through(65536, "10.64.0.1");
    EXPECT_EQ(outcome.mtu, mtu::kFull);
    EXPECT_GE(outcome.largest_forwarded, 1452u) << "the full-size probe went through";
}

TEST(TunnelMtu, APathThatDropsFullSizePacketsLowersTheMtuToWhatItCarries) {
    ASSERT_GE(sodium_init(), 0);
    // 1400-byte datagrams pass: 1340 + 32 bytes of transport framing fit,
    // 1420 + 32 do not.
    const auto outcome = probe_through(1400, "10.64.0.1");
    EXPECT_EQ(outcome.mtu, 1340u);
    EXPECT_LE(outcome.largest_forwarded, 1400u);
}

TEST(TunnelMtu, NoReplyAtAllFallsBackToTheFailsafe) {
    ASSERT_GE(sodium_init(), 0);
    const auto outcome = probe_through(65536, "10.64.0.9");
    EXPECT_EQ(outcome.mtu, mtu::kFailsafe);
}

TEST(TunnelMtu, NoProbeWithoutAServerTunnelAddress) {
    ASSERT_GE(sodium_init(), 0);
    const auto keys = lnsdk::BoringtunMesh::generate_keypair();
    lnsdk::BoringtunMesh alone;
    lnsdk::BoringtunConfig cfg;
    cfg.private_key = keys.first;
    cfg.public_key  = keys.second;
    cfg.tunnel_ip   = "10.64.0.3/32";
    cfg.allowed_ips = {"10.64.0.0/10"};
    EXPECT_EQ(alone.tunnel_mtu(), 0u);
    ASSERT_TRUE(alone.start(cfg));
    EXPECT_EQ(alone.tunnel_mtu(), mtu::kFull);
    EXPECT_FALSE(alone.probe_tunnel_mtu(100ms).has_value());
    alone.stop();
    EXPECT_EQ(alone.tunnel_mtu(), 0u);
}

#endif  // _WIN32
