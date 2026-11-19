// A fixed dataplane UDP port (MeshConfig::listen_port): the port a router
// mapping or a manual port forward points at is bound at every start and
// rebind, exclusively, and never replaced by another port.

#include <gtest/gtest.h>

#include <LemonadeNexusSDK/BoringtunMesh.hpp>
#include <LemonadeNexusSDK/Types.hpp>

#include <nlohmann/json.hpp>
#include <sodium.h>

#include <stdexcept>
#include <string>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <netinet/in.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

namespace {

#ifdef _WIN32
using socket_t = SOCKET;
constexpr socket_t kInvalidSocket = INVALID_SOCKET;
void close_socket(socket_t s) { closesocket(s); }
#else
using socket_t = int;
constexpr socket_t kInvalidSocket = -1;
void close_socket(socket_t s) { close(s); }
#endif

/// A UDP socket bound on every address to `want` (0 = any free port),
/// without address reuse, so it holds the port alone. Closed by release()
/// or on destruction.
struct UdpHolder {
    socket_t sock{kInvalidSocket};
    uint16_t port{0};

    explicit UdpHolder(uint16_t want) {
        sock = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (sock == kInvalidSocket) return;
        sockaddr_in addr{};
        addr.sin_family      = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
        addr.sin_port        = htons(want);
        socklen_t len        = sizeof(addr);
        if (::bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0 ||
            ::getsockname(sock, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
            release();
            return;
        }
        port = ntohs(addr.sin_port);
    }
    ~UdpHolder() { release(); }

    [[nodiscard]] bool bound() const { return sock != kInvalidSocket; }
    void release() {
        if (!bound()) return;
        close_socket(sock);
        sock = kInvalidSocket;
    }
};

/// A UDP port that was free a moment ago.
uint16_t free_udp_port() {
    return UdpHolder(0).port;
}

lnsdk::BoringtunConfig config_on(uint16_t listen_port, const std::string& tunnel_ip) {
    const auto keys = lnsdk::BoringtunMesh::generate_keypair();
    lnsdk::BoringtunConfig cfg;
    cfg.private_key = keys.first;
    cfg.public_key  = keys.second;
    cfg.tunnel_ip   = tunnel_ip;
    cfg.allowed_ips = {"10.64.0.0/10"};
    cfg.listen_port = listen_port;
    return cfg;
}

}  // namespace

class DataplanePort : public ::testing::Test {
protected:
    static void SetUpTestSuite() { ASSERT_GE(sodium_init(), 0); }
};

TEST_F(DataplanePort, AFixedPortIsBoundAndReported) {
    const uint16_t port = free_udp_port();
    ASSERT_NE(port, 0);

    lnsdk::BoringtunMesh mesh;
    ASSERT_TRUE(mesh.start(config_on(port, "10.64.0.2/32")));
    EXPECT_EQ(mesh.bound_port(), port);
    EXPECT_EQ(mesh.mesh_status().dataplane_port, port);

    mesh.stop();
    EXPECT_EQ(mesh.bound_port(), 0);
    EXPECT_EQ(mesh.mesh_status().dataplane_port, 0);
}

TEST_F(DataplanePort, AZeroPortTakesAnyPort) {
    lnsdk::BoringtunMesh mesh;
    ASSERT_TRUE(mesh.start(config_on(0, "10.64.0.2/32")));
    EXPECT_NE(mesh.bound_port(), 0);
    EXPECT_EQ(mesh.mesh_status().dataplane_port, mesh.bound_port());
}

TEST_F(DataplanePort, AFixedPortSurvivesSuspendAndRebind) {
    const uint16_t port = free_udp_port();
    ASSERT_NE(port, 0);

    lnsdk::BoringtunMesh mesh;
    ASSERT_TRUE(mesh.start(config_on(port, "10.64.0.2/32")));
    mesh.suspend();
    ASSERT_TRUE(mesh.rebind().has_value());
    EXPECT_EQ(mesh.bound_port(), port);
    EXPECT_EQ(mesh.mesh_status().dataplane_port, port);

    // A rebind without a suspension (the socket died under a running plane).
    ASSERT_TRUE(mesh.rebind().has_value());
    EXPECT_EQ(mesh.bound_port(), port);
}

// The forward points at the fixed port: while another socket holds it, the
// rebind fails and the plane stays suspended, instead of moving to a port the
// forward does not reach. The next rebind gets the port once it is free.
TEST_F(DataplanePort, ARebindNeverTakesAnotherPortWhileTheFixedOneIsHeld) {
    const uint16_t port = free_udp_port();
    ASSERT_NE(port, 0);

    lnsdk::BoringtunMesh mesh;
    ASSERT_TRUE(mesh.start(config_on(port, "10.64.0.2/32")));
    mesh.suspend();

    UdpHolder holder(port);
    ASSERT_TRUE(holder.bound()) << "the suspended plane released its port";
    EXPECT_FALSE(mesh.rebind().has_value());
    EXPECT_TRUE(mesh.is_active()) << "a failed rebind keeps the plane for the next one";

    holder.release();
    ASSERT_TRUE(mesh.rebind().has_value());
    EXPECT_EQ(mesh.bound_port(), port);
}

TEST_F(DataplanePort, ASecondInstanceOnTheSameFixedPortFailsToStart) {
    const uint16_t port = free_udp_port();
    ASSERT_NE(port, 0);

    lnsdk::BoringtunMesh first;
    ASSERT_TRUE(first.start(config_on(port, "10.64.0.2/32")));

    lnsdk::BoringtunMesh second;
    EXPECT_FALSE(second.start(config_on(port, "10.64.0.3/32")));
    EXPECT_FALSE(second.is_active());
    EXPECT_EQ(second.bound_port(), 0);
    EXPECT_EQ(first.bound_port(), port) << "the first instance keeps the port";

    // A fixed port that a plain socket holds is refused too: the exclusive
    // bind does not share the port with a socket that asked for reuse.
    first.stop();
    UdpHolder holder(port);
    ASSERT_TRUE(holder.bound());
    EXPECT_FALSE(second.start(config_on(port, "10.64.0.3/32")));
}

// start() with the config in use and another listen port moves the plane to
// that port (enable_mesh with a new listen_port uses this).
TEST_F(DataplanePort, AStartWithAnotherListenPortMovesThePlane) {
    const uint16_t first_port = free_udp_port();
    ASSERT_NE(first_port, 0);

    lnsdk::BoringtunMesh mesh;
    auto cfg = config_on(first_port, "10.64.0.2/32");
    ASSERT_TRUE(mesh.start(cfg));
    ASSERT_TRUE(mesh.start(cfg)) << "the same config is idempotent";
    EXPECT_EQ(mesh.bound_port(), first_port);

    const uint16_t second_port = free_udp_port();
    ASSERT_NE(second_port, 0);
    ASSERT_NE(second_port, first_port);
    cfg.listen_port = second_port;
    ASSERT_TRUE(mesh.start(cfg));
    EXPECT_EQ(mesh.bound_port(), second_port);

    // Back to any port: the plane restarts on a port the OS chooses.
    cfg.listen_port = 0;
    ASSERT_TRUE(mesh.start(cfg));
    EXPECT_NE(mesh.bound_port(), 0);
    EXPECT_NE(mesh.bound_port(), second_port);
}

TEST(MeshConfigJson, ListenPortRoundTripsAndAMissingKeyKeepsZero) {
    using nlohmann::json;
    const auto parsed = [](const json& j) { return j.get<lnsdk::MeshConfig>(); };
    EXPECT_EQ(lnsdk::MeshConfig{}.listen_port, 0);
    EXPECT_EQ(parsed(json::object()).listen_port, 0);
    EXPECT_EQ(parsed({{"prefer_direct", false}}).listen_port, 0);

    lnsdk::MeshConfig cfg;
    cfg.listen_port = 51941;
    const json encoded = cfg;
    EXPECT_EQ(encoded.at("listen_port"), 51941);
    EXPECT_EQ(parsed(encoded).listen_port, 51941);
    EXPECT_EQ(parsed({{"listen_port", 65535}}).listen_port, 65535);

    // A port outside 0..65535 is refused, not wrapped to another port.
    EXPECT_THROW((void)parsed({{"listen_port", 65536}}), std::invalid_argument);
    EXPECT_THROW((void)parsed({{"listen_port", -1}}), std::invalid_argument);
    EXPECT_ANY_THROW((void)parsed({{"listen_port", "51941"}}));
}

TEST(MeshTunnelStatusJson, DataplanePortRoundTripsAndDefaultsToZero) {
    using nlohmann::json;
    lnsdk::MeshTunnelStatus status;
    status.is_up          = true;
    status.dataplane_port = 51941;
    const json encoded = status;
    EXPECT_EQ(encoded.at("dataplane_port"), 51941);
    EXPECT_EQ(encoded.get<lnsdk::MeshTunnelStatus>().dataplane_port, 51941);
    const json without_port = {{"is_up", false}};
    EXPECT_EQ(without_port.get<lnsdk::MeshTunnelStatus>().dataplane_port, 0);
}
