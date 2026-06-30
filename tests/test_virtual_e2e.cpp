// Flagship end-to-end test: a real HTTP request travels over a real WireGuard
// (boringtun) tunnel that is terminated FULLY in userspace on BOTH ends — no
// kernel network interface, no TUN device, no root. This is the user-visible
// goal of the in-process dataplane: node-to-node traffic that the host kernel
// (and anything running on it) cannot observe.
//
// Topology, all over loopback UDP:
//
//   httplib::Client --(loopback TCP)--> client VirtualNetService (egress)
//     -> client UserspaceDataplane (encrypt) ==WG/UDP==> server UserspaceDataplane
//     (decrypt, dst == our virtual IP) -> server VirtualNetService (ingress)
//     -> httplib::Server on loopback -> "pong"
//   ... and the response retraces the path.

#include <gtest/gtest.h>

#include <LemonadeNexus/Network/VirtualNetService.hpp>
#include <LemonadeNexus/Boringtun/UserspaceDataplane.hpp>

#include <httplib.h>
#include <sodium.h>

#include <chrono>
#include <string>
#include <thread>

using namespace std::chrono_literals;
using nexus::network::VirtualNetService;
using nexus::boringtun::UserspaceDataplane;

namespace {

struct Keypair {
    std::string pub_b64, priv_b64;
};

Keypair make_keypair() {
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(pk, sk);
    char pub[sodium_base64_ENCODED_LEN(32, sodium_base64_VARIANT_ORIGINAL)];
    char priv[sodium_base64_ENCODED_LEN(32, sodium_base64_VARIANT_ORIGINAL)];
    sodium_bin2base64(pub, sizeof(pub), pk, 32, sodium_base64_VARIANT_ORIGINAL);
    sodium_bin2base64(priv, sizeof(priv), sk, 32, sodium_base64_VARIANT_ORIGINAL);
    return {pub, priv};
}

} // namespace

TEST(VirtualE2E, HttpOverUserspaceWireGuardTunnel) {
    ASSERT_GE(sodium_init(), 0);

    // --- A real httplib server, reachable only on loopback ---
    httplib::Server api;
    api.Get("/ping", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("pong", "text/plain");
    });
    int api_port = api.bind_to_any_port("127.0.0.1");
    ASSERT_GT(api_port, 0);
    std::thread api_thread([&api] { api.listen_after_bind(); });

    // --- Server node: dataplane + netstack terminating on 10.64.0.1 ---
    Keypair server_keys = make_keypair();
    Keypair client_keys = make_keypair();

    UserspaceDataplane server_dp;
    VirtualNetService  server_vnet;
    server_vnet.start();
    server_dp.set_inbound_handler(
        [&](std::span<const uint8_t> p) { server_vnet.deliver_inbound_ip_packet(p); });
    server_vnet.set_outbound_sink(
        [&](std::span<const uint8_t> p) { server_dp.send_outbound_ip_packet(p); });
    ASSERT_TRUE(server_dp.start({server_keys.priv_b64, server_keys.pub_b64, 0, 2}));

    // Router: 10.64.0.1 is ours; the client's /32 routes to the client peer.
    server_dp.add_local_ip(0x0A400001u);  // 10.64.0.1
    server_vnet.add_local_ip("10.64.0.1/10");
    ASSERT_TRUE(server_dp.add_peer(client_keys.pub_b64, "10.64.0.2/32", ""));
    ASSERT_TRUE(server_vnet.add_tcp_forward(
        "10.64.0.1", 80, "tcp:127.0.0.1:" + std::to_string(api_port)));

    // --- Client node: dataplane + netstack originating from 10.64.0.2 ---
    UserspaceDataplane client_dp;
    VirtualNetService  client_vnet;
    client_vnet.start();
    client_dp.set_inbound_handler(
        [&](std::span<const uint8_t> p) { client_vnet.deliver_inbound_ip_packet(p); });
    client_vnet.set_outbound_sink(
        [&](std::span<const uint8_t> p) { client_dp.send_outbound_ip_packet(p); });
    ASSERT_TRUE(client_dp.start({client_keys.priv_b64, client_keys.pub_b64, 0, 2}));

    client_dp.add_local_ip(0x0A400002u);  // 10.64.0.2
    client_vnet.add_local_ip("10.64.0.2/10");
    ASSERT_TRUE(client_dp.add_peer(server_keys.pub_b64, "10.64.0.0/10",
                                   "127.0.0.1:" + std::to_string(server_dp.bound_port())));

    // Egress: a real loopback port the test client dials; bridged to a virtual
    // TCP connection to 10.64.0.1:80 over the tunnel.
    uint16_t egress_port = client_vnet.add_tcp_egress("10.64.0.1", 80, "10.64.0.2");
    ASSERT_NE(egress_port, 0);

    // Give the API server a moment to start listening.
    std::this_thread::sleep_for(200ms);

    // --- Drive a real HTTP GET through the whole userspace tunnel ---
    httplib::Client client("127.0.0.1", egress_port);
    client.set_connection_timeout(10, 0);
    client.set_read_timeout(10, 0);

    httplib::Result res;
    auto deadline = std::chrono::steady_clock::now() + 15s;
    do {
        res = client.Get("/ping");
        if (res && res->status == 200) break;
        std::this_thread::sleep_for(200ms);
    } while (std::chrono::steady_clock::now() < deadline);

    ASSERT_TRUE(res) << "no HTTP response over the userspace tunnel";
    EXPECT_EQ(res->status, 200);
    EXPECT_EQ(res->body, "pong");

    // Teardown.
    client_dp.stop();
    server_dp.stop();
    client_vnet.stop();
    server_vnet.stop();
    api.stop();
    if (api_thread.joinable()) api_thread.join();
}
