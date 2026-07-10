// SDK-level counterpart of test_virtual_e2e: node A publishes a local HTTP
// service into the mesh via BoringtunMesh::tcp_ingress (the sidecar pattern —
// "expose lemond's port to my other devices"), and node B reaches it through
// tcp_egress. Both ends are fully userspace; the only real sockets are
// loopback TCP and the two WG/UDP sockets.

#include <gtest/gtest.h>

#include <LemonadeNexusSDK/BoringtunMesh.hpp>
#include <LemonadeNexusSDK/Types.hpp>

#include <httplib.h>
#include <sodium.h>

#include <chrono>
#include <string>
#include <thread>

using namespace std::chrono_literals;

TEST(MeshIngress, ExposedServiceReachableFromPeer) {
    ASSERT_GE(sodium_init(), 0);

    // --- The "lemond" stand-in: an HTTP server reachable only on loopback ---
    httplib::Server api;
    api.Get("/ping", [](const httplib::Request&, httplib::Response& res) {
        res.set_content("sidecar-pong", "text/plain");
    });
    int api_port = api.bind_to_any_port("127.0.0.1");
    ASSERT_GT(api_port, 0);
    std::thread api_thread([&api] { api.listen_after_bind(); });

    auto a_keys = lnsdk::BoringtunMesh::generate_keypair();  // {private, public}
    auto b_keys = lnsdk::BoringtunMesh::generate_keypair();

    // --- Node A (the sidecar): mesh IP 10.64.0.2, exposes the service ---
    lnsdk::BoringtunMesh a;
    lnsdk::BoringtunConfig acfg;
    acfg.private_key = a_keys.first;
    acfg.public_key  = a_keys.second;
    acfg.tunnel_ip   = "10.64.0.2/32";
    acfg.allowed_ips = {"10.64.0.0/10"};
    ASSERT_TRUE(a.start(acfg));
    ASSERT_TRUE(a.tcp_ingress(8080, "tcp:127.0.0.1:" + std::to_string(api_port)));
    ASSERT_GT(a.bound_port(), 0);

    // Ingress requires an active dataplane and sane arguments
    EXPECT_FALSE(a.tcp_ingress(0, "tcp:127.0.0.1:1"));
    EXPECT_FALSE(a.tcp_ingress(8081, ""));

    // --- Node B (another device): mesh IP 10.64.0.3, A is its initial peer ---
    lnsdk::BoringtunMesh b;
    lnsdk::BoringtunConfig bcfg;
    bcfg.private_key       = b_keys.first;
    bcfg.public_key        = b_keys.second;
    bcfg.tunnel_ip         = "10.64.0.3/32";
    bcfg.allowed_ips       = {"10.64.0.0/10"};
    bcfg.server_public_key = a_keys.second;
    bcfg.server_endpoint   = "127.0.0.1:" + std::to_string(a.bound_port());
    ASSERT_TRUE(b.start(bcfg));

    // A needs B as a peer for the return path
    lnsdk::MeshPeer bp;
    bp.wg_pubkey = b_keys.second;
    bp.tunnel_ip = "10.64.0.3/32";
    bp.endpoint  = "127.0.0.1:" + std::to_string(b.bound_port());
    ASSERT_TRUE(a.sync_peers({bp}).ok);

    // --- Dial A's exposed service from B through the mesh ---
    uint16_t egress_port = b.tcp_egress("10.64.0.2", 8080);
    ASSERT_NE(egress_port, 0);

    std::this_thread::sleep_for(200ms);

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

    ASSERT_TRUE(res) << "no HTTP response through the exposed mesh service";
    EXPECT_EQ(res->status, 200);
    EXPECT_EQ(res->body, "sidecar-pong");

    b.stop();
    a.stop();
    api.stop();
    if (api_thread.joinable()) api_thread.join();
}

TEST(MeshIngress, IngressRejectedWhenInactive) {
    lnsdk::BoringtunMesh idle;
    EXPECT_FALSE(idle.tcp_ingress(8080, "tcp:127.0.0.1:80"));
    EXPECT_EQ(idle.bound_port(), 0);
    EXPECT_EQ(idle.tcp_egress("10.64.0.1", 9101), 0);
}
