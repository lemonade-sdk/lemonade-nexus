// SDK-level counterpart of test_virtual_e2e: node A publishes a local HTTP
// service into the mesh via BoringtunMesh::tcp_ingress (the sidecar pattern —
// "expose lemond's port to my other devices"), and node B reaches it through
// tcp_egress. Both ends are fully userspace; the only real sockets are
// loopback TCP and the two encrypted mesh UDP sockets.

#include <gtest/gtest.h>

#include <LemonadeNexusSDK/BoringtunMesh.hpp>
#include <LemonadeNexusSDK/Types.hpp>

#include <httplib.h>
#include <sodium.h>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

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
    bp.mesh_pubkey = b_keys.second;
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

// A client reaches the private API of the server it joined at the server's
// tunnel address, through the server peer's plane route. When every server
// bound 10.64.0.10, the first endpoint that a server allocated held that
// address too. A listed peer on the server's address would get a /32 route, a
// longer match than the plane route, and the client's private API requests
// would go to that peer. The client must refuse the peer's claim.
TEST(MeshIngress, PrivateApiStaysOnTheServerWhenAPeerClaimsItsAddress) {
    ASSERT_GE(sodium_init(), 0);
    const std::string server_ip = "10.64.252.37";
    constexpr uint16_t kPrivatePort = 9101;

    const auto serve = [](httplib::Server& api, const std::string& body) {
        api.Get("/who", [body](const httplib::Request&, httplib::Response& res) {
            res.set_content(body, "text/plain");
        });
        return api.bind_to_any_port("127.0.0.1");
    };
    httplib::Server server_api;
    httplib::Server peer_api;
    const int server_api_port = serve(server_api, "server");
    const int peer_api_port = serve(peer_api, "peer");
    ASSERT_GT(server_api_port, 0);
    ASSERT_GT(peer_api_port, 0);
    std::thread server_thread([&] { server_api.listen_after_bind(); });
    std::thread peer_thread([&] { peer_api.listen_after_bind(); });

    const auto server_keys = lnsdk::BoringtunMesh::generate_keypair();
    const auto peer_keys = lnsdk::BoringtunMesh::generate_keypair();
    const auto client_keys = lnsdk::BoringtunMesh::generate_keypair();
    const auto config = [](const std::pair<std::string, std::string>& keys,
                           const std::string& tunnel_ip) {
        lnsdk::BoringtunConfig cfg;
        cfg.private_key = keys.first;
        cfg.public_key = keys.second;
        cfg.tunnel_ip = tunnel_ip + "/32";
        cfg.allowed_ips = {"10.64.0.0/10"};
        return cfg;
    };

    // The server and the peer both answer on the server's address.
    lnsdk::BoringtunMesh server;
    lnsdk::BoringtunMesh peer;
    ASSERT_TRUE(server.start(config(server_keys, server_ip)));
    ASSERT_TRUE(peer.start(config(peer_keys, server_ip)));
    ASSERT_TRUE(server.tcp_ingress(kPrivatePort,
                                   "tcp:127.0.0.1:" + std::to_string(server_api_port)));
    ASSERT_TRUE(peer.tcp_ingress(kPrivatePort, "tcp:127.0.0.1:" + std::to_string(peer_api_port)));

    // The client joined the server; the join gave it the server's address.
    auto client_cfg = config(client_keys, "10.65.0.9");
    client_cfg.server_public_key = server_keys.second;
    client_cfg.server_endpoint = "127.0.0.1:" + std::to_string(server.bound_port());
    client_cfg.server_tunnel_ip = server_ip;
    lnsdk::BoringtunMesh client;
    ASSERT_TRUE(client.start(client_cfg));

    lnsdk::MeshPeer client_entry;
    client_entry.mesh_pubkey = client_keys.second;
    client_entry.tunnel_ip = "10.65.0.9/32";
    client_entry.endpoint = "127.0.0.1:" + std::to_string(client.bound_port());
    ASSERT_TRUE(server.sync_peers({client_entry}).ok);
    ASSERT_TRUE(peer.sync_peers({client_entry}).ok);

    lnsdk::MeshPeer claimant;
    claimant.node_id = "claimant";
    claimant.mesh_pubkey = peer_keys.second;
    claimant.tunnel_ip = server_ip + "/32";
    claimant.endpoint = "127.0.0.1:" + std::to_string(peer.bound_port());
    ASSERT_TRUE(client.sync_peers({claimant}).ok);

    const uint16_t egress = client.tcp_egress(server_ip, kPrivatePort);
    ASSERT_NE(egress, 0);
    httplib::Client http("127.0.0.1", egress);
    http.set_connection_timeout(5, 0);
    http.set_read_timeout(5, 0);
    httplib::Result res;
    const auto deadline = std::chrono::steady_clock::now() + 15s;
    do {
        res = http.Get("/who");
        if (res && res->status == 200) break;
        std::this_thread::sleep_for(200ms);
    } while (std::chrono::steady_clock::now() < deadline);

    ASSERT_TRUE(res) << "no response from the private API address";
    EXPECT_EQ(res->body, "server") << "the private API request went to a peer";

    client.stop();
    peer.stop();
    server.stop();
    server_api.stop();
    peer_api.stop();
    server_thread.join();
    peer_thread.join();
}

TEST(MeshIngress, IngressRejectedWhenInactive) {
    lnsdk::BoringtunMesh idle;
    EXPECT_FALSE(idle.tcp_ingress(8080, "tcp:127.0.0.1:80"));
    EXPECT_EQ(idle.bound_port(), 0);
    EXPECT_EQ(idle.tcp_egress("10.64.0.1", 9101), 0);
}

// stop() destroys the netstack while egress and ingress calls run on other
// threads. Each of those calls must observe either the live netstack or none,
// never a freed one. A use-after-free here crashes intermittently in a normal
// build; ThreadSanitizer or AddressSanitizer reports it on every run.
TEST(MeshIngress, StopRacesEgressAndIngressSafely) {
    ASSERT_GE(sodium_init(), 0);
    auto keys = lnsdk::BoringtunMesh::generate_keypair();
    lnsdk::BoringtunConfig cfg;
    cfg.private_key = keys.first;
    cfg.public_key  = keys.second;
    cfg.tunnel_ip   = "10.64.0.9/32";
    cfg.allowed_ips = {"10.64.0.0/10"};

    lnsdk::BoringtunMesh mesh;
    std::atomic<bool> done{false};
    std::vector<std::thread> workers;
    for (int w = 0; w < 4; ++w) {
        workers.emplace_back([&mesh, &done, w] {
            uint16_t port = 1;
            while (!done.load()) {
                const std::string dst = "10.64.1." + std::to_string(w + 1);
                (void)mesh.tcp_egress(dst, port);
                (void)mesh.tcp_ingress(static_cast<uint16_t>(9000 + w), "tcp:127.0.0.1:1");
                mesh.close_egress(dst, port);
                (void)mesh.mesh_status();
                port = static_cast<uint16_t>(port % 200 + 1);
            }
        });
    }
    for (int i = 0; i < 40; ++i) {
        EXPECT_TRUE(mesh.start(cfg));
        std::this_thread::sleep_for(2ms);
        mesh.stop();
    }
    done = true;
    for (auto& t : workers) t.join();
    EXPECT_FALSE(mesh.is_active());
    EXPECT_EQ(mesh.tcp_egress("10.64.0.1", 9101), 0);
}
