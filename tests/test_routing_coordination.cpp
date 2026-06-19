#include <LemonadeNexus/Routing/RoutingCoordinationService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <asio.hpp>
#include <gtest/gtest.h>

#include <filesystem>
#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

using namespace nexus;
namespace fs = std::filesystem;

class RoutingCoordinationTest : public ::testing::Test {
protected:
    fs::path temp_dir;
    asio::io_context io;
    std::unique_ptr<crypto::SodiumCryptoService> crypto_svc;
    std::unique_ptr<storage::FileStorageService> storage_svc;
    std::unique_ptr<gossip::GossipService> gossip_svc;
    std::unique_ptr<routing::RoutingCoordinationService> routing;

    void make(bool with_root) {
        temp_dir = fs::temp_directory_path() /
                   ("nexus_test_routing_coord_" + std::to_string(getpid()));
        fs::create_directories(temp_dir);
        crypto_svc = std::make_unique<crypto::SodiumCryptoService>();
        crypto_svc->start();
        storage_svc = std::make_unique<storage::FileStorageService>(temp_dir);
        storage_svc->start();
        gossip_svc = std::make_unique<gossip::GossipService>(io, 0, *storage_svc, *crypto_svc);
        if (with_root) {
            auto kp = crypto_svc->ed25519_keygen();
            gossip_svc->set_root_pubkey(kp.public_key);
        }
        routing = std::make_unique<routing::RoutingCoordinationService>(*crypto_svc, *gossip_svc);
        routing->start();
    }

    void TearDown() override {
        if (routing) routing->stop();
        if (gossip_svc) gossip_svc->stop();
        if (storage_svc) storage_svc->stop();
        if (crypto_svc) crypto_svc->stop();
        if (!temp_dir.empty()) fs::remove_all(temp_dir);
    }

    routing::ConnectionRequestInput req(const std::string& client, const std::string& target) {
        routing::ConnectionRequestInput in;
        in.client_node_id = client;
        in.client_pubkey = "ed25519:" + client;
        in.target_node_id = target;
        in.target_identifier = "infer-" + target;
        in.source_ip = "203.0.113.7";
        return in;
    }
};

TEST_F(RoutingCoordinationTest, DisabledWithoutRoot) {
    make(/*with_root=*/false);
    EXPECT_FALSE(routing->enabled());
    auto r = routing->create_request(req("client-1", "ep-1"));
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.status, 503);
}

TEST_F(RoutingCoordinationTest, FullLifecycle) {
    make(/*with_root=*/true);
    ASSERT_TRUE(routing->enabled());

    routing::EndpointRegistration reg;
    reg.node_id = "ep-1";
    reg.endpoint_identifier = "infer-ep-1";
    reg.wg_pubkey = "WGEP";
    reg.mgmt_pubkey = "ed25519:ep-1";
    routing->register_endpoint(reg);

    auto in = req("client-1", "ep-1");
    in.conn_nonce = {{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}};
    in.client_wg_pub = "WGCLIENT";
    auto r = routing->create_request(in);
    ASSERT_TRUE(r.ok);
    EXPECT_EQ(r.status, 202);
    const std::string cid = r.connection_id;

    // Endpoint discovers the request by polling.
    auto pending = routing->take_pending_for_endpoint("ep-1");
    ASSERT_EQ(pending.size(), 1u);
    EXPECT_EQ(pending[0], cid);

    // Visibility: participants only.
    EXPECT_TRUE(routing->get_session(cid, "client-1").has_value());
    EXPECT_TRUE(routing->get_session(cid, "ep-1").has_value());
    EXPECT_FALSE(routing->get_session(cid, "stranger").has_value());

    // Client cannot get a directive before the endpoint is ready.
    EXPECT_FALSE(routing->build_client_directive(cid, "client-1").has_value());

    routing::EndpointReadyInput ready;
    ready.connection_id = cid;
    ready.endpoint_node_id = "ep-1";
    ready.endpoint_wg_pub = "WGEP";
    std::string err;
    ASSERT_TRUE(routing->endpoint_ready(ready, err)) << err;

    // Only the client may fetch the directive; nonce round-trips.
    EXPECT_FALSE(routing->build_client_directive(cid, "ep-1").has_value());
    auto d = routing->build_client_directive(cid, "client-1");
    ASSERT_TRUE(d.has_value());
    EXPECT_EQ(d->endpoint_identifier, "infer-ep-1");
    EXPECT_EQ(d->endpoint_wg_pub, "WGEP");
    EXPECT_EQ(d->conn_nonce, in.conn_nonce);
}

TEST_F(RoutingCoordinationTest, EndpointReadyUnknownConnection) {
    make(true);
    routing::EndpointReadyInput ready;
    ready.connection_id = "deadbeef";
    ready.endpoint_node_id = "ep-1";
    std::string err;
    EXPECT_FALSE(routing->endpoint_ready(ready, err));
    EXPECT_EQ(err, "unknown connection");
}

TEST_F(RoutingCoordinationTest, PerClientCapEnforced) {
    make(true);
    const auto cap = routing::RoutingCoordinationService::kMaxPendingPerClient;
    for (std::size_t i = 0; i < cap; ++i) {
        auto r = routing->create_request(req("client-1", "ep-" + std::to_string(i)));
        ASSERT_TRUE(r.ok) << "request " << i << " unexpectedly rejected";
    }
    auto over = routing->create_request(req("client-1", "ep-over"));
    EXPECT_FALSE(over.ok);
    EXPECT_EQ(over.status, 429);

    // A different client is unaffected by the first client's cap.
    EXPECT_TRUE(routing->create_request(req("client-2", "ep-x")).ok);
}
