// The port mapper drives gateway discovery, PCP, and NAT-PMP to keep one
// UDP mapping alive. It is checked against the fake gateway in
// tests/support with an injected gateway route and clock. The last test
// runs it inside the mesh orchestrator.

#include <gtest/gtest.h>

#include <LemonadeNexusSDK/BoringtunMesh.hpp>
#include <LemonadeNexusSDK/LemonadeNexusClient.hpp>
#include <LemonadeNexusSDK/MeshOrchestrator.hpp>
#include <LemonadeNexusSDK/PortMapper.hpp>

#include "support/FakeGateway.hpp"

#include <sodium.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using lnsdk::AddressScope;
using lnsdk::GatewayRoute;
using lnsdk::MappingProtocol;
using lnsdk::PortMapper;
using lnsdk::PortMapperOptions;
using test_support::FakeGateway;

namespace {

constexpr uint8_t kPcp = 2;
constexpr uint8_t kNatPmp = 0;
constexpr uint16_t kPort = 51820;
constexpr int64_t kStart = 1'700'000'000;

struct Harness {
    FakeGateway fake;
    int64_t clock{kStart};
    bool gateway_present{true};

    PortMapperOptions options(AddressScope server_scope = AddressScope::Public) {
        PortMapperOptions o;
        o.gateway_port = fake.port();
        o.server_scope = server_scope;
        o.gateway_source = [this]() -> std::optional<GatewayRoute> {
            if (!gateway_present) return std::nullopt;
            return GatewayRoute{"127.0.0.1", "127.0.0.1", "lo0"};
        };
        o.clock_unix = [this] { return clock; };
        return o;
    }

    /// Moves the clock and the fake's epoch together, as real time would.
    void pass(int64_t seconds) {
        clock += seconds;
        fake.advance_epoch(static_cast<uint32_t>(seconds));
    }

    size_t count(uint8_t protocol) const {
        size_t n = 0;
        for (const auto& r : fake.requests()) {
            if (r.protocol == protocol) ++n;
        }
        return n;
    }
};

}  // namespace

TEST(PortMapper, PrefersPcpWhenBothAnswer) {
    Harness h;
    ASSERT_NE(h.fake.port(), 0);
    h.fake.pcp_enabled = true;
    PortMapper mapper(h.options());

    EXPECT_TRUE(mapper.maintain(kPort));

    const auto m = mapper.mapping();
    EXPECT_EQ(m.protocol, MappingProtocol::Pcp);
    EXPECT_EQ(m.gateway, "127.0.0.1");
    EXPECT_EQ(m.local_address, "127.0.0.1");
    EXPECT_EQ(m.external_endpoint, "203.0.113.5:51820");
    EXPECT_EQ(m.internal_port, kPort);
    EXPECT_EQ(m.lifetime_sec, 7200u);
    EXPECT_EQ(m.mapped_at_unix, kStart);
    EXPECT_EQ(m.renew_at_unix, kStart + 1800);
    EXPECT_TRUE(m.last_error.empty());
    EXPECT_EQ(mapper.seconds_until_due(), 1800);

    const auto reqs = h.fake.requests();
    ASSERT_EQ(reqs.size(), 1u);
    EXPECT_EQ(reqs[0].protocol, kPcp);
    EXPECT_EQ(reqs[0].internal_port, kPort);
    EXPECT_EQ(reqs[0].suggested_port, kPort);
    EXPECT_EQ(reqs[0].lifetime_sec, 7200u);
    EXPECT_EQ(h.count(kNatPmp), 0u);
    EXPECT_EQ(h.fake.mapped_external_port(kPort), kPort);

    // Not due yet: no exchange.
    EXPECT_FALSE(mapper.maintain(kPort));
    EXPECT_EQ(h.fake.requests().size(), 1u);
}

TEST(PortMapper, FallsBackToNatPmpWhenPcpUnsupported) {
    Harness h;
    ASSERT_NE(h.fake.port(), 0);
    PortMapper mapper(h.options());

    EXPECT_TRUE(mapper.maintain(kPort));

    const auto m = mapper.mapping();
    EXPECT_EQ(m.protocol, MappingProtocol::NatPmp);
    EXPECT_EQ(m.external_endpoint, "203.0.113.5:51820");
    EXPECT_TRUE(m.last_error.empty());

    const auto reqs = h.fake.requests();
    ASSERT_EQ(reqs.size(), 3u);
    EXPECT_EQ(reqs[0].protocol, kPcp);
    EXPECT_EQ(reqs[1].protocol, kNatPmp);
    EXPECT_EQ(reqs[1].opcode, 0);
    EXPECT_EQ(reqs[2].protocol, kNatPmp);
    EXPECT_EQ(reqs[2].opcode, 1);
    EXPECT_EQ(reqs[2].internal_port, kPort);

    // A NAT-PMP renewal is one mapping request with the granted port.
    h.pass(1800);
    EXPECT_FALSE(mapper.maintain(kPort));
    const auto after = h.fake.requests();
    ASSERT_EQ(after.size(), 4u);
    EXPECT_EQ(after[3].protocol, kNatPmp);
    EXPECT_EQ(after[3].opcode, 1);
    EXPECT_EQ(after[3].suggested_port, kPort);
    EXPECT_EQ(mapper.mapping().renew_at_unix, h.clock + 1800);
}

TEST(PortMapper, PublishesNothingWhenNoGatewayAnswers) {
    Harness h;
    ASSERT_NE(h.fake.port(), 0);
    h.fake.pcp_enabled = true;
    h.fake.drop_requests = true;
    PortMapper mapper(h.options());

    EXPECT_FALSE(mapper.maintain(kPort));

    const auto m = mapper.mapping();
    EXPECT_EQ(m.protocol, MappingProtocol::None);
    EXPECT_TRUE(m.external_endpoint.empty());
    EXPECT_NE(m.last_error.find("did not answer"), std::string::npos);
    EXPECT_EQ(mapper.seconds_until_due(), 30);
    EXPECT_GE(h.count(kPcp), 1u);
    EXPECT_GE(h.count(kNatPmp), 1u);

    // Before the backoff ends nothing is sent.
    const size_t sent = h.fake.requests().size();
    EXPECT_FALSE(mapper.maintain(kPort));
    EXPECT_EQ(h.fake.requests().size(), sent);
}

TEST(PortMapper, PcpRefusalEndsTheAttempt) {
    Harness h;
    ASSERT_NE(h.fake.port(), 0);
    h.fake.pcp_enabled = true;
    h.fake.pcp_result = FakeGateway::kPcpNotAuthorized;
    PortMapper mapper(h.options());

    EXPECT_FALSE(mapper.maintain(kPort));

    const auto m = mapper.mapping();
    EXPECT_EQ(m.protocol, MappingProtocol::None);
    EXPECT_NE(m.last_error.find("NotAuthorized"), std::string::npos);
    EXPECT_EQ(h.count(kNatPmp), 0u);
    EXPECT_EQ(h.count(kPcp), 1u);
    EXPECT_EQ(mapper.seconds_until_due(), 30);
}

TEST(PortMapper, RenewsAtHalfLifeWithTheSameNonce) {
    Harness h;
    ASSERT_NE(h.fake.port(), 0);
    h.fake.pcp_enabled = true;
    PortMapper mapper(h.options());
    ASSERT_TRUE(mapper.maintain(kPort));
    const auto first = h.fake.requests().at(0);

    h.pass(1799);
    EXPECT_FALSE(mapper.maintain(kPort));
    EXPECT_EQ(h.fake.requests().size(), 1u);

    h.pass(1);
    EXPECT_FALSE(mapper.maintain(kPort));
    const auto reqs = h.fake.requests();
    ASSERT_EQ(reqs.size(), 2u);
    EXPECT_EQ(reqs[1].protocol, kPcp);
    EXPECT_EQ(reqs[1].nonce, first.nonce);
    EXPECT_EQ(reqs[1].internal_port, kPort);
    EXPECT_EQ(reqs[1].suggested_port, kPort);
    EXPECT_EQ(reqs[1].lifetime_sec, 7200u);

    const auto m = mapper.mapping();
    EXPECT_EQ(m.protocol, MappingProtocol::Pcp);
    EXPECT_EQ(m.external_endpoint, "203.0.113.5:51820");
    EXPECT_EQ(m.mapped_at_unix, h.clock);
    EXPECT_EQ(m.renew_at_unix, h.clock + 1800);
    EXPECT_EQ(mapper.seconds_until_due(), 1800);
}

TEST(PortMapper, FailedRenewalKeepsTheMappingUntilItEnds) {
    Harness h;
    ASSERT_NE(h.fake.port(), 0);
    h.fake.pcp_enabled = true;
    PortMapper mapper(h.options());
    ASSERT_TRUE(mapper.maintain(kPort));

    h.pass(1800);
    h.fake.drop_requests = true;
    EXPECT_FALSE(mapper.maintain(kPort));
    auto m = mapper.mapping();
    EXPECT_EQ(m.protocol, MappingProtocol::Pcp);
    EXPECT_EQ(m.external_endpoint, "203.0.113.5:51820");
    EXPECT_NE(m.last_error.find("did not answer"), std::string::npos);
    EXPECT_EQ(mapper.seconds_until_due(), 30);

    // The lifetime ends; the gateway now answers but refuses, so nothing
    // replaces the ended mapping.
    h.fake.drop_requests = false;
    h.fake.pcp_result = FakeGateway::kPcpNotAuthorized;
    h.pass(5400);
    EXPECT_TRUE(mapper.maintain(kPort));
    m = mapper.mapping();
    EXPECT_EQ(m.protocol, MappingProtocol::None);
    EXPECT_TRUE(m.external_endpoint.empty());
    EXPECT_NE(m.last_error.find("NotAuthorized"), std::string::npos);
}

TEST(PortMapper, GatewayRestartMapsAgain) {
    Harness h;
    ASSERT_NE(h.fake.port(), 0);
    h.fake.pcp_enabled = true;
    h.fake.advance_epoch(600);
    PortMapper mapper(h.options());
    ASSERT_TRUE(mapper.maintain(kPort));
    EXPECT_GE(mapper.mapping().epoch_sec, 600u);

    h.clock += 1800;
    h.fake.restart();
    ASSERT_FALSE(h.fake.mapped_external_port(kPort));

    EXPECT_FALSE(mapper.maintain(kPort));
    const auto reqs = h.fake.requests();
    ASSERT_EQ(reqs.size(), 2u);
    EXPECT_EQ(reqs[1].protocol, kPcp);
    EXPECT_EQ(reqs[1].lifetime_sec, 7200u);
    EXPECT_EQ(h.fake.mapped_external_port(kPort), kPort);

    const auto m = mapper.mapping();
    EXPECT_EQ(m.protocol, MappingProtocol::Pcp);
    EXPECT_EQ(m.external_endpoint, "203.0.113.5:51820");
    EXPECT_EQ(m.mapped_at_unix, h.clock);
    EXPECT_LT(m.epoch_sec, 600u);
}

TEST(PortMapper, InternalPortChangeReleasesTheOldMapping) {
    Harness h;
    ASSERT_NE(h.fake.port(), 0);
    h.fake.pcp_enabled = true;
    PortMapper mapper(h.options());
    ASSERT_TRUE(mapper.maintain(kPort));

    EXPECT_TRUE(mapper.maintain(kPort + 1));

    const auto reqs = h.fake.requests();
    ASSERT_EQ(reqs.size(), 3u);
    EXPECT_EQ(reqs[1].protocol, kPcp);
    EXPECT_EQ(reqs[1].internal_port, kPort);
    EXPECT_EQ(reqs[1].lifetime_sec, 0u);
    EXPECT_EQ(reqs[1].nonce, reqs[0].nonce);
    EXPECT_EQ(reqs[2].internal_port, kPort + 1);
    EXPECT_EQ(reqs[2].lifetime_sec, 7200u);
    EXPECT_FALSE(h.fake.mapped_external_port(kPort));
    EXPECT_EQ(h.fake.mapped_external_port(kPort + 1), kPort + 1);

    const auto m = mapper.mapping();
    EXPECT_EQ(m.internal_port, kPort + 1);
    EXPECT_EQ(m.external_endpoint, "203.0.113.5:51821");
}

TEST(PortMapper, LostGatewayClearsAndMapsAgainWhenBack) {
    Harness h;
    ASSERT_NE(h.fake.port(), 0);
    h.fake.pcp_enabled = true;
    PortMapper mapper(h.options());
    ASSERT_TRUE(mapper.maintain(kPort));

    h.gateway_present = false;
    EXPECT_TRUE(mapper.maintain(kPort));
    auto m = mapper.mapping();
    EXPECT_EQ(m.protocol, MappingProtocol::None);
    EXPECT_TRUE(m.external_endpoint.empty());
    EXPECT_EQ(m.last_error, "no default gateway");
    EXPECT_EQ(h.fake.requests().size(), 1u);
    EXPECT_EQ(mapper.seconds_until_due(), 30);

    h.gateway_present = true;
    h.pass(30);
    EXPECT_TRUE(mapper.maintain(kPort));
    m = mapper.mapping();
    EXPECT_EQ(m.protocol, MappingProtocol::Pcp);
    EXPECT_EQ(m.external_endpoint, "203.0.113.5:51820");
    EXPECT_TRUE(m.last_error.empty());
}

TEST(PortMapper, RejectsPrivateExternalAddressForPublicServer) {
    Harness h;
    ASSERT_NE(h.fake.port(), 0);
    h.fake.pcp_enabled = true;
    h.fake.set_external_address("192.168.1.9");
    PortMapper mapper(h.options(AddressScope::Public));

    EXPECT_FALSE(mapper.maintain(kPort));

    const auto m = mapper.mapping();
    EXPECT_EQ(m.protocol, MappingProtocol::None);
    EXPECT_TRUE(m.external_endpoint.empty());
    EXPECT_NE(m.last_error.find("not publishable"), std::string::npos);
    EXPECT_EQ(mapper.seconds_until_due(), 30);

    const auto reqs = h.fake.requests();
    ASSERT_EQ(reqs.size(), 2u);
    EXPECT_EQ(reqs[0].lifetime_sec, 7200u);
    EXPECT_EQ(reqs[1].lifetime_sec, 0u);
    EXPECT_EQ(reqs[1].internal_port, kPort);
    EXPECT_FALSE(h.fake.mapped_external_port(kPort));
}

TEST(PortMapper, AcceptsPrivateExternalAddressForPrivateServer) {
    Harness h;
    ASSERT_NE(h.fake.port(), 0);
    h.fake.pcp_enabled = true;
    h.fake.set_external_address("192.168.1.9");
    PortMapper mapper(h.options(AddressScope::Private));

    EXPECT_TRUE(mapper.maintain(kPort));

    const auto m = mapper.mapping();
    EXPECT_EQ(m.protocol, MappingProtocol::Pcp);
    EXPECT_EQ(m.external_endpoint, "192.168.1.9:51820");
    EXPECT_EQ(h.fake.requests().size(), 1u);
}

TEST(PortMapper, ReleaseSendsLifetimeZeroAndClearsTheState) {
    Harness h;
    ASSERT_NE(h.fake.port(), 0);
    h.fake.pcp_enabled = true;
    PortMapper mapper(h.options());
    ASSERT_TRUE(mapper.maintain(kPort));

    mapper.release();

    const auto reqs = h.fake.requests();
    ASSERT_EQ(reqs.size(), 2u);
    EXPECT_EQ(reqs[1].protocol, kPcp);
    EXPECT_EQ(reqs[1].internal_port, kPort);
    EXPECT_EQ(reqs[1].lifetime_sec, 0u);
    EXPECT_EQ(reqs[1].nonce, reqs[0].nonce);
    EXPECT_FALSE(h.fake.mapped_external_port(kPort));

    const auto m = mapper.mapping();
    EXPECT_EQ(m.protocol, MappingProtocol::None);
    EXPECT_TRUE(m.external_endpoint.empty());
    EXPECT_TRUE(m.last_error.empty());
    EXPECT_EQ(mapper.seconds_until_due(), 0);

    // A second release has nothing to send.
    mapper.release();
    EXPECT_EQ(h.fake.requests().size(), 2u);
}

TEST(PortMapper, DestructorReleasesALiveMapping) {
    Harness h;
    ASSERT_NE(h.fake.port(), 0);
    {
        PortMapper mapper(h.options());
        ASSERT_TRUE(mapper.maintain(kPort));
        EXPECT_EQ(mapper.mapping().protocol, MappingProtocol::NatPmp);
        EXPECT_EQ(h.fake.mapped_external_port(kPort), kPort);
    }
    const auto reqs = h.fake.requests();
    ASSERT_GE(reqs.size(), 4u);
    EXPECT_EQ(reqs.back().protocol, kNatPmp);
    EXPECT_EQ(reqs.back().opcode, 1);
    EXPECT_EQ(reqs.back().internal_port, kPort);
    EXPECT_EQ(reqs.back().lifetime_sec, 0u);
    EXPECT_FALSE(h.fake.mapped_external_port(kPort));
}

TEST(PortMapper, RejectsInternalPortZero) {
    Harness h;
    ASSERT_NE(h.fake.port(), 0);
    PortMapper mapper(h.options());

    EXPECT_FALSE(mapper.maintain(0));
    EXPECT_EQ(mapper.mapping().last_error, "internal port must not be 0");
    EXPECT_TRUE(h.fake.requests().empty());
}

// ---------------------------------------------------------------------------
// Inside the mesh orchestrator
// ---------------------------------------------------------------------------

namespace {

template <typename Pred>
bool wait_for(Pred pred, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return pred();
}

}  // namespace

// The orchestrator maps the dataplane's bound port once the dataplane is up
// (STUN off) and reports the mapping in its status; a lease that ends at a
// gateway that went silent clears the status. The client holds no session,
// so every private request is refused locally and the loop runs its local
// steps only.
TEST(PortMapperOrchestrator, StatusCarriesTheMappingUntilTheLeaseEnds) {
    ASSERT_GE(sodium_init(), 0);
    Harness h;
    ASSERT_NE(h.fake.port(), 0);
    h.fake.pcp_enabled = true;
    std::atomic<int64_t> clock{kStart};
    auto options = h.options();
    options.clock_unix = [&clock] { return clock.load(); };

    lnsdk::ServerConfig server;
    server.servers = {{"127.0.0.1", 1, true}};
    server.auto_discover = false;
    lnsdk::LemonadeNexusClient client(server);

    lnsdk::BoringtunMesh mesh;
    const auto keys = lnsdk::BoringtunMesh::generate_keypair();
    lnsdk::BoringtunConfig mesh_config;
    mesh_config.private_key = keys.first;
    mesh_config.public_key  = keys.second;
    mesh_config.tunnel_ip   = "10.64.0.9/32";
    mesh_config.allowed_ips = {"10.64.0.0/10"};
    ASSERT_TRUE(mesh.start(mesh_config));
    const uint16_t port = mesh.bound_port();
    ASSERT_NE(port, 0);
    {
        lnsdk::MeshOrchestrator orchestrator(client, mesh, "node-self");
        orchestrator.set_port_mapper_options(options);
        lnsdk::MeshConfig cfg;
        cfg.peer_refresh_interval_sec = 3600;
        cfg.heartbeat_interval_sec    = 3600;
        cfg.stun_refresh_interval_sec = 0;
        orchestrator.start(cfg);

        ASSERT_TRUE(wait_for([&] { return !orchestrator.status().mapped_endpoint.empty(); },
                             std::chrono::seconds(10)))
            << "the orchestrator did not map the dataplane port";
        const auto mapped = orchestrator.status();
        EXPECT_EQ(mapped.mapped_endpoint, "203.0.113.5:" + std::to_string(port));
        EXPECT_EQ(mapped.mapping_protocol, "pcp");
        EXPECT_EQ(h.fake.mapped_external_port(port), port);

        // The gateway reboots and answers nothing more; the lease runs out.
        h.fake.restart();
        h.fake.drop_requests = true;
        clock += 7200;
        orchestrator.refresh_now();
        EXPECT_TRUE(wait_for([&] { return orchestrator.status().mapped_endpoint.empty(); },
                             std::chrono::seconds(20)))
            << "the ended lease stayed in the status";
        EXPECT_EQ(orchestrator.status().mapping_protocol, "");
        orchestrator.stop();
    }
    mesh.stop();
}

// A gateway that answers nothing holds the first attempt for the whole PCP
// and NAT-PMP budget (about 11 s). The exchange runs on the mapping thread,
// so a refresh request meanwhile still runs its pass at once: the changed
// LAN address list is read within a second, not after the budget.
TEST(PortMapperOrchestrator, ASilentGatewayDoesNotHoldTheLoop) {
    ASSERT_GE(sodium_init(), 0);
    Harness h;
    ASSERT_NE(h.fake.port(), 0);
    h.fake.drop_requests = true;
    auto options = h.options();
    options.clock_unix = {};

    lnsdk::ServerConfig server;
    server.servers = {{"127.0.0.1", 1, true}};
    server.auto_discover = false;
    lnsdk::LemonadeNexusClient client(server);

    lnsdk::BoringtunMesh mesh;
    const auto keys = lnsdk::BoringtunMesh::generate_keypair();
    lnsdk::BoringtunConfig mesh_config;
    mesh_config.private_key = keys.first;
    mesh_config.public_key  = keys.second;
    mesh_config.tunnel_ip   = "10.64.0.9/32";
    mesh_config.allowed_ips = {"10.64.0.0/10"};
    ASSERT_TRUE(mesh.start(mesh_config));
    const auto port = std::to_string(mesh.bound_port());
    std::mutex lan_mtx;
    std::vector<lnsdk::InterfaceAddress> lan = {{"en0", "192.168.1.20", 24}};
    {
        lnsdk::MeshOrchestrator orchestrator(client, mesh, "node-self");
        orchestrator.set_port_mapper_options(options);
        orchestrator.set_local_address_source([&] {
            std::lock_guard lock(lan_mtx);
            return lan;
        });
        lnsdk::MeshConfig cfg;
        cfg.peer_refresh_interval_sec = 3600;
        cfg.heartbeat_interval_sec    = 3600;
        cfg.stun_refresh_interval_sec = 0;
        orchestrator.start(cfg);

        // The first pass posted the mapping attempt; the gateway got its
        // first request and keeps quiet.
        ASSERT_TRUE(wait_for([&] { return !h.fake.requests().empty(); }, std::chrono::seconds(5)));
        EXPECT_EQ(orchestrator.local_endpoints(), std::vector<std::string>{"192.168.1.20:" + port});

        {
            std::lock_guard lock(lan_mtx);
            lan = {{"wlan0", "10.0.5.7", 16}};
        }
        orchestrator.refresh_now();
        EXPECT_TRUE(wait_for([&] {
            return orchestrator.local_endpoints() == std::vector<std::string>{"10.0.5.7:" + port};
        }, std::chrono::seconds(2)))
            << "the refresh pass waited for the gateway";
        EXPECT_TRUE(orchestrator.status().mapped_endpoint.empty());
        orchestrator.stop();
    }
    mesh.stop();
}
