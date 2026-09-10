// The security mesh service on two real gossip nodes over localhost UDP:
// lifecycle, the honest ineligible-host attestation path end to end, and the
// transport gates in front of the router. Node A's gossip identity IS the
// pinned Genesis anchor; node B is a candidate.

#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Gossip/GossipTypes.hpp>
#include <LemonadeNexus/Security/Lifecycle/SecurityMeshService.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <asio.hpp>
#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

using namespace nexus;
namespace fs = std::filesystem;
using asio::ip::udp;

// Friend seam (same seam as tests/test_onboarding.cpp): the bound port is
// private, and the peer-certified callback sits behind certificate
// provisioning that a unit test cannot drive compactly. The gossip transport
// tests prove the wire path; `certify` invokes the exact callback
// SecurityMeshService wires in on_start.
namespace nexus::gossip {
struct GossipBallotTestAccess {
    static uint16_t port(GossipService& g) { return g.socket_.local_endpoint().port(); }
    static void certify(GossipService& g, const security::NodeId& peer) {
        if (g.peer_certified_cb_) g.peer_certified_cb_(peer);
    }
};
}  // namespace nexus::gossip

namespace {

struct Node {
    fs::path dir;
    std::unique_ptr<crypto::SodiumCryptoService> crypto;
    std::unique_ptr<storage::FileStorageService> storage;
    std::unique_ptr<crypto::KeyWrappingService> wrapping;
    std::unique_ptr<gossip::GossipService> gossip;
    std::unique_ptr<security::SecurityMeshService> mesh;

    [[nodiscard]] security::NodeId id() const {
        security::NodeId n{};
        n.bytes = gossip->keypair().public_key;
        return n;
    }
    [[nodiscard]] const crypto::Ed25519PublicKey& pubkey() const {
        return gossip->keypair().public_key;
    }
    [[nodiscard]] std::string pubkey_b64() const { return crypto::to_base64(pubkey()); }
    [[nodiscard]] uint16_t port() { return gossip::GossipBallotTestAccess::port(*gossip); }
    [[nodiscard]] std::string endpoint() { return "127.0.0.1:" + std::to_string(port()); }
    [[nodiscard]] udp::endpoint udp_endpoint() {
        return udp::endpoint{asio::ip::make_address("127.0.0.1"), port()};
    }
};

class SecurityMeshServiceTest : public ::testing::Test {
protected:
    // Declared before the nodes so it outlives their sockets and timers.
    asio::io_context io;
    fs::path root;
    std::vector<std::unique_ptr<Node>> nodes;

    void SetUp() override {
        root = fs::temp_directory_path() /
               ("nexus_test_sec_mesh_" + std::to_string(getpid()));
        fs::remove_all(root);
        fs::create_directories(root);
    }

    void TearDown() override {
        for (auto it = nodes.rbegin(); it != nodes.rend(); ++it) {
            if ((*it)->mesh) (*it)->mesh->stop();
            (*it)->gossip->stop();
            (*it)->wrapping->stop();
            (*it)->storage->stop();
            (*it)->crypto->stop();
        }
        nodes.clear();
        fs::remove_all(root);
    }

    // Every node shares one io_context that the test thread pumps, so the
    // whole security stack runs on the test thread.
    Node& make_node(const std::string& tag) {
        auto n = std::make_unique<Node>();
        n->dir = root / tag;
        fs::create_directories(n->dir);
        n->crypto = std::make_unique<crypto::SodiumCryptoService>();
        n->crypto->start();
        n->storage = std::make_unique<storage::FileStorageService>(n->dir);
        n->storage->start();
        n->wrapping = std::make_unique<crypto::KeyWrappingService>(*n->crypto, *n->storage);
        n->wrapping->start();
        n->gossip = std::make_unique<gossip::GossipService>(io, 0, *n->storage, *n->crypto);
        n->gossip->start();
        nodes.push_back(std::move(n));
        return *nodes.back();
    }

    // The gossip identity exists only after gossip->start(), so the mesh
    // service is built afterwards — the same order main.cpp uses.
    void make_mesh(Node& node, const crypto::Ed25519PublicKey& genesis_pub) {
        security::SecurityMeshConfig config;
        config.data_root = node.dir / "mesh";
        config.genesis_public_key = genesis_pub;
        config.identity = node.gossip->keypair();
        config.profile.security_ruleset = security::constants::kSecurityRulesetVersion;
        node.mesh = std::make_unique<security::SecurityMeshService>(io, config, *node.gossip,
                                                                    node.wrapping.get());
        node.mesh->start();
    }

    void peer_all() {
        for (auto& a : nodes)
            for (auto& b : nodes)
                if (a != b) a->gossip->add_peer(b->endpoint(), b->pubkey_b64());
    }

    bool pump_until(const std::function<bool()>& done,
                    std::chrono::milliseconds timeout = std::chrono::seconds(5)) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            io.restart();
            io.poll();
            if (done()) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return done();
    }

    void pump_for(std::chrono::milliseconds d) {
        (void)pump_until([] { return false; }, d);
    }

    // A raw packet in gossip framing. `claimed` goes into the header as the
    // sender identity; `signer` produces the trailing signature. They differ
    // only in the forgery test.
    static std::vector<uint8_t> build_packet(crypto::SodiumCryptoService& c,
                                             const crypto::Ed25519PublicKey& claimed,
                                             const crypto::Ed25519Keypair& signer,
                                             const std::vector<uint8_t>& payload) {
        gossip::GossipPacketHeader h{};
        h.magic    = gossip::kGossipMagic;
        h.version  = gossip::kGossipVersion;
        h.msg_type = gossip::GossipMsgType::SecurityEnvelope;
        std::memcpy(h.sender_pubkey, claimed.data(), claimed.size());
        h.payload_length = static_cast<uint16_t>(payload.size());

        std::vector<uint8_t> pkt(gossip::kGossipHeaderSize + payload.size() +
                                 gossip::kGossipSignatureSize);
        std::memcpy(pkt.data(), &h, gossip::kGossipHeaderSize);
        if (!payload.empty()) {
            std::memcpy(pkt.data() + gossip::kGossipHeaderSize, payload.data(), payload.size());
        }
        const std::size_t signed_len = gossip::kGossipHeaderSize + payload.size();
        auto sig = c.ed25519_sign(signer.private_key,
                                  std::span<const uint8_t>{pkt.data(), signed_len});
        std::memcpy(pkt.data() + signed_len, sig.data(), sig.size());
        return pkt;
    }

    // Push raw bytes at a node from a socket that is not a gossip peer.
    void inject(const std::vector<uint8_t>& pkt, Node& target) {
        udp::socket raw{io, udp::endpoint{udp::v4(), 0}};
        raw.set_option(asio::socket_base::send_buffer_size(65536));
        raw.send_to(asio::buffer(pkt), target.udp_endpoint());
    }
};

}  // namespace

// (a) Start and stop are clean, stopping twice is safe, and nothing fires
// after stop.
TEST_F(SecurityMeshServiceTest, StartStopIsCleanAndIdempotent) {
    auto& a = make_node("a");
    auto& b = make_node("b");
    peer_all();
    make_mesh(a, a.pubkey());  // A's own identity is the pinned anchor.
    make_mesh(b, a.pubkey());

    // A holds the one-shot Genesis authority; B waits with no assumed role.
    EXPECT_EQ(a.mesh->driver().phase(), security::DriverPhase::GenesisCollecting);
    EXPECT_EQ(b.mesh->driver().phase(), security::DriverPhase::Idle);

    pump_for(std::chrono::milliseconds(350));  // several driver ticks

    b.mesh->stop();
    b.mesh->stop();  // idempotent
    a.mesh->stop();
    a.mesh->stop();

    // No timer callback runs after stop; polling must stay uneventful.
    pump_for(std::chrono::milliseconds(350));
    EXPECT_EQ(a.mesh->driver().phase(), security::DriverPhase::GenesisCollecting);
    EXPECT_EQ(b.mesh->driver().phase(), security::DriverPhase::Idle);
}

// (b) The honest ineligible-host path over real sockets: Genesis challenges a
// certified peer, the peer answers with an empty platform bundle (this host
// has no TPM), and the verdict is a recorded FAIL — never a pass.
TEST_F(SecurityMeshServiceTest, IneligibleHostFailsAttestationOverUdp) {
    auto& a = make_node("a");
    auto& b = make_node("b");
    peer_all();
    make_mesh(a, a.pubkey());
    make_mesh(b, a.pubkey());

    // The callback seam stands in for a root-signed ServerHello exchange.
    gossip::GossipBallotTestAccess::certify(*a.gossip, b.id());

    ASSERT_TRUE(pump_until([&] {
        return a.mesh->runtime().attestation().verdict(b.id()).has_value();
    }));

    const auto verdict = a.mesh->runtime().attestation().verdict(b.id());
    ASSERT_TRUE(verdict.has_value());
    EXPECT_EQ(verdict->node_id, b.id());
    EXPECT_FALSE(verdict->passed);
}

// (c) Hostile input is contained before the services: garbage is dropped as
// malformed, and a packet claiming B's identity from a third socket never
// reaches the router as B (the gossip signature gate).
TEST_F(SecurityMeshServiceTest, GarbageAndForgedEnvelopesAreContained) {
    auto& a = make_node("a");
    auto& b = make_node("b");
    peer_all();
    make_mesh(a, a.pubkey());
    make_mesh(b, a.pubkey());

    // Garbage from an authenticated peer: reaches the router, dies as
    // Malformed, and must not disturb the service.
    const std::vector<uint8_t> garbage{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02};
    ASSERT_TRUE(b.gossip->send_to(a.id(), garbage));
    pump_for(std::chrono::milliseconds(200));

    // Forgery: the header claims B, but the signature comes from a stranger.
    // The packet-signature gate drops it before any sink or router work.
    const auto attacker = a.crypto->ed25519_keygen();
    inject(build_packet(*a.crypto, b.pubkey(), attacker, garbage), a);
    pump_for(std::chrono::milliseconds(200));

    // Nothing was attributed to B.
    EXPECT_FALSE(a.mesh->runtime().attestation().verdict(b.id()).has_value());

    // The stack is still alive: the real path still completes.
    gossip::GossipBallotTestAccess::certify(*a.gossip, b.id());
    ASSERT_TRUE(pump_until([&] {
        return a.mesh->runtime().attestation().verdict(b.id()).has_value();
    }));
    EXPECT_FALSE(a.mesh->runtime().attestation().verdict(b.id())->passed);
}

// (d) ServerConfig carries genesis_pubkey from every source; empty stays
// empty, so a node without the anchor runs no part of the new system.
TEST_F(SecurityMeshServiceTest, ServerConfigRoundTripsGenesisPubkey) {
    // Default: absent means not configured.
    {
        char prog[] = "nexus";
        char* argv[] = {prog};
        const auto config = core::load_config(1, argv);
        EXPECT_TRUE(config.genesis_pubkey.empty());
    }

    // JSON.
    const auto json_path = (root / "cfg.json").string();
    {
        std::ofstream f(json_path);
        f << R"({"genesis_pubkey":"anchor-from-json"})";
    }
    {
        char prog[] = "nexus";
        char flag[] = "--config";
        std::string path = json_path;
        char* argv[] = {prog, flag, path.data()};
        const auto config = core::load_config(3, argv);
        EXPECT_EQ(config.genesis_pubkey, "anchor-from-json");
    }

    // CLI.
    {
        char prog[] = "nexus";
        char flag[] = "--genesis-pubkey";
        char value[] = "anchor-from-cli";
        char* argv[] = {prog, flag, value};
        const auto config = core::load_config(3, argv);
        EXPECT_EQ(config.genesis_pubkey, "anchor-from-cli");
    }

    // Environment.
#ifndef _WIN32
    {
        ASSERT_EQ(::setenv("SP_GENESIS_PUBKEY", "anchor-from-env", 1), 0);
        char prog[] = "nexus";
        char* argv[] = {prog};
        const auto config = core::load_config(1, argv);
        EXPECT_EQ(config.genesis_pubkey, "anchor-from-env");
        ::unsetenv("SP_GENESIS_PUBKEY");
    }
#endif
}
