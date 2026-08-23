// Gossip as the transport of the security protocol: the packet signature is the
// peer identity, the byte bound is the only filter, and nothing is relayed.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Gossip/GossipTypes.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>
#include <LemonadeNexus/Security/Transport/SecurityTransport.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <asio.hpp>
#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>
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

// The bound port is private state; the friend seam reads it (same seam as
// tests/test_onboarding.cpp, defined inside its namespace for GCC).
namespace nexus::gossip {
struct GossipBallotTestAccess {
    static uint16_t port(GossipService& g) { return g.socket_.local_endpoint().port(); }
};
}  // namespace nexus::gossip

namespace {

constexpr std::size_t kMax = security::constants::kMaxSecurityMessageBytes;

struct Delivery {
    security::NodeId     sender;
    std::vector<uint8_t> bytes;
};

struct Node {
    std::unique_ptr<crypto::SodiumCryptoService> crypto;
    std::unique_ptr<storage::FileStorageService> storage;
    std::unique_ptr<gossip::GossipService>       gossip;
    std::vector<Delivery>                        received;

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

std::vector<uint8_t> bytes_of(std::string_view s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

class GossipSecurityTransportTest : public ::testing::Test {
protected:
    // Declared before the nodes so it outlives their sockets.
    asio::io_context io;
    fs::path root;
    std::vector<std::unique_ptr<Node>> nodes;

    void SetUp() override {
        root = fs::temp_directory_path() /
               ("nexus_test_sec_transport_" + std::to_string(getpid()));
        fs::remove_all(root);
        fs::create_directories(root);
    }

    void TearDown() override {
        for (auto it = nodes.rbegin(); it != nodes.rend(); ++it) {
            (*it)->gossip->stop();
            (*it)->storage->stop();
            (*it)->crypto->stop();
        }
        nodes.clear();
        fs::remove_all(root);
    }

    // Every node shares one io_context that the test thread pumps, so sinks
    // run on the test thread and `received` needs no lock.
    Node& make_node(const std::string& tag, bool with_sink = true) {
        auto n = std::make_unique<Node>();
        fs::create_directories(root / tag);
        n->crypto = std::make_unique<crypto::SodiumCryptoService>();
        n->crypto->start();
        n->storage = std::make_unique<storage::FileStorageService>(root / tag);
        n->storage->start();
        n->gossip = std::make_unique<gossip::GossipService>(io, 0, *n->storage, *n->crypto);
        if (with_sink) {
            Node* raw = n.get();
            n->gossip->set_security_sink(
                [raw](const security::NodeId& sender, std::span<const uint8_t> env) {
                    raw->received.push_back(
                        {sender, std::vector<uint8_t>(env.begin(), env.end())});
                });
        }
        n->gossip->start();
        nodes.push_back(std::move(n));
        return *nodes.back();
    }

    void peer_all() {
        for (auto& a : nodes)
            for (auto& b : nodes)
                if (a != b) a->gossip->add_peer(b->endpoint(), b->pubkey_b64());
    }

    bool pump_until(const std::function<bool()>& done,
                    std::chrono::milliseconds timeout = std::chrono::seconds(3)) {
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

    // A raw packet in gossip framing, signed by `kp` (the shape send_packet emits).
    static std::vector<uint8_t> build_packet(crypto::SodiumCryptoService& c,
                                             const crypto::Ed25519Keypair& kp,
                                             const std::vector<uint8_t>& payload) {
        gossip::GossipPacketHeader h{};
        h.magic    = gossip::kGossipMagic;
        h.version  = gossip::kGossipVersion;
        h.msg_type = gossip::GossipMsgType::SecurityEnvelope;
        std::memcpy(h.sender_pubkey, kp.public_key.data(), kp.public_key.size());
        h.payload_length = static_cast<uint16_t>(payload.size());

        std::vector<uint8_t> pkt(gossip::kGossipHeaderSize + payload.size() +
                                 gossip::kGossipSignatureSize);
        std::memcpy(pkt.data(), &h, gossip::kGossipHeaderSize);
        if (!payload.empty()) {
            std::memcpy(pkt.data() + gossip::kGossipHeaderSize, payload.data(), payload.size());
        }
        const std::size_t signed_len = gossip::kGossipHeaderSize + payload.size();
        auto sig = c.ed25519_sign(kp.private_key,
                                  std::span<const uint8_t>{pkt.data(), signed_len});
        std::memcpy(pkt.data() + signed_len, sig.data(), sig.size());
        return pkt;
    }

    // Push raw bytes at a node from a socket that is not a gossip peer.
    void inject(const std::vector<uint8_t>& pkt, Node& target) {
        udp::socket raw{io, udp::endpoint{udp::v4(), 0}};
        // macOS loopback refuses datagrams larger than the default send buffer.
        raw.set_option(asio::socket_base::send_buffer_size(65536));
        raw.send_to(asio::buffer(pkt), target.udp_endpoint());
    }
};

}  // namespace

// (a) Round trip: the bytes arrive unchanged and the sink identity is A's key.
TEST_F(GossipSecurityTransportTest, EnvelopeRoundTripCarriesTheSignerIdentity) {
    auto& a = make_node("a");
    auto& b = make_node("b");
    peer_all();

    const auto env = bytes_of("hotstuff-proposal-bytes");
    ASSERT_TRUE(a.gossip->send_to(b.id(), env));
    ASSERT_TRUE(pump_until([&] { return !b.received.empty(); }));

    ASSERT_EQ(b.received.size(), 1u);
    EXPECT_EQ(b.received[0].bytes, env);
    EXPECT_EQ(b.received[0].sender.bytes, a.pubkey());
    EXPECT_TRUE(a.received.empty());
}

// (b) The sink identity is the packet signer; payload content cannot change it.
TEST_F(GossipSecurityTransportTest, SinkIdentityIsThePacketSignerNotThePayload) {
    auto& a = make_node("a");
    auto& b = make_node("b");
    peer_all();

    // The payload claims B as its origin; the packet is signed by A.
    std::vector<uint8_t> forged(b.pubkey().begin(), b.pubkey().end());
    const auto tail = bytes_of(":sender-claim");
    forged.insert(forged.end(), tail.begin(), tail.end());

    ASSERT_TRUE(a.gossip->send_to(b.id(), forged));
    ASSERT_TRUE(pump_until([&] { return !b.received.empty(); }));

    ASSERT_EQ(b.received.size(), 1u);
    EXPECT_EQ(b.received[0].sender.bytes, a.pubkey());
    EXPECT_NE(b.received[0].sender.bytes, b.pubkey());
    EXPECT_EQ(b.received[0].bytes, forged);
}

// (c) Outbound: one byte over the bound is refused before any packet is built.
TEST_F(GossipSecurityTransportTest, OversizedEnvelopeIsRefusedOnSend) {
    auto& a = make_node("a");
    auto& b = make_node("b");
    peer_all();

    const std::vector<uint8_t> big(kMax + 1, 0x5A);
    EXPECT_FALSE(a.gossip->send_to(b.id(), big));
    EXPECT_EQ(a.gossip->broadcast(big), 0u);

    pump_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(b.received.empty());
}

// (c) Inbound: a correctly signed packet over the bound never reaches the sink.
TEST_F(GossipSecurityTransportTest, OversizedInboundEnvelopeIsDroppedBeforeTheSink) {
    auto& a = make_node("a");
    auto& b = make_node("b");
    peer_all();

    // Signed by A, so only the size check can drop it.
    const std::vector<uint8_t> over(kMax + 1, 0x5A);
    inject(build_packet(*a.crypto, a.gossip->keypair(), over), b);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_TRUE(b.received.empty());

    // Control: the same shape at exactly the bound is delivered.
    const std::vector<uint8_t> at_bound(kMax, 0x5A);
    inject(build_packet(*a.crypto, a.gossip->keypair(), at_bound), b);
    ASSERT_TRUE(pump_until([&] { return !b.received.empty(); }));
    ASSERT_EQ(b.received.size(), 1u);
    EXPECT_EQ(b.received[0].bytes.size(), kMax);
    EXPECT_EQ(b.received[0].sender.bytes, a.pubkey());
}

// (d) Unknown peer (and self) are refused.
TEST_F(GossipSecurityTransportTest, UnknownPeerAndSelfAreRefused) {
    auto& a = make_node("a");
    auto& b = make_node("b");
    peer_all();

    security::NodeId stranger{};
    stranger.bytes.fill(0x77);
    const auto env = bytes_of("x");
    EXPECT_FALSE(a.gossip->send_to(stranger, env));
    EXPECT_FALSE(a.gossip->send_to(a.id(), env));

    pump_for(std::chrono::milliseconds(100));
    EXPECT_TRUE(a.received.empty());
    EXPECT_TRUE(b.received.empty());
}

// (e) No sink: the envelope is dropped and the service keeps running.
TEST_F(GossipSecurityTransportTest, NoSinkDropsWithoutCrashing) {
    auto& a = make_node("a");
    auto& b = make_node("b", /*with_sink=*/false);
    peer_all();

    ASSERT_TRUE(a.gossip->send_to(b.id(), bytes_of("nobody-home")));
    pump_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(b.received.empty());

    // Still alive: a second envelope is also absorbed.
    ASSERT_TRUE(a.gossip->send_to(b.id(), bytes_of("still-nobody")));
    pump_for(std::chrono::milliseconds(100));
    EXPECT_TRUE(b.received.empty());
}

// (f) Broadcast reaches every peer with an endpoint and reports the count.
TEST_F(GossipSecurityTransportTest, BroadcastReachesEveryPeerWithAnEndpoint) {
    auto& a = make_node("a");
    auto& b = make_node("b");
    auto& c = make_node("c");
    peer_all();

    const auto env = bytes_of("epoch-announcement");
    EXPECT_EQ(a.gossip->broadcast(env), 2u);
    ASSERT_TRUE(pump_until([&] { return !b.received.empty() && !c.received.empty(); }));

    for (Node* n : {&b, &c}) {
        ASSERT_EQ(n->received.size(), 1u);
        EXPECT_EQ(n->received[0].bytes, env);
        EXPECT_EQ(n->received[0].sender.bytes, a.pubkey());
    }
    EXPECT_TRUE(a.received.empty());
}

// (g) Never relayed: B receiving from A does not forward to C.
TEST_F(GossipSecurityTransportTest, EnvelopeIsNeverRelayed) {
    auto& a = make_node("a");
    auto& b = make_node("b");
    auto& c = make_node("c");
    peer_all();

    ASSERT_TRUE(a.gossip->send_to(b.id(), bytes_of("point-to-point")));
    ASSERT_TRUE(pump_until([&] { return !b.received.empty(); }));
    pump_for(std::chrono::milliseconds(300));

    EXPECT_EQ(b.received.size(), 1u);
    EXPECT_TRUE(c.received.empty());
    EXPECT_TRUE(a.received.empty());
}

// (h) A flipped signature byte drops the packet before the sink.
TEST_F(GossipSecurityTransportTest, TamperedSignatureIsDroppedBeforeTheSink) {
    auto& a = make_node("a");
    auto& b = make_node("b");
    peer_all();

    auto pkt = build_packet(*a.crypto, a.gossip->keypair(), bytes_of("signed-by-a"));
    auto tampered = pkt;
    tampered.back() ^= 0x01;  // last byte of the trailing signature
    inject(tampered, b);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_TRUE(b.received.empty());

    // Control: the untouched packet from the same non-peer socket is delivered
    // and attributed to the signer, not to the source endpoint.
    inject(pkt, b);
    ASSERT_TRUE(pump_until([&] { return !b.received.empty(); }));
    ASSERT_EQ(b.received.size(), 1u);
    EXPECT_EQ(b.received[0].sender.bytes, a.pubkey());
    EXPECT_EQ(b.received[0].bytes, bytes_of("signed-by-a"));
}
