#include <gtest/gtest.h>

#include <LemonadeNexus/WireGuard/UserspaceDataplane.hpp>

#include <sodium.h>

#include <chrono>
#include <condition_variable>
#include <cstring>
#include <mutex>
#include <thread>
#include <vector>

using namespace nexus::wireguard;
using namespace std::chrono_literals;

namespace {

struct Keypair {
    std::string pub_b64;
    std::string priv_b64;
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

uint32_t ip(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    return (uint32_t(a) << 24) | (uint32_t(b) << 16) | (uint32_t(c) << 8) | d;
}

/// Build a minimal IPv4/UDP packet with the given payload.
std::vector<uint8_t> make_ipv4(uint32_t src, uint32_t dst,
                               const std::string& payload) {
    std::vector<uint8_t> pkt(20 + 8 + payload.size(), 0);
    pkt[0] = 0x45;                       // IPv4, IHL 5
    uint16_t total = static_cast<uint16_t>(pkt.size());
    pkt[2] = static_cast<uint8_t>(total >> 8);
    pkt[3] = static_cast<uint8_t>(total & 0xFF);
    pkt[8] = 64;                         // TTL
    pkt[9] = 17;                         // UDP
    for (int i = 0; i < 4; ++i) {
        pkt[12 + i] = static_cast<uint8_t>(src >> (8 * (3 - i)));
        pkt[16 + i] = static_cast<uint8_t>(dst >> (8 * (3 - i)));
    }
    uint16_t udp_len = static_cast<uint16_t>(8 + payload.size());
    pkt[20 + 4] = static_cast<uint8_t>(udp_len >> 8);
    pkt[20 + 5] = static_cast<uint8_t>(udp_len & 0xFF);
    std::memcpy(pkt.data() + 28, payload.data(), payload.size());
    return pkt;
}

/// Thread-safe inbox capturing packets delivered to a node's local handler.
struct Inbox {
    std::mutex mtx;
    std::condition_variable cv;
    std::vector<std::vector<uint8_t>> packets;

    UserspaceDataplane::InboundIpHandler handler() {
        return [this](std::span<const uint8_t> pkt) {
            std::lock_guard lock(mtx);
            packets.emplace_back(pkt.begin(), pkt.end());
            cv.notify_all();
        };
    }

    /// Wait until a packet whose payload contains `needle` arrives.
    bool wait_for_payload(const std::string& needle,
                          std::chrono::milliseconds timeout = 5000ms) {
        std::unique_lock lock(mtx);
        return cv.wait_for(lock, timeout, [&] { return contains_locked(needle); });
    }

    bool contains(const std::string& needle) {
        std::lock_guard lock(mtx);
        return contains_locked(needle);
    }

    size_t count() {
        std::lock_guard lock(mtx);
        return packets.size();
    }

private:
    bool contains_locked(const std::string& needle) {
        for (const auto& pkt : packets) {
            std::string_view view(reinterpret_cast<const char*>(pkt.data()), pkt.size());
            if (view.find(needle) != std::string_view::npos) return true;
        }
        return false;
    }
};

/// Retry-send until the receiving inbox sees the payload (handshake may still
/// be completing on the first attempts).
bool send_until_received(UserspaceDataplane& from, Inbox& to,
                         const std::vector<uint8_t>& pkt, const std::string& needle,
                         std::chrono::milliseconds timeout = 5000ms) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        (void)from.send_outbound_ip_packet(pkt);
        if (to.wait_for_payload(needle, 100ms)) return true;
    }
    return false;
}

struct Node {
    Keypair keys = make_keypair();
    UserspaceDataplane dataplane;
    Inbox inbox;

    bool start() {
        dataplane.set_inbound_handler(inbox.handler());
        return dataplane.start({keys.priv_b64, keys.pub_b64, /*listen_port=*/0,
                                /*rx_threads=*/2});
    }

    std::string loopback_endpoint() const {
        return "127.0.0.1:" + std::to_string(dataplane.bound_port());
    }
};

} // namespace

class UserspaceDataplaneTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() { ASSERT_GE(sodium_init(), 0); }
};

TEST_F(UserspaceDataplaneTest, TwoNodesHandshakeAndExchangePackets) {
    Node server, client;
    ASSERT_TRUE(server.start());
    ASSERT_TRUE(client.start());

    server.dataplane.add_local_ip(ip(10, 64, 0, 1));
    client.dataplane.add_local_ip(ip(10, 64, 0, 2));

    // Server learns the client's endpoint from rx (NATed-client pattern).
    ASSERT_TRUE(server.dataplane.add_peer(client.keys.pub_b64, "10.64.0.2/32", ""));
    // Client knows the server's endpoint and routes the whole plane to it.
    ASSERT_TRUE(client.dataplane.add_peer(server.keys.pub_b64, "10.64.0.0/10",
                                          server.loopback_endpoint()));

    // Client -> server.
    auto ping = make_ipv4(ip(10, 64, 0, 2), ip(10, 64, 0, 1), "ping-from-client");
    ASSERT_TRUE(send_until_received(client.dataplane, server.inbox, ping,
                                    "ping-from-client"))
        << "client->server packet never delivered";

    // Server -> client over the learned endpoint.
    auto pong = make_ipv4(ip(10, 64, 0, 1), ip(10, 64, 0, 2), "pong-from-server");
    ASSERT_TRUE(send_until_received(server.dataplane, client.inbox, pong,
                                    "pong-from-server"))
        << "server->client packet never delivered (endpoint not learned?)";

    // Stats reflect the established session.
    auto peers = server.dataplane.snapshot_peers();
    ASSERT_EQ(peers.size(), 1u);
    EXPECT_GT(peers[0].last_handshake, 0u);
    EXPECT_GT(peers[0].rx_bytes, 0u);
    EXPECT_FALSE(peers[0].endpoint.empty());

    client.dataplane.stop();
    server.dataplane.stop();
}

TEST_F(UserspaceDataplaneTest, HairpinRoutesClientToClientWithoutLocalDelivery) {
    Node server, alice, bob;
    ASSERT_TRUE(server.start());
    ASSERT_TRUE(alice.start());
    ASSERT_TRUE(bob.start());

    server.dataplane.add_local_ip(ip(10, 64, 0, 1));
    alice.dataplane.add_local_ip(ip(10, 64, 0, 2));
    bob.dataplane.add_local_ip(ip(10, 64, 0, 3));

    ASSERT_TRUE(server.dataplane.add_peer(alice.keys.pub_b64, "10.64.0.2/32", ""));
    ASSERT_TRUE(server.dataplane.add_peer(bob.keys.pub_b64, "10.64.0.3/32", ""));
    ASSERT_TRUE(alice.dataplane.add_peer(server.keys.pub_b64, "10.64.0.0/10",
                                         server.loopback_endpoint()));
    ASSERT_TRUE(bob.dataplane.add_peer(server.keys.pub_b64, "10.64.0.0/10",
                                       server.loopback_endpoint()));

    // Bob must have a session (and a learned endpoint at the server) before
    // hairpinned traffic can reach him.
    auto bob_hello = make_ipv4(ip(10, 64, 0, 3), ip(10, 64, 0, 1), "bob-hello");
    ASSERT_TRUE(send_until_received(bob.dataplane, server.inbox, bob_hello, "bob-hello"));

    // Alice -> Bob, relayed in userspace by the server.
    auto a_to_b = make_ipv4(ip(10, 64, 0, 2), ip(10, 64, 0, 3), "alice-to-bob");
    ASSERT_TRUE(send_until_received(alice.dataplane, bob.inbox, a_to_b, "alice-to-bob"))
        << "hairpin packet never reached bob";

    // The hairpinned packet must not have been delivered locally at the server.
    EXPECT_FALSE(server.inbox.contains("alice-to-bob"));

    alice.dataplane.stop();
    bob.dataplane.stop();
    server.dataplane.stop();
}

TEST_F(UserspaceDataplaneTest, SpoofedInnerSourceIsDropped) {
    Node server, alice;
    ASSERT_TRUE(server.start());
    ASSERT_TRUE(alice.start());

    server.dataplane.add_local_ip(ip(10, 64, 0, 1));
    ASSERT_TRUE(server.dataplane.add_peer(alice.keys.pub_b64, "10.64.0.2/32", ""));
    ASSERT_TRUE(alice.dataplane.add_peer(server.keys.pub_b64, "10.64.0.0/10",
                                         server.loopback_endpoint()));

    // Establish the session with a legitimate packet first.
    auto legit = make_ipv4(ip(10, 64, 0, 2), ip(10, 64, 0, 1), "legit-1");
    ASSERT_TRUE(send_until_received(alice.dataplane, server.inbox, legit, "legit-1"));

    // Alice forges a packet claiming to be 10.64.0.99 (not in her allowed IPs).
    auto spoofed = make_ipv4(ip(10, 64, 0, 99), ip(10, 64, 0, 1), "spoofed-evil");
    for (int i = 0; i < 20; ++i) {
        (void)alice.dataplane.send_outbound_ip_packet(spoofed);
        std::this_thread::sleep_for(10ms);
    }
    EXPECT_FALSE(server.inbox.contains("spoofed-evil"));

    // Legitimate traffic still flows afterwards.
    auto legit2 = make_ipv4(ip(10, 64, 0, 2), ip(10, 64, 0, 1), "legit-2");
    ASSERT_TRUE(send_until_received(alice.dataplane, server.inbox, legit2, "legit-2"));

    alice.dataplane.stop();
    server.dataplane.stop();
}

TEST_F(UserspaceDataplaneTest, RemovePeerMidTrafficStopsDelivery) {
    Node server, alice;
    ASSERT_TRUE(server.start());
    ASSERT_TRUE(alice.start());

    server.dataplane.add_local_ip(ip(10, 64, 0, 1));
    ASSERT_TRUE(server.dataplane.add_peer(alice.keys.pub_b64, "10.64.0.2/32", ""));
    ASSERT_TRUE(alice.dataplane.add_peer(server.keys.pub_b64, "10.64.0.0/10",
                                         server.loopback_endpoint()));

    auto before = make_ipv4(ip(10, 64, 0, 2), ip(10, 64, 0, 1), "before-removal");
    ASSERT_TRUE(send_until_received(alice.dataplane, server.inbox, before,
                                    "before-removal"));
    EXPECT_EQ(server.dataplane.peer_count(), 1u);

    ASSERT_TRUE(server.dataplane.remove_peer(alice.keys.pub_b64));
    EXPECT_EQ(server.dataplane.peer_count(), 0u);
    EXPECT_FALSE(server.dataplane.remove_peer(alice.keys.pub_b64));

    auto after = make_ipv4(ip(10, 64, 0, 2), ip(10, 64, 0, 1), "after-removal");
    for (int i = 0; i < 20; ++i) {
        (void)alice.dataplane.send_outbound_ip_packet(after);
        std::this_thread::sleep_for(10ms);
    }
    EXPECT_FALSE(server.inbox.contains("after-removal"));

    alice.dataplane.stop();
    server.dataplane.stop();
}

TEST_F(UserspaceDataplaneTest, ControlPlaneValidation) {
    Node node;
    ASSERT_TRUE(node.start());

    Keypair other = make_keypair();
    // Invalid pubkey / allowed IPs / endpoint.
    EXPECT_FALSE(node.dataplane.add_peer("not-base64!", "10.64.0.2/32", ""));
    EXPECT_FALSE(node.dataplane.add_peer(other.pub_b64, "banana", ""));
    EXPECT_FALSE(node.dataplane.add_peer(other.pub_b64, "10.64.0.2/32", "no-port"));
    EXPECT_FALSE(node.dataplane.add_peer(other.pub_b64, "10.64.0.2/32", "1.2.3.4:99999"));
    // Refuses self as a peer.
    EXPECT_FALSE(node.dataplane.add_peer(node.keys.pub_b64, "10.64.0.2/32", ""));
    // Unknown peer operations.
    EXPECT_FALSE(node.dataplane.update_endpoint(other.pub_b64, "127.0.0.1:1234"));
    EXPECT_FALSE(node.dataplane.remove_peer(other.pub_b64));
    // Valid add, then update.
    EXPECT_TRUE(node.dataplane.add_peer(other.pub_b64, "10.64.0.2/32", ""));
    EXPECT_TRUE(node.dataplane.has_peer(other.pub_b64));
    EXPECT_TRUE(node.dataplane.update_endpoint(other.pub_b64, "127.0.0.1:1234"));
    auto peers = node.dataplane.snapshot_peers();
    ASSERT_EQ(peers.size(), 1u);
    EXPECT_EQ(peers[0].endpoint, "127.0.0.1:1234");

    // Double start fails; stop is idempotent.
    EXPECT_FALSE(node.dataplane.start({node.keys.priv_b64, node.keys.pub_b64, 0, 1}));
    node.dataplane.stop();
    node.dataplane.stop();
}

// Retry-send over an identity session until the session sink sees the payload.
namespace {
bool send_session_until_received(UserspaceDataplane& from, const std::string& peer_pub,
                                 Inbox& to, const std::vector<uint8_t>& pkt,
                                 const std::string& needle,
                                 std::chrono::milliseconds timeout = 5000ms) {
    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        (void)from.send_on_session(peer_pub, pkt);
        if (to.wait_for_payload(needle, 100ms)) return true;
    }
    return false;
}
} // namespace

TEST_F(UserspaceDataplaneTest, IdentitySessionDeliversToSinkNotRouter) {
    Node a, b;
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(b.start());

    // Per-session sinks, independent of the node's global inbound handler and
    // with NO add_local_ip / add_peer — purely identity-keyed (no virtual IPs).
    Inbox sink_a, sink_b;
    ASSERT_TRUE(b.dataplane.add_identity_session(a.keys.pub_b64, "conn-1",
                /*endpoint=*/"", /*is_initiator=*/false, sink_b.handler()));
    ASSERT_TRUE(a.dataplane.add_identity_session(b.keys.pub_b64, "conn-1",
                b.loopback_endpoint(), /*is_initiator=*/true, sink_a.handler()));

    auto pkt = make_ipv4(ip(10, 0, 0, 1), ip(10, 0, 0, 2), "id-payload");
    EXPECT_TRUE(send_session_until_received(a.dataplane, b.keys.pub_b64, sink_b, pkt,
                                            "id-payload"))
        << "identity-session payload never delivered to the session sink";
    // It must NOT have gone through the cryptokey router / local handler.
    EXPECT_FALSE(b.inbox.contains("id-payload"));

    a.dataplane.stop();
    b.dataplane.stop();
}

TEST_F(UserspaceDataplaneTest, RemoveIdentitySessionRevokesDelivery) {
    Node a, b;
    ASSERT_TRUE(a.start());
    ASSERT_TRUE(b.start());

    Inbox sink_a, sink_b;
    ASSERT_TRUE(b.dataplane.add_identity_session(a.keys.pub_b64, "conn-2", "",
                false, sink_b.handler()));
    ASSERT_TRUE(a.dataplane.add_identity_session(b.keys.pub_b64, "conn-2",
                b.loopback_endpoint(), true, sink_a.handler()));

    auto first = make_ipv4(ip(10, 0, 0, 1), ip(10, 0, 0, 2), "before-revoke");
    ASSERT_TRUE(send_session_until_received(a.dataplane, b.keys.pub_b64, sink_b, first,
                                            "before-revoke"));

    // Revoke by removing the peer; further frames must not be delivered.
    ASSERT_TRUE(b.dataplane.remove_peer(a.keys.pub_b64));
    auto after = make_ipv4(ip(10, 0, 0, 1), ip(10, 0, 0, 2), "after-revoke");
    EXPECT_FALSE(send_session_until_received(a.dataplane, b.keys.pub_b64, sink_b, after,
                                             "after-revoke", 1500ms));

    a.dataplane.stop();
    b.dataplane.stop();
}
