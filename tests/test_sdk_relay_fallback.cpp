// Relay fallback end to end: two SDK mesh dataplanes with no direct path
// reach each other through a relay, using tickets a Tier 1 member signed.

#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Relay/RelayService.hpp>
#include <LemonadeNexus/Relay/RelayTicketAuth.hpp>
#include <LemonadeNexus/Relay/RelayWire.hpp>

#include <LemonadeNexusSDK/BoringtunMesh.hpp>
#include <LemonadeNexusSDK/RelayChannel.hpp>
#include <LemonadeNexusSDK/RelayFallback.hpp>

#include <asio.hpp>
#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>

using namespace nexus;
using namespace std::chrono_literals;

namespace {

uint64_t now_s() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                     std::chrono::system_clock::now().time_since_epoch())
                                     .count());
}

/// Wait until `done` is true or `timeout` passes, running `step` between checks.
template <typename Done, typename Step>
bool eventually(Done done, Step step, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        step();
        if (done()) return true;
        std::this_thread::sleep_for(100ms);
    }
    return done();
}

/// GET /ping on `mesh_ip`:8080 from `from`, through the mesh. Returns the body.
std::string ping_over_mesh(lnsdk::BoringtunMesh& from, const std::string& mesh_ip) {
    const uint16_t egress = from.tcp_egress(mesh_ip, 8080);
    if (egress == 0) return {};
    httplib::Client client("127.0.0.1", egress);
    client.set_connection_timeout(5, 0);
    client.set_read_timeout(5, 0);
    const auto deadline = std::chrono::steady_clock::now() + 20s;
    while (std::chrono::steady_clock::now() < deadline) {
        auto res = client.Get("/ping");
        if (res && res->status == 200) return res->body;
        std::this_thread::sleep_for(200ms);
    }
    return {};
}

}  // namespace

class SdkRelayFallbackTest : public ::testing::Test {
protected:
    asio::io_context io;
    std::unique_ptr<asio::executor_work_guard<asio::io_context::executor_type>> work;
    std::thread io_thread;
    std::unique_ptr<crypto::SodiumCryptoService> c;
    std::unique_ptr<relay::RelayService> r;
    crypto::Ed25519Keypair member;
    relay::RelayTicketAuthority authority;

    httplib::Server api;
    std::thread api_thread;
    int api_port{0};

    lnsdk::BoringtunMesh alice;  // 10.64.0.2, exposes the service
    lnsdk::BoringtunMesh bob;    // 10.64.0.3
    std::pair<std::string, std::string> alice_keys;
    std::pair<std::string, std::string> bob_keys;

    void SetUp() override {
        c = std::make_unique<crypto::SodiumCryptoService>();
        c->start();
        member = c->ed25519_keygen();
        authority.network_id.fill(0x5A);
        authority.epoch = 7;
        security::NodeId self;
        self.bytes = member.public_key;
        authority.members.push_back(self);

        // A Tier 2 relay: no tree, only the verified membership and its id.
        r = std::make_unique<relay::RelayService>(io, 0, *c);
        r->set_relay_id("relay-1");
        r->set_ticket_authority(
            [this]() -> std::optional<relay::RelayTicketAuthority> { return authority; });
        r->start();
        work = std::make_unique<asio::executor_work_guard<asio::io_context::executor_type>>(
            io.get_executor());
        io_thread = std::thread([this] { io.run(); });

        api.Get("/ping", [](const httplib::Request&, httplib::Response& res) {
            res.set_content("pong-through-relay", "text/plain");
        });
        api_port = api.bind_to_any_port("127.0.0.1");
        ASSERT_GT(api_port, 0);
        api_thread = std::thread([this] { api.listen_after_bind(); });

        alice_keys = lnsdk::BoringtunMesh::generate_keypair();
        bob_keys = lnsdk::BoringtunMesh::generate_keypair();
        lnsdk::BoringtunConfig acfg;
        acfg.private_key = alice_keys.first;
        acfg.public_key = alice_keys.second;
        acfg.tunnel_ip = "10.64.0.2/32";
        acfg.allowed_ips = {"10.64.0.0/10"};
        ASSERT_TRUE(alice.start(acfg));
        ASSERT_TRUE(alice.tcp_ingress(8080, "tcp:127.0.0.1:" + std::to_string(api_port)));
        lnsdk::BoringtunConfig bcfg;
        bcfg.private_key = bob_keys.first;
        bcfg.public_key = bob_keys.second;
        bcfg.tunnel_ip = "10.64.0.3/32";
        bcfg.allowed_ips = {"10.64.0.0/10"};
        ASSERT_TRUE(bob.start(bcfg));

        // Each side knows the other from the server's peer list, with no
        // direct endpoint: neither can reach the other without a relay.
        ASSERT_TRUE(alice.sync_peers({peer(bob_keys.second, "10.64.0.3/32")}).ok);
        ASSERT_TRUE(bob.sync_peers({peer(alice_keys.second, "10.64.0.2/32")}).ok);
    }

    void TearDown() override {
        bob.stop();
        alice.stop();
        api.stop();
        if (api_thread.joinable()) api_thread.join();
        if (r) r->stop();
        work.reset();
        io.stop();
        if (io_thread.joinable()) io_thread.join();
        if (c) c->stop();
    }

    static lnsdk::MeshPeer peer(const std::string& pubkey, const std::string& tunnel_ip) {
        lnsdk::MeshPeer p;
        p.mesh_pubkey = pubkey;
        p.tunnel_ip = tunnel_ip;
        p.keepalive = 1;
        return p;
    }

    /// A ticket for `holder` naming `relay_id`, as POST /api/relay/ticket
    /// returns it to the SDK.
    lnsdk::RelayTicket sdk_ticket(const std::string& holder, const std::string& relay_id) {
        relay::RelayTicket t;
        t.peer_id = holder;
        t.relay_id = relay_id;
        c->random_bytes(std::span<uint8_t>(t.session_nonce));
        t.issued_at = now_s();
        t.expires_at = t.issued_at + relay::kRelayTicketMaxLifetimeSec;
        t.network_id = authority.network_id;
        t.epoch = authority.epoch.underlying();
        relay::sign_relay_ticket(t, member);
        const auto j = nlohmann::json::parse(relay::relay_ticket_to_json(t));
        lnsdk::RelayTicket out;
        out.peer_id = j["peer_id"];
        out.relay_id = j["relay_id"];
        out.session_nonce = j["session_nonce"];
        out.issued_at = j["issued_at"];
        out.expires_at = j["expires_at"];
        out.network_id = j["network_id"];
        out.epoch = j["epoch"];
        out.issuer = j["issuer"];
        out.signature = j["signature"];
        return out;
    }

    static lnsdk::RelayFallback::Timing fast_timing() {
        lnsdk::RelayFallback::Timing t;
        t.backoff_base = 200ms;
        t.backoff_max = 1s;
        t.allocate_retry = 200ms;
        t.heartbeat_interval = 1s;
        t.pending_limit = 10s;
        t.candidate_ttl = 0ms;
        return t;
    }
};

TEST_F(SdkRelayFallbackTest, SelectionIsSymmetricAndIgnoresOrder) {
    const std::vector<std::string> ids = {"relay-a", "relay-b", "relay-c", "relay-d"};
    const auto ab = lnsdk::select_relay_for_pair(ids, "key-1", "key-2");
    const auto ba = lnsdk::select_relay_for_pair(ids, "key-2", "key-1");
    ASSERT_TRUE(ab && ba);
    EXPECT_EQ(ids[*ab], ids[*ba]);
    auto reversed = ids;
    std::reverse(reversed.begin(), reversed.end());
    EXPECT_EQ(reversed[*lnsdk::select_relay_for_pair(reversed, "key-1", "key-2")], ids[*ab]);
    // Removing another relay does not move the choice.
    std::vector<std::string> fewer;
    for (const auto& id : ids) {
        if (id == ids[*ab] || fewer.empty()) fewer.push_back(id);
    }
    EXPECT_EQ(fewer[*lnsdk::select_relay_for_pair(fewer, "key-1", "key-2")], ids[*ab]);
    EXPECT_FALSE(lnsdk::select_relay_for_pair({}, "key-1", "key-2"));
}

TEST_F(SdkRelayFallbackTest, RelayIsNeededOnlyWithoutAWorkingDirectPath) {
    using F = lnsdk::RelayFallback;
    const F::Timing t;
    const int64_t now = 1'000'000;
    // No direct endpoint: relay at once.
    EXPECT_TRUE(F::relay_needed(false, 0, now, 0ms, true, t));
    // A fresh handshake is a working path.
    EXPECT_FALSE(F::relay_needed(false, now - 10, now, 0ms, true, t));
    // A direct endpoint gets the short grace period, then falls back.
    EXPECT_EQ(t.direct_grace, lnsdk::kDirectAnswerWindow);
    EXPECT_FALSE(F::relay_needed(true, 0, now, 1s, true, t));
    EXPECT_TRUE(F::relay_needed(true, 0, now, t.direct_grace, true, t));
    EXPECT_TRUE(F::relay_needed(true, now - t.handshake_fresh_sec - 1, now, 60s, true, t));
    // Without prefer_direct, always relay.
    EXPECT_TRUE(F::relay_needed(true, now - 10, now, 0ms, false, t));
}

// A working relay stays: once it carried traffic, a pass that reads no
// handshake (an idle session renegotiating after REJECT_AFTER_TIME) or only
// keepalives (a session that predates the pairing) keeps it. Re-allocating
// then blamed a working relay, and the two sides chose different relays.
TEST_F(SdkRelayFallbackTest, AWorkingRelayIsKeptWhileItsSessionRenegotiates) {
    using F = lnsdk::RelayFallback;
    using A = F::PairedAction;
    const F::Timing t;
    const int64_t now = 1'000'000;
    // Paired, nothing yet: wait for the grace period, then blame the relay.
    EXPECT_EQ(F::paired_action(0, 0, now, 5s, false, t), A::Wait);
    EXPECT_EQ(F::paired_action(0, 0, now, t.handshake_grace + 1s, false, t), A::AbandonUnproven);
    // Keepalives through the relay prove it without a new handshake.
    EXPECT_EQ(F::paired_action(now - 2, 0, now, 90s, false, t), A::Working);
    // A handshake seen 179 s ago, and the dataplane reads none now while the
    // session renegotiates: the relay is kept.
    EXPECT_EQ(F::paired_action(now - 179, 0, now, 600s, false, t), A::Working);
    EXPECT_EQ(F::paired_action(now - 200, 0, now, 600s, false, t), A::Working);
    // Nothing through the relay for longer than the session lifetime and the
    // grace period: abandon it without blame.
    const int64_t grace = std::chrono::duration_cast<std::chrono::seconds>(t.handshake_grace).count();
    EXPECT_EQ(F::paired_action(now - t.handshake_fresh_sec - grace - 1, 0, now, 600s, false, t),
              A::AbandonStale);
    // A direct path that answered with a fresh handshake replaces the relay.
    EXPECT_EQ(F::paired_action(now - 2, now - 1, now, 60s, true, t), A::PromoteDirect);
    EXPECT_EQ(F::paired_action(now - 2, 0, now, 60s, true, t), A::Working);
}

TEST_F(SdkRelayFallbackTest, BothRendezvousSidesMatch) {
    const auto window = relay::relay_rendezvous_window(now_s());
    const auto a = alice.relay_rendezvous(bob_keys.second, "relay-1", window);
    const auto b = bob.relay_rendezvous(alice_keys.second, "relay-1", window);
    ASSERT_TRUE(a && b);
    EXPECT_TRUE(std::equal(a->begin(), a->begin() + 16, b->begin()));  // same id
    relay::RelayProof a_proof{}, b_proof{};
    std::copy(a->begin() + 16, a->begin() + 32, a_proof.begin());
    std::copy(b->begin() + 16, b->begin() + 32, b_proof.begin());
    const auto a_commit = relay::relay_proof_commitment(a_proof);
    const auto b_commit = relay::relay_proof_commitment(b_proof);
    EXPECT_TRUE(std::equal(b_commit.begin(), b_commit.end(), a->begin() + 32));
    EXPECT_TRUE(std::equal(a_commit.begin(), a_commit.end(), b->begin() + 32));
    EXPECT_FALSE(alice.relay_rendezvous("not-a-key", "relay-1", window));
}

TEST_F(SdkRelayFallbackTest, ChannelsCarryTheDataplaneThroughTheRelay) {
    const auto window = relay::relay_rendezvous_window(now_s());
    const auto open = [&](lnsdk::BoringtunMesh& self, const std::string& peer_key,
                          const std::string& holder, lnsdk::RelayChannel& channel) {
        const auto rv = self.relay_rendezvous(peer_key, "relay-1", window);
        ASSERT_TRUE(rv.has_value());
        lnsdk::RelayChannel::Options options;
        options.relay_ipv4 = "127.0.0.1";
        options.relay_port = r->local_port();
        options.dataplane_port = self.bound_port();
        options.allocate = lnsdk::relay_allocate_datagram(*rv, sdk_ticket(holder, "relay-1"), 1);
        options.allocate_retry = 200ms;
        ASSERT_TRUE(channel.open(std::move(options)));
    };
    lnsdk::RelayChannel alice_channel, bob_channel;
    open(alice, bob_keys.second, "alice", alice_channel);
    open(bob, alice_keys.second, "bob", bob_channel);

    ASSERT_TRUE(eventually(
        [&] {
            return alice_channel.state() == lnsdk::RelayChannel::State::Paired &&
                   bob_channel.state() == lnsdk::RelayChannel::State::Paired;
        },
        [] {}, 5s));
    ASSERT_TRUE(alice.set_peer_relay(bob_keys.second, alice_channel.local_endpoint(),
                                     alice_channel.relay_endpoint()));
    ASSERT_TRUE(bob.set_peer_relay(alice_keys.second, bob_channel.local_endpoint(),
                                   bob_channel.relay_endpoint()));

    EXPECT_EQ(ping_over_mesh(bob, "10.64.0.2"), "pong-through-relay");
    EXPECT_EQ(r->session_count(), 1u);

    // The status reports the relay, not the local shim.
    const auto status = bob.mesh_status();
    ASSERT_EQ(status.peers.size(), 1u);
    EXPECT_EQ(status.peers[0].relay_endpoint,
              "127.0.0.1:" + std::to_string(r->local_port()));
    EXPECT_TRUE(status.peers[0].endpoint.empty());
    EXPECT_GT(status.peers[0].last_handshake, 0);

    // Closing a channel tears the relay session down.
    alice_channel.close();
    bob_channel.close();
    EXPECT_TRUE(eventually([&] { return r->session_count() == 0; }, [] {}, 2s));
}

TEST_F(SdkRelayFallbackTest, FallbackMovesUnreachablePeersOntoTheRelay) {
    const auto candidates = [this] {
        return std::vector<lnsdk::RelayCandidate>{{"relay-1", "127.0.0.1", r->local_port()}};
    };
    lnsdk::RelayFallback alice_fallback(
        alice, [&](const std::string& relay_id) {
            return lnsdk::Result<lnsdk::RelayTicket>{true, sdk_ticket("alice", relay_id), 200, ""};
        },
        candidates, fast_timing());
    lnsdk::RelayFallback bob_fallback(
        bob, [&](const std::string& relay_id) {
            return lnsdk::Result<lnsdk::RelayTicket>{true, sdk_ticket("bob", relay_id), 200, ""};
        },
        candidates, fast_timing());
    const std::vector<lnsdk::MeshPeer> alice_peers = {peer(bob_keys.second, "10.64.0.3/32")};
    const std::vector<lnsdk::MeshPeer> bob_peers = {peer(alice_keys.second, "10.64.0.2/32")};

    ASSERT_TRUE(eventually(
        [&] {
            return alice_fallback.relayed_peers().contains(bob_keys.second) &&
                   bob_fallback.relayed_peers().contains(alice_keys.second);
        },
        [&] {
            alice_fallback.maintain(alice_peers, true);
            bob_fallback.maintain(bob_peers, true);
        },
        10s));
    EXPECT_EQ(bob_fallback.relayed_peers().at(alice_keys.second),
              "127.0.0.1:" + std::to_string(r->local_port()));

    EXPECT_EQ(ping_over_mesh(bob, "10.64.0.2"), "pong-through-relay");

    // A further pass keeps the working relay path.
    alice_fallback.maintain(alice_peers, true);
    bob_fallback.maintain(bob_peers, true);
    EXPECT_TRUE(bob_fallback.relayed_peers().contains(alice_keys.second));
    EXPECT_EQ(r->session_count(), 1u);

    // A renewal (the peer moved, or this device resumed) keeps a relay that
    // carries traffic: only paired_action ends a paired channel.
    bob_fallback.renew({alice_keys.second}, true);
    alice_fallback.renew({bob_keys.second}, false);
    for (int i = 0; i < 5; ++i) {
        alice_fallback.maintain(alice_peers, true);
        bob_fallback.maintain(bob_peers, true);
        std::this_thread::sleep_for(100ms);
    }
    EXPECT_TRUE(bob_fallback.relayed_peers().contains(alice_keys.second));
    EXPECT_TRUE(alice_fallback.relayed_peers().contains(bob_keys.second));
    EXPECT_EQ(r->session_count(), 1u);
    EXPECT_EQ(ping_over_mesh(bob, "10.64.0.2"), "pong-through-relay");

    // A peer the server stops listing loses its relay path and session.
    bob_fallback.maintain({}, true);
    alice_fallback.maintain({}, true);
    EXPECT_TRUE(bob_fallback.relayed_peers().empty());
    EXPECT_TRUE(eventually([&] { return r->session_count() == 0; }, [] {}, 2s));
}

TEST_F(SdkRelayFallbackTest, ARefusingRelayIsSkippedForTheNextOne) {
    // First only a relay entry whose ticket names a relay id the relay does
    // not have: the relay refuses it. Then the real one appears too.
    std::mutex mtx;
    std::vector<lnsdk::RelayCandidate> list = {{"relay-wrong", "127.0.0.1", r->local_port()}};
    const auto candidates = [&] {
        std::lock_guard lock(mtx);
        return list;
    };
    std::atomic<int> tickets{0};
    const auto issuer = [&](const std::string& holder) {
        return [&, holder](const std::string& relay_id) {
            ++tickets;
            return lnsdk::Result<lnsdk::RelayTicket>{true, sdk_ticket(holder, relay_id), 200, ""};
        };
    };
    lnsdk::RelayFallback alice_fallback(alice, issuer("alice"), candidates, fast_timing());
    lnsdk::RelayFallback bob_fallback(bob, issuer("bob"), candidates, fast_timing());
    const std::vector<lnsdk::MeshPeer> alice_peers = {peer(bob_keys.second, "10.64.0.3/32")};
    const std::vector<lnsdk::MeshPeer> bob_peers = {peer(alice_keys.second, "10.64.0.2/32")};
    const auto pass = [&] {
        alice_fallback.maintain(alice_peers, true);
        bob_fallback.maintain(bob_peers, true);
    };

    for (int i = 0; i < 15; ++i) {
        pass();
        std::this_thread::sleep_for(100ms);
    }
    EXPECT_GE(tickets.load(), 2);
    EXPECT_TRUE(alice_fallback.relayed_peers().empty());
    EXPECT_EQ(r->session_count(), 0u);

    {
        std::lock_guard lock(mtx);
        list.push_back({"relay-1", "127.0.0.1", r->local_port()});
    }
    ASSERT_TRUE(eventually(
        [&] {
            return alice_fallback.relayed_peers().contains(bob_keys.second) &&
                   bob_fallback.relayed_peers().contains(alice_keys.second);
        },
        pass, 15s));
    EXPECT_EQ(ping_over_mesh(bob, "10.64.0.2"), "pong-through-relay");
}

TEST_F(SdkRelayFallbackTest, NoTicketMeansNoChannelAndBackoff) {
    std::atomic<int> requests{0};
    lnsdk::RelayFallback::Timing timing = fast_timing();
    timing.backoff_base = 10s;
    lnsdk::RelayFallback fallback(
        bob,
        [&](const std::string&) {
            ++requests;
            return lnsdk::Result<lnsdk::RelayTicket>{false, {}, 421, "not a Tier 1 member"};
        },
        [&] { return std::vector<lnsdk::RelayCandidate>{{"relay-1", "127.0.0.1", r->local_port()}}; },
        timing);
    const std::vector<lnsdk::MeshPeer> peers = {peer(alice_keys.second, "10.64.0.2/32")};
    for (int i = 0; i < 5; ++i) fallback.maintain(peers, true);
    EXPECT_EQ(requests.load(), 1);  // retried only after the backoff
    EXPECT_TRUE(fallback.relayed_peers().empty());
    EXPECT_EQ(r->session_count(), 0u);
}

// A renewal with skip_grace lets a peer with a listed endpoint ask for a
// relay at the next pass; without it the grace period starts again.
TEST_F(SdkRelayFallbackTest, ARenewalCanSkipTheDirectGracePeriod) {
    std::atomic<int> requests{0};
    lnsdk::RelayFallback::Timing timing = fast_timing();
    timing.direct_grace = 60s;  // nothing ends the grace period by itself here
    timing.backoff_base = 60s;
    lnsdk::RelayFallback fallback(
        bob,
        [&](const std::string&) {
            ++requests;
            return lnsdk::Result<lnsdk::RelayTicket>{false, {}, 503, "unavailable"};
        },
        [&] { return std::vector<lnsdk::RelayCandidate>{{"relay-1", "127.0.0.1", r->local_port()}}; },
        timing);
    auto listed = peer(alice_keys.second, "10.64.0.2/32");
    listed.endpoint = "127.0.0.1:9";
    const std::vector<lnsdk::MeshPeer> peers = {listed};

    for (int i = 0; i < 3; ++i) fallback.maintain(peers, true);
    EXPECT_EQ(requests.load(), 0) << "a relay was requested within the grace period";

    fallback.renew({alice_keys.second}, false);
    fallback.maintain(peers, true);
    EXPECT_EQ(requests.load(), 0);

    fallback.renew({alice_keys.second}, true);
    fallback.maintain(peers, true);
    EXPECT_EQ(requests.load(), 1);

    // The failed request set a 60 s retry delay. A renewal ends it: the
    // peer's path changed since.
    fallback.maintain(peers, true);
    EXPECT_EQ(requests.load(), 1);
    fallback.renew({alice_keys.second}, true);
    fallback.maintain(peers, true);
    EXPECT_EQ(requests.load(), 2);
}

// maintain() reports when it needs the next pass: at the end of a peer's
// grace period, soon while a channel is being set up, and otherwise at the
// latest kMaxPassGap ahead.
TEST_F(SdkRelayFallbackTest, TheNextPassComesWhenTheGracePeriodEnds) {
    using F = lnsdk::RelayFallback;
    lnsdk::RelayFallback::Timing timing = fast_timing();
    timing.direct_grace = 1500ms;
    lnsdk::RelayFallback fallback(
        bob, [&](const std::string& relay_id) {
            return lnsdk::Result<lnsdk::RelayTicket>{true, sdk_ticket("bob", relay_id), 200, ""};
        },
        [&] { return std::vector<lnsdk::RelayCandidate>{{"relay-1", "127.0.0.1", r->local_port()}}; },
        timing);
    auto listed = peer(alice_keys.second, "10.64.0.2/32");
    listed.endpoint = "127.0.0.1:9";

    auto before = std::chrono::steady_clock::now();
    auto next = fallback.maintain({listed}, true);
    EXPECT_GE(next, before + timing.direct_grace - 100ms);
    EXPECT_LE(next, before + timing.direct_grace + 100ms);

    std::this_thread::sleep_until(next);
    before = std::chrono::steady_clock::now();
    next = fallback.maintain({listed}, true);  // opens a channel
    EXPECT_LE(next, before + F::kPendingPassGap + 50ms);

    before = std::chrono::steady_clock::now();
    next = fallback.maintain({}, true);
    EXPECT_GE(next, before + F::kMaxPassGap - 50ms);
    EXPECT_LE(next, before + F::kMaxPassGap + 50ms);
}
