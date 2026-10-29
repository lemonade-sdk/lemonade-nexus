// Direct paths for the SDK mesh dataplane: reflexive-address learning over
// the dataplane socket, hole-punch probes, and the move from a relay back to
// a direct path.

#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Network/StunService.hpp>
#include <LemonadeNexus/Network/StunWire.hpp>
#include <LemonadeNexus/Relay/RelayService.hpp>
#include <LemonadeNexus/Relay/RelayTicketAuth.hpp>

#include <LemonadeNexusSDK/BoringtunMesh.hpp>
#include <LemonadeNexusSDK/HolePunch.hpp>
#include <LemonadeNexusSDK/MeshOrchestrator.hpp>
#include <LemonadeNexusSDK/RelayFallback.hpp>

#include <asio.hpp>
#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <array>
#include <atomic>
#include <chrono>
#include <map>
#include <thread>

using namespace nexus;
using namespace std::chrono_literals;
namespace stun = nexus::network::stun;

namespace {

uint64_t now_s() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                     std::chrono::system_clock::now().time_since_epoch())
                                     .count());
}

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

stun::TransactionId txn_of(uint8_t seed) {
    stun::TransactionId txn{};
    for (std::size_t i = 0; i < txn.size(); ++i) txn[i] = static_cast<uint8_t>(seed + i);
    return txn;
}

/// A STUN responder that can misbehave in the ways a hostile or broken
/// network can.
class FakeStun {
public:
    enum class Mode {
        Correct,           ///< A valid answer.
        WrongTransaction,  ///< A valid answer for another transaction id.
        Overrun,           ///< An attribute length that runs past the message.
        Ipv6Family,        ///< XOR-MAPPED-ADDRESS with the IPv6 family code.
        OtherSource,       ///< A valid answer sent from another socket.
        Silent,            ///< No answer.
    };

    explicit FakeStun(asio::io_context& io)
        : socket_(io, asio::ip::udp::endpoint(asio::ip::address_v4::loopback(), 0)),
          other_(io, asio::ip::udp::endpoint(asio::ip::address_v4::loopback(), 0)) {
        receive();
    }

    [[nodiscard]] std::string endpoint() const {
        return "127.0.0.1:" + std::to_string(socket_.local_endpoint().port());
    }

    std::atomic<Mode> mode{Mode::Correct};
    std::atomic<int>  requests{0};

private:
    void receive() {
        socket_.async_receive_from(asio::buffer(buf_), from_,
                                   [this](const asio::error_code& ec, std::size_t n) {
                                       if (ec) return;
                                       handle({buf_.data(), n});
                                       receive();
                                   });
    }

    void handle(std::span<const uint8_t> request) {
        if (stun::message_type(request) != stun::kBindingRequest) return;
        ++requests;
        stun::TransactionId txn{};
        std::copy(request.begin() + 8, request.begin() + 20, txn.begin());
        const stun::MappedAddress mapped{from_.address().to_v4().to_uint(), from_.port()};
        auto reply = stun::encode_binding_response(txn, mapped);
        asio::error_code ec;
        switch (mode.load()) {
            case Mode::Correct:
                break;
            case Mode::WrongTransaction:
                txn[0] ^= 0xFF;
                reply = stun::encode_binding_response(txn, mapped);
                break;
            case Mode::Overrun:
                reply[22] = 0x00;
                reply[23] = 0x40;  // attribute length 64 in a 12-byte body
                break;
            case Mode::Ipv6Family:
                reply[25] = 0x02;
                break;
            case Mode::OtherSource:
                other_.send_to(asio::buffer(reply), from_, 0, ec);
                return;
            case Mode::Silent:
                return;
        }
        socket_.send_to(asio::buffer(reply), from_, 0, ec);
    }

    asio::ip::udp::socket   socket_;
    asio::ip::udp::socket   other_;
    asio::ip::udp::endpoint from_;
    std::array<uint8_t, 1500> buf_{};
};

}  // namespace

// ---------------------------------------------------------------------------
// STUN codec
// ---------------------------------------------------------------------------

TEST(StunWire, RequestAndResponseRoundTrip) {
    const auto txn = txn_of(1);
    const auto request = stun::encode_binding_request(txn);
    ASSERT_EQ(request.size(), stun::kHeaderSize);
    EXPECT_TRUE(stun::is_stun_message(request));
    EXPECT_EQ(stun::message_type(request), stun::kBindingRequest);

    const stun::MappedAddress mapped{0xCB007109, 51940};  // 203.0.113.9
    const auto response = stun::encode_binding_response(txn, mapped);
    ASSERT_EQ(response.size(), 32u);
    const auto decoded = stun::decode_binding_response(response, txn);
    ASSERT_TRUE(decoded);
    EXPECT_EQ(decoded->ipv4, mapped.ipv4);
    EXPECT_EQ(decoded->port, mapped.port);
    // The address travels XORed with the magic cookie, never in clear.
    EXPECT_NE(response[28], 0xCB);
}

TEST(StunWire, MalformedOrForeignResponsesAreRejected) {
    const auto txn = txn_of(7);
    const auto good = stun::encode_binding_response(txn, {0x08080808, 4000});

    EXPECT_FALSE(stun::decode_binding_response(good, txn_of(8)));  // wrong transaction id

    auto truncated = good;
    truncated.resize(28);
    EXPECT_FALSE(stun::is_stun_message(truncated));  // length field disagrees
    EXPECT_FALSE(stun::decode_binding_response(truncated, txn));

    auto no_cookie = good;
    no_cookie[4] ^= 0x01;
    EXPECT_FALSE(stun::decode_binding_response(no_cookie, txn));

    auto overrun = good;
    overrun[23] = 0x40;
    EXPECT_FALSE(stun::decode_binding_response(overrun, txn));

    auto ipv6 = good;
    ipv6[25] = 0x02;
    EXPECT_FALSE(stun::decode_binding_response(ipv6, txn));

    auto zero_port = stun::encode_binding_response(txn, {0x08080808, 0});
    EXPECT_FALSE(stun::decode_binding_response(zero_port, txn));

    // A request is not a response.
    EXPECT_FALSE(stun::decode_binding_response(stun::encode_binding_request(txn), txn));

    // A response without XOR-MAPPED-ADDRESS (another attribute only).
    auto other_attr = good;
    other_attr[21] = 0x01;  // MAPPED-ADDRESS, which this codec does not trust
    EXPECT_FALSE(stun::decode_binding_response(other_attr, txn));
}

TEST(StunWire, BoringTunDatagramsAreNeverTakenForStun) {
    // Every BoringTun message starts with a little-endian type of 1 to 4 and
    // three zero bytes. Put the STUN cookie where a STUN header has it.
    for (const std::size_t size : {148u, 92u, 64u, 32u, 200u}) {
        std::vector<uint8_t> datagram(size, 0);
        datagram[0] = size == 148 ? 1 : size == 92 ? 2 : size == 64 ? 3 : 4;
        datagram[4] = 0x21;
        datagram[5] = 0x12;
        datagram[6] = 0xA4;
        datagram[7] = 0x42;
        EXPECT_FALSE(stun::is_stun_message(datagram)) << size;
    }
}

// ---------------------------------------------------------------------------
// Address scope and endpoint checks
// ---------------------------------------------------------------------------

TEST(HolePunchScope, EndpointScopes) {
    using lnsdk::AddressScope;
    using lnsdk::endpoint_scope;
    EXPECT_EQ(endpoint_scope("203.0.113.9:51940"), AddressScope::Public);
    EXPECT_EQ(endpoint_scope("10.1.2.3:5"), AddressScope::Private);
    EXPECT_EQ(endpoint_scope("172.20.0.1:5"), AddressScope::Private);
    EXPECT_EQ(endpoint_scope("192.168.1.1:5"), AddressScope::Private);
    EXPECT_EQ(endpoint_scope("100.64.0.1:5"), AddressScope::Private);
    EXPECT_EQ(endpoint_scope("172.32.0.1:5"), AddressScope::Public);
    EXPECT_EQ(endpoint_scope("127.0.0.1:5"), AddressScope::Loopback);
    // Bogus endpoints a server could list.
    for (const char* bad : {"0.0.0.0:5", "169.254.1.1:5", "224.0.0.1:5", "255.255.255.255:5",
                            "240.0.0.1:5", "1.2.3.4:0", "1.2.3.4:65536", "1.2.3.4", "1.2.3:4",
                            "256.1.1.1:5", "1.2.3.4:5:6", "[::1]:5", "host.example:5", "",
                            "01234.1.1.1:5", "1.2.3.4:+5", " 1.2.3.4:5", "1.2.3.4:123456"}) {
        EXPECT_EQ(endpoint_scope(bad), AddressScope::Invalid) << bad;
    }
}

TEST(HolePunchScope, ReflexiveAddressMustFitTheStunServerScope) {
    using lnsdk::reflexive_publishable;
    EXPECT_TRUE(reflexive_publishable("203.0.113.9:4000", "198.51.100.1"));
    EXPECT_TRUE(reflexive_publishable("203.0.113.9:4000", "10.0.0.1"));
    // A public STUN server cannot observe a private or loopback source.
    EXPECT_FALSE(reflexive_publishable("10.0.0.5:4000", "198.51.100.1"));
    EXPECT_FALSE(reflexive_publishable("127.0.0.1:4000", "198.51.100.1"));
    EXPECT_TRUE(reflexive_publishable("10.0.0.5:4000", "10.0.0.1"));
    EXPECT_FALSE(reflexive_publishable("127.0.0.1:4000", "10.0.0.1"));
    EXPECT_TRUE(reflexive_publishable("127.0.0.1:4000", "127.0.0.1"));
    EXPECT_FALSE(reflexive_publishable("0.0.0.0:4000", "127.0.0.1"));
    EXPECT_FALSE(reflexive_publishable("224.0.0.1:4000", "127.0.0.1"));
}

TEST(HolePunchScope, ListedPeerEndpointsAreChecked) {
    using lnsdk::AddressScope;
    using lnsdk::peer_endpoint_usable;
    EXPECT_TRUE(peer_endpoint_usable("203.0.113.9:51940", AddressScope::Public));
    EXPECT_TRUE(peer_endpoint_usable("192.168.1.9:51940", AddressScope::Public));
    // Loopback aims probes at local services unless the deployment is local.
    EXPECT_FALSE(peer_endpoint_usable("127.0.0.1:22", AddressScope::Public));
    EXPECT_FALSE(peer_endpoint_usable("127.0.0.1:22", AddressScope::Invalid));
    EXPECT_TRUE(peer_endpoint_usable("127.0.0.1:22", AddressScope::Loopback));
    EXPECT_FALSE(peer_endpoint_usable("0.0.0.0:51940", AddressScope::Loopback));
    EXPECT_FALSE(peer_endpoint_usable("evil.example:51940", AddressScope::Public));
}

// ---------------------------------------------------------------------------
// Path selection and the punch schedule
// ---------------------------------------------------------------------------

TEST(HolePuncherSchedule, PathSelection) {
    using P = lnsdk::HolePuncher;
    const P::Timing t;
    const int64_t now = 1'000'000;
    // No listed endpoint: nothing to punch; the relay fallback decides.
    EXPECT_EQ(P::punch_mode(false, false, 0, now, true, t), P::Mode::Idle);
    EXPECT_EQ(P::punch_mode(false, true, 0, now, true, t), P::Mode::Idle);
    // A listed endpoint without a working session: punch.
    EXPECT_EQ(P::punch_mode(true, false, 0, now, true, t), P::Mode::Direct);
    EXPECT_EQ(P::punch_mode(true, false, now - t.handshake_fresh_sec, now, true, t),
              P::Mode::Direct);
    // A fresh handshake on the direct path: done.
    EXPECT_EQ(P::punch_mode(true, false, now - 10, now, true, t), P::Mode::Idle);
    // Relayed: try to upgrade only with prefer_direct.
    EXPECT_EQ(P::punch_mode(true, true, now - 10, now, true, t), P::Mode::Upgrade);
    EXPECT_EQ(P::punch_mode(true, true, now - 10, now, false, t), P::Mode::Idle);
    // Without prefer_direct a peer that has not fallen back still punches.
    EXPECT_EQ(P::punch_mode(true, false, 0, now, false, t), P::Mode::Direct);

    // And the relay fallback keeps the short direct grace period for a peer
    // that has a listed endpoint, so the first punch burst goes out first.
    using F = lnsdk::RelayFallback;
    const F::Timing ft;
    EXPECT_FALSE(F::relay_needed(true, 0, now, 1s, true, ft));
    EXPECT_TRUE(F::relay_needed(true, 0, now, lnsdk::kDirectAnswerWindow, true, ft));
    EXPECT_TRUE(F::relay_needed(false, 0, now, 0ms, true, ft));
}

// ---------------------------------------------------------------------------
// Peer liveness (MeshOrchestrator monitor pass)
// ---------------------------------------------------------------------------

namespace {

/// Runs monitor passes every 5 s from `from` to `to` and reports whether the
/// peer read online on every pass. `update` sets the peer's signals for the
/// pass time.
template <typename Update>
bool online_throughout(lnsdk::MeshPeer& peer, int64_t from, int64_t to, Update update) {
    lnsdk::PeerLiveness state{true, 0};
    for (int64_t now = from; now <= to; now += 5) {
        update(peer, now);
        const auto fresh = lnsdk::peer_signal_fresh(peer, now, 30);
        if (fresh) state = lnsdk::next_peer_liveness(state, *fresh);
        if (!state.online) return false;
    }
    return true;
}

}  // namespace

// A relayed peer renews its WireGuard handshake only every 60-120 s while its
// keepalives arrive every 5 s through the relay: it stays online.
TEST(SdkPeerLiveness, ARelayedPeerBetweenHandshakesStaysOnline) {
    const int64_t start = 1'000'000;
    lnsdk::MeshPeer peer;
    peer.keepalive = 5;
    peer.relay_endpoint = "198.51.100.7:9103";
    EXPECT_TRUE(online_throughout(peer, start, start + 600, [&](lnsdk::MeshPeer& p, int64_t now) {
        p.last_rx = now - 3;
        // Handshakes at start, +60, +180, +300, ...: 60 then 120 s apart.
        if (now - start == 60 || (now - start >= 180 && (now - start - 180) % 120 == 0)) {
            p.last_handshake = now;
        }
        if (p.last_handshake == 0) p.last_handshake = start;
    }));

    // Before its first packet arrives, a live session keeps it online too.
    lnsdk::MeshPeer quiet;
    quiet.relay_endpoint = "198.51.100.7:9103";
    EXPECT_TRUE(online_throughout(quiet, start, start + 600, [&](lnsdk::MeshPeer& p, int64_t now) {
        if (p.last_handshake == 0 || now - p.last_handshake >= 120) p.last_handshake = now - 2;
    }));
}

// One late keepalive (a single stale pass) does not flip an online peer; a
// second stale pass in a row does.
TEST(SdkPeerLiveness, OneStalePassDoesNotFlipAPeer) {
    using lnsdk::next_peer_liveness;
    auto state = next_peer_liveness({false, 0}, true);
    EXPECT_TRUE(state.online);
    state = next_peer_liveness(state, false);
    EXPECT_TRUE(state.online) << "one stale pass flipped the peer offline";
    state = next_peer_liveness(state, true);
    EXPECT_TRUE(state.online);
    EXPECT_EQ(state.stale_passes, 0u);
    state = next_peer_liveness(state, false);
    state = next_peer_liveness(state, false);
    EXPECT_FALSE(state.online);
    // An offline peer comes back on its first fresh signal.
    EXPECT_TRUE(next_peer_liveness(state, true).online);
    EXPECT_FALSE(next_peer_liveness(state, false).online);
}

// A peer silent for more than 180 s (no packet, no handshake, no server
// contact) reads offline; a peer with no signal at all is left as it was.
TEST(SdkPeerLiveness, APeerSilentForOver180SecondsGoesOffline) {
    const int64_t start = 1'000'000;
    lnsdk::MeshPeer peer;
    peer.keepalive = 5;
    peer.relay_endpoint = "198.51.100.7:9103";
    peer.last_rx = start;
    peer.last_handshake = start;
    peer.last_seen = static_cast<uint64_t>(start);
    lnsdk::PeerLiveness state{true, 0};
    for (int64_t now = start + 5; now <= start + 185; now += 5) {
        state = lnsdk::next_peer_liveness(state, *lnsdk::peer_signal_fresh(peer, now, 30));
    }
    EXPECT_FALSE(state.online);
    for (const int64_t age : {181, 200, 600}) {
        EXPECT_FALSE(*lnsdk::peer_signal_fresh(peer, start + age, 30)) << age;
    }

    lnsdk::MeshPeer no_handshake_yet;
    EXPECT_FALSE(lnsdk::peer_signal_fresh(no_handshake_yet, start, 30).has_value());
    // Before any packet, a handshake older than the session lifetime is stale.
    no_handshake_yet.last_handshake = start - 201;
    EXPECT_FALSE(*lnsdk::peer_signal_fresh(no_handshake_yet, start, 30));
    no_handshake_yet.last_handshake = start - 150;
    EXPECT_TRUE(*lnsdk::peer_signal_fresh(no_handshake_yet, start, 30));
}

// The run loop counts a wall-clock gap as a suspension only beyond its own
// work and the sleep it asked for, plus kResumeGap.
TEST(SdkMeshResume, OnlyAGapBeyondTheWorkAndTheSleepIsASuspension) {
    using lnsdk::kResumeGap;
    using lnsdk::loop_was_suspended;
    // A normal pass: 40 ms of work, then the 5 s monitor sleep.
    EXPECT_FALSE(loop_was_suspended(5040ms, 40ms, 5000ms));
    // A slow pass (HTTP timeouts) is not a suspension.
    EXPECT_FALSE(loop_was_suspended(45s, 40s, 5s));
    // Woken early by a refresh request.
    EXPECT_FALSE(loop_was_suspended(100ms, 10ms, 5000ms));
    // A wall clock that stepped back.
    EXPECT_FALSE(loop_was_suspended(-30s, 10ms, 5000ms));
    // Exactly at the limit, and beyond it.
    EXPECT_FALSE(loop_was_suspended(5s + kResumeGap, 0ms, 5s));
    EXPECT_TRUE(loop_was_suspended(5s + kResumeGap + 1ms, 0ms, 5s));
    // An app suspended for a minute while it slept.
    EXPECT_TRUE(loop_was_suspended(65s, 20ms, 5s));
    EXPECT_GE(kResumeGap, 2 * std::chrono::duration_cast<std::chrono::milliseconds>(
                                  lnsdk::kMonitorInterval));
}

TEST(HolePuncherSchedule, BothPeersPickTheSameSlot) {
    using P = lnsdk::HolePuncher;
    const int64_t interval = 60000;
    const auto ab = P::pair_slot_offset("key-alice", "key-bob", interval);
    EXPECT_EQ(ab, P::pair_slot_offset("key-bob", "key-alice", interval));
    EXPECT_GE(ab, 0);
    EXPECT_LT(ab, interval);
    EXPECT_NE(ab, P::pair_slot_offset("key-alice", "key-carol", interval));

    // The delay lands both clocks on the same wall-clock instant.
    const int64_t a_now = 1'700'000'000'123;
    const int64_t b_now = a_now + 700;  // the other clock reads 0.7 s later
    const auto a_slot = a_now + P::next_slot_delay(a_now, interval, ab);
    const auto b_slot = b_now + P::next_slot_delay(b_now, interval, ab);
    EXPECT_EQ(a_slot, b_slot);
    EXPECT_EQ((a_slot + ab) % interval, 0);
    EXPECT_GE(P::next_slot_delay(a_slot, interval, ab), 1);
    EXPECT_EQ(P::next_slot_delay(a_slot, interval, ab), interval);
}

// ---------------------------------------------------------------------------
// Dataplanes
// ---------------------------------------------------------------------------

class SdkHolePunchTest : public ::testing::Test {
protected:
    asio::io_context io;
    std::unique_ptr<asio::executor_work_guard<asio::io_context::executor_type>> work;
    std::thread io_thread;
    std::unique_ptr<crypto::SodiumCryptoService> c;
    std::unique_ptr<network::StunService> stun_service;
    std::unique_ptr<relay::RelayService> r;
    std::unique_ptr<FakeStun> fake;
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

        stun_service = std::make_unique<network::StunService>(io, 0, *c, "test-stun");
        stun_service->start();
        r = std::make_unique<relay::RelayService>(io, 0, *c);
        r->set_relay_id("relay-1");
        r->set_ticket_authority(
            [this]() -> std::optional<relay::RelayTicketAuthority> { return authority; });
        r->start();
        fake = std::make_unique<FakeStun>(io);
        work = std::make_unique<asio::executor_work_guard<asio::io_context::executor_type>>(
            io.get_executor());
        io_thread = std::thread([this] { io.run(); });

        api.Get("/ping", [](const httplib::Request&, httplib::Response& res) {
            res.set_content("pong", "text/plain");
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
    }

    void TearDown() override {
        bob.stop();
        alice.stop();
        api.stop();
        if (api_thread.joinable()) api_thread.join();
        if (r) r->stop();
        if (stun_service) stun_service->stop();
        work.reset();
        io.stop();
        if (io_thread.joinable()) io_thread.join();
        if (c) c->stop();
    }

    std::string stun_endpoint() const {
        return "127.0.0.1:" + std::to_string(stun_service->local_port());
    }

    static lnsdk::MeshPeer peer(const std::string& pubkey, const std::string& tunnel_ip,
                                const std::string& endpoint = {}) {
        lnsdk::MeshPeer p;
        p.mesh_pubkey = pubkey;
        p.tunnel_ip = tunnel_ip;
        p.endpoint = endpoint;
        p.keepalive = 1;
        return p;
    }

    /// The dataplane's status entry for `pubkey`, by value.
    static std::optional<lnsdk::MeshPeer> status_of(const lnsdk::MeshTunnelStatus& status,
                                                    const std::string& pubkey) {
        for (const auto& p : status.peers) {
            if (p.mesh_pubkey == pubkey) return p;
        }
        return std::nullopt;
    }

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

    static lnsdk::HolePuncher::Timing fast_punch() {
        lnsdk::HolePuncher::Timing t;
        t.burst_interval = 200ms;
        t.slot_interval = 1000ms;
        t.upgrade_interval = 1000ms;
        return t;
    }

    static lnsdk::RelayFallback::Timing fast_relay() {
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

// The STUN query leaves from the dataplane socket, so the reflexive address
// carries the dataplane's own port: the mapping that peers can punch toward.
TEST_F(SdkHolePunchTest, ReflexiveAddressComesFromTheDataplaneSocket) {
    const auto reflexive = alice.query_reflexive(stun_endpoint(), 2000ms);
    ASSERT_TRUE(reflexive.has_value());
    EXPECT_EQ(*reflexive, "127.0.0.1:" + std::to_string(alice.bound_port()));
    EXPECT_TRUE(lnsdk::reflexive_publishable(*reflexive, "127.0.0.1"));

    // The answer arrives through the dataplane's receive path and leaves the
    // dataplane working: a later query succeeds too.
    EXPECT_EQ(alice.query_reflexive(stun_endpoint(), 2000ms), reflexive);

    lnsdk::BoringtunMesh stopped;
    EXPECT_FALSE(stopped.query_reflexive(stun_endpoint(), 200ms));
}

TEST_F(SdkHolePunchTest, BadStunAnswersAreRejected) {
    fake->mode = FakeStun::Mode::Correct;
    ASSERT_EQ(alice.query_reflexive(fake->endpoint(), 1000ms),
              "127.0.0.1:" + std::to_string(alice.bound_port()));

    for (const auto mode : {FakeStun::Mode::WrongTransaction, FakeStun::Mode::Overrun,
                            FakeStun::Mode::Ipv6Family, FakeStun::Mode::OtherSource,
                            FakeStun::Mode::Silent}) {
        fake->mode = mode;
        const int before = fake->requests.load();
        EXPECT_FALSE(alice.query_reflexive(fake->endpoint(), 600ms, 3))
            << "mode " << static_cast<int>(mode);
        // Every attempt resent the request with the same transaction id.
        EXPECT_EQ(fake->requests.load() - before, 3) << "mode " << static_cast<int>(mode);
    }
    // A query to an address that is not a dotted IPv4 endpoint sends nothing.
    EXPECT_FALSE(alice.query_reflexive("stun.example:3478", 200ms));
}

// A probe is a handshake initiation to the listed endpoint. The peer becomes
// reachable there only after it answers with a valid handshake; the probe by
// itself changes nothing.
TEST_F(SdkHolePunchTest, ProbeMovesThePeerOnlyAfterAValidHandshake) {
    const auto alice_reflexive = alice.query_reflexive(stun_endpoint(), 2000ms);
    const auto bob_reflexive = bob.query_reflexive(stun_endpoint(), 2000ms);
    ASSERT_TRUE(alice_reflexive && bob_reflexive);

    // Both know each other from the peer list, with no endpoint yet.
    ASSERT_TRUE(alice.sync_peers({peer(bob_keys.second, "10.64.0.3/32")}).ok);
    ASSERT_TRUE(bob.sync_peers({peer(alice_keys.second, "10.64.0.2/32")}).ok);

    // A probe to an address where nobody answers sends a packet, and the
    // stored endpoint stays empty.
    asio::ip::udp::socket sink(io, asio::ip::udp::endpoint(asio::ip::address_v4::loopback(), 0));
    const std::string dead = "127.0.0.1:" + std::to_string(sink.local_endpoint().port());
    EXPECT_TRUE(alice.probe_peer(bob_keys.second, dead));
    std::this_thread::sleep_for(300ms);
    ASSERT_TRUE(status_of(alice.mesh_status(), bob_keys.second).has_value());
    EXPECT_TRUE(status_of(alice.mesh_status(), bob_keys.second)->endpoint.empty());

    // Unauthenticated datagrams to the dataplane socket change nothing either.
    {
        asio::ip::udp::socket intruder(io, asio::ip::udp::endpoint(asio::ip::udp::v4(), 0));
        const asio::ip::udp::endpoint target(asio::ip::address_v4::loopback(), alice.bound_port());
        std::vector<uint8_t> fake_init(148, 0xAB);
        fake_init[0] = 1;
        fake_init[1] = fake_init[2] = fake_init[3] = 0;
        intruder.send_to(asio::buffer(fake_init), target);
        intruder.send_to(asio::buffer(stun::encode_binding_response(txn_of(3), {0x7F000001, 9})),
                         target);
        std::this_thread::sleep_for(300ms);
        EXPECT_TRUE(status_of(alice.mesh_status(), bob_keys.second)->endpoint.empty());
        EXPECT_EQ(status_of(alice.mesh_status(), bob_keys.second)->last_handshake, 0);
    }

    // The probe to Bob's reflexive address completes a handshake, and both
    // sides now send to each other's reflexive address.
    EXPECT_TRUE(alice.probe_peer(bob_keys.second, *bob_reflexive));
    ASSERT_TRUE(eventually(
        [&] {
            const auto a = status_of(alice.mesh_status(), bob_keys.second);
            const auto b = status_of(bob.mesh_status(), alice_keys.second);
            return a && b && a->last_handshake > 0 && a->endpoint == *bob_reflexive &&
                   b->endpoint == *alice_reflexive;
        },
        [] {}, 5s));
    EXPECT_EQ(ping_over_mesh(bob, "10.64.0.2"), "pong");

    // Probes for an unknown peer or to a malformed endpoint are refused.
    EXPECT_FALSE(alice.probe_peer("not-a-key", *bob_reflexive));
    EXPECT_FALSE(alice.probe_peer(bob_keys.second, "bogus"));
}

// Loopback end to end: each side learns its reflexive address from the STUN
// service, the server's peer list carries it to the other side, and the
// punch gives a direct session without any relay.
TEST_F(SdkHolePunchTest, TwoDataplanesConnectDirectlyWithExchangedEndpoints) {
    const auto alice_reflexive = alice.query_reflexive(stun_endpoint(), 2000ms);
    const auto bob_reflexive = bob.query_reflexive(stun_endpoint(), 2000ms);
    ASSERT_TRUE(alice_reflexive && bob_reflexive);

    const std::vector<lnsdk::MeshPeer> alice_peers = {
        peer(bob_keys.second, "10.64.0.3/32", *bob_reflexive)};
    const std::vector<lnsdk::MeshPeer> bob_peers = {
        peer(alice_keys.second, "10.64.0.2/32", *alice_reflexive)};
    ASSERT_TRUE(alice.sync_peers(alice_peers).ok);
    ASSERT_TRUE(bob.sync_peers(bob_peers).ok);

    lnsdk::HolePuncher alice_punch(alice, fast_punch());
    lnsdk::HolePuncher bob_punch(bob, fast_punch());
    ASSERT_TRUE(eventually(
        [&] {
            const auto a = status_of(alice.mesh_status(), bob_keys.second);
            const auto b = status_of(bob.mesh_status(), alice_keys.second);
            return a && b && a->last_handshake > 0 && b->last_handshake > 0;
        },
        [&] {
            (void)alice_punch.maintain(alice_peers, {}, true);
            (void)bob_punch.maintain(bob_peers, {}, true);
        },
        10s));
    EXPECT_EQ(ping_over_mesh(bob, "10.64.0.2"), "pong");
    const auto b = status_of(bob.mesh_status(), alice_keys.second);
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(b->endpoint, *alice_reflexive);
    EXPECT_TRUE(b->relay_endpoint.empty());

    // With a fresh direct session the puncher sends nothing more.
    const auto sent = alice_punch.probes_sent() + bob_punch.probes_sent();
    for (int i = 0; i < 5; ++i) {
        (void)alice_punch.maintain(alice_peers, {}, true);
        (void)bob_punch.maintain(bob_peers, {}, true);
        std::this_thread::sleep_for(250ms);
    }
    EXPECT_EQ(alice_punch.probes_sent() + bob_punch.probes_sent(), sent);

    // A later peer refresh does not overwrite the live endpoint with the
    // unchanged listed one.
    ASSERT_TRUE(bob.sync_peers(bob_peers).ok);
    EXPECT_EQ(status_of(bob.mesh_status(), alice_keys.second)->endpoint, *alice_reflexive);
}

// Peers without endpoints fall back to the relay. When the server later lists
// their endpoints, the upgrade probes punch a direct path, and the relay
// fallback closes the relay without counting a failure.
TEST_F(SdkHolePunchTest, RelayedPeersMoveBackToADirectPath) {
    const auto candidates = [this] {
        return std::vector<lnsdk::RelayCandidate>{{"relay-1", "127.0.0.1", r->local_port()}};
    };
    lnsdk::RelayFallback alice_relay(
        alice, [&](const std::string& relay_id) {
            return lnsdk::Result<lnsdk::RelayTicket>{true, sdk_ticket("alice", relay_id), 200, ""};
        },
        candidates, fast_relay());
    lnsdk::RelayFallback bob_relay(
        bob, [&](const std::string& relay_id) {
            return lnsdk::Result<lnsdk::RelayTicket>{true, sdk_ticket("bob", relay_id), 200, ""};
        },
        candidates, fast_relay());
    lnsdk::HolePuncher alice_punch(alice, fast_punch());
    lnsdk::HolePuncher bob_punch(bob, fast_punch());

    std::vector<lnsdk::MeshPeer> alice_peers = {peer(bob_keys.second, "10.64.0.3/32")};
    std::vector<lnsdk::MeshPeer> bob_peers = {peer(alice_keys.second, "10.64.0.2/32")};
    const auto pass = [&] {
        ASSERT_TRUE(alice.sync_peers(alice_peers).ok);
        ASSERT_TRUE(bob.sync_peers(bob_peers).ok);
        (void)alice_punch.maintain(alice_peers, alice_relay.relayed_peers(), true);
        (void)bob_punch.maintain(bob_peers, bob_relay.relayed_peers(), true);
        alice_relay.maintain(alice_peers, true);
        bob_relay.maintain(bob_peers, true);
    };

    ASSERT_TRUE(eventually(
        [&] {
            return alice_relay.relayed_peers().contains(bob_keys.second) &&
                   bob_relay.relayed_peers().contains(alice_keys.second);
        },
        pass, 10s));
    EXPECT_EQ(ping_over_mesh(bob, "10.64.0.2"), "pong");
    EXPECT_EQ(r->session_count(), 1u);
    EXPECT_EQ(alice_punch.probes_sent() + bob_punch.probes_sent(), 0u);

    // Both sides publish their reflexive addresses; the peer lists carry them.
    const auto alice_reflexive = alice.query_reflexive(stun_endpoint(), 2000ms);
    const auto bob_reflexive = bob.query_reflexive(stun_endpoint(), 2000ms);
    ASSERT_TRUE(alice_reflexive && bob_reflexive);
    alice_peers[0].endpoint = *bob_reflexive;
    bob_peers[0].endpoint = *alice_reflexive;

    ASSERT_TRUE(eventually(
        [&] {
            return alice_relay.relayed_peers().empty() && bob_relay.relayed_peers().empty();
        },
        pass, 15s));
    EXPECT_GT(alice_punch.probes_sent() + bob_punch.probes_sent(), 0u);
    EXPECT_TRUE(eventually([&] { return r->session_count() == 0; }, [] {}, 3s));
    EXPECT_EQ(ping_over_mesh(bob, "10.64.0.2"), "pong");
    const auto b = status_of(bob.mesh_status(), alice_keys.second);
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(b->endpoint, *alice_reflexive);
    EXPECT_TRUE(b->relay_endpoint.empty());

    // Further passes keep the direct path: no new relay channel opens.
    for (int i = 0; i < 10; ++i) {
        pass();
        std::this_thread::sleep_for(100ms);
    }
    EXPECT_TRUE(bob_relay.relayed_peers().empty());
    EXPECT_EQ(r->session_count(), 0u);
    EXPECT_EQ(status_of(bob.mesh_status(), alice_keys.second)->endpoint, *alice_reflexive);
}

// Without prefer_direct a relayed peer stays on its relay: no upgrade probes.
TEST_F(SdkHolePunchTest, NoUpgradeProbesWithoutPreferDirect) {
    lnsdk::HolePuncher punch(alice, fast_punch());
    ASSERT_TRUE(alice.sync_peers({peer(bob_keys.second, "10.64.0.3/32")}).ok);
    const std::vector<lnsdk::MeshPeer> peers = {
        peer(bob_keys.second, "10.64.0.3/32", "127.0.0.1:" + std::to_string(bob.bound_port()))};
    const std::map<std::string, std::string> relayed = {{bob_keys.second, "127.0.0.1:9103"}};
    for (int i = 0; i < 8; ++i) {
        (void)punch.maintain(peers, relayed, false);
        std::this_thread::sleep_for(250ms);
    }
    EXPECT_EQ(punch.probes_sent(), 0u);
}

namespace {

/// A UDP socket that only counts the datagrams it receives: a listed
/// endpoint where nobody answers.
class UdpSink {
public:
    explicit UdpSink(asio::io_context& io)
        : socket_(io, asio::ip::udp::endpoint(asio::ip::address_v4::loopback(), 0)) {
        receive();
    }
    ~UdpSink() {
        asio::error_code ec;
        socket_.close(ec);
    }
    std::string endpoint() const {
        return "127.0.0.1:" + std::to_string(socket_.local_endpoint().port());
    }
    int received() const { return received_.load(); }

private:
    void receive() {
        socket_.async_receive_from(asio::buffer(buf_), from_,
                                   [this](const asio::error_code& ec, std::size_t) {
                                       if (ec) return;
                                       ++received_;
                                       receive();
                                   });
    }
    asio::ip::udp::socket socket_;
    asio::ip::udp::endpoint from_;
    std::array<uint8_t, 2048> buf_{};
    std::atomic<int> received_{0};
};

}  // namespace

// A renewed peer (its listed endpoint changed, it came back online, or this
// device resumed) is probed at once, although its session is fresh: that
// handshake went to the old path. A handshake after the renewal ends it.
TEST_F(SdkHolePunchTest, ARenewedPeerIsProbedAtOnceDespiteAFreshHandshake) {
    const auto alice_reflexive = alice.query_reflexive(stun_endpoint(), 2000ms);
    const auto bob_reflexive = bob.query_reflexive(stun_endpoint(), 2000ms);
    ASSERT_TRUE(alice_reflexive && bob_reflexive);
    const std::vector<lnsdk::MeshPeer> alice_peers = {
        peer(bob_keys.second, "10.64.0.3/32", *bob_reflexive)};
    const std::vector<lnsdk::MeshPeer> bob_peers = {
        peer(alice_keys.second, "10.64.0.2/32", *alice_reflexive)};
    ASSERT_TRUE(alice.sync_peers(alice_peers).ok);
    ASSERT_TRUE(bob.sync_peers(bob_peers).ok);
    lnsdk::HolePuncher alice_punch(alice, fast_punch());
    lnsdk::HolePuncher bob_punch(bob, fast_punch());
    ASSERT_TRUE(eventually(
        [&] {
            const auto a = status_of(alice.mesh_status(), bob_keys.second);
            return a && a->last_handshake > 0;
        },
        [&] {
            (void)alice_punch.maintain(alice_peers, {}, true);
            (void)bob_punch.maintain(bob_peers, {}, true);
        },
        10s));
    // Idle now: the session is fresh.
    const auto idle = alice_punch.probes_sent();
    (void)alice_punch.maintain(alice_peers, {}, true);
    EXPECT_EQ(alice_punch.probes_sent(), idle);

    // Handshake times have one-second resolution: let the renewal fall in a
    // later second than the session's handshake.
    std::this_thread::sleep_for(1100ms);
    alice_punch.renew({bob_keys.second});
    (void)alice_punch.maintain(alice_peers, {}, true);
    EXPECT_EQ(alice_punch.probes_sent(), idle + 1) << "the renewed peer was not probed at once";

    // The probe gets an answer in a later second; then the puncher is idle.
    const auto renewed_at = now_s();
    ASSERT_TRUE(eventually(
        [&] {
            const auto a = status_of(alice.mesh_status(), bob_keys.second);
            return a && static_cast<uint64_t>(a->last_handshake) > renewed_at;
        },
        [&] { (void)alice_punch.maintain(alice_peers, {}, true); }, 10s));
    (void)alice_punch.maintain(alice_peers, {}, true);
    const auto settled = alice_punch.probes_sent();
    for (int i = 0; i < 4; ++i) {
        std::this_thread::sleep_for(250ms);
        (void)alice_punch.maintain(alice_peers, {}, true);
    }
    EXPECT_EQ(alice_punch.probes_sent(), settled);
}

// A peer that moves onto a relay during its first burst finishes the burst,
// so a direct path that opens a moment later replaces the relay soon. A
// refresh request (burst_now) starts a new burst without waiting for a slot.
TEST_F(SdkHolePunchTest, TheFirstBurstOutlivesTheRelayAndBurstNowStartsAnother) {
    UdpSink sink(io);
    ASSERT_TRUE(alice.sync_peers({peer(bob_keys.second, "10.64.0.3/32")}).ok);
    auto timing = fast_punch();
    timing.slot_interval = 600000ms;     // no slot within the test
    timing.upgrade_interval = 600000ms;
    lnsdk::HolePuncher punch(alice, timing);
    const std::vector<lnsdk::MeshPeer> peers = {
        peer(bob_keys.second, "10.64.0.3/32", sink.endpoint())};
    const std::map<std::string, std::string> relayed = {{bob_keys.second, "127.0.0.1:9103"}};

    (void)punch.maintain(peers, {}, true);
    EXPECT_EQ(punch.probes_sent(), 1u);
    // The relay paired after the first probe.
    const auto run = [&](std::chrono::milliseconds span) {
        const auto end = std::chrono::steady_clock::now() + span;
        while (std::chrono::steady_clock::now() < end) {
            (void)punch.maintain(peers, relayed, true);
            std::this_thread::sleep_for(50ms);
        }
    };
    run(1500ms);
    EXPECT_EQ(punch.probes_sent(), timing.burst_count) << "the burst stopped at the relay";
    run(500ms);
    EXPECT_EQ(punch.probes_sent(), timing.burst_count) << "probes outside the burst and slots";

    punch.burst_now();
    run(1500ms);
    EXPECT_EQ(punch.probes_sent(), 2u * timing.burst_count);
    EXPECT_TRUE(eventually([&] { return sink.received() >= 2 * static_cast<int>(timing.burst_count); },
                           [] {}, 2s));
}

// After a suspension the dataplane sends every peer a fresh handshake
// initiation at its current address, and the peer answers it.
TEST_F(SdkHolePunchTest, RehandshakeAllRenewsTheSessions) {
    const auto alice_reflexive = alice.query_reflexive(stun_endpoint(), 2000ms);
    const auto bob_reflexive = bob.query_reflexive(stun_endpoint(), 2000ms);
    ASSERT_TRUE(alice_reflexive && bob_reflexive);
    ASSERT_TRUE(alice.sync_peers({peer(bob_keys.second, "10.64.0.3/32", *bob_reflexive)}).ok);
    ASSERT_TRUE(bob.sync_peers({peer(alice_keys.second, "10.64.0.2/32", *alice_reflexive)}).ok);
    ASSERT_TRUE(alice.probe_peer(bob_keys.second, *bob_reflexive));
    ASSERT_TRUE(eventually(
        [&] {
            const auto b = status_of(bob.mesh_status(), alice_keys.second);
            return b && b->last_handshake > 0;
        },
        [] {}, 5s));
    const auto before = status_of(bob.mesh_status(), alice_keys.second)->last_handshake;

    // Handshake times read in whole seconds, up to a second late.
    std::this_thread::sleep_for(2100ms);
    EXPECT_EQ(alice.rehandshake_all(), 1u);
    EXPECT_TRUE(eventually(
        [&] { return status_of(bob.mesh_status(), alice_keys.second)->last_handshake > before; },
        [] {}, 5s));
    EXPECT_EQ(ping_over_mesh(bob, "10.64.0.2"), "pong");

    lnsdk::BoringtunMesh stopped;
    EXPECT_EQ(stopped.rehandshake_all(), 0u);
}

// Relay first, direct later: a listed endpoint that never answers gets a
// relay once the short direct grace period ends, and when the peer's real
// address is listed, the punch replaces the relay.
TEST_F(SdkHolePunchTest, ASilentEndpointGetsARelayWithinTheWindowAndUpgradesLater) {
    UdpSink alice_sink(io), bob_sink(io);
    const auto candidates = [this] {
        return std::vector<lnsdk::RelayCandidate>{{"relay-1", "127.0.0.1", r->local_port()}};
    };
    auto timing = fast_relay();  // the default direct grace period
    lnsdk::RelayFallback alice_relay(
        alice, [&](const std::string& relay_id) {
            return lnsdk::Result<lnsdk::RelayTicket>{true, sdk_ticket("alice", relay_id), 200, ""};
        },
        candidates, timing);
    lnsdk::RelayFallback bob_relay(
        bob, [&](const std::string& relay_id) {
            return lnsdk::Result<lnsdk::RelayTicket>{true, sdk_ticket("bob", relay_id), 200, ""};
        },
        candidates, timing);
    lnsdk::HolePuncher alice_punch(alice, fast_punch());
    lnsdk::HolePuncher bob_punch(bob, fast_punch());

    std::vector<lnsdk::MeshPeer> alice_peers = {
        peer(bob_keys.second, "10.64.0.3/32", bob_sink.endpoint())};
    std::vector<lnsdk::MeshPeer> bob_peers = {
        peer(alice_keys.second, "10.64.0.2/32", alice_sink.endpoint())};
    const auto pass = [&] {
        ASSERT_TRUE(alice.sync_peers(alice_peers).ok);
        ASSERT_TRUE(bob.sync_peers(bob_peers).ok);
        (void)alice_punch.maintain(alice_peers, alice_relay.relayed_peers(), true);
        (void)bob_punch.maintain(bob_peers, bob_relay.relayed_peers(), true);
        (void)alice_relay.maintain(alice_peers, true);
        (void)bob_relay.maintain(bob_peers, true);
    };

    const auto start = std::chrono::steady_clock::now();
    pass();
    // Within the grace period the punch runs alone.
    std::this_thread::sleep_for(lnsdk::kDirectAnswerWindow / 2);
    pass();
    EXPECT_TRUE(alice_relay.relayed_peers().empty());
    EXPECT_GT(bob_sink.received(), 0) << "no probe went to the listed endpoint";

    ASSERT_TRUE(eventually(
        [&] {
            return alice_relay.relayed_peers().contains(bob_keys.second) &&
                   bob_relay.relayed_peers().contains(alice_keys.second);
        },
        pass, 10s));
    const auto relayed_after = std::chrono::steady_clock::now() - start;
    EXPECT_GE(relayed_after, lnsdk::kDirectAnswerWindow);
    EXPECT_LT(relayed_after, lnsdk::kDirectAnswerWindow + 3s);
    EXPECT_EQ(ping_over_mesh(bob, "10.64.0.2"), "pong");

    // The real addresses appear in the peer lists: the upgrade probes punch
    // a direct path, and the relay closes.
    const auto alice_reflexive = alice.query_reflexive(stun_endpoint(), 2000ms);
    const auto bob_reflexive = bob.query_reflexive(stun_endpoint(), 2000ms);
    ASSERT_TRUE(alice_reflexive && bob_reflexive);
    alice_peers[0].endpoint = *bob_reflexive;
    bob_peers[0].endpoint = *alice_reflexive;
    ASSERT_TRUE(eventually(
        [&] { return alice_relay.relayed_peers().empty() && bob_relay.relayed_peers().empty(); },
        pass, 15s));
    EXPECT_TRUE(eventually([&] { return r->session_count() == 0; }, [] {}, 3s));
    EXPECT_EQ(ping_over_mesh(bob, "10.64.0.2"), "pong");
}

// A relay request whose path is not in use yet closes when the peer answers
// on a direct path first: the other side, which asks the same relay later,
// is never paired, and neither side moves off the direct path.
TEST_F(SdkHolePunchTest, ADirectAnswerClosesAnUnusedRelayRequest) {
    const auto candidates = [this] {
        return std::vector<lnsdk::RelayCandidate>{{"relay-1", "127.0.0.1", r->local_port()}};
    };
    auto timing = fast_relay();
    timing.pending_limit = 30s;  // an unpaired request would outlive the test
    lnsdk::RelayFallback alice_relay(
        alice, [&](const std::string& relay_id) {
            return lnsdk::Result<lnsdk::RelayTicket>{true, sdk_ticket("alice", relay_id), 200, ""};
        },
        candidates, timing);
    lnsdk::RelayFallback bob_relay(
        bob, [&](const std::string& relay_id) {
            return lnsdk::Result<lnsdk::RelayTicket>{true, sdk_ticket("bob", relay_id), 200, ""};
        },
        candidates, timing);

    const auto alice_reflexive = alice.query_reflexive(stun_endpoint(), 2000ms);
    const auto bob_reflexive = bob.query_reflexive(stun_endpoint(), 2000ms);
    ASSERT_TRUE(alice_reflexive && bob_reflexive);
    // A long keepalive keeps the dataplanes from renewing a session on their
    // own. A session that forms before the renewal does not count after it.
    std::vector<lnsdk::MeshPeer> alice_peers = {
        peer(bob_keys.second, "10.64.0.3/32", *bob_reflexive)};
    std::vector<lnsdk::MeshPeer> bob_peers = {
        peer(alice_keys.second, "10.64.0.2/32", *alice_reflexive)};
    alice_peers[0].keepalive = bob_peers[0].keepalive = 25;
    ASSERT_TRUE(alice.sync_peers(alice_peers).ok);
    ASSERT_TRUE(bob.sync_peers(bob_peers).ok);
    std::this_thread::sleep_for(1100ms);

    // Alice renews Bob without a grace period: she asks the relay at once.
    const auto renewed_at = static_cast<int64_t>(now_s());
    alice_relay.renew({bob_keys.second}, true);
    (void)alice_relay.maintain(alice_peers, true);
    // Then the direct path answers. The dataplane reports handshake times in
    // whole seconds, and a handshake counts only when it reads later than
    // the renewal, so probe until one does, as the punch burst would.
    ASSERT_TRUE(eventually(
        [&] {
            const auto a = status_of(alice.mesh_status(), bob_keys.second);
            return a && a->last_handshake > renewed_at;
        },
        [&] { (void)alice.probe_peer(bob_keys.second, *bob_reflexive); }, 10s));
    (void)alice_relay.maintain(alice_peers, true);

    // Bob now asks the same relay. Alice's request is gone, so the relay
    // never pairs them, and Alice stays on the direct path.
    bob_relay.renew({alice_keys.second}, true);
    for (int i = 0; i < 10; ++i) {
        (void)alice_relay.maintain(alice_peers, true);
        (void)bob_relay.maintain(bob_peers, true);
        std::this_thread::sleep_for(100ms);
    }
    // Bob's request waits alone: a pairing would have moved him onto the
    // relay within one pass.
    EXPECT_TRUE(alice_relay.relayed_peers().empty());
    EXPECT_TRUE(bob_relay.relayed_peers().empty());
    EXPECT_EQ(status_of(alice.mesh_status(), bob_keys.second)->endpoint, *bob_reflexive);
}
