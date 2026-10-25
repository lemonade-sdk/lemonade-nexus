// Relay allocation over the wire: two peers join one session by rendezvous,
// and the relay forwards only between the two endpoints their tickets bound.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Relay/RelayService.hpp>
#include <LemonadeNexus/Relay/RelayTicketAuth.hpp>
#include <LemonadeNexus/Relay/RelayWire.hpp>

#include <asio.hpp>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <chrono>
#include <cstring>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace nexus;
using namespace std::chrono_literals;

namespace {

uint64_t now_s() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                     std::chrono::system_clock::now().time_since_epoch())
                                     .count());
}

/// A peer's mesh (X25519) keypair.
struct MeshKeys {
    std::array<uint8_t, 32> pk{};
    std::array<uint8_t, 32> sk{};
    MeshKeys() { crypto_box_keypair(pk.data(), sk.data()); }
};

/// What `self` sends to rendezvous with `peer` at `relay_id`.
relay::RelayRendezvous rendezvous(const MeshKeys& self, const MeshKeys& peer,
                                  std::string_view relay_id = "relay-1",
                                  uint64_t window = relay::relay_rendezvous_window(now_s())) {
    std::array<uint8_t, 32> shared{};
    EXPECT_EQ(crypto_scalarmult(shared.data(), self.sk.data(), peer.pk.data()), 0);
    auto out = relay::derive_relay_rendezvous(std::span<const uint8_t, 32>(shared), self.pk,
                                              peer.pk, relay_id, window);
    EXPECT_TRUE(out.has_value());
    return out.value_or(relay::RelayRendezvous{});
}

/// A UDP client on 127.0.0.1 that talks to the relay.
class WireClient {
public:
    WireClient(asio::io_context& io, uint16_t relay_port)
        : socket_(io, asio::ip::udp::endpoint(asio::ip::make_address("127.0.0.1"), 0)),
          relay_(asio::ip::make_address("127.0.0.1"), relay_port) {}

    void send(std::span<const uint8_t> datagram) {
        socket_.send_to(asio::buffer(datagram.data(), datagram.size()), relay_);
    }

    /// The next datagram, or nullopt after `timeout`.
    std::optional<std::vector<uint8_t>> receive(std::chrono::milliseconds timeout = 2000ms) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            if (socket_.available() > 0) {
                std::vector<uint8_t> buf(65536);
                asio::ip::udp::endpoint from;
                const auto n = socket_.receive_from(asio::buffer(buf), from);
                buf.resize(n);
                return buf;
            }
            std::this_thread::sleep_for(2ms);
        }
        return std::nullopt;
    }

    /// The next relay-protocol reply, decoded.
    std::optional<std::pair<relay::RelayPacketHeader, std::vector<uint8_t>>> reply(
        std::chrono::milliseconds timeout = 2000ms) {
        auto datagram = receive(timeout);
        if (!datagram) return std::nullopt;
        auto header = relay::decode_relay_header(*datagram);
        if (!header) return std::nullopt;
        std::vector<uint8_t> payload(datagram->begin() + relay::kRelayHeaderSize,
                                     datagram->begin() + relay::kRelayHeaderSize +
                                         header->payload_length);
        return std::make_pair(*header, std::move(payload));
    }

private:
    asio::ip::udp::socket socket_;
    asio::ip::udp::endpoint relay_;
};

std::vector<uint8_t> bytes(std::string_view text) { return {text.begin(), text.end()}; }

}  // namespace

class RelayServiceTest : public ::testing::Test {
protected:
    static void SetUpTestSuite() { ASSERT_GE(sodium_init(), 0); }

    asio::io_context io;
    std::unique_ptr<asio::executor_work_guard<asio::io_context::executor_type>> work;
    std::thread io_thread;
    std::unique_ptr<crypto::SodiumCryptoService> c;
    std::unique_ptr<relay::RelayService> r;
    crypto::Ed25519Keypair member;
    crypto::Ed25519Keypair outsider;
    relay::RelayTicketAuthority authority;
    MeshKeys alice_keys;
    MeshKeys bob_keys;

    void SetUp() override {
        c = std::make_unique<crypto::SodiumCryptoService>();
        c->start();
        member = c->ed25519_keygen();
        outsider = c->ed25519_keygen();
        authority.network_id.fill(0x5A);
        authority.epoch = 7;
        security::NodeId self;
        self.bytes = member.public_key;
        authority.members.push_back(self);
    }

    /// Start the relay with `limits`.
    void start_relay(const relay::RelayLimits& limits = {}) {
        r = std::make_unique<relay::RelayService>(io, 0, *c);
        r->set_relay_id("relay-1");
        r->set_limits(limits);
        r->set_ticket_authority(
            [this]() -> std::optional<relay::RelayTicketAuthority> { return authority; });
        r->start();
        work = std::make_unique<asio::executor_work_guard<asio::io_context::executor_type>>(
            io.get_executor());
        io_thread = std::thread([this] { io.run(); });
    }

    void TearDown() override {
        if (r) r->stop();
        work.reset();
        io.stop();
        if (io_thread.joinable()) io_thread.join();
        if (c) c->stop();
    }

    /// A ticket a Tier 1 member issues for `holder`, as /api/relay/ticket does.
    relay::RelayTicket ticket(const std::string& holder,
                              const crypto::Ed25519Keypair* issuer = nullptr,
                              std::string relay_id = "relay-1") {
        relay::RelayTicket t;
        t.peer_id = holder;
        t.relay_id = std::move(relay_id);
        c->random_bytes(std::span<uint8_t>(t.session_nonce));
        t.issued_at = now_s();
        t.expires_at = t.issued_at + relay::kRelayTicketMaxLifetimeSec;
        t.network_id = authority.network_id;
        t.epoch = authority.epoch.underlying();
        relay::sign_relay_ticket(t, issuer ? *issuer : member);
        return t;
    }

    relay::RelayAllocateRequest request(const relay::RelayRendezvous& rv,
                                        const relay::RelayTicket& t) {
        return relay::RelayAllocateRequest{rv.id, rv.own_proof, rv.peer_commitment, t};
    }

    static asio::ip::udp::endpoint ep(const char* ip, uint16_t port) {
        return {asio::ip::make_address(ip), port};
    }
};

// ── Rendezvous and codecs ───────────────────────────────────────────────────

TEST_F(RelayServiceTest, BothSidesDeriveTheSameRendezvousAndOpenEachOther) {
    const auto window = relay::relay_rendezvous_window(now_s());
    const auto a = rendezvous(alice_keys, bob_keys, "relay-1", window);
    const auto b = rendezvous(bob_keys, alice_keys, "relay-1", window);
    EXPECT_EQ(a.id, b.id);
    EXPECT_NE(a.own_proof, b.own_proof);
    EXPECT_EQ(relay::relay_proof_commitment(a.own_proof), b.peer_commitment);
    EXPECT_EQ(relay::relay_proof_commitment(b.own_proof), a.peer_commitment);

    // Another relay, another window, or another peer gives other material.
    EXPECT_NE(rendezvous(alice_keys, bob_keys, "relay-2", window).id, a.id);
    EXPECT_NE(rendezvous(alice_keys, bob_keys, "relay-1", window + 1).id, a.id);
    MeshKeys carol;
    EXPECT_NE(rendezvous(alice_keys, carol, "relay-1", window).id, a.id);

    // Degenerate inputs are refused.
    std::array<uint8_t, 32> zero{};
    EXPECT_FALSE(relay::derive_relay_rendezvous(std::span<const uint8_t, 32>(zero), alice_keys.pk,
                                                bob_keys.pk, "relay-1", window));
    std::array<uint8_t, 32> shared{};
    ASSERT_EQ(crypto_scalarmult(shared.data(), alice_keys.sk.data(), bob_keys.pk.data()), 0);
    EXPECT_FALSE(relay::derive_relay_rendezvous(std::span<const uint8_t, 32>(shared),
                                                alice_keys.pk, alice_keys.pk, "relay-1", window));
    EXPECT_FALSE(relay::derive_relay_rendezvous(std::span<const uint8_t, 32>(shared),
                                                alice_keys.pk, bob_keys.pk, "", window));
}

TEST_F(RelayServiceTest, TicketJsonIsStrict) {
    const auto t = ticket("alice");
    const auto json = relay::relay_ticket_to_json(t);
    const auto back = relay::relay_ticket_from_json(json);
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(relay::relay_ticket_digest(*back), relay::relay_ticket_digest(t));
    EXPECT_EQ(back->signature, t.signature);

    auto doc = nlohmann::json::parse(json);
    auto broken = doc;
    broken.erase("signature");
    EXPECT_FALSE(relay::relay_ticket_from_json(broken.dump()));
    broken = doc;
    broken["issuer"] = crypto::to_base64(std::vector<uint8_t>(31, 1));
    EXPECT_FALSE(relay::relay_ticket_from_json(broken.dump()));
    broken = doc;
    broken["network_id"] = "zz";
    EXPECT_FALSE(relay::relay_ticket_from_json(broken.dump()));
    broken = doc;
    broken["epoch"] = -1;
    EXPECT_FALSE(relay::relay_ticket_from_json(broken.dump()));
    broken = doc;
    broken["peer_id"] = std::string(relay::kRelayMaxIdBytes + 1, 'p');
    EXPECT_FALSE(relay::relay_ticket_from_json(broken.dump()));
    EXPECT_FALSE(relay::relay_ticket_from_json("not json"));
    EXPECT_FALSE(relay::relay_ticket_from_json(""));
    EXPECT_FALSE(relay::relay_ticket_from_json(std::string(relay::kRelayMaxTicketJsonBytes + 1, ' ')));
}

TEST_F(RelayServiceTest, HeaderDecodeRejectsMalformedDatagrams) {
    const relay::SessionId sid{1, 2, 3};
    const auto good = relay::make_relay_datagram(relay::RelayMsgType::Data, sid, 9, bytes("abc"));
    const auto header = relay::decode_relay_header(good);
    ASSERT_TRUE(header.has_value());
    EXPECT_EQ(header->session_id, sid);
    EXPECT_EQ(header->sequence_number, 9u);
    EXPECT_EQ(header->payload_length, 3u);
    // The magic is little-endian on the wire.
    EXPECT_EQ(good[0], 0x52);
    EXPECT_EQ(good[1], 0x4C);

    EXPECT_FALSE(relay::decode_relay_header(std::span<const uint8_t>(good).first(10)));
    auto bad_magic = good;
    bad_magic[0] ^= 0xFF;
    EXPECT_FALSE(relay::decode_relay_header(bad_magic));
    auto bad_version = good;
    bad_version[2] = 0x02;
    EXPECT_FALSE(relay::decode_relay_header(bad_version));
    auto truncated = good;
    truncated.pop_back();
    EXPECT_FALSE(relay::decode_relay_header(truncated));
}

// ── Wire allocation and forwarding ──────────────────────────────────────────

TEST_F(RelayServiceTest, TwoPeersPairOverTheWireAndOnlyTheyExchangeData) {
    start_relay();
    WireClient alice(io, r->local_port());
    WireClient bob(io, r->local_port());
    WireClient mallory(io, r->local_port());

    alice.send(relay::make_relay_allocate(rendezvous(alice_keys, bob_keys),
                                          relay::relay_ticket_to_json(ticket("alice")), 1));
    auto first = alice.reply();
    ASSERT_TRUE(first.has_value());
    ASSERT_EQ(first->first.msg_type, relay::RelayMsgType::Allocated);
    EXPECT_EQ(first->first.sequence_number, 1u);
    auto state = relay::decode_relay_allocated(first->second);
    ASSERT_TRUE(state.has_value());
    EXPECT_EQ(state->state, relay::RelayAllocationState::Waiting);
    EXPECT_EQ(state->idle_timeout_sec, relay::RelayLimits{}.idle_timeout_sec);
    const auto sid = first->first.session_id;

    // Data before the second side joins is dropped.
    alice.send(relay::make_relay_datagram(relay::RelayMsgType::Data, sid, 2, bytes("early")));

    bob.send(relay::make_relay_allocate(rendezvous(bob_keys, alice_keys),
                                        relay::relay_ticket_to_json(ticket("bob")), 1));
    auto second = bob.reply();
    ASSERT_TRUE(second.has_value());
    ASSERT_EQ(second->first.msg_type, relay::RelayMsgType::Allocated);
    EXPECT_EQ(second->first.session_id, sid);
    EXPECT_EQ(relay::decode_relay_allocated(second->second)->state,
              relay::RelayAllocationState::Paired);

    // The side that waited learns that the session is paired.
    auto bound = alice.reply();
    ASSERT_TRUE(bound.has_value());
    EXPECT_EQ(bound->first.msg_type, relay::RelayMsgType::Bound);
    EXPECT_EQ(bound->first.session_id, sid);

    // Each side's Data reaches the other side, without the relay header.
    alice.send(relay::make_relay_datagram(relay::RelayMsgType::Data, sid, 3, bytes("to-bob")));
    auto at_bob = bob.receive();
    ASSERT_TRUE(at_bob.has_value());
    EXPECT_EQ(*at_bob, bytes("to-bob"));
    bob.send(relay::make_relay_datagram(relay::RelayMsgType::Data, sid, 2, bytes("to-alice")));
    auto at_alice = alice.receive();
    ASSERT_TRUE(at_alice.has_value());
    EXPECT_EQ(*at_alice, bytes("to-alice"));

    // A third endpoint that knows the session id forwards nothing, learns
    // nothing from a heartbeat, and cannot tear the session down.
    mallory.send(relay::make_relay_datagram(relay::RelayMsgType::Data, sid, 1, bytes("spoof")));
    EXPECT_FALSE(alice.receive(200ms).has_value());
    EXPECT_FALSE(bob.receive(50ms).has_value());
    mallory.send(relay::make_relay_datagram(relay::RelayMsgType::Heartbeat, sid, 5));
    auto refused = mallory.reply();
    ASSERT_TRUE(refused.has_value());
    EXPECT_EQ(refused->first.msg_type, relay::RelayMsgType::Error);
    ASSERT_EQ(refused->second.size(), 1u);
    EXPECT_EQ(refused->second[0], static_cast<uint8_t>(relay::RelayErrorCode::SessionUnknown));
    mallory.send(relay::make_relay_datagram(relay::RelayMsgType::Teardown, sid, 6));
    std::this_thread::sleep_for(100ms);
    EXPECT_EQ(r->session_count(), 1u);

    // A bound side cannot forward bytes that look like a relay control
    // message (here a forged Error for the other side's session).
    const uint8_t forged_code[1] = {static_cast<uint8_t>(relay::RelayErrorCode::SessionUnknown)};
    alice.send(relay::make_relay_datagram(
        relay::RelayMsgType::Data, sid, 4,
        relay::make_relay_datagram(relay::RelayMsgType::Error, sid, 0, forged_code)));
    EXPECT_FALSE(bob.receive(200ms).has_value());

    const auto stats = r->get_session_stats(sid);
    ASSERT_TRUE(stats.has_value());
    EXPECT_EQ(stats->packets_forwarded, 2u);
    EXPECT_EQ(stats->packets_dropped, 3u);  // the early packet, the spoof, the forgery

    // A bound side gets heartbeat answers and may end the session.
    alice.send(relay::make_relay_datagram(relay::RelayMsgType::Heartbeat, sid, 7));
    auto ack = alice.reply();
    ASSERT_TRUE(ack.has_value());
    EXPECT_EQ(ack->first.msg_type, relay::RelayMsgType::HeartbeatAck);
    alice.send(relay::make_relay_datagram(relay::RelayMsgType::Teardown, sid, 8));
    std::this_thread::sleep_for(100ms);
    EXPECT_EQ(r->session_count(), 0u);
}

TEST_F(RelayServiceTest, WireRefusesBadTicketsAndMalformedRequests) {
    start_relay();
    WireClient client(io, r->local_port());
    const auto rv = rendezvous(alice_keys, bob_keys);

    const auto expect_error = [&](const std::vector<uint8_t>& datagram,
                                  relay::RelayErrorCode code) {
        client.send(datagram);
        auto reply = client.reply();
        ASSERT_TRUE(reply.has_value());
        EXPECT_EQ(reply->first.msg_type, relay::RelayMsgType::Error);
        ASSERT_EQ(reply->second.size(), 1u);
        EXPECT_EQ(reply->second[0], static_cast<uint8_t>(code));
    };
    const auto allocate = [&](const relay::RelayTicket& t) {
        return relay::make_relay_allocate(rv, relay::relay_ticket_to_json(t), 1);
    };

    auto expired = ticket("alice");
    expired.issued_at = now_s() - 600;
    expired.expires_at = expired.issued_at + 60;
    relay::sign_relay_ticket(expired, member);
    expect_error(allocate(expired), relay::RelayErrorCode::TicketRefused);

    expect_error(allocate(ticket("alice", nullptr, "relay-2")),
                 relay::RelayErrorCode::TicketRefused);
    expect_error(allocate(ticket("alice", &outsider)), relay::RelayErrorCode::TicketRefused);
    auto forged = ticket("alice");
    forged.peer_id = "mallory";
    expect_error(allocate(forged), relay::RelayErrorCode::TicketRefused);

    // Malformed: no ticket, a ticket that is not JSON, and an oversized one.
    std::vector<uint8_t> fixed_only(relay::kRelayAllocateFixedBytes, 0);
    expect_error(relay::make_relay_datagram(relay::RelayMsgType::Allocate, {}, 1, fixed_only),
                 relay::RelayErrorCode::Malformed);
    auto not_json = fixed_only;
    for (char ch : std::string("{not json")) not_json.push_back(static_cast<uint8_t>(ch));
    expect_error(relay::make_relay_datagram(relay::RelayMsgType::Allocate, {}, 1, not_json),
                 relay::RelayErrorCode::Malformed);
    auto oversized = fixed_only;
    oversized.resize(relay::kRelayAllocateFixedBytes + relay::kRelayMaxTicketJsonBytes + 1, ' ');
    expect_error(relay::make_relay_datagram(relay::RelayMsgType::Allocate, {}, 1, oversized),
                 relay::RelayErrorCode::Malformed);

    EXPECT_EQ(r->session_count(), 0u);
}

TEST_F(RelayServiceTest, ATicketAllocatesOnceButARetransmissionLearnsItsSession) {
    start_relay();
    const auto t = ticket("alice");
    const auto req = request(rendezvous(alice_keys, bob_keys), t);
    const auto alice_ep = ep("198.51.100.1", 1111);

    const auto first = r->allocate_rendezvous(req, alice_ep);
    ASSERT_FALSE(first.error) << first.error_message;

    // The same request from the same endpoint (its reply was lost).
    const auto again = r->allocate_rendezvous(req, alice_ep);
    ASSERT_FALSE(again.error) << again.error_message;
    EXPECT_EQ(again.session_id, first.session_id);

    // The same ticket from anywhere else is a replay.
    const auto replay = r->allocate_rendezvous(req, ep("203.0.113.9", 4444));
    ASSERT_TRUE(replay.error.has_value());
    EXPECT_EQ(*replay.error, relay::RelayErrorCode::TicketReplayed);

    // A replayed ticket under another rendezvous is refused too.
    MeshKeys carol;
    const auto other = r->allocate_rendezvous(request(rendezvous(alice_keys, carol), t),
                                              ep("203.0.113.9", 4444));
    ASSERT_TRUE(other.error.has_value());
    EXPECT_EQ(*other.error, relay::RelayErrorCode::TicketReplayed);
    EXPECT_EQ(r->session_count(), 1u);
}

TEST_F(RelayServiceTest, OnlyTheRealSecondSideCanJoin) {
    start_relay();
    const auto alice_ep = ep("198.51.100.1", 1111);
    const auto alice_rv = rendezvous(alice_keys, bob_keys);
    const auto waiting = r->allocate_rendezvous(request(alice_rv, ticket("alice")), alice_ep);
    ASSERT_FALSE(waiting.error);

    // Mallory saw Alice's request and replays its rendezvous and proof with a
    // ticket of her own: she cannot take Alice's slot.
    const auto copy = r->allocate_rendezvous(request(alice_rv, ticket("mallory")),
                                             ep("203.0.113.9", 4444));
    ASSERT_TRUE(copy.error.has_value());
    EXPECT_EQ(*copy.error, relay::RelayErrorCode::RendezvousBusy);

    // Nor can she join as the second side without Bob's proof.
    auto guess = rendezvous(bob_keys, alice_keys);
    guess.own_proof[0] ^= 0x01;
    const auto wrong = r->allocate_rendezvous(request(guess, ticket("mallory")),
                                              ep("203.0.113.9", 4444));
    ASSERT_TRUE(wrong.error.has_value());
    EXPECT_EQ(*wrong.error, relay::RelayErrorCode::ProofMismatch);

    // Bob's proof with Alice's own ticket holder is refused: two holders bind
    // a session.
    const auto bob_rv = rendezvous(bob_keys, alice_keys);
    const auto same_holder = r->allocate_rendezvous(request(bob_rv, ticket("alice")),
                                                    ep("198.51.100.2", 2222));
    ASSERT_TRUE(same_holder.error.has_value());
    EXPECT_EQ(*same_holder.error, relay::RelayErrorCode::RendezvousBusy);

    // So is Bob at Alice's own endpoint.
    const auto same_endpoint = r->allocate_rendezvous(request(bob_rv, ticket("bob")), alice_ep);
    ASSERT_TRUE(same_endpoint.error.has_value());
    EXPECT_EQ(*same_endpoint.error, relay::RelayErrorCode::RendezvousBusy);

    // Bob joins.
    const auto bob_ep = ep("198.51.100.2", 2222);
    const auto paired = r->allocate_rendezvous(request(bob_rv, ticket("bob")), bob_ep);
    ASSERT_FALSE(paired.error) << paired.error_message;
    EXPECT_TRUE(paired.paired);
    EXPECT_EQ(paired.session_id, waiting.session_id);
    ASSERT_TRUE(paired.notify.has_value());
    EXPECT_EQ(*paired.notify, alice_ep);

    // Once paired, the slot is closed: a third valid request starts a new
    // waiting session instead of joining this one.
    const auto late = r->allocate_rendezvous(request(bob_rv, ticket("bob")),
                                             ep("198.51.100.3", 3333));
    ASSERT_FALSE(late.error);
    EXPECT_NE(late.session_id, waiting.session_id);
    EXPECT_FALSE(late.paired);
}

TEST_F(RelayServiceTest, AllocationsAreBounded) {
    relay::RelayLimits limits;
    limits.max_sessions = 2;
    limits.max_sessions_per_holder = 1;
    start_relay(limits);
    MeshKeys carol, dave;

    ASSERT_FALSE(r->allocate_rendezvous(request(rendezvous(alice_keys, bob_keys), ticket("alice")),
                                        ep("198.51.100.1", 1))
                     .error);
    // One holder, one session.
    const auto second_for_alice = r->allocate_rendezvous(
        request(rendezvous(alice_keys, carol), ticket("alice")), ep("198.51.100.1", 2));
    ASSERT_TRUE(second_for_alice.error.has_value());
    EXPECT_EQ(*second_for_alice.error, relay::RelayErrorCode::CapacityExceeded);

    ASSERT_FALSE(r->allocate_rendezvous(request(rendezvous(carol, dave), ticket("carol")),
                                        ep("198.51.100.3", 3))
                     .error);
    // The relay holds at most two sessions.
    const auto third = r->allocate_rendezvous(request(rendezvous(dave, bob_keys), ticket("dave")),
                                              ep("198.51.100.4", 4));
    ASSERT_TRUE(third.error.has_value());
    EXPECT_EQ(*third.error, relay::RelayErrorCode::CapacityExceeded);
    EXPECT_EQ(r->session_count(), 2u);
}

TEST_F(RelayServiceTest, AllocateRequestsAreRateLimitedBeforeTicketChecks) {
    relay::RelayLimits limits;
    limits.allocate_per_minute = 1;
    limits.allocate_burst = 2;
    start_relay(limits);
    MeshKeys carol;
    const auto bad = ticket("alice", &outsider);  // refused, but it costs a token
    EXPECT_EQ(*r->allocate_rendezvous(request(rendezvous(alice_keys, bob_keys), bad),
                                      ep("198.51.100.1", 1))
                   .error,
              relay::RelayErrorCode::TicketRefused);
    EXPECT_FALSE(r->allocate_rendezvous(request(rendezvous(alice_keys, bob_keys), ticket("alice")),
                                        ep("198.51.100.1", 1))
                     .error);
    const auto limited = r->allocate_rendezvous(
        request(rendezvous(carol, bob_keys), ticket("carol")), ep("198.51.100.3", 3));
    ASSERT_TRUE(limited.error.has_value());
    EXPECT_EQ(*limited.error, relay::RelayErrorCode::RateLimited);
}

TEST_F(RelayServiceTest, SessionsExpireWhenUnpairedIdleOrTooOld) {
    relay::RelayLimits limits;
    limits.pending_timeout_sec = 30;
    limits.idle_timeout_sec = 90;
    limits.max_lifetime_sec = 3600;
    start_relay(limits);
    const auto now = std::chrono::steady_clock::now();

    // A session whose second side never comes.
    MeshKeys carol;
    const auto lonely = r->allocate_rendezvous(
        request(rendezvous(carol, bob_keys), ticket("carol")), ep("198.51.100.3", 3));
    ASSERT_FALSE(lonely.error);

    // A paired session.
    const auto a = r->allocate_rendezvous(request(rendezvous(alice_keys, bob_keys), ticket("alice")),
                                          ep("198.51.100.1", 1));
    const auto b = r->allocate_rendezvous(request(rendezvous(bob_keys, alice_keys), ticket("bob")),
                                          ep("198.51.100.2", 2));
    ASSERT_FALSE(a.error);
    ASSERT_TRUE(b.paired);
    EXPECT_EQ(r->session_count(), 2u);

    EXPECT_EQ(r->expire_sessions(now + 10s), 0u);
    // The unpaired session goes after the pending timeout; the paired one stays.
    EXPECT_EQ(r->expire_sessions(now + 31s), 1u);
    EXPECT_FALSE(r->get_session_stats(lonely.session_id).has_value());
    EXPECT_TRUE(r->get_session_stats(a.session_id).has_value());
    // The paired session goes once it is idle past the idle timeout.
    EXPECT_EQ(r->expire_sessions(now + 92s), 1u);
    EXPECT_EQ(r->session_count(), 0u);

    // A holder whose sessions expired may allocate again.
    EXPECT_FALSE(r->allocate_rendezvous(request(rendezvous(carol, alice_keys), ticket("carol")),
                                        ep("198.51.100.3", 3))
                     .error);
}

TEST_F(RelayServiceTest, NoSessionOutlivesItsMaximumLifetime) {
    relay::RelayLimits limits;
    limits.idle_timeout_sec = 100000;
    limits.max_lifetime_sec = 3600;
    start_relay(limits);
    const auto now = std::chrono::steady_clock::now();
    ASSERT_FALSE(r->allocate_rendezvous(request(rendezvous(alice_keys, bob_keys), ticket("alice")),
                                        ep("198.51.100.1", 1))
                     .error);
    ASSERT_TRUE(r->allocate_rendezvous(request(rendezvous(bob_keys, alice_keys), ticket("bob")),
                                       ep("198.51.100.2", 2))
                    .paired);
    EXPECT_EQ(r->expire_sessions(now + 3000s), 0u);
    EXPECT_EQ(r->expire_sessions(now + 3601s), 1u);
    EXPECT_EQ(r->session_count(), 0u);
}
