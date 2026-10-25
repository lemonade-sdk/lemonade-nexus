#include <LemonadeNexus/Routing/ConnectionTicket.hpp>
#include <LemonadeNexus/Routing/RoutingTypes.hpp>
#include <LemonadeNexus/Relay/RelayService.hpp>
#include <LemonadeNexus/Relay/RelayTicketAuth.hpp>
#include <LemonadeNexus/Relay/RelayTypes.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Gossip/ServerCertificate.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <asio.hpp>
#include <gtest/gtest.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

using namespace nexus;
namespace fs = std::filesystem;

static uint64_t now_s() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

// ── ConnectionTicket sign / verify ─────────────────────────────────────────

TEST(ConnectionTicket, SignVerifyRoundTrip) {
    crypto::SodiumCryptoService c; c.start();
    auto kp = c.ed25519_keygen();

    routing::ConnectionTicket t;
    t.connection_id = "abc123";
    t.client_node_id = "client-1";
    t.endpoint_node_id = "ep-1";
    t.conn_nonce = {{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}};
    t.data_path = routing::DataPath::Relay;
    t.issued_at = now_s();
    t.expires_at = t.issued_at + 30;

    routing::sign_connection_ticket(t, c, kp.private_key);
    EXPECT_TRUE(routing::verify_connection_ticket(t, c, kp.public_key));

    // Tamper: any covered field invalidates the signature.
    auto tampered = t;
    tampered.endpoint_node_id = "ep-evil";
    EXPECT_FALSE(routing::verify_connection_ticket(tampered, c, kp.public_key));

    // Wrong signer key.
    auto other = c.ed25519_keygen();
    EXPECT_FALSE(routing::verify_connection_ticket(t, c, other.public_key));
    c.stop();
}

// Certificates bind to a network id; one value serves the fixtures here.
inline const std::string kTestNetworkHex(64, 'a');

// ── verify_identity_binding (strict, no fail-open) ──────────────────────────

class IdentityBindingTest : public ::testing::Test {
protected:
    fs::path dir;
    asio::io_context io;
    std::unique_ptr<crypto::SodiumCryptoService> c;
    std::unique_ptr<storage::FileStorageService> s;
    std::unique_ptr<gossip::GossipService> g;
    crypto::Ed25519Keypair root;

    void make(bool with_root) {
        dir = fs::temp_directory_path() / ("nexus_idbind_" + std::to_string(getpid()));
        fs::create_directories(dir);
        c = std::make_unique<crypto::SodiumCryptoService>(); c->start();
        s = std::make_unique<storage::FileStorageService>(dir); s->start();
        g = std::make_unique<gossip::GossipService>(io, 0, *s, *c);
        root = c->ed25519_keygen();
        if (with_root) {
            g->set_root_pubkey(root.public_key);
            g->set_network_id(kTestNetworkHex);
        }
    }
    void TearDown() override {
        if (g) g->stop(); if (s) s->stop(); if (c) c->stop();
        if (!dir.empty()) fs::remove_all(dir);
    }
    gossip::ServerCertificate signed_cert() {
        gossip::ServerCertificate cert;
        cert.network_id = kTestNetworkHex;
        cert.server_id = "infer-x";
        cert.server_pubkey = crypto::to_base64(c->ed25519_keygen().public_key);
        cert.mesh_pubkey = crypto::to_base64(c->x25519_keygen().public_key);
        cert.issuer_pubkey = crypto::to_base64(root.public_key);
        cert.expires_at = 0;
        auto canon = gossip::canonical_cert_json(cert);
        auto sig = c->ed25519_sign(root.private_key,
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(canon.data()), canon.size()));
        cert.signature = crypto::to_base64(sig);
        return cert;
    }
};

TEST_F(IdentityBindingTest, RejectsWhenNoRoot) {
    make(/*with_root=*/false);
    EXPECT_FALSE(g->verify_identity_binding(signed_cert()));  // hard-fail, no fail-open
}

TEST_F(IdentityBindingTest, AcceptsRootSignedAndRejectsTamper) {
    make(/*with_root=*/true);
    auto cert = signed_cert();
    EXPECT_TRUE(g->verify_identity_binding(cert));

    auto tampered = cert;
    tampered.server_id = "infer-evil";          // not re-signed
    EXPECT_FALSE(g->verify_identity_binding(tampered));

    auto wrong_issuer = cert;
    wrong_issuer.issuer_pubkey = crypto::to_base64(c->ed25519_keygen().public_key);
    EXPECT_FALSE(g->verify_identity_binding(wrong_issuer));
}

// ── Relay bind token (single-use, side-bound) ───────────────────────────────

class RelayBindTest : public ::testing::Test {
protected:
    asio::io_context io;
    std::unique_ptr<crypto::SodiumCryptoService> c;
    std::unique_ptr<relay::RelayService> r;
    // The verified Tier 1 membership the relay checks tickets against. The
    // relay itself is not in it: it is a Tier 2 relay with no tree.
    crypto::Ed25519Keypair member;
    crypto::Ed25519Keypair outsider;
    relay::RelayTicketAuthority authority;
    bool authority_known = true;

    void SetUp() override {
        c = std::make_unique<crypto::SodiumCryptoService>(); c->start();
        member = c->ed25519_keygen();
        outsider = c->ed25519_keygen();
        authority.network_id.fill(0x5A);
        authority.epoch = 7;
        for (int i = 0; i < 4; ++i) {
            security::NodeId other;
            other.bytes = c->ed25519_keygen().public_key;
            authority.members.push_back(other);
        }
        security::NodeId self;
        self.bytes = member.public_key;
        authority.members.push_back(self);
        r = std::make_unique<relay::RelayService>(io, 0, *c);
        r->set_relay_id("relay-1");
        r->set_ticket_authority([this]() -> std::optional<relay::RelayTicketAuthority> {
            if (!authority_known) return std::nullopt;
            return authority;
        });
        r->start();
    }
    void TearDown() override { if (r) r->stop(); if (c) c->stop(); }

    /// A ticket a Tier 1 member issues, as /api/relay/ticket does.
    relay::RelayTicket make_ticket(const crypto::Ed25519Keypair* issuer = nullptr) {
        relay::RelayTicket t;
        t.peer_id = "p"; t.relay_id = "relay-1";
        c->random_bytes(std::span<uint8_t>(t.session_nonce));
        t.issued_at = now_s();
        t.expires_at = t.issued_at + relay::kRelayTicketMaxLifetimeSec;
        t.network_id = authority.network_id;
        t.epoch = authority.epoch.underlying();
        relay::sign_relay_ticket(t, issuer ? *issuer : member);
        return t;
    }

    std::string refusal(const relay::RelayTicket& t) {
        return r->do_allocate(t).error_message;
    }
};

TEST_F(RelayBindTest, TokenGatesBindAndIsSingleUse) {
    auto alloc = r->do_allocate(make_ticket());
    ASSERT_TRUE(alloc.error_message.empty()) << alloc.error_message;
    const auto sid = alloc.session_id;

    auto ta = r->compute_bind_token(sid, 0);
    auto tb = r->compute_bind_token(sid, 1);
    asio::ip::udp::endpoint epA(asio::ip::make_address("198.51.100.1"), 1111);
    asio::ip::udp::endpoint epB(asio::ip::make_address("198.51.100.2"), 2222);

    // Wrong token cannot bind (knowing session_id alone is not enough).
    std::array<uint8_t, 16> garbage{};
    EXPECT_FALSE(r->do_bind(sid, epA, std::span<const uint8_t>(garbage)).success);

    // Valid side-A token binds A.
    EXPECT_TRUE(r->do_bind(sid, epA, std::span<const uint8_t>(ta)).success);
    // Single-use: the same token cannot rebind side A.
    EXPECT_FALSE(r->do_bind(sid, epA, std::span<const uint8_t>(ta)).success);
    // Side-B token binds B.
    EXPECT_TRUE(r->do_bind(sid, epB, std::span<const uint8_t>(tb)).success);
}

TEST_F(RelayBindTest, ReplayedTicketNonceRejected) {
    auto t = make_ticket();
    EXPECT_TRUE(r->do_allocate(t).error_message.empty());
    auto again = r->do_allocate(t);     // same session_nonce
    EXPECT_EQ(again.error_message, "ticket already used");
}

// A Tier 2 relay holds no tree and no session. It accepts a ticket only from
// a current member of the Tier 1 membership it verified.
TEST_F(RelayBindTest, ATier2RelayAcceptsATicketFromACurrentTier1Member) {
    const auto t = make_ticket();
    EXPECT_EQ(r->check_ticket(t), relay::RelayTicketCheck::Valid);
    const auto alloc = r->do_allocate(t);
    EXPECT_TRUE(alloc.error_message.empty()) << alloc.error_message;
    EXPECT_NE(alloc.session_id, relay::SessionId{});
}

TEST_F(RelayBindTest, EveryBadTicketIsRefused) {
    // Forged: a field changed after signing, or a signature by another key.
    auto forged = make_ticket();
    forged.peer_id = "someone-else";
    EXPECT_EQ(r->check_ticket(forged), relay::RelayTicketCheck::BadSignature);
    auto stolen = make_ticket();
    stolen.signature = make_ticket(&outsider).signature;
    EXPECT_EQ(r->check_ticket(stolen), relay::RelayTicketCheck::BadSignature);

    // Expired, overlong, and issued in the future.
    auto expired = make_ticket();
    expired.issued_at = now_s() - 600;
    expired.expires_at = expired.issued_at + 60;
    relay::sign_relay_ticket(expired, member);
    EXPECT_EQ(r->check_ticket(expired), relay::RelayTicketCheck::Expired);
    EXPECT_EQ(refusal(expired), "ticket expired");
    auto overlong = make_ticket();
    overlong.expires_at = overlong.issued_at + 3600;
    relay::sign_relay_ticket(overlong, member);
    EXPECT_EQ(r->check_ticket(overlong), relay::RelayTicketCheck::LifetimeTooLong);
    auto future = make_ticket();
    future.issued_at = now_s() + 3600;
    future.expires_at = future.issued_at + 60;
    relay::sign_relay_ticket(future, member);
    EXPECT_EQ(r->check_ticket(future), relay::RelayTicketCheck::NotYetValid);

    // From a server outside the verified membership.
    EXPECT_EQ(r->check_ticket(make_ticket(&outsider)), relay::RelayTicketCheck::NotMember);

    // For another relay, signed by a real member.
    auto other_relay = make_ticket();
    other_relay.relay_id = "relay-2";
    relay::sign_relay_ticket(other_relay, member);
    EXPECT_EQ(r->check_ticket(other_relay), relay::RelayTicketCheck::WrongRelay);

    // For another epoch, or another network, signed by a real member.
    auto old_epoch = make_ticket();
    old_epoch.epoch = 6;
    relay::sign_relay_ticket(old_epoch, member);
    EXPECT_EQ(r->check_ticket(old_epoch), relay::RelayTicketCheck::WrongEpoch);
    auto foreign = make_ticket();
    foreign.network_id[0] ^= 0x01;
    relay::sign_relay_ticket(foreign, member);
    EXPECT_EQ(r->check_ticket(foreign), relay::RelayTicketCheck::WrongNetwork);

    // Replayed: one allocation per ticket.
    const auto once = make_ticket();
    EXPECT_TRUE(refusal(once).empty());
    EXPECT_EQ(refusal(once), "ticket already used");

    // No verified membership: nothing is accepted.
    authority_known = false;
    EXPECT_EQ(r->check_ticket(make_ticket()), relay::RelayTicketCheck::NoAuthority);

    // None of the refused tickets allocated a session.
    for (const auto& t :
         {forged, stolen, expired, overlong, future, old_epoch, foreign, other_relay}) {
        EXPECT_FALSE(refusal(t).empty());
    }
}

TEST_F(RelayBindTest, ARelayWithoutAMembershipSourceRefusesEveryTicket) {
    relay::RelayService bare(io, 0, *c);
    EXPECT_EQ(bare.check_ticket(make_ticket()), relay::RelayTicketCheck::NoAuthority);
    EXPECT_FALSE(bare.do_allocate(make_ticket()).error_message.empty());
}
