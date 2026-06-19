#include <LemonadeNexus/Routing/ConnectionTicket.hpp>
#include <LemonadeNexus/Routing/RoutingTypes.hpp>
#include <LemonadeNexus/Relay/RelayService.hpp>
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
        if (with_root) g->set_root_pubkey(root.public_key);
    }
    void TearDown() override {
        if (g) g->stop(); if (s) s->stop(); if (c) c->stop();
        if (!dir.empty()) fs::remove_all(dir);
    }
    gossip::ServerCertificate signed_cert() {
        gossip::ServerCertificate cert;
        cert.server_id = "infer-x";
        cert.server_pubkey = crypto::to_base64(c->ed25519_keygen().public_key);
        cert.wg_pubkey = crypto::to_base64(c->x25519_keygen().public_key);
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
    crypto::Ed25519Keypair central;

    void SetUp() override {
        c = std::make_unique<crypto::SodiumCryptoService>(); c->start();
        central = c->ed25519_keygen();
        r = std::make_unique<relay::RelayService>(io, 0, *c, central.public_key);
        r->start();
    }
    void TearDown() override { if (r) r->stop(); if (c) c->stop(); }

    relay::RelayTicket make_ticket() {
        relay::RelayTicket t;
        t.peer_id = "p"; t.relay_id = "relay-1";
        c->random_bytes(std::span<uint8_t>(t.session_nonce));
        t.issued_at = now_s(); t.expires_at = t.issued_at + 300;
        std::vector<uint8_t> canon;  // peer_id||relay_id||nonce||issued(8LE)||expires(8LE)
        canon.insert(canon.end(), t.peer_id.begin(), t.peer_id.end());
        canon.insert(canon.end(), t.relay_id.begin(), t.relay_id.end());
        canon.insert(canon.end(), t.session_nonce.begin(), t.session_nonce.end());
        auto le = [&](uint64_t v){ for(int i=0;i<8;++i){canon.push_back(v&0xFF); v>>=8;} };
        le(t.issued_at); le(t.expires_at);
        auto sig = c->ed25519_sign(central.private_key, std::span<const uint8_t>(canon));
        std::memcpy(t.signature.data(), sig.data(), sig.size());
        return t;
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
