// DNS record-delta origin verification after a restart, driven through the
// REAL implementation. The origin check in GossipService::handle_dns_record_sync
// runs AFTER the immediate-sender certificate gate and requires the ORIGINAL
// signer to be enrolled in the receiver's own peer table. A node's own key is
// never placed in its own table, so a restarted origin denies a replay of its
// own delta (S_SelfOriginReplay); an enrolled third-party origin passes
// (T_ThirdPartyOrigin); an unknown signer and a corrupted signature fail their
// own sub-conditions (T_MissingEnrollment, T_BadSignature).
//
// Conventions and fixture state match tests/test_gossip_ingress_security.cpp;
// no verification logic is mocked. There is no production re-push for DNS
// deltas, so restart scenarios re-inject the byte-for-byte forward captured
// from a real peer — the only non-production step; every check the receiving
// instance runs is the real one. Applied deltas are observed through a REAL A
// query to the node's own DNS service (do_resolve never reads zone_records_,
// so `resolve` would miss every delta these tests apply).

#include <LemonadeNexus/Core/ServerIdentity.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Gossip/GossipTypes.hpp>
#include <LemonadeNexus/Gossip/ServerCertificate.hpp>
#include <LemonadeNexus/Network/DnsService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>

#include "support/gossip_fixture.hpp"

#include <asio.hpp>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using namespace nexus;
namespace fs = std::filesystem;
using asio::ip::udp;

namespace {

// The friend seam, Node and wire fixture live in support/gossip_fixture.hpp.
using nexus_test::kTestNetworkHex;
using nexus_test::msgpack_of;
using Node = nexus_test::GossipTestNode;

class DnsOriginReplayTest : public nexus_test::GossipWireFixture {
protected:
    DnsOriginReplayTest() : GossipWireFixture("nexus_test_dns_origin_replay_") {}

    void stop_node_services(Node& n) override {
        if (n.dns) n.dns->stop();
        if (n.tree) n.tree->stop();
    }

    // The DNS service IS started: applied deltas are observed through real A
    // queries, and its UDP receive loop runs on the shared io_context.
    void attach_dns(Node& n) {
        n.tree = std::make_unique<tree::PermissionTreeService>(*n.storage, *n.crypto);
        n.tree->start();
        n.dns = std::make_unique<network::DnsService>(io, 0, *n.tree, "lemonade-nexus.io");
        n.dns->start();
    }

    // Parse a single-A-answer DNS response: returns the RDATA dotted-quad,
    // nullopt on NXDOMAIN/malformed. Standard header: flags @2-3, QDCOUNT
    // @4-5, ANCOUNT @6-7; the A record's 4-byte RDATA is the tail of the
    // datagram.
    static std::optional<std::string> parse_a_response(const std::vector<uint8_t>& r) {
        if (r.size() < 16) return std::nullopt;
        const bool qr = (r[2] & 0x80) != 0;
        const int opcode = (r[2] >> 3) & 0xF;
        const uint16_t ancount = static_cast<uint16_t>((r[6] << 8) | r[7]);
        if (!qr || opcode != 0 || ancount < 1) return std::nullopt;
        const auto* ip = r.data() + r.size() - 4;
        return std::to_string(ip[0]) + "." + std::to_string(ip[1]) + "." +
               std::to_string(ip[2]) + "." + std::to_string(ip[3]);
    }

    // Zone observation: a real A query to the node's own DNS service, answered
    // from zone_records_ — the same store apply_remote_delta writes.
    std::optional<std::string> zone_a(Node& n, const std::string& fqdn) {
        const auto q = core::build_dns_query(fqdn, 1, 0x4242);
        udp::socket sock{io, udp::endpoint{udp::v4(), 0}};
        // macOS loopback refuses datagrams larger than the default send buffer.
        sock.set_option(asio::socket_base::send_buffer_size(65536));
        sock.non_blocking(true);
        sock.send_to(asio::buffer(q),
                     udp::endpoint{asio::ip::make_address("127.0.0.1"), n.dns->local_port()});
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(500);
        std::vector<uint8_t> buf(512);
        while (std::chrono::steady_clock::now() < deadline) {
            io.poll();
            asio::error_code ec;
            udp::endpoint from{};
            const auto rlen = sock.receive_from(asio::buffer(buf), from, 0, ec);
            if (ec == asio::error::would_block) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
            if (ec) return std::nullopt;
            buf.resize(rlen);
            return parse_a_response(buf);
        }
        return std::nullopt;
    }

    // restart_node (base) rebuilds only the gossip service; the DnsService is
    // intentionally NOT rebuilt here: the zone is in-memory only, so a
    // restarted process starts with the same empty zone a fresh one would.

    // Common configure: anchor the test root and wire the pure DNS service.
    // The advertised endpoint lets the hello handler confirm it against the
    // observed UDP source (production behavior, not a test shortcut).
    void configure(Node& n, const crypto::Ed25519Keypair& root_kp) {
        n.gossip->set_root_pubkey(root_kp.public_key);
        n.gossip->set_network_id(kTestNetworkHex);
        n.gossip->set_dns(n.dns.get());
        n.gossip->set_our_advertised_endpoint(n.endpoint());
    }

    // Persist an identity keypair AND its matching live server certificate
    // into storage BEFORE the gossip service is constructed, so on_start
    // loads both: the "restart" helper rebuilds the service over the same
    // directory with the SAME identity, and the startup ServerHello passes
    // the proof-of-possession check (packet signer == cert pubkey).
    static void seed_identity(storage::FileStorageService& s,
                              const crypto::Ed25519Keypair& kp,
                              const std::string& server_cert_json) {
        seed_keypair(s, kp);
        storage::SignedEnvelope env;
        env.type = "server_certificate";
        env.data = server_cert_json;
        ASSERT_TRUE(s.write_file("identity", "server_cert.json", env));
    }
};

}  // namespace

// ---------------------------------------------------------------------------
// S: self-origin replay after restart
// ---------------------------------------------------------------------------

// The origin A signs a real delta through the production sign path; B applies
// it over real UDP and B's REAL epidemic forward is captured on a raw socket.
// A is then restarted as a fresh instance A2 over the same storage: same
// keypair, same persisted peer table (B, certified), its own key ABSENT from
// its own peer table — the production shape. Re-injecting B's captured
// forward must be DENIED: the sender gate passes (B certified) and the
// signature and canonical preimage are genuine, so the only failing
// sub-condition is origin enrollment of A's own key. Zone unchanged, no crash.
TEST_F(DnsOriginReplayTest, S_SelfOriginReplay) {
    auto root_kp = kc->ed25519_keygen();
    auto a_kp    = kc->ed25519_keygen();  // A/A2 identity — persisted, survives restart
    auto b_kp    = kc->ed25519_keygen();
    const auto a_b64 = crypto::to_base64(a_kp.public_key);
    const auto b_b64 = crypto::to_base64(b_kp.public_key);
    const auto a_cert = issue_cert(a_b64, "srv-a", root_kp);
    const auto b_cert = issue_cert(b_b64, "srv-b", root_kp);
    const std::string fqdn = "svc-a.us-east.lemonade-nexus.io";

    // A1: identity + own live cert pre-seeded (fixture state); peer table
    // empty at first — B joins via the real ServerHello exchange below.
    auto& a = make_node(
        "a",
        [&](Node& n) {
            attach_dns(n);
            seed_identity(*n.storage, a_kp, a_cert);
        },
        [&](Node& n) { configure(n, root_kp); });

    // B: identity + own cert, and A seeded by endpoint WITH A's cert
    // (fixture state: pre-seeded peer cert) so the delta below is applied.
    auto& b = make_node(
        "b",
        [&](Node& n) {
            attach_dns(n);
            seed_identity(*n.storage, b_kp, b_cert);
            seed_peers(*n.storage, nlohmann::json::array(
                {peer_entry(a_b64, a.endpoint(), a_cert)}));
        },
        [&](Node& n) { configure(n, root_kp); });

    // Positive path, leg 1: B's startup ServerHello carries B's cert; A's
    // real hello handler adopts it (proof-of-possession binds it to B's
    // observed endpoint). Wait until A's table cert-verifies B, then make B
    // an explicit peer of A (endpoint refresh; the cert is already stored).
    ASSERT_TRUE(pump_until([&] { return a.certified_peer(b_b64); }));
    a.gossip->add_peer(b.endpoint(), b_b64);

    // Capture socket: a bare UDP peer of B that records B's forward. The
    // forward loop validates no certificate before sending to a tracked
    // endpoint, so an empty identity entry is fine.
    udp::socket cap{io, udp::endpoint{udp::v4(), 0}};
    b.gossip->add_peer("127.0.0.1:" + std::to_string(cap.local_endpoint().port()), "");

    const auto serial_before = a.dns->soa_serial();
    const auto b_serial_before = b.dns->soa_serial();
    ASSERT_FALSE(zone_a(b, fqdn).has_value());

    // A signs and broadcasts through the production sign path: signer_pubkey =
    // own key, canonical data fields signed, msgpack wire, sent to every peer.
    gossip::DnsRecordDelta d{};
    d.delta_id    = "dns-origin-replay-1";
    d.operation   = "set";
    d.fqdn        = fqdn;
    d.record_type = "A";
    d.value       = "10.9.30.40";
    d.ttl         = 60;
    d.timestamp   = 1700000000;
    a.gossip->broadcast_dns_record_delta(d);

    // Positive path: B applies the delta to its zone (a real A query to B's
    // own service now answers it) AND B's real forward reaches the capture
    // socket. (UDP available() reports the pending datagram's byte count, so
    // > 0 means a datagram is queued.)
    ASSERT_TRUE(pump_until([&] {
        return zone_a(b, fqdn).has_value() && cap.available() > 0;
    }));
    EXPECT_EQ(zone_a(b, fqdn).value_or(""), "10.9.30.40");
    EXPECT_NE(b.dns->soa_serial(), b_serial_before);

    std::vector<uint8_t> fwd(2048);
    udp::endpoint from{};
    const std::size_t fwd_len = cap.receive_from(asio::buffer(fwd), from);
    fwd.resize(fwd_len);
    // The captured bytes are B's REAL forward: packet-signed by B (B is the
    // immediate sender at the wire level), payload untouched (A's delta).
    ASSERT_EQ(from, b.udp_endpoint());
    ASSERT_GE(fwd.size(), gossip::kGossipHeaderSize);
    gossip::GossipPacketHeader fwd_hdr{};
    std::memcpy(&fwd_hdr, fwd.data(), gossip::kGossipHeaderSize);
    EXPECT_EQ(fwd_hdr.msg_type, gossip::GossipMsgType::DnsRecordSync);

    // Model A's restart: fresh GossipService over the SAME storage. The
    // keypair and peer table (B, with cert, saved by A1's on_stop) are
    // re-loaded; A's own key is not among them.
    restart_node(a, [&](Node& n) { configure(n, root_kp); });

    // Fixture state of the restarted instance A2, asserted individually so
    // the expected branch below is uniquely determined:
    EXPECT_EQ(a.pubkey_b64(), a_b64);             // same identity keypair
    EXPECT_TRUE(a.certified_peer(b_b64));         // sender B still enrolled
    EXPECT_FALSE(a.certified_peer(a_b64));        // own key NOT self-enrolled
    ASSERT_FALSE(zone_a(a, fqdn).has_value());  // zone still empty
    EXPECT_EQ(a.dns->soa_serial(), serial_before);

    // Labelled injection: the exact bytes of B's production forward, re-sent
    // at A2 with B as immediate sender (no production re-push exists).
    inject(fwd, a);
    pump_for(std::chrono::milliseconds(300));

    // DENIED: origin enrollment of A's own key fails; zone unchanged, no crash.
    EXPECT_FALSE(zone_a(a, fqdn).has_value());
    EXPECT_EQ(a.dns->soa_serial(), serial_before);
    // B still holds the record: the delta itself is healthy everywhere; only
    // the origin's self-enrollment is absent on the restarted origin.
    EXPECT_TRUE(zone_a(b, fqdn).has_value());
}

// ---------------------------------------------------------------------------
// T: third-party origin (positive control)
// ---------------------------------------------------------------------------

// Positive control: an enrolled third-party signer C signs through the
// production path; B's REAL forward is captured and re-injected into fresh
// receiver R. The origin check must PASS for a signer that is not the
// immediate sender, proving S's denial is origin enrollment.
TEST_F(DnsOriginReplayTest, T_ThirdPartyOrigin) {
    auto root_kp = kc->ed25519_keygen();
    auto r_kp    = kc->ed25519_keygen();
    auto b_kp    = kc->ed25519_keygen();
    auto c_kp    = kc->ed25519_keygen();
    const auto r_b64 = crypto::to_base64(r_kp.public_key);
    const auto b_b64 = crypto::to_base64(b_kp.public_key);
    const auto c_b64 = crypto::to_base64(c_kp.public_key);
    const auto b_cert = issue_cert(b_b64, "srv-b", root_kp);
    const auto c_cert = issue_cert(c_b64, "srv-c", root_kp);
    const std::string fqdn = "svc-c.us-east.lemonade-nexus.io";

    // R: a fresh instance with pre-seeded peer certs for B and C at DISTINCT
    // placeholder endpoints; R never sends to them, and the certificate gate
    // is pubkey-based.
    auto& r = make_node(
        "r",
        [&](Node& n) {
            attach_dns(n);
            seed_identity(*n.storage, r_kp, issue_cert(r_b64, "srv-r", root_kp));
            seed_peers(*n.storage, nlohmann::json::array(
                {peer_entry(b_b64, "127.0.0.1:1", b_cert),
                 peer_entry(c_b64, "127.0.0.1:2", c_cert)}));
        },
        [&](Node& n) { configure(n, root_kp); });

    // B: knows C's cert (fixture state: pre-seeded peer cert) so B applies
    // C's delta and forwards.
    auto& b = make_node(
        "b",
        [&](Node& n) {
            attach_dns(n);
            seed_identity(*n.storage, b_kp, b_cert);
            seed_peers(*n.storage, nlohmann::json::array(
                {peer_entry(c_b64, "127.0.0.1:1", c_cert)}));
        },
        [&](Node& n) { configure(n, root_kp); });

    // C: the origin. Knows B's real endpoint so its production broadcast
    // reaches B (fixture state: pre-seeded peer entry with B's cert).
    auto& c = make_node(
        "c",
        [&](Node& n) {
            attach_dns(n);
            seed_identity(*n.storage, c_kp, c_cert);
            seed_peers(*n.storage, nlohmann::json::array(
                {peer_entry(b_b64, b.endpoint(), b_cert)}));
        },
        [&](Node& n) { configure(n, root_kp); });
    b.gossip->add_peer(c.endpoint(), c_b64);

    // Capture socket: bare UDP peer of B for the forward (empty identity,
    // never validated before sending).
    udp::socket cap{io, udp::endpoint{udp::v4(), 0}};
    b.gossip->add_peer("127.0.0.1:" + std::to_string(cap.local_endpoint().port()), "");

    ASSERT_FALSE(zone_a(r, fqdn).has_value());
    const auto serial_before = r.dns->soa_serial();

    // C signs and broadcasts through the production sign path.
    gossip::DnsRecordDelta d{};
    d.delta_id    = "dns-third-party-1";
    d.operation   = "set";
    d.fqdn        = fqdn;
    d.record_type = "A";
    d.value       = "10.11.12.13";
    d.ttl         = 60;
    d.timestamp   = 1700000001;
    c.gossip->broadcast_dns_record_delta(d);

    // B applies (sender C certified in B's table; origin C certified) and
    // forwards to the capture socket.
    ASSERT_TRUE(pump_until([&] {
        return zone_a(b, fqdn).has_value() && cap.available() > 0;
    }));

    std::vector<uint8_t> fwd(2048);
    udp::endpoint from{};
    fwd.resize(cap.receive_from(asio::buffer(fwd), from));
    ASSERT_EQ(from, b.udp_endpoint());  // B is the immediate (forwarding) sender
    ASSERT_GE(fwd.size(), gossip::kGossipHeaderSize);
    gossip::GossipPacketHeader fwd_hdr{};
    std::memcpy(&fwd_hdr, fwd.data(), gossip::kGossipHeaderSize);
    EXPECT_EQ(fwd_hdr.msg_type, gossip::GossipMsgType::DnsRecordSync);

    // LABELLED INJECTION: B's real forward, re-sent at fresh receiver R
    // (no production re-push exists; this is the delivery step).
    inject(fwd, r);
    ASSERT_TRUE(pump_until([&] { return zone_a(r, fqdn).has_value(); }));
    EXPECT_EQ(zone_a(r, fqdn).value_or(""), "10.11.12.13");
    EXPECT_NE(r.dns->soa_serial(), serial_before);
}

// ---------------------------------------------------------------------------
// T: unknown signer (no enrollment)
// ---------------------------------------------------------------------------

// Signer D has no certificate in R's peer table: the origin check must fail
// at the enrollment sub-condition. No production forwarder would emit these
// bytes, so this is a labelled direct injection of a B-signed datagram.
TEST_F(DnsOriginReplayTest, T_MissingEnrollment) {
    auto root_kp = kc->ed25519_keygen();
    auto r_kp    = kc->ed25519_keygen();
    auto b_kp    = kc->ed25519_keygen();
    auto d_kp    = kc->ed25519_keygen();  // no certificate anywhere
    const auto r_b64 = crypto::to_base64(r_kp.public_key);
    const auto b_b64 = crypto::to_base64(b_kp.public_key);
    const auto d_b64 = crypto::to_base64(d_kp.public_key);
    const std::string fqdn = "svc-d.us-east.lemonade-nexus.io";

    // R: fresh instance; B certified (so the sender gate passes), D absent.
    // Fixture state: pre-seeded peer cert for B only.
    auto& r = make_node(
        "r",
        [&](Node& n) {
            attach_dns(n);
            seed_identity(*n.storage, r_kp, issue_cert(r_b64, "srv-r", root_kp));
            seed_peers(*n.storage, nlohmann::json::array(
                {peer_entry(b_b64, "127.0.0.1:1",
                            issue_cert(b_b64, "srv-b", root_kp))}));
        },
        [&](Node& n) { configure(n, root_kp); });

    const auto serial_before = r.dns->soa_serial();
    ASSERT_FALSE(zone_a(r, fqdn).has_value());

    // D signs a well-formed delta; B packet-signs the datagram.
    const auto payload = dns_delta_payload(d_kp, "dns-missing-1", fqdn, "10.0.0.55");
    inject(build_packet(b_kp, gossip::GossipMsgType::DnsRecordSync, payload), r);
    pump_for(std::chrono::milliseconds(300));

    // Sender gate passes (B certified) — the failure is the origin check's
    // enrollment sub-condition for D. Zone unchanged.
    EXPECT_TRUE(r.certified_peer(b_b64));
    EXPECT_FALSE(r.certified_peer(d_b64));
    EXPECT_FALSE(zone_a(r, fqdn).has_value());
    EXPECT_EQ(r.dns->soa_serial(), serial_before);
}

// ---------------------------------------------------------------------------
// T: corrupted delta signature (signer enrolled)
// ---------------------------------------------------------------------------

// Signer C is enrolled, but one signature character is corrupted after
// signing: the origin check must fail at the Ed25519 verify sub-condition.
// The uncorrupted twin is applied, so the corrupted signature is the only
// difference. Also a labelled direct injection.
TEST_F(DnsOriginReplayTest, T_BadSignature) {
    auto root_kp = kc->ed25519_keygen();
    auto r_kp    = kc->ed25519_keygen();
    auto b_kp    = kc->ed25519_keygen();
    auto c_kp    = kc->ed25519_keygen();
    const auto r_b64 = crypto::to_base64(r_kp.public_key);
    const auto b_b64 = crypto::to_base64(b_kp.public_key);
    const auto c_b64 = crypto::to_base64(c_kp.public_key);
    const auto b_cert = issue_cert(b_b64, "srv-b", root_kp);
    const auto c_cert = issue_cert(c_b64, "srv-c", root_kp);
    const std::string fqdn = "svc-cb.us-east.lemonade-nexus.io";

    // R: fresh instance; B and C both certified at DISTINCT placeholder
    // endpoints.
    auto& r = make_node(
        "r",
        [&](Node& n) {
            attach_dns(n);
            seed_identity(*n.storage, r_kp, issue_cert(r_b64, "srv-r", root_kp));
            seed_peers(*n.storage, nlohmann::json::array(
                {peer_entry(b_b64, "127.0.0.1:1", b_cert),
                 peer_entry(c_b64, "127.0.0.1:2", c_cert)}));
        },
        [&](Node& n) { configure(n, root_kp); });

    const auto serial_before = r.dns->soa_serial();
    ASSERT_FALSE(zone_a(r, fqdn).has_value());

    // Corrupt exactly one character of the base64 signature.
    auto bad = dns_delta_payload(c_kp, "dns-badsig-1", fqdn, "10.0.0.66");
    {
        auto j = nlohmann::json::from_msgpack(bad);
        auto& sig = j["signature"].get_ref<std::string&>();
        sig[0] = sig[0] == 'A' ? 'B' : 'A';
        auto packed = nlohmann::json::to_msgpack(j);
        bad.assign(packed.begin(), packed.end());
    }
    inject(build_packet(b_kp, gossip::GossipMsgType::DnsRecordSync, bad), r);
    pump_for(std::chrono::milliseconds(300));

    // C IS enrolled: the denial cannot be the enrollment sub-condition. It
    // is the Ed25519 verify on the corrupted signature.
    EXPECT_TRUE(r.certified_peer(c_b64));
    EXPECT_FALSE(zone_a(r, fqdn).has_value());
    EXPECT_EQ(r.dns->soa_serial(), serial_before);

    // Control: the uncorrupted twin applies through the same path.
    const auto good = dns_delta_payload(c_kp, "dns-badsig-2", fqdn, "10.0.0.66");
    inject(build_packet(b_kp, gossip::GossipMsgType::DnsRecordSync, good), r);
    ASSERT_TRUE(pump_until([&] { return zone_a(r, fqdn).has_value(); }));
    EXPECT_EQ(zone_a(r, fqdn).value_or(""), "10.0.0.66");
    EXPECT_NE(r.dns->soa_serial(), serial_before);
}
