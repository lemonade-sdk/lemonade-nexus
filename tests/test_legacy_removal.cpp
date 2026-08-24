// M3 proof: the removed network-authority protocol is dead on the wire.
// Retired gossip types 0x07-0x10 (TEE challenge/response, enrollment votes,
// root-key rotation, Shamir shares, peer health, governance) must be dropped
// by TYPE — whatever the sender's trust level — and state-mutating ingress
// (sync deltas, NS slot claims) is gated on a root-signed certificate. Two
// real GossipServices on localhost UDP; hostile packets are raw signed
// datagrams from a non-peer socket. Each drop test carries a payload its
// control PROVES a live type accepts, so only the type byte (or the gate
// under test) explains the refusal.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Gossip/GossipTypes.hpp>
#include <LemonadeNexus/Gossip/ServerCertificate.hpp>
#include <LemonadeNexus/Security/Lifecycle/SecurityMeshService.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>
#include <LemonadeNexus/Security/Transport/SecurityTransport.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <asio.hpp>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

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
// tests/test_gossip_security_transport.cpp, defined inside its namespace).
namespace nexus::gossip {
struct GossipBallotTestAccess {
    static uint16_t port(GossipService& g) { return g.socket_.local_endpoint().port(); }
    // Observation only: reads the slot table so the NS-slot gate test can see
    // whether a claim landed. No test writes private state through this seam.
    static const NsSlotClaimData& ns_slot(GossipService& g, uint8_t slot) {
        return g.ns_slots_[slot - 1];
    }
};
}  // namespace nexus::gossip

namespace {

// The retired wire range. Reserved forever; a packet of any of these types
// must die in the dispatcher, never reach a handler.
constexpr uint8_t kRetiredFirst = 0x07;
constexpr uint8_t kRetiredLast  = 0x10;

struct Delivery {
    security::NodeId     sender;
    std::vector<uint8_t> bytes;
};

struct Node {
    fs::path dir;
    std::unique_ptr<crypto::SodiumCryptoService>   crypto;
    std::unique_ptr<storage::FileStorageService>   storage;
    std::unique_ptr<crypto::KeyWrappingService>    wrapping;
    std::unique_ptr<gossip::GossipService>         gossip;
    std::unique_ptr<security::SecurityMeshService> mesh;
    std::vector<Delivery>                          received;

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

class LegacyRemovalTest : public ::testing::Test {
protected:
    // Declared before the nodes so it outlives their sockets and timers.
    asio::io_context io;
    fs::path root;
    std::vector<std::unique_ptr<Node>> nodes;

    void SetUp() override {
        root = fs::temp_directory_path() /
               ("nexus_test_legacy_removal_" + std::to_string(getpid()));
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

    // Every node shares one io_context that the test thread pumps, so sinks
    // run on the test thread and `received` needs no lock. `seed` runs before
    // the gossip service exists (to pre-place storage state such as a peer
    // list); `configure` runs on the constructed service before start().
    Node& make_node(const std::string& tag, bool with_sink = true,
                    const std::function<void(Node&)>& seed = {},
                    const std::function<void(gossip::GossipService&)>& configure = {}) {
        auto n = std::make_unique<Node>();
        n->dir = root / tag;
        fs::create_directories(n->dir);
        n->crypto = std::make_unique<crypto::SodiumCryptoService>();
        n->crypto->start();
        n->storage = std::make_unique<storage::FileStorageService>(n->dir);
        n->storage->start();
        n->wrapping = std::make_unique<crypto::KeyWrappingService>(*n->crypto, *n->storage);
        n->wrapping->start();
        if (seed) seed(*n);
        n->gossip = std::make_unique<gossip::GossipService>(io, 0, *n->storage, *n->crypto);
        if (configure) configure(*n->gossip);
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

    // The gossip identity exists only after gossip->start(), so the mesh
    // service is built afterwards — the same order main.cpp uses. Mesh nodes
    // take no test sink: the mesh owns the security sink.
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

    // A raw packet in gossip framing, signed by `kp` (the shape send_packet
    // emits), of any message type — including the retired ones.
    static std::vector<uint8_t> build_packet(crypto::SodiumCryptoService& c,
                                             const crypto::Ed25519Keypair& kp,
                                             gossip::GossipMsgType msg_type,
                                             const std::vector<uint8_t>& payload) {
        gossip::GossipPacketHeader h{};
        h.magic    = gossip::kGossipMagic;
        h.version  = gossip::kGossipVersion;
        h.msg_type = msg_type;
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

    // One correctly signed packet of every retired type at `target`. The
    // payload matters: callers pass bytes a control PROVES a live type
    // accepts from the same sender, so a handler reached by a regressed
    // dispatcher could not quietly reject them as unparseable — the type byte
    // is the only variable.
    void inject_all_retired(crypto::SodiumCryptoService& c,
                            const crypto::Ed25519Keypair& signer, Node& target,
                            const std::vector<uint8_t>& payload) {
        for (uint8_t t = kRetiredFirst; t <= kRetiredLast; ++t) {
            inject(build_packet(c, signer, static_cast<gossip::GossipMsgType>(t), payload),
                   target);
        }
    }

    // Seed a peer list into storage BEFORE gossip starts, so load_peers()
    // adopts the entries (including any stored certificate).
    static void seed_peers(storage::FileStorageService& s, const nlohmann::json& arr) {
        storage::SignedEnvelope env;
        env.type = "peer_list";
        env.data = nlohmann::json{{"peers", arr}}.dump();
        ASSERT_TRUE(s.write_file("identity", "peers.json", env));
    }

    static nlohmann::json peer_entry(const std::string& pubkey_b64,
                                     const std::string& endpoint,
                                     const std::string& cert_json) {
        return {{"pubkey", pubkey_b64}, {"endpoint", endpoint},
                {"certificate_json", cert_json}};
    }

    // A delta signed exactly the way do_handle_deltas verifies one. The delta
    // signature is self-consistent by design; ADMISSION of the delta is what
    // the cert gate decides.
    static nlohmann::json make_signed_delta(crypto::SodiumCryptoService& c,
                                            const crypto::Ed25519Keypair& signer,
                                            const std::string& target_node_id,
                                            uint64_t seq) {
        const nlohmann::json data{{"k", "v"}};
        const std::string operation = "update_node";
        const std::string permission;
        const uint64_t timestamp = 1;
        const std::string canonical =
            operation + "\n" + target_node_id + "\n" + std::to_string(seq) + "\n" +
            permission + "\n" + std::to_string(timestamp) + "\n" + data.dump();
        auto sig = c.ed25519_sign(signer.private_key,
                                  std::vector<uint8_t>(canonical.begin(), canonical.end()));
        return {
            {"sequence", seq},
            {"operation", operation},
            {"target_node_id", target_node_id},
            {"data", data},
            {"signer_pubkey", crypto::to_base64(signer.public_key)},
            {"required_permission", permission},
            {"timestamp", timestamp},
            {"signature", crypto::to_base64(sig)},
        };
    }

    static std::vector<uint8_t> delta_response_payload(const nlohmann::json& delta) {
        return bytes_of(nlohmann::json{{"deltas", nlohmann::json::array({delta})},
                                       {"from_seq", 0}}
                            .dump());
    }
};

}  // namespace

// (a) Every retired type, correctly signed, carrying arbitrary payload: the
// receiver drops it in the dispatcher — no crash, no peer change, no state
// change, no security sink — and normal traffic still flows afterwards.
TEST_F(LegacyRemovalTest, RetiredWireTypesAreDroppedByType) {
    auto& a = make_node("a");
    auto& b = make_node("b");
    peer_all();

    const auto peers_before = a.gossip->get_peers();

    // The payload is exactly what the control below delivers to the security
    // sink under the live SecurityEnvelope type; under the retired types the
    // sink must stay empty.
    const auto payload = bytes_of("same-bytes-either-way");
    inject_all_retired(*b.crypto, b.gossip->keypair(), a, payload);
    pump_for(std::chrono::milliseconds(300));

    // No handler ran: no sink delivery, no delta applied, no peer set change.
    EXPECT_TRUE(a.received.empty());
    EXPECT_EQ(a.storage->latest_delta_seq(), 0u);
    const auto peers_after = a.gossip->get_peers();
    ASSERT_EQ(peers_after.size(), peers_before.size());
    for (std::size_t i = 0; i < peers_after.size(); ++i) {
        EXPECT_EQ(peers_after[i].pubkey, peers_before[i].pubkey);
    }

    // Control on the SAME delivery path: the identical bytes from the
    // identical raw socket, now under the live SecurityEnvelope type, reach
    // the sink. Injection works; the retired types died on type alone.
    inject(build_packet(*b.crypto, b.gossip->keypair(),
                        gossip::GossipMsgType::SecurityEnvelope, payload),
           a);
    ASSERT_TRUE(pump_until([&] { return !a.received.empty(); }));
    ASSERT_EQ(a.received.size(), 1u);
    EXPECT_EQ(a.received[0].sender.bytes, b.pubkey());
    EXPECT_EQ(a.received[0].bytes, payload);
}

// (b) The drop is by type, not by trust: a sender holding a VALID root-signed
// certificate is refused identically. Control: the same sender's cert DOES
// clear the gate on a live message class, so trust was never the reason.
TEST_F(LegacyRemovalTest, RetiredTypeFromCertifiedPeerIsEquallyDead) {
    auto& b = make_node("b");
    auto root_kp = b.crypto->ed25519_keygen();

    gossip::CertIssueParams p;
    p.server_pubkey_b64 = b.pubkey_b64();
    p.server_id         = "peer-b";
    const auto cert_json = nlohmann::json(
        gossip::issue_server_certificate(p, *b.crypto, root_kp.private_key,
                                         root_kp.public_key)).dump();

    auto& a = make_node(
        "a", /*with_sink=*/true,
        [&](Node& n) {
            seed_peers(*n.storage, nlohmann::json::array(
                {peer_entry(b.pubkey_b64(), b.endpoint(), cert_json)}));
        },
        [&](gossip::GossipService& g) { g.set_root_pubkey(root_kp.public_key); });

    // The payload is a delta the control below PROVES this certified sender
    // can apply; under the retired types it must change nothing. If a
    // regressed dispatcher routed a retired type into handle_delta_response,
    // the sender's real certificate would clear the gate and the delta would
    // apply — so the only thing standing between these packets and a state
    // change is the type byte.
    const auto delta = make_signed_delta(*b.crypto, b.gossip->keypair(), "node-b", 1);
    inject_all_retired(*b.crypto, b.gossip->keypair(), a, delta_response_payload(delta));
    pump_for(std::chrono::milliseconds(300));

    EXPECT_TRUE(a.received.empty());
    EXPECT_EQ(a.storage->latest_delta_seq(), 0u);

    // Control: the SAME bytes from the SAME identity under the live
    // DeltaResponse type are accepted. The retired types died on type alone.
    inject(build_packet(*b.crypto, b.gossip->keypair(),
                        gossip::GossipMsgType::DeltaResponse,
                        delta_response_payload(delta)),
           a);
    ASSERT_TRUE(pump_until([&] { return a.storage->latest_delta_seq() == 1; }));
    EXPECT_TRUE(a.received.empty());  // sync is not a security envelope
}

// (c) The cert-gate replacement rule: state-mutating sync ingress requires the
// packet signer to hold a root-signed certificate. A known but unenrolled
// peer changes nothing; the cert-verified peer's identical message applies.
// Real path throughout: issue_server_certificate with a test root key, the
// certificate stored in the receiver's peer list — no predicate seam.
TEST_F(LegacyRemovalTest, StateMutatingSyncRequiresRootSignedCertificate) {
    auto& b = make_node("b");
    auto root_kp = b.crypto->ed25519_keygen();

    gossip::CertIssueParams p;
    p.server_pubkey_b64 = b.pubkey_b64();
    p.server_id         = "peer-b";
    const auto cert_json = nlohmann::json(
        gossip::issue_server_certificate(p, *b.crypto, root_kp.private_key,
                                         root_kp.public_key)).dump();

    auto& a = make_node(
        "a", /*with_sink=*/true,
        [&](Node& n) {
            seed_peers(*n.storage, nlohmann::json::array(
                {peer_entry(b.pubkey_b64(), b.endpoint(), cert_json)}));
        },
        [&](gossip::GossipService& g) { g.set_root_pubkey(root_kp.public_key); });

    // A known peer WITHOUT a certificate: peer-list membership is not trust.
    auto unenrolled = b.crypto->ed25519_keygen();
    a.gossip->add_peer("127.0.0.1:9", crypto::to_base64(unenrolled.public_key));

    // Unenrolled sender: a validly signed delta must not mutate any state.
    const auto hostile = make_signed_delta(*b.crypto, unenrolled, "node-x", 1);
    inject(build_packet(*b.crypto, unenrolled, gossip::GossipMsgType::DeltaResponse,
                        delta_response_payload(hostile)),
           a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_EQ(a.storage->latest_delta_seq(), 0u);

    // Cert-verified sender: the same shape applies.
    const auto honest = make_signed_delta(*b.crypto, b.gossip->keypair(), "node-b", 1);
    inject(build_packet(*b.crypto, b.gossip->keypair(),
                        gossip::GossipMsgType::DeltaResponse,
                        delta_response_payload(honest)),
           a);
    ASSERT_TRUE(pump_until([&] { return a.storage->latest_delta_seq() == 1; }));
    const auto applied = a.storage->read_delta(1);
    ASSERT_TRUE(applied.has_value());
    EXPECT_EQ(applied->target_node_id, "node-b");
    EXPECT_EQ(applied->signer_pubkey, b.pubkey_b64());
}

// (d) With the full security mesh attached, retired-type packets leave the
// security plane untouched. The control proves the SAME payload moves real
// security state under the live ServerHello type: the verified certificate
// fires the peer-certified callback, and the genesis authority admits the
// peer and spends an attestation challenge on it.
TEST_F(LegacyRemovalTest, RetiredTypesDoNotTouchSecurityState) {
    auto& b = make_node("b", /*with_sink=*/false);
    auto root_kp = b.crypto->ed25519_keygen();

    gossip::CertIssueParams p;
    p.server_pubkey_b64 = b.pubkey_b64();
    p.server_id         = "peer-b";
    const auto cert_json = nlohmann::json(
        gossip::issue_server_certificate(p, *b.crypto, root_kp.private_key,
                                         root_kp.public_key)).dump();

    auto& a = make_node("a", /*with_sink=*/false, /*seed=*/{},
                        [&](gossip::GossipService& g) {
                            g.set_root_pubkey(root_kp.public_key);
                        });
    peer_all();
    make_mesh(a, a.pubkey());  // A's own identity is the pinned anchor
    make_mesh(b, a.pubkey());

    ASSERT_EQ(a.mesh->driver().phase(), security::DriverPhase::GenesisCollecting);
    ASSERT_EQ(b.mesh->driver().phase(), security::DriverPhase::Idle);
    ASSERT_FALSE(a.mesh->driver().current_epoch().has_value());
    ASSERT_EQ(a.mesh->runtime().epochs(), nullptr);
    ASSERT_EQ(a.mesh->runtime().attestation().attempts(b.id(), 1), 0u);
    ASSERT_FALSE(a.mesh->runtime().attestation().verdict(b.id()).has_value());

    // Retired types carrying the exact hello payload the control proves live.
    const auto hello_payload = bytes_of(cert_json);
    inject_all_retired(*b.crypto, b.gossip->keypair(), a, hello_payload);
    pump_for(std::chrono::milliseconds(400));  // several driver ticks

    // Nothing legacy reached the security plane.
    EXPECT_EQ(a.mesh->driver().phase(), security::DriverPhase::GenesisCollecting);
    EXPECT_EQ(b.mesh->driver().phase(), security::DriverPhase::Idle);
    EXPECT_FALSE(a.mesh->driver().current_epoch().has_value());
    EXPECT_EQ(a.mesh->runtime().epochs(), nullptr);
    EXPECT_EQ(a.mesh->runtime().attestation().attempts(b.id(), 1), 0u);
    EXPECT_FALSE(a.mesh->runtime().attestation().verdict(b.id()).has_value());

    // Control: the SAME bytes under the live ServerHello type clear the real
    // certificate verification and reach the security plane — the genesis
    // authority admits b and spends an attestation challenge on it.
    inject(build_packet(*b.crypto, b.gossip->keypair(),
                        gossip::GossipMsgType::ServerHello, hello_payload),
           a);
    ASSERT_TRUE(pump_until(
        [&] { return a.mesh->runtime().attestation().attempts(b.id(), 1) == 1; }));
    // The live path runs to the end: b answers the challenge and the REAL
    // verifier records a verdict — a failing one, because a dev host has no
    // platform evidence. Fail-closed, and genesis stays uncollected.
    ASSERT_TRUE(pump_until(
        [&] { return a.mesh->runtime().attestation().verdict(b.id()).has_value(); }));
    EXPECT_FALSE(a.mesh->runtime().attestation().verdict(b.id())->passed);
    EXPECT_EQ(a.mesh->driver().phase(), security::DriverPhase::GenesisCollecting);
    EXPECT_FALSE(a.mesh->driver().current_epoch().has_value());
}

// (e) The NS slot registry is state-mutating gossip ingress: a claim needs a
// verifying claimant signature AND a root-signed certificate for the
// claimant. Claims travel epidemically, so the gate binds to the claimant,
// not the forwarding sender. The friend seam only OBSERVES the slot table;
// every stimulus is a real signed datagram through the real dispatcher.
TEST_F(LegacyRemovalTest, NsSlotClaimRequiresCertifiedClaimant) {
    auto& b = make_node("b");
    auto root_kp = b.crypto->ed25519_keygen();

    gossip::CertIssueParams p;
    p.server_pubkey_b64 = b.pubkey_b64();
    p.server_id         = "peer-b";
    const auto cert_json = nlohmann::json(
        gossip::issue_server_certificate(p, *b.crypto, root_kp.private_key,
                                         root_kp.public_key)).dump();

    auto& a = make_node(
        "a", /*with_sink=*/true,
        [&](Node& n) {
            seed_peers(*n.storage, nlohmann::json::array(
                {peer_entry(b.pubkey_b64(), b.endpoint(), cert_json)}));
        },
        [&](gossip::GossipService& g) { g.set_root_pubkey(root_kp.public_key); });

    // A claim exactly as try_claim_ns_slot signs one: canonical JSON of the
    // claim fields, signed by the claimant, msgpack on the wire.
    auto claim_payload = [&](const crypto::Ed25519Keypair& claimant, uint8_t slot,
                             bool valid_sig) {
        nlohmann::json sign_payload;
        sign_payload["slot"]          = slot;
        sign_payload["server_pubkey"] = crypto::to_base64(claimant.public_key);
        sign_payload["server_ip"]     = "10.0.0.7";
        sign_payload["region"]        = "eu-west";
        sign_payload["timestamp"]     = uint64_t{1000};
        const auto sign_data = sign_payload.dump();
        auto sig = b.crypto->ed25519_sign(
            claimant.private_key,
            std::span<const uint8_t>(
                reinterpret_cast<const uint8_t*>(sign_data.data()), sign_data.size()));
        nlohmann::json wire = sign_payload;
        wire["signature"] = valid_sig ? crypto::to_base64(sig) : std::string("QkFEQkFE");
        auto packed = nlohmann::json::to_msgpack(wire);
        return std::vector<uint8_t>(packed.begin(), packed.end());
    };
    auto slot_holder = [&](uint8_t slot) {
        return gossip::GossipBallotTestAccess::ns_slot(*a.gossip, slot).server_pubkey;
    };

    // An unenrolled claimant with a correct self-signature: refused.
    auto unenrolled = b.crypto->ed25519_keygen();
    inject(build_packet(*b.crypto, unenrolled, gossip::GossipMsgType::NsSlotClaim,
                        claim_payload(unenrolled, 3, true)),
           a);
    // The certified claimant with a broken signature: refused.
    inject(build_packet(*b.crypto, b.gossip->keypair(), gossip::GossipMsgType::NsSlotClaim,
                        claim_payload(b.gossip->keypair(), 3, false)),
           a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_TRUE(slot_holder(3).empty());

    // Control: the certified claimant with a verifying signature takes the
    // slot. The refusals above were the gate, not a broken claim shape.
    inject(build_packet(*b.crypto, b.gossip->keypair(), gossip::GossipMsgType::NsSlotClaim,
                        claim_payload(b.gossip->keypair(), 3, true)),
           a);
    ASSERT_TRUE(pump_until([&] { return slot_holder(3) == b.pubkey_b64(); }));
}
