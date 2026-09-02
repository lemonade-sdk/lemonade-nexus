// Hostile wire-level tests for gossip ingress gating.
//
// Every state-mutating gossip message class is driven by raw, correctly signed
// datagrams sent from a non-peer UDP socket into a real GossipService with the
// real downstream services attached (ACLService, DnsService, IPAMService). The
// certificate path is the real one: gossip::issue_server_certificate signs with
// a test root key and set_root_pubkey anchors it — no fake certificate blob and
// no predicate seam ever stands in for the gate.
//
// Every refusal test carries a POSITIVE CONTROL that pushes the SAME bytes (or
// the same shape with exactly one field changed) through the SAME path and
// proves the mechanism applies them. A negative assertion therefore cannot pass
// because the payload was unparseable, the service was unwired, or the effect
// was unobservable.

#include <LemonadeNexus/ACL/ACLService.hpp>
#include <LemonadeNexus/ACL/Permission.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Gossip/GossipTypes.hpp>
#include <LemonadeNexus/Gossip/MisbehaviorDetector.hpp>
#include <LemonadeNexus/Gossip/ServerCertificate.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <LemonadeNexus/IPAM/IPAMTypes.hpp>
#include <LemonadeNexus/Network/DnsService.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>

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

// Observation-only friend seam. The bound port, the NS slot table, the
// revocation set and the certificate gate are private state that sits behind
// packet-signature verification and a bound socket; a test cannot reach them
// through the public surface. No test WRITES private state through this seam —
// every stimulus is a real signed datagram through the real dispatcher.
namespace nexus::gossip {
struct GossipBallotTestAccess {
    static uint16_t port(GossipService& g) { return g.socket_.local_endpoint().port(); }
    static const NsSlotClaimData& ns_slot(GossipService& g, uint8_t slot) {
        return g.ns_slots_[slot - 1];
    }
    static bool revoked(GossipService& g, const std::string& pubkey) {
        return g.is_revoked(pubkey);
    }
    static bool certified(GossipService& g, const std::string& pubkey) {
        return g.peer_certificate_is_root_signed(pubkey);
    }
};
}  // namespace nexus::gossip

namespace {

// Certificates bind to a network id; one value serves every fixture.
inline const std::string kTestNetworkHex(64, 'a');

struct Node {
    fs::path dir;
    std::unique_ptr<crypto::SodiumCryptoService>   crypto;
    std::unique_ptr<storage::FileStorageService>   storage;
    std::unique_ptr<acl::ACLService>               acl;
    std::unique_ptr<ipam::IPAMService>             ipam;
    std::unique_ptr<tree::PermissionTreeService>   tree;
    std::unique_ptr<network::DnsService>           dns;
    std::unique_ptr<gossip::GossipService>         gossip;
    // Every peer the ServerHello handler reported as certificate-verified.
    std::vector<security::NodeId>                  certified;

    [[nodiscard]] const crypto::Ed25519PublicKey& pubkey() const {
        return gossip->keypair().public_key;
    }
    [[nodiscard]] std::string pubkey_b64() const { return crypto::to_base64(pubkey()); }
    [[nodiscard]] uint16_t port() { return gossip::GossipBallotTestAccess::port(*gossip); }
    [[nodiscard]] std::string endpoint() { return "127.0.0.1:" + std::to_string(port()); }
    [[nodiscard]] udp::endpoint udp_endpoint() {
        return udp::endpoint{asio::ip::make_address("127.0.0.1"), port()};
    }
    [[nodiscard]] bool revoked(const std::string& pk) {
        return gossip::GossipBallotTestAccess::revoked(*gossip, pk);
    }
    [[nodiscard]] bool certified_peer(const std::string& pk) {
        return gossip::GossipBallotTestAccess::certified(*gossip, pk);
    }
    [[nodiscard]] bool has_peer(const std::string& pk) {
        for (const auto& p : gossip->get_peers()) {
            if (p.pubkey == pk) return true;
        }
        return false;
    }
    [[nodiscard]] std::string peer_cert_json(const std::string& pk) {
        for (const auto& p : gossip->get_peers()) {
            if (p.pubkey == pk) return p.certificate_json;
        }
        return {};
    }
    [[nodiscard]] std::string ns_holder(uint8_t slot) {
        return gossip::GossipBallotTestAccess::ns_slot(*gossip, slot).server_pubkey;
    }
};

std::vector<uint8_t> bytes_of(std::string_view s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

std::vector<uint8_t> msgpack_of(const nlohmann::json& j) {
    auto packed = nlohmann::json::to_msgpack(j);
    return std::vector<uint8_t>(packed.begin(), packed.end());
}

class GossipIngressSecurityTest : public ::testing::Test {
protected:
    // Declared before the nodes so it outlives their sockets and timers.
    asio::io_context io;
    fs::path root;
    // Key material and signatures for the hostile side. Kept out of the nodes
    // so certificates exist before the receiving node is constructed.
    std::unique_ptr<crypto::SodiumCryptoService> kc;
    std::vector<std::unique_ptr<Node>> nodes;

    void SetUp() override {
        root = fs::temp_directory_path() /
               ("nexus_test_gossip_ingress_" + std::to_string(getpid()));
        fs::remove_all(root);
        fs::create_directories(root);
        kc = std::make_unique<crypto::SodiumCryptoService>();
        kc->start();
    }

    void TearDown() override {
        for (auto it = nodes.rbegin(); it != nodes.rend(); ++it) {
            (*it)->gossip->stop();
            if ((*it)->acl) (*it)->acl->stop();
            if ((*it)->ipam) (*it)->ipam->stop();
            if ((*it)->tree) (*it)->tree->stop();
            (*it)->storage->stop();
            (*it)->crypto->stop();
        }
        nodes.clear();
        kc->stop();
        kc.reset();
        fs::remove_all(root);
    }

    // `seed` runs before the gossip service exists, so it can pre-place storage
    // state (a peer list with certificates) and build the downstream services.
    // `configure` runs on the constructed service before start(). Everything
    // shares one io_context that the test thread pumps, so callbacks run on the
    // test thread and need no lock.
    Node& make_node(const std::string& tag,
                    const std::function<void(Node&)>& seed = {},
                    const std::function<void(Node&)>& configure = {}) {
        auto n = std::make_unique<Node>();
        n->dir = root / tag;
        fs::create_directories(n->dir);
        n->crypto = std::make_unique<crypto::SodiumCryptoService>();
        n->crypto->start();
        n->storage = std::make_unique<storage::FileStorageService>(n->dir);
        n->storage->start();
        if (seed) seed(*n);
        n->gossip = std::make_unique<gossip::GossipService>(io, 0, *n->storage, *n->crypto);
        if (configure) configure(*n);
        n->gossip->start();
        nodes.push_back(std::move(n));
        return *nodes.back();
    }

    // A real SQLite-backed ACL service. The signing keypair is what derives the
    // at-rest key, so it must be set before any permission is written or read.
    static void attach_acl(Node& n, const crypto::Ed25519Keypair& kp) {
        n.acl = std::make_unique<acl::ACLService>(n.dir / "acl.db", *n.crypto);
        n.acl->set_signing_keypair(kp);
        n.acl->start();
    }

    static void attach_ipam(Node& n) {
        n.ipam = std::make_unique<ipam::IPAMService>(*n.storage);
        n.ipam->start();
    }

    // The DNS service binds its socket in the constructor, so it takes an
    // ephemeral port. It is never started: the zone map and the resolver are
    // pure, and an unstarted service posts no work onto the shared io_context.
    void attach_dns(Node& n) {
        n.tree = std::make_unique<tree::PermissionTreeService>(*n.storage, *n.crypto);
        n.tree->start();
        n.dns = std::make_unique<network::DnsService>(io, 0, *n.tree, "lemonade-nexus.io");
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
    // emits).
    std::vector<uint8_t> build_packet(const crypto::Ed25519Keypair& kp,
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
        auto sig = kc->ed25519_sign(kp.private_key,
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

    // The REAL certificate path: root-signed by `root_kp`, verifiable by any
    // node whose set_root_pubkey matches.
    std::string issue_cert(const std::string& server_pubkey_b64,
                           const std::string& server_id,
                           const crypto::Ed25519Keypair& root_kp,
                           const std::string& network_hex = kTestNetworkHex) {
        gossip::CertIssueParams p;
        p.network_id        = network_hex;
        p.server_pubkey_b64 = server_pubkey_b64;
        p.server_id         = server_id;
        return nlohmann::json(
            gossip::issue_server_certificate(p, *kc, root_kp.private_key,
                                             root_kp.public_key)).dump();
    }

    std::string sign_b64(const crypto::Ed25519Keypair& kp, const std::string& msg) {
        auto sig = kc->ed25519_sign(
            kp.private_key,
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg.data()),
                                     msg.size()));
        return crypto::to_base64(sig);
    }

    // An ACL delta signed exactly the way ACLService::verify_delta_signature
    // rebuilds the preimage (sorted keys, signature field excluded). The delta
    // signature is self-consistent by design; ADMISSION is what the cert gate
    // on the gossip sender decides.
    std::vector<uint8_t> acl_delta_payload(const crypto::Ed25519Keypair& signer,
                                           const std::string& delta_id,
                                           const std::string& user_id,
                                           const std::string& resource,
                                           uint32_t permissions) {
        nlohmann::json canonical;
        canonical["delta_id"]    = delta_id;
        canonical["operation"]   = "grant";
        canonical["permissions"] = permissions;
        canonical["resource"]    = resource;
        canonical["timestamp"]   = uint64_t{1000};
        canonical["user_id"]     = user_id;

        nlohmann::json wire = canonical;
        wire["signer_pubkey"] = crypto::to_base64(signer.public_key);
        wire["signature"]     = sign_b64(signer, canonical.dump());
        return msgpack_of(wire);
    }

    // A DNS delta signed exactly the way handle_dns_record_sync rebuilds the
    // origin preimage: data fields only, sorted keys.
    std::vector<uint8_t> dns_delta_payload(const crypto::Ed25519Keypair& signer,
                                           const std::string& delta_id,
                                           const std::string& fqdn,
                                           const std::string& value) {
        nlohmann::json canonical;
        canonical["delta_id"]    = delta_id;
        canonical["fqdn"]        = fqdn;
        canonical["operation"]   = "set";
        canonical["record_type"] = "A";
        canonical["timestamp"]   = uint64_t{1000};
        canonical["ttl"]         = uint32_t{60};
        canonical["value"]       = value;

        nlohmann::json wire = canonical;
        wire["signer_pubkey"] = crypto::to_base64(signer.public_key);
        wire["signature"]     = sign_b64(signer, canonical.dump());
        return msgpack_of(wire);
    }

    // A backbone claim signed by its author. `named_pubkey_b64` is the server
    // the claim NAMES; splitting it from the signer makes the self-claim rule
    // testable.
    std::vector<uint8_t> ipam_delta_payload(const crypto::Ed25519Keypair& signer,
                                            const std::string& named_pubkey_b64,
                                            const std::string& delta_id,
                                            const std::string& server_node_id,
                                            const std::string& backbone_ip) {
        nlohmann::json canonical;
        canonical["backbone_ip"]    = backbone_ip;
        canonical["delta_id"]       = delta_id;
        canonical["operation"]      = "allocate";
        canonical["server_node_id"] = server_node_id;
        canonical["server_pubkey"]  = named_pubkey_b64;
        canonical["timestamp"]      = uint64_t{1000};

        nlohmann::json wire = canonical;
        wire["signer_pubkey"] = crypto::to_base64(signer.public_key);
        wire["signature"]     = sign_b64(signer, canonical.dump());
        return msgpack_of(wire);
    }

    // An NS slot claim exactly as try_claim_ns_slot signs one. `named` is the
    // claimant the claim NAMES; `signer` is the key that actually signs it.
    // Splitting the two is what makes the binding testable.
    std::vector<uint8_t> ns_claim_payload(const crypto::Ed25519Keypair& signer,
                                          const std::string& named_pubkey_b64,
                                          uint8_t slot) {
        nlohmann::json sign_payload;
        sign_payload["slot"]          = slot;
        sign_payload["server_pubkey"] = named_pubkey_b64;
        sign_payload["server_ip"]     = "10.0.0.7";
        sign_payload["region"]        = "eu-west";
        sign_payload["timestamp"]     = uint64_t{1000};

        nlohmann::json wire = sign_payload;
        wire["signature"] = sign_b64(signer, sign_payload.dump());
        return msgpack_of(wire);
    }

    // A tree delta signed the way do_handle_deltas (and therefore
    // tree_delta_canonical) verifies one — the statement form a misbehavior
    // proof bundles.
    nlohmann::json tree_delta(const crypto::Ed25519Keypair& signer,
                              const std::string& target_node_id, uint64_t seq,
                              const nlohmann::json& data) {
        const std::string operation = "update_node";
        const std::string permission;
        const uint64_t timestamp = 1;
        const std::string canonical =
            operation + "\n" + target_node_id + "\n" + std::to_string(seq) + "\n" +
            permission + "\n" + std::to_string(timestamp) + "\n" + data.dump();
        return {
            {"sequence", seq},
            {"operation", operation},
            {"target_node_id", target_node_id},
            {"data", data},
            {"signer_pubkey", crypto::to_base64(signer.public_key)},
            {"required_permission", permission},
            {"timestamp", timestamp},
            {"signature", sign_b64(signer, canonical)},
        };
    }

    // Bundle two statements against `accused` without any dispositiveness
    // check — this is what a hostile reporter can always build.
    gossip::MisbehaviorProof forge_proof(const std::string& accused_pubkey_b64,
                                         const nlohmann::json& a,
                                         const nlohmann::json& b,
                                         const std::string& reporter_pubkey_b64) {
        gossip::MisbehaviorProof proof;
        proof.kind            = gossip::MisbehaviorKind::TreeDeltaEquivocation;
        proof.accused_pubkey  = accused_pubkey_b64;
        proof.statement_a     = a.dump();
        proof.statement_b     = b.dump();
        proof.reporter_pubkey = reporter_pubkey_b64;
        proof.observed_at     = 1000;
        proof.proof_id        = gossip::misbehavior_proof_id(
            proof.kind, proof.accused_pubkey, proof.statement_a, proof.statement_b, *kc);
        return proof;
    }

    static std::vector<uint8_t> proof_payload(const gossip::MisbehaviorProof& proof) {
        return bytes_of(nlohmann::json(proof).dump());
    }
};

}  // namespace

// ---------------------------------------------------------------------------
// (1) ACL delta ingress
// ---------------------------------------------------------------------------

// A validly signed ACL grant from an uncertified sender must not reach the ACL
// database. Control: the IDENTICAL payload bytes from a cert-verified peer are
// applied, so neither the delta signature, the delta id, nor the wire encoding
// can explain the refusal — only the sender's certificate does.
TEST_F(GossipIngressSecurityTest, AclDeltaRequiresCertifiedAuthorAndSender) {
    auto root_kp   = kc->ed25519_keygen();
    auto certified = kc->ed25519_keygen();
    auto outsider  = kc->ed25519_keygen();
    const auto certified_b64 = crypto::to_base64(certified.public_key);
    const auto cert_json = issue_cert(certified_b64, "peer-certified", root_kp);

    auto& a = make_node(
        "a",
        [&](Node& n) {
            attach_acl(n, kc->ed25519_keygen());
            seed_peers(*n.storage, nlohmann::json::array(
                {peer_entry(certified_b64, "127.0.0.1:9", cert_json)}));
        },
        [&](Node& n) {
            n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex);
            n.gossip->set_acl(n.acl.get());
        });

    // A known peer WITHOUT a certificate: peer-list membership is not trust.
    a.gossip->add_peer("127.0.0.1:9", crypto::to_base64(outsider.public_key));

    ASSERT_EQ(a.acl->get_permissions("user-1", "res-1"), acl::Permission::None);

    // Authored by an uncertified key, forwarded by an uncertified peer.
    const auto outsider_authored = acl_delta_payload(
        outsider, "delta-acl-1", "user-1", "res-1",
        static_cast<uint32_t>(acl::Permission::Read | acl::Permission::Write));
    inject(build_packet(outsider, gossip::GossipMsgType::AclDelta, outsider_authored), a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_EQ(a.acl->get_permissions("user-1", "res-1"), acl::Permission::None);

    // Laundering: the SAME uncertified-author bytes relayed by the certified
    // peer. The forwarder's certificate must not stand in for the author's.
    inject(build_packet(certified, gossip::GossipMsgType::AclDelta, outsider_authored), a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_EQ(a.acl->get_permissions("user-1", "res-1"), acl::Permission::None);

    // Certified author behind an uncertified forwarder: still refused at the
    // transport gate.
    const auto certified_authored = acl_delta_payload(
        certified, "delta-acl-2", "user-1", "res-1",
        static_cast<uint32_t>(acl::Permission::Read | acl::Permission::Write));
    inject(build_packet(outsider, gossip::GossipMsgType::AclDelta, certified_authored), a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_EQ(a.acl->get_permissions("user-1", "res-1"), acl::Permission::None);

    // Control: certified author, certified forwarder — applied.
    inject(build_packet(certified, gossip::GossipMsgType::AclDelta, certified_authored), a);
    ASSERT_TRUE(pump_until([&] {
        return a.acl->get_permissions("user-1", "res-1") != acl::Permission::None;
    }));
    EXPECT_TRUE(a.acl->check("user-1", "res-1",
                             acl::Permission::Read | acl::Permission::Write));
}

// ---------------------------------------------------------------------------
// (2) DNS record sync ingress
// ---------------------------------------------------------------------------

// A DNS record delta from an uncertified sender must not enter the zone.
// Control: the identical bytes from a cert-verified peer set the record, which
// then resolves. The SOA serial pins that the zone did not change at all under
// the hostile packet — a record set and instantly shadowed would still bump it.
TEST_F(GossipIngressSecurityTest, DnsRecordSyncRequiresCertifiedAuthorAndSender) {
    auto root_kp   = kc->ed25519_keygen();
    auto certified = kc->ed25519_keygen();
    auto outsider  = kc->ed25519_keygen();
    const auto certified_b64 = crypto::to_base64(certified.public_key);
    const auto cert_json = issue_cert(certified_b64, "peer-certified", root_kp);

    auto& a = make_node(
        "a",
        [&](Node& n) {
            attach_dns(n);
            seed_peers(*n.storage, nlohmann::json::array(
                {peer_entry(certified_b64, "127.0.0.1:9", cert_json)}));
        },
        [&](Node& n) {
            n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex);
            n.gossip->set_dns(n.dns.get());
        });

    a.gossip->add_peer("127.0.0.1:9", crypto::to_base64(outsider.public_key));

    const std::string fqdn = "srv1.us-east.seip.lemonade-nexus.io";
    const auto serial_before = a.dns->soa_serial();
    ASSERT_FALSE(a.dns->resolve(fqdn).has_value());

    // Authored by an uncertified key: refused whoever forwards it.
    const auto outsider_authored =
        dns_delta_payload(outsider, "delta-dns-1", fqdn, "10.9.8.7");
    inject(build_packet(outsider, gossip::GossipMsgType::DnsRecordSync, outsider_authored), a);
    inject(build_packet(certified, gossip::GossipMsgType::DnsRecordSync, outsider_authored), a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_FALSE(a.dns->resolve(fqdn).has_value());
    EXPECT_EQ(a.dns->soa_serial(), serial_before);

    // A certified author whose payload was tampered after signing writes
    // nothing either: the signature covers every data field.
    auto tampered = dns_delta_payload(certified, "delta-dns-2", fqdn, "10.9.8.7");
    {
        auto j = nlohmann::json::from_msgpack(tampered);
        j["value"] = "10.66.66.66";
        auto packed = nlohmann::json::to_msgpack(j);
        tampered.assign(packed.begin(), packed.end());
    }
    inject(build_packet(certified, gossip::GossipMsgType::DnsRecordSync, tampered), a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_FALSE(a.dns->resolve(fqdn).has_value());

    // Control: certified author, certified forwarder — the record lands.
    const auto genuine = dns_delta_payload(certified, "delta-dns-3", fqdn, "10.9.8.7");
    inject(build_packet(certified, gossip::GossipMsgType::DnsRecordSync, genuine), a);
    ASSERT_TRUE(pump_until([&] { return a.dns->resolve(fqdn).has_value(); }));
    EXPECT_EQ(a.dns->resolve(fqdn)->ipv4_address, "10.9.8.7");
    EXPECT_NE(a.dns->soa_serial(), serial_before);
}

// ---------------------------------------------------------------------------
// (3) Backbone IPAM sync ingress
// ---------------------------------------------------------------------------

// A backbone allocation from an uncertified sender must not enter IPAM. The
// certificate is the ONLY gate on this path — apply_remote_backbone_allocation
// verifies no signature of its own — so the refusal has to happen in gossip.
// Control: the identical bytes from a cert-verified peer allocate.
TEST_F(GossipIngressSecurityTest, BackboneIpamSyncRequiresCertifiedSelfClaim) {
    auto root_kp   = kc->ed25519_keygen();
    auto certified = kc->ed25519_keygen();
    auto outsider  = kc->ed25519_keygen();
    const auto certified_b64 = crypto::to_base64(certified.public_key);
    const auto outsider_b64  = crypto::to_base64(outsider.public_key);
    const auto cert_json = issue_cert(certified_b64, "peer-certified", root_kp);

    auto& a = make_node(
        "a",
        [&](Node& n) {
            attach_ipam(n);
            seed_peers(*n.storage, nlohmann::json::array(
                {peer_entry(certified_b64, "127.0.0.1:9", cert_json)}));
        },
        [&](Node& n) {
            n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex);
            n.gossip->set_ipam(n.ipam.get());
        });

    a.gossip->add_peer("127.0.0.1:9", outsider_b64);

    ASSERT_TRUE(a.ipam->get_backbone_allocations().empty());

    // An uncertified author claims an address: refused however it arrives.
    const auto outsider_claim = ipam_delta_payload(outsider, outsider_b64, "delta-ipam-1",
                                                   "srv-hostile", "172.16.0.42/32");
    inject(build_packet(outsider, gossip::GossipMsgType::BackboneIpamSync, outsider_claim), a);
    inject(build_packet(certified, gossip::GossipMsgType::BackboneIpamSync, outsider_claim), a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_TRUE(a.ipam->get_backbone_allocations().empty());

    // A certified author claiming SOMEONE ELSE's allocation: a backbone claim
    // is a statement about one's own address, so a third-party claim writes
    // nothing — the eviction lever is gone.
    const auto third_party = ipam_delta_payload(certified, outsider_b64, "delta-ipam-2",
                                                "srv-victim", "172.16.0.42/32");
    inject(build_packet(certified, gossip::GossipMsgType::BackboneIpamSync, third_party), a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_TRUE(a.ipam->get_backbone_allocations().empty());

    // Control: the certified author's claim about ITSELF is applied.
    const auto self_claim = ipam_delta_payload(certified, certified_b64, "delta-ipam-3",
                                               "srv-certified", "172.16.0.42/32");
    inject(build_packet(certified, gossip::GossipMsgType::BackboneIpamSync, self_claim), a);
    ASSERT_TRUE(pump_until([&] { return !a.ipam->get_backbone_allocations().empty(); }));
}

// ---------------------------------------------------------------------------
// (4) Misbehavior proof ingress
// ---------------------------------------------------------------------------

// A misbehavior proof is deliberately NOT cert-gated: it is dispositive
// evidence that any node re-verifies as a pure function, so anyone may report
// one. That makes non-dispositiveness the whole defence against griefing.
// Two hostile shapes must both fail to ban the accused:
//   (a) a frame-up — a genuine conflicting pair signed by the ATTACKER, but
//       accused_pubkey names the victim;
//   (b) a bundle of two statements the victim really did sign, at DIFFERENT
//       sequences, so they do not contradict each other.
// Control: a genuinely dispositive proof — two statements the victim signed at
// the SAME (target, sequence) with differing content — does ban and does drop
// the peer, proving the ban path is live and only dispositiveness held it back.
TEST_F(GossipIngressSecurityTest, HostileMisbehaviorProofDoesNotBanTheAccused) {
    auto root_kp  = kc->ed25519_keygen();
    auto victim   = kc->ed25519_keygen();
    auto attacker = kc->ed25519_keygen();
    const auto victim_b64   = crypto::to_base64(victim.public_key);
    const auto attacker_b64 = crypto::to_base64(attacker.public_key);
    const auto cert_json = issue_cert(victim_b64, "peer-victim", root_kp);

    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_peers(*n.storage, nlohmann::json::array(
                {peer_entry(victim_b64, "127.0.0.1:9", cert_json)}));
        },
        [&](Node& n) { n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex); });

    ASSERT_TRUE(a.has_peer(victim_b64));
    ASSERT_TRUE(a.certified_peer(victim_b64));
    ASSERT_FALSE(a.revoked(victim_b64));

    // (a) Frame-up: the statements really do conflict, but with each other's
    // signer being the attacker. Naming the victim as accused does not make
    // the attacker's signatures the victim's.
    const auto forged_1 = tree_delta(attacker, "node-z", 7, nlohmann::json{{"k", "one"}});
    const auto forged_2 = tree_delta(attacker, "node-z", 7, nlohmann::json{{"k", "two"}});
    inject(build_packet(attacker, gossip::GossipMsgType::MisbehaviorProofBroadcast,
                        proof_payload(forge_proof(victim_b64, forged_1, forged_2,
                                                  attacker_b64))),
           a);

    // (b) Non-dispositive: both statements carry the victim's real signature,
    // but they sit at different sequences — that is honest behaviour, not
    // equivocation.
    const auto honest_1 = tree_delta(victim, "node-z", 1, nlohmann::json{{"k", "one"}});
    const auto honest_2 = tree_delta(victim, "node-z", 2, nlohmann::json{{"k", "two"}});
    inject(build_packet(attacker, gossip::GossipMsgType::MisbehaviorProofBroadcast,
                        proof_payload(forge_proof(victim_b64, honest_1, honest_2,
                                                  attacker_b64))),
           a);

    pump_for(std::chrono::milliseconds(300));
    EXPECT_FALSE(a.revoked(victim_b64));
    EXPECT_TRUE(a.has_peer(victim_b64));
    EXPECT_TRUE(a.certified_peer(victim_b64));

    // Control: real equivocation by the victim. Built through the production
    // constructor, which returns nullopt unless the pair is provably
    // dispositive — so the control cannot silently degrade into a fabrication.
    const auto guilty_1 = tree_delta(victim, "node-z", 9, nlohmann::json{{"k", "one"}});
    const auto guilty_2 = tree_delta(victim, "node-z", 9, nlohmann::json{{"k", "two"}});
    const auto real_proof = gossip::make_tree_delta_equivocation_proof(
        guilty_1, guilty_2, attacker_b64, 1000, *kc);
    ASSERT_TRUE(real_proof.has_value());
    ASSERT_EQ(real_proof->accused_pubkey, victim_b64);

    inject(build_packet(attacker, gossip::GossipMsgType::MisbehaviorProofBroadcast,
                        proof_payload(*real_proof)),
           a);
    ASSERT_TRUE(pump_until([&] { return a.revoked(victim_b64); }));
    EXPECT_FALSE(a.has_peer(victim_b64));
    EXPECT_FALSE(a.certified_peer(victim_b64));
}

// ---------------------------------------------------------------------------
// (5) ServerHello ingress
// ---------------------------------------------------------------------------

// (5a) A certificate signed by some OTHER root must not enter the certificate
// store nor mark the presenter certified — even though the presenter holds the
// matching private key, so proof-of-possession succeeds and only the trust
// anchor is wrong. Control: a certificate from the CONFIGURED root, presented
// the same way over the same socket, is accepted and stored.
TEST_F(GossipIngressSecurityTest, ServerHelloRejectsCertificateFromForeignRoot) {
    auto root_kp   = kc->ed25519_keygen();
    auto rogue_root = kc->ed25519_keygen();
    auto imposter  = kc->ed25519_keygen();
    auto honest    = kc->ed25519_keygen();
    const auto imposter_b64 = crypto::to_base64(imposter.public_key);
    const auto honest_b64   = crypto::to_base64(honest.public_key);

    auto& a = make_node("a", /*seed=*/{}, [&](Node& n) {
        n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex);
        Node* raw = &n;
        n.gossip->set_peer_certified_callback(
            [raw](const security::NodeId& id) { raw->certified.push_back(id); });
    });

    // Self-consistent certificate under a root this node does not anchor.
    const auto rogue_cert = issue_cert(imposter_b64, "peer-imposter", rogue_root);
    inject(build_packet(imposter, gossip::GossipMsgType::ServerHello,
                        bytes_of(rogue_cert)),
           a);
    pump_for(std::chrono::milliseconds(300));

    EXPECT_TRUE(a.certified.empty());
    EXPECT_FALSE(a.has_peer(imposter_b64));
    EXPECT_FALSE(a.certified_peer(imposter_b64));

    // Control: the same shape under the configured root is accepted.
    const auto good_cert = issue_cert(honest_b64, "peer-honest", root_kp);
    inject(build_packet(honest, gossip::GossipMsgType::ServerHello,
                        bytes_of(good_cert)),
           a);
    ASSERT_TRUE(pump_until([&] { return !a.certified.empty(); }));
    ASSERT_EQ(a.certified.size(), 1u);
    EXPECT_EQ(a.certified[0].bytes, honest.public_key);
    EXPECT_TRUE(a.has_peer(honest_b64));
    EXPECT_FALSE(a.peer_cert_json(honest_b64).empty());
    EXPECT_TRUE(a.certified_peer(honest_b64));
    // The refused identity never appeared, and replaying a real certificate did
    // not create an entry for it either.
    EXPECT_FALSE(a.has_peer(imposter_b64));
}

// (5c) Two deployments sharing a root key by accident are still two networks.
// A certificate that is valid in every other way — same root, same node key,
// correct proof of possession — validates nowhere outside the network it names,
// and a certificate naming no network validates nowhere at all.
TEST_F(GossipIngressSecurityTest, ServerHelloRejectsCertificateFromForeignNetwork) {
    auto root_kp = kc->ed25519_keygen();
    auto foreign = kc->ed25519_keygen();
    auto honest  = kc->ed25519_keygen();
    const auto foreign_b64 = crypto::to_base64(foreign.public_key);
    const auto honest_b64  = crypto::to_base64(honest.public_key);

    auto& a = make_node("a", /*seed=*/{}, [&](Node& n) {
        n.gossip->set_root_pubkey(root_kp.public_key);
        n.gossip->set_network_id(kTestNetworkHex);
        Node* raw = &n;
        n.gossip->set_peer_certified_callback(
            [raw](const security::NodeId& id) { raw->certified.push_back(id); });
    });

    // Same root key, another network: root-signed and self-presented, and
    // still refused.
    const std::string other_network(64, 'b');
    const auto foreign_cert = issue_cert(foreign_b64, "peer-foreign", root_kp, other_network);
    inject(build_packet(foreign, gossip::GossipMsgType::ServerHello,
                        bytes_of(foreign_cert)),
           a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_TRUE(a.certified.empty());
    EXPECT_FALSE(a.certified_peer(foreign_b64));

    // A certificate that names no network at all: equally dead. There is no
    // acceptance path for unbound certificates.
    const auto unbound_cert = issue_cert(foreign_b64, "peer-unbound", root_kp, "");
    inject(build_packet(foreign, gossip::GossipMsgType::ServerHello,
                        bytes_of(unbound_cert)),
           a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_TRUE(a.certified.empty());

    // Control: the same shape on this network is accepted.
    const auto good_cert = issue_cert(honest_b64, "peer-honest", root_kp);
    inject(build_packet(honest, gossip::GossipMsgType::ServerHello,
                        bytes_of(good_cert)),
           a);
    ASSERT_TRUE(pump_until([&] { return !a.certified.empty(); }));
    EXPECT_TRUE(a.certified_peer(honest_b64));
    EXPECT_FALSE(a.certified_peer(foreign_b64));
}

// (5d) Re-signing a foreign-network certificate's network field does not help:
// the field is inside the canonical signed form, so an edited copy fails the
// root signature instead of the network check.
TEST_F(GossipIngressSecurityTest, EditedNetworkFieldBreaksTheRootSignature) {
    auto root_kp = kc->ed25519_keygen();
    auto node_kp = kc->ed25519_keygen();
    const auto node_b64 = crypto::to_base64(node_kp.public_key);

    auto& a = make_node("a", /*seed=*/{}, [&](Node& n) {
        n.gossip->set_root_pubkey(root_kp.public_key);
        n.gossip->set_network_id(kTestNetworkHex);
        Node* raw = &n;
        n.gossip->set_peer_certified_callback(
            [raw](const security::NodeId& id) { raw->certified.push_back(id); });
    });

    // Issued for another network, then edited to claim this one. The holder
    // itself presents it, so proof of possession holds; the signature does not.
    const std::string other_network(64, 'b');
    auto cert = nlohmann::json::parse(
                    issue_cert(node_b64, "peer-edited", root_kp, other_network))
                    .get<gossip::ServerCertificate>();
    cert.network_id = kTestNetworkHex;
    inject(build_packet(node_kp, gossip::GossipMsgType::ServerHello,
                        bytes_of(nlohmann::json(cert).dump())),
           a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_TRUE(a.certified.empty());
    EXPECT_FALSE(a.certified_peer(node_b64));
}

// (5b) A certificate is public, so a valid root signature alone proves nothing
// about who is presenting it. A packet signer whose key differs from
// cert.server_pubkey must be refused: the replayer must not bind the cert
// holder's identity to its own endpoint, nor gain the holder's trust.
// Control: the SAME certificate bytes over the SAME path, signed by its true
// holder, are accepted — so only the proof-of-possession check refused it.
TEST_F(GossipIngressSecurityTest, ServerHelloRequiresProofOfPossession) {
    auto root_kp  = kc->ed25519_keygen();
    auto holder   = kc->ed25519_keygen();
    auto replayer = kc->ed25519_keygen();
    const auto holder_b64   = crypto::to_base64(holder.public_key);
    const auto replayer_b64 = crypto::to_base64(replayer.public_key);

    auto& a = make_node("a", /*seed=*/{}, [&](Node& n) {
        n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex);
        Node* raw = &n;
        n.gossip->set_peer_certified_callback(
            [raw](const security::NodeId& id) { raw->certified.push_back(id); });
    });

    // A genuinely root-signed certificate for `holder`, captured off the wire.
    const auto cert_json = issue_cert(holder_b64, "peer-holder", root_kp);

    inject(build_packet(replayer, gossip::GossipMsgType::ServerHello,
                        bytes_of(cert_json)),
           a);
    pump_for(std::chrono::milliseconds(300));

    EXPECT_TRUE(a.certified.empty());
    EXPECT_FALSE(a.has_peer(holder_b64));
    EXPECT_FALSE(a.has_peer(replayer_b64));
    EXPECT_FALSE(a.certified_peer(holder_b64));
    EXPECT_FALSE(a.certified_peer(replayer_b64));

    // Control: identical bytes, signed by the key the certificate names.
    inject(build_packet(holder, gossip::GossipMsgType::ServerHello,
                        bytes_of(cert_json)),
           a);
    ASSERT_TRUE(pump_until([&] { return !a.certified.empty(); }));
    ASSERT_EQ(a.certified.size(), 1u);
    EXPECT_EQ(a.certified[0].bytes, holder.public_key);
    EXPECT_TRUE(a.has_peer(holder_b64));
    EXPECT_FALSE(a.peer_cert_json(holder_b64).empty());
    EXPECT_TRUE(a.certified_peer(holder_b64));
    EXPECT_FALSE(a.has_peer(replayer_b64));
}

// ---------------------------------------------------------------------------
// (6) NS slot claim ingress
// ---------------------------------------------------------------------------
//
// tests/test_legacy_removal.cpp already pins that a claim needs a verifying
// claimant signature and a root-signed claimant certificate. The two cases
// below pin the properties a naive "trust the sender" implementation would
// break, and must never regress.

// Claims travel epidemically, so a certified peer routinely forwards claims it
// did not author. The forwarder's own certificate must NOT launder an
// uncertified claimant: the gate binds to the CLAIMANT.
// Control: the SAME certified forwarder relaying a claim by a CERTIFIED
// claimant lands the slot — the forwarding path is live, and only the
// claimant's enrolment differs between the two packets.
TEST_F(GossipIngressSecurityTest, CertifiedForwarderCannotLaunderUncertifiedNsClaim) {
    auto root_kp   = kc->ed25519_keygen();
    auto forwarder = kc->ed25519_keygen();
    auto claimant  = kc->ed25519_keygen();
    auto outsider  = kc->ed25519_keygen();
    const auto forwarder_b64 = crypto::to_base64(forwarder.public_key);
    const auto claimant_b64  = crypto::to_base64(claimant.public_key);
    const auto outsider_b64  = crypto::to_base64(outsider.public_key);

    auto& a = make_node(
        "a",
        [&](Node& n) {
            // Distinct endpoints: load_peers merges the stored list by
            // endpoint, so two entries sharing one would silently collapse.
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(forwarder_b64, "127.0.0.1:9",
                           issue_cert(forwarder_b64, "peer-forwarder", root_kp)),
                peer_entry(claimant_b64, "127.0.0.1:10",
                           issue_cert(claimant_b64, "peer-claimant", root_kp)),
            }));
        },
        [&](Node& n) { n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex); });

    // The outsider is a known peer with no certificate, so only enrolment —
    // not reachability — separates it from the claimant.
    a.gossip->add_peer("127.0.0.1:11", outsider_b64);
    ASSERT_TRUE(a.certified_peer(forwarder_b64));
    ASSERT_TRUE(a.certified_peer(claimant_b64));
    ASSERT_FALSE(a.certified_peer(outsider_b64));

    // Certified forwarder relays the outsider's correctly self-signed claim.
    inject(build_packet(forwarder, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(outsider, outsider_b64, 4)),
           a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_TRUE(a.ns_holder(4).empty());

    // Control: the same forwarder relays a certified claimant's claim.
    inject(build_packet(forwarder, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(claimant, claimant_b64, 4)),
           a);
    ASSERT_TRUE(pump_until([&] { return a.ns_holder(4) == claimant_b64; }));
}

// The claim signature must verify against the key the claim NAMES, not merely
// against some enrolled key. Here both keys are certified peers, so a check
// that only asked "is this signature from an enrolled server?" would pass and
// hand slot 5 to a server that never asked for it.
// Control: the identical claim fields signed by the named claimant land.
TEST_F(GossipIngressSecurityTest, NsClaimSignatureMustBindTheNamedClaimant) {
    auto root_kp  = kc->ed25519_keygen();
    auto signer   = kc->ed25519_keygen();
    auto claimant = kc->ed25519_keygen();
    const auto signer_b64   = crypto::to_base64(signer.public_key);
    const auto claimant_b64 = crypto::to_base64(claimant.public_key);

    auto& a = make_node(
        "a",
        [&](Node& n) {
            // Distinct endpoints: load_peers merges the stored list by
            // endpoint, so two entries sharing one would silently collapse.
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(signer_b64, "127.0.0.1:9",
                           issue_cert(signer_b64, "peer-signer", root_kp)),
                peer_entry(claimant_b64, "127.0.0.1:10",
                           issue_cert(claimant_b64, "peer-claimant", root_kp)),
            }));
        },
        [&](Node& n) { n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex); });

    ASSERT_TRUE(a.certified_peer(signer_b64));
    ASSERT_TRUE(a.certified_peer(claimant_b64));

    // Signature valid for `signer`, claim names `claimant`: refused.
    inject(build_packet(signer, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(signer, claimant_b64, 5)),
           a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_TRUE(a.ns_holder(5).empty());

    // Control: identical fields, now signed by the claimant the claim names.
    // The packet signer stays `signer`, so the claim signature is the only
    // variable between the two injections.
    inject(build_packet(signer, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(claimant, claimant_b64, 5)),
           a);
    ASSERT_TRUE(pump_until([&] { return a.ns_holder(5) == claimant_b64; }));
}

// ---------------------------------------------------------------------------
// Relayed certificates through peer exchange
// ---------------------------------------------------------------------------

// Peer exchange is how a delta's AUTHOR can become certified without a direct
// hello: a relayed certificate is adopted only after the same full
// verification a direct hello gets, and a bogus one changes nothing. Once
// adopted, a delta authored by that origin verifies end to end.
TEST_F(GossipIngressSecurityTest, PeerExchangeAdoptsOnlyVerifiedRelayedCertificates) {
    auto root_kp = kc->ed25519_keygen();
    auto origin  = kc->ed25519_keygen();
    auto other   = kc->ed25519_keygen();
    const auto origin_b64 = crypto::to_base64(origin.public_key);
    const auto origin_cert = issue_cert(origin_b64, "peer-origin", root_kp);

    auto& a = make_node(
        "a",
        [&](Node& n) { attach_dns(n); },
        [&](Node& n) {
            n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex);
            n.gossip->set_dns(n.dns.get());
        });

    // The origin is a known peer with NO stored certificate yet, so its
    // authored delta is refused.
    a.gossip->add_peer("127.0.0.1:9", origin_b64);
    const std::string fqdn = "srv2.us-east.seip.lemonade-nexus.io";
    const auto authored = dns_delta_payload(origin, "delta-relay-1", fqdn, "10.4.4.4");
    inject(build_packet(origin, gossip::GossipMsgType::DnsRecordSync, authored), a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_FALSE(a.dns->resolve(fqdn).has_value());

    // A relayed certificate for the WRONG subject is not adopted...
    const auto wrong_subject = issue_cert(crypto::to_base64(other.public_key),
                                          "peer-other", root_kp);
    nlohmann::json bogus;
    bogus["peers"] = nlohmann::json::array(
        {{{"pubkey", origin_b64}, {"endpoint", "127.0.0.1:9"},
          {"certificate_json", wrong_subject}}});
    bogus["is_response"] = true;
    const auto bogus_str = bogus.dump();
    inject(build_packet(other, gossip::GossipMsgType::PeerExchange,
                        std::vector<uint8_t>(bogus_str.begin(), bogus_str.end())), a);
    pump_for(std::chrono::milliseconds(200));
    inject(build_packet(origin, gossip::GossipMsgType::DnsRecordSync, authored), a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_FALSE(a.dns->resolve(fqdn).has_value());

    // ...while the origin's real certificate, relayed the same way, is.
    nlohmann::json genuine;
    genuine["peers"] = nlohmann::json::array(
        {{{"pubkey", origin_b64}, {"endpoint", "127.0.0.1:9"},
          {"certificate_json", origin_cert}}});
    genuine["is_response"] = true;
    const auto genuine_str = genuine.dump();
    inject(build_packet(other, gossip::GossipMsgType::PeerExchange,
                        std::vector<uint8_t>(genuine_str.begin(), genuine_str.end())), a);
    pump_for(std::chrono::milliseconds(200));
    inject(build_packet(origin, gossip::GossipMsgType::DnsRecordSync, authored), a);
    ASSERT_TRUE(pump_until([&] { return a.dns->resolve(fqdn).has_value(); }));
    EXPECT_EQ(a.dns->resolve(fqdn)->ipv4_address, "10.4.4.4");
}

// A tier1 DNS label asserts finalized membership, not enrollment: a certified
// author that is not a current Tier 1 member cannot publish one, and with no
// membership source configured nothing qualifies. Membership makes the same
// record land.
TEST_F(GossipIngressSecurityTest, Tier1DnsLabelRequiresFinalizedMembership) {
    auto root_kp   = kc->ed25519_keygen();
    auto certified = kc->ed25519_keygen();
    const auto certified_b64 = crypto::to_base64(certified.public_key);
    const auto cert_json = issue_cert(certified_b64, "peer-certified", root_kp);

    bool is_member = false;
    auto& a = make_node(
        "a",
        [&](Node& n) {
            attach_dns(n);
            seed_peers(*n.storage, nlohmann::json::array(
                {peer_entry(certified_b64, "127.0.0.1:9", cert_json)}));
        },
        [&](Node& n) {
            n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex);
            n.gossip->set_dns(n.dns.get());
        });

    const std::string tier1_fqdn = "srv9.tier1.us-east.seip.lemonade-nexus.io";

    // No membership source configured: the label is unprovable, so it fails
    // closed even for a certified author.
    const auto first = dns_delta_payload(certified, "delta-t1-1", tier1_fqdn, "10.1.1.1");
    inject(build_packet(certified, gossip::GossipMsgType::DnsRecordSync, first), a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_FALSE(a.dns->resolve(tier1_fqdn).has_value());

    // A source that answers "not a member": still refused.
    a.gossip->set_tier1_membership_source([&](const std::string&) { return is_member; });
    const auto second = dns_delta_payload(certified, "delta-t1-2", tier1_fqdn, "10.1.1.1");
    inject(build_packet(certified, gossip::GossipMsgType::DnsRecordSync, second), a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_FALSE(a.dns->resolve(tier1_fqdn).has_value());

    // Finalized membership is what makes the label true.
    is_member = true;
    const auto third = dns_delta_payload(certified, "delta-t1-3", tier1_fqdn, "10.1.1.1");
    inject(build_packet(certified, gossip::GossipMsgType::DnsRecordSync, third), a);
    ASSERT_TRUE(pump_until([&] { return a.dns->resolve(tier1_fqdn).has_value(); }));
    EXPECT_EQ(a.dns->resolve(tier1_fqdn)->ipv4_address, "10.1.1.1");

    // Ordinary records never consult the membership source.
    is_member = false;
    const std::string plain_fqdn = "srv9.us-east.seip.lemonade-nexus.io";
    const auto plain = dns_delta_payload(certified, "delta-t1-4", plain_fqdn, "10.2.2.2");
    inject(build_packet(certified, gossip::GossipMsgType::DnsRecordSync, plain), a);
    ASSERT_TRUE(pump_until([&] { return a.dns->resolve(plain_fqdn).has_value(); }));
}
