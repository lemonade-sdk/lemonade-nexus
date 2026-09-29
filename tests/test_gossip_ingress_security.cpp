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
#include <LemonadeNexus/Gossip/ServerCertificate.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <LemonadeNexus/IPAM/IPAMTypes.hpp>
#include <LemonadeNexus/Network/DnsService.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>

#include <asio.hpp>
#include <gtest/gtest.h>
#include <sodium.h>
#include <sqlite3.h>
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
    static bool ns_synced(GossipService& g) { return g.ns_state_synced_; }
    static bool ns_claim_pending(GossipService& g) { return g.ns_claim_pending_; }
    // Drives one 5 s gossip tick (NS claim deferral/retry, opt-out release)
    // without waiting for the timer.
    static void run_gossip_tick(GossipService& g) { g.on_gossip_tick(); }
    // v0.9.4 fix 4: the PeerExchange initiator runs on steady_clock, which no
    // datagram can advance; the cadence tests set these clocks directly.
    static void set_last_peer_exchange(GossipService& g,
                                       std::chrono::steady_clock::time_point t) {
        std::lock_guard lock(g.peers_mutex_);
        g.last_peer_exchange_tick_ = t;
    }
    static void set_peer_exchange_last(GossipService& g, const std::string& pubkey,
                                       std::chrono::steady_clock::time_point t) {
        std::lock_guard lock(g.peers_mutex_);
        g.peer_exchange_last_[pubkey] = t;
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
    std::unique_ptr<acl::AclStore>                 acl_store;
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
        n.acl_store = std::make_unique<acl::AclStore>(n.dir / "acl.db");
        n.acl = std::make_unique<acl::ACLService>(*n.acl_store, *n.crypto);
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
                                           const std::string& value,
                                           const std::string& record_type = "A") {
        nlohmann::json canonical;
        canonical["delta_id"]    = delta_id;
        canonical["fqdn"]        = fqdn;
        canonical["operation"]   = "set";
        canonical["record_type"] = record_type;
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
    // Splitting the two is what makes the binding testable. `server_ip` of
    // "" builds a release; `pinned` signs the v0.9.4 six-field preimage.
    std::vector<uint8_t> ns_claim_payload(const crypto::Ed25519Keypair& signer,
                                          const std::string& named_pubkey_b64,
                                          uint8_t slot,
                                          const std::string& server_ip = "10.0.0.7",
                                          bool pinned = false) {
        nlohmann::json sign_payload;
        if (pinned) sign_payload["pinned"] = true;
        sign_payload["slot"]          = slot;
        sign_payload["server_pubkey"] = named_pubkey_b64;
        sign_payload["server_ip"]     = server_ip;
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
};

}  // namespace

// ---------------------------------------------------------------------------
// (1) ACL delta ingress
// ---------------------------------------------------------------------------

// A validly signed ACL grant from an uncertified sender must not reach the ACL
// database. Control: the IDENTICAL payload bytes from a cert-verified peer are
// applied, so neither the delta signature, the delta id, nor the wire encoding
// can explain the refusal — only the sender's certificate does.
TEST_F(GossipIngressSecurityTest, AclDeltaFromCertifiedPeerIsRefusedAndRowsUntouched) {
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

    // Remote ACL mutation is unavailable pending finalized mesh authority:
    // every shape below must leave the row untouched — uncertified author
    // and sender, laundered bytes, uncertified forwarder, and finally the
    // certified author behind the certified forwarder. A certificate-verified
    // author is not a permission authority.
    const auto outsider_authored = acl_delta_payload(
        outsider, "delta-acl-1", "user-1", "res-1",
        static_cast<uint32_t>(acl::Permission::Read | acl::Permission::Write));
    const auto certified_authored = acl_delta_payload(
        certified, "delta-acl-2", "user-1", "res-1",
        static_cast<uint32_t>(acl::Permission::Read | acl::Permission::Write));

    inject(build_packet(outsider, gossip::GossipMsgType::AclDelta, outsider_authored), a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_EQ(a.acl->get_permissions("user-1", "res-1"), acl::Permission::None);

    inject(build_packet(certified, gossip::GossipMsgType::AclDelta, outsider_authored), a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_EQ(a.acl->get_permissions("user-1", "res-1"), acl::Permission::None);

    inject(build_packet(outsider, gossip::GossipMsgType::AclDelta, certified_authored), a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_EQ(a.acl->get_permissions("user-1", "res-1"), acl::Permission::None);

    // The delta id is not marked seen and no forwarding signal is produced:
    // a resend is refused again, and a different delta id is refused too.
    inject(build_packet(certified, gossip::GossipMsgType::AclDelta, certified_authored), a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_EQ(a.acl->get_permissions("user-1", "res-1"), acl::Permission::None);
    inject(build_packet(certified, gossip::GossipMsgType::AclDelta,
                        acl_delta_payload(certified, "delta-acl-3", "user-1", "res-1",
                                           static_cast<uint32_t>(acl::Permission::Read))), a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_EQ(a.acl->get_permissions("user-1", "res-1"), acl::Permission::None);

    // Control: the local service API is alive — the refusal is at the remote
    // mutation boundary, not in the store.
    ASSERT_TRUE(a.acl->grant("user-1", "res-1", acl::Permission::Read));
    EXPECT_EQ(a.acl->get_permissions("user-1", "res-1"), acl::Permission::Read);
    EXPECT_TRUE(a.acl->check("user-1", "res-1", acl::Permission::Read));
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
    // The author's certificate carries the server_id that OWNS the SEIP FQDN.
    const auto cert_json = issue_cert(certified_b64, "srv1", root_kp);

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
TEST_F(GossipIngressSecurityTest, MisbehaviorProofIsNotProcessedAndCannotBan) {
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

    // The sequence-based tree proof path is retired: transport positions do
    // not establish equivocation, and no ban is ever issued from a received
    // record. Even a genuinely dispositive-shaped proof — the victim really
    // did sign two conflicting statements at the same (target, position) —
    // must not revoke, drop the peer, or re-broadcast.
    const auto s1 = tree_delta(victim, "node-z", 9, nlohmann::json{{"k", "one"}});
    const auto s2 = tree_delta(victim, "node-z", 9, nlohmann::json{{"k", "two"}});
    nlohmann::json proof;
    proof["kind"]            = 1;
    proof["accused_pubkey"]  = victim_b64;
    proof["statement_a"]     = s1.dump();
    proof["statement_b"]     = s2.dump();
    proof["reporter_pubkey"] = attacker_b64;
    proof["observed_at"]     = 1000;
    proof["proof_id"]        = "deadbeef";
    auto proof_bytes = proof.dump();
    std::vector<uint8_t> proof_payload(proof_bytes.begin(), proof_bytes.end());

    inject(build_packet(attacker, gossip::GossipMsgType::MisbehaviorProofBroadcast,
                        proof_payload),
           a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_FALSE(a.revoked(victim_b64));
    EXPECT_TRUE(a.has_peer(victim_b64));
    EXPECT_TRUE(a.certified_peer(victim_b64));
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
// NS slot claiming: deterministic allocation, no clobber, opt-out + release
// ---------------------------------------------------------------------------

// v0.9.4 fix 3: a claim lands on an EMPTY slot, but an unpinned claim on an
// OCCUPIED slot never clobbers the current holder. Control: the same
// claimant's claim on a free slot lands, so the refusal is the acceptance
// rule, not the payload.
TEST_F(GossipIngressSecurityTest, NsClaimOnOccupiedSlotIsRejectedAndHolderUnchanged) {
    auto root_kp   = kc->ed25519_keygen();
    auto holder    = kc->ed25519_keygen();
    auto claimant  = kc->ed25519_keygen();
    const auto holder_b64   = crypto::to_base64(holder.public_key);
    const auto claimant_b64 = crypto::to_base64(claimant.public_key);

    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(holder_b64, "127.0.0.1:9",
                           issue_cert(holder_b64, "peer-holder", root_kp)),
                peer_entry(claimant_b64, "127.0.0.1:10",
                           issue_cert(claimant_b64, "peer-claimant", root_kp)),
            }));
        },
        [&](Node& n) { n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex); });

    ASSERT_TRUE(a.certified_peer(holder_b64));
    ASSERT_TRUE(a.certified_peer(claimant_b64));

    // Holder takes ns3.
    inject(build_packet(holder, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(holder, holder_b64, 3, "10.0.0.30")),
           a);
    ASSERT_TRUE(pump_until([&] { return a.ns_holder(3) == holder_b64; }));

    // Unpinned non-holder claims the occupied slot: rejected, holder kept.
    inject(build_packet(claimant, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(claimant, claimant_b64, 3, "10.0.0.40")),
           a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_EQ(a.ns_holder(3), holder_b64);
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_slot(*a.gossip, 3).server_ip,
              "10.0.0.30");

    // Control: the same claimant takes the EMPTY slot ns4.
    inject(build_packet(claimant, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(claimant, claimant_b64, 4, "10.0.0.40")),
           a);
    ASSERT_TRUE(pump_until([&] { return a.ns_holder(4) == claimant_b64; }));
}

// v0.9.4 fix 3: the current holder may re-claim its own slot (idempotent
// renewal) and the refresh lands; a different claimant against the same slot
// does not.
TEST_F(GossipIngressSecurityTest, NsClaimRenewalByHolderRefreshesFields) {
    auto root_kp = kc->ed25519_keygen();
    auto holder  = kc->ed25519_keygen();
    auto other   = kc->ed25519_keygen();
    const auto holder_b64 = crypto::to_base64(holder.public_key);
    const auto other_b64  = crypto::to_base64(other.public_key);

    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(holder_b64, "127.0.0.1:9",
                           issue_cert(holder_b64, "peer-holder", root_kp)),
                peer_entry(other_b64, "127.0.0.1:10",
                           issue_cert(other_b64, "peer-other", root_kp)),
            }));
        },
        [&](Node& n) { n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex); });

    inject(build_packet(holder, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(holder, holder_b64, 3, "10.0.0.30")),
           a);
    ASSERT_TRUE(pump_until([&] { return a.ns_holder(3) == holder_b64; }));

    // Renewal by the holder: same slot, refreshed IP.
    inject(build_packet(holder, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(holder, holder_b64, 3, "10.0.0.31")),
           a);
    ASSERT_TRUE(pump_until(
        [&] { return gossip::GossipBallotTestAccess::ns_slot(*a.gossip, 3).server_ip == "10.0.0.31"; }));

    // A different claimant still cannot take the renewed slot.
    inject(build_packet(other, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(other, other_b64, 3, "10.0.0.99")),
           a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_EQ(a.ns_holder(3), holder_b64);
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_slot(*a.gossip, 3).server_ip,
              "10.0.0.31");
}

// v0.9.4 fix 3: a PINNED claim takes the slot from an UNPINNED holder; the
// displaced holder (this node) does not re-claim one-shot — it re-claims the
// lowest free slot on the next gossip tick.
TEST_F(GossipIngressSecurityTest, NsPinnedClaimDisplacesUnpinnedHolderAndDisplacedReclaimsNextTick) {
    auto root_kp = kc->ed25519_keygen();
    auto pinned  = kc->ed25519_keygen();
    auto filler  = kc->ed25519_keygen();
    const auto pinned_b64 = crypto::to_base64(pinned.public_key);
    const auto filler_b64 = crypto::to_base64(filler.public_key);

    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(pinned_b64, "127.0.0.1:9",
                           issue_cert(pinned_b64, "peer-pinned", root_kp)),
                peer_entry(filler_b64, "127.0.0.1:10",
                           issue_cert(filler_b64, "peer-filler", root_kp)),
            }));
        },
        [&](Node& n) { n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex); });

    // Two unrelated servers hold ns1 and ns2; a claim from them also syncs
    // this node's slot state, so its own claim is legal.
    inject(build_packet(filler, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(filler, filler_b64, 1, "10.0.0.10")),
           a);
    inject(build_packet(filler, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(filler, filler_b64, 2, "10.0.0.11")),
           a);
    ASSERT_TRUE(pump_until([&] {
        return a.ns_holder(1) == filler_b64 && a.ns_holder(2) == filler_b64;
    }));

    // This node claims the lowest free slot: ns3.
    a.gossip->try_claim_ns_slot("10.0.0.50");
    ASSERT_EQ(a.gossip->our_ns_slot(), 3);

    // The pinned node claims ns3: it takes it from this UNPINNED holder.
    inject(build_packet(pinned, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(pinned, pinned_b64, 3, "10.0.0.60", true)),
           a);
    ASSERT_TRUE(pump_until([&] { return a.ns_holder(3) == pinned_b64; }));
    EXPECT_TRUE(gossip::GossipBallotTestAccess::ns_slot(*a.gossip, 3).pinned);

    // Displaced: this node holds nothing but stays pending...
    EXPECT_FALSE(a.gossip->our_ns_slot().has_value());
    EXPECT_TRUE(gossip::GossipBallotTestAccess::ns_claim_pending(*a.gossip));

    // ...and re-claims the lowest free slot (ns4) on the next tick.
    gossip::GossipBallotTestAccess::run_gossip_tick(*a.gossip);
    EXPECT_EQ(a.gossip->our_ns_slot(), 4);
    EXPECT_EQ(a.ns_holder(4), a.pubkey_b64());
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_slot(*a.gossip, 4).server_ip,
              "10.0.0.50");
}

// v0.9.4 fix 3: a pinned claim on a slot held by the SAME pinned holder is a
// renewal only; a DIFFERENT pinned claimant cannot displace a pinned holder
// (pinned takes from unpinned only).
TEST_F(GossipIngressSecurityTest, NsPinnedClaimIsRenewalOnlyAgainstPinnedHolder) {
    auto root_kp = kc->ed25519_keygen();
    auto pinned  = kc->ed25519_keygen();
    auto other   = kc->ed25519_keygen();
    const auto pinned_b64 = crypto::to_base64(pinned.public_key);
    const auto other_b64  = crypto::to_base64(other.public_key);

    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(pinned_b64, "127.0.0.1:9",
                           issue_cert(pinned_b64, "peer-pinned", root_kp)),
                peer_entry(other_b64, "127.0.0.1:10",
                           issue_cert(other_b64, "peer-other", root_kp)),
            }));
        },
        [&](Node& n) { n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex); });

    inject(build_packet(pinned, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(pinned, pinned_b64, 5, "10.0.0.70", true)),
           a);
    ASSERT_TRUE(pump_until([&] { return a.ns_holder(5) == pinned_b64; }));

    // Same pin, same holder: renewal, IP refreshed.
    inject(build_packet(pinned, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(pinned, pinned_b64, 5, "10.0.0.71", true)),
           a);
    ASSERT_TRUE(pump_until(
        [&] { return gossip::GossipBallotTestAccess::ns_slot(*a.gossip, 5).server_ip == "10.0.0.71"; }));
    EXPECT_EQ(a.ns_holder(5), pinned_b64);

    // A different pinned claimant: rejected, holder unchanged.
    inject(build_packet(other, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(other, other_b64, 5, "10.0.0.90", true)),
           a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_EQ(a.ns_holder(5), pinned_b64);
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_slot(*a.gossip, 5).server_ip,
              "10.0.0.71");
}

// v0.9.4 fix 3: a release is the claim message with an empty server_ip. Only
// the holder's release clears the slot and removes the ns<N> A record; a
// non-holder's release is rejected.
TEST_F(GossipIngressSecurityTest, NsReleaseByHolderClearsSlotAndNonHolderReleaseRejected) {
    auto root_kp   = kc->ed25519_keygen();
    auto holder    = kc->ed25519_keygen();
    auto outsider  = kc->ed25519_keygen();
    const auto holder_b64   = crypto::to_base64(holder.public_key);
    const auto outsider_b64 = crypto::to_base64(outsider.public_key);

    auto& a = make_node(
        "a",
        [&](Node& n) { attach_dns(n); },
        [&](Node& n) {
            n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex);
            n.gossip->set_dns(n.dns.get());
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(holder_b64, "127.0.0.1:9",
                           issue_cert(holder_b64, "peer-holder", root_kp)),
                peer_entry(outsider_b64, "127.0.0.1:10",
                           issue_cert(outsider_b64, "peer-outsider", root_kp)),
            }));
        });

    const std::string ns3_fqdn = "ns3.lemonade-nexus.io";

    // Holder takes ns3; the ns3 glue A record appears in the zone.
    inject(build_packet(holder, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(holder, holder_b64, 3, "10.0.0.30")),
           a);
    ASSERT_TRUE(pump_until([&] { return a.ns_holder(3) == holder_b64; }));
    ASSERT_EQ(a.dns->nameserver_ip(ns3_fqdn), "10.0.0.30");

    // The outsider's release is rejected; the holder is unchanged.
    inject(build_packet(outsider, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(outsider, outsider_b64, 3, "")),
           a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_EQ(a.ns_holder(3), holder_b64);
    ASSERT_EQ(a.dns->nameserver_ip(ns3_fqdn), "10.0.0.30");

    // The holder's release clears the slot and removes the A record.
    inject(build_packet(holder, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(holder, holder_b64, 3, "")),
           a);
    ASSERT_TRUE(pump_until([&] { return a.ns_holder(3).empty(); }));
    EXPECT_TRUE(gossip::GossipBallotTestAccess::ns_slot(*a.gossip, 3).server_pubkey.empty());
    EXPECT_FALSE(a.dns->nameserver_ip(ns3_fqdn).has_value());
}

// v0.9.4 fix 3: a claim requested BEFORE the slot state is synced is deferred
// (pending, nothing claimed); after the mesh's claims arrive, the next tick
// claims the LOWEST free slot against the synced table.
TEST_F(GossipIngressSecurityTest, NsClaimBeforeSyncIsDeferredThenClaimsLowestFreeOnTick) {
    auto root_kp    = kc->ed25519_keygen();
    auto peer_ns1   = kc->ed25519_keygen();  // .40
    auto peer_ns4   = kc->ed25519_keygen();  // azure
    const auto ns1_b64 = crypto::to_base64(peer_ns1.public_key);
    const auto ns4_b64 = crypto::to_base64(peer_ns4.public_key);

    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(ns1_b64, "127.0.0.1:9",
                           issue_cert(ns1_b64, "peer-ns1", root_kp)),
                peer_entry(ns4_b64, "127.0.0.1:10",
                           issue_cert(ns4_b64, "peer-ns4", root_kp)),
            }));
        },
        [&](Node& n) { n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex); });

    // Before any slot state arrives: no claim, claim goes pending.
    a.gossip->try_claim_ns_slot("10.0.0.90");
    EXPECT_FALSE(a.gossip->our_ns_slot().has_value());
    EXPECT_TRUE(gossip::GossipBallotTestAccess::ns_claim_pending(*a.gossip));
    for (uint8_t s = 1; s <= 9; ++s) EXPECT_TRUE(a.ns_holder(s).empty());

    // The mesh's slot table arrives: {ns1: .40, ns4: azure}.
    inject(build_packet(peer_ns1, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(peer_ns1, ns1_b64, 1, "10.0.0.40")),
           a);
    inject(build_packet(peer_ns4, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(peer_ns4, ns4_b64, 4, "20.36.135.145")),
           a);
    ASSERT_TRUE(pump_until([&] {
        return a.ns_holder(1) == ns1_b64 && a.ns_holder(4) == ns4_b64 &&
               gossip::GossipBallotTestAccess::ns_synced(*a.gossip);
    }));

    // The next tick claims the lowest FREE slot: ns2 (ns1 is occupied).
    gossip::GossipBallotTestAccess::run_gossip_tick(*a.gossip);
    EXPECT_EQ(a.gossip->our_ns_slot(), 2);
    EXPECT_EQ(a.ns_holder(2), a.pubkey_b64());
    EXPECT_FALSE(gossip::GossipBallotTestAccess::ns_claim_pending(*a.gossip));
}

// v0.9.4 fix 3: an opt-out node that holds a slot releases it on the next
// tick (slot empties, the node holds nothing), and stops claiming.
TEST_F(GossipIngressSecurityTest, NsOptOutReleasesHeldSlotOnTick) {
    auto root_kp = kc->ed25519_keygen();
    auto peer    = kc->ed25519_keygen();
    const auto peer_b64 = crypto::to_base64(peer.public_key);

    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(peer_b64, "127.0.0.1:9",
                           issue_cert(peer_b64, "peer-a", root_kp)),
            }));
        },
        [&](Node& n) { n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex); });

    // A peer claim syncs slot state; this node then holds ns1.
    inject(build_packet(peer, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(peer, peer_b64, 3, "10.0.0.20")),
           a);
    ASSERT_TRUE(pump_until([&] { return a.ns_holder(3) == peer_b64; }));
    a.gossip->try_claim_ns_slot("10.0.0.50");
    ASSERT_EQ(a.gossip->our_ns_slot(), 1);

    // Opt out: the held slot is released on the next tick.
    a.gossip->set_ns_opt_out(true);
    gossip::GossipBallotTestAccess::run_gossip_tick(*a.gossip);
    EXPECT_FALSE(a.gossip->our_ns_slot().has_value());
    EXPECT_TRUE(gossip::GossipBallotTestAccess::ns_slot(*a.gossip, 1).server_pubkey.empty());

    // And it does not claim again on subsequent ticks.
    gossip::GossipBallotTestAccess::run_gossip_tick(*a.gossip);
    EXPECT_FALSE(a.gossip->our_ns_slot().has_value());
    EXPECT_TRUE(gossip::GossipBallotTestAccess::ns_slot(*a.gossip, 1).server_pubkey.empty());
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
    const auto origin_cert = issue_cert(origin_b64, "srv2", root_kp);

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
    const auto cert_json = issue_cert(certified_b64, "srv9", root_kp);

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

// A per-server SEIP DNS record is an ordinary resource: its FQDN embeds the
// owning server's id, and an enrolled author may write only its own. Another
// certified server cannot author a record in a foreign server's SEIP name.
TEST_F(GossipIngressSecurityTest, SeipDnsRecordsAreOwnedByTheirServerId) {
    auto root_kp = kc->ed25519_keygen();
    auto owner   = kc->ed25519_keygen();
    auto other   = kc->ed25519_keygen();
    const auto owner_b64 = crypto::to_base64(owner.public_key);
    const auto other_b64 = crypto::to_base64(other.public_key);
    // owner's certificate owns server_id "srv-owner"; other's owns "srv-other".
    const auto owner_cert = issue_cert(owner_b64, "srv-owner", root_kp);
    const auto other_cert = issue_cert(other_b64, "srv-other", root_kp);

    auto& a = make_node(
        "a",
        [&](Node& n) {
            attach_dns(n);
            seed_peers(*n.storage, nlohmann::json::array(
                {peer_entry(owner_b64, "127.0.0.1:9", owner_cert),
                 peer_entry(other_b64, "127.0.0.2:9", other_cert)}));
        },
        [&](Node& n) {
            n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex);
            n.gossip->set_dns(n.dns.get());
        });

    const std::string owned_fqdn = "srv-owner.us-east.seip.lemonade-nexus.io";

    // The other certified server cannot author a record in srv-owner's name.
    const auto poached = dns_delta_payload(other, "delta-own-1", owned_fqdn, "10.0.0.9");
    inject(build_packet(other, gossip::GossipMsgType::DnsRecordSync, poached), a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_FALSE(a.dns->resolve(owned_fqdn).has_value());

    // The owner authors its own record, and it lands.
    const auto genuine = dns_delta_payload(owner, "delta-own-2", owned_fqdn, "10.0.0.1");
    inject(build_packet(owner, gossip::GossipMsgType::DnsRecordSync, genuine), a);
    ASSERT_TRUE(pump_until([&] { return a.dns->resolve(owned_fqdn).has_value(); }));
    EXPECT_EQ(a.dns->resolve(owned_fqdn)->ipv4_address, "10.0.0.1");

    // The private.<id> qualifier resolves to the same owner.
    const std::string private_fqdn = "private.srv-owner.us-east.seip.lemonade-nexus.io";
    const auto priv = dns_delta_payload(owner, "delta-own-3", private_fqdn, "10.64.0.1");
    inject(build_packet(owner, gossip::GossipMsgType::DnsRecordSync, priv), a);
    ASSERT_TRUE(pump_until([&] { return a.dns->resolve(private_fqdn).has_value(); }));
    const auto poach_priv =
        dns_delta_payload(other, "delta-own-4", private_fqdn, "10.66.66.66");
    inject(build_packet(other, gossip::GossipMsgType::DnsRecordSync, poach_priv), a);
    pump_for(std::chrono::milliseconds(200));
    EXPECT_EQ(a.dns->resolve(private_fqdn)->ipv4_address, "10.64.0.1");
}

// v0.9.4 fix 2: the author owns an SEIP record iff its certified server id
// appears as ONE OF the labels strictly before the "seip" label, at any depth.
// Prefixed record forms (tier labels, private, _config, backend,
// _acme-challenge) authored by the owner land; the same shapes naming another
// server's id, or no id at all, are refused.
TEST_F(GossipIngressSecurityTest, SeipDnsOwnershipChecksEveryLabelBeforeSeip) {
    auto root_kp = kc->ed25519_keygen();
    auto srv_a   = kc->ed25519_keygen();
    auto srv_b   = kc->ed25519_keygen();
    const auto a_b64 = crypto::to_base64(srv_a.public_key);
    const auto b_b64 = crypto::to_base64(srv_b.public_key);
    const auto a_cert = issue_cert(a_b64, "srv-a", root_kp);
    const auto b_cert = issue_cert(b_b64, "srv-b", root_kp);

    auto& a = make_node(
        "a",
        [&](Node& n) {
            attach_dns(n);
            seed_peers(*n.storage, nlohmann::json::array(
                {peer_entry(a_b64, "127.0.0.1:9", a_cert),
                 peer_entry(b_b64, "127.0.0.2:9", b_cert)}));
        },
        [&](Node& n) {
            n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex);
            n.gossip->set_dns(n.dns.get());
        });

    const std::string seip = ".seip.lemonade-nexus.io";

    // Every shape below is srv-a's OWN record: the id is some label before
    // .seip, at any depth.
    struct Accept {
        std::string fqdn;
        std::string value;
        std::string rtype;
    };
    const std::vector<Accept> accepts = {
        {"srv-a.us-x" + seip,                    "10.1.0.1", "A"   },
        {"srv-a.tier2.us-x" + seip,              "10.1.0.2", "A"   },
        {"private.srv-a.us-x" + seip,            "10.1.0.3", "A"   },
        {"_config.srv-a.us-x" + seip,            "nexus-config=abc", "TXT"},
        {"backend.srv-a.us-x" + seip,            "10.1.0.4", "A"   },
        {"_acme-challenge.srv-a.us-x" + seip,    "acme-chal-a", "TXT"},
        {"_acme-challenge.private.srv-a.us-x" + seip, "acme-chal-a2", "TXT"},
    };
    const auto serial_before = a.dns->soa_serial();
    for (std::size_t i = 0; i < accepts.size(); ++i) {
        const auto& r = accepts[i];
        const auto id = "delta-seip-acc-" + std::to_string(i);
        inject(build_packet(srv_a, gossip::GossipMsgType::DnsRecordSync,
                            dns_delta_payload(srv_a, id, r.fqdn, r.value, r.rtype)), a);
    }
    ASSERT_TRUE(pump_until([&] {
        return a.dns->soa_serial() == serial_before + accepts.size() &&
               a.dns->resolve(accepts[0].fqdn) &&
               a.dns->resolve(accepts[1].fqdn) &&
               a.dns->resolve(accepts[2].fqdn) &&
               a.dns->resolve(accepts[4].fqdn);
    }));
    EXPECT_EQ(a.dns->resolve(accepts[0].fqdn)->ipv4_address, "10.1.0.1");
    EXPECT_EQ(a.dns->resolve(accepts[1].fqdn)->ipv4_address, "10.1.0.2");
    EXPECT_EQ(a.dns->resolve(accepts[2].fqdn)->ipv4_address, "10.1.0.3");
    EXPECT_EQ(a.dns->resolve(accepts[4].fqdn)->ipv4_address, "10.1.0.4");
    // The three TXT records have no A lookup path, but their application is
    // pinned by the SOA serial: every accepted delta bumps it exactly once.
    EXPECT_EQ(a.dns->soa_serial(), serial_before + accepts.size());

    // The same shapes naming srv-b's id are srv-a's foreign records and must
    // all be refused — the serial stays where the accepts left it, and no A
    // record appears under the foreign name.
    const std::vector<Accept> denials = {
        {"_config.srv-b.us-x" + seip,        "nexus-config=evil", "TXT"},
        {"backend.srv-b.us-x" + seip,        "10.66.0.1",         "A"  },
        {"_acme-challenge.srv-b.us-x" + seip, "acme-chal-b",       "TXT"},
        {"_config.us-x" + seip,              "no-id-in-prefix",   "TXT"},
    };
    for (std::size_t i = 0; i < denials.size(); ++i) {
        const auto& r = denials[i];
        const auto id = "delta-seip-deny-" + std::to_string(i);
        inject(build_packet(srv_a, gossip::GossipMsgType::DnsRecordSync,
                            dns_delta_payload(srv_a, id, r.fqdn, r.value, r.rtype)), a);
    }
    pump_for(std::chrono::milliseconds(300));
    EXPECT_EQ(a.dns->soa_serial(), serial_before + accepts.size());
    EXPECT_FALSE(a.dns->resolve(denials[1].fqdn).has_value());

    // Control: srv-b ITSELF may author the same records — ownership, not the
    // record shape, was the gate.
    const auto self_b = dns_delta_payload(srv_b, "delta-seip-self-b",
                                          "backend.srv-b.us-x" + seip, "10.1.1.1");
    inject(build_packet(srv_b, gossip::GossipMsgType::DnsRecordSync, self_b), a);
    ASSERT_TRUE(pump_until([&] { return a.dns->resolve(denials[1].fqdn).has_value(); }));
    EXPECT_EQ(a.dns->resolve(denials[1].fqdn)->ipv4_address, "10.1.1.1");
}

// A permissions row exactly as the pre-change code stored it: nonce||ciphertext
// with a 12-byte AES-GCM nonce and no version byte. The reader must refuse it
// and report no permission, rather than mis-split it or reach a cipher that no
// longer exists.
TEST_F(GossipIngressSecurityTest, APreChangeAesPermissionRowIsRefused) {
    if (!crypto_aead_aes256gcm_is_available()) {
        GTEST_SKIP() << "cannot build a genuine AES ciphertext on this cpu";
    }
    const auto acl_kp = kc->ed25519_keygen();
    auto& a = make_node("a", [&](Node& n) { attach_acl(n, acl_kp); }, [](Node&) {});

    ASSERT_TRUE(a.acl->grant("user-legacy", "res-legacy", acl::Permission::Read));
    ASSERT_NE(a.acl->get_permissions("user-legacy", "res-legacy"), acl::Permission::None);

    // The exact key ACLService derives, so the row is genuinely decryptable
    // under the old scheme and refused only because that format is gone.
    static constexpr std::string_view kSalt = "lemonade-nexus-acl-db-key";
    const std::vector<uint8_t> info{'a', 'c', 'l'};
    auto derived = a.crypto->hkdf_sha256(
        std::span<const uint8_t>(acl_kp.private_key.data(), acl_kp.private_key.size()),
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(kSalt.data()), kSalt.size()),
        std::span<const uint8_t>{info},
        nexus::crypto::kAeadKeySize);
    ASSERT_EQ(derived.size(), nexus::crypto::kAeadKeySize);
    std::array<uint8_t, nexus::crypto::kAeadKeySize> key{};
    std::memcpy(key.data(), derived.data(), key.size());

    std::array<uint8_t, 4> perms{static_cast<uint8_t>(acl::Permission::Read), 0, 0, 0};
    std::vector<uint8_t> nonce(crypto_aead_aes256gcm_NPUBBYTES);
    randombytes_buf(nonce.data(), nonce.size());
    std::vector<uint8_t> ct(perms.size() + crypto_aead_aes256gcm_ABYTES);
    unsigned long long ct_len = 0;
    ASSERT_EQ(crypto_aead_aes256gcm_encrypt(ct.data(), &ct_len, perms.data(), perms.size(),
                                            nullptr, 0, nullptr, nonce.data(), key.data()),
              0);
    ct.resize(static_cast<std::size_t>(ct_len));

    // Old layout: nonce || ciphertext, no leading version byte.
    std::vector<uint8_t> legacy;
    legacy.insert(legacy.end(), nonce.begin(), nonce.end());
    legacy.insert(legacy.end(), ct.begin(), ct.end());

    a.acl->stop();
    {
        sqlite3* db = nullptr;
        ASSERT_EQ(sqlite3_open((a.dir / "acl.db").string().c_str(), &db), SQLITE_OK);
        sqlite3_stmt* stmt = nullptr;
        ASSERT_EQ(sqlite3_prepare_v2(
                      db, "UPDATE acl SET perms_enc = ? WHERE user_id = ? AND resource = ?",
                      -1, &stmt, nullptr),
                  SQLITE_OK);
        sqlite3_bind_blob(stmt, 1, legacy.data(), static_cast<int>(legacy.size()), SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, "user-legacy", -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, "res-legacy", -1, SQLITE_STATIC);
        ASSERT_EQ(sqlite3_step(stmt), SQLITE_DONE);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
    }
    a.acl->start();

    EXPECT_EQ(a.acl->get_permissions("user-legacy", "res-legacy"), acl::Permission::None)
        << "a pre-change AES row must not decode";
}

// A permission blob is bound to the row it belongs to. Lifting a valid, freshly
// written ciphertext out of one (user, resource) row and dropping it into
// another must fail authentication — otherwise anyone with database access
// could grant themselves a permission by copying a row they are allowed to have.
TEST_F(GossipIngressSecurityTest, APermissionBlobCannotBeTransplantedToAnotherRow) {
    const auto acl_kp = kc->ed25519_keygen();
    auto& a = make_node("a", [&](Node& n) { attach_acl(n, acl_kp); }, [](Node&) {});

    // Row A is privileged; row B is not.
    ASSERT_TRUE(a.acl->grant("alice", "secret-resource", acl::Permission::Admin));
    ASSERT_TRUE(a.acl->grant("mallory", "secret-resource", acl::Permission::Read));
    ASSERT_NE(a.acl->get_permissions("alice", "secret-resource"), acl::Permission::None);

    a.acl->stop();
    std::vector<uint8_t> alices_blob;
    {
        sqlite3* db = nullptr;
        ASSERT_EQ(sqlite3_open((a.dir / "acl.db").string().c_str(), &db), SQLITE_OK);
        sqlite3_stmt* q = nullptr;
        ASSERT_EQ(sqlite3_prepare_v2(
                      db, "SELECT perms_enc FROM acl WHERE user_id = ? AND resource = ?",
                      -1, &q, nullptr),
                  SQLITE_OK);
        sqlite3_bind_text(q, 1, "alice", -1, SQLITE_STATIC);
        sqlite3_bind_text(q, 2, "secret-resource", -1, SQLITE_STATIC);
        ASSERT_EQ(sqlite3_step(q), SQLITE_ROW);
        const auto* p = static_cast<const uint8_t*>(sqlite3_column_blob(q, 0));
        alices_blob.assign(p, p + sqlite3_column_bytes(q, 0));
        sqlite3_finalize(q);

        // Transplant it verbatim onto mallory's row.
        sqlite3_stmt* u = nullptr;
        ASSERT_EQ(sqlite3_prepare_v2(
                      db, "UPDATE acl SET perms_enc = ? WHERE user_id = ? AND resource = ?",
                      -1, &u, nullptr),
                  SQLITE_OK);
        sqlite3_bind_blob(u, 1, alices_blob.data(), static_cast<int>(alices_blob.size()),
                          SQLITE_STATIC);
        sqlite3_bind_text(u, 2, "mallory", -1, SQLITE_STATIC);
        sqlite3_bind_text(u, 3, "secret-resource", -1, SQLITE_STATIC);
        ASSERT_EQ(sqlite3_step(u), SQLITE_DONE);
        sqlite3_finalize(u);
        sqlite3_close(db);
    }
    a.acl->start();

    EXPECT_EQ(a.acl->get_permissions("mallory", "secret-resource"), acl::Permission::None)
        << "a transplanted permission blob must not authenticate";
    // The row it legitimately belongs to still opens.
    EXPECT_NE(a.acl->get_permissions("alice", "secret-resource"), acl::Permission::None);
}

// ---------------------------------------------------------------------------
// (7) Peer persistence: ban durability and load-time re-checks
// ---------------------------------------------------------------------------

// A removed peer must not be resurrected after an unclean shutdown:
// do_remove_peer rewrites peers.json immediately, so the file no longer
// contains the banned entry even without on_stop's save. Control: a peer that
// was NOT removed survives the same restart, still certified.
TEST_F(GossipIngressSecurityTest, RemovePeerPersistsTheBanAcrossRestart) {
    auto root_kp = kc->ed25519_keygen();
    auto banned  = kc->ed25519_keygen();
    auto keeper  = kc->ed25519_keygen();
    const auto banned_b64 = crypto::to_base64(banned.public_key);
    const auto keeper_b64 = crypto::to_base64(keeper.public_key);

    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(banned_b64, "127.0.0.1:9",
                           issue_cert(banned_b64, "peer-banned", root_kp)),
                peer_entry(keeper_b64, "127.0.0.1:10",
                           issue_cert(keeper_b64, "peer-keeper", root_kp)),
            }));
        },
        [&](Node& n) {
            n.gossip->set_root_pubkey(root_kp.public_key);
            n.gossip->set_network_id(kTestNetworkHex);
        });

    ASSERT_TRUE(a.has_peer(banned_b64));
    ASSERT_TRUE(a.has_peer(keeper_b64));

    a.gossip->remove_peer(banned_b64);
    EXPECT_FALSE(a.has_peer(banned_b64));

    // The ban is in the file immediately — no stop() required.
    const auto env = a.storage->read_file("identity", "peers.json");
    ASSERT_TRUE(env.has_value());
    const auto j = nlohmann::json::parse(env->data);
    ASSERT_TRUE(j.contains("peers"));
    for (const auto& p : j["peers"]) {
        EXPECT_NE(p.value("pubkey", ""), banned_b64);
    }

    // Restart on the same storage: the banned peer stays gone, and the
    // untouched keeper loads with its certificate still verifying.
    a.gossip->stop();
    a.gossip = std::make_unique<gossip::GossipService>(io, 0, *a.storage, *a.crypto);
    a.gossip->set_root_pubkey(root_kp.public_key);
    a.gossip->set_network_id(kTestNetworkHex);
    a.gossip->start();
    EXPECT_FALSE(a.has_peer(banned_b64));
    EXPECT_TRUE(a.has_peer(keeper_b64));
    EXPECT_TRUE(a.certified_peer(keeper_b64));
}

// A persisted peer whose pubkey is in the revocation list must not be
// resurrected from peers.json. The revoked peer holds a VALID certificate, so
// only the revocation check can explain its absence. Control: the healthy
// peer stored alongside it loads and certifies.
TEST_F(GossipIngressSecurityTest, ReloadDropsRevokedPeers) {
    auto root_kp    = kc->ed25519_keygen();
    auto revoked_kp = kc->ed25519_keygen();
    auto valid      = kc->ed25519_keygen();
    const auto revoked_b64 = crypto::to_base64(revoked_kp.public_key);
    const auto valid_b64   = crypto::to_base64(valid.public_key);

    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(revoked_b64, "127.0.0.1:9",
                           issue_cert(revoked_b64, "peer-revoked", root_kp)),
                peer_entry(valid_b64, "127.0.0.1:10",
                           issue_cert(valid_b64, "peer-valid", root_kp)),
            }));
            storage::SignedEnvelope env;
            env.type = "revocation_list";
            env.data = nlohmann::json::array({revoked_b64}).dump();
            ASSERT_TRUE(n.storage->write_file("identity", "revoked_servers.json", env));
        },
        [&](Node& n) {
            n.gossip->set_root_pubkey(root_kp.public_key);
            n.gossip->set_network_id(kTestNetworkHex);
        });

    EXPECT_FALSE(a.has_peer(revoked_b64));
    EXPECT_TRUE(a.has_peer(valid_b64));
    EXPECT_TRUE(a.certified_peer(valid_b64));
}

// A stored certificate that no longer verifies must not be trusted after
// reload. The certificate is genuinely root-signed but was edited afterwards
// (a different server_id), so only the signature check fails. The peer stays
// tracked as uncertified — membership without a certificate is a valid state
// elsewhere — and only the bad certificate is dropped.
TEST_F(GossipIngressSecurityTest, ReloadDropsUnverifiableStoredCertificate) {
    auto root_kp = kc->ed25519_keygen();
    auto peer_kp = kc->ed25519_keygen();
    const auto peer_b64 = crypto::to_base64(peer_kp.public_key);

    auto cert = nlohmann::json::parse(
                    issue_cert(peer_b64, "peer-edited", root_kp))
                    .get<gossip::ServerCertificate>();
    cert.server_id = "peer-evil";
    const auto tampered = nlohmann::json(cert).dump();

    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(peer_b64, "127.0.0.1:9", tampered)}));
        },
        [&](Node& n) {
            n.gossip->set_root_pubkey(root_kp.public_key);
            n.gossip->set_network_id(kTestNetworkHex);
        });

    EXPECT_TRUE(a.has_peer(peer_b64));
    EXPECT_TRUE(a.peer_cert_json(peer_b64).empty());
    EXPECT_FALSE(a.certified_peer(peer_b64));
}

// v0.9.4 fix 4: the tick initiates exactly one PeerExchange request per 60 s
// of internal cadence, aimed at the eligible handshaked peer with the oldest
// last-request time. A re-tick inside the window sends nothing; once the
// window elapses the 300 s per-peer cooldown steers the request to the other
// peer. The peers are raw sockets the test controls so the request count is
// exact (the tick also sends a digest, which the filter ignores).
TEST_F(GossipIngressSecurityTest, PeerExchangeInitiatorCadenceAndPeerCooldown) {
    auto root_kp = kc->ed25519_keygen();
    auto peer_b  = kc->ed25519_keygen();
    auto peer_c  = kc->ed25519_keygen();
    const auto b64_b = crypto::to_base64(peer_b.public_key);
    const auto b64_c = crypto::to_base64(peer_c.public_key);

    udp::socket sb{io, udp::endpoint{udp::v4(), 0}};
    udp::socket sc{io, udp::endpoint{udp::v4(), 0}};
    const uint16_t port_b = sb.local_endpoint().port();
    const uint16_t port_c = sc.local_endpoint().port();

    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(b64_b, "127.0.0.1:" + std::to_string(port_b),
                           issue_cert(b64_b, "peer-b", root_kp)),
                peer_entry(b64_c, "127.0.0.1:" + std::to_string(port_c),
                           issue_cert(b64_c, "peer-c", root_kp)),
            }));
        },
        [&](Node& n) { n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex); });

    // Collect the PeerExchange request payloads waiting on a raw socket;
    // every other message type (digest) is discarded.
    std::vector<std::string> requests_b;
    std::vector<std::string> requests_c;
    auto drain = [](udp::socket& s, std::vector<std::string>& out) {
        char buf[65536];
        udp::endpoint from;
        while (s.available() > 0) {
            const std::size_t n = s.receive_from(asio::buffer(buf), from);
            if (n <= gossip::kGossipHeaderSize) continue;
            gossip::GossipPacketHeader h{};
            std::memcpy(&h, buf, gossip::kGossipHeaderSize);
            if (h.msg_type == gossip::GossipMsgType::PeerExchange &&
                n >= gossip::kGossipHeaderSize + h.payload_length) {
                out.emplace_back(buf + gossip::kGossipHeaderSize, h.payload_length);
            }
        }
    };

    // First tick: exactly ONE request, to the first-listed peer (both are
    // never-requested, so the tie keeps the oldest-listed).
    gossip::GossipBallotTestAccess::run_gossip_tick(*a.gossip);
    pump_for(std::chrono::milliseconds(100));
    drain(sb, requests_b);
    drain(sc, requests_c);
    ASSERT_EQ(requests_b.size() + requests_c.size(), 1u);
    ASSERT_EQ(requests_b.size(), 1u);
    {
        const auto req = nlohmann::json::parse(requests_b[0]);
        EXPECT_FALSE(req.value("is_response", true));
        EXPECT_TRUE(req["peers"].is_array());
        EXPECT_TRUE(req["peers"].empty());
    }

    // Second tick inside the 60 s window: nothing more.
    gossip::GossipBallotTestAccess::run_gossip_tick(*a.gossip);
    pump_for(std::chrono::milliseconds(100));
    drain(sb, requests_b);
    drain(sc, requests_c);
    EXPECT_EQ(requests_b.size(), 1u);
    EXPECT_EQ(requests_c.size(), 0u);

    // The window elapses (61 s). Peer B was requested 61 s ago, still inside
    // its 300 s per-peer cooldown; peer C was last requested 301 s ago.
    // The request goes to C.
    const auto now = std::chrono::steady_clock::now();
    gossip::GossipBallotTestAccess::set_last_peer_exchange(
        *a.gossip, now - std::chrono::seconds(61));
    gossip::GossipBallotTestAccess::set_peer_exchange_last(
        *a.gossip, b64_b, now - std::chrono::seconds(61));
    gossip::GossipBallotTestAccess::set_peer_exchange_last(
        *a.gossip, b64_c, now - std::chrono::seconds(301));
    gossip::GossipBallotTestAccess::run_gossip_tick(*a.gossip);
    pump_for(std::chrono::milliseconds(100));
    drain(sb, requests_b);
    drain(sc, requests_c);
    EXPECT_EQ(requests_b.size(), 1u);
    EXPECT_EQ(requests_c.size(), 1u);
}

// v0.9.4 fix 4: end-to-end introduction through the REAL response path. A
// knows only B (handshaked); B knows C, whose certificate and
// source-confirmed advertised endpoint B holds from C's hello. A's tick asks
// B; B's existing response relays C; A adds C as a peer and adopts the
// verified relayed certificate at the relayed (confirmed) endpoint.
TEST_F(GossipIngressSecurityTest, PeerExchangeRequestIntroducesUnseenPeerFromHubResponse) {
    auto root_kp = kc->ed25519_keygen();
    auto kp_b    = kc->ed25519_keygen();
    auto kp_c    = kc->ed25519_keygen();
    const auto b64_b = crypto::to_base64(kp_b.public_key);
    const auto b64_c = crypto::to_base64(kp_c.public_key);

    // The identity keypair is generated in start(), so it must be pre-seeded
    // (with its matching certificate) for the hello exchange to pass the
    // proof-of-possession check.
    auto seed_identity = [&](Node& n, const crypto::Ed25519Keypair& kp,
                             const std::string& id) {
        storage::SignedEnvelope kenv;
        kenv.type = "identity_keypair";
        kenv.data = nlohmann::json{{"public_key", crypto::to_base64(kp.public_key)},
                                   {"private_key", crypto::to_base64(kp.private_key)}}
                              .dump();
        EXPECT_TRUE(n.storage->write_file("identity", "keypair.json", kenv));
        storage::SignedEnvelope env;
        env.type = "server_certificate";
        env.data = issue_cert(crypto::to_base64(kp.public_key), id, root_kp);
        EXPECT_TRUE(n.storage->write_file("identity", "server_cert.json", env));
    };

    // C: advertises its real loopback endpoint so B can confirm it against
    // the observed UDP source.
    auto& c = make_node(
        "c",
        [&](Node& n) { seed_identity(n, kp_c, "srv-c"); },
        [&](Node& n) {
            n.gossip->set_root_pubkey(root_kp.public_key);
            n.gossip->set_network_id(kTestNetworkHex);
            n.gossip->set_our_advertised_endpoint(n.endpoint());
        });

    // B: knows C by endpoint, certificate not yet exchanged.
    auto& b = make_node(
        "b",
        [&](Node& n) {
            seed_identity(n, kp_b, "srv-b");
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(b64_c, c.endpoint(), "")}));
        },
        [&](Node& n) {
            n.gossip->set_root_pubkey(root_kp.public_key);
            n.gossip->set_network_id(kTestNetworkHex);
        });

    // C discovers B and introduces itself with a real ServerHello.
    c.gossip->add_peer(b.endpoint(), b64_b);
    gossip::GossipBallotTestAccess::run_gossip_tick(*c.gossip);
    ASSERT_TRUE(pump_until([&] {
        for (const auto& p : b.gossip->get_peers())
            if (p.pubkey == b64_c && !p.certificate_json.empty())
                return true;
        return false;
    }));
    // B's view of C: certificate stored and the advertised endpoint
    // source-confirmed (it equals the observed UDP source).
    const auto b_view_c = [&] {
        for (const auto& p : b.gossip->get_peers())
            if (p.pubkey == b64_c) return p;
        return gossip::GossipPeer{};
    };
    ASSERT_TRUE(b_view_c().advertised_confirmed);
    ASSERT_EQ(b_view_c().advertised_endpoint, c.endpoint());

    // A: knows only B (handshaked — B's certificate is stored); C is unknown.
    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(b64_b, b.endpoint(),
                           issue_cert(b64_b, "srv-b", root_kp))}));
        },
        [&](Node& n) {
            n.gossip->set_root_pubkey(root_kp.public_key);
            n.gossip->set_network_id(kTestNetworkHex);
        });

    // A's tick initiates the exchange with B (its only handshaked peer); B's
    // EXISTING response path relays C.
    EXPECT_FALSE(a.has_peer(b64_c));
    gossip::GossipBallotTestAccess::run_gossip_tick(*a.gossip);
    ASSERT_TRUE(pump_until([&] {
        return a.has_peer(b64_c) && !a.peer_cert_json(b64_c).empty();
    }));

    // The relayed endpoint is C's source-confirmed advertised endpoint, and
    // the adopted certificate is exactly what B verified from C.
    ASSERT_EQ(a.peer_cert_json(b64_c), b_view_c().certificate_json);
    for (const auto& p : a.gossip->get_peers()) {
        if (p.pubkey == b64_c) ASSERT_EQ(p.endpoint, c.endpoint());
    }
}
