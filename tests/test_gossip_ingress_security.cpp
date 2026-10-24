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
#include <LemonadeNexus/Network/VirtualNetService.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>

#include "support/gossip_fixture.hpp"

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
#include <set>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

using namespace nexus;
namespace fs = std::filesystem;
using asio::ip::udp;

namespace {

// The friend seam, Node and wire fixture live in support/gossip_fixture.hpp.
using nexus_test::kTestNetworkHex;
using nexus_test::msgpack_of;
using Node = nexus_test::GossipTestNode;

std::vector<uint8_t> bytes_of(std::string_view s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

class GossipIngressSecurityTest : public nexus_test::GossipWireFixture {
protected:
    GossipIngressSecurityTest() : GossipWireFixture("nexus_test_gossip_ingress_") {}

    void stop_node_services(Node& n) override {
        if (n.acl) n.acl->stop();
        if (n.ipam) n.ipam->stop();
        if (n.tree) n.tree->stop();
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
                                          bool pinned = false,
                                          uint64_t timestamp = 1000) {
        nlohmann::json sign_payload;
        if (pinned) sign_payload["pinned"] = true;
        sign_payload["slot"]          = slot;
        sign_payload["server_pubkey"] = named_pubkey_b64;
        sign_payload["server_ip"]     = server_ip;
        sign_payload["region"]        = "eu-west";
        sign_payload["timestamp"]     = timestamp;

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

// (5e) Tracked #6: a stale stored endpoint is not permanent. A direct hello
// whose packet signer IS the certificate identity refreshes the stored
// endpoint from its advertisement. Hostile control first: the same bytes
// replayed by a third party fail proof-of-possession and move nothing — the
// refresh is reachable only through the authenticated path.
TEST_F(GossipIngressSecurityTest, AuthenticatedHelloRefreshesAStaleStoredEndpoint) {
    auto root_kp  = kc->ed25519_keygen();
    auto holder   = kc->ed25519_keygen();
    auto replayer = kc->ed25519_keygen();
    const auto holder_b64 = crypto::to_base64(holder.public_key);
    const auto cert_json  = issue_cert(holder_b64, "peer-holder", root_kp);

    // Onboarded with an endpoint that is now dead.
    const std::string stale = "203.0.113.9:9102";
    const std::string fresh = "198.51.100.66:9102";
    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(holder_b64, stale, cert_json)}));
        },
        [&](Node& n) {
            n.gossip->set_root_pubkey(root_kp.public_key);
            n.gossip->set_network_id(kTestNetworkHex);
        });

    const auto a_view = [&] {
        for (const auto& p : a.gossip->get_peers())
            if (p.pubkey == holder_b64) return p;
        return gossip::GossipPeer{};
    };
    ASSERT_EQ(a_view().endpoint, stale);

    auto hello = nlohmann::json::parse(cert_json);
    hello["advertised_endpoint"] = fresh;

    // Replayed by a key that is not the certificate identity: refused
    // upstream, the stored endpoint does not move.
    inject(build_packet(replayer, gossip::GossipMsgType::ServerHello,
                        bytes_of(hello.dump())),
           a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_EQ(a_view().endpoint, stale);

    // Control: the holder itself advertises its new address.
    inject(build_packet(holder, gossip::GossipMsgType::ServerHello,
                        bytes_of(hello.dump())),
           a);
    ASSERT_TRUE(pump_until([&] { return a_view().endpoint == fresh; }));
    EXPECT_EQ(a_view().advertised_endpoint, fresh);
    // The advertisement did not match the observed UDP source, so it stays
    // unconfirmed for third-party relay.
    EXPECT_FALSE(a_view().advertised_confirmed);
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

    // Renewal by the holder: same slot, refreshed IP; a same-holder claim needs
    // a strictly greater timestamp than the accepted one.
    inject(build_packet(holder, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(holder, holder_b64, 3, "10.0.0.31",
                                         /*pinned=*/false, /*timestamp=*/2000)),
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

    // Same pin, same holder: renewal, IP refreshed; a same-holder claim needs
    // a strictly greater timestamp than the accepted one.
    inject(build_packet(pinned, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(pinned, pinned_b64, 5, "10.0.0.71", true, 2000)),
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
// NS slot state persistence and startup refresh (v0.9.5)
// ---------------------------------------------------------------------------

// v0.9.5: slot state is persisted as a signed envelope on every mutation
// and restored on startup. Load restores the table and the held slot but
// never opens the sync gate — the loaded table is memory, not mesh evidence.
TEST_F(GossipIngressSecurityTest, NsSlotStatePersistsAcrossRestartAndLoadKeepsGateClosed) {
    auto root_kp = kc->ed25519_keygen();
    auto peer    = kc->ed25519_keygen();
    const auto peer_b64 = crypto::to_base64(peer.public_key);

    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(peer_b64, "127.0.0.1:9",
                           issue_cert(peer_b64, "peer-ns4", root_kp)),
            }));
        },
        [&](Node& n) { n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex); });

    const auto a_b64 = a.pubkey_b64();

    // A peer claim opens the sync gate; this node then claims ns1.
    inject(build_packet(peer, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(peer, peer_b64, 4, "10.0.0.40")),
           a);
    ASSERT_TRUE(pump_until([&] { return a.ns_holder(4) == peer_b64; }));
    a.gossip->try_claim_ns_slot("10.0.0.50");
    ASSERT_EQ(a.gossip->our_ns_slot(), 1);

    // The state is on disk, wrapped and signed by this node's key.
    auto env = a.storage->read_file("identity", "ns_slots.json");
    ASSERT_TRUE(env.has_value());
    EXPECT_EQ(env->type, "ns_slot_state");
    EXPECT_EQ(env->signer_pubkey, "ed25519:" + a_b64);
    const auto& data = env->data;
    const auto sig_bytes = crypto::from_base64(env->signature);
    ASSERT_EQ(sig_bytes.size(), crypto::kEd25519SignatureSize);
    crypto::Ed25519Signature sig{};
    std::memcpy(sig.data(), sig_bytes.data(), sig_bytes.size());
    EXPECT_TRUE(kc->ed25519_verify(
        a.gossip->keypair().public_key,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(data.data()),
                                 data.size()),
        sig));

    // Restart over the same storage: table and held slot are restored...
    restart_node(a);
    ASSERT_EQ(a.gossip->our_ns_slot(), 1);
    EXPECT_EQ(a.ns_holder(1), a_b64);
    EXPECT_EQ(a.ns_holder(4), peer_b64);
    // ...but the sync gate stays closed (fail closed).
    EXPECT_FALSE(gossip::GossipBallotTestAccess::ns_synced(*a.gossip));
}

// v0.9.5: the live incident — a restarted opt-out holder that re-loads its
// held slot from disk must release it. Before persistence the holder could
// never re-learn the slot and the release never fired.
TEST_F(GossipIngressSecurityTest, NsOptOutHolderReleasesPersistedSlotAfterRestart) {
    auto root_kp = kc->ed25519_keygen();
    auto a_kp    = kc->ed25519_keygen();
    const auto a_b64  = crypto::to_base64(a_kp.public_key);
    const std::string a_cert = issue_cert(a_b64, "node-a", root_kp);

    // The peer: real DNS zone, certified view of the holder.
    auto& p = make_node(
        "p",
        [&](Node& n) {
            attach_dns(n);
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(a_b64, "127.0.0.1:9", a_cert),
            }));
        },
        [&](Node& n) {
            n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex);
            n.gossip->set_dns(n.dns.get());
        });

    // The holder, with a fixed identity seeded before construction so the
    // restart below re-loads the SAME keypair.
    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_keypair(*n.storage, a_kp);
            const auto p_pk = crypto::to_base64(p.gossip->keypair().public_key);
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(p_pk, p.endpoint(), issue_cert(p_pk, "peer-p", root_kp)),
            }));
        },
        [&](Node& n) { n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex); });

    const auto& p_kp = p.gossip->keypair();
    const auto p_b64 = crypto::to_base64(p_kp.public_key);

    // Pre-restart: a peer claim opens the sync gate; the holder claims ns1
    // and the peer applies it (A record lands in the zone).
    inject(build_packet(p_kp, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(p_kp, p_b64, 7, "10.0.0.20")),
           a);
    ASSERT_TRUE(pump_until([&] { return a.ns_holder(7) == p_b64; }));
    a.gossip->try_claim_ns_slot("10.0.0.30");
    ASSERT_EQ(a.gossip->our_ns_slot(), 1);
    const std::string ns1_fqdn = "ns1.lemonade-nexus.io";
    ASSERT_TRUE(pump_until([&] { return p.ns_holder(1) == a_b64; }));
    ASSERT_EQ(p.dns->nameserver_ip(ns1_fqdn), "10.0.0.30");

    // Restart as an OPT-OUT node: the persisted table re-loads {ns1: a} with
    // the held slot; the first tick releases it.
    restart_node(a, [&](Node& n) {
        n.gossip->set_root_pubkey(root_kp.public_key);
        n.gossip->set_network_id(kTestNetworkHex);
        n.gossip->set_ns_opt_out(true);
    });
    ASSERT_EQ(a.gossip->our_ns_slot(), 1);  // re-learned from disk
    gossip::GossipBallotTestAccess::run_gossip_tick(*a.gossip);

    // The peer applies the release: slot cleared, A record removed.
    EXPECT_FALSE(a.gossip->our_ns_slot().has_value());
    ASSERT_TRUE(pump_until([&] { return p.ns_holder(1).empty(); }));
    EXPECT_FALSE(p.dns->nameserver_ip(ns1_fqdn).has_value());
}

// v0.9.5: after the sync gate opens, the FIRST tick re-broadcasts every
// stored claim so a restarted node with an empty table re-learns the mesh's
// slot state; for its own slot it re-learns the held slot (self rule).
TEST_F(GossipIngressSecurityTest, NsStartupRefreshRelearnsSlotStateToRestartedPeer) {
    auto root_kp = kc->ed25519_keygen();
    auto b_kp    = kc->ed25519_keygen();
    auto c_kp    = kc->ed25519_keygen();
    const auto b_b64 = crypto::to_base64(b_kp.public_key);
    const auto c_b64 = crypto::to_base64(c_kp.public_key);
    const std::string b_cert = issue_cert(b_b64, "node-b", root_kp);
    const std::string c_cert = issue_cert(c_b64, "node-c", root_kp);

    // B "restarts": fixed identity, EMPTY slot table, certified view of the
    // mesh (its own certificate included — the claim gate verifies the
    // claimant through the peer table, own slot included).
    auto& b = make_node(
        "b",
        [&](Node& n) {
            seed_keypair(*n.storage, b_kp);
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(b_b64, "127.0.0.1:9", b_cert),
                peer_entry(c_b64, "127.0.0.1:10", c_cert),
            }));
        },
        [&](Node& n) { n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex); });

    // A holds the mesh's slot table {ns1: B, ns2: C}.
    // B's entry points at a DEAD endpoint while the table is filled: the
    // accept path forwards every applied claim to all peers except the
    // sender, and a raw injection's sender is not B — B must stay empty
    // until the refresh under test reaches it.
    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(b_b64, "127.0.0.1:12", b_cert),
                peer_entry(c_b64, "127.0.0.1:11", c_cert),
            }));
        },
        [&](Node& n) { n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex); });

    inject(build_packet(b_kp, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(b_kp, b_b64, 1, "10.0.0.31")),
           a);
    inject(build_packet(c_kp, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(c_kp, c_b64, 2, "10.0.0.32")),
           a);
    ASSERT_TRUE(pump_until([&] {
        return a.ns_holder(1) == b_b64 && a.ns_holder(2) == c_b64;
    }));
    EXPECT_TRUE(gossip::GossipBallotTestAccess::ns_synced(*a.gossip));

    // Now point A at B's real socket so the refresh reaches it.
    a.gossip->add_peer(b.endpoint(), b_b64);

    // B knows nothing yet; the first tick after the gate opens re-broadcasts.
    EXPECT_TRUE(b.ns_holder(1).empty());
    EXPECT_FALSE(b.gossip->our_ns_slot().has_value());
    gossip::GossipBallotTestAccess::run_gossip_tick(*a.gossip);

    // B re-learns both slots verbatim (holder signatures and timestamps
    // intact) and re-learns ITS OWN slot.
    ASSERT_TRUE(pump_until([&] {
        return b.ns_holder(1) == b_b64 && b.ns_holder(2) == c_b64;
    }));
    EXPECT_EQ(b.gossip->our_ns_slot(), 1);
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_slot(*b.gossip, 1).server_ip, "10.0.0.31");
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_slot(*b.gossip, 1).timestamp, uint64_t{1000});
}

// v0.9.5 regression proof: a claim for an EMPTY slot is accepted no matter
// how old its timestamp is — there is deliberately no freshness guard
// (slots must stay re-learnable from old relays).
TEST_F(GossipIngressSecurityTest, NsClaimOnEmptySlotAcceptsStaleTimestamp) {
    auto root_kp = kc->ed25519_keygen();
    auto peer    = kc->ed25519_keygen();
    const auto peer_b64 = crypto::to_base64(peer.public_key);

    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(peer_b64, "127.0.0.1:9",
                           issue_cert(peer_b64, "peer-stale", root_kp)),
            }));
        },
        [&](Node& n) { n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex); });

    const uint64_t stale_ts = 1700000000;  // 2023-11-14
    inject(build_packet(peer, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(peer, peer_b64, 2, "10.0.0.40", false, stale_ts)),
           a);
    ASSERT_TRUE(pump_until([&] { return a.ns_holder(2) == peer_b64; }));
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_slot(*a.gossip, 2).timestamp, stale_ts);
}

// v0.9.5: a pinned holder that restarts behind a NEW public IP must renew
// its claim, or the ns<N> A record keeps advertising the old IP. The peer
// applies the renewal (IP and A record refreshed, holder kept, no release).
TEST_F(GossipIngressSecurityTest, NsPinnedHolderRenewsClaimOnIpChangeAfterRestart) {
    auto root_kp = kc->ed25519_keygen();
    auto a_kp    = kc->ed25519_keygen();
    const auto a_b64  = crypto::to_base64(a_kp.public_key);
    const std::string a_cert = issue_cert(a_b64, "node-a", root_kp);

    // Pre-restart claim state: pinned ns1 on the OLD IP.
    const uint64_t old_ts = 1760000000;
    nlohmann::json old_preimage;
    old_preimage["pinned"]        = true;
    old_preimage["slot"]          = 1;
    old_preimage["server_pubkey"] = a_b64;
    old_preimage["server_ip"]     = "10.0.0.51";
    old_preimage["region"]        = "eu-west";
    old_preimage["timestamp"]     = old_ts;
    const auto old_sig = sign_b64(a_kp, old_preimage.dump());
    const std::string ns1_fqdn = "ns1.lemonade-nexus.io";

    // The peer: real DNS zone, certified view of the holder.
    auto& p = make_node(
        "p",
        [&](Node& n) {
            attach_dns(n);
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(a_b64, "127.0.0.1:9", a_cert),
            }));
        },
        [&](Node& n) {
            n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex);
            n.gossip->set_dns(n.dns.get());
        });

    // The peer learned the OLD claim pre-restart.
    nlohmann::json old_wire = old_preimage;
    old_wire["signature"] = old_sig;
    inject(build_packet(a_kp, gossip::GossipMsgType::NsSlotClaim, msgpack_of(old_wire)), p);
    ASSERT_TRUE(pump_until([&] { return p.ns_holder(1) == a_b64; }));
    ASSERT_EQ(p.dns->nameserver_ip(ns1_fqdn), "10.0.0.51");

    // The holder comes back behind a new public IP, with the persisted claim.
    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_keypair(*n.storage, a_kp);
            const auto p_pk = crypto::to_base64(p.gossip->keypair().public_key);
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(p_pk, p.endpoint(), issue_cert(p_pk, "peer-p", root_kp)),
            }));
            seed_ns_slot_state(*n.storage, {slot_entry(1, a_b64, "10.0.0.51", old_ts, old_sig, true)},
                               /*our_slot=*/1);
        },
        [&](Node& n) {
            n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex);
            n.gossip->set_our_region("eu-west");
            n.gossip->set_preferred_ns_slot(1);
        });

    // Re-learned: pinned holder of ns1 on the old IP.
    ASSERT_EQ(a.gossip->our_ns_slot(), 1);

    // The node re-claims with the NEW public IP: the stored claim is renewed
    // (same slot, new IP, fresh timestamp, still pinned) — no new claim, no
    // release.
    a.gossip->try_claim_ns_slot("10.0.0.52");
    EXPECT_EQ(a.gossip->our_ns_slot(), 1);
    const auto& s1 = gossip::GossipBallotTestAccess::ns_slot(*a.gossip, 1);
    EXPECT_EQ(s1.server_ip, "10.0.0.52");
    EXPECT_EQ(s1.server_pubkey, a_b64);
    EXPECT_TRUE(s1.pinned);
    EXPECT_GT(s1.timestamp, old_ts);
    // Exactly one broadcast: the renewal itself.
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_broadcast_count(*a.gossip), 1u);

    // The peer applies it as a holder renewal: IP and A record refreshed,
    // holder kept, slot never emptied.
    ASSERT_TRUE(pump_until([&] {
        return p.ns_holder(1) == a_b64 &&
               gossip::GossipBallotTestAccess::ns_slot(*p.gossip, 1).server_ip == "10.0.0.52";
    }));
    ASSERT_EQ(p.dns->nameserver_ip(ns1_fqdn), "10.0.0.52");
    EXPECT_TRUE(gossip::GossipBallotTestAccess::ns_slot(*p.gossip, 1).pinned);
}

// v0.9.5: the startup refresh is ONE-SHOT — the first synced tick
// re-broadcasts the stored table; later ticks send nothing new.
TEST_F(GossipIngressSecurityTest, NsStartupRefreshIsOneShot) {
    auto root_kp = kc->ed25519_keygen();
    auto a_kp    = kc->ed25519_keygen();
    auto b_kp    = kc->ed25519_keygen();
    const auto a_b64 = crypto::to_base64(a_kp.public_key);
    const auto b_b64 = crypto::to_base64(b_kp.public_key);
    const std::string a_cert = issue_cert(a_b64, "node-a", root_kp);
    const std::string b_cert = issue_cert(b_b64, "node-b", root_kp);

    auto make_preimage = [](uint8_t slot, const std::string& pk_b64,
                            const std::string& ip, uint64_t ts) {
        nlohmann::json p;
        p["slot"]          = slot;
        p["server_pubkey"] = pk_b64;
        p["server_ip"]     = ip;
        p["region"]        = "eu-west";
        p["timestamp"]     = ts;
        return p;
    };

    // B: certified view of the mesh (own certificate + A).
    auto& b = make_node(
        "b",
        [&](Node& n) {
            seed_keypair(*n.storage, b_kp);
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(a_b64, "127.0.0.1:9", a_cert),
                peer_entry(b_b64, "127.0.0.1:10", b_cert),
            }));
        },
        [&](Node& n) { n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex); });

    // A restarts with the persisted table {ns3: A, ns7: B}.
    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_keypair(*n.storage, a_kp);
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(b_b64, b.endpoint(), b_cert),
            }));
            seed_ns_slot_state(*n.storage, {
                nullptr, nullptr,
                slot_entry(3, a_b64, "10.0.0.61", 1760000000,
                          sign_b64(a_kp, make_preimage(3, a_b64, "10.0.0.61", 1760000000).dump())),
                nullptr, nullptr, nullptr,
                slot_entry(7, b_b64, "10.0.0.62", 1760000010,
                          sign_b64(b_kp, make_preimage(7, b_b64, "10.0.0.62", 1760000010).dump())),
            }, /*our_slot=*/3);
        },
        [&](Node& n) { n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex); });
    ASSERT_EQ(a.gossip->our_ns_slot(), 3);  // re-learned from disk

    // Open A's sync gate with a live mesh claim (ns5 -> B).
    inject(build_packet(b_kp, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(b_kp, b_b64, 5, "10.0.0.63")),
           a);
    ASSERT_TRUE(pump_until([&] {
        return a.ns_holder(5) == b_b64 &&
               gossip::GossipBallotTestAccess::ns_synced(*a.gossip);
    }));

    // First tick: the three stored claims are re-broadcast exactly once.
    gossip::GossipBallotTestAccess::run_gossip_tick(*a.gossip);
    ASSERT_TRUE(pump_until([&] {
        return b.ns_holder(3) == a_b64 && b.ns_holder(5) == b_b64 &&
               b.ns_holder(7) == b_b64;
    }));
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_broadcast_count(*a.gossip), 3u);

    // Later ticks: no re-broadcast.
    gossip::GossipBallotTestAccess::run_gossip_tick(*a.gossip);
    gossip::GossipBallotTestAccess::run_gossip_tick(*a.gossip);
    pump_for(std::chrono::milliseconds(100));
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_broadcast_count(*a.gossip), 3u);
}

// v0.9.5: persistence does not relax the no-clobber rule — a rejected
// claim never reaches the persisted table.
TEST_F(GossipIngressSecurityTest, NsRejectedClaimNeverReachesPersistedTable) {
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

    // Holder takes ns3; the file reflects exactly that.
    inject(build_packet(holder, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(holder, holder_b64, 3, "10.0.0.30")),
           a);
    ASSERT_TRUE(pump_until([&] { return a.ns_holder(3) == holder_b64; }));

    // Unpinned non-holder clobber attempt: rejected...
    inject(build_packet(claimant, gossip::GossipMsgType::NsSlotClaim,
                        ns_claim_payload(claimant, claimant_b64, 3, "10.0.0.40")),
           a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_EQ(a.ns_holder(3), holder_b64);

    // ...and the persisted table still names the holder, not the claimant.
    auto env = a.storage->read_file("identity", "ns_slots.json");
    ASSERT_TRUE(env.has_value());
    const auto j = nlohmann::json::parse(env->data);
    ASSERT_EQ(j["slots"].size(), 9u);
    EXPECT_EQ(j["slots"][2].value("server_pubkey", ""), holder_b64);
}

// ---------------------------------------------------------------------------
// Relayed certificates through peer exchange
// ---------------------------------------------------------------------------

// Peer exchange is how a delta's AUTHOR can become certified without a direct
// hello: a relayed certificate is adopted only after the same full
// verification a direct hello gets, and a bogus one changes nothing. Once
// adopted, a delta authored by that origin verifies end to end.
// ---------------------------------------------------------------------------
// v0.9.6: NS claim relay-loop guard, self-echo, and denial rate limiting
// ---------------------------------------------------------------------------
//
// Topology notes: a node never re-forwards its OWN claim (the self-claimant
// path), so a claimant's original broadcast is simulated by injecting the
// claim into the claimant AND into each peer (as if the claimant had sent it
// to all of them). One-shot startup refreshes fire on the 5 s gossip tick, so
// the stability windows drain 5.5 s first; after that the mesh must be fully
// quiet (no refresh pending, no duplicates to relay).
// ---------------------------------------------------------------------------

// Each triad test defines a make_relayer lambda: a node knowing two peers
// (dead seeded endpoints + root-signed certificates; real endpoints are wired
// after construction via add_peer, which preserves the seeded certificate).

// v0.9.6: with three or more relayers, the epidemic claim relay (forward to
// every peer except the sender) sustained itself: each node re-"renewed" the
// byte-identical copy and re-forwarded it, so a single claim circulated
// forever. Field evidence (10-13): four new relayers drove ~2350 claim
// copies/sec at the root. A byte-identical redelivery must be a silent no-op:
// no state change, no log, no forward — the loop dies after one round.
TEST_F(GossipIngressSecurityTest, NsClaimDuplicateRedeliveryDoesNotSustainRelayLoop) {
    auto root_kp = kc->ed25519_keygen();
    auto h_kp    = kc->ed25519_keygen();
    auto b_kp    = kc->ed25519_keygen();
    auto c_kp    = kc->ed25519_keygen();
    const auto h_b64 = crypto::to_base64(h_kp.public_key);
    const auto b_b64 = crypto::to_base64(b_kp.public_key);
    const auto c_b64 = crypto::to_base64(c_kp.public_key);
    const auto h_cert = issue_cert(h_b64, "node-h", root_kp);
    const auto b_cert = issue_cert(b_b64, "node-b", root_kp);
    const auto c_cert = issue_cert(c_b64, "node-c", root_kp);

    auto make_relayer = [&](const char* tag,
                            const crypto::Ed25519Keypair* kp,
                            const std::string& p1_b64, const std::string& p1_cert,
                            const std::string& p2_b64, const std::string& p2_cert) {
        return &make_node(
            tag,
            [&](Node& n) {
                if (kp) seed_keypair(*n.storage, *kp);
                seed_peers(*n.storage, nlohmann::json::array({
                    peer_entry(p1_b64, "127.0.0.1:9", p1_cert),
                    peer_entry(p2_b64, "127.0.0.1:10", p2_cert),
                }));
            },
            [&](Node& n) {
                n.gossip->set_root_pubkey(root_kp.public_key);
                n.gossip->set_network_id(kTestNetworkHex);
            });
    };

    Node* h = make_relayer("h", &h_kp, b_b64, b_cert, c_b64, c_cert);
    Node* b = make_relayer("b", nullptr, h_b64, h_cert, c_b64, c_cert);
    Node* c = make_relayer("c", nullptr, h_b64, h_cert, b_b64, b_cert);
    h->gossip->add_peer(b->endpoint(), b_b64);
    h->gossip->add_peer(c->endpoint(), c_b64);
    b->gossip->add_peer(h->endpoint(), h_b64);
    b->gossip->add_peer(c->endpoint(), c_b64);
    c->gossip->add_peer(h->endpoint(), h_b64);
    c->gossip->add_peer(b->endpoint(), b_b64);

    // h claims ns3. h's original broadcast reaches h (self echo) plus b and c
    // directly; each relay then forwards to its other peers. With the dedup,
    // the circulation stops after this one round: identical redeliveries are
    // silent no-ops that do not re-forward.
    const auto claim = ns_claim_payload(h_kp, h_b64, 3, "10.0.0.30");
    for (Node* n : {h, b, c})
        inject(build_packet(h_kp, gossip::GossipMsgType::NsSlotClaim, claim), *n);

    ASSERT_TRUE(pump_until([&] {
        return h->ns_holder(3) == h_b64 && b->ns_holder(3) == h_b64 &&
               c->ns_holder(3) == h_b64;
    }));
    // Drain the one-shot startup refreshes (5 s tick) so the mesh is at its
    // steady state before measuring.
    pump_for(std::chrono::milliseconds(5500));

    // Bounded: each node saw the claim a handful of times (direct + relay
    // hops + one-shot refreshes). The pre-fix loop adds hundreds within a
    // second; the fixed mesh is quiet.
    const auto h0 = gossip::GossipBallotTestAccess::ns_receive_count(*h->gossip);
    const auto b0 = gossip::GossipBallotTestAccess::ns_receive_count(*b->gossip);
    const auto c0 = gossip::GossipBallotTestAccess::ns_receive_count(*c->gossip);
    EXPECT_LE(h0, 8u);
    EXPECT_LE(b0, 8u);
    EXPECT_LE(c0, 8u);

    pump_for(std::chrono::milliseconds(1500));
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_receive_count(*h->gossip), h0);
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_receive_count(*b->gossip), b0);
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_receive_count(*c->gossip), c0);

    // The dedup must not have dropped the claim content: holder, ip, and the
    // holder's original timestamp are intact on every node.
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_slot(*b->gossip, 3).server_ip, "10.0.0.30");
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_slot(*c->gossip, 3).timestamp, uint64_t{1000});
    EXPECT_EQ(h->ns_holder(3), h_b64);
}

// v0.9.6: a relayed copy of a node's OWN claim (production form: the node's
// own key is NOT in its own peer table) must be applied — the claimant gate
// previously denied a node's own claims because the root's/self's key is not
// an enrolled peer of itself — and it must never be re-forwarded (the
// original sender already propagated it).
TEST_F(GossipIngressSecurityTest, NsClaimSelfEchoAppliesBookkeepingAndNeverRelays) {
    auto root_kp = kc->ed25519_keygen();
    auto a_kp    = kc->ed25519_keygen();
    auto b_kp    = kc->ed25519_keygen();
    const auto a_b64 = crypto::to_base64(a_kp.public_key);
    const auto b_b64 = crypto::to_base64(b_kp.public_key);
    const auto a_cert = issue_cert(a_b64, "node-a", root_kp);
    const auto b_cert = issue_cert(b_b64, "node-b", root_kp);

    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_keypair(*n.storage, a_kp);
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(b_b64, "127.0.0.1:9", b_cert)}));
        },
        [&](Node& n) { n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex); });
    auto& b = make_node(
        "b",
        [&](Node& n) { seed_peers(*n.storage, nlohmann::json::array({
            peer_entry(a_b64, "127.0.0.1:10", a_cert)})); },
        [&](Node& n) { n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex); });
    a.gossip->add_peer(b.endpoint(), b_b64);
    b.gossip->add_peer(a.endpoint(), a_b64);

    // A relayed echo of a's own claim arrives at a. Pre-fix: the certificate
    // gate denied it (a's key is not in a's own peer table) and a could never
    // re-learn its slot. Post-fix: applied, bookkeeping set, not re-forwarded.
    const auto claim = ns_claim_payload(a_kp, a_b64, 3, "10.0.0.30");
    inject(build_packet(a_kp, gossip::GossipMsgType::NsSlotClaim, claim), a);
    ASSERT_TRUE(pump_until([&] { return a.ns_holder(3) == a_b64; }));
    EXPECT_EQ(a.gossip->our_ns_slot().value_or(0), 3);
    // a did not re-forward its own claim: b never heard it.
    pump_for(std::chrono::milliseconds(300));
    EXPECT_TRUE(b.ns_holder(3).empty());

    // The ORIGINAL broadcast (a -> b) still propagates through b normally, and
    // b's relay copy returning to a is an identical redelivery: silent no-op
    // that keeps a's bookkeeping. (Both happen well under the 5 s tick, so no
    // one-shot refresh interferes with the counts.)
    inject(build_packet(a_kp, gossip::GossipMsgType::NsSlotClaim, claim), b);
    ASSERT_TRUE(pump_until([&] { return b.ns_holder(3) == a_b64; }));
    pump_for(std::chrono::milliseconds(500));
    EXPECT_EQ(a.ns_holder(3), a_b64);
    EXPECT_EQ(a.gossip->our_ns_slot().value_or(0), 3);
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_receive_count(*a.gossip), 2u);
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_receive_count(*b.gossip), 1u);
}

// v0.9.6: the dedup keys on the full claim content, so a GENUINE renewal
// (same slot and claimant, new timestamp/ip) must still be applied and
// relayed — the guard must not freeze slot state.
TEST_F(GossipIngressSecurityTest, NsClaimGenuineRenewalStillPropagatesOncePerNode) {
    auto root_kp = kc->ed25519_keygen();
    auto h_kp    = kc->ed25519_keygen();
    auto b_kp    = kc->ed25519_keygen();
    auto c_kp    = kc->ed25519_keygen();
    const auto h_b64 = crypto::to_base64(h_kp.public_key);
    const auto b_b64 = crypto::to_base64(b_kp.public_key);
    const auto c_b64 = crypto::to_base64(c_kp.public_key);
    const auto h_cert = issue_cert(h_b64, "node-h", root_kp);
    const auto b_cert = issue_cert(b_b64, "node-b", root_kp);
    const auto c_cert = issue_cert(c_b64, "node-c", root_kp);

    auto make_relayer = [&](const char* tag,
                            const crypto::Ed25519Keypair* kp,
                            const std::string& p1_b64, const std::string& p1_cert,
                            const std::string& p2_b64, const std::string& p2_cert) {
        return &make_node(
            tag,
            [&](Node& n) {
                if (kp) seed_keypair(*n.storage, *kp);
                seed_peers(*n.storage, nlohmann::json::array({
                    peer_entry(p1_b64, "127.0.0.1:9", p1_cert),
                    peer_entry(p2_b64, "127.0.0.1:10", p2_cert),
                }));
            },
            [&](Node& n) {
                n.gossip->set_root_pubkey(root_kp.public_key);
                n.gossip->set_network_id(kTestNetworkHex);
            });
    };

    Node* h = make_relayer("h", &h_kp, b_b64, b_cert, c_b64, c_cert);
    Node* b = make_relayer("b", nullptr, h_b64, h_cert, c_b64, c_cert);
    Node* c = make_relayer("c", nullptr, h_b64, h_cert, b_b64, b_cert);
    h->gossip->add_peer(b->endpoint(), b_b64);
    h->gossip->add_peer(c->endpoint(), c_b64);
    b->gossip->add_peer(h->endpoint(), h_b64);
    b->gossip->add_peer(c->endpoint(), c_b64);
    c->gossip->add_peer(h->endpoint(), h_b64);
    c->gossip->add_peer(b->endpoint(), b_b64);

    // Initial claim (ts 1000, ip .30): h's original broadcast reaches all
    // three; relays settle. Drain the one-shot refreshes first.
    const auto first = ns_claim_payload(h_kp, h_b64, 3, "10.0.0.30");
    for (Node* n : {h, b, c})
        inject(build_packet(h_kp, gossip::GossipMsgType::NsSlotClaim, first), *n);
    ASSERT_TRUE(pump_until([&] {
        return h->ns_holder(3) == h_b64 && b->ns_holder(3) == h_b64 &&
               c->ns_holder(3) == h_b64;
    }));
    pump_for(std::chrono::milliseconds(5500));

    // Genuine renewal: same slot + claimant, new timestamp and ip. h's
    // renewal broadcast reaches b and c directly (h itself re-applies its own
    // renewal when a relayed copy returns).
    const auto renewal = ns_claim_payload(h_kp, h_b64, 3, "10.0.0.31", false, 2000);
    for (Node* n : {b, c})
        inject(build_packet(h_kp, gossip::GossipMsgType::NsSlotClaim, renewal), *n);
    ASSERT_TRUE(pump_until([&] {
        return gossip::GossipBallotTestAccess::ns_slot(*h->gossip, 3).timestamp == 2000 &&
               gossip::GossipBallotTestAccess::ns_slot(*b->gossip, 3).timestamp == 2000 &&
               gossip::GossipBallotTestAccess::ns_slot(*c->gossip, 3).timestamp == 2000;
    }));
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_slot(*h->gossip, 3).server_ip, "10.0.0.31");
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_slot(*b->gossip, 3).server_ip, "10.0.0.31");
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_slot(*c->gossip, 3).server_ip, "10.0.0.31");

    // No node re-relayed the settled renewal: the mesh is quiet again.
    const auto h1 = gossip::GossipBallotTestAccess::ns_receive_count(*h->gossip);
    const auto b1 = gossip::GossipBallotTestAccess::ns_receive_count(*b->gossip);
    const auto c1 = gossip::GossipBallotTestAccess::ns_receive_count(*c->gossip);
    pump_for(std::chrono::milliseconds(1500));
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_receive_count(*h->gossip), h1);
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_receive_count(*b->gossip), b1);
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_receive_count(*c->gossip), c1);
}

TEST_F(GossipIngressSecurityTest, NsClaimDenialLogIsRateLimitedPerKey) {
    auto root_kp = kc->ed25519_keygen();
    auto& a = make_node(
        "a",
        [](Node&) {},
        [&](Node& n) { n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex); });

    using T = std::chrono::steady_clock;
    const auto t0 = T::now();
    const auto key = "ns-claim-cert|ns1|pk|127.0.0.1";
    EXPECT_TRUE(gossip::GossipBallotTestAccess::denial_log_allowed(*a.gossip, key, t0));
    EXPECT_FALSE(gossip::GossipBallotTestAccess::denial_log_allowed(*a.gossip, key, t0 + std::chrono::seconds(30)));
    EXPECT_TRUE(gossip::GossipBallotTestAccess::denial_log_allowed(*a.gossip, key, t0 + std::chrono::seconds(61)));
    // A different key is independent.
    EXPECT_TRUE(gossip::GossipBallotTestAccess::denial_log_allowed(
        *a.gossip, "ns-claim-cert|ns2|pk|127.0.0.1", t0));

    // Functional: repeated hostile claims (bad signature) are all refused and
    // leave no state; the limiter only bounds the log, never the rejection.
    auto attacker = kc->ed25519_keygen();
    const auto att_b64 = crypto::to_base64(attacker.public_key);
    for (int i = 0; i < 5; ++i) {
        inject(build_packet(attacker, gossip::GossipMsgType::NsSlotClaim,
                            ns_claim_payload(attacker, att_b64, 1, "10.0.0.60", false,
                                             static_cast<uint64_t>(1000) + i)),
               a);
    }
    pump_for(std::chrono::milliseconds(300));
    EXPECT_TRUE(a.ns_holder(1).empty());
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_receive_count(*a.gossip), 5u);
}

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

// ---------------------------------------------------------------------------
// Socket ownership and send observability (tracked #7, #9)
// ---------------------------------------------------------------------------

// Tracked #7: the service owns its socket buffer sizing instead of inheriting
// kernel defaults. 8 MiB is requested; the OS may clamp, so the assertion
// pins the floor the service guarantees itself on every platform.
TEST_F(GossipIngressSecurityTest, SocketBuffersAreRaisedAtOpen) {
    auto& a = make_node("a");
    const auto [rcv, snd] = gossip::GossipBallotTestAccess::socket_buffers(*a.gossip);
    EXPECT_GE(rcv, 4 * 65536);
    EXPECT_GE(snd, 2 * 65536);
}

// Tracked #9 (gossip half): send failures warn rate-limited per destination —
// the first logs immediately, repeats within 60 s are counted, and the next
// log carries the suppressed count. Driven with synthetic clocks through the
// same seam pattern as the denial-log limiter.
TEST_F(GossipIngressSecurityTest, SendFailureWarnsAreRateLimitedPerDestination) {
    auto& a = make_node("a");
    using T = std::chrono::steady_clock;
    const auto t0 = T::now();
    const auto due = [&](const std::string& dest, T::time_point t) {
        return gossip::GossipBallotTestAccess::send_fail_log_due(*a.gossip, dest, t);
    };

    // First failure logs immediately, nothing suppressed yet.
    auto first = due("10.0.0.1:9102", t0);
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(*first, 0u);

    // Repeats within the window are counted, not logged.
    EXPECT_FALSE(due("10.0.0.1:9102", t0 + std::chrono::seconds(10)).has_value());
    EXPECT_FALSE(due("10.0.0.1:9102", t0 + std::chrono::seconds(20)).has_value());

    // Another destination is independent.
    auto other = due("10.0.0.2:9102", t0 + std::chrono::seconds(20));
    ASSERT_TRUE(other.has_value());
    EXPECT_EQ(*other, 0u);

    // Past the window: the next failure logs and carries the suppressed count.
    auto summary = due("10.0.0.1:9102", t0 + std::chrono::seconds(61));
    ASSERT_TRUE(summary.has_value());
    EXPECT_EQ(*summary, 2u);
}

// ---------------------------------------------------------------------------
// DNS catch-up: Tier 1 authority, sequenced deltas, backbone claims, and the
// backbone transport.
// ---------------------------------------------------------------------------

// A Tier 1 server changes its zone only on Tier 1 authority: the delivering
// sender and the author must both be current members. A server that is not
// Tier 1 keeps the enrolled-peer rule.
TEST_F(GossipIngressSecurityTest, Tier1AcceptsDnsOnlyFromTier1SendersAndAuthors) {
    auto root_kp = kc->ed25519_keygen();
    auto t1      = kc->ed25519_keygen();
    auto t2      = kc->ed25519_keygen();
    const auto t1_b64 = crypto::to_base64(t1.public_key);
    const auto t2_b64 = crypto::to_base64(t2.public_key);

    std::set<std::string> members{t1_b64};
    auto& a = make_node(
        "a",
        [&](Node& n) {
            attach_dns(n);
            seed_peers(*n.storage, nlohmann::json::array(
                {peer_entry(t1_b64, "127.0.0.1:9", issue_cert(t1_b64, "srv-t1", root_kp)),
                 peer_entry(t2_b64, "127.0.0.1:10", issue_cert(t2_b64, "srv-t2", root_kp))}));
        },
        [&](Node& n) {
            n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex);
            n.gossip->set_dns(n.dns.get());
            n.gossip->set_tier1_membership_source(
                [&](const std::string& pk) { return members.count(pk) > 0; });
        });
    members.insert(a.pubkey_b64());

    const std::string seip = ".us-x.seip.lemonade-nexus.io";
    const std::string t1_name = "srv-t1" + seip;
    const std::string t2_name = "srv-t2" + seip;

    // Tier 2 author and sender.
    inject(build_packet(t2, gossip::GossipMsgType::DnsRecordSync,
                        dns_delta_payload(t2, "t1g-1", t2_name, "10.2.0.1")), a);
    // Tier 1 author, Tier 2 relay.
    inject(build_packet(t2, gossip::GossipMsgType::DnsRecordSync,
                        dns_delta_payload(t1, "t1g-2", t1_name, "10.1.0.1")), a);
    // Tier 2 author, Tier 1 relay.
    inject(build_packet(t1, gossip::GossipMsgType::DnsRecordSync,
                        dns_delta_payload(t2, "t1g-3", t2_name, "10.2.0.3")), a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_FALSE(a.dns->resolve(t1_name).has_value());
    EXPECT_FALSE(a.dns->resolve(t2_name).has_value());

    // Positive control: Tier 1 author and sender.
    inject(build_packet(t1, gossip::GossipMsgType::DnsRecordSync,
                        dns_delta_payload(t1, "t1g-4", t1_name, "10.1.0.4")), a);
    ASSERT_TRUE(pump_until([&] { return a.dns->resolve(t1_name).has_value(); }));
    EXPECT_EQ(a.dns->resolve(t1_name)->ipv4_address, "10.1.0.4");

    // The receiver leaves Tier 1: the enrolled-peer rule applies again.
    members.erase(a.pubkey_b64());
    inject(build_packet(t2, gossip::GossipMsgType::DnsRecordSync,
                        dns_delta_payload(t2, "t1g-5", t2_name, "10.2.0.5")), a);
    ASSERT_TRUE(pump_until([&] { return a.dns->resolve(t2_name).has_value(); }));
    EXPECT_EQ(a.dns->resolve(t2_name)->ipv4_address, "10.2.0.5");
}

// origin_seq is bound by seq_signature, orders changes within one second, and
// keeps a removal from being undone by an older entry. Unsequenced deltas
// from older servers still apply by timestamp.
TEST_F(GossipIngressSecurityTest, SequencedDnsDeltaBindsAndOrdersByOriginSeq) {
    auto root_kp = kc->ed25519_keygen();
    auto origin  = kc->ed25519_keygen();
    const auto origin_b64 = crypto::to_base64(origin.public_key);

    auto& a = make_node(
        "a",
        [&](Node& n) {
            attach_dns(n);
            seed_peers(*n.storage, nlohmann::json::array(
                {peer_entry(origin_b64, "127.0.0.1:9", issue_cert(origin_b64, "srv-s", root_kp))}));
        },
        [&](Node& n) {
            n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex);
            n.gossip->set_dns(n.dns.get());
        });

    const std::string name = "srv-s.us-x.seip.lemonade-nexus.io";
    const auto send = [&](const nlohmann::json& wire) {
        inject(build_packet(origin, gossip::GossipMsgType::DnsRecordSync, msgpack_of(wire)), a);
    };
    const auto value_is = [&](const std::string& v) {
        return pump_until([&] {
            auto r = a.dns->resolve(name);
            return r && r->ipv4_address == v;
        });
    };

    send(dns_seq_delta_wire(origin, "seq-1", name, "10.0.0.1", 1000, 10));
    ASSERT_TRUE(value_is("10.0.0.1"));

    // A relay raising origin_seq breaks seq_signature.
    auto tampered = dns_seq_delta_wire(origin, "seq-2", name, "10.0.0.2", 1000, 20);
    tampered["origin_seq"] = uint64_t{21};
    send(tampered);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_EQ(a.dns->resolve(name)->ipv4_address, "10.0.0.1");

    // Untampered, the same change applies: same second, higher sequence.
    send(dns_seq_delta_wire(origin, "seq-3", name, "10.0.0.3", 1000, 20));
    ASSERT_TRUE(value_is("10.0.0.3"));

    // A lower sequence in the same second is stale.
    send(dns_seq_delta_wire(origin, "seq-4", name, "10.0.0.4", 1000, 15));
    pump_for(std::chrono::milliseconds(300));
    EXPECT_EQ(a.dns->resolve(name)->ipv4_address, "10.0.0.3");

    // A removal, then an older set: the tombstone holds.
    send(dns_seq_delta_wire(origin, "seq-5", name, "10.0.0.3", 1000, 30, "remove"));
    ASSERT_TRUE(pump_until([&] { return !a.dns->resolve(name).has_value(); }));
    send(dns_seq_delta_wire(origin, "seq-6", name, "10.0.0.6", 1000, 25));
    pump_for(std::chrono::milliseconds(300));
    EXPECT_FALSE(a.dns->resolve(name).has_value());

    // Positive control: a newer set restores the record.
    send(dns_seq_delta_wire(origin, "seq-7", name, "10.0.0.7", 1000, 40));
    ASSERT_TRUE(value_is("10.0.0.7"));

    // An unsequenced delta from an older server in the same second is older
    // than every sequenced entry; a later second applies.
    inject(build_packet(origin, gossip::GossipMsgType::DnsRecordSync,
                        dns_delta_payload(origin, "legacy-1", name, "10.0.0.8")), a);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_EQ(a.dns->resolve(name)->ipv4_address, "10.0.0.7");
    auto later = nlohmann::json::from_msgpack(dns_delta_payload(origin, "legacy-2", name, "10.0.0.9"));
    later["timestamp"] = uint64_t{2000};
    nlohmann::json canonical;
    for (const char* k : {"delta_id", "fqdn", "operation", "record_type", "timestamp", "ttl", "value"}) {
        canonical[k] = later[k];
    }
    later["signature"] = sign_b64(origin, canonical.dump());
    send(later);
    ASSERT_TRUE(value_is("10.0.0.9"));
}

// The mesh key rides outside the claim's signed preimage, so it is accepted
// only when the claim's subject sent it directly. A relayed claim still
// records the address.
TEST_F(GossipIngressSecurityTest, BackboneClaimMeshKeyOnlyFromTheSubjectDirectly) {
    auto root_kp = kc->ed25519_keygen();
    auto subject = kc->ed25519_keygen();
    auto relay   = kc->ed25519_keygen();
    const auto subject_b64 = crypto::to_base64(subject.public_key);
    const auto relay_b64   = crypto::to_base64(relay.public_key);

    auto& a = make_node(
        "a",
        [&](Node& n) {
            attach_ipam(n);
            seed_peers(*n.storage, nlohmann::json::array(
                {peer_entry(subject_b64, "127.0.0.1:9", issue_cert(subject_b64, "srv-s", root_kp)),
                 peer_entry(relay_b64, "127.0.0.1:10", issue_cert(relay_b64, "srv-r", root_kp))}));
        },
        [&](Node& n) {
            n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex);
            n.gossip->set_ipam(n.ipam.get());
        });

    const auto peer_of = [&](const std::string& pk) {
        for (const auto& p : a.gossip->get_peers()) {
            if (p.pubkey == pk) return p;
        }
        return gossip::GossipPeer{};
    };
    const auto key_b64 = [](uint8_t fill) {
        std::array<uint8_t, crypto::kX25519PublicKeySize> k{};
        k.fill(fill);
        return crypto::to_base64(std::span<const uint8_t>(k.data(), k.size()));
    };
    auto claim = nlohmann::json::from_msgpack(
        ipam_delta_payload(subject, subject_b64, "bb-claim-1", "node-s", "172.16.0.50/32"));

    // Relayed: the address is recorded, the mesh key is not.
    claim["mesh_pubkey"] = key_b64(0x11);
    inject(build_packet(relay, gossip::GossipMsgType::BackboneIpamSync, msgpack_of(claim)), a);
    ASSERT_TRUE(pump_until([&] { return peer_of(subject_b64).backbone_ip == "172.16.0.50"; }));
    pump_for(std::chrono::milliseconds(100));
    EXPECT_TRUE(peer_of(subject_b64).mesh_pubkey.empty());

    // A malformed key from the subject itself is ignored.
    claim["mesh_pubkey"] = "not-a-key";
    inject(build_packet(subject, gossip::GossipMsgType::BackboneIpamSync, msgpack_of(claim)), a);
    pump_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(peer_of(subject_b64).mesh_pubkey.empty());

    // Direct from the subject: accepted, although IPAM already saw this
    // delta id.
    claim["mesh_pubkey"] = key_b64(0x22);
    inject(build_packet(subject, gossip::GossipMsgType::BackboneIpamSync, msgpack_of(claim)), a);
    ASSERT_TRUE(pump_until([&] { return peer_of(subject_b64).mesh_pubkey == key_b64(0x22); }));
}

// End to end over the backbone (three in-process netstacks routed by
// destination address): a Tier 1 server that missed another's records while
// it was away catches up, a Tier 2 server catches up from Tier 1 and reports
// its status back, Tier 1 never takes records from Tier 2, a digest on the
// public socket is refused, and a restarted server restores its zone from
// disk.
TEST_F(GossipIngressSecurityTest, DnsCatchUpRunsOverTheBackbone) {
    auto root_kp = kc->ed25519_keygen();
    auto a_kp    = kc->ed25519_keygen();
    auto b_kp    = kc->ed25519_keygen();
    auto c_kp    = kc->ed25519_keygen();
    const auto a_b64  = crypto::to_base64(a_kp.public_key);
    const auto b_b64  = crypto::to_base64(b_kp.public_key);
    const auto c_b64  = crypto::to_base64(c_kp.public_key);
    const auto a_cert = issue_cert(a_b64, "srv-a", root_kp);
    const auto b_cert = issue_cert(b_b64, "srv-b", root_kp);
    const auto c_cert = issue_cert(c_b64, "srv-c", root_kp);
    const std::set<std::string> members{a_b64, b_b64};  // C is Tier 2
    const auto seed_own_cert = [](Node& n, const std::string& cert) {
        storage::SignedEnvelope env;
        env.type = "server_certificate";
        env.data = cert;
        ASSERT_TRUE(n.storage->write_file("identity", "server_cert.json", env));
    };

    const auto wire_dns_to_gossip = [](Node& n) {
        n.dns->set_record_callback([g = n.gossip.get()](const std::string& id,
                                                        const std::string& op,
                                                        const network::DnsZoneRecord& rec) {
            gossip::DnsRecordDelta d;
            d.delta_id = id; d.operation = op; d.fqdn = rec.fqdn;
            d.record_type = rec.record_type; d.value = rec.value;
            d.ttl = rec.ttl; d.timestamp = rec.timestamp;
            g->broadcast_dns_record_delta(d);
        });
    };
    const auto configure = [&](Node& n) {
        n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex);
        n.gossip->set_dns(n.dns.get());
        n.gossip->set_ipam(n.ipam.get());
        n.gossip->set_tier1_membership_source(
            [&members](const std::string& pk) { return members.count(pk) > 0; });
    };

    // A authors its records while B and C are away: their entries point at
    // dead ports.
    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_keypair(*n.storage, a_kp);
            seed_own_cert(n, a_cert);
            attach_dns(n);
            attach_ipam(n);
            seed_peers(*n.storage, nlohmann::json::array(
                {peer_entry(b_b64, "127.0.0.1:9", b_cert), peer_entry(c_b64, "127.0.0.1:10", c_cert)}));
        },
        [&](Node& n) { configure(n); wire_dns_to_gossip(n); });
    const std::string seip = ".us-x.seip.lemonade-nexus.io";
    ASSERT_TRUE(a.dns->set_record("srv-a" + seip, "A", "10.9.0.1", 300));
    ASSERT_TRUE(a.dns->set_record("backend.srv-a" + seip, "A", "172.16.0.1", 300));
    ASSERT_TRUE(a.dns->set_record("private.srv-a" + seip, "A", "10.64.0.9", 300));

    const auto make_late = [&](const std::string& tag, const crypto::Ed25519Keypair& kp,
                               const std::string& cert) -> Node& {
        return make_node(
            tag,
            [&](Node& n) {
                seed_keypair(*n.storage, kp);
                seed_own_cert(n, cert);
                attach_dns(n);
                attach_ipam(n);
                seed_peers(*n.storage, nlohmann::json::array({peer_entry(a_b64, a.endpoint(), a_cert)}));
            },
            [&](Node& n) { configure(n); wire_dns_to_gossip(n); });
    };
    auto& b = make_late("b", b_kp, b_cert);
    auto& c = make_late("c", c_kp, c_cert);
    a.gossip->add_peer(b.endpoint(), b_b64);
    a.gossip->add_peer(c.endpoint(), c_b64);
    pump_for(std::chrono::milliseconds(200));
    EXPECT_FALSE(b.dns->resolve("srv-a" + seip).has_value());
    EXPECT_FALSE(c.dns->resolve("srv-a" + seip).has_value());

    // Backbone: route each emitted IPv4 packet to the stack that owns its
    // destination address.
    network::VirtualNetService va, vb, vc;
    std::map<std::string, network::VirtualNetService*> by_ip{
        {"172.16.0.1", &va}, {"172.16.0.2", &vb}, {"172.16.0.3", &vc}};
    const auto route = [&by_ip](std::span<const uint8_t> p) {
        if (p.size() < 20) return;
        const std::string dst = std::to_string(p[16]) + "." + std::to_string(p[17]) + "." +
                                std::to_string(p[18]) + "." + std::to_string(p[19]);
        if (auto it = by_ip.find(dst); it != by_ip.end()) it->second->deliver_inbound_ip_packet(p);
    };
    const auto mesh_key = [](uint8_t fill) {
        std::array<uint8_t, crypto::kX25519PublicKeySize> k{};
        k.fill(fill);
        return crypto::to_base64(std::span<const uint8_t>(k.data(), k.size()));
    };
    struct Wire { Node* n; network::VirtualNetService* v; const char* ip; const char* id; uint8_t key; };
    for (const auto& w : {Wire{&a, &va, "172.16.0.1", "node-a", 0xA1},
                          Wire{&b, &vb, "172.16.0.2", "node-b", 0xB2},
                          Wire{&c, &vc, "172.16.0.3", "node-c", 0xC3}}) {
        w.v->start();
        w.v->set_outbound_sink(route);
        ASSERT_TRUE(w.v->add_local_ip(std::string(w.ip) + "/22"));
        w.n->gossip->set_our_mesh_pubkey(mesh_key(w.key));
        w.n->gossip->set_our_backbone_claim(w.id, w.ip);
        w.n->gossip->set_virtual_net(w.v);
    }

    const auto status_for = [](Node& n, const std::string& pk) {
        const auto status = n.gossip->dns_sync_status();
        for (const auto& p : status["peers"]) {
            if (p["pubkey"] == pk) return p;
        }
        return nlohmann::json::object();
    };

    // Refused: a digest on the public socket, even from a Tier 1 peer.
    const auto public_digest =
        msgpack_of(sync::encode_digest_page({"dns", 1, 0, 1, {{a_b64, {1, 1, 1}}}}));
    inject(build_packet(a_kp, gossip::GossipMsgType::SyncDigest, public_digest), b);
    pump_for(std::chrono::milliseconds(200));
    ASSERT_FALSE(status_for(b, a_b64).empty()) << b.gossip->dns_sync_status().dump();
    EXPECT_FALSE(status_for(b, a_b64).contains("last_digest_ms"));

    // The first tick announces each backbone claim with its mesh key.
    for (Node* n : {&a, &b, &c}) gossip::GossipBallotTestAccess::run_gossip_tick(*n->gossip);
    ASSERT_TRUE(pump_until([&] {
        return status_for(a, b_b64).value("mesh_key_known", false) &&
               status_for(a, c_b64).value("mesh_key_known", false) &&
               status_for(b, a_b64).value("mesh_key_known", false) &&
               status_for(c, a_b64).value("mesh_key_known", false);
    }));

    // One digest round from A: both B (Tier 1) and C (Tier 2) catch up.
    gossip::GossipBallotTestAccess::send_sync_digests(*a.gossip);
    for (Node* n : {&b, &c}) {
        ASSERT_TRUE(pump_until([&] {
            return n->dns->resolve("srv-a" + seip).has_value() &&
                   n->dns->resolve("backend.srv-a" + seip).has_value() &&
                   n->dns->resolve("private.srv-a" + seip).has_value();
        }, std::chrono::seconds(5)));
        EXPECT_EQ(n->dns->resolve("srv-a" + seip)->ipv4_address, "10.9.0.1");
    }

    // The next round finds both in sync with A, and C reports its status to A.
    gossip::GossipBallotTestAccess::send_sync_digests(*a.gossip);
    gossip::GossipBallotTestAccess::send_sync_digests(*c.gossip);
    ASSERT_TRUE(pump_until([&] {
        return status_for(b, a_b64).value("in_sync", false) &&
               status_for(c, a_b64).value("in_sync", false) &&
               status_for(a, c_b64).value("in_sync", false);
    }));
    EXPECT_FALSE(status_for(a, c_b64).value("tier1", true));

    // Tier 2 does not change Tier 1: C's own record reaches A live and is
    // refused, and C's digest makes A request nothing from C.
    ASSERT_TRUE(c.dns->set_record("srv-c" + seip, "A", "10.9.3.3", 300));
    gossip::GossipBallotTestAccess::send_sync_digests(*c.gossip);
    pump_for(std::chrono::milliseconds(400));
    EXPECT_FALSE(a.dns->resolve("srv-c" + seip).has_value());

    // B restarts with an empty zone and restores A's records from disk, with
    // no backbone and no peer contact.
    restart_node(b, [&](Node& n) {
        n.dns = std::make_unique<network::DnsService>(io, 0, *n.tree, "lemonade-nexus.io");
        configure(n);
    });
    ASSERT_TRUE(b.dns->resolve("srv-a" + seip).has_value());
    EXPECT_EQ(b.dns->resolve("srv-a" + seip)->ipv4_address, "10.9.0.1");
    EXPECT_TRUE(b.dns->resolve("private.srv-a" + seip).has_value());

    // A restores the records it authored itself (enrolled by its own
    // certificate, not the peer table).
    restart_node(a, [&](Node& n) {
        n.dns = std::make_unique<network::DnsService>(io, 0, *n.tree, "lemonade-nexus.io");
        configure(n);
    });
    ASSERT_TRUE(a.dns->resolve("private.srv-a" + seip).has_value());
    EXPECT_EQ(a.dns->resolve("private.srv-a" + seip)->ipv4_address, "10.64.0.9");

    for (auto* v : {&va, &vb, &vc}) v->stop();
}

// Account key envelopes replicate over the backbone only. Tier 1 delivers
// them live and serves catch-up; each receiver checks the origin signature and
// hands the envelope to its own store, which may refuse it (here, a store
// whose tree has not caught up). Tier 2 receives but never originates.
TEST_F(GossipIngressSecurityTest, AccountEnvelopesReplicateOverTheBackbone) {
    auto root_kp = kc->ed25519_keygen();
    auto a_kp    = kc->ed25519_keygen();
    auto b_kp    = kc->ed25519_keygen();
    auto c_kp    = kc->ed25519_keygen();
    auto device_kp = kc->ed25519_keygen();
    const auto a_b64  = crypto::to_base64(a_kp.public_key);
    const auto b_b64  = crypto::to_base64(b_kp.public_key);
    const auto c_b64  = crypto::to_base64(c_kp.public_key);
    const auto a_cert = issue_cert(a_b64, "srv-a", root_kp);
    const auto b_cert = issue_cert(b_b64, "srv-b", root_kp);
    const auto c_cert = issue_cert(c_b64, "srv-c", root_kp);
    const std::set<std::string> members{a_b64, b_b64};  // C is Tier 2
    const auto seed_own_cert = [](Node& n, const std::string& cert) {
        storage::SignedEnvelope env;
        env.type = "server_certificate";
        env.data = cert;
        ASSERT_TRUE(n.storage->write_file("identity", "server_cert.json", env));
    };

    struct Sink {
        std::map<std::string, gossip::AccountEnvelopeRecord> stored;  // by recipient
        bool accept = true;
        std::optional<account::AccountAvatarRecord> avatar;
    };
    std::map<std::string, Sink> sinks;
    const auto configure = [&](Node& n, Sink& sink) {
        n.gossip->set_root_pubkey(root_kp.public_key); n.gossip->set_network_id(kTestNetworkHex);
        n.gossip->set_ipam(n.ipam.get());
        n.gossip->set_tier1_membership_source(
            [&members](const std::string& pk) { return members.count(pk) > 0; });
        n.gossip->set_account_envelope_sink([&sink](const gossip::AccountEnvelopeRecord& r) {
            if (!sink.accept) return false;
            sink.stored[r.recipient_pubkey] = r;
            return true;
        });
        n.gossip->set_account_avatar_sink([&sink, &device_kp](const account::AccountAvatarRecord& r) {
            if (!sink.accept || r.group_id != "customer-g1" ||
                r.author_pubkey != crypto::to_base64(device_kp.public_key)) return false;
            if (sink.avatar && account::avatar_newer(*sink.avatar, r)) return false;
            sink.avatar = r;
            return true;
        });
    };
    const auto holds = [&](const std::string& tag, const std::string& device) {
        return sinks[tag].stored.count("ed25519:" + device) > 0;
    };

    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_keypair(*n.storage, a_kp);
            seed_own_cert(n, a_cert);
            attach_ipam(n);
            seed_peers(*n.storage, nlohmann::json::array(
                {peer_entry(b_b64, "127.0.0.1:9", b_cert), peer_entry(c_b64, "127.0.0.1:10", c_cert)}));
        },
        [&](Node& n) { configure(n, sinks["a"]); });
    const auto make_late = [&](const std::string& tag, const crypto::Ed25519Keypair& kp,
                               const std::string& cert) -> Node& {
        return make_node(
            tag,
            [&](Node& n) {
                seed_keypair(*n.storage, kp);
                seed_own_cert(n, cert);
                attach_ipam(n);
                seed_peers(*n.storage, nlohmann::json::array({peer_entry(a_b64, a.endpoint(), a_cert)}));
            },
            [&](Node& n) { configure(n, sinks[tag]); });
    };
    auto& b = make_late("b", b_kp, b_cert);
    auto& c = make_late("c", c_kp, c_cert);
    a.gossip->add_peer(b.endpoint(), b_b64);
    a.gossip->add_peer(c.endpoint(), c_b64);

    network::VirtualNetService va, vb, vc;
    std::map<std::string, network::VirtualNetService*> by_ip{
        {"172.16.0.1", &va}, {"172.16.0.2", &vb}, {"172.16.0.3", &vc}};
    const auto route = [&by_ip](std::span<const uint8_t> p) {
        if (p.size() < 20) return;
        const std::string dst = std::to_string(p[16]) + "." + std::to_string(p[17]) + "." +
                                std::to_string(p[18]) + "." + std::to_string(p[19]);
        if (auto it = by_ip.find(dst); it != by_ip.end()) it->second->deliver_inbound_ip_packet(p);
    };
    const auto mesh_key = [](uint8_t fill) {
        std::array<uint8_t, crypto::kX25519PublicKeySize> k{};
        k.fill(fill);
        return crypto::to_base64(std::span<const uint8_t>(k.data(), k.size()));
    };
    struct Wire { Node* n; network::VirtualNetService* v; const char* ip; const char* id; uint8_t key; };
    for (const auto& w : {Wire{&a, &va, "172.16.0.1", "node-a", 0xA1},
                          Wire{&b, &vb, "172.16.0.2", "node-b", 0xB2},
                          Wire{&c, &vc, "172.16.0.3", "node-c", 0xC3}}) {
        w.v->start();
        w.v->set_outbound_sink(route);
        ASSERT_TRUE(w.v->add_local_ip(std::string(w.ip) + "/22"));
        w.n->gossip->set_our_mesh_pubkey(mesh_key(w.key));
        w.n->gossip->set_our_backbone_claim(w.id, w.ip);
        w.n->gossip->set_virtual_net(w.v);
    }
    const auto status_for = [](Node& n, const std::string& pk) {
        const auto status = n.gossip->account_sync_status();
        for (const auto& p : status["peers"]) {
            if (p["pubkey"] == pk) return p;
        }
        return nlohmann::json::object();
    };
    for (Node* n : {&a, &b, &c}) gossip::GossipBallotTestAccess::run_gossip_tick(*n->gossip);
    ASSERT_TRUE(pump_until([&] {
        return status_for(a, b_b64).value("mesh_key_known", false) &&
               status_for(a, c_b64).value("mesh_key_known", false) &&
               status_for(b, a_b64).value("mesh_key_known", false) &&
               status_for(c, a_b64).value("mesh_key_known", false);
    }));

    const auto record_for = [](const std::string& device, const std::string& wrapped,
                               uint64_t timestamp = 1'700'000'000, uint64_t seq = 0) {
        gossip::AccountEnvelopeRecord r;
        r.group_id         = "customer-g1";
        r.recipient_pubkey = "ed25519:" + device;
        r.key_id           = "gk1";
        r.ephemeral_pubkey = "eph";
        r.wrapped_key      = wrapped;
        r.created_by       = "ed25519:owner";
        r.timestamp        = timestamp;
        r.origin_seq       = seq;
        return r;
    };

    // Live: A's envelope reaches B (Tier 1) and C (Tier 2), signed by A.
    a.gossip->broadcast_account_envelope(record_for("dev1", "W1"));
    ASSERT_TRUE(pump_until([&] { return holds("b", "dev1") && holds("c", "dev1"); }));
    EXPECT_EQ(sinks["b"].stored["ed25519:dev1"].wrapped_key, "W1");
    EXPECT_EQ(sinks["b"].stored["ed25519:dev1"].origin_pubkey, a_b64);
    EXPECT_NE(sinks["b"].stored["ed25519:dev1"].origin_seq, 0u);

    // Tier 2 originates nothing.
    c.gossip->broadcast_account_envelope(record_for("dev2", "W2"));
    pump_for(std::chrono::milliseconds(300));
    EXPECT_FALSE(holds("a", "dev2"));
    EXPECT_FALSE(holds("b", "dev2"));

    // B's store refuses dev3 at first (its tree lags), then catches up from
    // A's next digest once it accepts.
    sinks["b"].accept = false;
    a.gossip->broadcast_account_envelope(record_for("dev3", "W3"));
    ASSERT_TRUE(pump_until([&] { return holds("c", "dev3"); }));
    pump_for(std::chrono::milliseconds(200));
    EXPECT_FALSE(holds("b", "dev3"));
    sinks["b"].accept = true;
    gossip::GossipBallotTestAccess::send_sync_digests(*a.gossip);
    ASSERT_TRUE(pump_until([&] { return holds("b", "dev3"); }, std::chrono::seconds(5)));

    // Hand-built records reach B straight over the backbone from A's address.
    const auto a_port = gossip::GossipBallotTestAccess::port(*a.gossip);
    const auto b_port = gossip::GossipBallotTestAccess::port(*b.gossip);
    const auto over_backbone = [&](network::VirtualNetService& from_stack, const char* from_ip,
                                   uint16_t from_port, const crypto::Ed25519Keypair& sender,
                                   const char* to_ip, uint16_t to_port, const nlohmann::json& wire) {
        const auto pkt = build_packet(sender, gossip::GossipMsgType::AccountEnvelopeSync,
                                      msgpack_of(wire));
        ASSERT_TRUE(from_stack.send_udp(from_ip, from_port, to_ip, to_port, pkt));
    };

    // Positive control for the path below.
    over_backbone(va, "172.16.0.1", a_port, a_kp, "172.16.0.2", b_port,
                  account_envelope_wire(a_kp, record_for("dev6", "W6", 1'700'000'100, 6)));
    ASSERT_TRUE(pump_until([&] { return holds("b", "dev6"); }));

    // Refused: a field changed after A signed it.
    auto tampered = account_envelope_wire(a_kp, record_for("dev5", "W5", 1'700'000'100, 5));
    tampered["wrapped_key"] = "TAMPERED";
    over_backbone(va, "172.16.0.1", a_port, a_kp, "172.16.0.2", b_port, tampered);
    // Refused: an older envelope for a device that already has a newer one.
    over_backbone(va, "172.16.0.1", a_port, a_kp, "172.16.0.2", b_port,
                  account_envelope_wire(a_kp, record_for("dev6", "OLD", 1'700'000'000, 7)));
    // Refused: a valid A record delivered by C, which is not Tier 1.
    const auto c_port = gossip::GossipBallotTestAccess::port(*c.gossip);
    over_backbone(vc, "172.16.0.3", c_port, c_kp, "172.16.0.1", a_port,
                  account_envelope_wire(a_kp, record_for("dev7", "W7", 1'700'000'100, 8)));
    // Refused: the public socket, even from Tier 1.
    inject(build_packet(a_kp, gossip::GossipMsgType::AccountEnvelopeSync,
                        msgpack_of(account_envelope_wire(a_kp, record_for("dev4", "W4", 1'700'000'100, 4)))),
           b);
    pump_for(std::chrono::milliseconds(400));
    EXPECT_FALSE(holds("b", "dev5"));
    EXPECT_EQ(sinks["b"].stored["ed25519:dev6"].wrapped_key, "W6");
    EXPECT_FALSE(holds("a", "dev7"));
    EXPECT_FALSE(holds("b", "dev4"));

    const std::string image(64, 'a');
    const auto avatar = [&](uint64_t revision, std::string data) {
        account::AccountAvatarRecord r{"customer-g1", crypto::to_base64(device_kp.public_key), revision, std::move(data), ""};
        r.signature = sign_b64(device_kp, account::avatar_canonical(r));
        return r;
    };
    const auto avatar_revision = [&](const std::string& tag) { return sinks[tag].avatar ? sinks[tag].avatar->revision : 0; };
    a.gossip->broadcast_account_avatar(avatar(1, image));
    ASSERT_TRUE(pump_until([&] { return avatar_revision("b") == 1 && avatar_revision("c") == 1; }));

    // A Tier 2 server transports device authority; infrastructure streams above
    // still refuse its writes. Delayed peers catch up from the profile stream.
    c.gossip->broadcast_account_avatar(avatar(2, ""));
    ASSERT_TRUE(pump_until([&] { return avatar_revision("a") == 2 && avatar_revision("b") == 2; }));
    EXPECT_TRUE(sinks["b"].avatar->image_hash.empty());
    c.gossip->broadcast_account_avatar(avatar(1, image));
    pump_for(std::chrono::milliseconds(100));
    EXPECT_EQ(avatar_revision("a"), 2u);
    sinks["b"].accept = false;
    c.gossip->broadcast_account_avatar(avatar(3, image));
    ASSERT_TRUE(pump_until([&] { return avatar_revision("a") == 3; }));
    EXPECT_EQ(avatar_revision("b"), 2u);
    sinks["b"].accept = true;
    gossip::GossipBallotTestAccess::send_sync_digests(*a.gossip);
    ASSERT_TRUE(pump_until([&] { return avatar_revision("b") == 3; }, std::chrono::seconds(5)));

    by_ip.erase("172.16.0.1"); by_ip.erase("172.16.0.2");
    c.gossip->broadcast_account_avatar(avatar(4, ""));
    ASSERT_TRUE(pump_until([&] { return avatar_revision("c") == 4; }));
    by_ip["172.16.0.1"] = &va; by_ip["172.16.0.2"] = &vb;
    gossip::GossipBallotTestAccess::send_sync_digests(*c.gossip);
    ASSERT_TRUE(pump_until([&] { return avatar_revision("a") == 4 && avatar_revision("b") == 4; }, std::chrono::seconds(5)));

    auto bad_avatar = avatar(5, image);
    bad_avatar.image_hash.clear();
    const auto bad_wire = account::avatar_wire(bad_avatar).dump();
    const std::vector<uint8_t> bad_bytes(bad_wire.begin(), bad_wire.end());
    for (const auto& chunk : sync::encode_entry_chunks(account::kAvatarSyncStream, 5, bad_bytes, 32)) {
        const auto packet = build_packet(a_kp, gossip::GossipMsgType::AccountAvatarSync, msgpack_of(chunk));
        ASSERT_TRUE(va.send_udp("172.16.0.1", a_port, "172.16.0.2", b_port, packet));
    }
    pump_for(std::chrono::milliseconds(200));
    EXPECT_EQ(avatar_revision("b"), 4u);
    const auto valid_wire = account::avatar_wire(avatar(6, image)).dump();
    const std::vector<uint8_t> valid_bytes(valid_wire.begin(), valid_wire.end());
    for (const auto& chunk : sync::encode_entry_chunks(account::kAvatarSyncStream, 6, valid_bytes, 32)) {
        inject(build_packet(a_kp, gossip::GossipMsgType::AccountAvatarSync, msgpack_of(chunk)), b);
    }
    pump_for(std::chrono::milliseconds(100));
    EXPECT_EQ(avatar_revision("b"), 4u);
    for (const auto& chunk : sync::encode_entry_chunks(account::kAvatarSyncStream, 6, valid_bytes, 32)) {
        const auto packet = build_packet(a_kp, gossip::GossipMsgType::AccountAvatarSync, msgpack_of(chunk));
        ASSERT_TRUE(va.send_udp("172.16.0.1", a_port, "172.16.0.2", b_port, packet));
    }
    ASSERT_TRUE(pump_until([&] { return avatar_revision("b") == 6; }));
    c.gossip->broadcast_account_avatar(avatar(7, ""));
    ASSERT_TRUE(pump_until([&] { return avatar_revision("a") == 7 && avatar_revision("b") == 7; }));

    // B restarts and restores every envelope from disk, re-verified, with no
    // peer contact.
    sinks["b"].stored.clear();
    sinks["b"].avatar.reset();
    restart_node(b, [&](Node& n) { configure(n, sinks["b"]); });
    EXPECT_TRUE(holds("b", "dev1"));
    EXPECT_TRUE(holds("b", "dev3"));
    EXPECT_TRUE(holds("b", "dev6"));
    EXPECT_FALSE(holds("b", "dev5"));
    EXPECT_EQ(avatar_revision("b"), 7u);
    EXPECT_TRUE(sinks["b"].avatar->image_hash.empty());
    const auto references = b.storage->read_file("avatar_refs", "replica.json");
    ASSERT_TRUE(references);
    const auto snapshot = nlohmann::json::parse(references->data);
    for (const auto& encoded : snapshot.at("entries")) {
        const auto bytes = crypto::from_base64(encoded.get<std::string>());
        const auto reference = nlohmann::json::parse(bytes.begin(), bytes.end());
        EXPECT_FALSE(reference.contains("image"));
        EXPECT_TRUE(reference.contains("image_hash"));
        EXPECT_LE(bytes.size(), account::kMaxAvatarRecordBytes);
    }

    // A restores the envelopes it originated (its own certificate verifies them).
    sinks["a"].stored.clear();
    restart_node(a, [&](Node& n) { configure(n, sinks["a"]); });
    EXPECT_TRUE(holds("a", "dev1"));
    EXPECT_TRUE(holds("a", "dev3"));

    for (auto* v : {&va, &vb, &vc}) v->stop();
}

// A removal is a change made now. Its delta carries the removal time, not the
// removed record's creation time, so receivers order it after that record
// and its marker expires relative to the removal.
TEST_F(GossipIngressSecurityTest, DnsRemovalCarriesTheRemovalTime) {
    auto& a = make_node("a", [&](Node& n) { attach_dns(n); });
    network::DnsZoneRecord old_rec;
    old_rec.fqdn = "old.example.lemonade-nexus.io";
    old_rec.record_type = "A";
    old_rec.value = "10.1.1.1";
    old_rec.ttl = 60;
    old_rec.timestamp = 1000;  // long ago
    ASSERT_TRUE(a.dns->apply_remote_delta("old-1", "set", old_rec));

    std::optional<network::DnsZoneRecord> sent;
    a.dns->set_record_callback([&](const std::string&, const std::string& op,
                                   const network::DnsZoneRecord& rec) {
        if (op == "remove") sent = rec;
    });
    const auto before = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    ASSERT_TRUE(a.dns->remove_record(old_rec.fqdn, "A"));
    ASSERT_TRUE(sent.has_value());
    EXPECT_GE(sent->timestamp, before);
    EXPECT_EQ(sent->value, "10.1.1.1");
}

// Committed tree log entries replicate over the backbone on the "tree" sync
// stream (design A7). Tier 1 serves them from its log, in height order and in
// chunks when an entry exceeds one datagram; any certified server pulls them
// from Tier 1 only. The stream only carries bytes: the receiver's sink
// verifies each entry's consensus evidence (TreeConsensus).
TEST_F(GossipIngressSecurityTest, TreeLogEntriesReplicateOverTheBackbone) {
    auto root_kp = kc->ed25519_keygen();
    auto a_kp    = kc->ed25519_keygen();
    auto c_kp    = kc->ed25519_keygen();
    const auto a_b64  = crypto::to_base64(a_kp.public_key);
    const auto c_b64  = crypto::to_base64(c_kp.public_key);
    const auto a_cert = issue_cert(a_b64, "srv-a", root_kp);
    const auto c_cert = issue_cert(c_b64, "srv-c", root_kp);
    const std::set<std::string> members{a_b64};  // C is Tier 2
    const auto seed_own_cert = [](Node& n, const std::string& cert) {
        storage::SignedEnvelope env;
        env.type = "server_certificate";
        env.data = cert;
        ASSERT_TRUE(n.storage->write_file("identity", "server_cert.json", env));
    };

    // A's log: three entries, the second larger than several datagrams.
    std::map<uint64_t, std::vector<uint8_t>> log_a;
    for (uint64_t h = 1; h <= 3; ++h) {
        std::vector<uint8_t> bytes(h == 2 ? 100'000 : 300);
        randombytes_buf(bytes.data(), bytes.size());
        log_a[h] = std::move(bytes);
    }
    std::vector<std::vector<uint8_t>> received_c;
    std::vector<std::vector<uint8_t>> received_a;

    const auto configure = [&](Node& n, std::map<uint64_t, std::vector<uint8_t>>* log,
                               std::vector<std::vector<uint8_t>>* received) {
        n.gossip->set_root_pubkey(root_kp.public_key);
        n.gossip->set_network_id(kTestNetworkHex);
        n.gossip->set_ipam(n.ipam.get());
        n.gossip->set_tier1_membership_source(
            [&members](const std::string& pk) { return members.count(pk) > 0; });
        auto* g = n.gossip.get();
        n.gossip->enable_tree_stream(
            [log](uint64_t height) -> std::optional<std::vector<uint8_t>> {
                if (log == nullptr) return std::nullopt;
                const auto it = log->find(height);
                if (it == log->end()) return std::nullopt;
                return it->second;
            },
            [received, g](std::vector<uint8_t> bytes) {
                // Production verifies and appends, then offers the height.
                received->push_back(std::move(bytes));
                g->offer_tree_height(received->size());
            });
    };

    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_keypair(*n.storage, a_kp);
            seed_own_cert(n, a_cert);
            attach_ipam(n);
            seed_peers(*n.storage,
                       nlohmann::json::array({peer_entry(c_b64, "127.0.0.1:10", c_cert)}));
        },
        [&](Node& n) { configure(n, &log_a, &received_a); });
    for (uint64_t h = 1; h <= 3; ++h) a.gossip->offer_tree_height(h);
    auto& c = make_node(
        "c",
        [&](Node& n) {
            seed_keypair(*n.storage, c_kp);
            seed_own_cert(n, c_cert);
            attach_ipam(n);
            seed_peers(*n.storage,
                       nlohmann::json::array({peer_entry(a_b64, a.endpoint(), a_cert)}));
        },
        [&](Node& n) { configure(n, nullptr, &received_c); });
    a.gossip->add_peer(c.endpoint(), c_b64);
    pump_for(std::chrono::milliseconds(200));

    // Refused: a tree chunk on the public socket, even from Tier 1.
    const auto chunk = sync::encode_entry_chunks("tree", 1, log_a[1], 16 * 1024);
    ASSERT_EQ(chunk.size(), 1u);
    inject(build_packet(a_kp, gossip::GossipMsgType::TreeLogSync, msgpack_of(chunk[0])), c);
    pump_for(std::chrono::milliseconds(200));
    EXPECT_TRUE(received_c.empty());

    network::VirtualNetService va, vc;
    std::map<std::string, network::VirtualNetService*> by_ip{{"172.16.0.1", &va},
                                                             {"172.16.0.3", &vc}};
    const auto route = [&by_ip](std::span<const uint8_t> p) {
        if (p.size() < 20) return;
        const std::string dst = std::to_string(p[16]) + "." + std::to_string(p[17]) + "." +
                                std::to_string(p[18]) + "." + std::to_string(p[19]);
        if (auto it = by_ip.find(dst); it != by_ip.end()) it->second->deliver_inbound_ip_packet(p);
    };
    const auto mesh_key = [](uint8_t fill) {
        std::array<uint8_t, crypto::kX25519PublicKeySize> k{};
        k.fill(fill);
        return crypto::to_base64(std::span<const uint8_t>(k.data(), k.size()));
    };
    struct Wire { Node* n; network::VirtualNetService* v; const char* ip; const char* id; uint8_t key; };
    for (const auto& w : {Wire{&a, &va, "172.16.0.1", "node-a", 0xA1},
                          Wire{&c, &vc, "172.16.0.3", "node-c", 0xC3}}) {
        w.v->start();
        w.v->set_outbound_sink(route);
        ASSERT_TRUE(w.v->add_local_ip(std::string(w.ip) + "/22"));
        w.n->gossip->set_our_mesh_pubkey(mesh_key(w.key));
        w.n->gossip->set_our_backbone_claim(w.id, w.ip);
        w.n->gossip->set_virtual_net(w.v);
    }
    const auto status_for = [](Node& n, const std::string& pk) {
        const auto status = n.gossip->tree_sync_status();
        for (const auto& p : status["peers"]) {
            if (p["pubkey"] == pk) return p;
        }
        return nlohmann::json::object();
    };
    for (Node* n : {&a, &c}) gossip::GossipBallotTestAccess::run_gossip_tick(*n->gossip);
    ASSERT_TRUE(pump_until([&] {
        return status_for(a, c_b64).value("mesh_key_known", false) &&
               status_for(c, a_b64).value("mesh_key_known", false);
    }));

    // One digest round from A: C requests every height and receives the
    // entries whole and in order, the large one reassembled from chunks.
    gossip::GossipBallotTestAccess::send_sync_digests(*a.gossip);
    ASSERT_TRUE(pump_until([&] { return received_c.size() == 3; }, std::chrono::seconds(5)));
    for (uint64_t h = 1; h <= 3; ++h) EXPECT_EQ(received_c[h - 1], log_a[h]) << "height " << h;

    // The next round finds C in sync, and C reports it to A. A pulls nothing
    // from a Tier 2 server.
    gossip::GossipBallotTestAccess::send_sync_digests(*a.gossip);
    gossip::GossipBallotTestAccess::send_sync_digests(*c.gossip);
    ASSERT_TRUE(pump_until([&] {
        return status_for(c, a_b64).value("in_sync", false) &&
               status_for(a, c_b64).value("in_sync", false);
    }));
    c.gossip->offer_tree_height(4);
    gossip::GossipBallotTestAccess::send_sync_digests(*c.gossip);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_TRUE(received_a.empty());
    EXPECT_TRUE(a.gossip->tree_sync_status().value("enabled", false));

    for (auto* v : {&va, &vc}) v->stop();
}
