// NS-claim IP-change behavior on a persisted pinned claim, driven through the
// real production path (GossipService::try_claim_ns_slot at startup) into a
// real GossipService with the real downstream DnsService attached. Every
// stimulus is a correctly signed datagram or a real claim through the public
// surface — no fake state.

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
#include <sodium.h>
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

using namespace nexus;
namespace fs = std::filesystem;
using asio::ip::udp;

namespace {

// The friend seam, Node and wire fixture live in support/gossip_fixture.hpp.
using nexus_test::kTestNetworkHex;
using nexus_test::msgpack_of;
using Node = nexus_test::GossipTestNode;

class NsClaimIpChangeTest : public nexus_test::GossipWireFixture {
protected:
    NsClaimIpChangeTest() : GossipWireFixture("nexus_test_ns_claim_ip_") {}

    void stop_node_services(Node& n) override {
        if (n.dns) n.dns->stop();
        if (n.tree) n.tree->stop();
    }

    // The DNS service binds its socket in the constructor (ephemeral port) and is
    // never started: the zone map and resolver are pure.
    void attach_dns(Node& n) {
        n.tree = std::make_unique<tree::PermissionTreeService>(*n.storage, *n.crypto);
        n.tree->start();
        n.dns = std::make_unique<network::DnsService>(io, 0, *n.tree, "lemonade-nexus.io");
    }

    // The six-field pinned preimage exactly as ns_claim_sign_payload(claim, true)
    // builds it. Signing this is what a pinned NS claim commits to.
    std::string pinned_preimage(uint8_t slot, const std::string& pubkey_b64,
                                const std::string& ip, uint64_t ts) {
        nlohmann::json p;
        p["pinned"]        = true;
        p["slot"]          = slot;
        p["server_pubkey"] = pubkey_b64;
        p["server_ip"]     = ip;
        p["region"]        = "eu-west";
        p["timestamp"]     = ts;
        return p.dump();
    }

    // A signed, fresh NS-claim wire (used to open a node's sync gate). `pinned`
    // selects the six-field preimage; otherwise the legacy five-field preimage.
    std::vector<uint8_t> make_claim_wire(const crypto::Ed25519Keypair& signer,
                                         const std::string& pubkey_b64, uint8_t slot,
                                         const std::string& ip, bool pinned, uint64_t ts) {
        nlohmann::json pre;
        if (pinned) pre["pinned"] = true;
        pre["slot"]          = slot;
        pre["server_pubkey"] = pubkey_b64;
        pre["server_ip"]     = ip;
        pre["region"]        = "eu-west";
        pre["timestamp"]     = ts;
        nlohmann::json wire = pre;
        wire["signature"] = sign_b64(signer, pre.dump());
        return msgpack_of(wire);
    }

    // Read back the persisted slot[0] entry from a node's ns_slots.json.
    nlohmann::json read_disk_slot0(Node& n) {
        auto env = n.storage->read_file("identity", "ns_slots.json");
        EXPECT_TRUE(env.has_value());
        if (!env.has_value()) return nullptr;
        const auto j = nlohmann::json::parse(env->data);
        return j["slots"][0];
    }
};

}  // namespace

TEST_F(NsClaimIpChangeTest, C1_ForwardIpChangeAppliesOnce) {
    const std::string OLD = "10.0.0.51";
    const std::string NEW = "10.0.0.52";
    const uint64_t old_ts = 1760000000;
    const std::string ns1 = "ns1.lemonade-nexus.io";

    auto root_kp = kc->ed25519_keygen();
    auto a_kp    = kc->ed25519_keygen();
    const auto a_b64  = crypto::to_base64(a_kp.public_key);
    const auto a_cert = issue_cert(a_b64, "node-a", root_kp);
    const auto old_sig = sign_b64(a_kp, pinned_preimage(1, a_b64, OLD, old_ts));

    // Peer: real DNS zone, certified view of the holder (dead endpoint is fine —
    // the peer only needs the holder's cert to pass the claimant gate).
    auto& p = make_node(
        "p",
        [&](Node& n) {
            attach_dns(n);
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(a_b64, "127.0.0.1:9", a_cert),
            }));
        },
        [&](Node& n) {
            n.gossip->set_root_pubkey(root_kp.public_key);
            n.gossip->set_network_id(kTestNetworkHex);
            n.gossip->set_dns(n.dns.get());
        });

    // The peer learned the OLD (pre-restart) pinned claim.
    nlohmann::json old_wire = nlohmann::json::parse(pinned_preimage(1, a_b64, OLD, old_ts));
    old_wire["signature"] = old_sig;
    inject(build_packet(a_kp, gossip::GossipMsgType::NsSlotClaim, msgpack_of(old_wire)), p);
    ASSERT_TRUE(pump_until([&] { return p.ns_holder(1) == a_b64; }));
    ASSERT_EQ(p.dns->nameserver_ip(ns1), OLD);

    // The holder comes back behind a NEW public IP, with the persisted pinned claim.
    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_keypair(*n.storage, a_kp);
            const auto p_pk = crypto::to_base64(p.gossip->keypair().public_key);
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(p_pk, p.endpoint(), issue_cert(p_pk, "peer-p", root_kp)),
            }));
            seed_ns_slot_state(*n.storage,
                               {slot_entry(1, a_b64, OLD, old_ts, old_sig, /*pinned=*/true)},
                               /*our_slot=*/1);
        },
        [&](Node& n) {
            n.gossip->set_root_pubkey(root_kp.public_key);
            n.gossip->set_network_id(kTestNetworkHex);
            n.gossip->set_our_region("eu-west");
            n.gossip->set_preferred_ns_slot(1);
        });
    ASSERT_EQ(a.gossip->our_ns_slot(), 1);  // re-learned from disk

    // --- Production renewal: re-claim with the NEW public IP (startup path). ---
    a.gossip->try_claim_ns_slot(NEW);

    // Holder: same slot, new IP, fresh timestamp, still pinned — exactly one broadcast.
    const auto& ha = gossip::GossipBallotTestAccess::ns_slot(*a.gossip, 1);
    EXPECT_EQ(a.gossip->our_ns_slot(), 1);
    EXPECT_EQ(ha.server_ip, NEW);
    EXPECT_EQ(ha.server_pubkey, a_b64);
    EXPECT_TRUE(ha.pinned);
    EXPECT_GT(ha.timestamp, old_ts);
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_broadcast_count(*a.gossip), 1u);
    const uint64_t renewed_ts = ha.timestamp;

    // Holder persisted the move (in-memory and on disk agree).
    const auto a_disk = read_disk_slot0(a);
    ASSERT_TRUE(a_disk.is_object());
    EXPECT_EQ(a_disk["server_ip"], NEW);
    EXPECT_EQ(a_disk["server_pubkey"], a_b64);
    EXPECT_EQ(a_disk["timestamp"], renewed_ts);
    EXPECT_TRUE(a_disk.value("pinned", false));

    // --- Peer applies it as a holder renewal: A record + state + disk move. ---
    ASSERT_TRUE(pump_until([&] {
        return p.ns_holder(1) == a_b64 &&
               gossip::GossipBallotTestAccess::ns_slot(*p.gossip, 1).server_ip == NEW;
    }));
    const auto& hp = gossip::GossipBallotTestAccess::ns_slot(*p.gossip, 1);
    EXPECT_EQ(hp.server_ip, NEW);
    EXPECT_EQ(hp.server_pubkey, a_b64);
    EXPECT_TRUE(hp.pinned);
    EXPECT_EQ(hp.timestamp, renewed_ts);  // propagated verbatim from the holder
    ASSERT_EQ(p.dns->nameserver_ip(ns1), NEW);

    const auto p_disk = read_disk_slot0(p);
    ASSERT_TRUE(p_disk.is_object());
    EXPECT_EQ(p_disk["server_ip"], NEW);
    EXPECT_EQ(p_disk["server_pubkey"], a_b64);
    EXPECT_EQ(p_disk["timestamp"], renewed_ts);

    // --- "Applies once": a second, byte-identical delivery is a dedup no-op. ---
    const auto p_rc_before = gossip::GossipBallotTestAccess::ns_receive_count(*p.gossip);
    const auto p_bc_before = gossip::GossipBallotTestAccess::ns_broadcast_count(*p.gossip);
    const auto a_rc_before = gossip::GossipBallotTestAccess::ns_receive_count(*a.gossip);
    inject(build_packet(a_kp, gossip::GossipMsgType::NsSlotClaim, a.ns_wire_of(1)), p);
    pump_for(std::chrono::milliseconds(300));

    const auto& hp2 = gossip::GossipBallotTestAccess::ns_slot(*p.gossip, 1);
    EXPECT_EQ(hp2.server_ip, NEW);
    EXPECT_EQ(hp2.timestamp, renewed_ts);  // unchanged
    EXPECT_EQ(p.dns->nameserver_ip(ns1), NEW);
    // The duplicate was received (ingress accounting) but changed nothing and was
    // NOT re-forwarded (no new broadcast from the peer, none back to the holder).
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_receive_count(*p.gossip), p_rc_before + 1);
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_broadcast_count(*p.gossip), p_bc_before);
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_receive_count(*a.gossip), a_rc_before);
}

// Mirror of the production renewal-timestamp selection in
// GossipService::try_claim_ns_slot — keep in lock-step. Fails closed when the
// held timestamp is UINT64_MAX (cannot be advanced).
static uint64_t select_renewal_ts(uint64_t now, uint64_t held, bool& failed) {
    failed = false;
    if (held == UINT64_MAX) { failed = true; return 0; }
    return (now > held + 1) ? now : (held + 1);
}

// C2: equal-timestamp conflict, A(T) -> B(T) -> replay A(T). The receiver keeps
// the first accepted entry, rejects the equal-timestamp conflict, dedups an
// identical re-delivery, and never re-forwards either; repeated after a reload,
// plus a bounded multi-peer relay to show the mesh settles.
TEST_F(NsClaimIpChangeTest, C2_EqualTimestampConflictRejected) {
    const std::string IP_A = "10.0.0.51";
    const std::string IP_B = "10.0.0.52";
    const uint64_t T = 1760000000;  // identical wall-clock value for both claims
    const std::string ns1 = "ns1.lemonade-nexus.io";

    auto root_kp = kc->ed25519_keygen();
    auto a_kp    = kc->ed25519_keygen();
    const auto a_b64  = crypto::to_base64(a_kp.public_key);
    const auto a_cert = issue_cert(a_b64, "node-a", root_kp);
    // Same holder, same timestamp, different ip: two distinct valid signatures.
    const auto wire_a = make_claim_wire(a_kp, a_b64, 1, IP_A, /*pinned=*/true, T);
    const auto wire_b = make_claim_wire(a_kp, a_b64, 1, IP_B, /*pinned=*/true, T);

    const auto config_p = [&](Node& n) {
        n.gossip->set_root_pubkey(root_kp.public_key);
        n.gossip->set_network_id(kTestNetworkHex);
        n.gossip->set_dns(n.dns.get());
    };
    auto& p = make_node(
        "p",
        [&](Node& n) {
            attach_dns(n);
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(a_b64, "127.0.0.1:9", a_cert),
            }));
        },
        config_p);

    const auto slot = [&] { return gossip::GossipBallotTestAccess::ns_slot(*p.gossip, 1); };
    const auto rc   = [&] { return gossip::GossipBallotTestAccess::ns_receive_count(*p.gossip); };

    // 1) A(T) into an empty slot: accepted.
    inject(build_packet(a_kp, gossip::GossipMsgType::NsSlotClaim, wire_a), p);
    ASSERT_TRUE(pump_until([&] { return slot().server_ip == IP_A; }));
    EXPECT_EQ(slot().timestamp, T);
    EXPECT_EQ(p.dns->nameserver_ip(ns1), IP_A);
    EXPECT_EQ(read_disk_slot0(p)["timestamp"], T);
    const auto rc_a = rc();

    // 2) Conflicting B(T): same holder, EQUAL timestamp, different ip -> REJECTED.
    inject(build_packet(a_kp, gossip::GossipMsgType::NsSlotClaim, wire_b), p);
    ASSERT_TRUE(pump_until([&] { return rc() >= rc_a + 1; }));
    EXPECT_EQ(slot().server_ip, IP_A);          // kept the first accepted, not rolled to B
    EXPECT_EQ(slot().timestamp, T);
    EXPECT_EQ(p.dns->nameserver_ip(ns1), IP_A); // A record unchanged
    EXPECT_EQ(read_disk_slot0(p)["timestamp"], T);
    const auto rc_b = rc();

    // 3) Replay A(T): byte-identical to the accepted entry -> dedup no-op.
    inject(build_packet(a_kp, gossip::GossipMsgType::NsSlotClaim, wire_a), p);
    ASSERT_TRUE(pump_until([&] { return rc() >= rc_b + 1; }));
    EXPECT_EQ(slot().server_ip, IP_A);
    EXPECT_EQ(slot().timestamp, T);

    // The rejected (B) and deduped (A) deliveries changed nothing and were not
    // re-broadcast by the peer (its own origin-broadcast count stays put).
    const auto bc = gossip::GossipBallotTestAccess::ns_broadcast_count(*p.gossip);
    pump_for(std::chrono::milliseconds(200));
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_broadcast_count(*p.gossip), bc);

    // --- Repeat after reloading the persisted state (the protection must survive a
    // restart). The in-memory DNS zone is not persisted, so it is empty here until a
    // non-deduped apply; the slot state and the persisted entry are the targets.
    restart_node(p, config_p);
    ASSERT_EQ(slot().server_ip, IP_A);   // reloaded A(T) from disk
    ASSERT_EQ(slot().timestamp, T);
    EXPECT_EQ(read_disk_slot0(p)["timestamp"], T);
    const auto rc_r = rc();
    inject(build_packet(a_kp, gossip::GossipMsgType::NsSlotClaim, wire_b), p);
    ASSERT_TRUE(pump_until([&] { return rc() >= rc_r + 1; }));
    EXPECT_EQ(slot().server_ip, IP_A);    // still rejected after reload
    EXPECT_EQ(slot().timestamp, T);
    EXPECT_EQ(read_disk_slot0(p)["timestamp"], T);

    // --- Bounded multi-peer relay: a rejected equal-timestamp conflict must not
    // propagate — O rejects B(T) without forwarding, R never sees IP_B, and the
    // mesh settles with no storm.
    auto o_kp = kc->ed25519_keygen();
    auto r_kp = kc->ed25519_keygen();
    const auto o_pk   = crypto::to_base64(o_kp.public_key);
    const auto r_pk   = crypto::to_base64(r_kp.public_key);
    const auto o_cert = issue_cert(o_pk, "origin", root_kp);
    const auto r_cert = issue_cert(r_pk, "relayer", root_kp);

    // R (relayer/leaf) is created first. It certifies the claimant (holder) and O
    // (the forwarder of the copy it will receive), each at a DISTINCT endpoint
    // (same-endpoint entries would be deduped at load). R does not deliver onward
    // to a live node, so the flow cannot loop back.
    auto& r = make_node(
        "r",
        [&](Node& n) {
            attach_dns(n);
            seed_keypair(*n.storage, r_kp);
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(a_b64, "127.0.0.1:9",  a_cert),  // claimant (holder)
                peer_entry(o_pk,  "127.0.0.1:10", o_cert),  // forwarder (O)
            }));
        },
        config_p);
    // O (origin) is created second, so it knows R's REAL endpoint and can forward
    // to it. It certifies the claimant (holder) and R (the forward target).
    auto& o = make_node(
        "o",
        [&](Node& n) {
            attach_dns(n);
            seed_keypair(*n.storage, o_kp);
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(a_b64, "127.0.0.1:9", a_cert),   // claimant (holder)
                peer_entry(r_pk,  r.endpoint(),    r_cert),  // R at its real endpoint
            }));
        },
        config_p);

    const auto wire_s3_a = make_claim_wire(a_kp, a_b64, 3, IP_A, true, T);
    const auto wire_s3_b = make_claim_wire(a_kp, a_b64, 3, IP_B, true, T);

    // A(T): O accepts (claimant certified; O is not the claimant) and forwards to R;
    // R accepts (forwarder + claimant certified).
    inject(build_packet(a_kp, gossip::GossipMsgType::NsSlotClaim, wire_s3_a), o);
    ASSERT_TRUE(pump_until([&] {
        return o.ns_holder(3) == a_b64 && r.ns_holder(3) == a_b64;
    }));
    ASSERT_EQ(gossip::GossipBallotTestAccess::ns_slot(*r.gossip, 3).server_ip, IP_A);

    // B(T): O rejects it (equal ts) and does NOT forward it; R must never see IP_B.
    inject(build_packet(a_kp, gossip::GossipMsgType::NsSlotClaim, wire_s3_b), o);
    pump_for(std::chrono::milliseconds(400));
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_slot(*o.gossip, 3).server_ip, IP_A);
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_slot(*r.gossip, 3).server_ip, IP_A);  // R never saw B

    // A(T) again: O dedups; nothing re-propagates. Confirm the mesh is quiet.
    inject(build_packet(a_kp, gossip::GossipMsgType::NsSlotClaim, wire_s3_a), o);
    pump_for(std::chrono::milliseconds(400));
    const auto oc  = gossip::GossipBallotTestAccess::ns_receive_count(*o.gossip);
    const auto rc2 = gossip::GossipBallotTestAccess::ns_receive_count(*r.gossip);
    pump_for(std::chrono::milliseconds(800));
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_receive_count(*o.gossip), oc);
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_receive_count(*r.gossip), rc2);
}


TEST_F(NsClaimIpChangeTest, C3_UnchangedIpRestartIsANoOpAndRefreshDedups) {
    const std::string P1 = "10.0.0.51";
    const uint64_t ts1   = 1760000000;
    const std::string ns1 = "ns1.lemonade-nexus.io";

    auto root_kp = kc->ed25519_keygen();
    auto a_kp    = kc->ed25519_keygen();
    auto p_kp    = kc->ed25519_keygen();
    const auto a_b64 = crypto::to_base64(a_kp.public_key);
    const auto p_b64 = crypto::to_base64(p_kp.public_key);
    const auto a_cert = issue_cert(a_b64, "node-a", root_kp);
    const auto sig1   = sign_b64(a_kp, pinned_preimage(1, a_b64, P1, ts1));

    auto& p = make_node(
        "p",
        [&](Node& n) {
            attach_dns(n);
            // P's real identity IS p_kp, so the ns5 claim it sends below names a key
            // that A's peer table actually holds (otherwise the claimant lookup fails).
            seed_keypair(*n.storage, p_kp);
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(a_b64, "127.0.0.1:9", a_cert),
            }));
        },
        [&](Node& n) {
            n.gossip->set_root_pubkey(root_kp.public_key);
            n.gossip->set_network_id(kTestNetworkHex);
            n.gossip->set_dns(n.dns.get());
        });

    // Peer learns the ORIGINAL claim (P1, ts1).
    nlohmann::json orig_wire = nlohmann::json::parse(pinned_preimage(1, a_b64, P1, ts1));
    orig_wire["signature"] = sig1;
    inject(build_packet(a_kp, gossip::GossipMsgType::NsSlotClaim, msgpack_of(orig_wire)), p);
    ASSERT_TRUE(pump_until([&] { return p.ns_holder(1) == a_b64; }));
    ASSERT_EQ(p.dns->nameserver_ip(ns1), P1);

    // Configure shared by the initial build and the restart (same identity).
    const auto config_a = [&](Node& n) {
        n.gossip->set_root_pubkey(root_kp.public_key);
        n.gossip->set_network_id(kTestNetworkHex);
        n.gossip->set_our_region("eu-west");
        n.gossip->set_preferred_ns_slot(1);
    };

    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_keypair(*n.storage, a_kp);
            const auto p_pk = crypto::to_base64(p.gossip->keypair().public_key);
            seed_peers(*n.storage, nlohmann::json::array({
                peer_entry(p_pk, p.endpoint(), issue_cert(p_pk, "peer-p", root_kp)),
            }));
            seed_ns_slot_state(*n.storage,
                               {slot_entry(1, a_b64, P1, ts1, sig1, /*pinned=*/true)},
                               /*our_slot=*/1);
        },
        config_a);
    ASSERT_EQ(a.gossip->our_ns_slot(), 1);

    // --- Same-IP restart: re-claim with the SAME public IP. ---
    restart_node(a, config_a);
    ASSERT_EQ(a.gossip->our_ns_slot(), 1);  // re-learned from disk

    // main.cpp calls try_claim_ns_slot(server_public_ip) at startup. With an
    // unchanged IP this takes the "already hold" skip: no renewal, no new timestamp,
    // no broadcast. The persisted timestamp is unchanged.
    a.gossip->try_claim_ns_slot(P1);
    const auto& ha = gossip::GossipBallotTestAccess::ns_slot(*a.gossip, 1);
    EXPECT_EQ(ha.server_ip, P1);
    EXPECT_EQ(ha.timestamp, ts1);  // unchanged
    EXPECT_TRUE(ha.pinned);
    // Fresh service instance (restart) + no renewal => zero broadcasts.
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_broadcast_count(*a.gossip), 0u);
    const auto a_disk = read_disk_slot0(a);
    ASSERT_TRUE(a_disk.is_object());
    EXPECT_EQ(a_disk["timestamp"], ts1);

    // --- Open A's sync gate, then drive the one-shot refresh. ---
    // The load does NOT set ns_state_synced_ (fail closed); a live accepted claim
    // does. P claims an unrelated slot (ns5) to open the gate; P is A's only
    // certified peer.
    inject(build_packet(p_kp, gossip::GossipMsgType::NsSlotClaim,
                        make_claim_wire(p_kp, p_b64, 5, "10.0.0.99", /*pinned=*/false, 1000)),
           a);
    ASSERT_TRUE(pump_until([&] {
        return a.ns_holder(5) == p_b64 && gossip::GossipBallotTestAccess::ns_synced(*a.gossip);
    }));

    // P's view before the refresh: slot1 is A@P1@ts1.
    const uint64_t p_ts_before = gossip::GossipBallotTestAccess::ns_slot(*p.gossip, 1).timestamp;
    const auto p_bc_before = gossip::GossipBallotTestAccess::ns_broadcast_count(*p.gossip);
    const auto p_rc_before = gossip::GossipBallotTestAccess::ns_receive_count(*p.gossip);
    ASSERT_EQ(p_ts_before, ts1);

    // First synced tick: the one-shot refresh re-broadcasts the stored table
    // byte-identically. A's slot1 (P1@ts1) reaches P.
    gossip::GossipBallotTestAccess::run_gossip_tick(*a.gossip);
    pump_for(std::chrono::milliseconds(300));

    // P deduped the byte-identical refresh: slot1 timestamp unchanged, A record
    // unchanged, no re-forward (accept-forwards go through send_packet, not
    // broadcast_ns_slot_claim, so the broadcast counter is untouched).
    const auto& hp = gossip::GossipBallotTestAccess::ns_slot(*p.gossip, 1);
    EXPECT_EQ(hp.server_ip, P1);
    EXPECT_EQ(hp.timestamp, ts1);  // unchanged (constant-timestamp field observation)
    ASSERT_EQ(p.dns->nameserver_ip(ns1), P1);
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_broadcast_count(*p.gossip), p_bc_before);
    // P saw the refresh delivery but did not re-broadcast it.
    EXPECT_GT(gossip::GossipBallotTestAccess::ns_receive_count(*p.gossip), p_rc_before);
}

// C4: holder renewal timestamps are strictly increasing even when the wall
// clock does not advance (same-second burst, rolled-back clock); the receiver's
// equal-timestamp rejection (C2) makes nondecreasing insufficient.
TEST_F(NsClaimIpChangeTest, C4_HolderRenewalTimestampStrictlyIncreasing) {
    // (a) Deterministic selection logic (mirrors the production formula).
    bool failed = false;
    EXPECT_EQ(select_renewal_ts(1000, 1000, failed), 1001u);  EXPECT_FALSE(failed); // same second
    EXPECT_EQ(select_renewal_ts(1000, 5000, failed), 5001u);  EXPECT_FALSE(failed); // rollback
    EXPECT_EQ(select_renewal_ts(9000, 1000, failed), 9000u);  EXPECT_FALSE(failed); // far ahead
    EXPECT_EQ(select_renewal_ts(1000, UINT64_MAX, failed), 0u); EXPECT_TRUE(failed); // overflow

    const uint64_t now_s = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    const uint64_t ahead = now_s + 3600;  // FUTURE fixture: held ts ahead of the wall clock

    auto root_kp   = kc->ed25519_keygen();
    auto holder_kp = kc->ed25519_keygen();
    const auto holder_pub = crypto::to_base64(holder_kp.public_key);

    const auto config_a = [&](Node& n) {
        n.gossip->set_root_pubkey(root_kp.public_key);
        n.gossip->set_network_id(kTestNetworkHex);
        n.gossip->set_our_region("eu-west");
        n.gossip->set_preferred_ns_slot(1);
    };
    auto seed_holder = [&](const char* tag, const std::string ip, uint64_t ts) -> Node& {
        const auto sig = sign_b64(holder_kp, pinned_preimage(1, holder_pub, ip, ts));
        return make_node(
            tag,
            [&](Node& n) {
                seed_keypair(*n.storage, holder_kp);
                seed_ns_slot_state(*n.storage, {slot_entry(1, holder_pub, ip, ts, sig, true)}, 1);
            },
            config_a);
    };

    // (b) Two successive IP changes while the held ts dominates (ahead > now):
    // the holder must still produce strictly increasing timestamps.
    auto& a = seed_holder("a", "10.0.0.51", ahead);
    ASSERT_EQ(a.gossip->our_ns_slot(), 1);
    auto& sa = gossip::GossipBallotTestAccess::ns_slot(*a.gossip, 1);
    a.gossip->try_claim_ns_slot("10.0.0.52");  // change 1
    const uint64_t t1 = sa.timestamp;
    a.gossip->try_claim_ns_slot("10.0.0.53");  // change 2
    const uint64_t t2 = sa.timestamp;
    EXPECT_GT(t1, ahead);   // clamped past the held value, not left at it
    EXPECT_GT(t2, t1);      // strictly greater even though the wall clock did not advance

    // (c) Change after a clock rollback across a restart: the held ts is ahead of
    // the clock (fixture, NOT evidence the system clock was changed); the renewal
    // clamps to held+1 and does not roll back to now.
    auto& b = seed_holder("b", "10.0.0.54", ahead);
    restart_node(b, config_a);                 // model the restart over the persisted state
    ASSERT_EQ(b.gossip->our_ns_slot(), 1);
    b.gossip->try_claim_ns_slot("10.0.0.55");
    const auto& sb = gossip::GossipBallotTestAccess::ns_slot(*b.gossip, 1);
    EXPECT_EQ(sb.timestamp, ahead + 1);        // clamped to held+1 (ahead > now)
    EXPECT_GT(sb.timestamp, ahead);
}

// C5: at UINT64_MAX the holder cannot advance the timestamp, so the renewal fails
// closed: the accepted claim, DNS, persisted entry, and broadcast count are all
// left unchanged (no wrap, no saturate-and-emit, no reuse).
TEST_F(NsClaimIpChangeTest, C5_AtMaxTimestampRenewalFailsClosed) {
    const std::string IP_OLD = "10.0.0.51";
    const std::string IP_NEW = "10.0.0.52";
    auto root_kp   = kc->ed25519_keygen();
    auto holder_kp = kc->ed25519_keygen();
    const auto holder_pub = crypto::to_base64(holder_kp.public_key);
    const auto sig_max = sign_b64(holder_kp, pinned_preimage(1, holder_pub, IP_OLD, UINT64_MAX));
    const auto config_a = [&](Node& n) {
        n.gossip->set_root_pubkey(root_kp.public_key);
        n.gossip->set_network_id(kTestNetworkHex);
        n.gossip->set_our_region("eu-west");
        n.gossip->set_preferred_ns_slot(1);
    };
    auto& a = make_node(
        "a",
        [&](Node& n) {
            seed_keypair(*n.storage, holder_kp);
            seed_ns_slot_state(*n.storage, {slot_entry(1, holder_pub, IP_OLD, UINT64_MAX, sig_max, true)}, 1);
        },
        config_a);
    ASSERT_EQ(a.gossip->our_ns_slot(), 1);
    const auto bc0 = gossip::GossipBallotTestAccess::ns_broadcast_count(*a.gossip);
    a.gossip->try_claim_ns_slot(IP_NEW);  // must fail closed (no renewal emitted)
    const auto& s = gossip::GossipBallotTestAccess::ns_slot(*a.gossip, 1);
    EXPECT_EQ(a.gossip->our_ns_slot(), 1);                 // still holds
    EXPECT_EQ(s.server_ip, IP_OLD);                        // IP unchanged
    EXPECT_EQ(s.timestamp, UINT64_MAX);                    // timestamp unchanged
    EXPECT_EQ(gossip::GossipBallotTestAccess::ns_broadcast_count(*a.gossip), bc0);  // no broadcast
    EXPECT_EQ(read_disk_slot0(a)["timestamp"], UINT64_MAX); // persisted unchanged
    EXPECT_EQ(read_disk_slot0(a)["server_ip"], IP_OLD);
}
