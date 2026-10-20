#pragma once

// The shared wire-level gossip fixture: real GossipService nodes on one
// io_context the test thread pumps, raw correctly-signed datagrams through the
// real dispatcher, and the real root-signed certificate path. Suites derive
// from GossipWireFixture, name their temp root, attach their own downstream
// services, and stop them in stop_node_services().

#include <LemonadeNexus/ACL/ACLService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Gossip/GossipTypes.hpp>
#include <LemonadeNexus/Gossip/ServerCertificate.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>
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
#include <mutex>
#include <span>
#include <string>
#include <thread>
#include <utility>
#include <vector>
#ifdef _WIN32
#  include <process.h>
#else
#  include <unistd.h>
#endif

// Observation-only friend seam. The bound port, the NS slot table, the
// revocation set and the certificate gate are private state that sits behind
// packet-signature verification and a bound socket; a test cannot reach them
// through the public surface. No test WRITES private state through this seam —
// every stimulus is a real signed datagram through the real dispatcher, or a
// labelled raw injection of bytes the production code itself emitted.
namespace nexus::gossip {
struct GossipBallotTestAccess {
    static uint16_t port(GossipService& g) { return g.socket_.local_endpoint().port(); }
    static const NsSlotClaimData& ns_slot(GossipService& g, uint8_t slot) {
        return g.ns_slots_[slot - 1];
    }
    static bool ns_synced(GossipService& g) { return g.ns_state_synced_; }
    static bool ns_claim_pending(GossipService& g) { return g.ns_claim_pending_; }
    // One-shot refresh test: how many NsSlotClaim messages this service
    // broadcast (every send goes through broadcast_ns_slot_claim).
    static std::uint64_t ns_broadcast_count(const GossipService& g) {
        return g.test_ns_claim_broadcast_count_;
    }
    // v0.9.6 relay-loop tests: how many NsSlotClaim messages this service
    // RECEIVED (all ingress, before validation).
    static std::uint64_t ns_receive_count(const GossipService& g) {
        return g.test_ns_claim_received_count_;
    }
    // v0.9.6: drive the denial-log rate limiter with synthetic clock values.
    static bool denial_log_allowed(GossipService& g, const std::string& key,
                                   std::chrono::steady_clock::time_point now) {
        return g.denial_log_allowed(key, now);
    }
    // Drives one 5 s gossip tick (NS claim deferral/retry, opt-out release)
    // without waiting for the timer.
    static void run_gossip_tick(GossipService& g) { g.on_gossip_tick(); }
    // DNS catch-up runs on a 30 s cadence; tests send a digest round directly.
    static void send_dns_digests(GossipService& g) { g.send_dns_sync_digests(); }
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

namespace nexus_test {

namespace fs = std::filesystem;
using asio::ip::udp;

inline int test_pid() {
#ifdef _WIN32
    return _getpid();
#else
    return ::getpid();
#endif
}

// Certificates bind to a network id; one value serves every fixture.
inline const std::string kTestNetworkHex(64, 'a');

inline std::vector<uint8_t> msgpack_of(const nlohmann::json& j) {
    auto packed = nlohmann::json::to_msgpack(j);
    return std::vector<uint8_t>(packed.begin(), packed.end());
}

/// One gossip node plus the downstream services a suite may attach; unattached
/// members stay null and inert.
struct GossipTestNode {
    fs::path dir;
    std::unique_ptr<nexus::crypto::SodiumCryptoService>   crypto;
    std::unique_ptr<nexus::storage::FileStorageService>   storage;
    std::unique_ptr<nexus::acl::AclStore>                 acl_store;
    std::unique_ptr<nexus::acl::ACLService>               acl;
    std::unique_ptr<nexus::ipam::IPAMService>             ipam;
    std::unique_ptr<nexus::tree::PermissionTreeService>   tree;
    std::unique_ptr<nexus::network::DnsService>           dns;
    std::unique_ptr<nexus::gossip::GossipService>         gossip;
    // Every peer the ServerHello handler reported as certificate-verified.
    std::vector<nexus::security::NodeId>                  certified;

    [[nodiscard]] const nexus::crypto::Ed25519PublicKey& pubkey() const {
        return gossip->keypair().public_key;
    }
    [[nodiscard]] std::string pubkey_b64() const { return nexus::crypto::to_base64(pubkey()); }
    [[nodiscard]] uint16_t port() {
        return nexus::gossip::GossipBallotTestAccess::port(*gossip);
    }
    [[nodiscard]] std::string endpoint() { return "127.0.0.1:" + std::to_string(port()); }
    [[nodiscard]] udp::endpoint udp_endpoint() {
        return udp::endpoint{asio::ip::make_address("127.0.0.1"), port()};
    }
    [[nodiscard]] bool revoked(const std::string& pk) {
        return nexus::gossip::GossipBallotTestAccess::revoked(*gossip, pk);
    }
    [[nodiscard]] bool certified_peer(const std::string& pk) {
        return nexus::gossip::GossipBallotTestAccess::certified(*gossip, pk);
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
        return nexus::gossip::GossipBallotTestAccess::ns_slot(*gossip, slot).server_pubkey;
    }
    // The exact wire broadcast_ns_slot_claim would emit for this stored entry;
    // re-encoding is deterministic, so the stored signature stays valid.
    [[nodiscard]] std::vector<uint8_t> ns_wire_of(uint8_t slot) {
        const auto& c = nexus::gossip::GossipBallotTestAccess::ns_slot(*gossip, slot);
        nlohmann::json j{{"slot", c.slot}, {"server_pubkey", c.server_pubkey},
                         {"server_ip", c.server_ip}, {"region", c.region},
                         {"timestamp", c.timestamp}, {"signature", c.signature}};
        if (c.pinned) j["pinned"] = true;
        return msgpack_of(j);
    }
};

class GossipWireFixture : public ::testing::Test {
protected:
    /// `root_tag` prefixes the per-run temp root, e.g. "nexus_test_gossip_ingress_".
    explicit GossipWireFixture(std::string root_tag) : root_tag_(std::move(root_tag)) {}

    // Declared before the nodes so it outlives their sockets and timers.
    asio::io_context io;
    fs::path root;
    // Key material and signatures for the hostile/fixture side. Kept out of the
    // nodes so certificates exist before the receiving node is constructed.
    std::unique_ptr<nexus::crypto::SodiumCryptoService> kc;
    std::vector<std::unique_ptr<GossipTestNode>> nodes;

    void SetUp() override {
        root = fs::temp_directory_path() / (root_tag_ + std::to_string(test_pid()));
        fs::remove_all(root);
        fs::create_directories(root);
        kc = std::make_unique<nexus::crypto::SodiumCryptoService>();
        kc->start();
    }

    // Suite-attached services, stopped between gossip and storage in the
    // suite's own order.
    virtual void stop_node_services(GossipTestNode&) {}

    void TearDown() override {
        for (auto it = nodes.rbegin(); it != nodes.rend(); ++it) {
            (*it)->gossip->stop();
            stop_node_services(**it);
            (*it)->storage->stop();
            (*it)->crypto->stop();
        }
        nodes.clear();
        kc->stop();
        kc.reset();
        fs::remove_all(root);
    }

    // `seed` runs before the gossip service exists, so it can pre-place storage
    // state (keypair, peer list with certificates) and build the downstream
    // services. `configure` runs on the constructed service before start().
    // Everything shares one io_context that the test thread pumps, so callbacks
    // run on the test thread and need no lock.
    GossipTestNode& make_node(const std::string& tag,
                              const std::function<void(GossipTestNode&)>& seed = {},
                              const std::function<void(GossipTestNode&)>& configure = {}) {
        auto n = std::make_unique<GossipTestNode>();
        n->dir = root / tag;
        fs::create_directories(n->dir);
        n->crypto = std::make_unique<nexus::crypto::SodiumCryptoService>();
        n->crypto->start();
        n->storage = std::make_unique<nexus::storage::FileStorageService>(n->dir);
        n->storage->start();
        if (seed) seed(*n);
        n->gossip = std::make_unique<nexus::gossip::GossipService>(io, 0, *n->storage,
                                                                   *n->crypto);
        if (configure) configure(*n);
        n->gossip->start();
        nodes.push_back(std::move(n));
        return *nodes.back();
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

    // Models a process restart: stops the gossip service and rebuilds it over
    // the SAME storage directory (keypair, peers.json and ns_slots.json are
    // re-loaded from disk); other services are left as they are. `configure`
    // runs before start().
    void restart_node(GossipTestNode& n,
                      const std::function<void(GossipTestNode&)>& configure = {}) {
        n.gossip->stop();
        n.gossip.reset();
        n.gossip = std::make_unique<nexus::gossip::GossipService>(io, 0, *n.storage,
                                                                  *n.crypto);
        if (configure) configure(n);
        n.gossip->start();
    }

    // A raw packet in gossip framing, signed by `kp` (the shape send_packet
    // emits).
    std::vector<uint8_t> build_packet(const nexus::crypto::Ed25519Keypair& kp,
                                      nexus::gossip::GossipMsgType msg_type,
                                      const std::vector<uint8_t>& payload) {
        namespace gossip = nexus::gossip;
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
    void inject(const std::vector<uint8_t>& pkt, GossipTestNode& target) {
        udp::socket raw{io, udp::endpoint{udp::v4(), 0}};
        // macOS loopback refuses datagrams larger than the default send buffer.
        raw.set_option(asio::socket_base::send_buffer_size(65536));
        raw.send_to(asio::buffer(pkt), target.udp_endpoint());
    }

    // Seed a peer list into storage BEFORE gossip starts, so load_peers()
    // adopts the entries (including any stored certificate). load_peers
    // deduplicates by ENDPOINT, so every entry needs a distinct endpoint, even
    // a placeholder one.
    static void seed_peers(nexus::storage::FileStorageService& s, const nlohmann::json& arr) {
        nexus::storage::SignedEnvelope env;
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

    // Persist an identity keypair into storage BEFORE the gossip service is
    // constructed, so on_start loads it: the "restart" helpers rebuild the
    // service over the same directory with the SAME identity.
    static void seed_keypair(nexus::storage::FileStorageService& s,
                             const nexus::crypto::Ed25519Keypair& kp) {
        nexus::storage::SignedEnvelope env;
        env.type = "identity_keypair";
        env.data = nlohmann::json{{"public_key", nexus::crypto::to_base64(kp.public_key)},
                                  {"private_key", nexus::crypto::to_base64(kp.private_key)}}
            .dump();
        ASSERT_TRUE(s.write_file("identity", "keypair.json", env));
    }

    // The v0.9.5 slot-state file, shaped exactly like save_ns_slots emits
    // it (our_slot + 9 entries, null when empty, pinned key only when set).
    static void seed_ns_slot_state(nexus::storage::FileStorageService& s,
                                   const std::vector<nlohmann::json>& slots,
                                   int our_slot = -1) {
        nlohmann::json arr = nlohmann::json::array();
        for (int i = 0; i < 9; ++i) {
            arr.push_back(i < static_cast<int>(slots.size()) ? slots[i] : nullptr);
        }
        nlohmann::json j{{"slots", arr}};
        if (our_slot > 0) j["our_slot"] = our_slot;
        nexus::storage::SignedEnvelope env;
        env.type = "ns_slot_state";
        env.data = j.dump();
        ASSERT_TRUE(s.write_file("identity", "ns_slots.json", env));
    }

    static nlohmann::json slot_entry(uint8_t slot, const std::string& server_pubkey_b64,
                                     const std::string& server_ip,
                                     uint64_t timestamp,
                                     const std::string& signature,
                                     bool pinned = false) {
        nlohmann::json e{{"slot", slot}, {"server_pubkey", server_pubkey_b64},
                         {"server_ip", server_ip}, {"region", "eu-west"},
                         {"timestamp", timestamp}, {"signature", signature}};
        if (pinned) e["pinned"] = true;
        return e;
    }

    // The REAL certificate path: root-signed by `root_kp`, verifiable by any
    // node whose set_root_pubkey matches.
    std::string issue_cert(const std::string& server_pubkey_b64,
                           const std::string& server_id,
                           const nexus::crypto::Ed25519Keypair& root_kp,
                           const std::string& network_hex = kTestNetworkHex) {
        nexus::gossip::CertIssueParams p;
        p.network_id        = network_hex;
        p.server_pubkey_b64 = server_pubkey_b64;
        p.server_id         = server_id;
        return nlohmann::json(
            nexus::gossip::issue_server_certificate(p, *kc, root_kp.private_key,
                                                    root_kp.public_key)).dump();
    }

    std::string sign_b64(const nexus::crypto::Ed25519Keypair& kp, const std::string& msg) {
        auto sig = kc->ed25519_sign(
            kp.private_key,
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg.data()),
                                     msg.size()));
        return nexus::crypto::to_base64(sig);
    }

    // A DNS delta signed exactly the way handle_dns_record_sync rebuilds the
    // origin preimage (data fields only, sorted keys). The wire form adds
    // signer_pubkey + signature, mirroring broadcast_dns_record_delta.
    std::vector<uint8_t> dns_delta_payload(const nexus::crypto::Ed25519Keypair& signer,
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
        wire["signer_pubkey"] = nexus::crypto::to_base64(signer.public_key);
        wire["signature"]     = sign_b64(signer, canonical.dump());
        return msgpack_of(wire);
    }

    // A sequenced DNS delta: `signature` over the legacy preimage, and
    // `seq_signature` over the same fields plus origin_seq, as
    // broadcast_dns_record_delta emits.
    nlohmann::json dns_seq_delta_wire(const nexus::crypto::Ed25519Keypair& signer,
                                      const std::string& delta_id,
                                      const std::string& fqdn,
                                      const std::string& value,
                                      uint64_t timestamp,
                                      uint64_t origin_seq,
                                      const std::string& operation = "set") {
        nlohmann::json canonical;
        canonical["delta_id"]    = delta_id;
        canonical["fqdn"]        = fqdn;
        canonical["operation"]   = operation;
        canonical["record_type"] = "A";
        canonical["timestamp"]   = timestamp;
        canonical["ttl"]         = uint32_t{60};
        canonical["value"]       = value;
        nlohmann::json seq_canonical = canonical;
        seq_canonical["origin_seq"] = origin_seq;

        nlohmann::json wire = canonical;
        wire["signer_pubkey"] = nexus::crypto::to_base64(signer.public_key);
        wire["signature"]     = sign_b64(signer, canonical.dump());
        wire["origin_seq"]    = origin_seq;
        wire["seq_signature"] = sign_b64(signer, seq_canonical.dump());
        return wire;
    }

private:
    std::string root_tag_;
};

}  // namespace nexus_test
