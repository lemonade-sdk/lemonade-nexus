// Wire-level tests for delta record transfer.
//
// The transfer moves original author-signed records between bounded pools.
// Retention is transfer only: a retained record never mutates the local tree
// or ACL. Every stimulus is a real signed datagram through the real
// dispatcher (or a real tree apply for the local-retention path); the
// certificate path is the production one (issue_server_certificate + a real
// ServerHello exchange + set_root_pubkey). The friend seam only observes
// pool state and drives the declared test knobs (caps, fault injection).

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Gossip/GossipTypes.hpp>
#include <LemonadeNexus/Gossip/ServerCertificate.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>

#include <asio.hpp>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <span>
#include <string>
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
using json = nlohmann::json;

namespace nexus::gossip {
// Observation + declared test knobs only.
struct GossipBallotTestAccess {
    static uint16_t port(GossipService& g) { return g.socket_.local_endpoint().port(); }
    static bool certified(GossipService& g, const std::string& pk) {
        return g.peer_certificate_is_root_signed(pk);
    }
    static uint64_t pool_latest(GossipService& g) {
        std::lock_guard lock(g.transfer_mutex_);
        return g.pool_position_index_.empty()
                   ? 0
                   : static_cast<uint64_t>(g.pool_position_index_.rbegin()->first);
    }
    static uint64_t pool_record_count(GossipService& g) {
        std::lock_guard lock(g.transfer_mutex_);
        return static_cast<uint64_t>(g.pool_position_index_.size());
    }
    static bool pool_available(GossipService& g) {
        std::lock_guard lock(g.transfer_mutex_);
        return g.pool_available_;
    }
    static std::string pool_generation(GossipService& g) {
        std::lock_guard lock(g.transfer_mutex_);
        return g.pool_generation_;
    }
    static uint64_t pool_verified_bytes(GossipService& g) {
        std::lock_guard lock(g.transfer_mutex_);
        return g.pool_verified_bytes_;
    }
    static uint64_t pool_excluded_bytes(GossipService& g) {
        std::lock_guard lock(g.transfer_mutex_);
        return g.pool_excluded_bytes_;
    }
    static bool pool_excluded(GossipService& g, const std::string& hash) {
        std::lock_guard lock(g.transfer_mutex_);
        return g.pool_excluded_.count(hash) != 0;
    }
    static bool has_outstanding(GossipService& g, const std::string& pk) {
        std::lock_guard lock(g.transfer_mutex_);
        return g.outstanding_.count(pk) != 0;
    }
    static uint64_t outstanding_nonce(GossipService& g, const std::string& pk) {
        std::lock_guard lock(g.transfer_mutex_);
        auto it = g.outstanding_.find(pk);
        return it == g.outstanding_.end() ? 0 : it->second.nonce;
    }
    static bool outstanding_info(GossipService& g, const std::string& pk,
                                 uint64_t& nonce, uint64_t& from_pos,
                                 std::string& generation) {
        std::lock_guard lock(g.transfer_mutex_);
        auto it = g.outstanding_.find(pk);
        if (it == g.outstanding_.end()) return false;
        nonce = it->second.nonce;
        from_pos = it->second.from_pos;
        generation = it->second.generation;
        return true;
    }
    static bool has_log(GossipService& g, const std::string& pk) {
        std::lock_guard lock(g.transfer_mutex_);
        return g.peer_logs_.count(pk) != 0;
    }
    static uint64_t cursor_of(GossipService& g, const std::string& pk) {
        std::lock_guard lock(g.transfer_mutex_);
        auto it = g.peer_logs_.find(pk);
        return it == g.peer_logs_.end() ? 0 : it->second.cursor;
    }
    static uint64_t backoff_until(GossipService& g, const std::string& pk) {
        std::lock_guard lock(g.transfer_mutex_);
        auto it = g.peer_logs_.find(pk);
        return it == g.peer_logs_.end() ? 0 : it->second.backoff_until_ms;
    }
    static void set_pool_max_records(GossipService& g, std::size_t v) {
        g.test_pool_max_records_ = v;
    }
    static void set_pool_max_bytes(GossipService& g, std::uint64_t v) {
        g.test_pool_max_bytes_ = v;
    }
    static void set_peer_log_cap(GossipService& g, std::size_t v) {
        g.test_peer_log_cap_ = v;
    }
    static void fail_next_pool_write(GossipService& g) { g.test_fail_next_pool_write_ = true; }
    // Models the request timeout elapsing while a response is in flight.
    static void set_outstanding_deadline(GossipService& g, const std::string& pk,
                                         uint64_t deadline_ms) {
        g.test_set_outstanding_deadline(pk, deadline_ms);
    }
    static bool pool_has_uncertain_write(GossipService& g) {
        return g.test_pool_has_uncertain_write();
    }
    static uint64_t receive_error_count(GossipService& g) {
        return g.test_receive_error_count_;
    }
    static void drop_outstanding(GossipService& g, const std::string& peer) {
        g.test_drop_outstanding(peer);
    }
};
}  // namespace nexus::gossip

namespace {

inline const std::string kTestNetworkHex(64, 'a');

std::vector<uint8_t> bytes_of(const std::string& s) {
    return std::vector<uint8_t>(s.begin(), s.end());
}

struct Node {
    fs::path dir;
    std::unique_ptr<crypto::SodiumCryptoService>    crypto;
    std::unique_ptr<storage::FileStorageService>    storage;
    std::unique_ptr<tree::PermissionTreeService>    tree;
    std::unique_ptr<gossip::GossipService>          gossip;

    [[nodiscard]] const crypto::Ed25519Keypair& keypair() const { return gossip->keypair(); }
    [[nodiscard]] std::string pubkey_b64() const { return crypto::to_base64(keypair().public_key); }
    [[nodiscard]] uint16_t port() { return gossip::GossipBallotTestAccess::port(*gossip); }
    [[nodiscard]] std::string endpoint() { return "127.0.0.1:" + std::to_string(port()); }
    [[nodiscard]] udp::endpoint udp_endpoint() {
        return udp::endpoint{asio::ip::make_address("127.0.0.1"), port()};
    }
    [[nodiscard]] bool certified_peer(const std::string& pk) {
        return gossip::GossipBallotTestAccess::certified(*gossip, pk);
    }
    // The retained pool files on disk (hash -> text), straight from storage.
    [[nodiscard]] std::vector<std::pair<std::string, std::string>> pool_files() const {
        std::vector<std::pair<std::string, std::string>> out;
        for (const auto& e : storage->list_pool_entries()) {
            if (e.temporary) continue;
            storage::FileStorageService::PoolRead result;
            if (auto text = storage->read_pool_record(e.hash,
                    gossip::GossipService::kMaxRetainedRecordBytes, result)) {
                out.emplace_back(e.hash, *text);
            }
        }
        return out;
    }
};

class DeltaTransferTest : public ::testing::Test {
protected:
    asio::io_context io;
    fs::path root;
    std::unique_ptr<crypto::SodiumCryptoService> kc;
    std::vector<std::unique_ptr<Node>> nodes;
    // The author whose signed records move between pools.
    crypto::Ed25519Keypair author_kp{};
    std::string            author_pubkey;  // "ed25519:base64..."

    void SetUp() override {
        root = fs::temp_directory_path() /
               ("nexus_test_delta_transfer_" + std::to_string(getpid()));
        fs::remove_all(root);
        fs::create_directories(root);
        kc = std::make_unique<crypto::SodiumCryptoService>();
        kc->start();
        author_kp = kc->ed25519_keygen();
        author_pubkey = "ed25519:" + crypto::to_base64(author_kp.public_key);
    }

    void TearDown() override {
        for (auto it = nodes.rbegin(); it != nodes.rend(); ++it) {
            (*it)->gossip->stop();
            if ((*it)->tree) (*it)->tree->stop();
            (*it)->storage->stop();
            (*it)->crypto->stop();
        }
        nodes.clear();
        kc->stop();
        kc.reset();
        fs::remove_all(root);
    }

    // A node with a real tree (root bootstrapped so the author holds the
    // required permissions) and the production retention wiring.
    // Construct a FRESH gossip service over the node's retained storage:
    // the old instance is stopped (socket closed, timer cancelled, peers
    // saved) and destroyed; the retention sink is rewired. Same-object
    // stop/start is not supported.
    void respawn_gossip(Node& n,
                        const std::function<void(gossip::GossipService&)>& configure =
                            {}) {
        n.gossip->stop();
        auto g = std::make_unique<gossip::GossipService>(io, 0, *n.storage, *n.crypto);
        if (n.tree) {
            g->set_tree(n.tree.get());
            n.tree->set_delta_retention_sink(
                [g2 = g.get()](const storage::FileStorageService::RetainedDelta& rec) {
                    return g2->retain_local_delta(rec);
                });
        }
        n.gossip = std::move(g);
        if (configure) configure(*n.gossip);
        n.gossip->start();
    }

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
        bootstrap_root(*n);
        n->tree = std::make_unique<tree::PermissionTreeService>(*n->storage, *n->crypto);
        n->tree->start();
        if (seed) seed(*n);
        n->gossip = std::make_unique<gossip::GossipService>(io, 0, *n->storage, *n->crypto);
        // The main.cpp wiring: local retention through the gossip pool.
        n->tree->set_delta_retention_sink(
            [g = n->gossip.get()](const storage::FileStorageService::RetainedDelta& rec) {
                return g->retain_local_delta(rec);
            });
        n->gossip->set_tree(n->tree.get());
        if (configure) configure(*n);
        n->gossip->start();
        nodes.push_back(std::move(n));
        return *nodes.back();
    }

    // Bootstrap a root node that grants the author admin, directly into
    // storage, self-signed (the pattern from test_permission_tree).
    void bootstrap_root(Node& n) {
        tree::TreeNode root_node;
        root_node.id = "root";
        root_node.parent_id = "";
        root_node.type = tree::NodeType::Root;
        root_node.mgmt_pubkey = author_pubkey;
        root_node.assignments = {{author_pubkey, {"admin"}}};
        auto canonical = tree::canonical_node_json(root_node);
        auto msg = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
        auto sig = kc->ed25519_sign(author_kp.private_key, msg);
        root_node.signature = crypto::to_base64(sig);

        storage::SignedEnvelope env;
        env.version = 1;
        env.type = "tree_node";
        env.data = json(root_node).dump();
        env.signer_pubkey = author_pubkey;
        env.signature = root_node.signature;
        ASSERT_TRUE(n.storage->write_node("root", env));
    }

    // The REAL certificate path: root-signed by `root_kp`.
    std::string issue_cert(const std::string& server_pubkey_b64,
                           const std::string& server_id,
                           const crypto::Ed25519Keypair& root_kp) {
        gossip::CertIssueParams p;
        p.network_id        = kTestNetworkHex;
        p.server_pubkey_b64 = server_pubkey_b64;
        p.server_id         = server_id;
        return json(gossip::issue_server_certificate(p, *kc,
                root_kp.private_key, root_kp.public_key)).dump();
    }

    // Bounded pump: at most ONE handler per deadline-checked iteration,
    // with an overall handler budget. A pathologically re-arming handler
    // chain cannot run past the deadline or the budget.
    bool pump_until(const std::function<bool()>& done,
                    std::chrono::milliseconds timeout = std::chrono::seconds(3)) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        std::uint64_t budget = 20000;
        while (std::chrono::steady_clock::now() < deadline) {
            if (io.poll_one() > 0 && --budget == 0) return done();
            if (done()) return true;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        return done();
    }

    void pump_for(std::chrono::milliseconds d) {
        (void)pump_until([] { return false; }, d);
    }

    // A real gossip-framed packet signed by `kp` (the shape send_packet emits).
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

    void inject(const std::vector<uint8_t>& pkt, Node& target) {
        udp::socket raw{io, udp::endpoint{udp::v4(), 0}};
        raw.set_option(asio::socket_base::send_buffer_size(65536));
        raw.send_to(asio::buffer(pkt), target.udp_endpoint());
    }

    // A signed tree delta by the author, over the production canonical form.
    tree::TreeDelta signed_delta(const std::string& operation,
                                 const std::string& target_node_id,
                                 const tree::TreeNode& node_data,
                                 uint64_t timestamp = 0) {
        tree::TreeDelta delta;
        delta.operation      = operation;
        delta.target_node_id = target_node_id;
        delta.node_data      = node_data;
        delta.signer_pubkey  = author_pubkey;
        // The apply path enforces a freshness window; default to now.
        delta.timestamp = timestamp ? timestamp : static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        auto canonical = tree::canonical_delta_json(delta);
        auto msg = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
        delta.signature = crypto::to_base64(kc->ed25519_sign(author_kp.private_key, msg));
        return delta;
    }

    tree::TreeNode child_node(const std::string& id, const std::string& parent,
                              std::string hostname = "") {
        tree::TreeNode node;
        node.id = id;
        node.parent_id = parent;
        node.type = tree::NodeType::Customer;
        node.mgmt_pubkey = author_pubkey;
        node.hostname = std::move(hostname);
        return node;
    }

    // The author-signed record exactly as the transfer wire carries it
    // (statement fields only — the transport position is added by the sender
    // from its pool index).
    json record_json(const tree::TreeDelta& d) {
        json r;
        r["operation"]      = d.operation;
        r["target_node_id"] = d.target_node_id;
        r["node_data"]      = json(d.node_data);
        r["signer_pubkey"]  = d.signer_pubkey;
        r["signature"]      = d.signature;
        r["timestamp"]      = d.timestamp;
        return r;
    }

    // A digest exactly as do_send_digest emits one, for this node's pool.
    std::vector<uint8_t> digest_bytes(Node& n) {
        json digest;
        digest["latest_pos"] = gossip::GossipBallotTestAccess::pool_latest(*n.gossip);
        digest["log_generation"] =
            gossip::GossipBallotTestAccess::pool_generation(*n.gossip);
        digest["peer_count"] = 1;
        digest["timestamp"] = 1000;
        return bytes_of(digest.dump());
    }

    storage::FileStorageService::PoolRead pool_read_result{
        storage::FileStorageService::PoolRead::Ok};

    // A retained record exactly as storage serializes one.
    storage::FileStorageService::RetainedDelta record_to_stored(
        const tree::TreeDelta& d, uint64_t position) {
        storage::FileStorageService::RetainedDelta r;
        r.position       = position;
        r.record_hash    = hash_of(d);
        r.operation      = d.operation;
        r.target_node_id = d.target_node_id;
        r.data           = json(d.node_data).dump();
        r.signer_pubkey  = d.signer_pubkey;
        r.signature      = d.signature;
        r.timestamp      = d.timestamp;
        return r;
    }

    // The retained identity of a delta: hex(SHA-256(canonical statement)).
    std::string hash_of(const tree::TreeDelta& d) {
        auto canonical = tree::canonical_delta_json(d);
        auto digest = kc->sha256(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size()));
        return crypto::to_hex(digest);
    }

    void corrupt_pool_record(Node& n, const std::string& hash, const std::string& content) {
        const auto file = n.storage->pool_dir() / (hash + ".json");
        ASSERT_TRUE(fs::exists(file));
        std::ofstream out(file, std::ios::binary | std::ios::trunc);
        out << content;
    }

    // Two nodes that become each other's cert-verified peers through the
    // production ServerHello exchange (real certificates, real proof of
    // possession, real root anchor).
    void make_certified_pair(Node& a, Node& b, const crypto::Ed25519Keypair& root_kp) {
        a.gossip->set_root_pubkey(root_kp.public_key);
        b.gossip->set_root_pubkey(root_kp.public_key);
        a.gossip->set_network_id(kTestNetworkHex);
        b.gossip->set_network_id(kTestNetworkHex);
        a.gossip->do_add_peer(b.endpoint(), b.pubkey_b64());
        b.gossip->do_add_peer(a.endpoint(), a.pubkey_b64());
        auto hello = [&](Node& from, Node& to) {
            auto cert = issue_cert(from.pubkey_b64(),
                                   "srv-" + std::to_string(from.port()), root_kp);
            json h = json::parse(cert);
            h["is_response"] = false;
            inject(build_packet(from.keypair(), gossip::GossipMsgType::ServerHello,
                                bytes_of(h.dump())),
                   to);
        };
        hello(a, b);
        pump_for(std::chrono::milliseconds(200));
        hello(b, a);
        pump_for(std::chrono::milliseconds(200));
        EXPECT_TRUE(a.certified_peer(b.pubkey_b64()));
        EXPECT_TRUE(b.certified_peer(a.pubkey_b64()));
    }
};

// ---------------------------------------------------------------------------
// (1) Local retention keeps the original author's fields
// ---------------------------------------------------------------------------

TEST_F(DeltaTransferTest, LocalApplyRetainsSignedRecordWithOriginalFields) {
    auto& a = make_node("a");

    auto d = signed_delta("create_node", "child-1", child_node("child-1", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d));

    const auto hash = hash_of(d);
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*a.gossip), 1u);
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_latest(*a.gossip), 1u);

    auto files = a.pool_files();
    ASSERT_EQ(files.size(), 1u);
    EXPECT_EQ(files[0].first, hash);
    auto stored = json::parse(files[0].second);
    // The retained record carries the ORIGINAL author fields, untouched.
    EXPECT_EQ(stored["signer_pubkey"].get<std::string>(), author_pubkey);
    EXPECT_EQ(stored["signature"].get<std::string>(), d.signature);
    EXPECT_EQ(stored["operation"].get<std::string>(), "create_node");
    EXPECT_EQ(stored["target_node_id"].get<std::string>(), "child-1");
    EXPECT_EQ(stored["record_hash"].get<std::string>(), hash);
    EXPECT_EQ(stored["position"].get<uint64_t>(), 1u);
    // Retention is transfer only: the local apply created the node once.
    EXPECT_TRUE(a.tree->get_node("child-1").has_value());
}

TEST_F(DeltaTransferTest, RetentionRefusalNeverRollsBackTheAppliedMutation) {
    auto& a = make_node("a");
    // Exhaust the byte budget so no record fits.
    gossip::GossipBallotTestAccess::set_pool_max_bytes(*a.gossip, 1);

    auto d = signed_delta("create_node", "child-1", child_node("child-1", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d));
    EXPECT_TRUE(a.tree->get_node("child-1").has_value());
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*a.gossip), 0u)
        << "a record above the byte budget must not be retained";

    auto d2 = signed_delta("create_node", "child-2", child_node("child-2", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d2));
    EXPECT_TRUE(a.tree->get_node("child-2").has_value());
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*a.gossip), 0u);
}

TEST_F(DeltaTransferTest, WriteFailureLeavesPoolStateUntouched) {
    auto& a = make_node("a");
    gossip::GossipBallotTestAccess::fail_next_pool_write(*a.gossip);

    auto d = signed_delta("create_node", "child-1", child_node("child-1", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d));
    EXPECT_TRUE(a.tree->get_node("child-1").has_value());
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*a.gossip), 0u);
    EXPECT_TRUE(a.pool_files().empty());

    // The position is not burned: the next retain takes position 1.
    auto d2 = signed_delta("create_node", "child-2", child_node("child-2", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d2));
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*a.gossip), 1u);
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_latest(*a.gossip), 1u);
}

// ---------------------------------------------------------------------------
// (2) Pool corruption, collision, and capacity accounting
// ---------------------------------------------------------------------------

TEST_F(DeltaTransferTest, CorruptRecordIsExcludedPreservedAndOccupiesItsIdentifier) {
    auto& a = make_node("a");
    auto d1 = signed_delta("create_node", "child-1", child_node("child-1", "root"));
    auto d2 = signed_delta("create_node", "child-2", child_node("child-2", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d1));
    ASSERT_TRUE(a.tree->apply_delta(d2));
    const auto h2 = hash_of(d2);
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*a.gossip), 2u);

    // Corrupt the position-2 file in place (byte-identical afterwards).
    const std::string corrupt = "not-valid-pool-content";
    corrupt_pool_record(a, h2, corrupt);

    // A fresh gossip service over the same storage reconstructs the pool.
    // The corrupted file sits at the HIGHEST position: its position cannot
    // be reconstructed, so the pool is unavailable — no transfer view, no
    // new retention — while every file is preserved.
    auto fresh = std::make_unique<gossip::GossipService>(io, 0, *a.storage, *a.crypto);
    fresh->start();
    EXPECT_FALSE(gossip::GossipBallotTestAccess::pool_available(*fresh));
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*fresh), 0u);
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_latest(*fresh), 0u);
    {
        std::ifstream in(a.storage->pool_dir() / (h2 + ".json"), std::ios::binary);
        std::string content((std::istreambuf_iterator<char>(in)), {});
        EXPECT_EQ(content, corrupt)
            << "evidence must not be auto-repaired or overwritten";
        std::ifstream in1(a.storage->pool_dir() / (hash_of(d1) + ".json"), std::ios::binary);
        std::string content1((std::istreambuf_iterator<char>(in1)), {});
        EXPECT_NE(content1.find(R"("id":"child-1")"), std::string::npos)
            << "the intact record must be preserved as well";
    }
    // New retention is refused while the pool is unavailable.
    storage::FileStorageService::RetainedDelta rec;
    rec.operation = d2.operation;
    rec.target_node_id = d2.target_node_id;
    rec.data = json(d2.node_data).dump();
    rec.signer_pubkey = d2.signer_pubkey;
    rec.signature = d2.signature;
    rec.timestamp = d2.timestamp;
    EXPECT_FALSE(fresh->retain_local_delta(rec));
    auto d3 = signed_delta("create_node", "child-3", child_node("child-3", "root"));
    storage::FileStorageService::RetainedDelta rec3;
    rec3.operation = d3.operation;
    rec3.target_node_id = d3.target_node_id;
    rec3.data = json(d3.node_data).dump();
    rec3.signer_pubkey = d3.signer_pubkey;
    rec3.signature = d3.signature;
    rec3.timestamp = d3.timestamp;
    EXPECT_FALSE(fresh->retain_local_delta(rec3))
        << "no new retention while the pool is unavailable";
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*fresh), 0u);
    fresh->stop();
}

TEST_F(DeltaTransferTest, CorruptBytesCountTowardCapacity) {
    auto& a = make_node("a");
    auto d1 = signed_delta("create_node", "child-1", child_node("child-1", "root"));
    auto d2 = signed_delta("create_node", "child-2", child_node("child-2", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d1));
    ASSERT_TRUE(a.tree->apply_delta(d2));
    const auto h2 = hash_of(d2);
    const auto corrupt = "garbage";
    corrupt_pool_record(a, h2, corrupt);

    // Strict rule: a corrupted highest position makes the pool unavailable,
    // so new retention is refused regardless of remaining byte capacity.
    auto fresh = std::make_unique<gossip::GossipService>(io, 0, *a.storage, *a.crypto);
    fresh->start();
    ASSERT_FALSE(gossip::GossipBallotTestAccess::pool_available(*fresh));

    auto d3 = signed_delta("create_node", "child-3", child_node("child-3", "root"));
    storage::FileStorageService::RetainedDelta rec;
    rec.operation = d3.operation;
    rec.target_node_id = d3.target_node_id;
    rec.data = json(d3.node_data).dump();
    rec.signer_pubkey = d3.signer_pubkey;
    rec.signature = d3.signature;
    rec.timestamp = d3.timestamp;
    EXPECT_FALSE(fresh->retain_local_delta(rec))
        << "corruption must not create free capacity or retention";
    fresh->stop();

    // Without corruption, the byte budget still bounds retention: a budget
    // that fits the current pool exactly excludes the next record.
    auto& c = make_node("c");
    auto d4 = signed_delta("create_node", "child-4", child_node("child-4", "root"));
    auto d5 = signed_delta("create_node", "child-5", child_node("child-5", "root"));
    ASSERT_TRUE(c.tree->apply_delta(d4));
    ASSERT_TRUE(c.tree->apply_delta(d5));
    const auto used = gossip::GossipBallotTestAccess::pool_verified_bytes(*c.gossip);
    gossip::GossipBallotTestAccess::set_pool_max_bytes(*c.gossip, used);
    auto d6 = signed_delta("create_node", "child-6", child_node("child-6", "root"));
    storage::FileStorageService::RetainedDelta rec2;
    rec2.operation = d6.operation;
    rec2.target_node_id = d6.target_node_id;
    rec2.data = json(d6.node_data).dump();
    rec2.signer_pubkey = d6.signer_pubkey;
    rec2.signature = d6.signature;
    rec2.timestamp = d6.timestamp;
    EXPECT_FALSE(c.gossip->retain_local_delta(rec2))
        << "a byte budget that fits the current pool must exclude the next record";
}

TEST_F(DeltaTransferTest, BoundsExceededAtStartupMakeThePoolUnavailable) {
    // Three genuine signed records, pre-placed in the pool directory.
    auto d1 = signed_delta("create_node", "c-1", child_node("c-1", "root"));
    auto d2 = signed_delta("create_node", "c-2", child_node("c-2", "root"));
    auto d3 = signed_delta("create_node", "c-3", child_node("c-3", "root"));
    auto rec_for = [](const tree::TreeDelta& d, uint64_t position, const std::string& hash) {
        storage::FileStorageService::RetainedDelta rec;
        rec.position = position;
        rec.record_hash = hash;
        rec.operation = d.operation;
        rec.target_node_id = d.target_node_id;
        rec.data = json(d.node_data).dump();
        rec.signer_pubkey = d.signer_pubkey;
        rec.signature = d.signature;
        rec.timestamp = d.timestamp;
        return rec;
    };

    auto& a = make_node(
        "a",
        [&](Node& n) {
            const auto g = "00112233445566778899aabbccddeeff";
            ASSERT_TRUE(n.storage->write_pool_generation(g));
            ASSERT_EQ(n.storage->write_pool_record(
                hash_of(d1), rec_for(d1, 1, hash_of(d1)).to_json()),
              storage::FileStorageService::PoolWrite::Ok);
            ASSERT_EQ(n.storage->write_pool_record(
                hash_of(d2), rec_for(d2, 2, hash_of(d2)).to_json()),
              storage::FileStorageService::PoolWrite::Ok);
            ASSERT_EQ(n.storage->write_pool_record(
                hash_of(d3), rec_for(d3, 3, hash_of(d3)).to_json()),
              storage::FileStorageService::PoolWrite::Ok);
        });

    // The cap is applied before any content is read: 2 < 3 records -> the pool
    // is unavailable and new retention is refused; files untouched.
    // A fresh service over the retained storage performs the bounded
    // reconstruction under the 2-record cap.
    respawn_gossip(a, [](gossip::GossipService& g) {
        gossip::GossipBallotTestAccess::set_pool_max_records(g, 2);
    });
    EXPECT_FALSE(gossip::GossipBallotTestAccess::pool_available(*a.gossip));
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*a.gossip), 0u);
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_latest(*a.gossip), 0u);

    auto d4 = signed_delta("create_node", "c-4", child_node("c-4", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d4));
    EXPECT_TRUE(a.tree->get_node("c-4").has_value());
    EXPECT_FALSE(a.gossip->retain_local_delta(rec_for(d4, 0, hash_of(d4))));
    // The three pre-placed files are still on disk.
    EXPECT_EQ(a.pool_files().size(), 3u);
}

TEST_F(DeltaTransferTest, MissingGenerationWithRecordsMakesThePoolUnavailable) {
    auto d1 = signed_delta("create_node", "c-1", child_node("c-1", "root"));
    storage::FileStorageService::RetainedDelta rec;
    rec.position = 1;
    rec.record_hash = hash_of(d1);
    rec.operation = d1.operation;
    rec.target_node_id = d1.target_node_id;
    rec.data = json(d1.node_data).dump();
    rec.signer_pubkey = d1.signer_pubkey;
    rec.signature = d1.signature;
    rec.timestamp = d1.timestamp;

    auto& a = make_node("a", [&](Node& n) {
        ASSERT_EQ(n.storage->write_pool_record(hash_of(d1), rec.to_json()),
          storage::FileStorageService::PoolWrite::Ok);
    });
    // Records exist but no generation metadata: incomplete reconstruction.
    EXPECT_FALSE(gossip::GossipBallotTestAccess::pool_available(*a.gossip));
    EXPECT_EQ(a.pool_files().size(), 1u);
}

TEST_F(DeltaTransferTest, PositionDuplicationMakesThePoolUnavailable) {
    auto d1 = signed_delta("create_node", "c-1", child_node("c-1", "root"));
    auto d2 = signed_delta("create_node", "c-2", child_node("c-2", "root"));
    auto rec_for = [&](const tree::TreeDelta& d, const std::string& hash) {
        storage::FileStorageService::RetainedDelta rec;
        rec.position = 1;  // duplicated
        rec.record_hash = hash;
        rec.operation = d.operation;
        rec.target_node_id = d.target_node_id;
        rec.data = json(d.node_data).dump();
        rec.signer_pubkey = d.signer_pubkey;
        rec.signature = d.signature;
        rec.timestamp = d.timestamp;
        return rec;
    };
    auto& a = make_node("a", [&](Node& n) {
        ASSERT_TRUE(n.storage->write_pool_generation("00112233445566778899aabbccddeeff"));
        ASSERT_EQ(n.storage->write_pool_record(
            hash_of(d1), rec_for(d1, hash_of(d1)).to_json()),
          storage::FileStorageService::PoolWrite::Ok);
        ASSERT_EQ(n.storage->write_pool_record(
            hash_of(d2), rec_for(d2, hash_of(d2)).to_json()),
          storage::FileStorageService::PoolWrite::Ok);
    });
    EXPECT_FALSE(gossip::GossipBallotTestAccess::pool_available(*a.gossip));
    EXPECT_EQ(a.pool_files().size(), 2u);
}

TEST_F(DeltaTransferTest, OversizedRecordIsRefusedBeforeReadThenTrim) {
    auto& a = make_node("a");
    // node_data above the per-record bound.
    const std::string blob(gossip::GossipService::kMaxRetainedRecordBytes + 1, 'x');
    auto d = signed_delta("create_node", "big", child_node("big", "root", blob));
    ASSERT_TRUE(a.tree->apply_delta(d));
    EXPECT_TRUE(a.tree->get_node("big").has_value());
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*a.gossip), 0u);
    EXPECT_TRUE(a.pool_files().empty());
}

// ---------------------------------------------------------------------------
// (3) Transport identity gates
// ---------------------------------------------------------------------------

TEST_F(DeltaTransferTest, DigestFromUncertifiedPeerAllocatesNothingAndRequestsNothing) {
    auto root_kp = kc->ed25519_keygen();
    auto stranger = kc->ed25519_keygen();
    auto& a = make_node("a", {}, [&](Node& n) {
        n.gossip->set_root_pubkey(root_kp.public_key);
        n.gossip->set_network_id(kTestNetworkHex);
    });
    // Give the recipient a pool that would be worth requesting, if anything
    // were processed at all.
    auto d = signed_delta("create_node", "child-1", child_node("child-1", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d));

    // A digest signed by the stranger, claiming to be a rich pool.
    json digest;
    digest["latest_pos"] = 1;
    digest["log_generation"] = "ffffffffffffffffffffffffffffffff";
    digest["peer_count"] = 1;
    digest["timestamp"] = 1000;
    inject(build_packet(stranger, gossip::GossipMsgType::Digest, bytes_of(digest.dump())), a);
    pump_for(std::chrono::milliseconds(300));

    const auto stranger_b64 = crypto::to_base64(stranger.public_key);
    EXPECT_FALSE(gossip::GossipBallotTestAccess::has_log(*a.gossip, stranger_b64))
        << "an uncertified digest must allocate no transfer state";
    EXPECT_FALSE(gossip::GossipBallotTestAccess::has_outstanding(*a.gossip, stranger_b64))
        << "an uncertified digest must trigger no request";
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*a.gossip), 1u);
}

TEST_F(DeltaTransferTest, DeltaRequestFromUncertifiedPeerReturnsNoData) {
    auto root_kp = kc->ed25519_keygen();
    auto stranger = kc->ed25519_keygen();
    auto& a = make_node("a", {}, [&](Node& n) {
        n.gossip->set_root_pubkey(root_kp.public_key);
        n.gossip->set_network_id(kTestNetworkHex);
    });
    auto d = signed_delta("create_node", "child-1", child_node("child-1", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d));

    // A request from the stranger's own socket; a response would be answerable
    // on it.
    udp::socket raw{io, udp::endpoint{udp::v4(), 0}};
    json request;
    request["nonce"] = 7;
    request["from_pos"] = 0;
    raw.send_to(
        asio::buffer(build_packet(stranger, gossip::GossipMsgType::DeltaRequest,
                                  bytes_of(request.dump()))),
        a.udp_endpoint());
    pump_for(std::chrono::milliseconds(300));

    // Nothing was sent back (no datagram is pending on the requester's
    // socket).
    EXPECT_EQ(raw.available(), 0u) << "an uncertified delta request must receive no data";
}

TEST_F(DeltaTransferTest, DeltaResponseFromUncertifiedPeerIsDropped) {
    auto root_kp = kc->ed25519_keygen();
    auto stranger = kc->ed25519_keygen();
    auto& a = make_node("a", {}, [&](Node& n) {
        n.gossip->set_root_pubkey(root_kp.public_key);
        n.gossip->set_network_id(kTestNetworkHex);
    });
    auto d = signed_delta("create_node", "child-1", child_node("child-1", "root"));

    json response;
    response["nonce"] = 1;
    response["from_pos"] = 0;
    response["generation"] = "00112233445566778899aabbccddeeff";
    response["latest_pos"] = 1;
    response["complete"] = true;
    auto rec = record_json(d);
    rec["position"] = 1;
    response["records"] = json::array({rec});
    inject(build_packet(stranger, gossip::GossipMsgType::DeltaResponse,
                        bytes_of(response.dump())),
           a);
    pump_for(std::chrono::milliseconds(300));

    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*a.gossip), 0u);
}

// ---------------------------------------------------------------------------
// (4) End-to-end bounded transfer over the real sockets
// ---------------------------------------------------------------------------

TEST_F(DeltaTransferTest, EndToEndDigestDrivesBoundedPageTransfer) {
    auto root_kp = kc->ed25519_keygen();
    auto& a = make_node("a");
    auto& b = make_node("b");
    make_certified_pair(a, b, root_kp);
    const auto a_b64 = a.pubkey_b64();

    // `a` applies three signed records locally; they land in its pool.
    auto d1 = signed_delta("create_node", "c-1", child_node("c-1", "root"));
    auto d2 = signed_delta("create_node", "c-2", child_node("c-2", "root"));
    auto d3 = signed_delta("create_node", "c-3", child_node("c-3", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d1));
    ASSERT_TRUE(a.tree->apply_delta(d2));
    ASSERT_TRUE(a.tree->apply_delta(d3));
    ASSERT_EQ(gossip::GossipBallotTestAccess::pool_latest(*a.gossip), 3u);

    // The digest drives the transfer.
    inject(build_packet(a.keypair(), gossip::GossipMsgType::Digest, digest_bytes(a)), b);
    ASSERT_TRUE(pump_until([&] {
        return gossip::GossipBallotTestAccess::pool_record_count(*b.gossip) == 3u;
    }, std::chrono::seconds(5)));

    // `b` retained the ORIGINAL author fields, at positions 1..3.
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_latest(*b.gossip), 3u);
    EXPECT_EQ(gossip::GossipBallotTestAccess::cursor_of(*b.gossip, a_b64), 3u);
    auto files = b.pool_files();
    ASSERT_EQ(files.size(), 3u);
    for (const auto& [hash, text] : files) {
        auto r = json::parse(text);
        EXPECT_EQ(r["signer_pubkey"].get<std::string>(), author_pubkey)
            << "retained records must carry the original author, not the forwarder";
        EXPECT_EQ(r["record_hash"].get<std::string>(), hash);
    }
    // Retention is transfer only: none of the records is applied to b's tree.
    EXPECT_FALSE(b.tree->get_node("c-1").has_value());
    EXPECT_FALSE(b.tree->get_node("c-2").has_value());
    EXPECT_FALSE(b.tree->get_node("c-3").has_value());

    // No outstanding request is left dangling.
    EXPECT_FALSE(gossip::GossipBallotTestAccess::has_outstanding(*b.gossip, a_b64));
}

TEST_F(DeltaTransferTest, PageBoundSplitsTransferIntoContinuedRequests) {
    auto root_kp = kc->ed25519_keygen();
    auto& a = make_node("a");
    auto& b = make_node("b");
    make_certified_pair(a, b, root_kp);
    const auto a_b64 = a.pubkey_b64();

    // 150 records: more than one page.
    const int kRecords = 150;
    for (int i = 0; i < kRecords; ++i) {
        auto d = signed_delta("create_node", "c-" + std::to_string(i),
                              child_node("c-" + std::to_string(i), "root"));
        ASSERT_TRUE(a.tree->apply_delta(d));
    }
    ASSERT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*a.gossip),
              static_cast<uint64_t>(kRecords));

    inject(build_packet(a.keypair(), gossip::GossipMsgType::Digest, digest_bytes(a)), b);
    ASSERT_TRUE(pump_until(
        [&] { return gossip::GossipBallotTestAccess::pool_record_count(*b.gossip) ==
                    static_cast<uint64_t>(kRecords); },
        std::chrono::seconds(10)));
    EXPECT_EQ(gossip::GossipBallotTestAccess::cursor_of(*b.gossip, a_b64),
              static_cast<uint64_t>(kRecords));
}

TEST_F(DeltaTransferTest, DuplicateRecordIsIdempotentAndAdvancesTheCursor) {
    auto root_kp = kc->ed25519_keygen();
    auto& a = make_node("a");
    auto& b = make_node("b");
    make_certified_pair(a, b, root_kp);
    const auto a_b64 = a.pubkey_b64();

    // The SAME record is applied locally on both nodes (identical statement).
    auto d = signed_delta("create_node", "c-1", child_node("c-1", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d));
    ASSERT_TRUE(b.tree->apply_delta(d));
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*b.gossip), 1u);

    inject(build_packet(a.keypair(), gossip::GossipMsgType::Digest, digest_bytes(a)), b);
    pump_for(std::chrono::milliseconds(500));

    // The served duplicate advances the cursor to the peer's latest position
    // without creating a second file.
    EXPECT_EQ(gossip::GossipBallotTestAccess::cursor_of(*b.gossip, a_b64), 1u);
    EXPECT_EQ(b.pool_files().size(), 1u);
}

TEST_F(DeltaTransferTest, ResponseBindsToOutstandingRequestOrIsDropped) {
    auto root_kp = kc->ed25519_keygen();
    auto& a = make_node("a");
    auto& b = make_node("b");
    make_certified_pair(a, b, root_kp);
    const auto a_b64 = a.pubkey_b64();

    auto d1 = signed_delta("create_node", "c-1", child_node("c-1", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d1));
    auto rec1 = record_json(d1);
    rec1["position"] = 1;

    // (a) Unsolicited: no outstanding request on `b` -> dropped, nothing
    // retained.
    json response;
    response["nonce"] = 123;
    response["from_pos"] = 0;
    response["generation"] = gossip::GossipBallotTestAccess::pool_generation(*a.gossip);
    response["latest_pos"] = 1;
    response["complete"] = true;
    response["records"] = json::array({rec1});
    inject(build_packet(a.keypair(), gossip::GossipMsgType::DeltaResponse,
                        bytes_of(response.dump())),
           b);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*b.gossip), 0u);

    // (b) Real transfer: the digest drives `b` to request, `a` serves record 1.
    inject(build_packet(a.keypair(), gossip::GossipMsgType::Digest, digest_bytes(a)), b);
    ASSERT_TRUE(pump_until([&] {
        return gossip::GossipBallotTestAccess::pool_record_count(*b.gossip) == 1u;
    }, std::chrono::seconds(5)));
    EXPECT_EQ(gossip::GossipBallotTestAccess::cursor_of(*b.gossip, a_b64), 1u);

    // (c) Stale content must never be retained and must not break the session:
    // a second record lands on `a`, the digest drives a new request, and —
    // while that request is in flight — a crafted answer with a WRONG nonce
    // offers a record that `a` never held. Whatever the interleaving, the
    // crafted record is dropped (no outstanding slot binds to it) and the
    // genuine request completes.
    auto d2 = signed_delta("create_node", "c-2", child_node("c-2", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d2));
    auto stranger_rec = record_json(signed_delta("create_node", "evil",
                                                  child_node("evil", "root")));
    stranger_rec["position"] = 2;
    response["records"] = json::array({stranger_rec});
    inject(build_packet(a.keypair(), gossip::GossipMsgType::Digest, digest_bytes(a)), b);
    // The digest drives a real request; the stale answer is in flight
    // alongside whatever `a` sends. Whichever binds first, the crafted
    // record cannot bind: its nonce is the one from step (a).
    inject(build_packet(a.keypair(), gossip::GossipMsgType::DeltaResponse,
                        bytes_of(response.dump())),
           b);

    ASSERT_TRUE(pump_until([&] {
        return gossip::GossipBallotTestAccess::pool_record_count(*b.gossip) == 2u;
    }, std::chrono::seconds(5)));
    EXPECT_EQ(gossip::GossipBallotTestAccess::cursor_of(*b.gossip, a_b64), 2u);
    // The crafted record was never retained.
    const auto evil_hash = hash_of(signed_delta("create_node", "evil",
                                                 child_node("evil", "root")));
    EXPECT_EQ(b.storage->pool_record_exists(evil_hash), false)
        << "a non-binding response must not retain its records";
}

TEST_F(DeltaTransferTest, LateResponseAfterGenerationChangeIsDropped) {
    auto root_kp = kc->ed25519_keygen();
    auto& a = make_node("a");
    auto& b = make_node("b");
    make_certified_pair(a, b, root_kp);
    const auto a_b64 = a.pubkey_b64();

    auto d = signed_delta("create_node", "c-1", child_node("c-1", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d));
    const auto gen1 = gossip::GossipBallotTestAccess::pool_generation(*a.gossip);

    // A digest under generation 1 gives `b` a live view of `a`'s log.
    // Capture the request `b` actually issues so the late answer below
    // matches its nonce and position EXACTLY: the only mismatch is the
    // generation, and no unrelated field difference can explain a pass.
    inject(build_packet(a.keypair(), gossip::GossipMsgType::Digest, digest_bytes(a)), b);
    ASSERT_TRUE(pump_until([&] {
        return gossip::GossipBallotTestAccess::has_outstanding(*b.gossip, a_b64);
    }, std::chrono::seconds(5)));
    std::uint64_t cap_nonce = 0, cap_from_pos = 0;
    std::string cap_generation;
    ASSERT_TRUE(gossip::GossipBallotTestAccess::outstanding_info(
        *b.gossip, a_b64, cap_nonce, cap_from_pos, cap_generation));
    ASSERT_EQ(cap_generation, gen1);
    // Let the captured request complete so the session settles.
    pump_for(std::chrono::milliseconds(400));

    // A new log generation: `b` must reset the cursor and drop any
    // outstanding request.
    json gen2_digest;
    gen2_digest["latest_pos"] = 1;
    gen2_digest["log_generation"] = "ffffffffffffffffffffffffffffffff";
    gen2_digest["peer_count"] = 1;
    gen2_digest["timestamp"] = 1001;
    inject(build_packet(a.keypair(), gossip::GossipMsgType::Digest,
                        bytes_of(gen2_digest.dump())),
           b);
    pump_for(std::chrono::milliseconds(200));
    // The superseded request is gone: the cursor is back at 0 (any new
    // outstanding request is from the reset position under the new
    // generation, which the late answer below must not satisfy).
    EXPECT_EQ(gossip::GossipBallotTestAccess::cursor_of(*b.gossip, a_b64), 0u)
        << "a generation change must reset the cursor";
    const auto count_before =
        gossip::GossipBallotTestAccess::pool_record_count(*b.gossip);

    // Now a LATE answer from the superseded generation arrives, carrying
    // the exact nonce and position of the captured request: it must be
    // dropped — no retention, no cursor movement.
    auto rec = record_json(d);
    rec["position"] = cap_from_pos + 1;
    json response;
    response["nonce"] = cap_nonce;
    response["from_pos"] = cap_from_pos;
    response["generation"] = gen1;
    response["latest_pos"] = 1;
    response["complete"] = true;
    response["records"] = json::array({rec});
    inject(build_packet(a.keypair(), gossip::GossipMsgType::DeltaResponse,
                        bytes_of(response.dump())),
           b);
    pump_for(std::chrono::milliseconds(400));
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*b.gossip),
              count_before)
        << "a late response from a superseded generation must not retain";
    EXPECT_EQ(gossip::GossipBallotTestAccess::cursor_of(*b.gossip, a_b64), 0u)
        << "a late response from a superseded generation must not move the cursor";
}

// ---------------------------------------------------------------------------
// (5) Bounded transfer failure: gaps and incomplete pages
// ---------------------------------------------------------------------------

TEST_F(DeltaTransferTest, UnservableRecordStopsThePageAndTheCursor) {
    auto root_kp = kc->ed25519_keygen();
    auto& a = make_node("a");
    auto& b = make_node("b");
    make_certified_pair(a, b, root_kp);
    const auto a_b64 = a.pubkey_b64();

    // Three records; corrupt the middle file so position 2 is unservable.
    auto d1 = signed_delta("create_node", "c-1", child_node("c-1", "root"));
    auto d2 = signed_delta("create_node", "c-2", child_node("c-2", "root"));
    auto d3 = signed_delta("create_node", "c-3", child_node("c-3", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d1));
    ASSERT_TRUE(a.tree->apply_delta(d2));
    ASSERT_TRUE(a.tree->apply_delta(d3));
    corrupt_pool_record(a, hash_of(d2), "garbage-not-json");

    inject(build_packet(a.keypair(), gossip::GossipMsgType::Digest, digest_bytes(a)), b);
    pump_for(std::chrono::milliseconds(700));

    // The page served position 1 and stopped at 2: `b` retained exactly one
    // record, the cursor advanced to 1, and position 3 was never served over
    // the gap.
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*b.gossip), 1u);
    EXPECT_EQ(gossip::GossipBallotTestAccess::cursor_of(*b.gossip, a_b64), 1u);
    for (const auto& [hash, text] : b.pool_files()) {
        EXPECT_NE(hash, hash_of(d2));
        EXPECT_NE(hash, hash_of(d3))
            << "records beyond an unservable position must not be served over it";
    }
}

TEST_F(DeltaTransferTest, RepeatedIncompletePagesExhaustTheStallBudgetAndBackOff) {
    auto root_kp = kc->ed25519_keygen();
    auto& a = make_node("a");
    auto& b = make_node("b");
    make_certified_pair(a, b, root_kp);
    const auto a_b64 = a.pubkey_b64();

    // Make EVERY page from `a` fail at its first position.
    auto d1 = signed_delta("create_node", "c-1", child_node("c-1", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d1));
    corrupt_pool_record(a, hash_of(d1), "garbage");

    // Drive the transfer repeatedly: each digest yields a failed page, and
    // after the stall budget the requester must enter backoff and stop
    // requesting.
    for (int i = 0; i < static_cast<int>(gossip::GossipService::kStallBudget) + 1; ++i) {
        inject(build_packet(a.keypair(), gossip::GossipMsgType::Digest, digest_bytes(a)), b);
        pump_for(std::chrono::milliseconds(400));
    }
    EXPECT_EQ(gossip::GossipBallotTestAccess::cursor_of(*b.gossip, a_b64), 0u);
    EXPECT_TRUE(gossip::GossipBallotTestAccess::backoff_until(*b.gossip, a_b64) > 0)
        << "repeated transfer failure must exhaust the stall budget into backoff";

    // A further digest while in backoff issues no request.
    inject(build_packet(a.keypair(), gossip::GossipMsgType::Digest, digest_bytes(a)), b);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_FALSE(gossip::GossipBallotTestAccess::has_outstanding(*b.gossip, a_b64));
}

// ---------------------------------------------------------------------------
// (6) Backoff survives generation changes; eviction cannot bypass it
// ---------------------------------------------------------------------------

TEST_F(DeltaTransferTest, BackoffSurvivesGenerationChangeAndEviction) {
    auto root_kp = kc->ed25519_keygen();
    auto stranger = kc->ed25519_keygen();
    auto& a = make_node("a");
    auto& b = make_node("b");
    make_certified_pair(a, b, root_kp);
    const auto a_b64 = a.pubkey_b64();

    // Put `b` in backoff toward `a` (every page fails at its first position).
    auto d1 = signed_delta("create_node", "c-1", child_node("c-1", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d1));
    corrupt_pool_record(a, hash_of(d1), "garbage");
    for (int i = 0; i < static_cast<int>(gossip::GossipService::kStallBudget) + 1; ++i) {
        inject(build_packet(a.keypair(), gossip::GossipMsgType::Digest, digest_bytes(a)), b);
        pump_for(std::chrono::milliseconds(400));
    }
    const auto backoff = gossip::GossipBallotTestAccess::backoff_until(*b.gossip, a_b64);
    ASSERT_GT(backoff, 0u);

    // (a) A new generation from `a` does not reset the backoff.
    json gen2;
    gen2["latest_pos"] = 1;
    gen2["log_generation"] = "ffffffffffffffffffffffffffffffff";
    gen2["peer_count"] = 1;
    gen2["timestamp"] = 2000;
    inject(build_packet(a.keypair(), gossip::GossipMsgType::Digest, bytes_of(gen2.dump())), b);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_TRUE(gossip::GossipBallotTestAccess::backoff_until(*b.gossip, a_b64) >= backoff)
        << "a generation change must not reset an exhausted retry budget";
    EXPECT_FALSE(gossip::GossipBallotTestAccess::has_outstanding(*b.gossip, a_b64));

    // (b) Eviction cannot bypass it: with the peer log capped at one, a new
    // peer's digest cannot evict `a`'s backoff entry.
    gossip::GossipBallotTestAccess::set_peer_log_cap(*b.gossip, 1);
    const auto stranger_b64 = crypto::to_base64(stranger.public_key);
    json s3;
    s3["latest_pos"] = 1;
    s3["log_generation"] = "abcdefabcdefabcdefabcdefabcdefab";
    s3["peer_count"] = 1;
    s3["timestamp"] = 2001;
    inject(build_packet(stranger, gossip::GossipMsgType::Digest, bytes_of(s3.dump())), b);
    pump_for(std::chrono::milliseconds(300));
    EXPECT_TRUE(gossip::GossipBallotTestAccess::has_log(*b.gossip, a_b64))
        << "an entry in backoff must not be evicted";
    EXPECT_TRUE(gossip::GossipBallotTestAccess::backoff_until(*b.gossip, a_b64) >= backoff);
    EXPECT_FALSE(gossip::GossipBallotTestAccess::has_log(*b.gossip, stranger_b64))
        << "new state must be refused while nothing is evictable";
}

// ---------------------------------------------------------------------------
// (7) Admission: final vs retryable refusals
// ---------------------------------------------------------------------------

TEST_F(DeltaTransferTest, MalformedRecordIsFinalAndAdvancesTheCursor) {
    // Deterministic wire case: `b` is not cert-verified by `a`, so `a`
    // serves no real page; the only answer `b` gets is the crafted one,
    // which binds to `b`'s own outstanding request. One record is valid,
    // the next has malformed statement fields: it must be refused (final)
    // and the cursor must advance past it.
    auto root_kp = kc->ed25519_keygen();
    auto& a = make_node("a");
    auto& b = make_node("b");
    a.gossip->set_root_pubkey(root_kp.public_key);
    b.gossip->set_root_pubkey(root_kp.public_key);
    a.gossip->set_network_id(kTestNetworkHex);
    b.gossip->set_network_id(kTestNetworkHex);
    a.gossip->do_add_peer(b.endpoint(), b.pubkey_b64());
    b.gossip->do_add_peer(a.endpoint(), a.pubkey_b64());
    // Only the a -> b hello: `b` trusts `a`, `a` does not trust `b`.
    {
        auto cert = issue_cert(a.pubkey_b64(), "srv-" + std::to_string(a.port()), root_kp);
        json h = json::parse(cert);
        h["is_response"] = false;
        inject(build_packet(a.keypair(), gossip::GossipMsgType::ServerHello,
                            bytes_of(h.dump())),
               b);
    }
    pump_for(std::chrono::milliseconds(200));
    ASSERT_TRUE(b.certified_peer(a.pubkey_b64()));
    ASSERT_FALSE(a.certified_peer(b.pubkey_b64()));

    auto d1 = signed_delta("create_node", "c-1", child_node("c-1", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d1));
    const auto a_b64 = a.pubkey_b64();

    // The digest drives `b` to request; `a` denies the uncertified request,
    // so the outstanding stays live.
    inject(build_packet(a.keypair(), gossip::GossipMsgType::Digest, digest_bytes(a)), b);
    ASSERT_TRUE(pump_until([&] {
        return gossip::GossipBallotTestAccess::has_outstanding(*b.gossip, a_b64);
    }, std::chrono::seconds(5)));

    uint64_t nonce = 0, from_pos = 0;
    std::string generation;
    ASSERT_TRUE(gossip::GossipBallotTestAccess::outstanding_info(
        *b.gossip, a_b64, nonce, from_pos, generation));

    // Crafted answer: the valid record at position 1, then a malformed
    // statement at position 2.
    auto valid = record_json(d1);
    valid["position"] = from_pos + 1;
    json malformed = json::object();
    malformed["position"] = from_pos + 2;
    malformed["operation"] = "create_node";
    json response;
    response["nonce"] = nonce;
    response["from_pos"] = from_pos;
    response["generation"] = generation;
    response["latest_pos"] = from_pos + 2;
    response["complete"] = true;
    response["records"] = json::array({valid, malformed});
    inject(build_packet(a.keypair(), gossip::GossipMsgType::DeltaResponse,
                        bytes_of(response.dump())),
           b);
    pump_for(std::chrono::milliseconds(400));

    // The valid record was retained; the malformed one was refused (final)
    // and the cursor advanced past it. The request was consumed.
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*b.gossip), 1u);
    EXPECT_EQ(gossip::GossipBallotTestAccess::cursor_of(*b.gossip, a_b64), from_pos + 2);
    EXPECT_FALSE(gossip::GossipBallotTestAccess::has_outstanding(*b.gossip, a_b64));
}

TEST_F(DeltaTransferTest, RetentionRefusalIsRetryableAndStopsTheCursor) {
    auto root_kp = kc->ed25519_keygen();
    auto& a = make_node("a");
    auto& b = make_node("b");
    make_certified_pair(a, b, root_kp);
    const auto a_b64 = a.pubkey_b64();

    auto d = signed_delta("create_node", "c-1", child_node("c-1", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d));

    // Exhaust `b`'s pool byte budget before the transfer.
    gossip::GossipBallotTestAccess::set_pool_max_bytes(*b.gossip, 1);

    inject(build_packet(a.keypair(), gossip::GossipMsgType::Digest, digest_bytes(a)), b);
    pump_for(std::chrono::milliseconds(700));

    // The record is refused retryably: no retention, no cursor advance, and
    // the retry loop must stall (not loop forever within the pump window).
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*b.gossip), 0u);
    EXPECT_EQ(gossip::GossipBallotTestAccess::cursor_of(*b.gossip, a_b64), 0u);
}

TEST_F(DeltaTransferTest, MissingPermissionContextIsRetryableNotFinal) {
    // `b` has NO tree: every received record is refused retryably. One-way
    // certification (`b` trusts `a`, not vice versa) keeps `a` from serving
    // a real page, so the crafted answer is the only one that binds.
    auto root_kp = kc->ed25519_keygen();
    auto& a = make_node("a");
    auto b = std::make_unique<Node>();
    b->dir = root / "b";
    fs::create_directories(b->dir);
    b->crypto = std::make_unique<crypto::SodiumCryptoService>();
    b->crypto->start();
    b->storage = std::make_unique<storage::FileStorageService>(b->dir);
    b->storage->start();
    b->gossip = std::make_unique<gossip::GossipService>(io, 0, *b->storage, *b->crypto);
    b->gossip->start();
    nodes.push_back(std::move(b));
    auto& bn = *nodes.back();
    a.gossip->set_root_pubkey(root_kp.public_key);
    bn.gossip->set_root_pubkey(root_kp.public_key);
    a.gossip->set_network_id(kTestNetworkHex);
    bn.gossip->set_network_id(kTestNetworkHex);
    a.gossip->do_add_peer(bn.endpoint(), bn.pubkey_b64());
    bn.gossip->do_add_peer(a.endpoint(), a.pubkey_b64());
    {
        auto cert = issue_cert(a.pubkey_b64(), "srv-" + std::to_string(a.port()), root_kp);
        json h = json::parse(cert);
        h["is_response"] = false;
        inject(build_packet(a.keypair(), gossip::GossipMsgType::ServerHello,
                            bytes_of(h.dump())),
               bn);
    }
    pump_for(std::chrono::milliseconds(200));
    ASSERT_TRUE(bn.certified_peer(a.pubkey_b64()));
    ASSERT_FALSE(a.certified_peer(bn.pubkey_b64()));
    const auto a_b64 = a.pubkey_b64();

    auto d = signed_delta("create_node", "c-1", child_node("c-1", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d));

    // The digest drives a real outstanding request; `a` denies it (b is not
    // certified by a), so the request stays live.
    inject(build_packet(a.keypair(), gossip::GossipMsgType::Digest, digest_bytes(a)), bn);
    ASSERT_TRUE(pump_until([&] {
        return gossip::GossipBallotTestAccess::has_outstanding(*bn.gossip, a_b64);
    }, std::chrono::seconds(5)));
    uint64_t nonce = 0, from_pos = 0;
    std::string generation;
    ASSERT_TRUE(gossip::GossipBallotTestAccess::outstanding_info(
        *bn.gossip, a_b64, nonce, from_pos, generation));

    // The valid record, answered by `a`.
    auto rec = record_json(d);
    rec["position"] = from_pos + 1;
    json response;
    response["nonce"] = nonce;
    response["from_pos"] = from_pos;
    response["generation"] = generation;
    response["latest_pos"] = from_pos + 1;
    response["complete"] = true;
    response["records"] = json::array({rec});
    inject(build_packet(a.keypair(), gossip::GossipMsgType::DeltaResponse,
                        bytes_of(response.dump())),
           bn);
    pump_for(std::chrono::milliseconds(500));

    // Refused retryably: nothing retained, and the cursor did not advance —
    // the record is eligible for retry once context exists.
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*bn.gossip), 0u);
    EXPECT_EQ(gossip::GossipBallotTestAccess::cursor_of(*bn.gossip, a_b64), 0u);
}

// ---------------------------------------------------------------------------
// (9) Incoming page hardening
// ---------------------------------------------------------------------------

// The receive side enforces the page bounds itself. Both oversized shapes
// must drop before any binding or retention: the outstanding request stays
// live, nothing is retained, and the cursor does not move.
TEST_F(DeltaTransferTest, PageBoundsAreEnforcedOnReceipt) {
    auto root_kp = kc->ed25519_keygen();
    auto& a = make_node("a");
    auto& b = make_node("b");
    make_certified_pair(a, b, root_kp);
    const auto a_b64 = a.pubkey_b64();

    auto d1 = signed_delta("create_node", "c-1", child_node("c-1", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d1));
    auto rec = record_json(d1);
    rec["position"] = 1;

    // A live request with a captured nonce: the hostile pages below must
    // not consume it.
    inject(build_packet(a.keypair(), gossip::GossipMsgType::Digest, digest_bytes(a)), b);
    ASSERT_TRUE(pump_until([&] {
        return gossip::GossipBallotTestAccess::has_outstanding(*b.gossip, a_b64);
    }, std::chrono::seconds(5)));
    std::uint64_t nonce = 0, from_pos = 0;
    std::string generation;
    ASSERT_TRUE(gossip::GossipBallotTestAccess::outstanding_info(
        *b.gossip, a_b64, nonce, from_pos, generation));
    // Let the real answer settle first so only the crafted pages are in play.
    pump_for(std::chrono::milliseconds(600));
    const auto count_after_real =
        gossip::GossipBallotTestAccess::pool_record_count(*b.gossip);

    // (a) Payload above the 60,000-byte receive bound.
    {
        json page;
        page["nonce"] = nonce;
        page["from_pos"] = from_pos;
        page["generation"] = generation;
        page["latest_pos"] = 1;
        page["complete"] = true;
        page["records"] = json::array();
        page["pad"] = std::string(61000, 'x');
        const auto big = bytes_of(page.dump());
        ASSERT_GT(big.size(), 60000u);
        inject(build_packet(a.keypair(), gossip::GossipMsgType::DeltaResponse, big), b);
        pump_for(std::chrono::milliseconds(400));
    }
    // (b) More than 100 records in one page.
    {
        json page;
        page["nonce"] = nonce;
        page["from_pos"] = from_pos;
        page["generation"] = generation;
        page["latest_pos"] = 101;
        page["complete"] = true;
        json arr = json::array();
        for (int i = 0; i < 101; ++i) {
            // Minimal bodies: the record count is rejected before any
            // per-record parsing, and the datagram must stay within the
            // kernel size limit.
            arr.push_back(json{{"position", from_pos + 1 + i}});
        }
        page["records"] = arr;
        inject(build_packet(a.keypair(), gossip::GossipMsgType::DeltaResponse,
                            bytes_of(page.dump())),
               b);
        pump_for(std::chrono::milliseconds(400));
    }

    // Neither hostile page retained anything or moved the cursor.
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*b.gossip),
              count_after_real);
    EXPECT_EQ(gossip::GossipBallotTestAccess::cursor_of(*b.gossip, a_b64),
              gossip::GossipBallotTestAccess::pool_latest(*b.gossip));
}

// Mistyped envelope and record fields are refused at the envelope stage:
// nlohmann value() would throw type_error on a present-but-mistyped field;
// the handler must refuse, not propagate.
TEST_F(DeltaTransferTest, MalformedEnvelopeFieldsAreDroppedNotThrown) {
    auto root_kp = kc->ed25519_keygen();
    auto& a = make_node("a");
    auto& b = make_node("b");
    // One-way certification: b trusts a, but a does not trust b, so a never
    // serves b and the crafted pages are the only responses that can bind to
    // b's outstanding request.
    a.gossip->set_root_pubkey(root_kp.public_key);
    a.gossip->set_network_id(kTestNetworkHex);
    b.gossip->set_root_pubkey(root_kp.public_key);
    b.gossip->set_network_id(kTestNetworkHex);
    a.gossip->do_add_peer(b.endpoint(), b.pubkey_b64());
    b.gossip->do_add_peer(a.endpoint(), a.pubkey_b64());
    {
        auto cert = issue_cert(a.pubkey_b64(),
                               "srv-" + std::to_string(a.port()), root_kp);
        json h = json::parse(cert);
        h["is_response"] = false;
        inject(build_packet(a.keypair(), gossip::GossipMsgType::ServerHello,
                            bytes_of(h.dump())),
               b);
    }
    pump_for(std::chrono::milliseconds(200));
    ASSERT_TRUE(b.certified_peer(a.pubkey_b64()));
    EXPECT_FALSE(a.certified_peer(b.pubkey_b64()));
    const auto a_b64 = a.pubkey_b64();

    // a advertises a non-empty log so b has something to request.
    auto d0 = signed_delta("create_node", "seed-1", child_node("seed-1", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d0));
    inject(build_packet(a.keypair(), gossip::GossipMsgType::Digest, digest_bytes(a)), b);
    ASSERT_TRUE(pump_until([&] {
        return gossip::GossipBallotTestAccess::has_outstanding(*b.gossip, a_b64);
    }, std::chrono::seconds(5)));
    std::uint64_t nonce = 0, from_pos = 0;
    std::string generation;
    ASSERT_TRUE(gossip::GossipBallotTestAccess::outstanding_info(
        *b.gossip, a_b64, nonce, from_pos, generation));
    pump_for(std::chrono::milliseconds(600));
    const auto count_before =
        gossip::GossipBallotTestAccess::pool_record_count(*b.gossip);

    auto send = [&](json page) {
        inject(build_packet(a.keypair(), gossip::GossipMsgType::DeltaResponse,
                            bytes_of(page.dump())),
               b);
        pump_for(std::chrono::milliseconds(250));
    };

    json base;
    base["nonce"] = nonce;
    base["from_pos"] = from_pos;
    base["generation"] = generation;
    base["latest_pos"] = 1;
    base["complete"] = true;
    base["records"] = json::array();

    json p = base; p["nonce"] = std::string("not-a-number"); send(p);
    p = base; p["from_pos"] = -3; send(p);
    p = base; p["latest_pos"] = true; send(p);
    p = base; p["generation"] = 42; send(p);
    p = base; p["complete"] = "yes"; send(p);
    p = base; p["records"] = json::array({json{{"position", "one"}}}); send(p);

    // The process is still alive, nothing was retained, and the cursor did
    // not move: every malformed page was refused, none escaped the
    // receive callback.
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*b.gossip),
              count_before);
    EXPECT_EQ(gossip::GossipBallotTestAccess::cursor_of(*b.gossip, a_b64),
              gossip::GossipBallotTestAccess::pool_latest(*b.gossip));
    // The real session can still make progress. Model the deadline expiry of
    // the unanswered request (production frees the slot at the deadline),
    // complete the certification so a serves b, and re-digest: the new
    // request binds to the genuine answer.
    gossip::GossipBallotTestAccess::drop_outstanding(*b.gossip, a_b64);
    {
        auto cert = issue_cert(b.pubkey_b64(),
                               "srv-" + std::to_string(b.port()), root_kp);
        json h = json::parse(cert);
        h["is_response"] = false;
        inject(build_packet(b.keypair(), gossip::GossipMsgType::ServerHello,
                            bytes_of(h.dump())),
               a);
    }
    pump_for(std::chrono::milliseconds(200));
    auto d2 = signed_delta("create_node", "c-2", child_node("c-2", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d2));
    inject(build_packet(a.keypair(), gossip::GossipMsgType::Digest, digest_bytes(a)), b);
    ASSERT_TRUE(pump_until([&] {
        // Both of a's records (seed-1 and c-2) arrive over the wire.
        return gossip::GossipBallotTestAccess::pool_record_count(*b.gossip) == 2u;
    }, std::chrono::seconds(5)));
}

// A response that arrives after the request deadline must change nothing:
// no retention, no cursor movement, and the expired slot is freed so a new
// request can be issued. The crafted page carries the EXACT captured
// nonce, position, and generation — only the deadline differs.
TEST_F(DeltaTransferTest, ExpiredRequestResponseChangesNothing) {
    auto root_kp = kc->ed25519_keygen();
    auto& a = make_node("a");
    auto& b = make_node("b");
    make_certified_pair(a, b, root_kp);
    const auto a_b64 = a.pubkey_b64();

    auto d1 = signed_delta("create_node", "c-1", child_node("c-1", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d1));
    auto rec = record_json(d1);

    // One-way: `a` does not certify `b`, so `a` never answers `b`'s
    // request and the captured request stays live to age out.
    a.gossip->set_root_pubkey(root_kp.public_key);
    b.gossip->set_root_pubkey(root_kp.public_key);
    a.gossip->set_network_id(kTestNetworkHex);
    b.gossip->set_network_id(kTestNetworkHex);
    a.gossip->do_add_peer(b.endpoint(), b.pubkey_b64());
    b.gossip->do_add_peer(a.endpoint(), a.pubkey_b64());
    {
        auto cert = issue_cert(a.pubkey_b64(), "srv-" + std::to_string(a.port()), root_kp);
        json h = json::parse(cert);
        h["is_response"] = false;
        inject(build_packet(a.keypair(), gossip::GossipMsgType::ServerHello,
                            bytes_of(h.dump())),
               b);
    }
    pump_for(std::chrono::milliseconds(200));

    inject(build_packet(a.keypair(), gossip::GossipMsgType::Digest, digest_bytes(a)), b);
    ASSERT_TRUE(pump_until([&] {
        return gossip::GossipBallotTestAccess::has_outstanding(*b.gossip, a_b64);
    }, std::chrono::seconds(5)));
    std::uint64_t nonce = 0, from_pos = 0;
    std::string generation;
    ASSERT_TRUE(gossip::GossipBallotTestAccess::outstanding_info(
        *b.gossip, a_b64, nonce, from_pos, generation));

    // Age the request out while the answer is "in flight".
    gossip::GossipBallotTestAccess::set_outstanding_deadline(*b.gossip, a_b64, 0);

    rec["position"] = from_pos + 1;
    json response;
    response["nonce"] = nonce;
    response["from_pos"] = from_pos;
    response["generation"] = generation;
    response["latest_pos"] = from_pos + 1;
    response["complete"] = true;
    response["records"] = json::array({rec});
    inject(build_packet(a.keypair(), gossip::GossipMsgType::DeltaResponse,
                        bytes_of(response.dump())),
           b);
    pump_for(std::chrono::milliseconds(400));

    // The exact-bound answer to an expired request changes nothing.
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*b.gossip), 0u);
    EXPECT_EQ(gossip::GossipBallotTestAccess::cursor_of(*b.gossip, a_b64), 0u);
    EXPECT_FALSE(gossip::GossipBallotTestAccess::has_outstanding(*b.gossip, a_b64))
        << "the expired slot must be freed";

    // The session recovers: a new digest issues a fresh request and the
    // same (now fresh-bound) page is retained.
    inject(build_packet(a.keypair(), gossip::GossipMsgType::Digest, digest_bytes(a)), b);
    ASSERT_TRUE(pump_until([&] {
        return gossip::GossipBallotTestAccess::has_outstanding(*b.gossip, a_b64);
    }, std::chrono::seconds(5)));
    std::uint64_t nonce2 = 0, from_pos2 = 0;
    std::string generation2;
    ASSERT_TRUE(gossip::GossipBallotTestAccess::outstanding_info(
        *b.gossip, a_b64, nonce2, from_pos2, generation2));
    response["nonce"] = nonce2;
    response["from_pos"] = from_pos2;
    response["generation"] = generation2;
    response["records"] = json::array({rec});
    inject(build_packet(a.keypair(), gossip::GossipMsgType::DeltaResponse,
                        bytes_of(response.dump())),
           b);
    pump_for(std::chrono::milliseconds(400));
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*b.gossip), 1u);
    EXPECT_EQ(gossip::GossipBallotTestAccess::cursor_of(*b.gossip, a_b64),
              from_pos2 + 1);
}

// A clean shutdown must not leave a re-arming receive behind: with a
// bounded deadline and handler budget the io context reaches quiescence,
// and no non-aborted receive error occurs on the closed socket.
TEST_F(DeltaTransferTest, StoppedServiceDoesNotRearmReceive) {
    auto& a = make_node("a");
    ASSERT_EQ(gossip::GossipBallotTestAccess::receive_error_count(*a.gossip), 0u);
    a.gossip->stop();

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    bool quiesced = false;
    std::uint64_t handlers = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        if (io.poll_one() > 0) {
            ++handlers;
            if (handlers > 1000) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        } else {
            quiesced = true;
            break;
        }
    }
    EXPECT_TRUE(quiesced)
        << "a re-arming receive chain never reaches quiescence";
    EXPECT_LE(handlers, 4u)
        << "only the aborted completion(s) may run after a clean stop";
    EXPECT_EQ(gossip::GossipBallotTestAccess::receive_error_count(*a.gossip), 0u)
        << "a closed socket must not produce non-aborted receive errors";
}

// ---------------------------------------------------------------------------
// (10) Pool position integrity and serve-time verification
// ---------------------------------------------------------------------------

// If the highest-position record is corrupt, its position cannot be
// reconstructed. The pool must be unavailable — the position must NOT be
// reused under the existing generation, the file must be preserved, and no
// shortened log may be published.
TEST_F(DeltaTransferTest, CorruptHighestPositionMakesPoolUnavailableAndBurnsThePosition) {
    auto& a = make_node("a");

    auto d1 = signed_delta("create_node", "c-1", child_node("c-1", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d1));
    auto d2 = signed_delta("create_node", "c-2", child_node("c-2", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d2));
    const auto hash1 = hash_of(d1);
    const auto hash2 = hash_of(d2);
    ASSERT_EQ(gossip::GossipBallotTestAccess::pool_latest(*a.gossip), 2u);

    // Corrupt the HIGHEST position (2). A shorter-log reconstruction would
    // assign the next record position 2 again.
    corrupt_pool_record(a, hash2, "corrupted beyond recovery");

    respawn_gossip(a);

    EXPECT_FALSE(gossip::GossipBallotTestAccess::pool_available(*a.gossip))
        << "an unreconstructable position must make the pool unavailable";

    // New retention is refused; the burned position is never reused.
    auto d3 = signed_delta("create_node", "c-3", child_node("c-3", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d3));
    EXPECT_FALSE(a.storage->pool_record_exists(hash_of(d3)))
        << "no new record may take the unreconstructable position";
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*a.gossip), 0u);
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_latest(*a.gossip), 0u);

    // Both files are preserved, untouched.
    auto kept = a.storage->read_pool_record(hash2, 1000, pool_read_result);
    ASSERT_TRUE(kept.has_value());
    EXPECT_EQ(*kept, "corrupted beyond recovery");
    auto kept1 = a.storage->read_pool_record(hash1, 1000, pool_read_result);
    ASSERT_TRUE(kept1.has_value());
    EXPECT_TRUE(kept1->find(R"("position":1)") != std::string::npos);
}

// A middle-position corruption also prevents complete reconstruction: the
// position gap cannot be proven, so the pool is unavailable too.
TEST_F(DeltaTransferTest, CorruptMiddlePositionAlsoMakesPoolUnavailable) {
    auto& a = make_node("a");

    auto d1 = signed_delta("create_node", "m-1", child_node("m-1", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d1));
    auto d2 = signed_delta("create_node", "m-2", child_node("m-2", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d2));
    auto d3 = signed_delta("create_node", "m-3", child_node("m-3", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d3));

    corrupt_pool_record(a, hash_of(d2), "corrupt-middle");
    respawn_gossip(a);
    EXPECT_FALSE(gossip::GossipBallotTestAccess::pool_available(*a.gossip));
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*a.gossip), 0u);

    // And retention stays refused.
    auto d4 = signed_delta("create_node", "m-4", child_node("m-4", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d4));
    EXPECT_FALSE(a.storage->pool_record_exists(hash_of(d4)));
}

// Serve-time verification: a record file that changed after reconstruction
// must not be served, even when the replacement is well-formed and signed.
// The page fails boundedly; nothing beyond the corruption is served and the
// index is not silently repaired.
TEST_F(DeltaTransferTest, ServingReverifiesContentAgainstTheIndex) {
    auto root_kp = kc->ed25519_keygen();
    auto& a = make_node("a");
    auto& b = make_node("b");
    make_certified_pair(a, b, root_kp);
    const auto a_b64 = a.pubkey_b64();

    auto d1 = signed_delta("create_node", "v-1", child_node("v-1", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d1));
    auto d2 = signed_delta("create_node", "v-2", child_node("v-2", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d2));
    const auto hash1 = hash_of(d1);
    // The running service already indexed both records.
    ASSERT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*a.gossip), 2u);

    // Swap the position-1 file for a DIFFERENT valid signed record
    // (different identifier, valid signature) while the service is running.

    storage::FileStorageService::RetainedDelta impostor = record_to_stored(d2, 1);
    impostor.position = 1;
    impostor.record_hash = hash1;  // claims the position-1 identifier
    ASSERT_EQ(a.storage->write_pool_record(hash1, impostor.to_json()),
              storage::FileStorageService::PoolWrite::Ok);

    // A fresh transfer session must not receive the swapped content.
    inject(build_packet(a.keypair(), gossip::GossipMsgType::Digest, digest_bytes(a)), b);
    pump_for(std::chrono::milliseconds(800));
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*b.gossip), 0u)
        << "a record whose content no longer matches its identifier must not be served";
    EXPECT_EQ(gossip::GossipBallotTestAccess::cursor_of(*b.gossip, a_b64), 0u);
    // The serving index is untouched: still two verified records, and the
    // corrupt file is preserved (not repaired, not deleted).
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*a.gossip), 2u);
    auto kept = a.storage->read_pool_record(hash1, 1000, pool_read_result);
    ASSERT_TRUE(kept.has_value());
    EXPECT_TRUE(kept->find(hash_of(d2)) == std::string::npos);
    EXPECT_TRUE(kept->find(R"("target_node_id":"v-2")") != std::string::npos);
}

// ---------------------------------------------------------------------------
// (11) Uncertain pool write: rename done, directory sync failed
// ---------------------------------------------------------------------------

// The uncertain outcome quarantines the pool immediately: the position is
// burned (never handed out again), further retention is refused, and the
// bytes are not ignored. A restart reconciles: the verified file is
// re-indexed at its own position and the pool is available again.
TEST_F(DeltaTransferTest, UncertainPoolWriteQuarantinesPoolAndBurnsPosition) {
    auto& a = make_node("a");

    a.storage->test_arm_pool_dirsync_failure();
    auto d1 = signed_delta("create_node", "u-1", child_node("u-1", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d1));

    // Immediately: the write reached the uncertain boundary.
    EXPECT_TRUE(gossip::GossipBallotTestAccess::pool_has_uncertain_write(*a.gossip));
    EXPECT_FALSE(gossip::GossipBallotTestAccess::pool_available(*a.gossip));
    // The destination exists: its storage must not be ignored or overwritten.
    EXPECT_TRUE(a.storage->pool_record_exists(hash_of(d1)));

    // A DIFFERENT record must not be retained on top of the uncertain state,
    // and must not take the burned position.
    auto d2 = signed_delta("create_node", "u-2", child_node("u-2", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d2));
    EXPECT_FALSE(a.storage->pool_record_exists(hash_of(d2)));
    EXPECT_FALSE(gossip::GossipBallotTestAccess::pool_available(*a.gossip));

    // Restart: reconstruction verifies the file and re-indexes it at its
    // own position (1). The pool is available again; the position was not
    // lost and the bytes were not ignored.
    respawn_gossip(a);
    EXPECT_FALSE(gossip::GossipBallotTestAccess::pool_has_uncertain_write(*a.gossip));
    ASSERT_TRUE(gossip::GossipBallotTestAccess::pool_available(*a.gossip));
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*a.gossip), 1u);
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_latest(*a.gossip), 1u);

    // The recovered position is 1 (the verified file re-indexed at its own
    // position); a never-applied record takes position 2.
    auto d3 = signed_delta("create_node", "u-3", child_node("u-3", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d3));
    EXPECT_TRUE(a.storage->pool_record_exists(hash_of(d3)));
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_latest(*a.gossip), 2u);
}

// ---------------------------------------------------------------------------
// (12) Admission: retryable denials and final unknown operations
// ---------------------------------------------------------------------------

// A known operation that lacks the required permission in the CURRENT tree
// is not necessarily permanently invalid: it is refused retryably, and the
// SAME signed statement is admitted once a valid permission context
// becomes available.
TEST_F(DeltaTransferTest, DeniedInCurrentTreeIsRetryableAndSucceedsAfterGrant) {
    auto root_kp = kc->ed25519_keygen();

    // The receiver `c` boots with a root whose admin is the fixture author;
    // the statement's author `pk2` has NO assignment there.
    auto c = std::make_unique<Node>();
    c->dir = root / "c";
    fs::create_directories(c->dir);
    c->crypto = std::make_unique<crypto::SodiumCryptoService>();
    c->crypto->start();
    c->storage = std::make_unique<storage::FileStorageService>(c->dir);
    c->storage->start();
    bootstrap_root(*c);
    c->tree = std::make_unique<tree::PermissionTreeService>(*c->storage, *c->crypto);
    c->tree->start();
    c->gossip = std::make_unique<gossip::GossipService>(io, 0, *c->storage, *c->crypto);
    c->gossip->set_tree(c->tree.get());
    c->gossip->start();
    nodes.push_back(std::move(c));
    auto& cv = *nodes.back();
    cv.gossip->set_root_pubkey(root_kp.public_key);
    cv.gossip->set_network_id(kTestNetworkHex);

    // A forwarder key cert-verified on `c`; every page below is crafted
    // from it, bound to `c`'s own captured request.
    auto fwd = kc->ed25519_keygen();
    const auto fwd_b64 = crypto::to_base64(fwd.public_key);
    {
        auto cert = issue_cert(fwd_b64, "srv-fwd", root_kp);
        json h = json::parse(cert);
        h["is_response"] = false;
        inject(build_packet(fwd, gossip::GossipMsgType::ServerHello,
                            bytes_of(h.dump())),
               cv);
        cv.gossip->do_add_peer("127.0.0.1:1", fwd_b64);
    }
    pump_for(std::chrono::milliseconds(200));
    ASSERT_TRUE(cv.certified_peer(fwd_b64));

    // A second author with no assignment on `root`.
    auto kp2 = kc->ed25519_keygen();
    const auto pk2 = "ed25519:" + crypto::to_base64(kp2.public_key);
    auto signed_by = [&](const crypto::Ed25519Keypair& kp, const std::string& pk,
                         const std::string& op, const std::string& target,
                         const tree::TreeNode& node) {
        tree::TreeDelta d;
        d.operation = op;
        d.target_node_id = target;
        d.node_data = node;
        d.signer_pubkey = pk;
        d.timestamp = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        auto canonical = tree::canonical_delta_json(d);
        auto msg = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
        d.signature = crypto::to_base64(kc->ed25519_sign(kp.private_key, msg));
        return d;
    };

    const auto stmt = signed_by(kp2, pk2, "create_node", "p-1",
                                child_node("p-1", "root"));

    // One digest-driven request/answer round with the crafted page.
    auto send_page = [&](std::uint64_t position, const tree::TreeDelta& d) {
        json digest;
        digest["latest_pos"] = position;
        digest["log_generation"] = "abcdef0123456789abcdef0123456789";
        digest["peer_count"] = 1;
        digest["timestamp"] = 1000;
        inject(build_packet(fwd, gossip::GossipMsgType::Digest, bytes_of(digest.dump())),
               cv);
        ASSERT_TRUE(pump_until([&] {
            return gossip::GossipBallotTestAccess::has_outstanding(*cv.gossip, fwd_b64);
        }, std::chrono::seconds(5)));
        std::uint64_t nonce = 0, from_pos = 0;
        std::string generation;
        ASSERT_TRUE(gossip::GossipBallotTestAccess::outstanding_info(
            *cv.gossip, fwd_b64, nonce, from_pos, generation));
        auto r = record_json(d);
        r["position"] = position;
        json response;
        response["nonce"] = nonce;
        response["from_pos"] = from_pos;
        response["generation"] = generation;
        response["latest_pos"] = position;
        response["complete"] = true;
        response["records"] = json::array({r});
        inject(build_packet(fwd, gossip::GossipMsgType::DeltaResponse,
                            bytes_of(response.dump())),
               cv);
        pump_for(std::chrono::milliseconds(300));
    };

    // Round 1: a known operation the signer lacks permission for in the
    // CURRENT tree -> refused retryably: nothing retained, cursor stalls at 0.
    send_page(1, stmt);
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*cv.gossip), 0u);
    EXPECT_EQ(gossip::GossipBallotTestAccess::cursor_of(*cv.gossip, fwd_b64), 0u);

    // The valid permission context becomes available: the admin author
    // grants pk2 on the root through the production local path.
    {
        tree::TreeNode rn;
        rn.id = "root";
        rn.parent_id = "";
        rn.type = tree::NodeType::Root;
        rn.mgmt_pubkey = author_pubkey;
        rn.assignments = {{author_pubkey, {"admin"}}, {pk2, {"admin"}}};
        auto grant = signed_delta("update_assignment", "root", rn);
        ASSERT_TRUE(cv.tree->apply_delta(grant));
    }

    // Round 2: the SAME signed statement is admitted once the context
    // allows it.
    send_page(1, stmt);
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*cv.gossip), 1u)
        << "the same signed statement must be admitted once the context allows it";
    EXPECT_EQ(gossip::GossipBallotTestAccess::cursor_of(*cv.gossip, fwd_b64), 1u);
    EXPECT_TRUE(cv.storage->pool_record_exists(hash_of(stmt)));
}

TEST_F(DeltaTransferTest, UnknownOperationIsFinalAndAdvancesTheCursor) {
    auto root_kp = kc->ed25519_keygen();
    auto& a = make_node("a");
    auto& b = make_node("b");
    make_certified_pair(a, b, root_kp);
    const auto a_b64 = a.pubkey_b64();

    auto d1 = signed_delta("create_node", "k-1", child_node("k-1", "root"));
    ASSERT_TRUE(a.tree->apply_delta(d1));
    auto d2 = signed_delta("frobnicate", "k-1", child_node("k-1", "root"));
    ASSERT_EQ(a.tree->apply_delta(d2), false);  // unknown op is not locally applyable

    // One-way trust so only crafted pages bind.
    // (reuse the pattern: b trusts a; a never answers because we craft
    // directly with captured nonces — a's real answer is an empty/real page
    // that also advances; to keep it deterministic, use a fresh receiver.)
    auto c = std::make_unique<Node>();
    c->dir = root / "c";
    fs::create_directories(c->dir);
    c->crypto = std::make_unique<crypto::SodiumCryptoService>();
    c->crypto->start();
    c->storage = std::make_unique<storage::FileStorageService>(c->dir);
    c->storage->start();
    bootstrap_root(*c);
    c->tree = std::make_unique<tree::PermissionTreeService>(*c->storage, *c->crypto);
    c->tree->start();
    c->gossip = std::make_unique<gossip::GossipService>(io, 0, *c->storage, *c->crypto);
    c->gossip->set_tree(c->tree.get());
    c->gossip->start();
    nodes.push_back(std::move(c));
    auto& cv = *nodes.back();
    (void)a; (void)b; (void)a_b64;

    auto fwd = kc->ed25519_keygen();
    const auto fwd_b64 = crypto::to_base64(fwd.public_key);
    {
        auto cert = issue_cert(fwd_b64, "srv-fwd", root_kp);
        json h = json::parse(cert);
        h["is_response"] = false;
        cv.gossip->set_root_pubkey(root_kp.public_key);
        cv.gossip->set_network_id(kTestNetworkHex);
        inject(build_packet(fwd, gossip::GossipMsgType::ServerHello,
                            bytes_of(h.dump())),
               cv);
        cv.gossip->do_add_peer("127.0.0.1:1", fwd_b64);
    }
    pump_for(std::chrono::milliseconds(200));
    ASSERT_TRUE(cv.certified_peer(fwd_b64));

    // One page: the valid record at position 1, the unknown-operation
    // record (validly signed by the author) at position 2.
    json digest;
    digest["latest_pos"] = 2;
    digest["log_generation"] = "abcdef0123456789abcdef0123456789";
    digest["peer_count"] = 1;
    digest["timestamp"] = 1000;
    inject(build_packet(fwd, gossip::GossipMsgType::Digest, bytes_of(digest.dump())), cv);
    ASSERT_TRUE(pump_until([&] {
        return gossip::GossipBallotTestAccess::has_outstanding(*cv.gossip, fwd_b64);
    }, std::chrono::seconds(5)));
    std::uint64_t nonce = 0, from_pos = 0;
    std::string generation;
    ASSERT_TRUE(gossip::GossipBallotTestAccess::outstanding_info(
        *cv.gossip, fwd_b64, nonce, from_pos, generation));
    auto r1 = record_json(d1); r1["position"] = 1;
    auto r2 = record_json(d2); r2["position"] = 2;
    json response;
    response["nonce"] = nonce;
    response["from_pos"] = from_pos;
    response["generation"] = generation;
    response["latest_pos"] = 2;
    response["complete"] = true;
    response["records"] = json::array({r1, r2});
    inject(build_packet(fwd, gossip::GossipMsgType::DeltaResponse,
                        bytes_of(response.dump())),
           cv);
    pump_for(std::chrono::milliseconds(400));

    // The valid record was retained; the unknown-operation record was
    // refused finally and the cursor advanced past it.
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*cv.gossip), 1u);
    EXPECT_EQ(gossip::GossipBallotTestAccess::cursor_of(*cv.gossip, fwd_b64), 2u);
    EXPECT_FALSE(cv.storage->pool_record_exists(hash_of(d2)));
}

// ---------------------------------------------------------------------------
// (8) Mesh state: production writes race production reads
// ---------------------------------------------------------------------------

// The tunnel-IP and NS-slot fields are written on the io thread by the
// production handlers (ServerHello tunnel assignment, NS slot claims) and
// read from other threads through the production getters. This test runs
// the io context on its own thread so the writes are REAL cross-thread
// production writes, while a reader thread exercises the same fields
// concurrently. Under -fsanitize=thread an unlocked access on either side
// is reported.
TEST_F(DeltaTransferTest, MeshStateProductionWritesRaceProductionReads) {
    auto root_kp = kc->ed25519_keygen();
    auto& a = make_node("a");
    auto& b = make_node("b");
    make_certified_pair(a, b, root_kp);

    // The production tunnel-IP assignment: a cert-verified ServerHello
    // response carrying assigned_tunnel_ip.
    auto send_tunnel_ip = [&] {
        auto cert = issue_cert(b.pubkey_b64(), "srv-b", root_kp);
        json h = json::parse(cert);
        h["is_response"] = true;
        h["assigned_tunnel_ip"] = "10.64.0.5";
        inject(build_packet(b.keypair(), gossip::GossipMsgType::ServerHello,
                            bytes_of(h.dump())),
               a);
    };
    // A production NS slot claim: signed by the claimant (b), who is
    // cert-verified on a. A fresh timestamp makes each claim win the LWW
    // rule, so every one is a real write to the slot table.
    std::atomic<uint64_t> claim_ts{1000};
    auto send_ns_claim = [&](uint8_t slot) {
        json sign_payload;
        sign_payload["slot"]          = slot;
        sign_payload["server_pubkey"] = b.pubkey_b64();
        sign_payload["server_ip"]     = "10.0.0.9";
        sign_payload["region"]        = "eu-west";
        sign_payload["timestamp"]     = claim_ts.fetch_add(1);
        json wire = sign_payload;
        wire["signature"] = crypto::to_base64(kc->ed25519_sign(
            b.keypair().private_key, bytes_of(sign_payload.dump())));
        auto packed = json::to_msgpack(wire);
        inject(build_packet(b.keypair(), gossip::GossipMsgType::NsSlotClaim,
                            std::vector<uint8_t>(packed.begin(), packed.end())),
               a);
    };

    // Prime both fields through the production path.
    send_tunnel_ip();
    send_ns_claim(3);
    pump_for(std::chrono::milliseconds(300));
    ASSERT_EQ(a.gossip->our_tunnel_ip(), "10.64.0.5");
    ASSERT_EQ(a.gossip->our_ns_slot().value_or(0), 0u);  // b claimed, not a
    auto slots = a.gossip->get_ns_slots();
    ASSERT_FALSE(slots.empty());

    // Run the io context on a dedicated thread: every injected claim is a
    // production write ON THAT THREAD.
    std::thread io_thread([&] { io.run(); });

    std::atomic<bool> stop_reader{false};
    std::atomic<uint64_t> reads{0};
    std::thread reader([&] {
        while (!stop_reader) {
            (void)a.gossip->our_tunnel_ip();
            (void)a.gossip->our_ns_slot();
            (void)a.gossip->get_ns_slots();
            ++reads;
        }
    });

    for (int i = 0; i < 400; ++i) {
        send_ns_claim(static_cast<uint8_t>(1 + (i % 9)));
    }
    pump_for(std::chrono::milliseconds(1500));  // drain the queue

    stop_reader = true;
    reader.join();
    io.stop();
    io_thread.join();

    EXPECT_GT(reads.load(), 100u)
        << "the reader must actually interleave with the io-thread writes";
    // All nine slots were claimed by the production handler.
    auto final_slots = a.gossip->get_ns_slots();
    ASSERT_EQ(final_slots.size(), 9u);
    for (const auto& s : final_slots) {
        EXPECT_EQ(s.server_pubkey, b.pubkey_b64());
    }
    EXPECT_EQ(a.gossip->our_tunnel_ip(), "10.64.0.5");
}

}  // namespace