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
    auto fresh = std::make_unique<gossip::GossipService>(io, 0, *a.storage, *a.crypto);
    fresh->start();
    EXPECT_TRUE(gossip::GossipBallotTestAccess::pool_available(*fresh));
    // One verified record (position 1); the corrupt file is excluded and
    // preserved byte-identically.
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*fresh), 1u);
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_excluded(*fresh, h2), true);
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_excluded_bytes(*fresh),
              static_cast<uint64_t>(corrupt.size()));
    {
        std::ifstream in(a.storage->pool_dir() / (h2 + ".json"), std::ios::binary);
        std::string content((std::istreambuf_iterator<char>(in)), {});
        EXPECT_EQ(content, corrupt)
            << "evidence must not be auto-repaired or overwritten";
    }
    // The excluded identifier still occupies its file: re-retaining the same
    // record is a collision refusal, not an overwrite.
    storage::FileStorageService::RetainedDelta rec;
    rec.operation = d2.operation;
    rec.target_node_id = d2.target_node_id;
    rec.data = json(d2.node_data).dump();
    rec.signer_pubkey = d2.signer_pubkey;
    rec.signature = d2.signature;
    rec.timestamp = d2.timestamp;
    EXPECT_FALSE(fresh->retain_local_delta(rec));
    EXPECT_EQ(gossip::GossipBallotTestAccess::pool_record_count(*fresh), 1u);
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

    auto fresh = std::make_unique<gossip::GossipService>(io, 0, *a.storage, *a.crypto);
    fresh->start();
    ASSERT_TRUE(gossip::GossipBallotTestAccess::pool_available(*fresh));

    // A budget that fits verified + excluded exactly leaves no room for the
    // next record: corruption does not create free capacity.
    const auto used = gossip::GossipBallotTestAccess::pool_verified_bytes(*fresh) +
                      gossip::GossipBallotTestAccess::pool_excluded_bytes(*fresh);
    gossip::GossipBallotTestAccess::set_pool_max_bytes(*fresh, used);

    auto d3 = signed_delta("create_node", "child-3", child_node("child-3", "root"));
    storage::FileStorageService::RetainedDelta rec;
    rec.operation = d3.operation;
    rec.target_node_id = d3.target_node_id;
    rec.data = json(d3.node_data).dump();
    rec.signer_pubkey = d3.signer_pubkey;
    rec.signature = d3.signature;
    rec.timestamp = d3.timestamp;
    EXPECT_FALSE(fresh->retain_local_delta(rec))
        << "excluded evidence bytes must count toward the capacity bound";

    // Lift the bound and the same record is retained.
    gossip::GossipBallotTestAccess::set_pool_max_bytes(*fresh, 0);
    EXPECT_TRUE(fresh->retain_local_delta(rec));
    fresh->stop();
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
            ASSERT_TRUE(n.storage->write_pool_record(
                hash_of(d1), rec_for(d1, 1, hash_of(d1)).to_json()));
            ASSERT_TRUE(n.storage->write_pool_record(
                hash_of(d2), rec_for(d2, 2, hash_of(d2)).to_json()));
            ASSERT_TRUE(n.storage->write_pool_record(
                hash_of(d3), rec_for(d3, 3, hash_of(d3)).to_json()));
        });

    // The cap is applied before any content is read: 2 < 3 records -> the pool
    // is unavailable and new retention is refused; files untouched.
    gossip::GossipBallotTestAccess::set_pool_max_records(*a.gossip, 2);
    a.gossip->stop();
    a.gossip->start();
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
        ASSERT_TRUE(n.storage->write_pool_record(hash_of(d1), rec.to_json()));
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
        ASSERT_TRUE(n.storage->write_pool_record(
            hash_of(d1), rec_for(d1, hash_of(d1)).to_json()));
        ASSERT_TRUE(n.storage->write_pool_record(
            hash_of(d2), rec_for(d2, hash_of(d2)).to_json()));
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
    inject(build_packet(a.keypair(), gossip::GossipMsgType::Digest, digest_bytes(a)), b);
    pump_for(std::chrono::milliseconds(400));
    // `b` may have already consumed a page; whatever its cursor is, the
    // generation reset below is what the test is about.
    const auto cursor_before =
        gossip::GossipBallotTestAccess::cursor_of(*b.gossip, a_b64);

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

    // Now a LATE answer from the superseded generation arrives: it must be
    // dropped — no retention, no cursor movement.
    auto rec = record_json(d);
    rec["position"] = 1;
    json response;
    response["nonce"] = 1;
    response["from_pos"] = cursor_before;
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
    (void)cursor_before;
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
// (8) Mesh state: one lock, no torn reads
// ---------------------------------------------------------------------------

// The tunnel-IP / NS-slot state is written on the io thread and read from
// other threads (status API, ServerIdentity). Under -fsanitize=thread the
// pre-fix code (peers lock on some paths, no lock on others) races; the
// shared mesh_state_mutex_ must cover every access.
TEST_F(DeltaTransferTest, MeshStateIsSafeForConcurrentReadsAndWrites) {
    auto& a = make_node("a");

    std::atomic<bool> stop{false};
    std::atomic<uint64_t> reads{0};
    std::thread reader([&] {
        while (!stop) {
            (void)a.gossip->our_tunnel_ip();
            (void)a.gossip->our_ns_slot();
            (void)a.gossip->get_ns_slots();
            ++reads;
        }
    });
    for (int i = 0; i < 200000; ++i) {
        a.gossip->set_preferred_ns_slot(static_cast<uint8_t>(i % 10));
    }
    stop = true;
    reader.join();
    EXPECT_GT(reads.load(), 10u)
        << "the reader must actually interleave with the writer";
}

}  // namespace
