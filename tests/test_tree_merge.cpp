// The one-time tree merge (docs/Design-Tree-Consensus-and-Storage-Key.md,
// A9; docs/Tree-Merge-Ceremony.md): the merge body, the deterministic merge
// rule, the root-signed height-1 commit, the signed exports and requests of
// the supported migration, and how servers await, take, and refuse a merge.

#include <LemonadeNexus/Core/TreeMigrationControl.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeConsensus.hpp>
#include <LemonadeNexus/Tree/TreeLog.hpp>
#include <LemonadeNexus/Tree/TreeMerge.hpp>
#include <LemonadeNexus/Tree/TreeOps.hpp>
#include <LemonadeNexus/Tree/TreeReplication.hpp>

#include <gtest/gtest.h>

#include "support/tree_seed.hpp"

#include <algorithm>
#include <filesystem>
#include <map>
#include <set>
#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

using namespace nexus;
namespace fs = std::filesystem;
namespace sec = nexus::security;

namespace {

constexpr uint64_t kBlockTimeMs = 1'700'000'000'000;

std::string principal_of(const crypto::Ed25519Keypair& kp) {
    return "ed25519:" +
           crypto::to_base64(std::span<const uint8_t>(kp.public_key.data(), kp.public_key.size()));
}

tree::TreeNode node(const std::string& id, const std::string& parent, tree::NodeType type,
                    const std::string& owner) {
    tree::TreeNode n;
    n.id = id;
    n.parent_id = parent;
    n.type = type;
    n.mgmt_pubkey = owner;
    n.assignments = {{owner, {"admin"}}};
    return n;
}

tree::TreeNode endpoint(const std::string& id, const std::string& parent, const std::string& owner,
                        const std::string& tunnel_ip) {
    auto n = node(id, parent, tree::NodeType::Endpoint, owner);
    n.tunnel_ip = tunnel_ip;
    n.endpoint_identifier = "client-" + id;
    n.mesh_pubkey = "mesh-" + id;
    return n;
}

const tree::MergeConflict* conflict_for(const tree::MergeResult& result, const std::string& id,
                                        const std::string& kind) {
    const auto it = std::find_if(result.conflicts.begin(), result.conflicts.end(),
                                 [&](const auto& c) { return c.node_id == id && c.kind == kind; });
    return it == result.conflicts.end() ? nullptr : &*it;
}

}  // namespace

class TreeMergeTest : public ::testing::Test {
protected:
    void SetUp() override {
        dir = fs::temp_directory_path() / ("nexus_test_tree_merge_" + std::to_string(getpid()));
        fs::remove_all(dir);
        fs::create_directories(dir);
        crypto_svc.start();
        root_kp = crypto_svc.ed25519_keygen();
        other_kp = crypto_svc.ed25519_keygen();
        root_key = principal_of(root_kp);
        network.fill(0x42);
    }

    void TearDown() override {
        crypto_svc.stop();
        fs::remove_all(dir);
    }

    /// Root server "east": root, group acme with device d1. Server "west":
    /// group beta with device d2.
    std::vector<tree::TreeExport> two_servers() const {
        tree::TreeExport east;
        east.server = "east";
        east.root_server = true;
        east.nodes = {tree::make_root_node(root_key),
                      node("acme", "root", tree::NodeType::Customer, root_key),
                      endpoint("d1", "acme", root_key, "10.64.0.10/32")};
        east.joined_here = {"d1"};
        east.created_here = {"acme"};
        tree::TreeExport west;
        west.server = "west";
        west.nodes = {tree::make_root_node(root_key),
                      node("beta", "root", tree::NodeType::Customer, root_key),
                      endpoint("d2", "beta", root_key, "10.64.0.11/32")};
        west.joined_here = {"d2"};
        west.created_here = {"beta"};
        return {east, west};
    }

    /// The signed height-1 commit for `nodes`.
    tree::TreeLogEntry signed_commit(const tree::rules::NodeMap& nodes,
                                     const crypto::Ed25519Keypair& signer) {
        auto entry = tree::build_merge_entry(nodes, kBlockTimeMs, network, root_key);
        EXPECT_TRUE(entry.has_value());
        const auto preimage = tree::merge_preimage(*entry, network, nodes.size());
        const auto signature = crypto_svc.ed25519_sign(
            signer.private_key,
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(preimage.data()),
                                     preimage.size()));
        return tree::attach_merge_signature(*entry, signature);
    }

    tree::rules::NodeMap merged_nodes() {
        const auto result = tree::merge_tree_exports(two_servers(), {});
        EXPECT_TRUE(result.conflicts.empty());
        return result.nodes;
    }

    fs::path dir;
    crypto::SodiumCryptoService crypto_svc;
    crypto::Ed25519Keypair root_kp;
    crypto::Ed25519Keypair other_kp;
    std::string root_key;
    sec::NetworkId network{};
};

// =========================================================================
// Merge body
// =========================================================================

TEST_F(TreeMergeTest, TheMergeBodyIsCanonical) {
    const auto nodes = merged_nodes();
    const auto body = tree::encode_merge_body(nodes);
    ASSERT_TRUE(body.has_value());
    const auto decoded = tree::decode_merge_body(*body);
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(tree::compute_tree_digest(*decoded), tree::compute_tree_digest(nodes));

    auto trailing = *body;
    trailing.push_back(0);
    EXPECT_FALSE(tree::decode_merge_body(trailing).has_value());
    auto short_body = *body;
    short_body.pop_back();
    EXPECT_FALSE(tree::decode_merge_body(short_body).has_value());
    auto miscounted = *body;
    miscounted[0] ^= 0x01;
    EXPECT_FALSE(tree::decode_merge_body(miscounted).has_value());
}

TEST_F(TreeMergeTest, ExportsRoundTrip) {
    const auto exports = two_servers();
    const auto parsed = tree::tree_export_from_json(tree::tree_export_to_json(exports[0]));
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->server, "east");
    EXPECT_TRUE(parsed->root_server);
    EXPECT_EQ(parsed->nodes.size(), 3u);
    EXPECT_EQ(parsed->joined_here, exports[0].joined_here);
    auto bad = tree::tree_export_to_json(exports[0]);
    bad["type"] = "something-else";
    EXPECT_FALSE(tree::tree_export_from_json(bad).has_value());
}

// =========================================================================
// The merge rule and its conflicts
// =========================================================================

TEST_F(TreeMergeTest, DisjointTreesUnionWithoutConflicts) {
    const auto result = tree::merge_tree_exports(two_servers(), {});
    EXPECT_TRUE(result.conflicts.empty()) << tree::merge_conflicts_to_json(result.conflicts).dump();
    EXPECT_EQ(result.nodes.size(), 5u);
    for (const char* id : {"root", "acme", "beta", "d1", "d2"}) {
        EXPECT_TRUE(result.nodes.contains(id)) << id;
    }
}

TEST_F(TreeMergeTest, ADeviceComesFromTheServerItJoined) {
    auto exports = two_servers();
    // west also holds d1, with another hostname, but east's IPAM joined it.
    exports[1].nodes.push_back(endpoint("d1", "acme", root_key, "10.64.0.10/32"));
    exports[1].nodes.back().hostname = "stale-copy";
    exports[1].nodes.push_back(node("acme", "root", tree::NodeType::Customer, root_key));
    const auto result = tree::merge_tree_exports(exports, {});
    EXPECT_TRUE(result.conflicts.empty()) << tree::merge_conflicts_to_json(result.conflicts).dump();
    EXPECT_NE(result.nodes.at("d1").hostname, "stale-copy");
}

TEST_F(TreeMergeTest, AGroupComesFromItsCreatorsRecord) {
    auto exports = two_servers();
    auto copy = node("acme", "root", tree::NodeType::Customer, root_key);
    copy.hostname = "west-acme";
    exports[1].nodes.push_back(copy);
    const auto result = tree::merge_tree_exports(exports, {});
    EXPECT_TRUE(result.conflicts.empty());
    EXPECT_NE(result.nodes.at("acme").hostname, "west-acme");
}

TEST_F(TreeMergeTest, TheRootComesFromTheRootServer) {
    auto exports = two_servers();
    exports[1].nodes[0].hostname = "west-root";  // west's root differs
    const auto result = tree::merge_tree_exports(exports, {});
    EXPECT_TRUE(result.conflicts.empty());
    EXPECT_EQ(result.nodes.at("root").hostname, "root");

    // The root server lost its root: the tie-break takes another copy.
    exports[0].nodes.erase(exports[0].nodes.begin());
    const auto fallback = tree::merge_tree_exports(exports, {});
    EXPECT_TRUE(fallback.conflicts.empty());
    EXPECT_EQ(fallback.nodes.at("root").hostname, "west-root");

    // No export holds a root at all: no commit.
    exports[1].nodes.erase(exports[1].nodes.begin());
    const auto missing = tree::merge_tree_exports(exports, {});
    EXPECT_NE(conflict_for(missing, "root", "root_missing"), nullptr);
}

TEST_F(TreeMergeTest, DivergentCopiesAreDecidedByTheTieBreak) {
    // A group both servers claim to have created, with different contents.
    auto base = two_servers();
    auto copy = node("acme", "root", tree::NodeType::Customer, root_key);
    copy.hostname = "west-acme";
    base[1].nodes.push_back(copy);
    base[1].created_here.insert("acme");

    // 1. The highest version wins.
    auto exports = base;
    exports[1].nodes.back().version = 3;
    auto result = tree::merge_tree_exports(exports, {});
    EXPECT_TRUE(result.conflicts.empty());
    EXPECT_EQ(result.nodes.at("acme").hostname, "west-acme");

    // 2. Then the copy that the most exports hold.
    exports = base;
    tree::TreeExport south;
    south.server = "south";
    south.nodes = {copy};
    exports.push_back(south);
    result = tree::merge_tree_exports(exports, {});
    EXPECT_EQ(result.nodes.at("acme").hostname, "west-acme");

    // 3. Then the root server's copy.
    result = tree::merge_tree_exports(base, {});
    EXPECT_TRUE(result.conflicts.empty());
    EXPECT_EQ(result.nodes.at("acme").hostname, "");
    const auto decided = std::find_if(result.decisions.begin(), result.decisions.end(),
                                      [](const std::string& d) { return d.starts_with("acme:"); });
    ASSERT_NE(decided, result.decisions.end());
    EXPECT_NE(decided->find("tie-break"), std::string::npos);

    // 4. Then byte order, when no export is the root server's.
    exports = base;
    exports[0].nodes.erase(std::remove_if(exports[0].nodes.begin(), exports[0].nodes.end(),
                                          [](const tree::TreeNode& n) { return n.id == "acme"; }),
                           exports[0].nodes.end());
    tree::TreeExport north;
    north.server = "north";
    auto other = node("acme", "root", tree::NodeType::Customer, root_key);
    other.hostname = "aaa-north";
    north.nodes = {other};
    north.created_here = {"acme"};
    exports.push_back(north);
    result = tree::merge_tree_exports(exports, {});
    const auto a = tree::encode_tree_node(copy);
    const auto b = tree::encode_tree_node(other);
    EXPECT_EQ(result.nodes.at("acme").hostname, a < b ? "west-acme" : "aaa-north");
}

TEST_F(TreeMergeTest, SharedIdentifiersAndBrokenStructureAreDroppedDeterministically) {
    auto exports = two_servers();
    // A device whose group exists nowhere, and a device beneath it.
    exports[1].nodes.push_back(endpoint("d3", "gamma", root_key, "10.64.0.12/32"));
    exports[1].nodes.push_back(endpoint("d3-child", "d3", root_key, "10.64.0.13/32"));
    // A device that west's independent IPAM gave east's d1 address. east
    // records d1's join, so d1 stays.
    exports[1].nodes.push_back(endpoint("d4", "beta", root_key, "10.64.0.10/32"));
    // Two groups that name each other as parent.
    exports[1].nodes.push_back(node("loop-a", "loop-b", tree::NodeType::Customer, root_key));
    exports[1].nodes.push_back(node("loop-b", "loop-a", tree::NodeType::Customer, root_key));
    const auto result = tree::merge_tree_exports(exports, {});
    EXPECT_TRUE(result.conflicts.empty()) << tree::merge_conflicts_to_json(result.conflicts).dump();

    std::map<std::string, std::string> reasons;
    for (const auto& d : result.dropped) reasons[d.node_id] = d.reason;
    EXPECT_EQ(reasons["d3"], "orphan");
    EXPECT_EQ(reasons["d3-child"], "unreachable");
    EXPECT_EQ(reasons["d4"], "duplicate_tunnel_address");
    EXPECT_EQ(reasons["loop-a"], "unreachable");
    EXPECT_EQ(reasons["loop-b"], "unreachable");
    EXPECT_EQ(reasons.size(), 5u);
    EXPECT_TRUE(result.nodes.contains("d1"));
    for (const auto& [id, reason] : reasons) EXPECT_FALSE(result.nodes.contains(id)) << id;

    // The report names what each server's tree gains and loses.
    const auto report = tree::merge_report(exports, result);
    EXPECT_EQ(report["node_count"], result.nodes.size());
    EXPECT_EQ(report["servers"]["west"]["added"], nlohmann::json({"acme", "d1"}));
    EXPECT_EQ(report["dropped"].size(), 5u);
}

TEST_F(TreeMergeTest, TheMergeIsAFunctionOfTheExportsOnly) {
    auto exports = two_servers();
    auto copy = node("acme", "root", tree::NodeType::Customer, root_key);
    copy.hostname = "west-acme";
    exports[1].nodes.push_back(copy);
    exports[1].created_here.insert("acme");
    exports[1].nodes.push_back(endpoint("d4", "beta", root_key, "10.64.0.10/32"));
    const auto first = tree::merge_tree_exports(exports, {});
    const auto first_body = tree::encode_merge_body(first.nodes);

    // Another export order and another node order give the same bytes.
    std::reverse(exports.begin(), exports.end());
    for (auto& e : exports) std::reverse(e.nodes.begin(), e.nodes.end());
    const auto second = tree::merge_tree_exports(exports, {});
    EXPECT_EQ(tree::encode_merge_body(second.nodes), first_body);
    EXPECT_EQ(second.decisions, first.decisions);
    EXPECT_EQ(tree::merge_report(exports, second)["dropped"],
              tree::merge_report(exports, first)["dropped"]);
    const auto a = tree::build_merge_entry(first.nodes, kBlockTimeMs, network, root_key);
    const auto b = tree::build_merge_entry(second.nodes, kBlockTimeMs, network, root_key);
    ASSERT_TRUE(a && b);
    EXPECT_EQ(a->state_root, b->state_root);
}

TEST_F(TreeMergeTest, AnOperatorResolutionStillDecidesFirst) {
    auto exports = two_servers();
    auto copy = node("acme", "root", tree::NodeType::Customer, root_key);
    copy.hostname = "west-acme";
    exports[1].nodes.push_back(copy);
    exports[1].created_here.insert("acme");
    const auto resolved = tree::merge_tree_exports(exports, {{"acme", "west"}, {"d2", "drop"}});
    EXPECT_TRUE(resolved.conflicts.empty());
    EXPECT_EQ(resolved.nodes.at("acme").hostname, "west-acme");
    EXPECT_FALSE(resolved.nodes.contains("d2"));
}

TEST_F(TreeMergeTest, BadExportsAndResolutionsAreListed) {
    auto exports = two_servers();
    exports[1].root_server = true;  // two root servers
    const auto result = tree::merge_tree_exports(exports, {{"nobody", "east"}, {"d1", "west"}});
    EXPECT_NE(conflict_for(result, "root", "bad_exports"), nullptr);
    EXPECT_NE(conflict_for(result, "nobody", "bad_resolution"), nullptr);
    EXPECT_NE(conflict_for(result, "d1", "bad_resolution"), nullptr);
}

// =========================================================================
// The height-1 commit
// =========================================================================

TEST_F(TreeMergeTest, TheRootSignedCommitVerifies) {
    const auto entry = signed_commit(merged_nodes(), root_kp);
    EXPECT_FALSE(tree::verify_merge_signature(crypto_svc, entry, network, root_key).has_value());
    // It survives the replication wire form.
    const auto wire = tree::decode_replicated_entry(tree::encode_replicated_entry(entry));
    ASSERT_TRUE(wire.has_value());
    EXPECT_FALSE(tree::verify_merge_signature(crypto_svc, *wire, network, root_key).has_value());
}

TEST_F(TreeMergeTest, ACommitWithABadSignatureIsRefused) {
    const auto nodes = merged_nodes();
    // Signed by another key.
    EXPECT_TRUE(tree::verify_merge_signature(crypto_svc, signed_commit(nodes, other_kp), network,
                                             root_key)
                    .has_value());
    // A flipped signature bit.
    auto flipped = signed_commit(nodes, root_kp);
    auto sig = crypto::from_base64(flipped.commit["signature"].get<std::string>());
    sig[5] ^= 0x01;
    flipped.commit["signature"] = crypto::to_base64(sig);
    EXPECT_TRUE(tree::verify_merge_signature(crypto_svc, flipped, network, root_key).has_value());
    // A tree changed after signing.
    auto edited = signed_commit(nodes, root_kp);
    auto changed = nodes;
    changed.erase("d2");
    auto rebuilt = tree::build_merge_entry(changed, kBlockTimeMs, network, root_key);
    edited.batch = rebuilt->batch;
    edited.ops_digest = rebuilt->ops_digest;
    edited.tree_digest = rebuilt->tree_digest;
    edited.state_root = rebuilt->state_root;
    EXPECT_TRUE(tree::verify_merge_signature(crypto_svc, edited, network, root_key).has_value());
    // Another network, and a server that names another root key.
    sec::NetworkId other_network{};
    other_network.fill(0x43);
    const auto good = signed_commit(nodes, root_kp);
    EXPECT_TRUE(tree::verify_merge_signature(crypto_svc, good, other_network, root_key).has_value());
    EXPECT_TRUE(tree::verify_merge_signature(crypto_svc, good, network, principal_of(other_kp))
                    .has_value());
    EXPECT_TRUE(tree::verify_merge_signature(crypto_svc, good, network, "").has_value());
    // Only height 1.
    auto later = good;
    later.height = 2;
    EXPECT_TRUE(tree::verify_merge_signature(crypto_svc, later, network, root_key).has_value());
}

TEST_F(TreeMergeTest, TheMergeCommitReplaysOnlyOnTheEmptyBase) {
    const auto entry = signed_commit(merged_nodes(), root_kp);
    tree::TreeChainState empty;
    empty.root = tree::empty_base_root();
    auto state = empty;
    ASSERT_TRUE(tree::replay_entry(state, entry).verdict.ok());
    EXPECT_EQ(state.nodes.size(), 5u);
    EXPECT_EQ(state.root, entry.state_root);
    // Not on top of any other state: the merge is one-shot.
    EXPECT_FALSE(tree::replay_entry(state, entry).verdict.ok());
    tree::TreeChainState other;
    other.nodes.emplace("root", tree::make_root_node(root_key));
    other.root = tree::base_state_root(tree::compute_tree_digest(other.nodes));
    EXPECT_FALSE(tree::replay_entry(other, entry).verdict.ok());
}

// =========================================================================
// The migration on one server: await the merge, take it, then run ops
// =========================================================================

class TreeMergeLogTest : public TreeMergeTest {
protected:
    void SetUp() override {
        TreeMergeTest::SetUp();
        server_kp = crypto_svc.ed25519_keygen();
        self.bytes = server_kp.public_key;
        open_tree();
        // Before the switch this server wrote its own tree: a root, and a
        // group with a device only it holds.
        ASSERT_TRUE(test_support::put_nodes(
            *tree_svc, {tree::make_root_node(root_key),
                        node("local-group", "root", tree::NodeType::Customer, root_key)}));
        pre_merge = tree_svc->tree_digest();
        start();
    }

    void TearDown() override {
        close();
        TreeMergeTest::TearDown();
    }

    void open_tree() {
        storage = std::make_unique<storage::FileStorageService>(dir / "data");
        storage->start();
        tree_svc = std::make_unique<tree::PermissionTreeService>(*storage, crypto_svc);
        tree_svc->start();
    }

    void start() {
        tree::TreeConsensusConfig config;
        config.self = self;
        config.network_id = network;
        config.root_key = root_key;
        config.wall_clock_ms = [] { return kBlockTimeMs + 1000; };
        tc = std::make_unique<tree::TreeConsensus>(std::move(config), *tree_svc, crypto_svc,
                                                   dir / "data" / "tree" / "log");
        tc->set_members({self});
        started = tc->start();
    }

    void restart() {
        close();
        open_tree();
        start();
    }

    void close() {
        tc.reset();
        if (tree_svc) tree_svc->stop();
        tree_svc.reset();
        if (storage) storage->stop();
        storage.reset();
    }

    /// A create op for group `id` by the root key, sealed by this server.
    tree::TreeOp create_group(const std::string& id) {
        tree::TreeOp op;
        op.kind = tree::TreeOpKind::CreateNode;
        op.target = id;
        op.principal = root_key;
        op.body.source = tree::TreeOpSource::Session;
        op.body.node = node(id, "root", tree::NodeType::Customer, root_key);
        op.network_id = network;
        op.signed_at = kBlockTimeMs / 1000;
        crypto_svc.random_bytes(std::span<uint8_t>(op.nonce));
        tree::sign_tree_op(crypto_svc, op, server_kp);
        return op;
    }

    crypto::Ed25519Keypair server_kp;
    sec::NodeId self{};
    sec::Digest pre_merge{};
    std::unique_ptr<storage::FileStorageService> storage;
    std::unique_ptr<tree::PermissionTreeService> tree_svc;
    std::unique_ptr<tree::TreeConsensus> tc;
    bool started = false;
};

TEST_F(TreeMergeLogTest, WritesAreRefusedUntilTheMergeThenTheMergedTreeTakesOps) {
    ASSERT_TRUE(started) << tc->halt_reason();
    EXPECT_TRUE(tc->awaiting_merge());
    EXPECT_TRUE(tc->status_summary().healthy);  // the updater's health gate passes
    EXPECT_EQ(tc->status_summary().pre_merge_nodes, 2u);
    // Before the merge: the tree is served, and writes are refused with a
    // retryable reason. Nothing is queued, so nothing applies twice later.
    EXPECT_TRUE(tree_svc->get_node("local-group").has_value());
    const auto refused = tc->submit(create_group("early"));
    EXPECT_EQ(refused.verdict.refusal, tree::TreeOpRefusal::Unavailable);
    EXPECT_EQ(tc->log().height(), 0u);

    // The root-signed merge commit arrives: the merged tree replaces the
    // pre-merge tree, as the commit says.
    const auto merged = merged_nodes();
    EXPECT_EQ(tc->receive_replicated(signed_commit(merged, root_kp)),
              tree::ReplicaResult::Applied);
    EXPECT_FALSE(tc->awaiting_merge());
    EXPECT_EQ(tc->log().height(), 1u);
    EXPECT_EQ(tc->log().applied_height(), 1u);
    EXPECT_EQ(tree_svc->tree_digest(), tree::compute_tree_digest(merged));
    EXPECT_FALSE(tree_svc->get_node("local-group").has_value());  // it was not in the merge
    EXPECT_TRUE(tree_svc->get_node("d2").has_value());

    // From now on a write is a tree operation: it is admitted for ordering.
    const auto admitted = tc->submit(create_group("later"));
    EXPECT_TRUE(admitted.verdict.ok()) << admitted.verdict.reason;
    EXPECT_NE(admitted.ticket, nullptr);
    EXPECT_FALSE(tree_svc->get_node("later").has_value());  // applied only after commit
}

TEST_F(TreeMergeLogTest, ARestartWhileAwaitingKeepsThePreMergeTree) {
    ASSERT_TRUE(started);
    restart();
    ASSERT_TRUE(started) << tc->halt_reason();
    EXPECT_TRUE(tc->awaiting_merge());
    EXPECT_EQ(tree_svc->tree_digest(), pre_merge);
    EXPECT_EQ(tc->log().height(), 0u);
}

TEST_F(TreeMergeLogTest, ACrashBetweenAppendAndApplyIsRepairedFromTheLog) {
    ASSERT_TRUE(started);
    close();
    // The commit reached the log, but the process stopped before the tree
    // followed it (applied.json still says 0).
    {
        tree::TreeLog log(dir / "data" / "tree" / "log");
        ASSERT_EQ(log.open(tree::rules::NodeMap{}), tree::TreeLog::OpenResult::Ok);
        const auto entry = signed_commit(merged_nodes(), root_kp);
        auto next = log.state();
        ASSERT_TRUE(tree::replay_entry(next, entry).verdict.ok());
        ASSERT_TRUE(log.append(entry, std::move(next)));
        EXPECT_EQ(log.applied_height(), 0u);
    }
    open_tree();
    EXPECT_EQ(tree_svc->tree_digest(), pre_merge);
    start();
    ASSERT_TRUE(started) << tc->halt_reason();
    EXPECT_FALSE(tc->awaiting_merge());
    EXPECT_EQ(tree_svc->tree_digest(), tree::compute_tree_digest(merged_nodes()));
    EXPECT_EQ(tc->log().applied_height(), 1u);
}

TEST_F(TreeMergeLogTest, AForgedOrUnsignedMergeIsRefusedAndTheServerKeepsWaiting) {
    ASSERT_TRUE(started);
    const auto forged = signed_commit(merged_nodes(), other_kp);
    EXPECT_EQ(tc->receive_replicated(forged), tree::ReplicaResult::Refused);
    auto unsigned_entry = *tree::build_merge_entry(merged_nodes(), kBlockTimeMs, network, root_key);
    EXPECT_EQ(tc->receive_replicated(unsigned_entry), tree::ReplicaResult::Refused);
    EXPECT_EQ(tc->log().height(), 0u);
    EXPECT_TRUE(tc->healthy());
    EXPECT_TRUE(tc->awaiting_merge());
    EXPECT_EQ(tree_svc->tree_digest(), pre_merge);
    EXPECT_NE(tc->status_summary().last_refusal.find("merge"), std::string::npos);
    // The genuine commit still installs.
    EXPECT_EQ(tc->receive_replicated(signed_commit(merged_nodes(), root_kp)),
              tree::ReplicaResult::Applied);
}

TEST_F(TreeMergeLogTest, ASecondMergeIsRefused) {
    ASSERT_TRUE(started);
    ASSERT_EQ(tc->receive_replicated(signed_commit(merged_nodes(), root_kp)),
              tree::ReplicaResult::Applied);
    // A second merge is height 1 again: this log already holds height 1.
    auto nodes = merged_nodes();
    nodes.erase("d2");
    EXPECT_EQ(tc->receive_replicated(signed_commit(nodes, root_kp)), tree::ReplicaResult::Refused);
    EXPECT_EQ(tc->log().state().nodes.size(), 5u);
    // Renumbered as height 2 it does not verify: a merge is valid only at 1.
    auto later = signed_commit(nodes, root_kp);
    later.height = 2;
    EXPECT_EQ(tc->receive_replicated(later), tree::ReplicaResult::Refused);
    // And a restart keeps the one merge.
    restart();
    ASSERT_TRUE(started) << tc->halt_reason();
    EXPECT_EQ(tc->log().height(), 1u);
    EXPECT_TRUE(tree_svc->get_node("d2").has_value());
}

// =========================================================================
// The supported migration: signed exports, the root holder's build, and the
// rollout across servers
// =========================================================================

class TreeMigrationTest : public TreeMergeTest {
protected:
    void SetUp() override {
        TreeMergeTest::SetUp();
        for (int i = 0; i < 3; ++i) tier1.push_back(crypto_svc.ed25519_keygen());
        root_gossip = crypto_svc.ed25519_keygen();
    }

    tree::SignedMergeInput input() const {
        tree::SignedMergeInput in;
        in.network_id = network;
        in.root_key = root_key;
        in.root_signer = principal_of(root_gossip);
        for (const auto& kp : tier1) in.members.push_back(principal_of(kp));
        in.block_time_ms = kBlockTimeMs;
        return in;
    }

    /// Three Tier 1 trees that differ, and the root server's backup.
    std::vector<nlohmann::json> signed_exports() {
        std::vector<nlohmann::json> docs;
        const std::vector<std::vector<tree::TreeNode>> trees = {
            {tree::make_root_node(root_key),
             node("acme", "root", tree::NodeType::Customer, root_key),
             endpoint("d1", "acme", root_key, "10.64.0.10/32")},
            {tree::make_root_node(root_key)},
            {tree::make_root_node(root_key),
             node("beta", "root", tree::NodeType::Customer, root_key)},
        };
        for (std::size_t i = 0; i < tier1.size(); ++i) {
            tree::TreeExport e;
            e.server = "tier1-" + std::to_string(i);
            e.nodes = trees[i];
            if (i == 0) e.joined_here = {"d1"};
            docs.push_back(tree::sign_tree_export(crypto_svc, tree::tree_export_to_json(e),
                                                  network, tier1[i]));
        }
        tree::TreeExport backup;
        backup.server = "root-server-backup";
        backup.root_server = true;
        backup.nodes = {tree::make_root_node(root_key),
                        node("ns1-group", "root", tree::NodeType::Customer, root_key),
                        endpoint("d9", "ns1-group", root_key, "10.64.0.90/32")};
        backup.joined_here = {"d9"};
        docs.push_back(tree::sign_tree_export(crypto_svc, tree::tree_export_to_json(backup),
                                              network, root_gossip));
        return docs;
    }

    std::vector<crypto::Ed25519Keypair> tier1;
    crypto::Ed25519Keypair root_gossip;
};

TEST_F(TreeMigrationTest, DivergentTreesAndTheBackupMergeIntoOneCommit) {
    const auto build = tree::build_signed_merge(crypto_svc, signed_exports(), input());
    ASSERT_TRUE(build.refusal.empty()) << build.refusal;
    ASSERT_TRUE(build.entry.has_value()) << build.report.dump();
    for (const char* id : {"root", "acme", "d1", "beta", "ns1-group", "d9"}) {
        EXPECT_TRUE(build.result.nodes.contains(id)) << id;
    }
    EXPECT_EQ(build.report["signers"].size(), 4u);
    EXPECT_EQ(build.report["tree_digest"], crypto::to_base64(build.entry->tree_digest));

    // The same input in another order builds the same commit.
    auto docs = signed_exports();
    std::reverse(docs.begin(), docs.end());
    const auto again = tree::build_signed_merge(crypto_svc, docs, input());
    ASSERT_TRUE(again.entry.has_value());
    EXPECT_EQ(again.entry->state_root, build.entry->state_root);
    EXPECT_EQ(again.preimage, build.preimage);
}

TEST_F(TreeMigrationTest, ForgedMissingOrExtraExportsAreRefused) {
    const auto refused = [&](std::vector<nlohmann::json> docs) {
        return !tree::build_signed_merge(crypto_svc, docs, input()).refusal.empty();
    };
    // A node changed after signing.
    auto docs = signed_exports();
    docs[0]["nodes"][0] = docs[1]["nodes"][0];
    docs[0]["nodes"].push_back(docs[2]["nodes"][1]);
    EXPECT_TRUE(refused(docs));
    // A member's export is missing: its tree would be lost.
    docs = signed_exports();
    docs.erase(docs.begin() + 1);
    EXPECT_TRUE(refused(docs));
    // A server that is not a member signed an export.
    docs = signed_exports();
    tree::TreeExport stray;
    stray.server = "stray";
    stray.nodes = {tree::make_root_node(root_key)};
    docs.push_back(tree::sign_tree_export(crypto_svc, tree::tree_export_to_json(stray), network,
                                          other_kp));
    EXPECT_TRUE(refused(docs));
    // One member signed two exports.
    docs = signed_exports();
    docs[1] = tree::sign_tree_export(crypto_svc, docs[1], network, tier1[0]);
    EXPECT_TRUE(refused(docs));
    // A member claims to be the root server.
    docs = signed_exports();
    auto claimed = docs[1];
    claimed["root_server"] = true;
    docs[1] = tree::sign_tree_export(crypto_svc, claimed, network, tier1[1]);
    EXPECT_TRUE(refused(docs));
    // An export for another network.
    docs = signed_exports();
    sec::NetworkId other_network{};
    other_network.fill(0x43);
    docs[2] = tree::sign_tree_export(crypto_svc, docs[2], other_network, tier1[2]);
    EXPECT_TRUE(refused(docs));
    // An unsigned export.
    docs = signed_exports();
    docs[0].erase("signature");
    EXPECT_TRUE(refused(docs));
}

TEST_F(TreeMigrationTest, ExportRequestsAreRootSignedFreshTargetedAndSingleUse) {
    const auto target = principal_of(tier1[0]);
    const std::string nonce(32, 'a');
    const auto make = [&](uint64_t issued, const crypto::Ed25519Keypair& signer,
                          const std::string& to = "") {
        const auto text = tree::tree_export_request(network, to.empty() ? target : to, issued,
                                                    nonce);
        const auto sig = crypto_svc.ed25519_sign(
            signer.private_key,
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(text.data()), text.size()));
        return nlohmann::json{{"request", text}, {"signature", crypto::to_base64(sig)}};
    };
    const uint64_t now = kBlockTimeMs;
    std::string why;
    const auto ok = tree::verify_tree_export_request(crypto_svc, make(now, root_kp), network,
                                                     root_key, target, now, why);
    ASSERT_TRUE(ok.has_value()) << why;
    EXPECT_EQ(ok->nonce, nonce);
    EXPECT_FALSE(tree::verify_tree_export_request(crypto_svc, make(now, other_kp), network,
                                                  root_key, target, now, why));
    EXPECT_FALSE(tree::verify_tree_export_request(crypto_svc, make(now, root_kp), network,
                                                  root_key, principal_of(tier1[1]), now, why));
    EXPECT_FALSE(tree::verify_tree_export_request(
        crypto_svc, make(now - tree::kTreeExportRequestWindowMs - 1, root_kp), network, root_key,
        target, now, why));
    sec::NetworkId other_network{};
    other_network.fill(0x43);
    EXPECT_FALSE(tree::verify_tree_export_request(crypto_svc, make(now, root_kp), other_network,
                                                  root_key, target, now, why));
    auto spaced = make(now, root_kp);
    spaced["request"] = " " + spaced["request"].get<std::string>();
    EXPECT_FALSE(tree::verify_tree_export_request(crypto_svc, spaced, network, root_key, target,
                                                  now, why));

    tree::TreeExportNonces nonces;
    EXPECT_TRUE(nonces.admit(nonce, now, now));
    EXPECT_FALSE(nonces.admit(nonce, now, now + 1000));
}

TEST_F(TreeMigrationTest, ExportsCollectTheDevicesJoinedAndTheGroupsCreatedHere) {
    storage::FileStorageService files(dir / "export-data");
    files.start();
    ipam::IPAMService ipam(files);
    ipam.start();
    const auto alloc = ipam.allocate_tunnel_ip("d1");
    ASSERT_FALSE(alloc.base_network.empty());
    storage::SignedDelta delta;
    delta.operation = "create_node";
    delta.target_node_id = "acme";
    delta.data = "{}";
    ASSERT_NE(files.append_delta(delta), 0u);

    tree::rules::NodeMap nodes;
    nodes["root"] = tree::make_root_node(root_key);
    nodes["acme"] = node("acme", "root", tree::NodeType::Customer, root_key);
    nodes["d1"] = endpoint("d1", "acme", root_key, alloc.base_network);
    nodes["d2"] = endpoint("d2", "acme", root_key, "10.64.9.9/32");  // another server's address
    const auto exported = tree::collect_tree_export("tier1-x", false, nodes, ipam, files);
    EXPECT_EQ(exported.nodes.size(), 4u);
    EXPECT_EQ(exported.joined_here, (std::set<std::string>{"d1"}));
    EXPECT_EQ(exported.created_here, (std::set<std::string>{"acme"}));
    ipam.stop();
    files.stop();
}

// The rollout: old and new releases run side by side for a while. A new
// server awaits the merge and votes for no tree block, so no tree block can
// take height 1 before the merge commit. Once every server runs the new
// release, the root holder signs the merge and any server delivers it; every
// other server verifies it for itself and follows.
TEST_F(TreeMigrationTest, EveryAwaitingServerAdoptsTheSameMergeFromAnyCarrier) {
    const auto build = tree::build_signed_merge(crypto_svc, signed_exports(), input());
    ASSERT_TRUE(build.entry.has_value());
    const auto preimage = build.preimage;
    const auto sig = crypto_svc.ed25519_sign(
        root_kp.private_key,
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(preimage.data()),
                                 preimage.size()));
    const auto commit = tree::attach_merge_signature(*build.entry, sig);

    std::vector<std::unique_ptr<storage::FileStorageService>> storages;
    std::vector<std::unique_ptr<tree::PermissionTreeService>> trees;
    std::vector<std::unique_ptr<tree::TreeConsensus>> servers;
    for (std::size_t i = 0; i < tier1.size(); ++i) {
        storages.push_back(std::make_unique<storage::FileStorageService>(
            dir / ("rollout-" + std::to_string(i))));
        storages.back()->start();
        trees.push_back(std::make_unique<tree::PermissionTreeService>(*storages.back(), crypto_svc));
        trees.back()->start();
        // Each server's own pre-merge tree.
        const auto doc = signed_exports()[i];
        const auto exported = tree::tree_export_from_json(doc);
        ASSERT_TRUE(exported.has_value());
        ASSERT_TRUE(test_support::put_nodes(*trees.back(), exported->nodes));
        tree::TreeConsensusConfig config;
        config.self.bytes = tier1[i].public_key;
        config.network_id = network;
        config.root_key = root_key;
        config.wall_clock_ms = [] { return kBlockTimeMs + 1000; };
        servers.push_back(std::make_unique<tree::TreeConsensus>(
            std::move(config), *trees.back(), crypto_svc,
            dir / ("rollout-" + std::to_string(i)) / "tree" / "log"));
        ASSERT_TRUE(servers.back()->start());
        EXPECT_TRUE(servers.back()->awaiting_merge());
    }
    // Server 0 gets the commit; it carries it to the others in the wire form.
    ASSERT_EQ(servers[0]->receive_replicated(commit), tree::ReplicaResult::Applied);
    const auto bytes = servers[0]->encoded_entry(1);
    ASSERT_TRUE(bytes.has_value());
    for (std::size_t i = 1; i < servers.size(); ++i) {
        const auto carried = tree::decode_replicated_entry(*bytes);
        ASSERT_TRUE(carried.has_value());
        EXPECT_EQ(servers[i]->receive_replicated(*carried), tree::ReplicaResult::Applied);
    }
    for (std::size_t i = 0; i < servers.size(); ++i) {
        EXPECT_FALSE(servers[i]->awaiting_merge());
        EXPECT_EQ(servers[i]->status_summary().root, commit.state_root);
        EXPECT_EQ(trees[i]->tree_digest(), commit.tree_digest);
        EXPECT_TRUE(trees[i]->get_node("d9").has_value());  // the backup's device
    }
    servers.clear();
    for (auto& t : trees) t->stop();
    for (auto& s : storages) s->stop();
}

// The root holder's control socket steps (TreeMigrationControl.hpp): the key
// signs a request for a current member, and a merge only after the dry run's
// tree digest matches the rebuilt one.
TEST_F(TreeMigrationTest, TheRootHolderSignsOnlyTheReviewedMerge) {
    bool holds = true;
    core::TreeMigrationHooks hooks;
    hooks.crypto = &crypto_svc;
    hooks.wall_clock_ms = [] { return kBlockTimeMs; };
    hooks.random_nonce_hex = [] { return std::string(32, 'b'); };
    hooks.facts = [&] {
        core::TreeMigrationFacts f;
        f.network_id = network;
        f.root_key = root_key;
        f.holds_root_key = holds;
        f.signer = principal_of(root_gossip);
        f.membership_known = true;
        for (const auto& kp : tier1) f.members.push_back({principal_of(kp), "", 0, ""});
        return f;
    };
    hooks.sign_with_root_key =
        [&](std::span<const uint8_t> message) -> std::optional<crypto::Ed25519Signature> {
        if (!holds) return std::nullopt;
        return crypto_svc.ed25519_sign(root_kp.private_key, message);
    };
    hooks.export_backup = [](const fs::path&, std::string& error) -> std::optional<nlohmann::json> {
        error = "no backup in this test";
        return std::nullopt;
    };
    const auto call = [&](nlohmann::json request) {
        return core::handle_tree_migration_request(request, hooks);
    };

    const auto context = call({{"op", "tree_merge_context"}});
    ASSERT_TRUE(context["ok"].get<bool>());
    EXPECT_EQ(context["members"].size(), 3u);
    EXPECT_TRUE(context["holds_root_key"].get<bool>());

    // A request for a member verifies on that member; none for a stranger.
    const auto request = call({{"op", "tree_merge_request"}, {"target", principal_of(tier1[2])}});
    ASSERT_TRUE(request["ok"].get<bool>()) << request.dump();
    std::string why;
    EXPECT_TRUE(tree::verify_tree_export_request(crypto_svc, request["body"], network, root_key,
                                                 principal_of(tier1[2]), kBlockTimeMs, why))
        << why;
    EXPECT_FALSE(call({{"op", "tree_merge_request"}, {"target", principal_of(other_kp)}})["ok"]
                     .get<bool>());

    // Dry run, then the signature for exactly that tree.
    nlohmann::json exports = signed_exports();
    const auto dry = call({{"op", "tree_merge_build"}, {"exports", exports},
                           {"block_time_ms", kBlockTimeMs}});
    ASSERT_TRUE(dry["ok"].get<bool>()) << dry.dump();
    const auto digest = dry["report"]["tree_digest"].get<std::string>();
    EXPECT_FALSE(call({{"op", "tree_merge_sign"}, {"exports", exports},
                       {"block_time_ms", kBlockTimeMs}, {"tree_digest", "AAAA"}})["ok"]
                     .get<bool>());
    EXPECT_FALSE(call({{"op", "tree_merge_sign"}, {"exports", exports},
                       {"block_time_ms", kBlockTimeMs}})["ok"]
                     .get<bool>());
    const auto signed_reply = call({{"op", "tree_merge_sign"}, {"exports", exports},
                                    {"block_time_ms", kBlockTimeMs}, {"tree_digest", digest}});
    ASSERT_TRUE(signed_reply["ok"].get<bool>()) << signed_reply.dump();
    const auto commit = tree::tree_log_entry_from_json(signed_reply["commit"]);
    ASSERT_TRUE(commit.has_value());
    EXPECT_FALSE(tree::verify_merge_signature(crypto_svc, *commit, network, root_key).has_value());

    // A forged export makes the build refuse; nothing is signed.
    auto forged = exports;
    forged[0]["nodes"].push_back(forged[2]["nodes"][1]);
    EXPECT_FALSE(call({{"op", "tree_merge_build"}, {"exports", forged}})["ok"].get<bool>());

    // A server without the root key serves only the context.
    holds = false;
    EXPECT_FALSE(call({{"op", "tree_merge_build"}, {"exports", exports}})["ok"].get<bool>());
    EXPECT_TRUE(call({{"op", "tree_merge_context"}})["ok"].get<bool>());
    holds = true;
    EXPECT_FALSE(call({{"op", "tree_merge_unknown"}})["ok"].get<bool>());
    EXPECT_FALSE(call({{"op", "tree_merge_export_backup"}, {"data_root", "relative"}})["ok"]
                     .get<bool>());
}

// POST /api/tree/merge/export on a Tier 1 member: only while it awaits the
// merge, only for a fresh request the root key signed for it, and only once.
TEST_F(TreeMigrationTest, AMemberExportsItsTreeOnlyForAFreshRootSignedRequest) {
    bool awaiting = true;
    core::TreeMergeExportSource source;
    source.crypto = &crypto_svc;
    source.network_id = network;
    source.root_key = root_key;
    source.self = principal_of(tier1[0]);
    source.keypair = &tier1[0];
    source.awaiting_merge = [&] { return awaiting; };
    source.collect = [&] {
        tree::TreeExport e;
        e.server = "tier1-0";
        e.nodes = {tree::make_root_node(root_key)};
        return e;
    };
    source.wall_clock_ms = [] { return kBlockTimeMs; };
    core::TreeMergeExportEndpoint endpoint(std::move(source));

    const auto request = [&](const crypto::Ed25519Keypair& signer, const std::string& nonce) {
        const auto text =
            tree::tree_export_request(network, principal_of(tier1[0]), kBlockTimeMs, nonce);
        const auto sig = crypto_svc.ed25519_sign(
            signer.private_key,
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(text.data()), text.size()));
        return nlohmann::json{{"request", text}, {"signature", crypto::to_base64(sig)}};
    };
    EXPECT_EQ(endpoint.answer(request(other_kp, std::string(32, '1'))).first, 403);
    const auto [status, body] = endpoint.answer(request(root_kp, std::string(32, '2')));
    ASSERT_EQ(status, 200) << body.dump();
    std::string signer;
    EXPECT_FALSE(tree::verify_tree_export(crypto_svc, body, network, signer).has_value());
    EXPECT_EQ(signer, principal_of(tier1[0]));
    EXPECT_EQ(endpoint.answer(request(root_kp, std::string(32, '2'))).first, 409);  // replay
    awaiting = false;
    EXPECT_EQ(endpoint.answer(request(root_kp, std::string(32, '3'))).first, 409);
}

// Without a backup the root server contributes no tree: the root is the
// application root of the root management key, and every member's tree is
// still required.
TEST_F(TreeMigrationTest, WithoutABackupTheRootComesFromTheRootKey) {
    auto docs = signed_exports();
    docs.pop_back();  // no backup
    // Every member's root differs from the key's root.
    for (auto& doc : docs) {
        auto parsed = *tree::tree_export_from_json(doc);
        for (auto& n : parsed.nodes) {
            if (n.id == "root") n.hostname = "local-" + parsed.server;
        }
        const auto signer = doc["signer"].get<std::string>();
        const auto index = static_cast<std::size_t>(
            std::find_if(tier1.begin(), tier1.end(),
                         [&](const auto& kp) { return principal_of(kp) == signer; }) -
            tier1.begin());
        doc = tree::sign_tree_export(crypto_svc, tree::tree_export_to_json(parsed), network,
                                     tier1[index]);
    }
    const auto build = tree::build_signed_merge(crypto_svc, docs, input());
    ASSERT_TRUE(build.refusal.empty()) << build.refusal;
    ASSERT_TRUE(build.entry.has_value()) << build.report.dump();
    EXPECT_EQ(tree::encode_tree_node(build.result.nodes.at("root")),
              tree::encode_tree_node(tree::make_root_node(root_key)));
    EXPECT_FALSE(build.result.nodes.contains("d9"));  // the backup's device
    EXPECT_TRUE(build.result.nodes.contains("d1"));
    // A member is still required.
    docs.erase(docs.begin());
    EXPECT_FALSE(tree::build_signed_merge(crypto_svc, docs, input()).refusal.empty());
}

// No root server export at all: the merge takes the root by the other rules.
TEST_F(TreeMergeTest, NoRootServerExportIsAllowed) {
    auto exports = two_servers();
    exports[0].root_server = false;
    const auto result = tree::merge_tree_exports(exports, {});
    EXPECT_TRUE(result.conflicts.empty()) << tree::merge_conflicts_to_json(result.conflicts).dump();
    EXPECT_TRUE(result.nodes.contains("root"));
}
