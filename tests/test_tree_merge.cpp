// The tree merge ceremony (docs/Design-Tree-Consensus-and-Storage-Key.md,
// A9): the merge body, the merge rule and its conflict list, the root-signed
// height-1 commit, and how a tree log accepts or refuses that commit.

#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeConsensus.hpp>
#include <LemonadeNexus/Tree/TreeLog.hpp>
#include <LemonadeNexus/Tree/TreeMerge.hpp>
#include <LemonadeNexus/Tree/TreeOps.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
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

TEST_F(TreeMergeTest, TheRootComesFromTheRootServer) {
    auto exports = two_servers();
    exports[1].nodes[0].hostname = "west-root";  // west's root differs
    const auto result = tree::merge_tree_exports(exports, {});
    EXPECT_TRUE(result.conflicts.empty());
    EXPECT_EQ(result.nodes.at("root").hostname, "root");

    exports[0].nodes.erase(exports[0].nodes.begin());  // the root server lost its root
    const auto missing = tree::merge_tree_exports(exports, {});
    EXPECT_NE(conflict_for(missing, "root", "root_missing"), nullptr);
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

TEST_F(TreeMergeTest, UndecidedCopiesAndBrokenStructureAreListed) {
    auto exports = two_servers();
    // A group both servers claim to have created, with different contents.
    auto copy = node("acme", "root", tree::NodeType::Customer, root_key);
    copy.hostname = "west-acme";
    exports[1].nodes.push_back(copy);
    exports[1].created_here.insert("acme");
    // A device whose group exists nowhere.
    exports[1].nodes.push_back(endpoint("d3", "gamma", root_key, "10.64.0.12/32"));
    // Two devices that independent IPAM files gave the same address.
    exports[1].nodes.push_back(endpoint("d4", "beta", root_key, "10.64.0.10/32"));
    const auto result = tree::merge_tree_exports(exports, {});

    const auto* divergent = conflict_for(result, "acme", "divergent");
    ASSERT_NE(divergent, nullptr);
    EXPECT_EQ(divergent->servers, (std::vector<std::string>{"east", "west"}));
    EXPECT_NE(conflict_for(result, "d3", "orphan"), nullptr);
    EXPECT_NE(conflict_for(result, "d1", "duplicate_tunnel_address"), nullptr);
    EXPECT_NE(conflict_for(result, "d4", "duplicate_tunnel_address"), nullptr);

    // The listing is deterministic: export order does not change it.
    std::swap(exports[0], exports[1]);
    const auto again = tree::merge_tree_exports(exports, {});
    EXPECT_EQ(tree::merge_conflicts_to_json(again.conflicts),
              tree::merge_conflicts_to_json(result.conflicts));

    // An admin resolves each one; the merge is then clean.
    const auto resolved = tree::merge_tree_exports(
        exports, {{"acme", "east"}, {"d3", "drop"}, {"d4", "drop"}});
    EXPECT_TRUE(resolved.conflicts.empty())
        << tree::merge_conflicts_to_json(resolved.conflicts).dump();
    EXPECT_FALSE(resolved.nodes.contains("d3"));
    EXPECT_EQ(resolved.nodes.at("acme").hostname, "");
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
// A server's tree log and the commit
// =========================================================================

class TreeMergeLogTest : public TreeMergeTest {
protected:
    void SetUp() override {
        TreeMergeTest::SetUp();
        open(tree::TreeLogMode::ReadOnly);
    }

    void TearDown() override {
        close();
        TreeMergeTest::TearDown();
    }

    void open(tree::TreeLogMode mode) {
        storage = std::make_unique<storage::FileStorageService>(dir / "data");
        storage->start();
        tree_svc = std::make_unique<tree::PermissionTreeService>(*storage, crypto_svc);
        tree_svc->start();
        tree::TreeConsensusConfig config;
        config.self.bytes = other_kp.public_key;
        config.network_id = network;
        config.root_key = root_key;
        config.wall_clock_ms = [] { return kBlockTimeMs + 1000; };
        config.mode = mode;
        tc = std::make_unique<tree::TreeConsensus>(std::move(config), *tree_svc, crypto_svc,
                                                   dir / "data" / "tree" / "log");
        started = tc->start();
    }

    void close() {
        tc.reset();
        if (tree_svc) tree_svc->stop();
        tree_svc.reset();
        if (storage) storage->stop();
        storage.reset();
    }

    std::unique_ptr<storage::FileStorageService> storage;
    std::unique_ptr<tree::PermissionTreeService> tree_svc;
    std::unique_ptr<tree::TreeConsensus> tc;
    bool started = false;
};

TEST_F(TreeMergeLogTest, AReadOnlyServerTakesTheCommitThenOpsModeAdoptsIt) {
    ASSERT_TRUE(started);
    // Release N: a local tree written through the direct paths.
    ASSERT_TRUE(tree_svc->bootstrap_root(tree::make_root_node(root_key)));
    const auto local = tree_svc->tree_digest();

    const auto entry = signed_commit(merged_nodes(), root_kp);
    EXPECT_EQ(tc->receive_replicated(entry), tree::ReplicaResult::Applied);
    EXPECT_EQ(tc->log().height(), 1u);
    EXPECT_EQ(tree_svc->tree_digest(), local);  // read-only: local writes stay
    EXPECT_EQ(tc->receive_replicated(entry), tree::ReplicaResult::Duplicate);

    // Release N+1: the same server restarts in ops mode and its tree becomes
    // the committed, merged tree.
    close();
    open(tree::TreeLogMode::Ops);
    ASSERT_TRUE(started) << tc->halt_reason();
    EXPECT_EQ(tree_svc->tree_digest(), tree::compute_tree_digest(tc->log().state().nodes));
    EXPECT_TRUE(tree_svc->get_node("beta").has_value());
    EXPECT_TRUE(tree_svc->get_node("d1").has_value());
    EXPECT_EQ(tc->log().applied_height(), 1u);
}

TEST_F(TreeMergeLogTest, AHeight1CommitWithABadSignatureIsRefused) {
    ASSERT_TRUE(started);
    const auto forged = signed_commit(merged_nodes(), other_kp);
    EXPECT_EQ(tc->receive_replicated(forged), tree::ReplicaResult::Refused);
    EXPECT_EQ(tc->log().height(), 0u);
    EXPECT_TRUE(tc->healthy());
    EXPECT_NE(tc->status_summary().last_refusal.find("merge"), std::string::npos);
    // The genuine commit still installs.
    EXPECT_EQ(tc->receive_replicated(signed_commit(merged_nodes(), root_kp)),
              tree::ReplicaResult::Applied);
}

TEST_F(TreeMergeLogTest, AMergeCommitDoesNotReplaceALaterLog) {
    ASSERT_TRUE(started);
    ASSERT_EQ(tc->receive_replicated(signed_commit(merged_nodes(), root_kp)),
              tree::ReplicaResult::Applied);
    // A second ceremony's commit is height 1 again: this log already has it.
    auto nodes = merged_nodes();
    nodes.erase("d2");
    EXPECT_EQ(tc->receive_replicated(signed_commit(nodes, root_kp)), tree::ReplicaResult::Refused);
    EXPECT_EQ(tc->log().state().nodes.size(), 5u);
}
