// Tree operations, Phase 1 (docs/Design-Tree-Consensus-and-Storage-Key.md):
// the valid path for every op kind, the required rejection cases, and
// determinism (the same ops on independent trees give identical nodes and
// versions; validation reads the supplied block time, never the wall clock).

#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Routing/IdentifierDerivation.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeOpSubmitter.hpp>
#include <LemonadeNexus/Tree/TreeOps.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <filesystem>
#include <map>
#include <string>
#include "support/tree_seed.hpp"
#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

using namespace nexus;
namespace fs = std::filesystem;
using tree::TreeOp;
using tree::TreeOpKind;
using tree::TreeOpRefusal;
using tree::TreeOpSource;

namespace {

// A fixed block time in 1970. Every op below is signed near it, so an op that
// validates proves validation never compared against the 2020s wall clock.
constexpr uint64_t kBlock = 1'000'000;

std::string b64(const crypto::Ed25519PublicKey& pk) {
    return crypto::to_base64(std::span<const uint8_t>(pk.data(), pk.size()));
}

std::string principal_of(const crypto::Ed25519Keypair& kp) { return "ed25519:" + b64(kp.public_key); }

}  // namespace

class TreeOpsTest : public ::testing::Test {
protected:
    fs::path temp_root;
    std::unique_ptr<crypto::SodiumCryptoService> crypto_svc;
    std::unique_ptr<storage::FileStorageService> storage_svc;
    std::unique_ptr<tree::PermissionTreeService> tree_svc;

    crypto::Ed25519Keypair root_kp;
    crypto::Ed25519Keypair server_kp;
    crypto::Ed25519Keypair stranger_kp;
    std::string root_pk;
    security::NetworkId network{};
    tree::TreeOpPolicy policy;

    void SetUp() override {
        temp_root = fs::temp_directory_path() /
                    ("nexus_test_tree_ops_" + std::to_string(getpid()));
        fs::remove_all(temp_root);
        fs::create_directories(temp_root);

        crypto_svc = std::make_unique<crypto::SodiumCryptoService>();
        crypto_svc->start();
        root_kp = crypto_svc->ed25519_keygen();
        server_kp = crypto_svc->ed25519_keygen();
        stranger_kp = crypto_svc->ed25519_keygen();
        root_pk = principal_of(root_kp);
        network.fill(0x11);
        policy.network_id = network;
        policy.trusted_submitters = {principal_of(server_kp)};

        storage_svc = make_storage("a");
        tree_svc = std::make_unique<tree::PermissionTreeService>(*storage_svc, *crypto_svc);
        tree_svc->start();
    }

    void TearDown() override {
        tree_svc->stop();
        storage_svc->stop();
        crypto_svc->stop();
        fs::remove_all(temp_root);
    }

    /// Storage under temp_root/<name> holding a self-signed root.
    std::unique_ptr<storage::FileStorageService> make_storage(const std::string& name) {
        auto storage = std::make_unique<storage::FileStorageService>(temp_root / name);
        storage->start();
        tree::TreeNode root;
        root.id = "root";
        root.type = tree::NodeType::Root;
        root.mgmt_pubkey = root_pk;
        root.assignments = {{root_pk, {"admin"}}};
        const auto canonical = tree::canonical_node_json(root);
        root.signature = crypto::to_base64(crypto_svc->ed25519_sign(
            root_kp.private_key,
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(canonical.data()),
                                     canonical.size())));
        storage::SignedEnvelope env;
        env.version = 1;
        env.type = "tree_node";
        env.data = nlohmann::json(root).dump();
        env.signer_pubkey = root_pk;
        env.signature = root.signature;
        EXPECT_TRUE(storage->write_node("root", env));
        return storage;
    }

    /// Bind to the network, set the signed time, and sign with the server key.
    TreeOp seal(TreeOp op, uint64_t signed_at = kBlock,
                const crypto::Ed25519Keypair* key = nullptr) {
        op.network_id = network;
        op.signed_at = signed_at;
        tree::sign_tree_op(*crypto_svc, op, key ? *key : server_kp);
        return op;
    }

    tree::TreeOpVerdict submit(const TreeOp& op, uint64_t block = kBlock,
                               tree::PermissionTreeService* svc = nullptr) {
        return (svc ? *svc : *tree_svc).submit_local_op(op, policy, block);
    }

    uint64_t version_of(const std::string& id) {
        auto n = tree_svc->get_node(id);
        return n ? n->version : 0;
    }

    TreeOp create_op(const tree::TreeNode& node, const std::string& principal) {
        TreeOp op;
        op.kind = TreeOpKind::CreateNode;
        op.target = node.id;
        op.principal = principal;
        op.body.source = TreeOpSource::Session;
        op.body.node = node;
        return op;
    }

    TreeOp update_op(const tree::TreeNode& node, const std::string& principal,
                     uint64_t base_version) {
        TreeOp op;
        op.kind = TreeOpKind::UpdateFields;
        op.target = node.id;
        op.base_version = base_version;
        op.principal = principal;
        op.body.source = TreeOpSource::Session;
        op.body.node = node;
        return op;
    }

    TreeOp assign_op(const std::string& target, const std::string& principal,
                     const std::string& who, std::vector<std::string> perms) {
        TreeOp op;
        op.kind = TreeOpKind::SetAssignment;
        op.target = target;
        op.base_version = version_of(target);
        op.principal = principal;
        op.body.source = TreeOpSource::Session;
        op.body.assignment_principal = who;
        op.body.assignment_permissions = std::move(perms);
        return op;
    }

    TreeOp delete_op(const std::string& target, const std::string& principal) {
        TreeOp op;
        op.kind = TreeOpKind::DeleteNode;
        op.target = target;
        op.base_version = version_of(target);
        op.principal = principal;
        op.body.source = TreeOpSource::Session;
        return op;
    }

    tree::TreeDelta signed_delta(const std::string& operation, const std::string& target,
                                 const tree::TreeNode& data, const crypto::Ed25519Keypair& kp,
                                 uint64_t timestamp = kBlock) {
        tree::TreeDelta d;
        d.operation = operation;
        d.target_node_id = target;
        d.node_data = data;
        d.signer_pubkey = principal_of(kp);
        d.timestamp = timestamp;
        const auto canonical = tree::canonical_delta_json(d);
        d.signature = crypto::to_base64(crypto_svc->ed25519_sign(
            kp.private_key,
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(canonical.data()),
                                     canonical.size())));
        return d;
    }

    /// Wrap a delta the way the delta route does.
    TreeOp delta_op(const tree::TreeDelta& d) {
        TreeOp op;
        if (d.operation == "create_node") {
            op.kind = TreeOpKind::CreateNode;
            op.target = d.node_data.id;
        } else if (d.operation == "delete_node") {
            op.kind = TreeOpKind::DeleteNode;
            op.target = d.target_node_id;
        } else {
            op.kind = TreeOpKind::UpdateFields;
            op.target = d.target_node_id;
        }
        if (op.kind != TreeOpKind::CreateNode) op.base_version = version_of(op.target);
        op.principal = d.signer_pubkey;
        op.body.source = TreeOpSource::Delta;
        op.body.delta = d;
        return op;
    }

    /// A Join op for `device`, with a fresh challenge the device signed. A
    /// nonempty `hostname` is the device name the join carries.
    TreeOp join_op(const crypto::Ed25519Keypair& device,
                   const std::string& link_group = {}, const std::string& link_owner = {},
                   const std::string& mesh_pubkey = {}, const std::string& hostname = {}) {
        std::array<uint8_t, 32> challenge{};
        crypto_svc->random_bytes(std::span<uint8_t>(challenge));
        const auto sig = crypto_svc->ed25519_sign(device.private_key,
                                                  std::span<const uint8_t>(challenge));
        TreeOp op;
        op.kind = TreeOpKind::Join;
        op.principal = principal_of(device);
        op.target = tree::derive_join_node_id(*crypto_svc, op.principal);
        op.base_version = version_of(op.target);
        op.body.source = TreeOpSource::Device;
        auto& js = op.body.join;
        js.device_pubkey = op.principal;
        js.challenge = crypto::to_base64(std::span<const uint8_t>(challenge));
        js.challenge_signature = crypto::to_base64(std::span<const uint8_t>(sig.data(), sig.size()));
        js.region = "us-east";
        js.cpu_id = "cpu";
        js.net_mac = "mac";
        js.mesh_pubkey_present = !mesh_pubkey.empty();
        js.mesh_pubkey = mesh_pubkey;
        js.hostname_present = !hostname.empty();
        js.hostname = hostname;
        js.link_group_id = link_group;
        js.link_owner_pubkey = link_owner;
        return op;
    }

    /// A device node stored under `parent` with `hostname`, owned and
    /// editable by the root key, as a record from before a rule existed.
    tree::TreeNode stored_device(const std::string& id, const std::string& parent,
                                 const std::string& hostname) {
        tree::TreeNode n;
        n.id = id;
        n.parent_id = parent;
        n.type = tree::NodeType::Endpoint;
        n.hostname = hostname;
        n.mgmt_pubkey = root_pk;
        n.assignments = {{root_pk, {"read", "edit_node"}}};
        return n;
    }

    tree::TreeNode customer(const std::string& id, const std::string& owner) {
        tree::TreeNode n;
        n.id = id;
        n.parent_id = "root";
        n.type = tree::NodeType::Customer;
        n.mgmt_pubkey = owner;
        n.assignments = {{owner, {"admin"}}};
        return n;
    }
};

// =========================================================================
// Valid path, every kind
// =========================================================================

TEST_F(TreeOpsTest, CreateNodeFromSessionApplies) {
    auto v = submit(seal(create_op(customer("acme", root_pk), root_pk)));
    ASSERT_TRUE(v.ok()) << v.reason;
    auto n = tree_svc->get_node("acme");
    ASSERT_TRUE(n.has_value());
    EXPECT_EQ(n->version, 1u);
    EXPECT_EQ(n->parent_id, "root");
    EXPECT_EQ(version_of("root"), 0u) << "the parent is not written by a create";
}

TEST_F(TreeOpsTest, CreateNodeFromDeltaApplies) {
    auto d = signed_delta("create_node", "acme", customer("acme", root_pk), root_kp);
    auto v = submit(seal(delta_op(d), d.timestamp));
    ASSERT_TRUE(v.ok()) << v.reason;
    EXPECT_EQ(version_of("acme"), 1u);
}

TEST_F(TreeOpsTest, UpdateFieldsIncrementsVersion) {
    ASSERT_TRUE(submit(seal(create_op(customer("acme", root_pk), root_pk))).ok());
    auto node = *tree_svc->get_node("acme");
    node.hostname = "acme-renamed";
    auto v = submit(seal(update_op(node, root_pk, 1), kBlock + 1));
    ASSERT_TRUE(v.ok()) << v.reason;
    EXPECT_EQ(tree_svc->get_node("acme")->hostname, "acme-renamed");
    EXPECT_EQ(version_of("acme"), 2u);
}

TEST_F(TreeOpsTest, UpdateFieldsFromDeltaApplies) {
    ASSERT_TRUE(submit(seal(create_op(customer("acme", root_pk), root_pk))).ok());
    auto data = customer("acme", root_pk);
    data.shared_domain = "acme.example";
    auto d = signed_delta("update_node", "acme", data, root_kp, kBlock + 2);
    auto v = submit(seal(delta_op(d), d.timestamp), kBlock + 2);
    ASSERT_TRUE(v.ok()) << v.reason;
    EXPECT_EQ(tree_svc->get_node("acme")->shared_domain, "acme.example");
    EXPECT_EQ(version_of("acme"), 2u);
}

TEST_F(TreeOpsTest, SetAssignmentApplies) {
    ASSERT_TRUE(submit(seal(create_op(customer("acme", root_pk), root_pk))).ok());
    auto device = crypto_svc->ed25519_keygen();
    ASSERT_TRUE(submit(seal(join_op(device, "acme", root_pk))).ok());
    const auto before = version_of("acme");

    auto v = submit(seal(assign_op("acme", root_pk, principal_of(device),
                                   {"read", "edit_node", "read"})));
    ASSERT_TRUE(v.ok()) << v.reason;
    EXPECT_TRUE(tree_svc->check_permission(principal_of(device), "acme",
                                           acl::Permission::EditNode));
    EXPECT_EQ(version_of("acme"), before + 1);
}

TEST_F(TreeOpsTest, DeleteNodeRemovesNodeAndSweepsLinkGrants) {
    ASSERT_TRUE(submit(seal(create_op(customer("acme", root_pk), root_pk))).ok());
    auto dev1 = crypto_svc->ed25519_keygen();
    auto dev2 = crypto_svc->ed25519_keygen();
    ASSERT_TRUE(submit(seal(join_op(dev1, "acme", root_pk))).ok());
    ASSERT_TRUE(submit(seal(join_op(dev2, "acme", root_pk))).ok());
    const auto id1 = tree::derive_join_node_id(*crypto_svc, principal_of(dev1));
    const auto id2 = tree::derive_join_node_id(*crypto_svc, principal_of(dev2));
    ASSERT_TRUE(tree_svc->check_permission(principal_of(dev2), id1, acl::Permission::Read));
    const auto sibling_version = version_of(id1);

    auto v = submit(seal(delete_op(id2, root_pk)));
    ASSERT_TRUE(v.ok()) << v.reason;
    EXPECT_FALSE(tree_svc->get_node(id2).has_value());
    EXPECT_FALSE(tree_svc->check_permission(principal_of(dev2), id1, acl::Permission::Read));
    EXPECT_FALSE(tree_svc->check_permission(principal_of(dev2), "acme", acl::Permission::Read));
    EXPECT_EQ(version_of(id1), sibling_version + 1) << "the sweep writes the sibling";
}

TEST_F(TreeOpsTest, DeleteNodeFromDeltaApplies) {
    ASSERT_TRUE(submit(seal(create_op(customer("acme", root_pk), root_pk))).ok());
    auto d = signed_delta("delete_node", "acme", tree::TreeNode{}, root_kp, kBlock + 3);
    auto v = submit(seal(delta_op(d), d.timestamp), kBlock + 3);
    ASSERT_TRUE(v.ok()) << v.reason;
    EXPECT_FALSE(tree_svc->get_node("acme").has_value());
}

// A group admin removes a device it holds no entry on through the API (a
// session op). A signed delta keeps the stricter
// rule: delete_node on the node itself.
TEST_F(TreeOpsTest, GroupAdminRemovesDevicesThroughTheApiOnly) {
    auto owner = crypto_svc->ed25519_keygen();
    auto device = crypto_svc->ed25519_keygen();
    const auto owner_pk = principal_of(owner);
    ASSERT_TRUE(submit(seal(create_op(customer("acme", owner_pk), root_pk))).ok());
    tree::TreeNode node;
    node.id = "acme-dev";
    node.parent_id = "acme";
    node.type = tree::NodeType::Endpoint;
    node.mgmt_pubkey = principal_of(device);
    node.assignments = {{principal_of(device), {"read", "edit_node"}}};
    ASSERT_TRUE(submit(seal(create_op(node, owner_pk))).ok());
    ASSERT_FALSE(tree_svc->check_permission(owner_pk, "acme-dev", acl::Permission::DeleteNode));

    auto d = signed_delta("delete_node", "acme-dev", tree::TreeNode{}, owner, kBlock + 1);
    EXPECT_EQ(submit(seal(delta_op(d), d.timestamp), kBlock + 1).refusal,
              TreeOpRefusal::Forbidden);
    EXPECT_TRUE(tree_svc->get_node("acme-dev").has_value());

    auto v = submit(seal(delete_op("acme-dev", owner_pk)), kBlock + 2);
    ASSERT_TRUE(v.ok()) << v.reason;
    EXPECT_FALSE(tree_svc->get_node("acme-dev").has_value());

    // The device itself administers nothing above its node.
    auto other = node;
    other.id = "acme-dev-2";
    ASSERT_TRUE(submit(seal(create_op(other, owner_pk)), kBlock + 3).ok());
    EXPECT_EQ(submit(seal(delete_op("acme-dev-2", principal_of(device))), kBlock + 4).refusal,
              TreeOpRefusal::Forbidden);
}

TEST_F(TreeOpsTest, JoinCreatesGroupAndEndpoint) {
    auto device = crypto_svc->ed25519_keygen();
    auto op = join_op(device);
    const auto node_id = op.target;
    // The address is a function of the tree before the join.
    const auto expected_ip = tree::derive_tunnel_address(tree_svc->nodes_snapshot(), node_id);
    auto v = submit(seal(op));
    ASSERT_TRUE(v.ok()) << v.reason;

    auto group = tree_svc->get_node("customer-" + node_id);
    ASSERT_TRUE(group.has_value());
    EXPECT_EQ(group->version, 1u);
    EXPECT_TRUE(tree_svc->check_permission(principal_of(device), group->id,
                                           acl::Permission::Admin));
    auto ep = tree_svc->get_node(node_id);
    ASSERT_TRUE(ep.has_value());
    EXPECT_EQ(ep->version, 1u);
    EXPECT_EQ(ep->parent_id, group->id);
    EXPECT_EQ(ep->tunnel_ip, expected_ip);
    EXPECT_FALSE(expected_ip.empty());
    EXPECT_EQ(ep->hostname, "endpoint-" + node_id.substr(0, 8));
    // Re-derived in the apply step, not taken from the submitter.
    EXPECT_EQ(ep->endpoint_identifier,
              routing::derive_endpoint_identifier(node_id, "us-east", "cpu", "mac", false));
    EXPECT_EQ(tree_svc->resolve_by_identifier(ep->endpoint_identifier)->id, node_id);
}

TEST_F(TreeOpsTest, LinkedJoinGrantsSiblingsInSortedOrder) {
    ASSERT_TRUE(submit(seal(create_op(customer("acme", root_pk), root_pk))).ok());
    std::vector<crypto::Ed25519Keypair> devices;
    for (int i = 0; i < 4; ++i) {
        devices.push_back(crypto_svc->ed25519_keygen());
        auto v = submit(seal(join_op(devices.back(),
                                     "acme", root_pk)));
        ASSERT_TRUE(v.ok()) << v.reason;
    }
    const auto last = tree::derive_join_node_id(*crypto_svc, principal_of(devices.back()));
    auto node = *tree_svc->get_node(last);
    // Own entry, owner entry, then one grant per earlier sibling sorted by id.
    ASSERT_EQ(node.assignments.size(), 5u);
    std::vector<std::string> sibling_ids;
    for (std::size_t i = 0; i + 1 < devices.size(); ++i) {
        sibling_ids.push_back(tree::derive_join_node_id(*crypto_svc, principal_of(devices[i])));
    }
    std::sort(sibling_ids.begin(), sibling_ids.end());
    for (std::size_t i = 0; i < sibling_ids.size(); ++i) {
        EXPECT_EQ(node.assignments[2 + i].management_pubkey,
                  tree_svc->get_node(sibling_ids[i])->mgmt_pubkey);
        EXPECT_TRUE(tree_svc->check_permission(principal_of(devices.back()), sibling_ids[i],
                                               acl::Permission::ConnectPrivate));
    }
}

TEST_F(TreeOpsTest, ReturningJoinRecordsAddressAndRotatedKey) {
    auto device = crypto_svc->ed25519_keygen();
    ASSERT_TRUE(submit(seal(join_op(device, {}, {}, "meshA"))).ok());
    const auto node_id = tree::derive_join_node_id(*crypto_svc, principal_of(device));
    ASSERT_EQ(version_of(node_id), 1u);

    // Same address, rotated key: the node is rewritten once.
    ASSERT_TRUE(submit(seal(join_op(device, {}, {}, "meshB"))).ok());
    EXPECT_EQ(tree_svc->get_node(node_id)->mesh_pubkey, "meshB");
    EXPECT_EQ(version_of(node_id), 2u);

    // Nothing changed: no write, no version increment.
    ASSERT_TRUE(submit(seal(join_op(device, {}, {}, "meshB"))).ok());
    EXPECT_EQ(version_of(node_id), 2u);
}

// Device names fold to one mesh-port label (tree::device_label). A join, a
// create, or a rename that gives a device the label a sibling holds, or no
// label at all, is refused in the apply step, so every replica refuses it.
TEST_F(TreeOpsTest, DeviceNamesFoldToOneLabelPerGroup) {
    ASSERT_TRUE(submit(seal(create_op(customer("acme", root_pk), root_pk))).ok());
    ASSERT_TRUE(submit(seal(create_op(customer("beta", root_pk), root_pk))).ok());
    auto first = crypto_svc->ed25519_keygen();
    auto v = submit(seal(join_op(first, "acme", root_pk, {}, "Work PC")));
    ASSERT_TRUE(v.ok()) << v.reason;
    const auto first_id = tree::derive_join_node_id(*crypto_svc, principal_of(first));
    EXPECT_EQ(tree_svc->get_node(first_id)->hostname, "Work PC");

    // A sibling whose name folds to the same label is refused; the reason
    // names the device that holds the label.
    auto second = crypto_svc->ed25519_keygen();
    const auto second_id = tree::derive_join_node_id(*crypto_svc, principal_of(second));
    auto refused = submit(seal(join_op(second, "acme", root_pk, {}, "work-pc")));
    EXPECT_EQ(refused.refusal, TreeOpRefusal::Conflict);
    EXPECT_NE(refused.reason.find("'Work PC'"), std::string::npos) << refused.reason;
    EXPECT_NE(refused.reason.find(first_id), std::string::npos) << refused.reason;
    EXPECT_NE(refused.reason.find("pick another name"), std::string::npos) << refused.reason;
    EXPECT_FALSE(tree_svc->get_node(second_id).has_value());

    // A name with no letter or digit folds to nothing and is refused.
    auto blank = submit(seal(join_op(second, "acme", root_pk, {}, "***")));
    EXPECT_EQ(blank.refusal, TreeOpRefusal::Conflict);
    EXPECT_NE(blank.reason.find("pick another name"), std::string::npos) << blank.reason;

    // Another label joins the group; another group reuses the label.
    v = submit(seal(join_op(second, "acme", root_pk, {}, "Work PC 2")));
    ASSERT_TRUE(v.ok()) << v.reason;
    auto third = crypto_svc->ed25519_keygen();
    v = submit(seal(join_op(third, "beta", root_pk, {}, "work pc")));
    ASSERT_TRUE(v.ok()) << v.reason;

    // A rename to a sibling's label is refused; a rename that keeps the
    // label, with other fields changed, passes.
    auto node = *tree_svc->get_node(second_id);
    node.hostname = "WORK_PC";
    auto renamed = submit(seal(update_op(node, principal_of(second), node.version)));
    EXPECT_EQ(renamed.refusal, TreeOpRefusal::Conflict);
    EXPECT_NE(renamed.reason.find(first_id), std::string::npos) << renamed.reason;
    EXPECT_EQ(tree_svc->get_node(second_id)->hostname, "Work PC 2");
    node.hostname = "work pc 2";
    node.region = "eu-west";
    v = submit(seal(update_op(node, principal_of(second), node.version)));
    ASSERT_TRUE(v.ok()) << v.reason;
    EXPECT_EQ(tree_svc->get_node(second_id)->hostname, "work pc 2");
    node = *tree_svc->get_node(second_id);
    node.hostname = "!!";
    EXPECT_EQ(submit(seal(update_op(node, principal_of(second), node.version))).refusal,
              TreeOpRefusal::Conflict);

    // A session create of a device follows the same rule.
    auto extra = stored_device("node-extra", "acme", "work-pc");
    auto created = submit(seal(create_op(extra, root_pk)));
    EXPECT_EQ(created.refusal, TreeOpRefusal::Conflict);
    EXPECT_FALSE(tree_svc->get_node("node-extra").has_value());
    extra.hostname = "Printer";
    v = submit(seal(create_op(extra, root_pk)));
    ASSERT_TRUE(v.ok()) << v.reason;
}

// A collision stored before the rule stays as it is: the devices keep their
// names and stay editable. Only a change of label is judged.
TEST_F(TreeOpsTest, AStoredNameCollisionStaysEditable) {
    ASSERT_TRUE(submit(seal(create_op(customer("acme", root_pk), root_pk))).ok());
    ASSERT_TRUE(test_support::put_node(*tree_svc, stored_device("node-a", "acme", "Work PC")));
    ASSERT_TRUE(test_support::put_node(*tree_svc, stored_device("node-b", "acme", "work-pc")));

    auto node = *tree_svc->get_node("node-b");
    node.region = "eu-west";
    auto v = submit(seal(update_op(node, root_pk, node.version)));
    ASSERT_TRUE(v.ok()) << v.reason;
    node = *tree_svc->get_node("node-b");
    node.hostname = "Work  PC";  // the same label as before
    v = submit(seal(update_op(node, root_pk, node.version)));
    ASSERT_TRUE(v.ok()) << v.reason;
    EXPECT_EQ(tree_svc->get_node("node-a")->hostname, "Work PC");

    // A third device still cannot take the label.
    EXPECT_EQ(submit(seal(create_op(stored_device("node-c", "acme", "WORK PC"), root_pk))).refusal,
              TreeOpRefusal::Conflict);
}

// =========================================================================
// Rejections
// =========================================================================

TEST_F(TreeOpsTest, ReplayedOpIdIsRefused) {
    const auto op = seal(create_op(customer("acme", root_pk), root_pk));
    ASSERT_TRUE(submit(op).ok());
    ASSERT_TRUE(submit(seal(delete_op("acme", root_pk))).ok());
    // The node is gone, so only the committed op id stops a re-create.
    auto v = submit(op);
    EXPECT_EQ(v.refusal, TreeOpRefusal::Replayed) << v.reason;
    EXPECT_FALSE(tree_svc->get_node("acme").has_value());
}

TEST_F(TreeOpsTest, ReplayedDeltaStatementIsRefused) {
    ASSERT_TRUE(submit(seal(create_op(customer("acme", root_pk), root_pk))).ok());
    auto data = customer("acme", root_pk);
    data.hostname = "first";
    auto d = signed_delta("update_node", "acme", data, root_kp);
    ASSERT_TRUE(submit(seal(delta_op(d), d.timestamp)).ok());
    // Re-wrapped with the new base version: a different op id, the same
    // client statement. It must not apply twice.
    auto again = seal(delta_op(d), d.timestamp);
    auto v = submit(again);
    EXPECT_EQ(v.refusal, TreeOpRefusal::Replayed) << v.reason;
    EXPECT_EQ(version_of("acme"), 2u);
}

TEST_F(TreeOpsTest, StaleBaseVersionIsRefused) {
    ASSERT_TRUE(submit(seal(create_op(customer("acme", root_pk), root_pk))).ok());
    auto node = *tree_svc->get_node("acme");
    node.hostname = "one";
    ASSERT_TRUE(submit(seal(update_op(node, root_pk, 1))).ok());
    node.hostname = "two";
    auto v = submit(seal(update_op(node, root_pk, 1), kBlock + 1));
    EXPECT_EQ(v.refusal, TreeOpRefusal::StaleBaseVersion) << v.reason;
    EXPECT_EQ(tree_svc->get_node("acme")->hostname, "one");

    // A create must start from base version 0.
    auto create = create_op(customer("beta", root_pk), root_pk);
    create.base_version = 3;
    EXPECT_EQ(submit(seal(create)).refusal, TreeOpRefusal::StaleBaseVersion);
}

TEST_F(TreeOpsTest, WrongNetworkIsRefused) {
    auto op = create_op(customer("acme", root_pk), root_pk);
    op.signed_at = kBlock;
    op.network_id.fill(0x22);
    tree::sign_tree_op(*crypto_svc, op, server_kp);  // validly signed, other network
    EXPECT_EQ(submit(op).refusal, TreeOpRefusal::WrongNetwork);
    EXPECT_FALSE(tree_svc->get_node("acme").has_value());
}

TEST_F(TreeOpsTest, BadSignaturesAreRefused) {
    // Tampered submitter signature.
    auto op = seal(create_op(customer("acme", root_pk), root_pk));
    auto sig = crypto::from_base64(op.signature);
    sig[0] ^= 0x01;
    op.signature = crypto::to_base64(sig);
    EXPECT_EQ(submit(op).refusal, TreeOpRefusal::BadSignature);

    // A field changed after signing no longer matches the op id.
    auto changed = seal(create_op(customer("acme", root_pk), root_pk));
    changed.body.node.hostname = "injected";
    EXPECT_EQ(submit(changed).refusal, TreeOpRefusal::BadOpId);

    // Signed by a key that is not a trusted submitter.
    auto untrusted = seal(create_op(customer("acme", root_pk), root_pk), kBlock, &stranger_kp);
    EXPECT_EQ(submit(untrusted).refusal, TreeOpRefusal::UntrustedSubmitter);

    // A forged delta inside a validly signed op.
    auto d = signed_delta("create_node", "acme", customer("acme", root_pk), root_kp);
    d.node_data.hostname = "forged";
    EXPECT_EQ(submit(seal(delta_op(d), d.timestamp)).refusal, TreeOpRefusal::BadStatement);

    // A join whose challenge signature is not the device's.
    auto device = crypto_svc->ed25519_keygen();
    auto join = join_op(device);
    auto other = join_op(stranger_kp);
    join.body.join.challenge_signature = other.body.join.challenge_signature;
    EXPECT_EQ(submit(seal(join)).refusal, TreeOpRefusal::BadStatement);

    EXPECT_FALSE(tree_svc->get_node("acme").has_value());
    EXPECT_FALSE(tree_svc->get_node(join.target).has_value());
}

TEST_F(TreeOpsTest, AuthorWithoutPermissionIsRefused) {
    ASSERT_TRUE(submit(seal(create_op(customer("acme", root_pk), root_pk))).ok());
    const auto stranger = principal_of(stranger_kp);

    auto create = create_op(customer("evil", stranger), stranger);
    EXPECT_EQ(submit(seal(create)).refusal, TreeOpRefusal::Forbidden);

    auto node = *tree_svc->get_node("acme");
    node.hostname = "taken";
    EXPECT_EQ(submit(seal(update_op(node, stranger, 1))).refusal, TreeOpRefusal::Forbidden);
    EXPECT_EQ(submit(seal(delete_op("acme", stranger))).refusal, TreeOpRefusal::Forbidden);
    EXPECT_EQ(submit(seal(assign_op("acme", stranger, stranger, {"admin"}))).refusal,
              TreeOpRefusal::Forbidden);

    // A delta the stranger really signed is still not authority.
    auto d = signed_delta("create_node", "evil", customer("evil", stranger), stranger_kp);
    EXPECT_EQ(submit(seal(delta_op(d), d.timestamp)).refusal, TreeOpRefusal::Forbidden);

    EXPECT_FALSE(tree_svc->get_node("evil").has_value());
    EXPECT_EQ(tree_svc->get_node("acme")->hostname, "");
}

TEST_F(TreeOpsTest, AdminCannotChangeOwnAnchorEntry) {
    auto v = submit(seal(assign_op("root", root_pk, root_pk, {"read"})));
    EXPECT_EQ(v.refusal, TreeOpRefusal::Forbidden);
    EXPECT_EQ(v.reason, "an admin cannot change its own entry on the node that grants it");
    EXPECT_TRUE(tree_svc->check_permission(root_pk, "root", acl::Permission::Admin));
}

TEST_F(TreeOpsTest, UnjoinedPrincipalIsRefused) {
    ASSERT_TRUE(submit(seal(create_op(customer("acme", root_pk), root_pk))).ok());
    const auto stranger = principal_of(stranger_kp);
    auto v = submit(seal(assign_op("acme", root_pk, stranger, {"read"})));
    EXPECT_EQ(v.refusal, TreeOpRefusal::Forbidden);
    EXPECT_EQ(v.reason, "the identity has not joined this group");

    // The same grant smuggled into a full-record update.
    auto node = *tree_svc->get_node("acme");
    node.assignments.push_back({stranger, {"read"}});
    auto u = submit(seal(update_op(node, root_pk, 1)));
    EXPECT_EQ(u.refusal, TreeOpRefusal::ContentRefused);
    EXPECT_EQ(u.reason, "assignment names an identity that has not joined");
    EXPECT_FALSE(tree_svc->check_permission(stranger, "acme", acl::Permission::Read));
}

TEST_F(TreeOpsTest, IdentityFieldChangeIsRefused) {
    ASSERT_TRUE(submit(seal(create_op(customer("acme", root_pk), root_pk))).ok());
    ASSERT_TRUE(submit(seal(create_op(customer("beta", root_pk), root_pk))).ok());
    const auto base = *tree_svc->get_node("acme");

    auto reparent = base;
    reparent.parent_id = "beta";
    auto rekey = base;
    rekey.mgmt_pubkey = principal_of(stranger_kp);
    auto retype = base;
    retype.type = tree::NodeType::Endpoint;
    auto relabel = base;
    relabel.endpoint_identifier = "client-spoofed";
    uint64_t t = kBlock;
    for (const auto& changed : {reparent, rekey, retype, relabel}) {
        auto v = submit(seal(update_op(changed, root_pk, 1), ++t));
        EXPECT_EQ(v.refusal, TreeOpRefusal::ContentRefused) << v.reason;
    }
    const auto after = *tree_svc->get_node("acme");
    EXPECT_EQ(nlohmann::json(after).dump(), nlohmann::json(base).dump());
}

TEST_F(TreeOpsTest, OpOutsideFreshnessIsRefused) {
    // Inside the window at both edges.
    EXPECT_TRUE(submit(seal(create_op(customer("old-edge", root_pk), root_pk),
                            kBlock - tree::kTreeOpMaxAgeSec)).ok());
    EXPECT_TRUE(submit(seal(create_op(customer("new-edge", root_pk), root_pk),
                            kBlock + tree::kTreeOpMaxFutureSec)).ok());
    // One second past either edge.
    EXPECT_EQ(submit(seal(create_op(customer("too-old", root_pk), root_pk),
                          kBlock - tree::kTreeOpMaxAgeSec - 1)).refusal,
              TreeOpRefusal::Stale);
    EXPECT_EQ(submit(seal(create_op(customer("too-new", root_pk), root_pk),
                          kBlock + tree::kTreeOpMaxFutureSec + 1)).refusal,
              TreeOpRefusal::Stale);
    // A delta keeps its own signed time; the wrapper cannot refresh it.
    auto d = signed_delta("create_node", "late", customer("late", root_pk), root_kp,
                          kBlock - 400);
    auto wrapped = delta_op(d);
    EXPECT_EQ(submit(seal(wrapped, kBlock)).refusal, TreeOpRefusal::BadStatement);
    EXPECT_EQ(submit(seal(wrapped, d.timestamp)).refusal, TreeOpRefusal::Stale);
    EXPECT_FALSE(tree_svc->get_node("late").has_value());
}

TEST_F(TreeOpsTest, OversizeOpIsRefused) {
    auto node = customer("big", root_pk);
    node.hostname.assign(tree::kMaxTreeOpEncodedBytes, 'x');
    EXPECT_EQ(submit(seal(create_op(node, root_pk))).refusal, TreeOpRefusal::Oversize);
}

TEST_F(TreeOpsTest, RootIsNeverDeleted) {
    auto v = submit(seal(delete_op("root", root_pk)));
    EXPECT_EQ(v.refusal, TreeOpRefusal::ContentRefused);
    EXPECT_TRUE(tree_svc->get_node("root").has_value());
}

// =========================================================================
// Determinism
// =========================================================================

TEST_F(TreeOpsTest, SameOpSequenceGivesIdenticalTrees) {
    // Tree B loads the same initial state from its own directory, so its
    // hash maps are filled in a different order from tree A's.
    auto storage_b = make_storage("b");
    tree::PermissionTreeService tree_b(*storage_b, *crypto_svc);
    tree_b.start();

    std::vector<crypto::Ed25519Keypair> devices;
    for (int i = 0; i < 5; ++i) devices.push_back(crypto_svc->ed25519_keygen());

    // Build each op once, against tree A's state before it applies; both
    // trees then apply the identical signed op.
    auto both = [&](const TreeOp& op) {
        auto va = submit(op);
        auto vb = submit(op, kBlock, &tree_b);
        ASSERT_EQ(va.refusal, vb.refusal) << va.reason << " / " << vb.reason;
        ASSERT_TRUE(va.ok()) << va.reason;
    };
    both(seal(create_op(customer("acme", root_pk), root_pk)));
    for (std::size_t i = 0; i < devices.size(); ++i) {
        both(seal(join_op(devices[i], "acme",
                          root_pk)));
    }
    both(seal(join_op(stranger_kp)));
    both(seal(assign_op("acme", root_pk, principal_of(devices[0]), {"edit_node", "read"})));
    auto renamed = *tree_svc->get_node("acme");
    renamed.hostname = "acme-2";
    both(seal(update_op(renamed, root_pk, renamed.version)));
    both(seal(delete_op(tree::derive_join_node_id(*crypto_svc, principal_of(devices[2])),
                        root_pk)));

    auto encode_all = [](tree::PermissionTreeService& t) {
        std::map<std::string, std::string> out;
        out["root"] = nlohmann::json(*t.get_node("root")).dump();
        for (const auto& n : t.collect_subtree("root")) {
            out[n.id] = nlohmann::json(n).dump();  // includes "version"
        }
        return out;
    };
    const auto a = encode_all(*tree_svc);
    const auto b = encode_all(tree_b);
    EXPECT_EQ(a, b);
    EXPECT_GT(a.size(), 7u);
    EXPECT_EQ(tree_svc->get_tree_hash(), tree_b.get_tree_hash());
    tree_b.stop();
    storage_b->stop();
}

TEST_F(TreeOpsTest, ValidationUsesBlockTimeNotWallClock) {
    const auto op = seal(create_op(customer("acme", root_pk), root_pk), 1000);
    tree::CommittedOpIds none;
    tree::rules::NodeMap nodes{{"root", *tree_svc->get_node("root")}};
    const tree::TreeState state(nodes, policy);

    // Fresh at a 1970 block time, decades before the wall clock.
    EXPECT_TRUE(tree::validate_op(*crypto_svc, op, state, 1100, none).ok());
    // The same op, the same state, a later block time: stale. Repeated calls
    // agree, and validation changes nothing.
    for (int i = 0; i < 3; ++i) {
        EXPECT_EQ(tree::validate_op(*crypto_svc, op, state, 2000, none).refusal,
                  TreeOpRefusal::Stale);
        EXPECT_TRUE(tree::validate_op(*crypto_svc, op, state, 1100, none).ok());
    }
    EXPECT_EQ(nodes.size(), 1u);

    // Replay is decided by the committed set passed in.
    tree::CommittedOpIds committed;
    committed.insert(tree::op_id_hex(op), op.signed_at);
    EXPECT_EQ(tree::validate_op(*crypto_svc, op, state, 1100, committed).refusal,
              TreeOpRefusal::Replayed);
}

TEST_F(TreeOpsTest, JoinNodeIdMatchesAuthUserId) {
    auth::AuthService auth(*storage_svc, *crypto_svc, "lemonade-nexus.local",
                           std::string(64, 'a'));
    auth.start();
    auto device = crypto_svc->ed25519_keygen();
    const auto bare = b64(device.public_key);
    const auto challenge_b64 = auth.issue_ed25519_challenge(bare).value("challenge", std::string{});
    const auto challenge = crypto::from_base64(challenge_b64);
    const auto sig = crypto_svc->ed25519_sign(device.private_key, std::span<const uint8_t>(challenge));
    auto result = auth.authenticate({{"method", "ed25519"},
                                     {"pubkey", bare},
                                     {"challenge", challenge_b64},
                                     {"signature", crypto::to_base64(std::span<const uint8_t>(
                                                       sig.data(), sig.size()))}});
    ASSERT_TRUE(result.authenticated) << result.error_message;
    EXPECT_EQ(tree::derive_join_node_id(*crypto_svc, "ed25519:" + bare), result.user_id);
    auth.stop();
}

TEST_F(TreeOpsTest, SubmitterGivesEachRequestItsOwnOpId) {
    // The local submitter signs with the wall clock as block time. Two
    // requests with identical content in the same second are distinct ops.
    tree::TreeOpSubmitter submitter(*tree_svc, *crypto_svc, network, server_kp);
    ASSERT_TRUE(submitter.submit(create_op(customer("acme", root_pk), root_pk)).verdict.ok());
    auto node = *tree_svc->get_node("acme");
    node.hostname = "same";
    const auto first = submitter.submit(update_op(node, root_pk, 1));
    const auto second = submitter.submit(update_op(node, root_pk, 2));
    ASSERT_TRUE(first.verdict.ok());
    ASSERT_TRUE(second.verdict.ok());
    EXPECT_NE(first.op_id, second.op_id);
    EXPECT_FALSE(first.pending);
    EXPECT_EQ(version_of("acme"), 3u);
    // A dry run validates without applying.
    EXPECT_TRUE(submitter.dry_run(update_op(node, root_pk, 3)).ok());
    EXPECT_EQ(version_of("acme"), 3u);
    EXPECT_EQ(submitter.dry_run(update_op(node, root_pk, 2)).refusal,
              TreeOpRefusal::StaleBaseVersion);
}

// =========================================================================
// Node version compatibility
// =========================================================================

TEST_F(TreeOpsTest, VersionIsOptionalInJsonAndOutsideCanonicalForm) {
    auto node = customer("acme", root_pk);
    const auto canonical_v0 = tree::canonical_node_json(node);
    nlohmann::json j0 = node;
    EXPECT_FALSE(j0.contains("version")) << "records without ops keep their exact JSON";

    node.version = 7;
    nlohmann::json j7 = node;
    EXPECT_EQ(j7.value("version", uint64_t{0}), 7u);
    EXPECT_EQ(tree::canonical_node_json(node), canonical_v0);
    EXPECT_EQ(j7.get<tree::TreeNode>().version, 7u);
    EXPECT_EQ(j0.get<tree::TreeNode>().version, 0u) << "absent means 0";
}

TEST_F(TreeOpsTest, VersionsPersistAcrossRestart) {
    ASSERT_TRUE(submit(seal(create_op(customer("acme", root_pk), root_pk))).ok());
    auto node = *tree_svc->get_node("acme");
    ASSERT_TRUE(submit(seal(update_op(node, root_pk, 1))).ok());
    tree_svc->stop();
    tree_svc = std::make_unique<tree::PermissionTreeService>(*storage_svc, *crypto_svc);
    tree_svc->start();
    EXPECT_EQ(version_of("acme"), 2u);
    EXPECT_EQ(version_of("root"), 0u);
}

// =========================================================================
// Server-assigned addresses and the relay type
// =========================================================================

// A joined device holds add_child and edit_node on its endpoint and owns its
// group. Tunnel addresses, private subnets, and relays act on the whole plane,
// so the device sets none of them; only a root admin does. Each refusal is
// checked on the session path and the signed-delta path.
TEST_F(TreeOpsTest, OnlyARootAdminSetsAddressesOrCreatesRelays) {
    const auto device_kp = crypto_svc->ed25519_keygen();
    const auto device = principal_of(device_kp);
    auto join = join_op(device_kp);
    const auto endpoint_id = join.target;
    ASSERT_TRUE(submit(seal(join)).ok());
    const auto endpoint = *tree_svc->get_node(endpoint_id);
    ASSERT_FALSE(endpoint.tunnel_ip.empty());

    auto child = [&](const std::string& id) {
        tree::TreeNode n;
        n.id = id;
        n.parent_id = endpoint_id;
        n.type = tree::NodeType::Endpoint;
        n.mgmt_pubkey = device;
        n.assignments = {{device, {"read", "connect_private", "admin"}}};
        return n;
    };
    uint64_t t = kBlock;
    auto refused = [&](const TreeOp& op, uint64_t signed_at) {
        const auto v = submit(seal(op, signed_at));
        EXPECT_EQ(v.refusal, TreeOpRefusal::ContentRefused) << v.reason;
        return v.reason;
    };

    // A child that carries another device's address, a subnet, or the relay type.
    auto victim_address = child("c-address");
    victim_address.tunnel_ip = "10.65.0.9/32";
    EXPECT_EQ(refused(create_op(victim_address, device), ++t),
              "only a root admin may create a relay or set node addresses");
    auto subnet = child("c-subnet");
    subnet.private_subnet = "10.128.0.0/30";
    refused(create_op(subnet, device), ++t);
    auto relay = child("c-relay");
    relay.type = tree::NodeType::Relay;
    refused(create_op(relay, device), ++t);
    for (const auto& node : {victim_address, subnet, relay}) {
        const auto d = signed_delta("create_node", node.id, node, device_kp, ++t);
        refused(delta_op(d), d.timestamp);
        EXPECT_FALSE(tree_svc->get_node(node.id).has_value());
    }

    // A plain child is allowed, and admin on it does not move its address.
    ASSERT_TRUE(submit(seal(create_op(child("c-plain"), device), ++t)).ok());
    auto moved = *tree_svc->get_node("c-plain");
    moved.tunnel_ip = "10.65.0.9/32";
    EXPECT_EQ(refused(update_op(moved, device, version_of("c-plain")), ++t),
              "only a root admin may change node addresses");

    // edit_node on its own endpoint, and admin of its group, do not move the
    // endpoint's address or set its subnet.
    auto own = endpoint;
    own.tunnel_ip = "10.65.0.9/32";
    refused(update_op(own, device, version_of(endpoint_id)), ++t);
    auto own_subnet = endpoint;
    own_subnet.private_subnet = "10.128.0.0/24";
    refused(update_op(own_subnet, device, version_of(endpoint_id)), ++t);
    const auto d = signed_delta("update_node", endpoint_id, own, device_kp, ++t);
    refused(delta_op(d), d.timestamp);
    EXPECT_EQ(tree_svc->get_node(endpoint_id)->tunnel_ip, endpoint.tunnel_ip);

    // The root admin may create a relay with an address.
    tree::TreeNode root_relay;
    root_relay.id = "relay-1";
    root_relay.parent_id = "root";
    root_relay.type = tree::NodeType::Relay;
    root_relay.mgmt_pubkey = root_pk;
    root_relay.tunnel_ip = "10.64.0.7/32";
    EXPECT_TRUE(submit(seal(create_op(root_relay, root_pk), ++t)).ok());
}

// =========================================================================
// Removed-nodes hook
// =========================================================================

// A replica applies a delete that another server took. The hook runs on the
// replica with the record as it was before the delete, so each server can
// clean up its own state for the node. A restore through replace_all is not a
// delete and does not call it.
TEST_F(TreeOpsTest, ApplyingACommittedDeleteReportsTheRemovedNode) {
    ASSERT_TRUE(submit(seal(create_op(customer("acme", root_pk), root_pk))).ok());
    const auto before = *tree_svc->get_node("acme");
    std::vector<tree::TreeNode> reported;
    tree_svc->set_removed_nodes_hook([&](const std::vector<tree::TreeNode>& removed) {
        // The hook runs without the tree lock held, so it may read the tree.
        EXPECT_FALSE(tree_svc->get_node("acme").has_value());
        reported.insert(reported.end(), removed.begin(), removed.end());
    });

    ASSERT_TRUE(tree_svc->apply_committed_ops({seal(delete_op("acme", root_pk))}, kBlock).ok());
    ASSERT_EQ(reported.size(), 1u);
    EXPECT_EQ(nlohmann::json(reported[0]).dump(), nlohmann::json(before).dump());

    reported.clear();
    ASSERT_TRUE(tree_svc->replace_all({}, tree::CommittedOpIds{}));
    EXPECT_TRUE(reported.empty());
    tree_svc->set_removed_nodes_hook({});
}

// =========================================================================
// Invites into a chosen group (AcceptInvite) and moves (MoveNode)
// =========================================================================

/// Two networks: "alpha" (owner A, subgroups "alpha-sub1" and "alpha-sub2",
/// devices "alpha-dev" with key A and "alpha-dev2" with key A2) and "beta"
/// (owner B, devices "beta-dev" with key B and "beta-dev2" with key B2).
class TreeMembershipTest : public TreeOpsTest {
protected:
    crypto::Ed25519Keypair a_kp, a2_kp, b_kp, b2_kp;
    std::string pa, pa2, pb, pb2;
    uint64_t clock = kBlock;

    void SetUp() override {
        TreeOpsTest::SetUp();
        a_kp = crypto_svc->ed25519_keygen();
        a2_kp = crypto_svc->ed25519_keygen();
        b_kp = crypto_svc->ed25519_keygen();
        b2_kp = crypto_svc->ed25519_keygen();
        pa = principal_of(a_kp);
        pa2 = principal_of(a2_kp);
        pb = principal_of(b_kp);
        pb2 = principal_of(b2_kp);
        build(*tree_svc);
    }

    /// Seal with a strictly increasing signed time, so equal content never
    /// collides on op id.
    TreeOp next(TreeOp op) { return seal(std::move(op), ++clock); }

    tree::TreeOpVerdict run(const TreeOp& op, tree::PermissionTreeService* svc = nullptr) {
        return submit(op, clock, svc);
    }

    static tree::TreeNode node(const std::string& id, const std::string& parent,
                               tree::NodeType type, const std::string& key,
                               std::vector<tree::Assignment> assignments) {
        tree::TreeNode n;
        n.id = id;
        n.parent_id = parent;
        n.type = type;
        n.mgmt_pubkey = key;
        n.assignments = std::move(assignments);
        return n;
    }

    void build(tree::PermissionTreeService& svc) {
        using tree::NodeType;
        // Each node is created by the admin of its parent, in an order where
        // every identity an assignment names has already joined.
        const std::vector<std::pair<tree::TreeNode, std::string>> nodes = {
            {node("alpha", "root", NodeType::Customer, pa, {{pa, {"admin"}}}), root_pk},
            {node("alpha-sub1", "alpha", NodeType::Customer, pa, {{pa, {"add_child", "read"}}}),
             pa},
            {node("alpha-sub2", "alpha", NodeType::Customer, pa, {{pa, {"add_child", "read"}}}),
             pa},
            {node("alpha-dev2", "alpha", NodeType::Endpoint, pa2,
                  {{pa2, {"edit_node", "read", "write"}}, {pa, {"connect_private", "read"}}}),
             pa},
            {node("alpha-dev", "alpha", NodeType::Endpoint, pa,
                  {{pa, {"add_child", "delete_node", "edit_node", "read", "write"}},
                   {pa2, {"connect_private", "read"}}}),
             pa},
            {node("beta", "root", NodeType::Customer, pb, {{pb, {"admin"}}}), root_pk},
            {node("beta-dev2", "beta", NodeType::Endpoint, pb2,
                  {{pb2, {"edit_node", "read", "write"}}, {pb, {"connect_private", "read"}}}),
             pb},
            {node("beta-dev", "beta", NodeType::Endpoint, pb,
                  {{pb, {"add_child", "delete_node", "edit_node", "read", "write"}},
                   {pb2, {"connect_private", "read"}}}),
             pb},
        };
        for (const auto& [n, signer] : nodes) {
            auto v = submit(seal(create_op(n, signer), kBlock), kBlock, &svc);
            ASSERT_TRUE(v.ok()) << n.id << ": " << v.reason;
        }
    }

    TreeOp accept_op(const std::string& target, const std::string& invitee,
                     const std::string& inviter, std::vector<std::string> perms) {
        TreeOp op;
        op.kind = TreeOpKind::AcceptInvite;
        op.target = target;
        op.base_version = version_of(target);
        op.principal = invitee;
        op.body.source = TreeOpSource::Session;
        op.body.inviter = inviter;
        op.body.invite_permissions = std::move(perms);
        return op;
    }

    TreeOp move_op(const std::string& target, const std::string& new_parent,
                   const std::string& signer) {
        TreeOp op;
        op.kind = TreeOpKind::MoveNode;
        op.target = target;
        op.base_version = version_of(target);
        op.principal = signer;
        op.body.source = TreeOpSource::Session;
        op.body.new_parent_id = new_parent;
        return op;
    }

    bool connects(const std::string& principal, const std::string& from, const std::string& to) {
        return tree_svc->may_connect(principal, from, to);
    }
};

TEST_F(TreeMembershipTest, AcceptInviteMakesAMemberWithoutMovingAnything) {
    const auto beta_before = nlohmann::json(*tree_svc->get_node("beta")).dump();
    const auto beta_dev_before = nlohmann::json(*tree_svc->get_node("beta-dev")).dump();

    auto v = run(next(accept_op("alpha", pb, pa, {"read", "connect_private"})));
    ASSERT_TRUE(v.ok()) << v.reason;

    const auto alpha = *tree_svc->get_node("alpha");
    EXPECT_TRUE(tree::rules::signer_has_permission(alpha, pb, acl::Permission::Read));
    EXPECT_FALSE(tree::rules::signer_has_permission(alpha, pb, acl::Permission::Admin));
    // Nothing of the invitee's own network changed or moved.
    EXPECT_EQ(nlohmann::json(*tree_svc->get_node("beta")).dump(), beta_before);
    EXPECT_EQ(nlohmann::json(*tree_svc->get_node("beta-dev")).dump(), beta_dev_before);
    // Neither side gains control over the other's group.
    EXPECT_FALSE(tree_svc->check_permission(pa, "beta", acl::Permission::Read));
    EXPECT_FALSE(tree_svc->administers(pa, "beta-dev"));
    EXPECT_FALSE(tree_svc->administers(pb, "alpha-dev"));
}

TEST_F(TreeMembershipTest, AcceptInviteRefusesWhatTheInviterCannotGrant) {
    auto refusal = [&](const TreeOp& op) { return run(next(op)).refusal; };
    // An inviter with no authority on the target.
    EXPECT_EQ(refusal(accept_op("alpha", pb, principal_of(stranger_kp), {"read"})),
              TreeOpRefusal::Forbidden);
    // Escalation: admin, delete_node, and edit_node are never granted.
    EXPECT_EQ(refusal(accept_op("alpha", pb, pa, {"read", "admin"})), TreeOpRefusal::Invalid);
    EXPECT_EQ(refusal(accept_op("alpha", pb, pa, {"read", "delete_node"})),
              TreeOpRefusal::Invalid);
    EXPECT_EQ(refusal(accept_op("alpha", pb, pa, {"read", "edit_node"})),
              TreeOpRefusal::Invalid);
    // A member that holds read and add_child cannot pass on connect.
    ASSERT_TRUE(run(next(accept_op("alpha", pb, pa, {"add_child", "read"}))).ok());
    EXPECT_EQ(refusal(accept_op("alpha", pb2, pb, {"connect_private", "read"})),
              TreeOpRefusal::Forbidden);
    // An inviter that lost its authority voids the invite.
    ASSERT_TRUE(run(next(assign_op("alpha", pa, pb, {}))).ok());
    EXPECT_EQ(refusal(accept_op("alpha", pb2, pb, {"read"})), TreeOpRefusal::Forbidden);
}

TEST_F(TreeMembershipTest, AcceptInviteRefusesBadTargetsAndHomeMembers) {
    auto refusal = [&](const TreeOp& op) { return run(next(op)).refusal; };
    EXPECT_EQ(refusal(accept_op("alpha-dev", pb, pa, {"read"})), TreeOpRefusal::Invalid);
    EXPECT_EQ(refusal(accept_op("alpha", pb, pa, {"connect_private"})), TreeOpRefusal::Invalid)
        << "a membership needs read";
    EXPECT_EQ(refusal(accept_op("alpha", pa2, pa, {"read"})), TreeOpRefusal::Conflict)
        << "a device joined inside the group keeps its home entry";
    EXPECT_EQ(refusal(accept_op("alpha-sub1", pa, pa, {"read"})), TreeOpRefusal::Conflict)
        << "an admin above the group is not made a member";

    const auto op = next(accept_op("alpha", pb, pa, {"read"}));
    ASSERT_TRUE(run(op).ok());
    EXPECT_EQ(run(op).refusal, TreeOpRefusal::Replayed);
}

TEST_F(TreeMembershipTest, MembershipReachCoversOnlyTheMembersDevices) {
    EXPECT_FALSE(connects(pb, "beta-dev", "alpha-dev"));
    EXPECT_FALSE(connects(pa, "alpha-dev", "beta-dev"));

    ASSERT_TRUE(run(next(accept_op("alpha", pb, pa, {"connect_private", "read"}))).ok());
    // B's device reaches alpha's devices, and alpha's devices reach it back.
    EXPECT_TRUE(connects(pb, "beta-dev", "alpha-dev"));
    EXPECT_TRUE(connects(pb, "beta-dev", "alpha-dev2"));
    EXPECT_TRUE(connects(pa, "alpha-dev", "beta-dev"));
    EXPECT_TRUE(connects(pa2, "alpha-dev2", "beta-dev"));
    // B's other device has its own key: the membership does not cover it in
    // either direction, so alpha sees nothing else of B's network.
    EXPECT_FALSE(connects(pb2, "beta-dev2", "alpha-dev"));
    EXPECT_FALSE(connects(pa, "alpha-dev", "beta-dev2"));
    // A key acting through a node it does not own gets no membership reach.
    EXPECT_FALSE(connects(pb, "beta-dev2", "alpha-dev"));
    // An admin entry is not a membership: the root admin reaches nothing.
    EXPECT_FALSE(tree::rules::membership_reaches(tree_svc->nodes_snapshot(), root_pk,
                                                 *tree_svc->get_node("alpha-dev")));
}

TEST_F(TreeMembershipTest, MemberInASubgroupReachesOnlyThatSubgroup) {
    const auto sub_dev =
        node("sub1-dev", "alpha-sub1", tree::NodeType::Endpoint, pa2, {{pa2, {"read"}}});
    ASSERT_TRUE(run(next(create_op(sub_dev, pa))).ok());
    ASSERT_TRUE(run(next(accept_op("alpha-sub1", pb, pa, {"connect_private", "read"}))).ok());
    EXPECT_TRUE(connects(pb, "beta-dev", "sub1-dev"));
    EXPECT_FALSE(connects(pb, "beta-dev", "alpha-dev"));
    EXPECT_FALSE(tree_svc->check_permission(pb, "alpha", acl::Permission::Read));
}

TEST_F(TreeMembershipTest, MemberLeavesAndAdminRemovesMembers) {
    ASSERT_TRUE(run(next(accept_op("alpha", pb, pa, {"connect_private", "read"}))).ok());
    ASSERT_TRUE(run(next(accept_op("alpha", pb2, pa, {"connect_private", "read"}))).ok());

    // A member cannot remove another member.
    EXPECT_EQ(run(next(assign_op("alpha", pb, pb2, {}))).refusal, TreeOpRefusal::Forbidden);
    // A member leaves by removing its own entry.
    ASSERT_TRUE(run(next(assign_op("alpha", pb, pb, {}))).ok());
    EXPECT_FALSE(connects(pb, "beta-dev", "alpha-dev"));
    EXPECT_FALSE(connects(pa, "alpha-dev", "beta-dev"));
    // The group admin removes the other member.
    ASSERT_TRUE(run(next(assign_op("alpha", pa, pb2, {}))).ok());
    EXPECT_FALSE(connects(pb2, "beta-dev2", "alpha-dev"));

    // A device joined inside the group cannot drop its home entry this way,
    // and an admin cannot remove its own anchor entry.
    ASSERT_TRUE(run(next(assign_op("alpha", pa, pa2, {"read"}))).ok());
    EXPECT_EQ(run(next(assign_op("alpha", pa2, pa2, {}))).refusal, TreeOpRefusal::Forbidden);
    EXPECT_EQ(run(next(assign_op("alpha", pa, pa, {}))).refusal, TreeOpRefusal::Forbidden);
}

TEST_F(TreeMembershipTest, MoveDeviceKeepsIdentityAndDropsOldLinkGrants) {
    auto dev1 = crypto_svc->ed25519_keygen();
    auto dev2 = crypto_svc->ed25519_keygen();
    ASSERT_TRUE(run(next(join_op(dev1, "alpha-sub1", pa))).ok());
    ASSERT_TRUE(run(next(join_op(dev2, "alpha-sub1", pa))).ok());
    const auto id1 = tree::derive_join_node_id(*crypto_svc, principal_of(dev1));
    const auto id2 = tree::derive_join_node_id(*crypto_svc, principal_of(dev2));
    const auto before = *tree_svc->get_node(id2);
    ASSERT_TRUE(tree_svc->check_permission(principal_of(dev2), id1, acl::Permission::Read));
    ASSERT_TRUE(connects(principal_of(dev1), id1, id2));

    auto v = run(next(move_op(id2, "alpha-sub2", pa)));
    ASSERT_TRUE(v.ok()) << v.reason;
    const auto after = *tree_svc->get_node(id2);
    EXPECT_EQ(after.parent_id, "alpha-sub2");
    EXPECT_EQ(after.tunnel_ip, before.tunnel_ip);
    EXPECT_FALSE(after.tunnel_ip.empty());
    EXPECT_EQ(after.endpoint_identifier, before.endpoint_identifier);
    EXPECT_EQ(nlohmann::json(after.assignments).dump(), nlohmann::json(before.assignments).dump())
        << "own assignments stay";
    // The old group and the old sibling no longer name the moved key.
    EXPECT_FALSE(tree_svc->check_permission(principal_of(dev2), id1, acl::Permission::Read));
    EXPECT_FALSE(
        tree_svc->check_permission(principal_of(dev2), "alpha-sub1", acl::Permission::Read));
    // Out of the old group's scope, the old sibling no longer connects.
    EXPECT_FALSE(connects(principal_of(dev1), id1, id2));
    // The move granted the moved key nothing in the new group.
    EXPECT_FALSE(
        tree_svc->check_permission(principal_of(dev2), "alpha-sub2", acl::Permission::Read));
}

TEST_F(TreeMembershipTest, MoveSubgroupCarriesItsSubtree) {
    const auto sub_dev =
        node("sub1-dev", "alpha-sub1", tree::NodeType::Endpoint, pa2, {{pa2, {"read"}}});
    ASSERT_TRUE(run(next(create_op(sub_dev, pa))).ok());
    auto v = run(next(move_op("alpha-sub1", "alpha-sub2", pa)));
    ASSERT_TRUE(v.ok()) << v.reason;
    EXPECT_EQ(tree_svc->get_node("alpha-sub1")->parent_id, "alpha-sub2");
    EXPECT_EQ(tree_svc->get_node("sub1-dev")->parent_id, "alpha-sub1");
    EXPECT_TRUE(tree_svc->is_descendant_of("sub1-dev", "alpha-sub2"));
}

TEST_F(TreeMembershipTest, MoveRefusesWithoutAuthorityOrIntoACycle) {
    auto refusal = [&](const std::string& target, const std::string& parent,
                       const std::string& signer) {
        return run(next(move_op(target, parent, signer))).refusal;
    };
    // No delete_node or admin on the device.
    EXPECT_EQ(refusal("alpha-dev", "alpha-sub1", pb), TreeOpRefusal::Forbidden);
    // Rights on the device but no add_child on the destination.
    EXPECT_EQ(refusal("beta-dev", "alpha-sub1", pb), TreeOpRefusal::Forbidden);
    // A group under itself or under its descendant.
    ASSERT_TRUE(run(next(move_op("alpha-sub2", "alpha-sub1", pa))).ok());
    EXPECT_EQ(refusal("alpha-sub1", "alpha-sub2", pa), TreeOpRefusal::Invalid);
    EXPECT_EQ(refusal("alpha-sub1", "alpha-sub1", pa), TreeOpRefusal::Invalid);
    // The root and top-level groups never move, even for the root admin.
    EXPECT_EQ(refusal("root", "alpha", root_pk), TreeOpRefusal::Forbidden);
    EXPECT_EQ(refusal("beta", "alpha", root_pk), TreeOpRefusal::Forbidden);
    // Only under a group, and only to a new parent.
    EXPECT_EQ(refusal("alpha-dev2", "alpha-dev", pa), TreeOpRefusal::Invalid);
    EXPECT_EQ(refusal("alpha-dev2", "alpha", pa), TreeOpRefusal::Conflict);
}

TEST_F(TreeMembershipTest, DeleteRightAloneDoesNotTakeOverASubgroup) {
    // B is a member of alpha with add_child, and holds delete_node on
    // alpha-sub1. Moving the subgroup into B's own network would hand B admin
    // over alpha's devices: refused.
    ASSERT_TRUE(run(next(accept_op("alpha", pb, pa, {"add_child", "read"}))).ok());
    auto sub = *tree_svc->get_node("alpha-sub1");
    sub.assignments.push_back({pb, {"delete_node"}});
    ASSERT_TRUE(test_support::put_node(*tree_svc, sub));
    EXPECT_EQ(run(next(move_op("alpha-sub1", "beta", pb))).refusal, TreeOpRefusal::Forbidden);
    // B may move its own device into alpha, where it holds add_child. The
    // device gains no reach to alpha's devices by that.
    ASSERT_TRUE(run(next(move_op("beta-dev2", "alpha", pb))).ok());
    EXPECT_FALSE(connects(pb2, "beta-dev2", "alpha-dev"));
}

TEST_F(TreeMembershipTest, NewOpKindsRoundTripAndApplyIdentically) {
    auto storage_b = make_storage("b2");
    tree::PermissionTreeService tree_b(*storage_b, *crypto_svc);
    tree_b.start();
    build(tree_b);

    auto both = [&](const TreeOp& op) {
        const auto sig = tree::tree_op_signature_bytes(op);
        ASSERT_TRUE(sig.has_value());
        const auto decoded = tree::decode_tree_op(tree::encode_tree_op(op), *sig);
        ASSERT_TRUE(decoded.has_value());
        EXPECT_EQ(tree::op_id_hex(*decoded), tree::op_id_hex(op));
        auto va = run(op);
        auto vb = run(*decoded, &tree_b);
        ASSERT_EQ(va.refusal, vb.refusal) << va.reason << " / " << vb.reason;
        ASSERT_TRUE(va.ok()) << va.reason;
    };
    both(next(accept_op("alpha", pb, pa, {"connect_private", "read"})));
    both(next(move_op("alpha-dev2", "alpha-sub1", pa)));
    both(next(move_op("alpha-sub1", "alpha-sub2", pa)));
    EXPECT_EQ(tree_svc->tree_digest(), tree_b.tree_digest());
    tree_b.stop();
    storage_b->stop();
}

// --- Service permissions (svc:<family>) -------------------------------------

using Names = std::vector<std::string>;

TEST_F(TreeMembershipTest, ServicePermissionNamesAreCheckedLikeOtherNames) {
    using tree::rules::is_service_permission;
    using tree::rules::permission_name_known;
    EXPECT_TRUE(is_service_permission("svc:inference"));
    EXPECT_TRUE(is_service_permission("svc:a"));
    EXPECT_TRUE(is_service_permission("svc:files.read_v2-x"));
    EXPECT_TRUE(is_service_permission("svc:" + std::string(63, 'a')));
    EXPECT_FALSE(is_service_permission("svc:" + std::string(64, 'a')));
    EXPECT_FALSE(is_service_permission("svc:"));
    EXPECT_FALSE(is_service_permission("svc:Inference"));
    EXPECT_FALSE(is_service_permission("svc:in ference"));
    EXPECT_FALSE(is_service_permission("svc:-x"));
    EXPECT_FALSE(is_service_permission("svc:.x"));
    EXPECT_FALSE(is_service_permission("svc:x/y"));
    EXPECT_FALSE(is_service_permission("svc:x\xc3\xa4"));
    EXPECT_FALSE(is_service_permission("svc"));
    EXPECT_FALSE(is_service_permission("SVC:x"));
    EXPECT_FALSE(is_service_permission("inference"));
    EXPECT_TRUE(permission_name_known("read"));
    EXPECT_TRUE(permission_name_known("svc:inference"));
    EXPECT_FALSE(permission_name_known("made_up"));

    // An assignment and an invite refuse each malformed name and keep
    // refusing a made-up plain name; nothing is stored.
    const auto alpha_before = version_of("alpha");
    const Names bad_names = {"svc:",   "svc:Inference", "svc:in ference", "svc:-x",
                             "svc:" + std::string(64, 'a'), "made_up"};
    for (const auto& bad : bad_names) {
        auto v = run(next(assign_op("alpha", pa, pa2, {"read", bad})));
        EXPECT_EQ(v.refusal, TreeOpRefusal::Invalid) << bad;
        EXPECT_EQ(v.reason, "unknown permission '" + bad + "'");
        auto i = run(next(accept_op("alpha", pb, pa, {"read", bad})));
        EXPECT_EQ(i.refusal, TreeOpRefusal::Invalid) << bad;
        EXPECT_EQ(i.reason, "an invite cannot grant '" + bad + "'");
    }
    EXPECT_EQ(version_of("alpha"), alpha_before);
}

TEST_F(TreeMembershipTest, ServicePermissionsAreStoredAndGrantNothing) {
    // The group admin assigns one to a joined key, and an invite carries one.
    auto v = run(next(assign_op("alpha", pa, pa2, {"svc:inference", "read", "svc:inference"})));
    ASSERT_TRUE(v.ok()) << v.reason;
    v = run(next(accept_op("alpha", pb, pa, {"read", "svc:inference"})));
    ASSERT_TRUE(v.ok()) << v.reason;
    auto entry = [&](const std::string& node_id, const std::string& who) -> Names {
        const auto n = *tree_svc->get_node(node_id);
        for (const auto& a : n.assignments) {
            if (tree::canonical_principal(a.management_pubkey) == tree::canonical_principal(who)) {
                return a.permissions;
            }
        }
        return {};
    };
    EXPECT_EQ(entry("alpha", pa2), (Names{"read", "svc:inference"}));
    EXPECT_EQ(entry("alpha", pb), (Names{"read", "svc:inference"}));

    // The name is no authority: the holder cannot write, administer, grant,
    // or invite with it.
    EXPECT_FALSE(tree_svc->check_permission(pb, "alpha", acl::Permission::Write));
    EXPECT_FALSE(tree_svc->check_permission(pb, "alpha", acl::Permission::EditNode));
    EXPECT_FALSE(tree_svc->administers(pb, "alpha-dev"));
    EXPECT_FALSE(connects(pb, "beta-dev", "alpha-dev")) << "a service permission is not a membership";
    EXPECT_EQ(run(next(assign_op("alpha", pa2, pb2, {"read"}))).refusal, TreeOpRefusal::Forbidden);
    EXPECT_EQ(run(next(accept_op("alpha", pb2, pa2, {"read"}))).refusal, TreeOpRefusal::Forbidden);

    // A key whose entry holds only a service permission reads, edits, and
    // connects nothing on that node.
    v = run(next(assign_op("alpha-dev2", pa, pa, {"svc:inference"})));
    ASSERT_TRUE(v.ok()) << v.reason;
    EXPECT_EQ(entry("alpha-dev2", pa), (Names{"svc:inference"}));
    EXPECT_FALSE(tree_svc->check_permission(pa, "alpha-dev2", acl::Permission::Read));
    EXPECT_FALSE(tree_svc->check_permission(pa, "alpha-dev2", acl::Permission::EditNode));
    EXPECT_FALSE(tree_svc->check_permission(pa, "alpha-dev2", acl::Permission::ConnectPrivate));
    EXPECT_FALSE(tree_svc->check_permission(pa, "alpha-dev2", acl::Permission::ConnectShared));
    EXPECT_FALSE(connects(pa, "alpha-dev", "alpha-dev2"));
}

TEST_F(TreeMembershipTest, AnInvitePassesOnOnlyTheServicePermissionsTheInviterHolds) {
    const auto nodes = [&] { return tree_svc->nodes_snapshot(); };
    using tree::rules::AssignmentRefusal;
    using tree::rules::invite_refusal;
    // The group admin grants any service permission; a member with
    // add_child and svc:x grants svc:x and nothing else.
    EXPECT_FALSE(invite_refusal(nodes(), "alpha", pa, {"read", "svc:y"}).has_value());
    auto v = run(next(accept_op("alpha", pb, pa, {"add_child", "read", "svc:x"})));
    ASSERT_TRUE(v.ok()) << v.reason;
    EXPECT_FALSE(invite_refusal(nodes(), "alpha", pb, {"read", "svc:x"}).has_value());
    const auto denied = invite_refusal(nodes(), "alpha", pb, {"read", "svc:y"});
    ASSERT_TRUE(denied.has_value());
    EXPECT_EQ(denied->refusal, AssignmentRefusal::Forbidden);
    EXPECT_EQ(denied->reason, "the inviter does not hold 'svc:y' on the invite target");
    EXPECT_EQ(run(next(accept_op("alpha", pb2, pb, {"read", "svc:y"}))).refusal,
              TreeOpRefusal::Forbidden);
    v = run(next(accept_op("alpha", pb2, pb, {"read", "svc:x"})));
    ASSERT_TRUE(v.ok()) << v.reason;
    v = run(next(accept_op("alpha", principal_of(stranger_kp), pa, {"read", "svc:y"})));
    ASSERT_TRUE(v.ok()) << v.reason;
    // Administration above the target counts; a member's entry on the parent
    // group gives it nothing on a subgroup.
    EXPECT_FALSE(invite_refusal(nodes(), "alpha-sub1", pa, {"read", "svc:z"}).has_value());
    EXPECT_TRUE(invite_refusal(nodes(), "alpha-sub1", pb, {"read", "svc:x"}).has_value());
}

TEST_F(TreeMembershipTest, ServicePermissionsSurviveCanonicalAndBinaryEncoding) {
    const Names names{"read", "svc:files.read-v2_x", "svc:inference"};
    const auto dev = node("svc-dev", "alpha", tree::NodeType::Endpoint, pa2, {{pa2, names}});
    const auto canonical = tree::canonical_node_json(dev);
    EXPECT_NE(canonical.find("\"svc:inference\""), std::string::npos);
    EXPECT_NE(canonical.find("\"svc:files.read-v2_x\""), std::string::npos);
    const auto decoded = tree::decode_tree_node(tree::encode_tree_node(dev));
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded->assignments.size(), 1u);
    EXPECT_EQ(decoded->assignments[0].permissions, names);
    EXPECT_EQ(tree::canonical_node_json(*decoded), canonical);
    const auto from_json = nlohmann::json(dev).get<tree::TreeNode>();
    EXPECT_EQ(from_json.assignments[0].permissions, names);

    // The ops that carry the names apply identically on a second replica
    // through the binary op encoding.
    auto storage_b = make_storage("b3");
    tree::PermissionTreeService tree_b(*storage_b, *crypto_svc);
    tree_b.start();
    build(tree_b);
    auto both = [&](const TreeOp& op) {
        const auto sig = tree::tree_op_signature_bytes(op);
        ASSERT_TRUE(sig.has_value());
        const auto decoded_op = tree::decode_tree_op(tree::encode_tree_op(op), *sig);
        ASSERT_TRUE(decoded_op.has_value());
        EXPECT_EQ(tree::op_id_hex(*decoded_op), tree::op_id_hex(op));
        auto va = run(op);
        auto vb = run(*decoded_op, &tree_b);
        ASSERT_EQ(va.refusal, vb.refusal) << va.reason << " / " << vb.reason;
        ASSERT_TRUE(va.ok()) << va.reason;
    };
    both(next(create_op(dev, pa)));
    both(next(assign_op("alpha", pa, pa2, {"read", "svc:inference"})));
    both(next(accept_op("alpha", pb, pa, {"read", "svc:inference"})));
    EXPECT_EQ(tree_svc->tree_digest(), tree_b.tree_digest());
    EXPECT_EQ(tree_b.get_node("svc-dev")->assignments[0].permissions, names);
    tree_b.stop();
    storage_b->stop();
}

TEST_F(TreeMembershipTest, PeerPermissionsCollectDeviceGroupAndAdminNames) {
    using tree::rules::peer_permissions;
    auto v = run(next(accept_op("alpha", pb, pa, {"connect_private", "read", "svc:inference"})));
    ASSERT_TRUE(v.ok()) << v.reason;
    const auto sub_dev =
        node("sub1-dev", "alpha-sub1", tree::NodeType::Endpoint, pa2, {{pa2, {"read"}}});
    ASSERT_TRUE(run(next(create_op(sub_dev, pa))).ok());
    v = run(next(accept_op("alpha-sub1", pb2, pa, {"read", "svc:sub"})));
    ASSERT_TRUE(v.ok()) << v.reason;
    const auto nodes = tree_svc->nodes_snapshot();

    // A membership: the group entry reaches every device beneath the group.
    auto member = peer_permissions(nodes, pb, nodes.at("alpha-dev"));
    EXPECT_EQ(member.names, (Names{"connect_private", "read", "svc:inference"}));
    EXPECT_FALSE(member.admin);
    EXPECT_EQ(peer_permissions(nodes, pb, nodes.at("sub1-dev")).names,
              (Names{"connect_private", "read", "svc:inference"}));
    // A subgroup entry reaches only that subgroup.
    EXPECT_EQ(peer_permissions(nodes, pb2, nodes.at("sub1-dev")).names, (Names{"read", "svc:sub"}));
    EXPECT_TRUE(peer_permissions(nodes, pb2, nodes.at("alpha-dev")).names.empty());
    // The group admin: "admin" plus its literal entry on the device.
    auto admin = peer_permissions(nodes, pa, nodes.at("alpha-dev2"));
    EXPECT_TRUE(admin.admin);
    EXPECT_EQ(admin.names, (Names{"admin", "connect_private", "read"}));
    // The root admin reaches every device through its anchor alone.
    auto root = peer_permissions(nodes, root_pk, nodes.at("beta-dev"));
    EXPECT_TRUE(root.admin);
    EXPECT_EQ(root.names, Names{"admin"});
    // A per-device entry only, a key with no entry, and no principal.
    EXPECT_EQ(peer_permissions(nodes, pa2, nodes.at("alpha-dev")).names,
              (Names{"connect_private", "read"}));
    EXPECT_TRUE(
        peer_permissions(nodes, principal_of(stranger_kp), nodes.at("alpha-dev")).names.empty());
    EXPECT_TRUE(peer_permissions(nodes, "", nodes.at("alpha-dev")).names.empty());
    // Both base64 spellings of one key are one principal.
    std::string alt = "ed25519:";
    for (char ch : pb.substr(8)) {
        if (ch == '=') continue;
        alt.push_back(ch == '+' ? '-' : ch == '/' ? '_' : ch);
    }
    EXPECT_EQ(peer_permissions(nodes, alt, nodes.at("alpha-dev")).names, member.names);
}

// --- Account deletion (DeleteAccount) ---------------------------------------

class TreeAccountDeletionTest : public TreeMembershipTest {
protected:
    TreeOp account_op(const std::string& principal) {
        TreeOp op;
        op.kind = TreeOpKind::DeleteAccount;
        op.target = tree::derive_join_node_id(*crypto_svc, principal);
        op.principal = principal;
        op.body.source = TreeOpSource::Session;
        return op;
    }

    /// B is a member of alpha; A is a member of beta with add_child and owns
    /// a device it placed under beta.
    void add_cross_memberships() {
        ASSERT_TRUE(run(next(accept_op("alpha", pb, pa, {"connect_private", "read"}))).ok());
        ASSERT_TRUE(run(next(accept_op("beta", pa, pb, {"add_child", "read"}))).ok());
        const auto placed =
            node("a-in-beta", "beta", tree::NodeType::Endpoint, pa, {{pa, {"read"}}});
        ASSERT_TRUE(run(next(create_op(placed, pa))).ok());
    }

    static std::string dump(const std::optional<tree::TreeNode>& n) {
        return n ? nlohmann::json(*n).dump() : std::string{};
    }
};

TEST_F(TreeAccountDeletionTest, RemovesTheAccountSubtreeMembershipsAndGrants) {
    add_cross_memberships();
    const auto root_before = dump(tree_svc->get_node("root"));
    std::vector<tree::AccountDeletion> seen;
    tree_svc->set_account_deleted_hook(
        [&](const tree::AccountDeletion& d) { seen.push_back(d); });

    auto v = run(next(account_op(pb)));
    ASSERT_TRUE(v.ok()) << v.reason;

    // B's group and everything beneath it, including A's device placed there.
    for (const auto* id : {"beta", "beta-dev", "beta-dev2", "a-in-beta"}) {
        EXPECT_FALSE(tree_svc->get_node(id).has_value()) << id;
    }
    // B's membership in alpha is gone; A's network is otherwise unchanged.
    const auto alpha = *tree_svc->get_node("alpha");
    EXPECT_FALSE(tree::rules::signer_has_permission(alpha, pb, acl::Permission::Read));
    EXPECT_TRUE(tree::rules::signer_has_permission(alpha, pa, acl::Permission::Admin));
    for (const auto* id : {"alpha-dev", "alpha-dev2", "alpha-sub1", "alpha-sub2"}) {
        EXPECT_TRUE(tree_svc->get_node(id).has_value()) << id;
    }
    // No surviving node names B's keys.
    for (const auto& [id, n] : tree_svc->nodes_snapshot()) {
        for (const auto& a : n.assignments) {
            const auto key = tree::canonical_principal(a.management_pubkey);
            EXPECT_NE(key, tree::canonical_principal(pb)) << id;
            EXPECT_NE(key, tree::canonical_principal(pb2)) << id;
        }
    }
    EXPECT_EQ(dump(tree_svc->get_node("root")), root_before) << "the root never changes";

    ASSERT_EQ(seen.size(), 1u);
    EXPECT_EQ(seen[0].account_id, tree::derive_join_node_id(*crypto_svc, pb));
    EXPECT_EQ(seen[0].removed.size(), 4u);
    // pa still owns alpha, so only B's keys are swept.
    std::vector<std::string> expected = {tree::canonical_principal(pb),
                                         tree::canonical_principal(pb2)};
    std::sort(expected.begin(), expected.end());
    EXPECT_EQ(seen[0].swept_keys, expected);
    tree_svc->set_account_deleted_hook({});
}

TEST_F(TreeAccountDeletionTest, OtherAccountsAndTheirMembershipsStay) {
    add_cross_memberships();
    // Deleting A's account removes alpha and A's device under beta, and A's
    // membership in beta, but leaves B's account whole.
    ASSERT_TRUE(run(next(account_op(pa))).ok());
    EXPECT_FALSE(tree_svc->get_node("alpha").has_value());
    EXPECT_FALSE(tree_svc->get_node("alpha-dev2").has_value()) << "a device in A's group";
    EXPECT_FALSE(tree_svc->get_node("a-in-beta").has_value()) << "a node A's key owns";
    EXPECT_TRUE(tree_svc->get_node("beta").has_value());
    EXPECT_TRUE(tree_svc->get_node("beta-dev").has_value());
    EXPECT_TRUE(tree_svc->get_node("beta-dev2").has_value());
    EXPECT_FALSE(tree_svc->check_permission(pa, "beta", acl::Permission::Read));
    EXPECT_TRUE(tree_svc->administers(pb, "beta-dev2"));
}

TEST_F(TreeAccountDeletionTest, TheRootOwnersAccountGoesAndTheRootStays) {
    const auto root_before = dump(tree_svc->get_node("root"));
    const auto own = node("root-owner-group", "root", tree::NodeType::Customer, root_pk,
                          {{root_pk, {"admin"}}});
    ASSERT_TRUE(run(next(create_op(own, root_pk))).ok());
    const auto dev = node("root-owner-dev", "root-owner-group", tree::NodeType::Endpoint, root_pk,
                          {{root_pk, {"read"}}});
    ASSERT_TRUE(run(next(create_op(dev, root_pk))).ok());

    auto v = run(next(account_op(root_pk)));
    ASSERT_TRUE(v.ok()) << v.reason;
    EXPECT_FALSE(tree_svc->get_node("root-owner-group").has_value());
    EXPECT_FALSE(tree_svc->get_node("root-owner-dev").has_value());
    EXPECT_EQ(dump(tree_svc->get_node("root")), root_before)
        << "the root and its owner assignment never change";
    // Every other account stays.
    EXPECT_TRUE(tree_svc->get_node("alpha").has_value());
    EXPECT_TRUE(tree_svc->get_node("beta-dev").has_value());
    EXPECT_TRUE(tree_svc->is_mgmt_pubkey_in_use(root_pk)) << "the root still names the key";
}

TEST_F(TreeAccountDeletionTest, RefusesAnotherAccountForgeryAndReplay) {
    // An op that names another principal's account is refused.
    auto other = account_op(pb);
    other.target = tree::derive_join_node_id(*crypto_svc, pa);
    EXPECT_EQ(run(next(other)).refusal, TreeOpRefusal::Malformed);
    // A base version other than 0.
    auto based = account_op(pb);
    based.base_version = 1;
    EXPECT_EQ(run(next(based)).refusal, TreeOpRefusal::Malformed);
    // A principal that is not an ed25519 key has no account id.
    auto bad = account_op(pb);
    bad.principal = "not-a-key";
    EXPECT_EQ(run(next(bad)).refusal, TreeOpRefusal::Malformed);
    // A submitter outside the trusted set.
    EXPECT_EQ(run(seal(account_op(pb), ++clock, &stranger_kp)).refusal,
              TreeOpRefusal::UntrustedSubmitter);
    // A tampered op no longer matches its id.
    auto tampered = next(account_op(pb));
    tampered.principal = pa;
    EXPECT_EQ(run(tampered).refusal, TreeOpRefusal::BadOpId);
    // A stale op.
    EXPECT_EQ(run(seal(account_op(pb), clock - tree::kTreeOpMaxAgeSec - 1)).refusal,
              TreeOpRefusal::Stale);
    EXPECT_TRUE(tree_svc->get_node("beta").has_value()) << "nothing was deleted";

    const auto op = next(account_op(pb));
    ASSERT_TRUE(run(op).ok());
    EXPECT_EQ(run(op).refusal, TreeOpRefusal::Replayed);
}

TEST_F(TreeAccountDeletionTest, ARepeatedDeletionChangesNothing) {
    ASSERT_TRUE(run(next(account_op(pb))).ok());
    const auto digest = tree_svc->tree_digest();
    auto v = run(next(account_op(pb)));
    EXPECT_TRUE(v.ok()) << v.reason;
    EXPECT_EQ(tree_svc->tree_digest(), digest);
}

TEST_F(TreeAccountDeletionTest, ReplicasApplyTheSameDeletion) {
    auto storage_b = make_storage("acct-b");
    tree::PermissionTreeService tree_b(*storage_b, *crypto_svc);
    tree_b.start();
    build(tree_b);
    auto both = [&](const TreeOp& op) {
        const auto sig = tree::tree_op_signature_bytes(op);
        ASSERT_TRUE(sig.has_value());
        const auto decoded = tree::decode_tree_op(tree::encode_tree_op(op), *sig);
        ASSERT_TRUE(decoded.has_value());
        EXPECT_EQ(tree::op_id_hex(*decoded), tree::op_id_hex(op));
        auto va = run(op);
        auto vb = run(*decoded, &tree_b);
        ASSERT_EQ(va.refusal, vb.refusal) << va.reason << " / " << vb.reason;
        ASSERT_TRUE(va.ok()) << va.reason;
    };
    both(next(accept_op("alpha", pb, pa, {"connect_private", "read"})));
    both(next(accept_op("beta", pa, pb, {"add_child", "read"})));
    both(next(account_op(pb)));
    EXPECT_EQ(tree_svc->tree_digest(), tree_b.tree_digest());
    tree_b.stop();
    storage_b->stop();
}

TEST_F(TreeAccountDeletionTest, TheDeletionSurvivesARestart) {
    const auto op = next(account_op(pb));
    ASSERT_TRUE(run(op).ok());
    tree_svc->stop();
    tree_svc = std::make_unique<tree::PermissionTreeService>(*storage_svc, *crypto_svc);
    tree_svc->start();
    EXPECT_FALSE(tree_svc->get_node("beta").has_value());
    EXPECT_FALSE(tree_svc->get_node("beta-dev").has_value());
    EXPECT_TRUE(tree_svc->get_node("alpha").has_value());
    EXPECT_EQ(run(op).refusal, TreeOpRefusal::Replayed) << "replay stays refused after a restart";
}

// =========================================================================
// Invite redemption across Tier 1 servers (link extension, invite grant)
// =========================================================================

/// Server A (server_kp) and server B (server_b_kp) are both trusted
/// submitters. An invite is minted on one and redeemed through the other.
class TreeInviteRedemptionTest : public TreeMembershipTest {
protected:
    crypto::Ed25519Keypair server_b_kp;

    void SetUp() override {
        TreeMembershipTest::SetUp();
        server_b_kp = crypto_svc->ed25519_keygen();
        policy.trusted_submitters.push_back(principal_of(server_b_kp));
    }

    /// The signed mint a Tier 1 server makes for an invite to `group`.
    auth::LinkTokenEvent grant(const crypto::Ed25519Keypair& minter, const std::string& group,
                               const std::string& owner, std::vector<std::string> perms,
                               const std::string& token = "lnk_invite", uint64_t ttl = 600) {
        auth::LinkTokenEvent g;
        g.kind = auth::LinkTokenEventKind::Mint;
        g.token_hash = auth::link_token_hash_hex(token);
        g.network_id = crypto::to_hex(std::span<const uint8_t>(network.data(), network.size()));
        g.expires_at = kBlock + ttl;
        g.group_node_id = group;
        g.permissions = std::move(perms);
        g.owner_user_id = "owner";
        g.owner_pubkey = owner;
        g.created_at = kBlock;
        g.timestamp = kBlock;
        g.origin_pubkey = b64(minter.public_key);
        g.origin_seq = 1;
        resign(g, minter);
        return g;
    }

    void resign(auth::LinkTokenEvent& g, const crypto::Ed25519Keypair& minter) {
        const auto bytes = auth::link_token_event_signing_bytes(g);
        g.signature = crypto::to_base64(
            crypto_svc->ed25519_sign(minter.private_key, std::span<const uint8_t>(bytes)));
    }

    /// A linked join op that carries the link extension and `g`.
    TreeOp linked_join(const crypto::Ed25519Keypair& device, const auth::LinkTokenEvent& g) {
        auto op = join_op(device, g.group_node_id, g.owner_pubkey);
        op.body.link_extension = true;
        op.body.invite_grant = g;
        return op;
    }

    TreeOp accept_with(const std::string& invitee, const auth::LinkTokenEvent& g) {
        auto op = accept_op(g.group_node_id, invitee, g.owner_pubkey, g.permissions);
        op.body.link_extension = true;
        op.body.invite_grant = g;
        return op;
    }

    TreeOp seal_by(TreeOp op, const crypto::Ed25519Keypair& submitter) {
        return seal(std::move(op), ++clock, &submitter);
    }
};

TEST_F(TreeInviteRedemptionTest, AnInviteMintedOnOneServerIsRedeemedThroughAnother) {
    const auto g = grant(server_kp, "alpha", pa, {"read", "connect_private"});
    const auto device = crypto_svc->ed25519_keygen();
    auto v = run(seal_by(linked_join(device, g), server_b_kp));
    ASSERT_TRUE(v.ok()) << v.reason;
    const auto id = tree::derive_join_node_id(*crypto_svc, principal_of(device));
    EXPECT_EQ(tree_svc->get_node(id)->parent_id, "alpha");

    // An invite for an existing identity redeems through either server too.
    const auto g2 = grant(server_b_kp, "alpha", pa, {"read", "connect_private"}, "lnk_member");
    auto accepted = run(seal_by(accept_with(pb, g2), server_kp));
    ASSERT_TRUE(accepted.ok()) << accepted.reason;
}

// Two servers submit ops that redeem the same invite. Whatever order
// consensus fixes, every replica applies the first and refuses the second.
TEST_F(TreeInviteRedemptionTest, ASecondRedemptionIsRefusedOnEveryReplica) {
    auto storage_b = make_storage("redeem-b");
    tree::PermissionTreeService tree_b(*storage_b, *crypto_svc);
    tree_b.start();
    build(tree_b);

    const auto g = grant(server_kp, "alpha", pa, {"read", "connect_private"});
    const auto d1 = crypto_svc->ed25519_keygen();
    const auto d2 = crypto_svc->ed25519_keygen();
    const auto first = seal_by(linked_join(d1, g), server_kp);
    const auto second = seal_by(linked_join(d2, g), server_b_kp);
    const auto as_member = seal_by(accept_with(pb, g), server_b_kp);

    for (auto* svc : {tree_svc.get(), &tree_b}) {
        ASSERT_TRUE(run(first, svc).ok());
        const auto again = run(second, svc);
        EXPECT_EQ(again.refusal, TreeOpRefusal::Replayed) << again.reason;
        const auto member = run(as_member, svc);
        EXPECT_EQ(member.refusal, TreeOpRefusal::Replayed) << member.reason;
    }
    EXPECT_EQ(tree_svc->tree_digest(), tree_b.tree_digest());
    EXPECT_FALSE(tree_svc->get_node(tree::derive_join_node_id(*crypto_svc, principal_of(d2))));

    // The redemption id outlives the freshness window until the invite expires.
    tree::CommittedOpIds committed;
    tree::record_committed(committed, first);
    committed.prune_signed_before(tree::committed_id_cutoff(g.expires_at));
    EXPECT_TRUE(committed.contains(*tree::redemption_id_hex(first)));
    committed.prune_signed_before(g.expires_at + 1);
    EXPECT_FALSE(committed.contains(*tree::redemption_id_hex(first)));
    tree_b.stop();
    storage_b->stop();
}

TEST_F(TreeInviteRedemptionTest, AForgedExpiredOrMismatchedGrantIsRefused) {
    const auto device = crypto_svc->ed25519_keygen();
    const auto refusal_of = [&](const auth::LinkTokenEvent& g) {
        auto op = seal_by(linked_join(device, g), server_b_kp);
        return submit(op, clock).refusal;
    };

    auto tampered = grant(server_kp, "alpha", pa, {"read", "connect_private"});
    tampered.permissions.push_back("add_child");
    EXPECT_EQ(refusal_of(tampered), TreeOpRefusal::BadStatement);

    const auto untrusted = grant(stranger_kp, "alpha", pa, {"read"});
    EXPECT_EQ(refusal_of(untrusted), TreeOpRefusal::BadStatement);

    auto other_network = grant(server_kp, "alpha", pa, {"read"});
    other_network.network_id = std::string(64, 'f');
    resign(other_network, server_kp);
    EXPECT_EQ(refusal_of(other_network), TreeOpRefusal::WrongNetwork);

    const auto short_lived = grant(server_kp, "alpha", pa, {"read"}, "lnk_short", 60);
    clock = kBlock + 60;
    EXPECT_EQ(refusal_of(short_lived), TreeOpRefusal::Stale) << "expired by the block time";

    clock = kBlock;
    auto spend = grant(server_kp, "alpha", pa, {});
    spend.kind = auth::LinkTokenEventKind::Spend;
    resign(spend, server_kp);
    EXPECT_EQ(refusal_of(spend), TreeOpRefusal::BadStatement);

    // The op must match the grant: another group, or other permissions.
    const auto g = grant(server_kp, "alpha", pa, {"read", "connect_private"});
    auto wrong_group = linked_join(device, g);
    wrong_group.body.join.link_group_id = "beta";
    EXPECT_EQ(submit(seal_by(wrong_group, server_b_kp), clock).refusal,
              TreeOpRefusal::BadStatement);
    auto wrong_perms = accept_with(pb, g);
    wrong_perms.body.invite_permissions = {"read", "connect_private", "add_child"};
    EXPECT_EQ(submit(seal_by(wrong_perms, server_b_kp), clock).refusal,
              TreeOpRefusal::BadStatement);

    // A grant needs the extension, and only a join or an acceptance has one.
    auto no_extension = linked_join(device, g);
    no_extension.body.link_extension = false;
    EXPECT_EQ(submit(seal_by(no_extension, server_b_kp), clock).refusal,
              TreeOpRefusal::Malformed);
    auto on_move = move_op("alpha-dev2", "alpha-sub1", pa);
    on_move.body.link_extension = true;
    EXPECT_EQ(submit(seal_by(on_move, server_b_kp), clock).refusal, TreeOpRefusal::Malformed);
    EXPECT_FALSE(tree_svc->get_node(tree::derive_join_node_id(*crypto_svc, principal_of(device))));
}

// The extension is appended only when set: an op without it encodes (and
// gets the op id) exactly as an earlier release computes, and one with it
// round-trips through the wire form.
TEST_F(TreeInviteRedemptionTest, TheLinkExtensionRoundTripsAndOldOpsKeepTheirEncoding) {
    const auto device = crypto_svc->ed25519_keygen();
    const auto g = grant(server_kp, "alpha", pa, {"read", "connect_private"});
    auto plain = join_op(device, "alpha", pa);
    auto extended = plain;
    extended.body.link_extension = true;
    auto with_grant = extended;
    with_grant.body.invite_grant = g;

    const auto plain_bytes = tree::encode_tree_op(plain);
    const auto extended_bytes = tree::encode_tree_op(extended);
    ASSERT_GT(extended_bytes.size(), plain_bytes.size());
    EXPECT_TRUE(std::equal(plain_bytes.begin(), plain_bytes.end(), extended_bytes.begin()))
        << "the extension only appends";

    for (auto op : {plain, extended, with_grant}) {
        op = seal_by(op, server_kp);
        const auto decoded =
            tree::decode_tree_op(tree::encode_tree_op(op), *tree::tree_op_signature_bytes(op));
        ASSERT_TRUE(decoded.has_value());
        EXPECT_EQ(decoded->body.link_extension, op.body.link_extension);
        EXPECT_EQ(decoded->body.invite_grant, op.body.invite_grant);
        EXPECT_EQ(tree::op_id_hex(*decoded), tree::op_id_hex(op));
    }

    // An extension on another op kind does not decode.
    auto move = seal_by(move_op("alpha-dev2", "alpha-sub1", pa), server_kp);
    auto bytes = tree::encode_tree_op(move);
    bytes.insert(bytes.end(),
                 extended_bytes.begin() + static_cast<std::ptrdiff_t>(plain_bytes.size()),
                 extended_bytes.end());
    EXPECT_FALSE(tree::decode_tree_op(bytes, *tree::tree_op_signature_bytes(move)).has_value());
}

// The group owner's key already holds an entry on a linked device. With the
// extension, the join completes that entry, so the owner's first device and
// the new device reach each other. An op from an earlier release (no
// extension) keeps that release's result on every replica.
TEST_F(TreeInviteRedemptionTest, ALinkedJoinGivesTheOwnersDeviceAccessToTheNewDevice) {
    const auto with_ext = crypto_svc->ed25519_keygen();
    auto op = join_op(with_ext, "alpha", pa);
    op.body.link_extension = true;
    ASSERT_TRUE(run(seal_by(op, server_kp)).ok());
    const auto id = tree::derive_join_node_id(*crypto_svc, principal_of(with_ext));
    EXPECT_TRUE(connects(pa, "alpha-dev", id)) << "the owner's device misses the new device";
    EXPECT_TRUE(connects(principal_of(with_ext), id, "alpha-dev"));
    EXPECT_TRUE(connects(pa2, "alpha-dev2", id));
    EXPECT_TRUE(connects(principal_of(with_ext), id, "alpha-dev2"));
    EXPECT_FALSE(connects(pb, "beta-dev", id));
    // The owner keeps control of the device and gains nothing else.
    const auto node = *tree_svc->get_node(id);
    EXPECT_TRUE(tree::rules::signer_has_permission(node, pa, acl::Permission::DeleteNode));
    EXPECT_FALSE(tree::rules::signer_has_permission(node, pa, acl::Permission::Admin));

    const auto without_ext = crypto_svc->ed25519_keygen();
    ASSERT_TRUE(run(seal_by(join_op(without_ext, "alpha", pa), server_kp)).ok());
    const auto old_id = tree::derive_join_node_id(*crypto_svc, principal_of(without_ext));
    EXPECT_FALSE(connects(pa, "alpha-dev", old_id)) << "an earlier release's op keeps its result";
    EXPECT_TRUE(connects(pa2, "alpha-dev2", old_id));
}
