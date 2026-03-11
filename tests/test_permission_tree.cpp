#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <cstring>
#include <filesystem>

using namespace nexus;
namespace fs = std::filesystem;

/// Helper to create a signed delta with proper Ed25519 signature.
class PermissionTreeTest : public ::testing::Test {
protected:
    fs::path temp_dir;
    std::unique_ptr<crypto::SodiumCryptoService> crypto_svc;
    std::unique_ptr<storage::FileStorageService> storage_svc;
    std::unique_ptr<tree::PermissionTreeService> tree_svc;

    crypto::Ed25519Keypair root_keypair;
    std::string root_pubkey_str; // "ed25519:base64..."

    void SetUp() override {
        temp_dir = fs::temp_directory_path() / ("nexus_test_tree_" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()));
        fs::create_directories(temp_dir);

        crypto_svc = std::make_unique<crypto::SodiumCryptoService>();
        crypto_svc->start();

        storage_svc = std::make_unique<storage::FileStorageService>(temp_dir);
        storage_svc->start();

        tree_svc = std::make_unique<tree::PermissionTreeService>(*storage_svc, *crypto_svc);

        // Generate root keypair
        root_keypair = crypto_svc->ed25519_keygen();
        root_pubkey_str = "ed25519:" + crypto::to_base64(root_keypair.public_key);

        // Manually bootstrap a root node in storage so tree can load it
        bootstrap_root_node();

        tree_svc->start();
    }

    void TearDown() override {
        tree_svc->stop();
        storage_svc->stop();
        crypto_svc->stop();
        fs::remove_all(temp_dir);
    }

    /// Bootstrap a self-signed root node directly into storage
    void bootstrap_root_node() {
        tree::TreeNode root;
        root.id = "root";
        root.parent_id = "";
        root.type = tree::NodeType::Root;
        root.mgmt_pubkey = root_pubkey_str;
        root.assignments = {{root_pubkey_str, {"admin"}}};

        // Self-sign the root node
        auto canonical = tree::canonical_node_json(root);
        auto msg = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
        auto sig = crypto_svc->ed25519_sign(root_keypair.private_key, msg);
        root.signature = crypto::to_base64(sig);

        // Persist directly via storage
        storage::SignedEnvelope env;
        env.version = 1;
        env.type = "tree_node";
        env.data = nlohmann::json(root).dump();
        env.signer_pubkey = root_pubkey_str;
        env.signature = root.signature;
        storage_svc->write_node("root", env);
    }

    /// Create a properly signed delta
    tree::TreeDelta make_signed_delta(const std::string& operation,
                                       const std::string& target_node_id,
                                       const tree::TreeNode& node_data,
                                       const crypto::Ed25519Keypair& signer) {
        tree::TreeDelta delta;
        delta.operation = operation;
        delta.target_node_id = target_node_id;
        delta.node_data = node_data;
        delta.signer_pubkey = "ed25519:" + crypto::to_base64(signer.public_key);

        auto now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        delta.timestamp = now;

        auto canonical = tree::canonical_delta_json(delta);
        auto msg = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
        auto sig = crypto_svc->ed25519_sign(signer.private_key, msg);
        delta.signature = crypto::to_base64(sig);
        return delta;
    }
};

// --- Basic operations ---

TEST_F(PermissionTreeTest, RootNodeExistsAfterStart) {
    auto root = tree_svc->get_node("root");
    ASSERT_TRUE(root.has_value());
    EXPECT_EQ(root->id, "root");
    EXPECT_EQ(root->type, tree::NodeType::Root);
}

TEST_F(PermissionTreeTest, GetNonExistentNodeReturnsNullopt) {
    auto node = tree_svc->get_node("nonexistent");
    EXPECT_FALSE(node.has_value());
}

// --- Create node ---

TEST_F(PermissionTreeTest, CreateChildNode) {
    tree::TreeNode child;
    child.id = "customer1";
    child.parent_id = "root";
    child.type = tree::NodeType::Customer;
    child.mgmt_pubkey = root_pubkey_str;

    auto delta = make_signed_delta("create_node", "customer1", child, root_keypair);
    EXPECT_TRUE(tree_svc->apply_delta(delta));

    auto node = tree_svc->get_node("customer1");
    ASSERT_TRUE(node.has_value());
    EXPECT_EQ(node->id, "customer1");
    EXPECT_EQ(node->parent_id, "root");
    EXPECT_EQ(node->type, tree::NodeType::Customer);
}

TEST_F(PermissionTreeTest, CreateDuplicateNodeFails) {
    tree::TreeNode child;
    child.id = "customer1";
    child.parent_id = "root";
    child.type = tree::NodeType::Customer;
    child.mgmt_pubkey = root_pubkey_str;

    auto delta1 = make_signed_delta("create_node", "customer1", child, root_keypair);
    EXPECT_TRUE(tree_svc->apply_delta(delta1));

    // Second create with same ID should fail
    auto delta2 = make_signed_delta("create_node", "customer1", child, root_keypair);
    EXPECT_FALSE(tree_svc->apply_delta(delta2));
}

// --- Update node ---

TEST_F(PermissionTreeTest, UpdateExistingNode) {
    // Create a child first
    tree::TreeNode child;
    child.id = "customer1";
    child.parent_id = "root";
    child.type = tree::NodeType::Customer;
    child.mgmt_pubkey = root_pubkey_str;
    child.assignments = {{root_pubkey_str, {"edit_node"}}};

    auto create_delta = make_signed_delta("create_node", "customer1", child, root_keypair);
    ASSERT_TRUE(tree_svc->apply_delta(create_delta));

    // Update it
    child.tunnel_ip = "10.64.0.1/32";
    auto update_delta = make_signed_delta("update_node", "customer1", child, root_keypair);
    EXPECT_TRUE(tree_svc->apply_delta(update_delta));

    auto node = tree_svc->get_node("customer1");
    ASSERT_TRUE(node.has_value());
    EXPECT_EQ(node->tunnel_ip, "10.64.0.1/32");
}

// --- Delete node ---

TEST_F(PermissionTreeTest, DeleteExistingNode) {
    tree::TreeNode child;
    child.id = "to_delete";
    child.parent_id = "root";
    child.type = tree::NodeType::Customer;
    child.mgmt_pubkey = root_pubkey_str;
    child.assignments = {{root_pubkey_str, {"delete_node"}}};

    auto create = make_signed_delta("create_node", "to_delete", child, root_keypair);
    ASSERT_TRUE(tree_svc->apply_delta(create));

    auto del = make_signed_delta("delete_node", "to_delete", child, root_keypair);
    EXPECT_TRUE(tree_svc->apply_delta(del));

    EXPECT_FALSE(tree_svc->get_node("to_delete").has_value());
}

// --- Permission checks ---

TEST_F(PermissionTreeTest, CheckPermissionOnRootNode) {
    EXPECT_TRUE(tree_svc->check_permission(root_pubkey_str, "root", acl::Permission::Admin));
}

TEST_F(PermissionTreeTest, UnknownSignerLacksPermission) {
    auto unknown_kp = crypto_svc->ed25519_keygen();
    auto unknown_pub = "ed25519:" + crypto::to_base64(unknown_kp.public_key);
    EXPECT_FALSE(tree_svc->check_permission(unknown_pub, "root", acl::Permission::Read));
}

TEST_F(PermissionTreeTest, DeltaWithInsufficientPermsFails) {
    auto unauthorized_kp = crypto_svc->ed25519_keygen();

    tree::TreeNode child;
    child.id = "unauth_child";
    child.parent_id = "root";
    child.type = tree::NodeType::Customer;

    auto delta = make_signed_delta("create_node", "unauth_child", child, unauthorized_kp);
    EXPECT_FALSE(tree_svc->apply_delta(delta));
}

// --- Change permissions ---

TEST_F(PermissionTreeTest, UpdateAssignmentsOnNode) {
    // Create child with initial perms
    auto child_kp = crypto_svc->ed25519_keygen();
    auto child_pub = "ed25519:" + crypto::to_base64(child_kp.public_key);

    tree::TreeNode child;
    child.id = "customer1";
    child.parent_id = "root";
    child.type = tree::NodeType::Customer;
    child.mgmt_pubkey = child_pub;
    child.assignments = {{root_pubkey_str, {"edit_node"}},
                         {child_pub, {"read"}}};

    auto create = make_signed_delta("create_node", "customer1", child, root_keypair);
    ASSERT_TRUE(tree_svc->apply_delta(create));

    // Update assignments - grant child more permissions
    child.assignments = {{root_pubkey_str, {"edit_node", "delete_node"}},
                         {child_pub, {"read", "write", "add_child"}}};

    auto update = make_signed_delta("update_assignment", "customer1", child, root_keypair);
    EXPECT_TRUE(tree_svc->apply_delta(update));

    auto node = tree_svc->get_node("customer1");
    ASSERT_TRUE(node.has_value());
    EXPECT_EQ(node->assignments.size(), 2u);
}

// --- Get children ---

TEST_F(PermissionTreeTest, GetChildrenOfRoot) {
    // Create two children under root
    for (const auto& name : {"child1", "child2"}) {
        tree::TreeNode child;
        child.id = name;
        child.parent_id = "root";
        child.type = tree::NodeType::Customer;
        child.mgmt_pubkey = root_pubkey_str;

        auto delta = make_signed_delta("create_node", name, child, root_keypair);
        ASSERT_TRUE(tree_svc->apply_delta(delta));
    }

    auto children = tree_svc->get_children("root");
    EXPECT_EQ(children.size(), 2u);
}

// --- Get nodes by type ---

TEST_F(PermissionTreeTest, GetNodesByType) {
    // Create a customer and a relay
    tree::TreeNode customer;
    customer.id = "cust1";
    customer.parent_id = "root";
    customer.type = tree::NodeType::Customer;
    customer.mgmt_pubkey = root_pubkey_str;
    ASSERT_TRUE(tree_svc->apply_delta(
        make_signed_delta("create_node", "cust1", customer, root_keypair)));

    tree::TreeNode relay;
    relay.id = "relay1";
    relay.parent_id = "root";
    relay.type = tree::NodeType::Relay;
    relay.mgmt_pubkey = root_pubkey_str;
    ASSERT_TRUE(tree_svc->apply_delta(
        make_signed_delta("create_node", "relay1", relay, root_keypair)));

    auto customers = tree_svc->get_nodes_by_type(tree::NodeType::Customer);
    auto relays = tree_svc->get_nodes_by_type(tree::NodeType::Relay);
    EXPECT_EQ(customers.size(), 1u);
    EXPECT_EQ(relays.size(), 1u);
    EXPECT_EQ(customers[0].id, "cust1");
    EXPECT_EQ(relays[0].id, "relay1");
}

// --- Signature chain validation ---

TEST_F(PermissionTreeTest, ValidateSignatureChainForRoot) {
    EXPECT_TRUE(tree_svc->validate_signature_chain("root"));
}

// --- Tree hash ---

TEST_F(PermissionTreeTest, TreeHashIsDeterministic) {
    auto h1 = tree_svc->get_tree_hash();
    auto h2 = tree_svc->get_tree_hash();
    EXPECT_EQ(h1, h2);
}

TEST_F(PermissionTreeTest, TreeHashChangesWhenNodeAdded) {
    auto h1 = tree_svc->get_tree_hash();

    tree::TreeNode child;
    child.id = "new_node";
    child.parent_id = "root";
    child.type = tree::NodeType::Customer;
    child.mgmt_pubkey = root_pubkey_str;
    ASSERT_TRUE(tree_svc->apply_delta(
        make_signed_delta("create_node", "new_node", child, root_keypair)));

    auto h2 = tree_svc->get_tree_hash();
    EXPECT_NE(h1, h2);
}

// --- Timestamp validation ---

TEST_F(PermissionTreeTest, DeltaWithZeroTimestampRejected) {
    tree::TreeNode child;
    child.id = "child_zero_ts";
    child.parent_id = "root";
    child.type = tree::NodeType::Customer;
    child.mgmt_pubkey = root_pubkey_str;

    tree::TreeDelta delta;
    delta.operation = "create_node";
    delta.target_node_id = "child_zero_ts";
    delta.node_data = child;
    delta.signer_pubkey = root_pubkey_str;
    delta.timestamp = 0; // zero timestamp

    auto canonical = tree::canonical_delta_json(delta);
    auto msg = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
    auto sig = crypto_svc->ed25519_sign(root_keypair.private_key, msg);
    delta.signature = crypto::to_base64(sig);

    EXPECT_FALSE(tree_svc->apply_delta(delta));
}

// --- Replay protection ---

TEST_F(PermissionTreeTest, ReplayedDeltaRejected) {
    tree::TreeNode child;
    child.id = "child_replay";
    child.parent_id = "root";
    child.type = tree::NodeType::Customer;
    child.mgmt_pubkey = root_pubkey_str;

    auto delta = make_signed_delta("create_node", "child_replay", child, root_keypair);
    EXPECT_TRUE(tree_svc->apply_delta(delta));

    // Exact same delta replayed should be rejected
    EXPECT_FALSE(tree_svc->apply_delta(delta));
}

// --- Create an endpoint node under a customer ---

TEST_F(PermissionTreeTest, CreateEndpointUnderCustomer) {
    // Create customer
    tree::TreeNode customer;
    customer.id = "acme_corp";
    customer.parent_id = "root";
    customer.type = tree::NodeType::Customer;
    customer.mgmt_pubkey = root_pubkey_str;
    customer.assignments = {{root_pubkey_str, {"admin"}}};
    ASSERT_TRUE(tree_svc->apply_delta(
        make_signed_delta("create_node", "acme_corp", customer, root_keypair)));

    // Create endpoint under customer
    tree::TreeNode endpoint;
    endpoint.id = "acme_ep1";
    endpoint.parent_id = "acme_corp";
    endpoint.type = tree::NodeType::Endpoint;
    endpoint.mgmt_pubkey = root_pubkey_str;
    endpoint.tunnel_ip = "10.64.0.1/32";
    endpoint.wg_pubkey = "wg_test_pubkey";

    auto delta = make_signed_delta("create_node", "acme_ep1", endpoint, root_keypair);
    EXPECT_TRUE(tree_svc->apply_delta(delta));

    auto ep = tree_svc->get_node("acme_ep1");
    ASSERT_TRUE(ep.has_value());
    EXPECT_EQ(ep->type, tree::NodeType::Endpoint);
    EXPECT_EQ(ep->tunnel_ip, "10.64.0.1/32");

    // Verify it shows up as a child of the customer
    auto children = tree_svc->get_children("acme_corp");
    EXPECT_EQ(children.size(), 1u);
}
