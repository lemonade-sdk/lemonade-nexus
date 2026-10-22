#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <gtest/gtest.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

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
        temp_dir = fs::temp_directory_path() / ("nexus_test_tree_" + std::to_string(getpid()));
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

// The SDK spells principals url-safe unpadded while the server spells them
// standard base64, so BOTH live in stored nodes. Authorization must match on key
// bytes, or every SDK client 403s the moment the server canonicalizes its claim.
TEST_F(PermissionTreeTest, PrincipalMatchesAcrossBase64Spellings) {
    auto kp = crypto_svc->ed25519_keygen();
    auto std_b64 = crypto::to_base64(kp.public_key);
    std::string url_b64;
    for (char ch : std_b64) {
        if (ch == '=') continue;
        else if (ch == '+') url_b64.push_back('-');
        else if (ch == '/') url_b64.push_back('_');
        else url_b64.push_back(ch);
    }
    ASSERT_NE(url_b64, std_b64);

    // Stored the way an SDK client writes it.
    tree::TreeNode child;
    child.id = "sdk_child";
    child.parent_id = "root";
    child.type = tree::NodeType::Customer;
    child.mgmt_pubkey = "ed25519:" + url_b64;
    child.assignments = {{"ed25519:" + url_b64, {"read", "write"}}};
    auto create = make_signed_delta("create_node", "sdk_child", child, root_keypair);
    ASSERT_TRUE(tree_svc->apply_delta(create));

    // Queried the way the server now canonicalizes a JWT claim.
    EXPECT_TRUE(tree_svc->check_permission("ed25519:" + std_b64, "sdk_child",
                                            acl::Permission::Read));
    // ...and the original spelling still works.
    EXPECT_TRUE(tree_svc->check_permission("ed25519:" + url_b64, "sdk_child",
                                            acl::Permission::Read));
    // A different key is still refused.
    auto other = crypto_svc->ed25519_keygen();
    EXPECT_FALSE(tree_svc->check_permission("ed25519:" + crypto::to_base64(other.public_key),
                                            "sdk_child", acl::Permission::Read));
}

// This is the owner-protection guard on credential revocation: if it misses a
// surviving node because that node spells the key differently, deleting one device
// permanently revokes the owner's still-in-use key, with no un-revoke path.
TEST_F(PermissionTreeTest, MgmtPubkeyInUseMatchesAcrossBase64Spellings) {
    auto kp = crypto_svc->ed25519_keygen();
    auto std_b64 = crypto::to_base64(kp.public_key);
    std::string url_b64;
    for (char ch : std_b64) {
        if (ch == '=') continue;
        else if (ch == '+') url_b64.push_back('-');
        else if (ch == '/') url_b64.push_back('_');
        else url_b64.push_back(ch);
    }
    ASSERT_NE(url_b64, std_b64);

    tree::TreeNode owned;
    owned.id = "in_use_node";
    owned.parent_id = "root";
    owned.type = tree::NodeType::Customer;
    owned.mgmt_pubkey = "ed25519:" + url_b64;   // stored the SDK way
    owned.assignments = {{root_pubkey_str, {"read", "write"}}};
    ASSERT_TRUE(tree_svc->apply_delta(
        make_signed_delta("create_node", "in_use_node", owned, root_keypair)));

    // Queried the server way -- must still see the key as in use.
    EXPECT_TRUE(tree_svc->is_mgmt_pubkey_in_use("ed25519:" + std_b64));
    EXPECT_TRUE(tree_svc->is_mgmt_pubkey_in_use("ed25519:" + url_b64));

    auto other = crypto_svc->ed25519_keygen();
    EXPECT_FALSE(tree_svc->is_mgmt_pubkey_in_use(
        "ed25519:" + crypto::to_base64(other.public_key)));
}

// Writes must agree with reads: a signer whose stored assignment uses the other
// spelling has to pass do_apply_delta's authorization too, or owners can read a
// node but get 403 on every mutation of it.
TEST_F(PermissionTreeTest, DeltaAuthorizationMatchesAcrossBase64Spellings) {
    auto kp = crypto_svc->ed25519_keygen();
    auto std_b64 = crypto::to_base64(kp.public_key);
    std::string url_b64;
    for (char ch : std_b64) {
        if (ch == '=') continue;
        else if (ch == '+') url_b64.push_back('-');
        else if (ch == '/') url_b64.push_back('_');
        else url_b64.push_back(ch);
    }
    ASSERT_NE(url_b64, std_b64);

    // Parent grants the key under the STANDARD spelling...
    tree::TreeNode parent;
    parent.id = "spell_parent";
    parent.parent_id = "root";
    parent.type = tree::NodeType::Customer;
    parent.mgmt_pubkey = "ed25519:" + std_b64;
    parent.assignments = {{"ed25519:" + std_b64, {"read", "write", "add_child"}}};
    ASSERT_TRUE(tree_svc->apply_delta(
        make_signed_delta("create_node", "spell_parent", parent, root_keypair)));

    // ...and the client signs its delta under the URL-SAFE spelling. Sign with that
    // spelling in place: the signature covers signer_pubkey.
    tree::TreeNode child;
    child.id = "spell_child";
    child.parent_id = "spell_parent";
    child.type = tree::NodeType::Endpoint;

    tree::TreeDelta delta;
    delta.operation      = "create_node";
    delta.target_node_id = "spell_child";
    delta.node_data      = child;
    delta.signer_pubkey  = "ed25519:" + url_b64;
    delta.timestamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    auto canonical = tree::canonical_delta_json(delta);
    auto msg = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
    delta.signature = crypto::to_base64(crypto_svc->ed25519_sign(kp.private_key, msg));

    EXPECT_TRUE(tree_svc->apply_delta(delta));
    EXPECT_TRUE(tree_svc->get_node("spell_child").has_value());
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

// --- Canonical JSON includes hostname (SDK/server parity) ---

TEST_F(PermissionTreeTest, CanonicalDeltaJsonIncludesHostname) {
    // Verify that canonical_delta_json includes the "hostname" key in node_data,
    // even when hostname is empty. This ensures SDK-signed deltas produce the
    // same canonical form as the server, preventing signature verification failure.
    tree::TreeNode node;
    node.id = "ep1";
    node.parent_id = "root";
    node.type = tree::NodeType::Endpoint;

    tree::TreeDelta delta;
    delta.operation = "create_node";
    delta.target_node_id = "ep1";
    delta.node_data = node;
    delta.signer_pubkey = root_pubkey_str;
    delta.timestamp = 1000;

    auto canonical = tree::canonical_delta_json(delta);
    // hostname must appear in the canonical JSON
    EXPECT_NE(canonical.find("\"hostname\""), std::string::npos)
        << "canonical delta JSON must include hostname field for SDK/server parity";
}

TEST_F(PermissionTreeTest, CanonicalDeltaJsonWithHostnameSet) {
    tree::TreeNode node;
    node.id = "ep2";
    node.parent_id = "root";
    node.type = tree::NodeType::Endpoint;
    node.hostname = "my-laptop";

    tree::TreeDelta delta;
    delta.operation = "create_node";
    delta.target_node_id = "ep2";
    delta.node_data = node;
    delta.signer_pubkey = root_pubkey_str;
    delta.timestamp = 1000;

    auto canonical = tree::canonical_delta_json(delta);
    EXPECT_NE(canonical.find("\"hostname\":\"my-laptop\""), std::string::npos);
}

TEST_F(PermissionTreeTest, CanonicalJsonUsesMeshPubkeyLabel) {
    // Wire and canonical (signed) forms both bind "mesh_pubkey".
    tree::TreeNode node;
    node.id = "ep-mesh-key";
    node.parent_id = "root";
    node.type = tree::NodeType::Endpoint;
    node.mesh_pubkey = "mesh-key";

    nlohmann::json current = node;
    EXPECT_EQ(current.at("mesh_pubkey"), "mesh-key");

    const auto canonical_node = tree::canonical_node_json(node);
    EXPECT_NE(canonical_node.find("\"mesh_pubkey\":\"mesh-key\""), std::string::npos);

    tree::TreeDelta delta;
    delta.operation = "create_node";
    delta.target_node_id = node.id;
    delta.node_data = node;
    const auto canonical_delta = tree::canonical_delta_json(delta);
    EXPECT_NE(canonical_delta.find("\"mesh_pubkey\":\"mesh-key\""), std::string::npos);
}

TEST_F(PermissionTreeTest, CreateEndpointWithHostname) {
    // Create customer first
    tree::TreeNode customer;
    customer.id = "cust_host";
    customer.parent_id = "root";
    customer.type = tree::NodeType::Customer;
    customer.mgmt_pubkey = root_pubkey_str;
    customer.assignments = {{root_pubkey_str, {"admin"}}};
    ASSERT_TRUE(tree_svc->apply_delta(
        make_signed_delta("create_node", "cust_host", customer, root_keypair)));

    // Create endpoint with hostname set
    tree::TreeNode endpoint;
    endpoint.id = "ep_host";
    endpoint.parent_id = "cust_host";
    endpoint.type = tree::NodeType::Endpoint;
    endpoint.hostname = "my-laptop";
    endpoint.mgmt_pubkey = root_pubkey_str;
    endpoint.tunnel_ip = "10.64.0.5/32";

    auto delta = make_signed_delta("create_node", "ep_host", endpoint, root_keypair);
    EXPECT_TRUE(tree_svc->apply_delta(delta));

    auto ep = tree_svc->get_node("ep_host");
    ASSERT_TRUE(ep.has_value());
    EXPECT_EQ(ep->hostname, "my-laptop");
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
    endpoint.mesh_pubkey = "mesh_test_pubkey";

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

// A mesh transport static binds to exactly one node. The service holds the
// invariant for every caller; the API layer additionally compares normalized
// spellings before any dataplane change.
TEST_F(PermissionTreeTest, MeshPubkeyBindsToExactlyOneNode) {
    tree::TreeNode owner;
    owner.id = "mesh_owner";
    owner.parent_id = "root";
    owner.type = tree::NodeType::Endpoint;
    owner.mesh_pubkey = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
    ASSERT_TRUE(tree_svc->insert_join_node(owner));

    // A different node claiming the same static is refused outright.
    tree::TreeNode squatter;
    squatter.id = "mesh_squatter";
    squatter.parent_id = "root";
    squatter.type = tree::NodeType::Endpoint;
    squatter.mesh_pubkey = owner.mesh_pubkey;
    EXPECT_FALSE(tree_svc->insert_join_node(squatter));
    EXPECT_FALSE(tree_svc->get_node("mesh_squatter").has_value());

    // And a different node updating itself onto the static is refused too.
    tree::TreeNode bystander;
    bystander.id = "mesh_bystander";
    bystander.parent_id = "root";
    bystander.type = tree::NodeType::Endpoint;
    bystander.mesh_pubkey = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=";
    ASSERT_TRUE(tree_svc->insert_join_node(bystander));
    tree::TreeNode stolen = bystander;
    stolen.mesh_pubkey = owner.mesh_pubkey;
    EXPECT_FALSE(tree_svc->update_node_direct("mesh_bystander", stolen));
    EXPECT_EQ(tree_svc->get_node("mesh_bystander")->mesh_pubkey, bystander.mesh_pubkey);

    // The owner itself may rotate and rebind freely.
    tree::TreeNode rotated = owner;
    rotated.mesh_pubkey = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=";
    EXPECT_TRUE(tree_svc->update_node_direct("mesh_owner", rotated));
    tree::TreeNode back = rotated;
    back.mesh_pubkey = owner.mesh_pubkey;
    EXPECT_TRUE(tree_svc->update_node_direct("mesh_owner", back));
}

// --- Administration: who may change assignments ---

namespace {

/// A group under root administered by `owner`, with one endpoint whose own key
/// holds the edit rights every joined device gets on itself.
struct GroupFixture {
    crypto::Ed25519Keypair owner_kp, device_kp;
    std::string owner, device;
};

} // namespace

class TreeAdministrationTest : public PermissionTreeTest {
protected:
    GroupFixture g;

    std::string pub(const crypto::Ed25519Keypair& kp) {
        return "ed25519:" + crypto::to_base64(kp.public_key);
    }

    void SetUp() override {
        PermissionTreeTest::SetUp();
        g.owner_kp = crypto_svc->ed25519_keygen();
        g.device_kp = crypto_svc->ed25519_keygen();
        g.owner = pub(g.owner_kp);
        g.device = pub(g.device_kp);

        tree::TreeNode owner_dev;
        owner_dev.id = "owner-dev";
        owner_dev.parent_id = "grp";
        owner_dev.type = tree::NodeType::Endpoint;
        owner_dev.mgmt_pubkey = g.owner;

        tree::TreeNode grp;
        grp.id = "grp";
        grp.parent_id = "root";
        grp.type = tree::NodeType::Customer;
        grp.mgmt_pubkey = g.owner;
        grp.assignments = {{g.owner, {"read", "write", "add_child", "delete_node",
                                      "edit_node", "admin"}}};
        ASSERT_TRUE(tree_svc->apply_delta(make_signed_delta("create_node", "grp", grp,
                                                            root_keypair)));
        ASSERT_TRUE(tree_svc->apply_delta(make_signed_delta("create_node", "owner-dev",
                                                            owner_dev, g.owner_kp)));

        tree::TreeNode dev;
        dev.id = "dev";
        dev.parent_id = "grp";
        dev.type = tree::NodeType::Endpoint;
        dev.mgmt_pubkey = g.device;
        dev.assignments = {{g.device, {"read", "write", "edit_node"}},
                           {g.owner, {"read", "write", "add_child", "delete_node",
                                      "edit_node"}}};
        ASSERT_TRUE(tree_svc->apply_delta(make_signed_delta("create_node", "dev", dev,
                                                            g.owner_kp)));
    }

    void restart_tree() {
        tree_svc->stop();
        tree_svc = std::make_unique<tree::PermissionTreeService>(*storage_svc, *crypto_svc);
        tree_svc->start();
    }
};

// The overwrite this guards against: an edit_node holder renames its own record
// onto "root", the server persists it under that id, and the next restart loads
// the forged root with the device as admin.
TEST_F(TreeAdministrationTest, UpdateCannotRenameANodeOntoAnotherNode) {
    tree::TreeNode forged = *tree_svc->get_node("dev");
    forged.id = "root";
    forged.parent_id = "";
    forged.type = tree::NodeType::Root;
    forged.assignments = {{g.device, {"admin"}}};
    EXPECT_FALSE(tree_svc->apply_delta(make_signed_delta("update_node", "dev", forged,
                                                         g.device_kp)));

    restart_tree();
    EXPECT_FALSE(tree_svc->check_permission(g.device, "root", acl::Permission::Admin));
    EXPECT_TRUE(tree_svc->check_permission(root_pubkey_str, "root", acl::Permission::Admin));
    EXPECT_EQ(tree_svc->get_node("dev")->parent_id, "grp");
}

TEST_F(TreeAdministrationTest, UpdateKeepsParentTypeAndManagementKey) {
    auto base = *tree_svc->get_node("dev");

    auto moved = base;
    moved.parent_id = "root";
    EXPECT_FALSE(tree_svc->apply_delta(make_signed_delta("update_node", "dev", moved,
                                                         g.device_kp)));
    auto retyped = base;
    retyped.type = tree::NodeType::Customer;
    EXPECT_FALSE(tree_svc->apply_delta(make_signed_delta("update_node", "dev", retyped,
                                                         g.device_kp)));
    auto rekeyed = base;
    rekeyed.mgmt_pubkey = pub(crypto_svc->ed25519_keygen());
    EXPECT_FALSE(tree_svc->apply_delta(make_signed_delta("update_node", "dev", rekeyed,
                                                         g.device_kp)));

    // An ordinary field edit by the same holder still applies.
    auto renamed = base;
    renamed.hostname = "laptop";
    EXPECT_TRUE(tree_svc->apply_delta(make_signed_delta("update_node", "dev", renamed,
                                                        g.device_kp)));
    EXPECT_EQ(tree_svc->get_node("dev")->hostname, "laptop");
}

TEST_F(TreeAdministrationTest, EditNodeCannotChangeAssignments) {
    const auto outsider = pub(crypto_svc->ed25519_keygen());
    auto base = *tree_svc->get_node("dev");

    auto self_grant = base;
    self_grant.assignments[0].permissions.push_back("admin");
    EXPECT_FALSE(tree_svc->apply_delta(make_signed_delta("update_assignment", "dev",
                                                         self_grant, g.device_kp)));
    auto add_other = base;
    add_other.assignments.push_back({outsider, {"read", "connect_private"}});
    EXPECT_FALSE(tree_svc->apply_delta(make_signed_delta("update_node", "dev", add_other,
                                                         g.device_kp)));
    auto drop_owner = base;
    drop_owner.assignments.pop_back();
    EXPECT_FALSE(tree_svc->apply_delta(make_signed_delta("update_node", "dev", drop_owner,
                                                         g.device_kp)));

    EXPECT_FALSE(tree_svc->check_permission(g.device, "dev", acl::Permission::Admin));
    EXPECT_FALSE(tree_svc->check_permission(outsider, "dev", acl::Permission::Read));
    EXPECT_TRUE(tree_svc->check_permission(g.owner, "dev", acl::Permission::DeleteNode));
}

TEST_F(TreeAdministrationTest, GroupAdminPromotesOnlyJoinedMembers) {
    auto grp = *tree_svc->get_node("grp");

    // The device has joined the group, so its owner may promote it.
    auto promote = grp;
    promote.assignments.push_back({g.device, {"admin"}});
    EXPECT_TRUE(tree_svc->apply_delta(make_signed_delta("update_assignment", "grp", promote,
                                                        g.owner_kp)));
    EXPECT_TRUE(tree_svc->check_permission(g.device, "grp", acl::Permission::Admin));

    // A key that never joined cannot be named, even by an admin.
    auto stranger = *tree_svc->get_node("grp");
    stranger.assignments.push_back({pub(crypto_svc->ed25519_keygen()), {"read"}});
    EXPECT_FALSE(tree_svc->apply_delta(make_signed_delta("update_assignment", "grp",
                                                         stranger, g.owner_kp)));

    // A member of another group has joined, but not this group.
    tree::TreeNode other_grp;
    other_grp.id = "other";
    other_grp.parent_id = "root";
    other_grp.type = tree::NodeType::Customer;
    const auto other_kp = crypto_svc->ed25519_keygen();
    other_grp.mgmt_pubkey = pub(other_kp);
    ASSERT_TRUE(tree_svc->apply_delta(make_signed_delta("create_node", "other", other_grp,
                                                        root_keypair)));
    auto cross = *tree_svc->get_node("grp");
    cross.assignments.push_back({pub(other_kp), {"read"}});
    EXPECT_FALSE(tree_svc->apply_delta(make_signed_delta("update_assignment", "grp", cross,
                                                         g.owner_kp)));
}

TEST_F(TreeAdministrationTest, AdminOfAGroupAdministersItsDevicesButNotOtherGroups) {
    // The owner holds admin on the group, not on the device: the ancestor walk
    // lets it change the device's assignments.
    auto dev = *tree_svc->get_node("dev");
    dev.assignments[0].permissions = {"read"};
    EXPECT_TRUE(tree_svc->apply_delta(make_signed_delta("update_assignment", "dev", dev,
                                                        g.owner_kp)));
    EXPECT_FALSE(tree_svc->check_permission(g.device, "dev", acl::Permission::EditNode));

    // Its admin does not reach above the group.
    auto root = *tree_svc->get_node("root");
    root.assignments.push_back({g.owner, {"admin"}});
    EXPECT_FALSE(tree_svc->apply_delta(make_signed_delta("update_assignment", "root", root,
                                                         g.owner_kp)));
}

TEST_F(TreeAdministrationTest, CreateNamesOthersOnlyAsAnAdmin) {
    // The device may add a child under itself (owner grants add_child first).
    auto dev = *tree_svc->get_node("dev");
    dev.assignments[0].permissions.push_back("add_child");
    ASSERT_TRUE(tree_svc->apply_delta(make_signed_delta("update_assignment", "dev", dev,
                                                        g.owner_kp)));

    tree::TreeNode child;
    child.id = "dev-child";
    child.parent_id = "dev";
    child.type = tree::NodeType::Endpoint;
    child.assignments = {{g.device, {"read", "edit_node"}}};
    EXPECT_TRUE(tree_svc->apply_delta(make_signed_delta("create_node", "dev-child", child,
                                                        g.device_kp)));

    // Granting the owner's key there is a grant by a non-admin: refused.
    tree::TreeNode granting = child;
    granting.id = "dev-child-2";
    granting.assignments.push_back({g.owner, {"read"}});
    EXPECT_FALSE(tree_svc->apply_delta(make_signed_delta("create_node", "dev-child-2",
                                                         granting, g.device_kp)));
}

TEST_F(TreeAdministrationTest, RootIsNeverCreatedOrDeletedByDelta) {
    tree::TreeNode second_root;
    second_root.id = "root2";
    second_root.parent_id = "";
    second_root.type = tree::NodeType::Root;
    EXPECT_FALSE(tree_svc->apply_delta(make_signed_delta("create_node", "root2", second_root,
                                                         root_keypair)));

    EXPECT_FALSE(tree_svc->apply_delta(make_signed_delta("delete_node", "root",
                                                         *tree_svc->get_node("root"),
                                                         root_keypair)));
    EXPECT_TRUE(tree_svc->get_node("root").has_value());
}

// A node file whose record names a different node is refused on load instead
// of replacing that node.
TEST_F(TreeAdministrationTest, LoadRefusesAFileWhoseRecordNamesAnotherNode) {
    tree::TreeNode forged = *tree_svc->get_node("dev");
    forged.id = "root";
    forged.parent_id = "";
    forged.type = tree::NodeType::Root;
    forged.assignments = {{g.device, {"admin"}}};
    storage::SignedEnvelope env;
    env.version = 1;
    env.type = "tree_node";
    env.data = nlohmann::json(forged).dump();
    ASSERT_TRUE(storage_svc->write_node("dev", env));

    restart_tree();
    EXPECT_FALSE(tree_svc->check_permission(g.device, "root", acl::Permission::Admin));
    EXPECT_TRUE(tree_svc->check_permission(root_pubkey_str, "root", acl::Permission::Admin));
    EXPECT_FALSE(tree_svc->get_node("dev").has_value());
}

TEST_F(TreeAdministrationTest, SetAssignmentReplacesTheEntryUnderTheSameRules) {
    using Change = tree::PermissionTreeService::AssignmentChange;
    std::string reason;

    // Promote: one entry for the key, holding exactly what was set.
    ASSERT_EQ(tree_svc->set_assignment("grp", g.owner, g.device, {"read", "admin"}, reason),
              Change::Applied) << reason;
    EXPECT_TRUE(tree_svc->check_permission(g.device, "grp", acl::Permission::Admin));
    std::size_t entries = 0;
    const auto grp_node = tree_svc->get_node("grp");
    ASSERT_TRUE(grp_node.has_value());
    for (const auto& a : grp_node->assignments) {
        if (tree::canonical_principal(a.management_pubkey) ==
            tree::canonical_principal(g.device)) ++entries;
    }
    EXPECT_EQ(entries, 1u);

    // Demote by setting a smaller list, then remove with an empty one.
    ASSERT_EQ(tree_svc->set_assignment("grp", g.owner, g.device, {"read"}, reason),
              Change::Applied) << reason;
    EXPECT_FALSE(tree_svc->check_permission(g.device, "grp", acl::Permission::Admin));
    EXPECT_TRUE(tree_svc->check_permission(g.device, "grp", acl::Permission::Read));
    ASSERT_EQ(tree_svc->set_assignment("grp", g.owner, g.device, {}, reason),
              Change::Applied) << reason;
    EXPECT_FALSE(tree_svc->check_permission(g.device, "grp", acl::Permission::Read));

    // Refusals.
    EXPECT_EQ(tree_svc->set_assignment("grp", g.device, g.device, {"admin"}, reason),
              Change::Forbidden);  // not an admin
    EXPECT_EQ(tree_svc->set_assignment("grp", g.owner, pub(crypto_svc->ed25519_keygen()),
                                       {"read"}, reason),
              Change::Forbidden);  // never joined
    EXPECT_EQ(tree_svc->set_assignment("grp", g.owner, g.owner, {"read"}, reason),
              Change::Forbidden);  // own entry on its admin node
    EXPECT_EQ(tree_svc->set_assignment("grp", g.owner, g.device, {"superuser"}, reason),
              Change::Invalid);
    EXPECT_EQ(tree_svc->set_assignment("nope", g.owner, g.device, {"read"}, reason),
              Change::NotFound);
    EXPECT_TRUE(tree_svc->check_permission(g.owner, "grp", acl::Permission::Admin));

    // A group admin sets node-level access on a device in its group.
    ASSERT_EQ(tree_svc->set_assignment("dev", g.owner, g.owner, {"read", "connect_private"},
                                       reason),
              Change::Applied) << reason;
    EXPECT_TRUE(tree_svc->check_permission(g.owner, "dev", acl::Permission::ConnectPrivate));

    // The change survives a restart.
    restart_tree();
    EXPECT_TRUE(tree_svc->check_permission(g.owner, "dev", acl::Permission::ConnectPrivate));
}
