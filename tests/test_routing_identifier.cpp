#include <LemonadeNexus/Routing/IdentifierDerivation.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <gtest/gtest.h>

#include <filesystem>
#include <set>
#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

using namespace nexus;
namespace fs = std::filesystem;

// ---------------------------------------------------------------------------
// Pure derivation
// ---------------------------------------------------------------------------

TEST(RoutingIdentifier, IsDeterministic) {
    auto a = routing::derive_endpoint_identifier("node-1", "us-east", "cpu-x", "aa:bb", true);
    auto b = routing::derive_endpoint_identifier("node-1", "us-east", "cpu-x", "aa:bb", true);
    EXPECT_EQ(a, b);
}

TEST(RoutingIdentifier, PrefixReflectsRole) {
    EXPECT_TRUE(routing::derive_endpoint_identifier("n", "r", "c", "m", true)
                    .starts_with("infer-"));
    EXPECT_TRUE(routing::derive_endpoint_identifier("n", "r", "c", "m", false)
                    .starts_with("client-"));
}

TEST(RoutingIdentifier, DistinctInputsDiffer) {
    auto base = routing::derive_endpoint_identifier("n", "r", "cpu", "mac", true);
    EXPECT_NE(base, routing::derive_endpoint_identifier("n2", "r", "cpu", "mac", true));
    EXPECT_NE(base, routing::derive_endpoint_identifier("n", "r2", "cpu", "mac", true));
    EXPECT_NE(base, routing::derive_endpoint_identifier("n", "r", "cpu2", "mac", true));
    EXPECT_NE(base, routing::derive_endpoint_identifier("n", "r", "cpu", "mac2", true));
}

TEST(RoutingIdentifier, CoreHasEightyBits) {
    // 10 bytes -> 16 base32 chars; with 3 group separators that's "<prefix>-xxxx-xxxx-xxxx-xxxx".
    auto id = routing::derive_endpoint_identifier("n", "r", "c", "m", true);
    auto dash = id.find('-');
    ASSERT_NE(dash, std::string::npos);
    std::string label = id.substr(dash + 1);
    std::size_t core_chars = 0;
    for (char ch : label) if (ch != '-') ++core_chars;
    EXPECT_EQ(core_chars, 16u);
}

// ---------------------------------------------------------------------------
// Tree integration: binding validation, reverse index, collision rejection
// ---------------------------------------------------------------------------

class RoutingIdentifierTreeTest : public ::testing::Test {
protected:
    fs::path temp_dir;
    std::unique_ptr<crypto::SodiumCryptoService> crypto_svc;
    std::unique_ptr<storage::FileStorageService> storage_svc;
    std::unique_ptr<tree::PermissionTreeService> tree_svc;

    void SetUp() override {
        temp_dir = fs::temp_directory_path() /
                   ("nexus_test_routing_id_" + std::to_string(getpid()));
        fs::create_directories(temp_dir);

        crypto_svc = std::make_unique<crypto::SodiumCryptoService>();
        crypto_svc->start();
        storage_svc = std::make_unique<storage::FileStorageService>(temp_dir);
        storage_svc->start();
        tree_svc = std::make_unique<tree::PermissionTreeService>(*storage_svc, *crypto_svc);
        tree_svc->start();

        tree::TreeNode root;
        root.id = "root";
        root.type = tree::NodeType::Root;
        tree_svc->bootstrap_root(root);

        tree::TreeNode customer;
        customer.id = "customer-a";
        customer.parent_id = "root";
        customer.type = tree::NodeType::Customer;
        ASSERT_TRUE(tree_svc->insert_join_node(customer));
    }

    void TearDown() override {
        tree_svc->stop();
        storage_svc->stop();
        crypto_svc->stop();
        fs::remove_all(temp_dir);
    }

    tree::TreeNode make_endpoint(const std::string& id, bool is_inference,
                                 const std::string& cpu, const std::string& mac) {
        tree::TreeNode n;
        n.id = id;
        n.parent_id = "customer-a";
        n.type = tree::NodeType::Endpoint;
        n.region = "us-east";
        n.cpu_id = cpu;
        n.net_mac = mac;
        n.is_inference = is_inference;
        n.endpoint_identifier =
            routing::derive_endpoint_identifier(id, n.region, cpu, mac, is_inference);
        return n;
    }
};

TEST_F(RoutingIdentifierTreeTest, ValidBindingAndReverseLookup) {
    auto ep = make_endpoint("ep-1", true, "cpu-1", "mac-1");
    ASSERT_TRUE(tree_svc->insert_join_node(ep));

    EXPECT_TRUE(tree_svc->validate_identifier_binding(ep));

    auto resolved = tree_svc->resolve_by_identifier(ep.endpoint_identifier);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->id, "ep-1");
}

TEST_F(RoutingIdentifierTreeTest, TamperedBindingRejected) {
    auto ep = make_endpoint("ep-1", true, "cpu-1", "mac-1");
    // Stored identifier no longer matches the node's inputs.
    ep.endpoint_identifier = "infer-tamp-ered0-0000-0000";
    EXPECT_FALSE(tree_svc->validate_identifier_binding(ep));
}

TEST_F(RoutingIdentifierTreeTest, CollidingNewRegistrationRejectedIncumbentKept) {
    auto incumbent = make_endpoint("ep-1", true, "cpu-1", "mac-1");
    ASSERT_TRUE(tree_svc->insert_join_node(incumbent));

    // A different node claims the SAME identifier — must be rejected.
    tree::TreeNode squatter = make_endpoint("ep-2", true, "cpu-2", "mac-2");
    squatter.endpoint_identifier = incumbent.endpoint_identifier;
    EXPECT_FALSE(tree_svc->insert_join_node(squatter));

    // Incumbent still owns the identifier (never auto-renamed).
    auto resolved = tree_svc->resolve_by_identifier(incumbent.endpoint_identifier);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->id, "ep-1");
}

TEST_F(RoutingIdentifierTreeTest, IndexSurvivesReload) {
    auto ep = make_endpoint("ep-1", false, "cpu-1", "mac-1");
    ASSERT_TRUE(tree_svc->insert_join_node(ep));
    const std::string ident = ep.endpoint_identifier;

    // Restart the service: index must be rebuilt from persisted nodes.
    tree_svc->stop();
    tree_svc = std::make_unique<tree::PermissionTreeService>(*storage_svc, *crypto_svc);
    tree_svc->start();

    auto resolved = tree_svc->resolve_by_identifier(ident);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->id, "ep-1");
}

// ---------------------------------------------------------------------------
// M2: subtree access scope + resolve_authorized chokepoint
// ---------------------------------------------------------------------------

class RoutingScopeTest : public ::testing::Test {
protected:
    fs::path temp_dir;
    std::unique_ptr<crypto::SodiumCryptoService> crypto_svc;
    std::unique_ptr<storage::FileStorageService> storage_svc;
    std::unique_ptr<tree::PermissionTreeService> tree_svc;

    // Tree shape:
    //   root
    //   └─ customer-a
    //      ├─ client-1   (the caller)
    //      ├─ ep-sibling (grant connect_private to caller)
    //      └─ sub
    //         └─ ep-deep (grant connect_private to caller)
    //   customer-b
    //      └─ ep-other   (NOT in caller's group)
    std::string caller_pubkey = "ed25519:CALLER";

    void add(const std::string& id, const std::string& parent,
             tree::NodeType type, bool grant_connect = false,
             bool is_inference = true) {
        tree::TreeNode n;
        n.id = id;
        n.parent_id = parent;
        n.type = type;
        n.region = "us-east";
        n.cpu_id = "cpu-" + id;
        n.net_mac = "mac-" + id;
        n.is_inference = is_inference;
        if (type == tree::NodeType::Endpoint) {
            n.endpoint_identifier = routing::derive_endpoint_identifier(
                id, n.region, n.cpu_id, n.net_mac, is_inference);
        }
        if (grant_connect) {
            n.assignments = {{caller_pubkey, {"connect_private"}}};
        }
        ASSERT_TRUE(tree_svc->insert_join_node(n));
    }

    void SetUp() override {
        temp_dir = fs::temp_directory_path() /
                   ("nexus_test_routing_scope_" + std::to_string(getpid()));
        fs::create_directories(temp_dir);
        crypto_svc = std::make_unique<crypto::SodiumCryptoService>();
        crypto_svc->start();
        storage_svc = std::make_unique<storage::FileStorageService>(temp_dir);
        storage_svc->start();
        tree_svc = std::make_unique<tree::PermissionTreeService>(*storage_svc, *crypto_svc);
        tree_svc->start();

        tree::TreeNode root; root.id = "root"; root.type = tree::NodeType::Root;
        tree_svc->bootstrap_root(root);
        add("customer-a", "root", tree::NodeType::Customer);
        add("client-1",   "customer-a", tree::NodeType::Endpoint);
        add("ep-sibling", "customer-a", tree::NodeType::Endpoint, /*grant=*/true);
        add("sub",        "customer-a", tree::NodeType::Customer);
        add("ep-deep",    "sub",        tree::NodeType::Endpoint, /*grant=*/true);
        add("customer-b", "root", tree::NodeType::Customer);
        add("ep-other",   "customer-b", tree::NodeType::Endpoint, /*grant=*/true);
    }
    void TearDown() override {
        tree_svc->stop(); storage_svc->stop(); crypto_svc->stop();
        fs::remove_all(temp_dir);
    }
};

TEST_F(RoutingScopeTest, SubtreeIncludesDescendantsExcludesRoot) {
    auto sub = tree_svc->collect_subtree("customer-a");
    std::set<std::string> ids;
    for (const auto& n : sub) ids.insert(n.id);
    EXPECT_TRUE(ids.count("client-1"));
    EXPECT_TRUE(ids.count("ep-sibling"));
    EXPECT_TRUE(ids.count("sub"));
    EXPECT_TRUE(ids.count("ep-deep"));   // grandchild included
    EXPECT_FALSE(ids.count("customer-a")); // root of the walk excluded
    EXPECT_FALSE(ids.count("ep-other"));   // different group excluded
}

TEST_F(RoutingScopeTest, IsDescendantOf) {
    EXPECT_TRUE(tree_svc->is_descendant_of("ep-deep", "customer-a"));
    EXPECT_TRUE(tree_svc->is_descendant_of("ep-sibling", "customer-a"));
    EXPECT_FALSE(tree_svc->is_descendant_of("ep-other", "customer-a"));
    EXPECT_FALSE(tree_svc->is_descendant_of("customer-a", "customer-a"));
}

TEST_F(RoutingScopeTest, ResolveAuthorizedHappyPath) {
    auto ep = tree_svc->get_node("ep-sibling");
    ASSERT_TRUE(ep.has_value());
    auto out = tree_svc->resolve_authorized(caller_pubkey, "client-1",
                                            ep->endpoint_identifier);
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(out->id, "ep-sibling");

    // Deep descendant also reachable.
    auto deep = tree_svc->get_node("ep-deep");
    ASSERT_TRUE(deep.has_value());
    EXPECT_TRUE(tree_svc->resolve_authorized(caller_pubkey, "client-1",
                                             deep->endpoint_identifier).has_value());
}

TEST_F(RoutingScopeTest, ResolveAuthorizedDeniesOutOfScope) {
    auto other = tree_svc->get_node("ep-other");
    ASSERT_TRUE(other.has_value());
    // ep-other has a connect grant for the caller, but is in a DIFFERENT group:
    // scope test must exclude it regardless of the ACL.
    EXPECT_FALSE(tree_svc->resolve_authorized(caller_pubkey, "client-1",
                                              other->endpoint_identifier).has_value());
}

TEST_F(RoutingScopeTest, ResolveAuthorizedDeniesWithoutGrant) {
    // client-1 (the caller's own node) is in scope but has no connect grant for
    // the caller, and self-connect is disallowed anyway.
    auto self = tree_svc->get_node("client-1");
    ASSERT_TRUE(self.has_value());
    EXPECT_FALSE(tree_svc->resolve_authorized(caller_pubkey, "client-1",
                                              self->endpoint_identifier).has_value());
}

TEST_F(RoutingScopeTest, ResolveAuthorizedUnknownIdentifier) {
    EXPECT_FALSE(tree_svc->resolve_authorized(caller_pubkey, "client-1",
                                              "infer-does-not-exist").has_value());
}
