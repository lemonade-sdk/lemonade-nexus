// Closed public root-claim surface: no public caller (authentication,
// registration, open_registration) may create the global permission root,
// assign its ownership, or create or restore root-level grants. Fresh root
// initialization is unavailable pending the deferred authority work. Covers
// both HTTP entry points (/api/auth and /api/join), preservation of existing
// root data and reduced/revoked assignments under repeated and concurrent
// requests, and that mesh certificate trust (root_pubkey) is unaffected.

#include <LemonadeNexus/Network/HttpServer.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>
#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/ACL/Permission.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Relay/RelayService.hpp>
#include <LemonadeNexus/Relay/RelayDiscoveryService.hpp>
#include <LemonadeNexus/Routing/RoutingCoordinationService.hpp>
#include <LemonadeNexus/Core/BinaryAttestation.hpp>
#include <LemonadeNexus/Core/ServerAdmissionService.hpp>
#include <LemonadeNexus/Network/DdnsService.hpp>
#include <LemonadeNexus/Acme/AcmeService.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Gossip/ServerCertificate.hpp>
#include <LemonadeNexus/Api/AuthApiHandler.hpp>
#include <LemonadeNexus/Api/TreeApiHandler.hpp>

#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <array>
#include <algorithm>
#include <barrier>
#include <chrono>
#include <filesystem>
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
using json = nlohmann::json;

// ============================================================================
// Unit tests
// ============================================================================

class RootClaimRegressionTest : public ::testing::Test {
protected:
    std::unique_ptr<crypto::SodiumCryptoService> crypto;

    crypto::Ed25519Keypair mesh_kp;
    crypto::Ed25519Keypair other_kp;

    static std::string canon_b64_of(const crypto::Ed25519Keypair& kp) {
        return crypto::to_base64(
            std::span<const uint8_t>(kp.public_key.data(), kp.public_key.size()));
    }

    void SetUp() override {
        crypto = std::make_unique<crypto::SodiumCryptoService>();
        crypto->start();
        mesh_kp = crypto->ed25519_keygen();
        other_kp = crypto->ed25519_keygen();
    }

    void TearDown() override {
        crypto->stop();
    }
};

// Mesh certificate trust still anchors on root_pubkey: a certificate signed
// by the mesh root key verifies against that key and fails against any other
// key. Nothing in the root-claim closure touches this path.
TEST_F(RootClaimRegressionTest, CertificateTrustUnaffected) {
    gossip::CertIssueParams p;
    p.network_id = std::string(64, 'a');
    p.server_pubkey_b64 = canon_b64_of(other_kp);
    p.server_id = "peer-b";
    auto cert = gossip::issue_server_certificate(p, *crypto, mesh_kp.private_key,
                                                 mesh_kp.public_key);
    auto canonical = gossip::canonical_cert_json(cert);
    crypto::Ed25519Signature sig{};
    auto sig_bytes = crypto::from_base64(cert.signature);
    std::copy_n(sig_bytes.begin(), sig_bytes.size(), sig.begin());

    auto canon_span = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
    EXPECT_TRUE(crypto->do_ed25519_verify(mesh_kp.public_key, canon_span, sig));
    EXPECT_FALSE(crypto->do_ed25519_verify(other_kp.public_key, canon_span, sig));
}

// ============================================================================
// HTTP tests: /api/auth and /api/join through the real handlers
// ============================================================================

struct JoinHttpContextHolder {
    api::ApiContext* ctx = nullptr;
    api::TreeApiHandler* tree_handler = nullptr;
    api::AuthApiHandler* auth_handler = nullptr;
};
static JoinHttpContextHolder& join_holder() {
    static JoinHttpContextHolder h;
    return h;
}

class RootClaimHttpTest : public ::testing::Test {
protected:
    uint16_t test_port_{0};
    fs::path temp_dir;
    asio::io_context io;

    std::unique_ptr<crypto::SodiumCryptoService> crypto;
    std::unique_ptr<storage::FileStorageService> storage;
    std::unique_ptr<crypto::KeyWrappingService> key_wrapping;
    std::unique_ptr<tree::PermissionTreeService> tree;
    std::unique_ptr<auth::AuthService> auth;
    std::unique_ptr<ipam::IPAMService> ipam;
    std::unique_ptr<network::HttpServer> http;

    std::unique_ptr<relay::RelayService> relay;
    std::unique_ptr<relay::RelayDiscoveryService> relay_discovery;
    std::unique_ptr<gossip::GossipService> gossip;
    std::unique_ptr<routing::RoutingCoordinationService> routing;
    std::unique_ptr<core::BinaryAttestationService> attestation;
    std::unique_ptr<core::ServerAdmissionService> admission;
    std::unique_ptr<network::DdnsService> ddns;
    std::unique_ptr<acme::AcmeService> acme;

    core::ServerConfig config;
    std::string jwt_secret;
    // Deliberately distinct keys: mesh trust anchor, pre-existing root owner,
    // and an unrelated stranger.
    crypto::Ed25519Keypair mesh_kp;
    crypto::Ed25519Keypair owner_kp;
    crypto::Ed25519Keypair stranger_kp;

    static std::string hex_of(const crypto::Ed25519Keypair& kp) {
        return crypto::to_hex(
            std::span<const uint8_t>(kp.public_key.data(), kp.public_key.size()));
    }
    static std::string bare_b64(const crypto::Ed25519Keypair& kp) {
        return crypto::to_base64(
            std::span<const uint8_t>(kp.public_key.data(), kp.public_key.size()));
    }
    static std::string prefixed_b64(const crypto::Ed25519Keypair& kp) {
        return "ed25519:" + bare_b64(kp);
    }

    void SetUp() override {
        test_port_ = static_cast<uint16_t>(19300 + (getpid() % 10000));
        temp_dir = fs::temp_directory_path() / ("nexus_test_rootboot_http_" + std::to_string(getpid()));
        fs::create_directories(temp_dir);

        crypto = std::make_unique<crypto::SodiumCryptoService>();
        crypto->start();
        storage = std::make_unique<storage::FileStorageService>(temp_dir);
        storage->start();
        key_wrapping = std::make_unique<crypto::KeyWrappingService>(*crypto, *storage);
        key_wrapping->start();

        tree = std::make_unique<tree::PermissionTreeService>(*storage, *crypto);
        tree->start();

        std::array<uint8_t, 32> secret_bytes{};
        crypto->random_bytes(std::span<uint8_t>(secret_bytes));
        jwt_secret = crypto::to_hex(std::span<const uint8_t>(secret_bytes));

        auth = std::make_unique<auth::AuthService>(*storage, *crypto,
                                                   "lemonade-nexus.local", jwt_secret);
        auth->start();
        ipam = std::make_unique<ipam::IPAMService>(*storage);
        ipam->start();
        http = std::make_unique<network::HttpServer>(test_port_);

        mesh_kp = crypto->ed25519_keygen();
        owner_kp = crypto->ed25519_keygen();
        stranger_kp = crypto->ed25519_keygen();
        // Mesh trust anchor only; the test starts with NO application root.
        config.root_pubkey = hex_of(mesh_kp);
        config.open_registration = true;

        crypto::Ed25519Keypair server_kp = crypto->ed25519_keygen();
        relay = std::make_unique<relay::RelayService>(io, 0, *crypto, server_kp.public_key);
        relay_discovery = std::make_unique<relay::RelayDiscoveryService>(*storage);
        gossip = std::make_unique<gossip::GossipService>(io, 0, *storage, *crypto);
        routing = std::make_unique<routing::RoutingCoordinationService>(*crypto, *gossip);
        attestation = std::make_unique<core::BinaryAttestationService>(*crypto, *storage);
        admission = std::make_unique<core::ServerAdmissionService>(
            config, *crypto, *key_wrapping, *storage, *gossip);
        ddns = std::make_unique<network::DdnsService>(io, *crypto, *storage, *attestation, *gossip);
        acme = std::make_unique<acme::AcmeService>(*storage);

        join_holder().ctx = new api::ApiContext{
            .config           = config,
            .auth             = *auth,
            .tree             = *tree,
            .ipam             = *ipam,
            .gossip           = *gossip,
            .crypto           = *crypto,
            .key_wrapping     = *key_wrapping,
            .storage          = *storage,
            .acme             = *acme,
            .http_server      = *http,
            .ddns             = *ddns,
            .relay            = *relay,
            .relay_discovery  = *relay_discovery,
            .routing          = *routing,
            .attestation      = *attestation,
            .admission        = *admission,
            .boringtun        = nullptr,
            .dns              = nullptr,
            .server_fqdn      = "test.local",
            .server_seip_fqdn = "",
            .server_private_fqdn = "",
            .server_public_ip = "",
            .tunnel_bind_ip   = "",
        };
        join_holder().tree_handler = new api::TreeApiHandler(*join_holder().ctx);
        join_holder().tree_handler->register_routes(http->server(), http->server());
        join_holder().auth_handler = new api::AuthApiHandler(*join_holder().ctx);
        join_holder().auth_handler->register_routes(http->server(), http->server());
        http->start();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    void TearDown() override {
        http->stop();
        delete join_holder().auth_handler;
        join_holder().auth_handler = nullptr;
        delete join_holder().tree_handler;
        join_holder().tree_handler = nullptr;
        delete join_holder().ctx;
        if (auth) auth->stop();
        if (ipam) ipam->stop();
        if (tree) tree->stop();
        if (key_wrapping) key_wrapping->stop();
        if (storage) storage->stop();
        if (crypto) crypto->stop();
        fs::remove_all(temp_dir);
    }

    httplib::Client make_client() { return httplib::Client("127.0.0.1", test_port_); }

    // Full ed25519 challenge-response login; returns the /api/auth response.
    httplib::Result login(const crypto::Ed25519Keypair& kp) {
        const auto pubkey_form = bare_b64(kp);
        auto cli = make_client();
        auto c_res = cli.Post("/api/auth/challenge",
                              json{{"pubkey", pubkey_form}}.dump(), "application/json");
        if (!c_res || c_res->status != 200) return httplib::Result();
        const auto challenge_b64 =
            json::parse(c_res->body).value("challenge", std::string{});
        auto challenge = crypto::from_base64(challenge_b64);
        auto sig = crypto->ed25519_sign(kp.private_key,
                                        std::span<const uint8_t>(challenge));
        json body = {
            {"method", "ed25519"},
            {"pubkey", pubkey_form},
            {"challenge", challenge_b64},
            {"signature", crypto::to_base64(
                              std::span<const uint8_t>(sig.data(), sig.size()))},
        };
        return cli.Post("/api/auth", body.dump(), "application/json");
    }

    httplib::Result join(const crypto::Ed25519Keypair& kp) {
        auto cli = make_client();
        const auto bare = bare_b64(kp);
        auto c_res = cli.Post("/api/auth/challenge",
                              json{{"pubkey", bare}}.dump(), "application/json");
        if (!c_res || c_res->status != 200) return httplib::Result();
        const auto challenge_b64 =
            json::parse(c_res->body).value("challenge", std::string{});
        auto challenge = crypto::from_base64(challenge_b64);
        auto sig = crypto->ed25519_sign(kp.private_key,
                                        std::span<const uint8_t>(challenge));
        json body = {
            {"method", "ed25519"},
            {"pubkey", bare},
            {"public_key", prefixed_b64(kp)},
            {"challenge", challenge_b64},
            {"signature", crypto::to_base64(
                              std::span<const uint8_t>(sig.data(), sig.size()))},
        };
        return cli.Post("/api/join", body.dump(), "application/json");
    }

    // Simulates a pre-existing installation: the root was established before
    // this code existed. Seeded directly, never through a public endpoint.
    void seed_root(const crypto::Ed25519Keypair& kp,
                   const std::vector<std::string>& perms =
                       {"read", "write", "add_child", "delete_node",
                        "edit_node", "admin"}) {
        tree::TreeNode root;
        root.id          = "root";
        root.parent_id   = "";
        root.type        = tree::NodeType::Root;
        root.hostname    = "root";
        root.mgmt_pubkey = prefixed_b64(kp);
        root.assignments = {{.management_pubkey = prefixed_b64(kp),
                             .permissions = perms}};
        EXPECT_TRUE(tree->bootstrap_root(root));
    }

    // The Customer node a joiner's endpoint is placed under (if any).
    std::optional<tree::TreeNode> find_customer(const crypto::Ed25519Keypair& kp) {
        for (const auto& child : tree->get_children("root")) {
            if (child.type == tree::NodeType::Customer &&
                child.mgmt_pubkey == prefixed_b64(kp)) {
                return child;
            }
        }
        return std::nullopt;
    }

    bool root_matches(const tree::TreeNode& expected) const {
        auto root = tree->get_node("root");
        if (!root) return false;
        if (root->id != expected.id || root->type != expected.type ||
            root->mgmt_pubkey != expected.mgmt_pubkey ||
            root->hostname != expected.hostname) {
            return false;
        }
        if (root->assignments.size() != expected.assignments.size()) return false;
        for (std::size_t i = 0; i < expected.assignments.size(); ++i) {
            if (root->assignments[i].management_pubkey !=
                expected.assignments[i].management_pubkey) return false;
            if (root->assignments[i].permissions !=
                expected.assignments[i].permissions) return false;
        }
        return true;
    }
};

// /api/auth: the first caller to authenticate cannot claim the root. The
// root is not created, no ownership is assigned, and no grant appears.
TEST_F(RootClaimHttpTest, FirstCallerCannotClaimRootViaAuth) {
    auto res = login(owner_kp);
    ASSERT_TRUE(static_cast<bool>(res));
    ASSERT_EQ(res->status, 200) << res->body;
    EXPECT_TRUE(json::parse(res->body).value("authenticated", false)) << res->body;
    EXPECT_FALSE(tree->get_node("root").has_value());

    // A second, different first caller is no more privileged.
    res = login(stranger_kp);
    ASSERT_TRUE(static_cast<bool>(res));
    ASSERT_EQ(res->status, 200);
    EXPECT_FALSE(tree->get_node("root").has_value());
}

// /api/join: with no root, every caller is refused explicitly. Nothing is
// created: no root, no customer group, no endpoint.
TEST_F(RootClaimHttpTest, FirstCallerCannotClaimRootViaJoin) {
    auto res = join(owner_kp);
    ASSERT_TRUE(static_cast<bool>(res));
    ASSERT_EQ(res->status, 409) << res->body;
    EXPECT_NE(res->body.find("root initialization is unavailable"), std::string::npos);
    EXPECT_FALSE(tree->get_node("root").has_value());

    res = join(stranger_kp);
    ASSERT_TRUE(static_cast<bool>(res));
    ASSERT_EQ(res->status, 409);
    EXPECT_FALSE(tree->get_node("root").has_value());
}

// open_registration cannot be used to acquire root permissions: a joiner gets
// its own Customer/Endpoint nodes, while the pre-existing root record stays
// exactly as seeded — same owner, same single assignment.
TEST_F(RootClaimHttpTest, OpenRegistrationCannotGrantRootPermissions) {
    seed_root(owner_kp);
    const auto seeded = tree->get_node("root");
    ASSERT_TRUE(seeded.has_value());

    auto res = join(stranger_kp);
    ASSERT_TRUE(static_cast<bool>(res));
    ASSERT_EQ(res->status, 200) << res->body;

    auto customer = find_customer(stranger_kp);
    ASSERT_TRUE(customer.has_value());
    EXPECT_EQ(customer->parent_id, "root");

    // The root itself: ownership and grants unchanged.
    auto root = tree->get_node("root");
    ASSERT_TRUE(root.has_value());
    EXPECT_EQ(root->mgmt_pubkey, prefixed_b64(owner_kp));
    ASSERT_EQ(root->assignments.size(), 1u);
    EXPECT_EQ(root->assignments[0].management_pubkey, prefixed_b64(owner_kp));
    EXPECT_EQ(root->assignments[0].permissions, seeded->assignments[0].permissions);
}

// Repeated and concurrent requests against an existing root never modify it:
// the record is compared field-by-field after a sequential round and a
// concurrent burst of logins and joins.
TEST_F(RootClaimHttpTest, ExistingRootUnchangedOnRepeatedAndConcurrentRequests) {
    seed_root(owner_kp);
    const auto seeded = tree->get_node("root");
    ASSERT_TRUE(seeded.has_value());

    // Sequential round.
    EXPECT_EQ(login(owner_kp)->status, 200);
    EXPECT_EQ(login(stranger_kp)->status, 200);
    EXPECT_EQ(join(stranger_kp)->status, 200);
    ASSERT_TRUE(root_matches(*seeded));

    // Concurrent burst: mixed logins and joins, barrier-synchronized.
    std::atomic<int> logins_ok{0}, joins_ok{0};
    const int nthreads = 8;
    std::barrier sync(nthreads + 1);
    std::vector<std::thread> threads;
    threads.reserve(nthreads);
    for (int i = 0; i < nthreads; ++i) {
        threads.emplace_back([this, i, &sync, &logins_ok, &joins_ok]() {
            sync.arrive_and_wait();
            auto l = (i % 2 == 0) ? login(owner_kp) : login(stranger_kp);
            if (l && l->status == 200) logins_ok.fetch_add(1);
            auto j = join(stranger_kp);
            if (j && j->status == 200) joins_ok.fetch_add(1);
        });
    }
    sync.arrive_and_wait();
    for (auto& t : threads) t.join();

    EXPECT_GE(logins_ok.load(), 4);
    EXPECT_GE(joins_ok.load(), 2);
    EXPECT_TRUE(root_matches(*seeded)) << "root was modified by public requests";
}

// Reduced or revoked root grants survive repeated owner and stranger
// requests: no re-grant, no restore.
TEST_F(RootClaimHttpTest, ReducedAndRevokedRootGrantsPreserved) {
    seed_root(owner_kp);

    // Operator reduces the owner's grants.
    auto node = tree->get_node("root");
    tree::TreeNode reduced = *node;
    reduced.assignments[0].permissions = {"read"};
    EXPECT_TRUE(tree->update_node_direct("root", reduced));

    EXPECT_EQ(login(owner_kp)->status, 200);
    EXPECT_EQ(login(stranger_kp)->status, 200);
    EXPECT_EQ(join(stranger_kp)->status, 200);
    ASSERT_TRUE(root_matches(reduced)) << "reduced grants were restored";

    // Operator revokes the assignment entirely.
    tree::TreeNode revoked = reduced;
    revoked.assignments.clear();
    EXPECT_TRUE(tree->update_node_direct("root", revoked));

    EXPECT_EQ(login(owner_kp)->status, 200);
    EXPECT_EQ(join(stranger_kp)->status, 200);
    auto root = tree->get_node("root");
    ASSERT_TRUE(root.has_value());
    EXPECT_EQ(root->assignments.size(), 0u);
    EXPECT_EQ(root->mgmt_pubkey, prefixed_b64(owner_kp));
}

// Existing authorized join behavior is intact: with a pre-existing root and
// open registration, a joiner gets its Customer group and Endpoint under it,
// and a re-join is idempotent.
TEST_F(RootClaimHttpTest, AuthorizedJoinBehaviorUnchanged) {
    seed_root(owner_kp);

    auto res = join(stranger_kp);
    ASSERT_TRUE(static_cast<bool>(res));
    ASSERT_EQ(res->status, 200) << res->body;

    auto customer = find_customer(stranger_kp);
    ASSERT_TRUE(customer.has_value());
    EXPECT_EQ(customer->parent_id, "root");
    auto endpoints = tree->get_children(customer->id);
    ASSERT_EQ(endpoints.size(), 1u);
    EXPECT_EQ(endpoints[0].type, tree::NodeType::Endpoint);
    EXPECT_EQ(endpoints[0].mgmt_pubkey, prefixed_b64(stranger_kp));

    // Re-join: no duplicate group or endpoint.
    res = join(stranger_kp);
    ASSERT_TRUE(static_cast<bool>(res));
    ASSERT_EQ(res->status, 200) << res->body;
    EXPECT_EQ(tree->get_children(customer->id).size(), 1u);
    EXPECT_TRUE(root_matches(*tree->get_node("root")));
}

// The closed-registration link-token exemption recognizes the owner of the
// EXISTING root (pure validation of stored data) and no one else.
TEST_F(RootClaimHttpTest, ClosedRegistrationExemptionUsesExistingOwnershipOnly) {
    seed_root(owner_kp);
    config.open_registration = false;

    auto res = join(owner_kp);
    ASSERT_TRUE(static_cast<bool>(res));
    ASSERT_EQ(res->status, 200) << res->body;

    res = join(stranger_kp);
    ASSERT_TRUE(static_cast<bool>(res));
    ASSERT_EQ(res->status, 403) << res->body;
    EXPECT_NE(res->body.find("registration closed"), std::string::npos);
    EXPECT_FALSE(find_customer(stranger_kp).has_value());
}
