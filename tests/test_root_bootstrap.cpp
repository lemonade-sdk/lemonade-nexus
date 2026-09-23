// Application-owner bootstrap policy: the root node is created only for the
// locally configured owner key (ServerConfig::root_pubkey), after a real
// Ed25519 proof of possession. Covers the helper directly and both HTTP
// entry points (/api/auth and /api/join), including concurrency and the
// former open-registration grant path.

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
#include <LemonadeNexus/Api/RootBootstrap.hpp>
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
// Unit tests for bootstrap_root_for_owner
// ============================================================================

class RootBootstrapTest : public ::testing::Test {
protected:
    fs::path temp_dir;
    std::unique_ptr<crypto::SodiumCryptoService> crypto;
    std::unique_ptr<storage::FileStorageService> storage;
    std::unique_ptr<tree::PermissionTreeService> tree;

    core::ServerConfig config;

    // Deliberately three distinct keys: the mesh trust anchor (server
    // certificates), the application owner, and an unrelated stranger.
    crypto::Ed25519Keypair mesh_kp;
    crypto::Ed25519Keypair owner_kp;
    crypto::Ed25519Keypair stranger_kp;

    static std::string hex_of(const crypto::Ed25519Keypair& kp) {
        return crypto::to_hex(
            std::span<const uint8_t>(kp.public_key.data(), kp.public_key.size()));
    }
    static std::string canon_b64_of(const crypto::Ed25519Keypair& kp) {
        return crypto::to_base64(
            std::span<const uint8_t>(kp.public_key.data(), kp.public_key.size()));
    }
    // url-safe, unpadded spelling of the same key bytes
    static std::string url_unpadded(const crypto::Ed25519Keypair& kp) {
        std::string out = canon_b64_of(kp);
        for (auto& ch : out) {
            if (ch == '+') ch = '-';
            else if (ch == '/') ch = '_';
        }
        out.erase(out.find('='));
        return out;
    }

    void SetUp() override {
        temp_dir = fs::temp_directory_path() / ("nexus_test_rootboot_" + std::to_string(getpid()));
        fs::create_directories(temp_dir);

        crypto = std::make_unique<crypto::SodiumCryptoService>();
        crypto->start();
        storage = std::make_unique<storage::FileStorageService>(temp_dir);
        storage->start();
        tree = std::make_unique<tree::PermissionTreeService>(*storage, *crypto);
        tree->start();

        mesh_kp = crypto->ed25519_keygen();
        owner_kp = crypto->ed25519_keygen();
        stranger_kp = crypto->ed25519_keygen();
        config.root_pubkey = hex_of(mesh_kp);
        config.application_owner_pubkey = hex_of(owner_kp);
    }

    void TearDown() override {
        tree->stop();
        storage->stop();
        crypto->stop();
        fs::remove_all(temp_dir);
    }

    using Outcome = api::RootBootstrapOutcome;

    // Seed a foreign root directly (simulates a pre-existing installation).
    void seed_foreign_root(const std::string& foreign_canon_b64) {
        tree::TreeNode root;
        root.id          = "root";
        root.parent_id   = "";
        root.type        = tree::NodeType::Root;
        root.hostname    = "root";
        root.mgmt_pubkey = "ed25519:" + foreign_canon_b64;
        root.assignments = {{.management_pubkey = "ed25519:" + foreign_canon_b64,
                             .permissions = {"read", "write", "admin"}}};
        EXPECT_TRUE(tree->bootstrap_root(root));
    }

    std::size_t owner_assignment_count() {
        auto root = tree->get_node("root");
        if (!root) return 0;
        std::size_t n = 0;
        for (const auto& a : root->assignments) {
            if (tree::canonical_principal(a.management_pubkey) ==
                "ed25519:" + canon_b64_of(owner_kp)) {
                ++n;
            }
        }
        return n;
    }

    static bool assignments_equal(const std::vector<tree::Assignment>& a,
                                  const std::vector<tree::Assignment>& b) {
        if (a.size() != b.size()) return false;
        for (std::size_t i = 0; i < a.size(); ++i) {
            if (a[i].management_pubkey != b[i].management_pubkey) return false;
            if (a[i].permissions != b[i].permissions) return false;
        }
        return true;
    }
};

TEST_F(RootBootstrapTest, OwnerCreatesRoot) {
    EXPECT_EQ(api::bootstrap_root_for_owner(*tree, config, canon_b64_of(owner_kp)),
              Outcome::OwnerRootCreated);

    auto root = tree->get_node("root");
    ASSERT_TRUE(root.has_value());
    EXPECT_EQ(root->type, tree::NodeType::Root);
    // Stored in the canonical prefixed form, regardless of caller spelling.
    EXPECT_EQ(root->mgmt_pubkey, "ed25519:" + canon_b64_of(owner_kp));
    ASSERT_EQ(root->assignments.size(), 1u);
    EXPECT_EQ(root->assignments[0].permissions,
              (std::vector<std::string>{"read", "write", "add_child", "delete_node",
                                         "edit_node", "admin"}));
}

TEST_F(RootBootstrapTest, OwnerRootExistingIsIdempotent) {
    EXPECT_EQ(api::bootstrap_root_for_owner(*tree, config, canon_b64_of(owner_kp)),
              Outcome::OwnerRootCreated);
    for (int i = 0; i < 3; ++i) {
        EXPECT_EQ(api::bootstrap_root_for_owner(*tree, config, canon_b64_of(owner_kp)),
                  Outcome::OwnerRootExisting);
    }
    EXPECT_EQ(owner_assignment_count(), 1u);
}

TEST_F(RootBootstrapTest, UnrelatedKeyNeverCreatesRoot) {
    EXPECT_EQ(api::bootstrap_root_for_owner(*tree, config, canon_b64_of(stranger_kp)),
              Outcome::NotOwner);
    EXPECT_FALSE(tree->get_node("root").has_value());
}

// Former behavior: with open_registration=true every later authenticating key
// was granted {"read","add_child"} on the root. That grant must be gone.
TEST_F(RootBootstrapTest, UnrelatedKeyGetsNoGrantWhenRootExists) {
    config.open_registration = true;
    EXPECT_EQ(api::bootstrap_root_for_owner(*tree, config, canon_b64_of(owner_kp)),
              Outcome::OwnerRootCreated);

    EXPECT_EQ(api::bootstrap_root_for_owner(*tree, config, canon_b64_of(stranger_kp)),
              Outcome::NotOwner);

    auto root = tree->get_node("root");
    ASSERT_TRUE(root.has_value());
    EXPECT_EQ(root->assignments.size(), 1u);
    for (const auto& a : root->assignments) {
        EXPECT_NE(tree::canonical_principal(a.management_pubkey),
                  "ed25519:" + canon_b64_of(stranger_kp));
    }
}

TEST_F(RootBootstrapTest, MissingOwnerConfigRefusesCreation) {
    config.application_owner_pubkey = "";
    EXPECT_EQ(api::bootstrap_root_for_owner(*tree, config, canon_b64_of(owner_kp)),
              Outcome::OwnerNotConfigured);
    EXPECT_FALSE(tree->get_node("root").has_value());
}

TEST_F(RootBootstrapTest, InvalidOwnerConfigRefusesCreation) {
    config.application_owner_pubkey = "zz-not-hex";
    EXPECT_EQ(api::bootstrap_root_for_owner(*tree, config, canon_b64_of(owner_kp)),
              Outcome::OwnerNotConfigured);
    EXPECT_FALSE(tree->get_node("root").has_value());

    // Valid hex, wrong length (16 bytes, not an Ed25519 key)
    config.application_owner_pubkey = std::string(32, '0');
    EXPECT_EQ(api::bootstrap_root_for_owner(*tree, config, canon_b64_of(owner_kp)),
              Outcome::OwnerNotConfigured);
    EXPECT_FALSE(tree->get_node("root").has_value());
}

// The mesh trust anchor (root_pubkey, used for server-certificate
// verification) is not an application-owner credential: holding it cannot
// create or claim the application root.
TEST_F(RootBootstrapTest, MeshTrustKeyAloneCannotClaimApplicationRoot) {
    EXPECT_EQ(api::bootstrap_root_for_owner(*tree, config, canon_b64_of(mesh_kp)),
              Outcome::NotOwner);
    EXPECT_FALSE(tree->get_node("root").has_value());

    // Even with the application owner unconfigured, the mesh key alone does
    // not bootstrap.
    config.application_owner_pubkey = "";
    EXPECT_EQ(api::bootstrap_root_for_owner(*tree, config, canon_b64_of(mesh_kp)),
              Outcome::OwnerNotConfigured);
    EXPECT_FALSE(tree->get_node("root").has_value());
}

// Setting the application-owner key must not move the mesh trust anchor:
// a certificate signed by the mesh root key verifies against that key and
// fails against the application-owner key; the owner setting plays no part
// in the verification.
TEST_F(RootBootstrapTest, CertificateVerificationIgnoresApplicationOwnerConfig) {
    gossip::CertIssueParams p;
    p.network_id = std::string(64, 'a');
    p.server_pubkey_b64 = canon_b64_of(stranger_kp);
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
    EXPECT_FALSE(crypto->do_ed25519_verify(owner_kp.public_key, canon_span, sig));
}

// One-time bootstrap: once the root exists, owner logins verify ownership
// only. Reduced grants are not topped up and removed grants are not
// restored.
TEST_F(RootBootstrapTest, ExistingRootGrantsAreNeverModified) {
    EXPECT_EQ(api::bootstrap_root_for_owner(*tree, config, canon_b64_of(owner_kp)),
              Outcome::OwnerRootCreated);

    // Reduce the owner assignment (drop admin/write).
    auto node = tree->get_node("root");
    ASSERT_TRUE(node.has_value());
    tree::TreeNode reduced = *node;
    reduced.assignments[0].permissions = {"read", "add_child", "delete_node",
                                          "edit_node"};
    EXPECT_TRUE(tree->update_node_direct("root", reduced));

    EXPECT_EQ(api::bootstrap_root_for_owner(*tree, config, canon_b64_of(owner_kp)),
              Outcome::OwnerRootExisting);
    auto after = tree->get_node("root");
    ASSERT_TRUE(after.has_value());
    ASSERT_EQ(after->assignments.size(), 1u);
    EXPECT_EQ(after->assignments[0].permissions, reduced.assignments[0].permissions);

    // Remove the owner assignment entirely: still no re-grant.
    tree::TreeNode stripped = *after;
    stripped.assignments.clear();
    EXPECT_TRUE(tree->update_node_direct("root", stripped));
    EXPECT_EQ(api::bootstrap_root_for_owner(*tree, config, canon_b64_of(owner_kp)),
              Outcome::OwnerRootExisting);
    auto still = tree->get_node("root");
    ASSERT_TRUE(still.has_value());
    EXPECT_EQ(still->assignments.size(), 0u);
    EXPECT_EQ(still->mgmt_pubkey, reduced.mgmt_pubkey);
}

// A root established by another key is a configuration conflict: it is
// detected, reported, and left completely intact — no transfer, no grants.
TEST_F(RootBootstrapTest, ExistingForeignRootDetectedAsConflict) {
    seed_foreign_root(canon_b64_of(stranger_kp));
    const auto before = tree->get_node("root");

    EXPECT_EQ(api::bootstrap_root_for_owner(*tree, config, canon_b64_of(owner_kp)),
              Outcome::OwnershipConflict);

    auto after = tree->get_node("root");
    ASSERT_TRUE(after.has_value());
    EXPECT_EQ(after->mgmt_pubkey, before->mgmt_pubkey);
    EXPECT_TRUE(assignments_equal(after->assignments, before->assignments));
    EXPECT_EQ(owner_assignment_count(), 0u);

    // An unrelated caller against the same foreign root is simply NotOwner,
    // with the same no-change guarantee.
    EXPECT_EQ(api::bootstrap_root_for_owner(*tree, config, canon_b64_of(stranger_kp)),
              Outcome::NotOwner);
    auto still = tree->get_node("root");
    EXPECT_TRUE(assignments_equal(still->assignments, before->assignments));
}

// The configured hex and a url-safe unpadded base64 presentation of the same
// key must normalize to the same principal.
TEST_F(RootBootstrapTest, NormalizationAcrossEncodings) {
    EXPECT_EQ(api::bootstrap_root_for_owner(*tree, config, url_unpadded(owner_kp)),
              Outcome::OwnerRootCreated);
    auto root = tree->get_node("root");
    ASSERT_TRUE(root.has_value());
    EXPECT_EQ(root->mgmt_pubkey, "ed25519:" + canon_b64_of(owner_kp));
    EXPECT_EQ(api::bootstrap_root_for_owner(*tree, config, "ed25519:" + url_unpadded(owner_kp)),
              Outcome::OwnerRootExisting);
}

// ============================================================================
// HTTP tests: /api/auth and /api/join through the real handlers
// ============================================================================

struct JoinHttpContextHolder {
    api::ApiContext* ctx = nullptr;
    api::TreeApiHandler* tree_handler = nullptr;
    api::AuthApiHandler* auth_handler = nullptr;
    ~JoinHttpContextHolder() {
        delete auth_handler;
        delete tree_handler;
        delete ctx;
    }
};
static JoinHttpContextHolder& join_holder() {
    static JoinHttpContextHolder h;
    return h;
}

class RootBootstrapHttpTest : public ::testing::Test {
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
        // Distinct mesh trust anchor and application-owner key.
        config.root_pubkey = hex_of(mesh_kp);
        config.application_owner_pubkey = hex_of(owner_kp);
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
        if (http) http->stop();
        delete join_holder().auth_handler;
        join_holder().auth_handler = nullptr;
        delete join_holder().tree_handler;
        join_holder().tree_handler = nullptr;
        delete join_holder().ctx;
        join_holder().ctx = nullptr;
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
};

TEST_F(RootBootstrapHttpTest, OwnerLoginCreatesRootOverHttp) {
    auto res = login(owner_kp);
    ASSERT_TRUE(static_cast<bool>(res));
    ASSERT_EQ(res->status, 200) << res->body;
    EXPECT_TRUE(json::parse(res->body).value("authenticated", false)) << res->body;

    auto root = tree->get_node("root");
    ASSERT_TRUE(root.has_value());
    EXPECT_EQ(root->mgmt_pubkey, prefixed_b64(owner_kp));
}

// An unrelated key still authenticates normally, but never creates or claims
// the root — with or without an existing root, and with open_registration on.
TEST_F(RootBootstrapHttpTest, UnrelatedLoginNeverClaimsRootOverHttp) {
    auto res = login(stranger_kp);
    ASSERT_TRUE(static_cast<bool>(res));
    ASSERT_EQ(res->status, 200);
    EXPECT_TRUE(json::parse(res->body).value("authenticated", false));
    EXPECT_FALSE(tree->get_node("root").has_value());

    // Root now exists (created by the owner); the stranger gets no grant.
    auto owner_res = login(owner_kp);
    ASSERT_TRUE(owner_res && owner_res->status == 200);
    ASSERT_TRUE(tree->get_node("root").has_value());

    auto again = login(stranger_kp);
    ASSERT_TRUE(again && again->status == 200);

    auto root = tree->get_node("root");
    ASSERT_TRUE(root.has_value());
    for (const auto& a : root->assignments) {
        EXPECT_NE(tree::canonical_principal(a.management_pubkey),
                  prefixed_b64(stranger_kp));
    }
}

// Concurrent first logins by the owner: exactly one root, owner-owned, with
// exactly one owner assignment (idempotent re-grant under the race).
TEST_F(RootBootstrapHttpTest, ConcurrentOwnerFirstLoginsCreateExactlyOneRoot) {
    constexpr int kThreads = 4;
    std::atomic<int> successes{0};
    std::barrier sync_point{kThreads};
    std::vector<std::thread> workers;
    workers.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        workers.emplace_back([this, &successes, &sync_point] {
            sync_point.arrive_and_wait();
            auto res = login(owner_kp);
            if (res && res->status == 200 &&
                json::parse(res->body).value("authenticated", false)) {
                successes++;
            }
        });
    }
    for (auto& w : workers) w.join();

    EXPECT_EQ(successes.load(), kThreads);
    auto root = tree->get_node("root");
    ASSERT_TRUE(root.has_value());
    EXPECT_EQ(root->mgmt_pubkey, prefixed_b64(owner_kp));
    std::size_t owner_grants = 0;
    for (const auto& a : root->assignments) {
        if (tree::canonical_principal(a.management_pubkey) == prefixed_b64(owner_kp)) {
            ++owner_grants;
        }
    }
    EXPECT_EQ(owner_grants, 1u);
}

// A non-owner cannot establish the root through /api/join either.
TEST_F(RootBootstrapHttpTest, JoinRefusedBeforeOwnerEstablishesRoot) {
    auto res = join(stranger_kp);
    ASSERT_TRUE(static_cast<bool>(res));
    ASSERT_EQ(res->status, 409);
    EXPECT_NE(res->body.find("root"), std::string::npos);
    EXPECT_FALSE(tree->get_node("root").has_value());
}

TEST_F(RootBootstrapHttpTest, JoinRefusedWhenOwnerNotConfigured) {
    config.application_owner_pubkey = "";
    auto res = join(stranger_kp);
    ASSERT_TRUE(static_cast<bool>(res));
    ASSERT_EQ(res->status, 409);
    EXPECT_NE(res->body.find("no root owner configured"), std::string::npos);
    EXPECT_FALSE(tree->get_node("root").has_value());

    // The configured key cannot help either: the configuration is the binding.
    config.application_owner_pubkey = hex_of(stranger_kp);
    auto owner_res = join(owner_kp);
    ASSERT_TRUE(owner_res && owner_res->status == 409);
    EXPECT_FALSE(tree->get_node("root").has_value());
}

// The mesh trust anchor (holder of root_pubkey) can authenticate but cannot
// create or claim the application root.
TEST_F(RootBootstrapHttpTest, MeshAnchorKeyLoginCreatesNoRoot) {
    auto res = login(mesh_kp);
    ASSERT_TRUE(static_cast<bool>(res));
    ASSERT_EQ(res->status, 200) << res->body;
    EXPECT_TRUE(json::parse(res->body).value("authenticated", false));
    EXPECT_FALSE(tree->get_node("root").has_value());
}

// Repeated owner logins against an existing root with reduced grants change
// nothing: the tree and assignments remain exactly as stored.
TEST_F(RootBootstrapHttpTest, ReducedGrantsPreservedAcrossOwnerLogins) {
    auto res = login(owner_kp);
    ASSERT_TRUE(static_cast<bool>(res));
    ASSERT_EQ(res->status, 200) << res->body;
    ASSERT_TRUE(tree->get_node("root").has_value());

    // Operator reduces the owner's root grants.
    auto node = tree->get_node("root");
    tree::TreeNode reduced = *node;
    reduced.assignments[0].permissions = {"read"};
    EXPECT_TRUE(tree->update_node_direct("root", reduced));

    res = login(owner_kp);
    ASSERT_TRUE(static_cast<bool>(res));
    ASSERT_EQ(res->status, 200) << res->body;

    auto after = tree->get_node("root");
    ASSERT_TRUE(after.has_value());
    ASSERT_EQ(after->assignments.size(), 1u);
    EXPECT_EQ(after->assignments[0].permissions, (std::vector<std::string>{"read"}));
}

TEST_F(RootBootstrapHttpTest, OwnerJoinCreatesRootAndCustomerGroup) {
    auto res = join(owner_kp);
    ASSERT_TRUE(static_cast<bool>(res));
    ASSERT_EQ(res->status, 200);

    auto root = tree->get_node("root");
    ASSERT_TRUE(root.has_value());
    EXPECT_EQ(root->mgmt_pubkey, prefixed_b64(owner_kp));

    const auto node_id = json::parse(res->body).value("node_id", std::string{});
    ASSERT_FALSE(node_id.empty());
    auto customer = tree->get_node("customer-" + node_id);
    ASSERT_TRUE(customer.has_value());
    EXPECT_EQ(customer->parent_id, "root");
    EXPECT_TRUE(tree->get_node(node_id).has_value());
}
