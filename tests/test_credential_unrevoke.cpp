// Endpoint coverage for the operator un-revoke path (POST
// /api/credentials/unrevoke): unauthenticated -> 401, authenticated
// non-admin -> 403, admin -> 200 with the revocation actually lifted.
//
// The admin gate is the root-node Permission::Admin check, the same
// convention used by the onboarding admission routes.

#include <LemonadeNexus/Api/AdminApiHandler.hpp>
#include <LemonadeNexus/Api/IRequestHandler.hpp>
#include <LemonadeNexus/ACL/Permission.hpp>
#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <LemonadeNexus/Network/DdnsService.hpp>
#include <LemonadeNexus/Network/HttpServer.hpp>
#include <LemonadeNexus/Relay/RelayService.hpp>
#include <LemonadeNexus/Relay/RelayDiscoveryService.hpp>
#include <LemonadeNexus/Routing/RoutingCoordinationService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>
#include <LemonadeNexus/Acme/AcmeService.hpp>
#include <LemonadeNexus/Core/BinaryAttestation.hpp>
#include <LemonadeNexus/Core/ServerAdmissionService.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>

#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <jwt-cpp/jwt.h>
#include <asio.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <span>
#include <thread>
#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

using namespace nexus;
namespace fs = std::filesystem;
using json = nlohmann::json;

class CredentialUnrevokeEndpointTest : public ::testing::Test {
protected:
    uint16_t port_{0};
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

    crypto::Ed25519Keypair root_keypair;
    std::string root_pubkey_str;  // "ed25519:<base64>"
    std::string jwt_secret;

    httplib::Server server;
    std::thread server_thread;

    httplib::Client make_client() const { return httplib::Client("127.0.0.1", port_); }
    api::AdminApiHandler* handler_{nullptr};
    std::unique_ptr<api::ApiContext> ctx_;

    void SetUp() override {
        port_ = static_cast<uint16_t>(19300 + (getpid() % 10000));
        temp_dir = fs::temp_directory_path() / ("nexus_test_unrevoke_" + std::to_string(getpid()));
        fs::create_directories(temp_dir);

        crypto = std::make_unique<crypto::SodiumCryptoService>();
        crypto->start();

        storage = std::make_unique<storage::FileStorageService>(temp_dir);
        storage->start();

        key_wrapping = std::make_unique<crypto::KeyWrappingService>(*crypto, *storage);
        key_wrapping->start();

        root_keypair = crypto->ed25519_keygen();
        root_pubkey_str = "ed25519:" + crypto::to_base64(root_keypair.public_key);
        bootstrap_root_node();

        tree = std::make_unique<tree::PermissionTreeService>(*storage, *crypto);
        tree->start();

        std::array<uint8_t, 32> secret_bytes{};
        crypto->random_bytes(std::span<uint8_t>(secret_bytes));
        jwt_secret = crypto::to_hex(std::span<const uint8_t>(secret_bytes));

        auth = std::make_unique<auth::AuthService>(*storage, *crypto, "lemonade-nexus.local",
                                                   jwt_secret);
        auth->start();

        ipam = std::make_unique<ipam::IPAMService>(*storage);
        ipam->start();

        // Stand-ins: the un-revoke route only touches auth + tree, so these
        // unstarted services are never used.
        http = std::make_unique<network::HttpServer>(0);
        relay = std::make_unique<relay::RelayService>(io, 0, *crypto, root_keypair.public_key);
        relay_discovery = std::make_unique<relay::RelayDiscoveryService>(*storage);
        gossip = std::make_unique<gossip::GossipService>(io, 0, *storage, *crypto);
        routing = std::make_unique<routing::RoutingCoordinationService>(*crypto, *gossip);
        attestation = std::make_unique<core::BinaryAttestationService>(*crypto, *storage);
        admission = std::make_unique<core::ServerAdmissionService>(
            config, *crypto, *key_wrapping, *storage, *gossip);
        ddns = std::make_unique<network::DdnsService>(
            io, *crypto, *storage, *attestation, *gossip);
        acme = std::make_unique<acme::AcmeService>(*storage);

        ctx_ = std::make_unique<api::ApiContext>(api::ApiContext{
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
        });
        handler_ = new api::AdminApiHandler(*ctx_);
        handler_->register_routes(server, server);

        server_thread = std::thread([this] { server.listen("127.0.0.1", port_); });
        // Wait for the server to accept connections.
        for (int i = 0; i < 50; ++i) {
            if (make_client().Get("/") != nullptr) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }

    void TearDown() override {
        server.stop();
        if (server_thread.joinable()) server_thread.join();
        delete handler_;
        handler_ = nullptr;
        ipam->stop();
        auth->stop();
        tree->stop();
        key_wrapping->stop();
        storage->stop();
        crypto->stop();
        fs::remove_all(temp_dir);
    }

    void bootstrap_root_node() {
        tree::TreeNode root;
        root.id = "root";
        root.parent_id = "";
        root.type = tree::NodeType::Root;
        root.mgmt_pubkey = root_pubkey_str;
        root.assignments = {{root_pubkey_str, {"admin"}}};

        auto canonical = tree::canonical_node_json(root);
        auto msg = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
        auto sig = crypto->ed25519_sign(root_keypair.private_key, msg);
        root.signature = crypto::to_base64(sig);

        storage::SignedEnvelope env;
        env.version = 1;
        env.type = "tree_node";
        env.data = json(root).dump();
        env.signer_pubkey = root_pubkey_str;
        env.signature = root.signature;
        storage->write_node("root", env);
    }

    /// JWT for the given pubkey claim; the root key has Admin on the root node.
    std::string make_jwt(const std::string& pubkey) {
        auto now = std::chrono::system_clock::now();
        return jwt::create()
            .set_issuer("lemonade-nexus")
            .set_subject(pubkey)
            .set_issued_at(now)
            .set_expires_at(now + std::chrono::hours{1})
            .set_payload_claim("pubkey", jwt::claim(pubkey))
            .sign(jwt::algorithm::hs256{jwt_secret});
    }

    httplib::Result post_unrevoke(const std::string& pubkey, const std::string& token) {
        httplib::Headers h;
        if (!token.empty()) {
            h.emplace("Authorization", "Bearer " + token);
        }
        json body{{"pubkey", pubkey}};
        return make_client().Post("/api/credentials/unrevoke", h, body.dump(), "application/json");
    }

    std::vector<std::string> blocklist() {
        std::vector<std::string> out;
        std::ifstream ifs(temp_dir / "credentials" / "revoked.json");
        if (ifs) {
            json j;
            ifs >> j;
            if (j.is_array()) {
                for (const auto& e : j) {
                    if (e.is_string()) out.push_back(e.get<std::string>());
                }
            }
        }
        return out;
    }

    static bool contains(const std::vector<std::string>& v, const std::string& s) {
        for (const auto& e : v) {
            if (e == s) return true;
        }
        return false;
    }
};

TEST_F(CredentialUnrevokeEndpointTest, UnauthenticatedIs401) {
    auto pk = crypto::to_base64(
        std::span<const uint8_t>(root_keypair.public_key.data(),
                                 root_keypair.public_key.size()));
    ASSERT_TRUE(auth->revoke_ed25519(pk));

    auto result = post_unrevoke(pk, "");
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->status, 401);

    // The blocklist is untouched.
    EXPECT_TRUE(contains(blocklist(), pk));
}

TEST_F(CredentialUnrevokeEndpointTest, NonAdminIs403) {
    auto pk = crypto::to_base64(
        std::span<const uint8_t>(root_keypair.public_key.data(),
                                 root_keypair.public_key.size()));
    ASSERT_TRUE(auth->revoke_ed25519(pk));

    // A valid JWT for a key with no root Admin assignment.
    auto result = post_unrevoke(pk, make_jwt("ed25519:notadmin"));
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->status, 403);

    EXPECT_TRUE(contains(blocklist(), pk));
}

TEST_F(CredentialUnrevokeEndpointTest, AdminUnrevokes) {
    auto kp = crypto->ed25519_keygen();
    auto pk = crypto::to_base64(
        std::span<const uint8_t>(kp.public_key.data(), kp.public_key.size()));
    ASSERT_TRUE(auth->revoke_ed25519(pk));
    EXPECT_TRUE(contains(blocklist(), pk));

    auto result = post_unrevoke(pk, make_jwt(root_pubkey_str));
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->status, 200);
    auto body = json::parse(result->body);
    EXPECT_TRUE(body.value("success", false));

    // The revocation is actually lifted: blocklist entry gone and the key can
    // authenticate again.
    EXPECT_FALSE(contains(blocklist(), pk));

    auto challenge = auth->issue_ed25519_challenge(pk).value("challenge", std::string{});
    auto challenge_bytes = crypto::from_base64(challenge);
    auto sig = crypto->ed25519_sign(kp.private_key, std::span<const uint8_t>(challenge_bytes));
    auto login = auth->authenticate({
        {"method",    "ed25519"},
        {"pubkey",    pk},
        {"challenge", challenge},
        {"signature", crypto::to_base64(
                          std::span<const uint8_t>(sig.data(), sig.size()))},
    });
    EXPECT_TRUE(login.authenticated);
    EXPECT_FALSE(login.session_token.empty());
}

TEST_F(CredentialUnrevokeEndpointTest, AdminUnrevokeNotRevokedIs400) {
    auto kp = crypto->ed25519_keygen();
    auto pk = crypto::to_base64(
        std::span<const uint8_t>(kp.public_key.data(), kp.public_key.size()));

    auto result = post_unrevoke(pk, make_jwt(root_pubkey_str));
    ASSERT_NE(result, nullptr);
    EXPECT_EQ(result->status, 400);
    auto body = json::parse(result->body);
    EXPECT_TRUE(body.contains("error"));
}

TEST_F(CredentialUnrevokeEndpointTest, AdminMissingPubkeyIs400) {
    json body;  // no "pubkey" field
    httplib::Headers h = {{"Authorization", "Bearer " + make_jwt(root_pubkey_str)}};
    auto result = make_client().Post("/api/credentials/unrevoke", h, body.dump(), "application/json");
    ASSERT_NE(result, nullptr);

    EXPECT_EQ(result->status, 400);
}
