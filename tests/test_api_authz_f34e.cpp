// F-34e API authorization over the real HTTP routes:
//  - /api/tls/reload is not routed at all: no session authorizes a TLS
//    reload, so the operation is unavailable even on a TLS-configured
//    server (certificate changes happen via local/ACME renewal only).
//  - /api/relay/ticket may only be minted for the caller's own identity.
//  - /api/relay/register requires the existing relay_register permission on
//    the application root; a valid session alone is insufficient, and with
//    no root the operation is unavailable (no mutation).
//  - /api/routing/internal/broker stays on its existing server-identity
//    (enrolled peer + Ed25519 signature) gate; no user role is added.

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
#include <LemonadeNexus/Api/AuthApiHandler.hpp>
#include <LemonadeNexus/Api/RelayApiHandler.hpp>
#include <LemonadeNexus/Api/CertApiHandler.hpp>

#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
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

struct HandlerContextHolder {
    api::ApiContext* ctx = nullptr;
    api::AuthApiHandler* auth_handler = nullptr;
    api::RelayApiHandler* relay_handler = nullptr;
    api::CertApiHandler* cert_handler = nullptr;
    ~HandlerContextHolder() {
        delete cert_handler;
        delete relay_handler;
        delete auth_handler;
        delete ctx;
    }
};
static HandlerContextHolder& holder() {
    static HandlerContextHolder h;
    return h;
}

class ApiAuthzF34eTest : public ::testing::Test {
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
    crypto::Ed25519Keypair root_keypair;
    crypto::Ed25519Keypair mesh_keypair;
    std::string jwt_secret;

    void SetUp() override {
        test_port_ = static_cast<uint16_t>(19500 + (getpid() % 10000));
        temp_dir = fs::temp_directory_path() / ("nexus_test_api_authz_" + std::to_string(getpid()));
        fs::create_directories(temp_dir);

        crypto = std::make_unique<crypto::SodiumCryptoService>();
        crypto->start();
        storage = std::make_unique<storage::FileStorageService>(temp_dir);
        storage->start();
        key_wrapping = std::make_unique<crypto::KeyWrappingService>(*crypto, *storage);
        key_wrapping->start();

        root_keypair = crypto->ed25519_keygen();
        mesh_keypair = crypto->ed25519_keygen();
        config.root_pubkey = crypto::to_hex(std::span<const uint8_t>(
            mesh_keypair.public_key.data(), mesh_keypair.public_key.size()));

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

        relay = std::make_unique<relay::RelayService>(io, 0, *crypto, root_keypair.public_key);
        relay_discovery = std::make_unique<relay::RelayDiscoveryService>(*storage);
        gossip = std::make_unique<gossip::GossipService>(io, 0, *storage, *crypto);
        routing = std::make_unique<routing::RoutingCoordinationService>(*crypto, *gossip);
        attestation = std::make_unique<core::BinaryAttestationService>(*crypto, *storage);
        admission = std::make_unique<core::ServerAdmissionService>(
            config, *crypto, *key_wrapping, *storage, *gossip);
        ddns = std::make_unique<network::DdnsService>(io, *crypto, *storage, *attestation, *gossip);
        acme = std::make_unique<acme::AcmeService>(*storage);

        holder().ctx = new api::ApiContext{
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
        holder().auth_handler = new api::AuthApiHandler(*holder().ctx);
        holder().auth_handler->register_routes(http->server(), http->server());
        holder().relay_handler = new api::RelayApiHandler(*holder().ctx);
        holder().relay_handler->register_routes(http->server(), http->server());
        holder().cert_handler = new api::CertApiHandler(*holder().ctx);
        holder().cert_handler->register_routes(http->server(), http->server());
        http->start();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // Secondary HTTPS server carrying only the cert routes, used to prove
    // the reload operation is unavailable with TLS actually configured.
    std::unique_ptr<network::HttpServer> tls_http;
    api::ApiContext* tls_ctx = nullptr;
    api::CertApiHandler* tls_cert_handler = nullptr;
    fs::path side_cert, side_key;

    // Write a self-signed cert + key for `cn` (with a matching DNS SAN).
    static bool make_self_signed(const std::string& cn, const fs::path& cert_p,
                                 const fs::path& key_p) {
        EVP_PKEY* pkey = EVP_RSA_gen(2048);
        if (!pkey) return false;
        X509* x = X509_new();
        ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
        X509_gmtime_adj(X509_getm_notBefore(x), 0);
        X509_gmtime_adj(X509_getm_notAfter(x), 60 * 60 * 24);
        X509_set_pubkey(x, pkey);
        X509_NAME* name = X509_get_subject_name(x);
        X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>(cn.c_str()), -1, -1, 0);
        X509_set_issuer_name(x, name);
        std::string san = "DNS:" + cn;
        if (X509_EXTENSION* ext =
                X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name, san.c_str())) {
            X509_add_ext(x, ext, -1);
            X509_EXTENSION_free(ext);
        }
        bool ok = X509_sign(x, pkey, EVP_sha256()) != 0;
        if (ok) {
            if (FILE* cf = std::fopen(cert_p.string().c_str(), "wb")) {
                ok = ok && PEM_write_X509(cf, x); std::fclose(cf);
            }
            if (FILE* kf = std::fopen(key_p.string().c_str(), "wb")) {
                ok = ok && PEM_write_PrivateKey(kf, pkey, nullptr, nullptr, 0, nullptr, nullptr);
                std::fclose(kf);
            }
        }
        X509_free(x);
        EVP_PKEY_free(pkey);
        return ok;
    }

    // Returns 0 when TLS could not be configured; tests must ASSERT on it.
    uint16_t start_tls_side_server() {
        const uint16_t port = static_cast<uint16_t>(test_port_ + 7);
        side_cert = temp_dir / "side_cert.pem";
        side_key  = temp_dir / "side_key.pem";
        if (!make_self_signed("side.test.local", side_cert, side_key)) return 0;
        tls_http = std::make_unique<network::HttpServer>(
            port, "127.0.0.1", side_cert.string(), side_key.string());
        if (!tls_http->is_tls()) return 0;

        tls_ctx = new api::ApiContext{
            .config           = config,
            .auth             = *auth,
            .tree             = *tree,
            .ipam             = *ipam,
            .gossip           = *gossip,
            .crypto           = *crypto,
            .key_wrapping     = *key_wrapping,
            .storage          = *storage,
            .acme             = *acme,
            .http_server      = *tls_http,
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
        tls_cert_handler = new api::CertApiHandler(*tls_ctx);
        tls_cert_handler->register_routes(tls_http->server(), tls_http->server());
        tls_http->start();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        return port;
    }

    void TearDown() override {
        if (tls_http) tls_http->stop();
        delete tls_cert_handler;
        tls_cert_handler = nullptr;
        delete tls_ctx;
        tls_ctx = nullptr;
        if (http) http->stop();
        // Route lambdas are dead with the server; drop handlers and context
        // before tearing down the services they reference.
        delete holder().cert_handler;
        holder().cert_handler = nullptr;
        delete holder().relay_handler;
        holder().relay_handler = nullptr;
        delete holder().auth_handler;
        holder().auth_handler = nullptr;
        delete holder().ctx;
        holder().ctx = nullptr;
        if (auth) auth->stop();
        if (ipam) ipam->stop();
        if (tree) tree->stop();
        if (key_wrapping) key_wrapping->stop();
        if (storage) storage->stop();
        if (crypto) crypto->stop();
        fs::remove_all(temp_dir);
    }

    httplib::Client make_client() { return httplib::Client("127.0.0.1", test_port_); }

    // Full ed25519 challenge-response login; returns {session_token, user_id}.
    std::optional<std::pair<std::string, std::string>> login_ed25519(
            const crypto::Ed25519Keypair& kp) {
        const auto bare = crypto::to_base64(
            std::span<const uint8_t>(kp.public_key.data(), kp.public_key.size()));
        auto cli = make_client();
        auto c_res = cli.Post("/api/auth/challenge",
                              json{{"pubkey", bare}}.dump(), "application/json");
        if (!c_res || c_res->status != 200) return std::nullopt;
        const auto challenge =
            json::parse(c_res->body).value("challenge", std::string{});
        auto challenge_bytes = crypto::from_base64(challenge);
        auto sig = crypto->ed25519_sign(kp.private_key,
                                        std::span<const uint8_t>(challenge_bytes));
        json body = {
            {"method", "ed25519"},
            {"pubkey", bare},
            {"challenge", challenge},
            {"signature", crypto::to_base64(
                               std::span<const uint8_t>(sig.data(), sig.size()))},
        };
        auto res = cli.Post("/api/auth", body.dump(), "application/json");
        if (!res || res->status != 200) return std::nullopt;
        auto j = json::parse(res->body);
        return std::pair{j.value("session_token", std::string{}),
                         j.value("user_id", std::string{})};
    }

    // Seed an application root (pre-existing installation) with an
    // assignment for `grantee`.
    void seed_root(const crypto::Ed25519Keypair& grantee,
                   const std::vector<std::string>& perms) {
        const auto canonical = "ed25519:" + crypto::to_base64(
            std::span<const uint8_t>(grantee.public_key.data(),
                                     grantee.public_key.size()));
        tree::TreeNode root;
        root.id          = "root";
        root.parent_id   = "";
        root.type        = tree::NodeType::Root;
        root.hostname    = "root";
        root.mgmt_pubkey = canonical;
        root.assignments = {{.management_pubkey = canonical,
                             .permissions = perms}};
        EXPECT_TRUE(tree->bootstrap_root(root));
    }

    bool relay_file_exists(const std::string& relay_id) const {
        return fs::exists(temp_dir / "relay" / relay_id);
    }
};

// ── /api/tls/reload ─────────────────────────────────────────────────────────

TEST_F(ApiAuthzF34eTest, TlsReloadRouteUnavailableWithoutSession) {
    const auto port = start_tls_side_server();
    ASSERT_NE(port, 0);
    httplib::SSLClient cli("side.test.local", port);
    cli.set_hostname_addr_map({{"side.test.local", "127.0.0.1"}});
    cli.set_ca_cert_path(side_cert.string());
    auto res = cli.Post("/api/tls/reload",
                        json{{"cert_path", "/etc/lemonade/evil.crt"},
                             {"key_path", "/etc/lemonade/evil.key"}}.dump(),
                        "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 404);
}

// TLS is configured on the side server; an ordinary authenticated caller
// still has no route and no authorization to trigger a reload.
TEST_F(ApiAuthzF34eTest, TlsReloadUnavailableForOrdinaryAuthenticatedCaller) {
    const auto port = start_tls_side_server();
    ASSERT_NE(port, 0);
    auto login = login_ed25519(root_keypair);
    ASSERT_TRUE(login.has_value());
    httplib::Headers headers{{"Authorization", "Bearer " + login->first}};
    httplib::SSLClient cli("side.test.local", port);
    cli.set_hostname_addr_map({{"side.test.local", "127.0.0.1"}});
    cli.set_ca_cert_path(side_cert.string());
    auto res = cli.Post("/api/tls/reload", headers,
                        json{{"cert_path", "/etc/lemonade/evil.crt"},
                             {"key_path", "/etc/lemonade/evil.key"}}.dump(),
                        "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 404);
    EXPECT_EQ(res->body.find("\"success\":true"), std::string::npos);
}

// ── /api/relay/ticket ───────────────────────────────────────────────────────

TEST_F(ApiAuthzF34eTest, RelayTicketForForeignIdentityRefused) {
    auto login = login_ed25519(root_keypair);
    ASSERT_TRUE(login.has_value());
    httplib::Headers headers{{"Authorization", "Bearer " + login->first}};
    auto cli = make_client();
    auto res = cli.Post("/api/relay/ticket", headers,
                        json{{"peer_id", "victim-node"},
                             {"relay_id", "relay-1"}}.dump(),
                        "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 403);
    EXPECT_EQ(json::parse(res->body).value("peer_id", std::string{}), "");
}

TEST_F(ApiAuthzF34eTest, RelayTicketForOwnIdentitySucceeds) {
    auto login = login_ed25519(root_keypair);
    ASSERT_TRUE(login.has_value());
    httplib::Headers headers{{"Authorization", "Bearer " + login->first}};
    auto cli = make_client();
    auto res = cli.Post("/api/relay/ticket", headers,
                        json{{"peer_id", login->second},
                             {"relay_id", "relay-1"}}.dump(),
                        "application/json");
    ASSERT_TRUE(res);
    ASSERT_EQ(res->status, 200) << res->body;
    auto j = json::parse(res->body);
    EXPECT_EQ(j.value("peer_id", ""), login->second);
    EXPECT_EQ(j.value("relay_id", ""), "relay-1");
    EXPECT_GT(j.value("expires_at", 0), j.value("issued_at", 0));
    EXPECT_FALSE(j.value("session_nonce", std::string{}).empty());
}

// ── /api/relay/register ─────────────────────────────────────────────────────

TEST_F(ApiAuthzF34eTest, RelayRegisterWithoutRootUnavailableNoMutation) {
    auto login = login_ed25519(root_keypair);
    ASSERT_TRUE(login.has_value());
    httplib::Headers headers{{"Authorization", "Bearer " + login->first}};
    auto cli = make_client();
    auto res = cli.Post("/api/relay/register", headers,
                        json{{"relay_id", "evil-relay"},
                             {"endpoint", "203.0.113.7:3478"}}.dump(),
                        "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 409);
    EXPECT_FALSE(relay_file_exists("evil-relay"));
}

TEST_F(ApiAuthzF34eTest, RelayRegisterSessionAloneInsufficientNoMutation) {
    // Root exists but the caller holds no relay_register permission.
    seed_root(mesh_keypair, {"read"});
    auto login = login_ed25519(root_keypair);
    ASSERT_TRUE(login.has_value());
    httplib::Headers headers{{"Authorization", "Bearer " + login->first}};
    auto cli = make_client();
    auto res = cli.Post("/api/relay/register", headers,
                        json{{"relay_id", "evil-relay"},
                             {"endpoint", "203.0.113.7:3478"}}.dump(),
                        "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 403);
    EXPECT_FALSE(relay_file_exists("evil-relay"));
}

TEST_F(ApiAuthzF34eTest, RelayRegisterWithPermissionSucceeds) {
    seed_root(root_keypair, {"relay_register"});
    auto login = login_ed25519(root_keypair);
    ASSERT_TRUE(login.has_value());
    httplib::Headers headers{{"Authorization", "Bearer " + login->first}};
    auto cli = make_client();
    auto res = cli.Post("/api/relay/register", headers,
                        json{{"relay_id", "good-relay"},
                             {"endpoint", "198.51.100.4:3478"},
                             {"region", "us-ca"}}.dump(),
                        "application/json");
    ASSERT_TRUE(res);
    ASSERT_EQ(res->status, 200) << res->body;
    auto j = json::parse(res->body);
    EXPECT_EQ(j.value("success", false), true);
    EXPECT_EQ(j.value("relay_id", ""), "good-relay");
    EXPECT_TRUE(relay_file_exists("good-relay"));
}
