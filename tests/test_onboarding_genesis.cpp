// Onboarding e2e: the supported flow carries, verifies, and persists the
// Genesis anchor; a restart through start_security_mesh (the production
// startup path) runs the security lifecycle from the persisted config.

#include <LemonadeNexus/Api/IRequestHandler.hpp>
#include <LemonadeNexus/Api/OnboardApiHandler.hpp>
#include <LemonadeNexus/Acme/AcmeService.hpp>
#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Core/BinaryAttestation.hpp>
#include <LemonadeNexus/Core/OnboardingClient.hpp>
#include <LemonadeNexus/Core/OnboardingTypes.hpp>
#include <LemonadeNexus/Core/ServerAdmissionService.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Core/SecurityMeshStartup.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Gossip/ServerCertificate.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <LemonadeNexus/Network/DdnsService.hpp>
#include <LemonadeNexus/Network/HttpServer.hpp>
#include <LemonadeNexus/Relay/RelayDiscoveryService.hpp>
#include <LemonadeNexus/Relay/RelayService.hpp>
#include <LemonadeNexus/Routing/RoutingCoordinationService.hpp>
#include <LemonadeNexus/Security/DurableWrite.hpp>
#include <LemonadeNexus/Security/Genesis/BootstrapCertificate.hpp>
#include <LemonadeNexus/Security/Lifecycle/SecurityMeshService.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>

#include <asio.hpp>
#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
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

namespace {

std::string b64(const std::vector<uint8_t>& v) {
    return crypto::to_base64(std::span<const uint8_t>(v.data(), v.size()));
}

std::string b64_array(const crypto::Ed25519PublicKey& k) {
    return b64(std::vector<uint8_t>(k.begin(), k.end()));
}

std::string hex_array(const crypto::Ed25519PublicKey& k) {
    return crypto::to_hex(std::span<const uint8_t>(k.data(), k.size()));
}

std::string derived_network_hex(const crypto::Ed25519PublicKey& genesis) {
    return crypto::to_hex(security::derive_network_id(
        genesis, security::constants::kSecurityRulesetVersion,
        security::constants::kConsensusRulesetVersion));
}

void set_ssl_cert_file(const std::string& path) {
#ifdef _WIN32
    (void)_putenv_s("SSL_CERT_FILE", path.c_str());
#else
    ::setenv("SSL_CERT_FILE", path.c_str(), 1);
#endif
}

uint64_t now_unix() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

// Test CA + "localhost" leaf; SSL_CERT_FILE makes the default trust paths trust it.

bool write_pem(const fs::path& path, const char* type, const void* obj) {
    if (FILE* f = std::fopen(path.string().c_str(), "wb")) {
        bool ok = (type[0] == 'X') ? PEM_write_X509(f, static_cast<const X509*>(obj))
                                   : PEM_write_PrivateKey(f, static_cast<const EVP_PKEY*>(obj),
                                                          nullptr, nullptr, 0, nullptr, nullptr);
        std::fclose(f);
        return ok;
    }
    return false;
}

bool make_ca(const fs::path& cert_p, const fs::path& key_p) {
    EVP_PKEY* key = EVP_RSA_gen(2048);
    if (!key) return false;
    X509* x = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 24 * 3600);
    X509_set_pubkey(x, key);
    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("nexus-onboard-test-ca"),
                               -1, -1, 0);
    X509_set_issuer_name(x, name);
    if (X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_basic_constraints,
                                                  "critical,CA:TRUE")) {
        X509_add_ext(x, ext, -1);
        X509_EXTENSION_free(ext);
    }
    bool ok = X509_sign(x, key, EVP_sha256()) != 0;
    ok = ok && write_pem(cert_p, "X", x) && write_pem(key_p, "K", key);
    X509_free(x);
    EVP_PKEY_free(key);
    return ok;
}

bool make_leaf(const fs::path& cert_p, const fs::path& key_p, const X509* ca,
               EVP_PKEY* ca_key) {
    EVP_PKEY* key = EVP_RSA_gen(2048);
    if (!key) return false;
    X509* x = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x), 2);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 24 * 3600);
    X509_set_pubkey(x, key);
    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0);
    X509_set_issuer_name(x, X509_get_subject_name(ca));
    if (X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, nullptr, NID_subject_alt_name,
                                                  "DNS:localhost")) {
        X509_add_ext(x, ext, -1);
        X509_EXTENSION_free(ext);
    }
    bool ok = X509_sign(x, ca_key, EVP_sha256()) != 0;
    ok = ok && write_pem(cert_p, "X", x) && write_pem(key_p, "K", key);
    X509_free(x);
    EVP_PKEY_free(key);
    return ok;
}

}  // namespace

// ===========================================================================
// Root holder stack + TLS onboarding endpoint
// ===========================================================================

class GenesisAnchorOnboarding : public ::testing::Test {
protected:
    fs::path root;
    uint16_t tls_port{0};

    asio::io_context io;
    std::unique_ptr<crypto::SodiumCryptoService> crypto;
    std::unique_ptr<storage::FileStorageService> storage;
    std::unique_ptr<crypto::KeyWrappingService> kw;
    std::unique_ptr<gossip::GossipService> gossip;
    std::unique_ptr<core::ServerAdmissionService> admission;

    // ApiContext stand-ins the public onboarding routes never touch.
    std::unique_ptr<tree::PermissionTreeService> tree;
    std::unique_ptr<auth::AuthService> auth;
    std::unique_ptr<ipam::IPAMService> ipam;
    std::unique_ptr<relay::RelayService> relay;
    std::unique_ptr<relay::RelayDiscoveryService> relay_discovery;
    std::unique_ptr<routing::RoutingCoordinationService> routing;
    std::unique_ptr<core::BinaryAttestationService> attestation;
    std::unique_ptr<network::DdnsService> ddns;
    std::unique_ptr<acme::AcmeService> acme;
    std::unique_ptr<network::HttpServer> http;

    core::ServerConfig config;
    std::unique_ptr<api::ApiContext> ctx;
    std::unique_ptr<api::OnboardApiHandler> handler;
    std::unique_ptr<httplib::SSLServer> server;
    std::thread server_thread;

    fs::path ca_pem, leaf_pem, leaf_key_pem;
    X509* ca_x509{nullptr};
    EVP_PKEY* ca_key{nullptr};

    // Candidate gossip keypair pre-created, as --first-run would leave it.
    fs::path candidate_dir;
    crypto::Ed25519Keypair candidate_key;
    fs::path candidate_config_path;

    void SetUp() override {
        root = fs::temp_directory_path() /
               ("nexus_test_onboard_genesis_" + std::to_string(getpid()));
        fs::remove_all(root);
        fs::create_directories(root);
        tls_port = static_cast<uint16_t>(19300 + (getpid() % 1000));

        ca_pem = root / "ca.pem";
        leaf_pem = root / "leaf.pem";
        leaf_key_pem = root / "leaf.key";
        ASSERT_TRUE(make_ca(ca_pem, root / "ca.key"));
        {
            FILE* f = std::fopen(ca_pem.string().c_str(), "rb");
            ASSERT_NE(f, nullptr);
            ca_x509 = PEM_read_X509(f, nullptr, nullptr, nullptr);
            std::fclose(f);
            f = std::fopen((root / "ca.key").string().c_str(), "rb");
            ASSERT_NE(f, nullptr);
            ca_key = PEM_read_PrivateKey(f, nullptr, nullptr, nullptr);
            std::fclose(f);
            ASSERT_NE(ca_x509, nullptr);
            ASSERT_NE(ca_key, nullptr);
        }
        ASSERT_TRUE(make_leaf(leaf_pem, leaf_key_pem, ca_x509, ca_key));
        set_ssl_cert_file(ca_pem.string());

        // Root holder: identity key = mesh root; gossip key = pinned Genesis anchor.
        crypto = std::make_unique<crypto::SodiumCryptoService>();
        crypto->start();
        storage = std::make_unique<storage::FileStorageService>(root / "root");
        storage->start();
        kw = std::make_unique<crypto::KeyWrappingService>(*crypto, *storage);
        kw->start();
        auto root_identity = kw->generate_and_store_identity({});
        gossip = std::make_unique<gossip::GossipService>(io, 0, *storage, *crypto);
        gossip->start();
        config.data_root = (root / "root").string();
        config.root_pubkey = hex_array(root_identity.public_key);
        config.genesis_pubkey = b64_array(gossip->keypair().public_key);
        config.onboard_enabled = true;

        admission = std::make_unique<core::ServerAdmissionService>(
            config, *crypto, *kw, *storage, *gossip);
        admission->set_network_id(derived_network_hex(gossip->keypair().public_key));
        admission->start();

        tree = std::make_unique<tree::PermissionTreeService>(*storage, *crypto);
        tree->start();
        auth = std::make_unique<auth::AuthService>(*storage, *crypto, "nexus.test",
                                                   "test-jwt-secret-0123456789abcdef0123456789abcdef");
        auth->start();
        ipam = std::make_unique<ipam::IPAMService>(*storage);
        ipam->start();
        relay = std::make_unique<relay::RelayService>(io, 0, *crypto,
                                                      root_identity.public_key);
        relay_discovery = std::make_unique<relay::RelayDiscoveryService>(*storage);
        routing = std::make_unique<routing::RoutingCoordinationService>(*crypto, *gossip);
        attestation = std::make_unique<core::BinaryAttestationService>(*crypto, *storage);
        ddns = std::make_unique<network::DdnsService>(io, *crypto, *storage, *attestation,
                                                      *gossip);
        acme = std::make_unique<acme::AcmeService>(*storage);
        http = std::make_unique<network::HttpServer>(tls_port + 1000);
        ctx = std::make_unique<api::ApiContext>(api::ApiContext{
            .config           = config,
            .auth             = *auth,
            .tree             = *tree,
            .ipam             = *ipam,
            .gossip           = *gossip,
            .crypto           = *crypto,
            .key_wrapping     = *kw,
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
            .server_fqdn      = "localhost",
            .server_seip_fqdn = "",
            .server_private_fqdn = "",
            .server_public_ip = "",
            .tunnel_bind_ip   = "",
        });
        handler = std::make_unique<api::OnboardApiHandler>(*ctx);

        const std::string leaf_cert = leaf_pem.string();
        const std::string leaf_key = leaf_key_pem.string();
        server = std::make_unique<httplib::SSLServer>(leaf_cert.c_str(),
                                                      leaf_key.c_str());
        handler->register_routes(*server, *server);
        server_thread = std::thread([this] { server->listen("127.0.0.1", tls_port); });
        for (int i = 0; i < 100 && !server->is_running(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        ASSERT_TRUE(server->is_running());

        candidate_dir = root / "candidate";
        candidate_key = crypto->ed25519_keygen();
        {
            storage::FileStorageService cstorage{candidate_dir};
            cstorage.start();
            nlohmann::json kp_json;
            kp_json["public_key"] = b64_array(candidate_key.public_key);
            kp_json["private_key"] = b64(std::vector<uint8_t>(
                candidate_key.private_key.begin(), candidate_key.private_key.end()));
            storage::SignedEnvelope env;
            env.type = "identity_keypair";
            env.data = kp_json.dump();
            env.signer_pubkey = "ed25519:" + b64_array(candidate_key.public_key);
            env.timestamp = now_unix();
            ASSERT_TRUE(cstorage.write_file("identity", "keypair.json", env));
            cstorage.stop();
        }
        candidate_config_path = root / "candidate" / "config.json";
    }

    void TearDown() override {
        if (server && server->is_running()) server->stop();
        if (server_thread.joinable()) server_thread.join();
        if (admission) admission->stop();
        if (gossip) gossip->stop();
        if (tree) tree->stop();
        if (auth) auth->stop();
        if (ipam) ipam->stop();
        if (relay) relay->stop();
        if (routing) routing->stop();
        if (attestation) attestation->stop();
        if (ddns) ddns->stop();
        if (kw) kw->stop();
        if (storage) storage->stop();
        if (crypto) crypto->stop();
        if (ca_x509) X509_free(ca_x509);
        if (ca_key) EVP_PKEY_free(ca_key);
        if (!root.empty() && !HasFailure()) fs::remove_all(root);
    }

    /// A bare SSLClient, like the production client: no explicit CA.
    bool default_trust_reaches_server() {
        httplib::SSLClient client("localhost", tls_port);
        auto r = client.Get("/api/onboard/info");
        return static_cast<bool>(r) && client.get_openssl_verify_result() == X509_V_OK;
    }

    /// Two probes: the flow's clients are not the first TLS client in the
    /// process, so the second probe's result is what the flow experiences.
    bool default_trust_ok() {
        return default_trust_reaches_server() && default_trust_reaches_server();
    }
    core::ServerConfig candidate_config(const std::string& token) {
        core::ServerConfig c;
        c.data_root = candidate_dir.string();
        c.root_pubkey = config.root_pubkey;
        c.region = "us-test";
        c.onboard_server_id = "e2e-node-1";
        c.onboard_target = "localhost:" + std::to_string(tls_port);
        c.onboard_timeout_sec = 60;
        c.onboard_token = token;
        c.config_path = candidate_config_path.string();
        return c;
    }

    core::ServerConfig load_config_file(const fs::path& path) {
        std::ifstream f(path);
        auto j = nlohmann::json::parse(f);
        core::ServerConfig c;
        j.get_to(c);
        c.config_path = path.string();
        return c;
    }
};

// ===========================================================================
// Real-client tests need the production client's default TLS trust to reach
// the fixture. On Linux SSL_CERT_FILE is deterministic: an unreachable fixture
// fails the test, never skips. Where the trust cannot be directed (e.g. the
// macOS login keychain) the test skips.
// ===========================================================================
#ifdef __linux__
#define REQUIRE_DEFAULT_TRUST()                                                    \
    do {                                                                           \
        if (!default_trust_ok()) {                                                 \
            ADD_FAILURE() << "default TLS trust cannot reach the test server on " \
                             "Linux; SSL_CERT_FILE is deterministic there";        \
            return;                                                                \
        }                                                                          \
    } while (0)
#else
#define REQUIRE_DEFAULT_TRUST()                                                    \
    do {                                                                           \
        if (!default_trust_ok())                                                   \
            GTEST_SKIP() << "platform default TLS trust cannot be directed here; " \
                             "production flow validation runs on the Linux hosts"; \
    } while (0)
#endif

// The supported flow persists the verified anchor, and a restart through the
// production startup path runs the security lifecycle for a Tier 2 candidate.
TEST_F(GenesisAnchorOnboarding, FullFlowPersistsAnchorAndRestartRunsTheMesh) {
    REQUIRE_DEFAULT_TRUST();
    auto token = admission->mint_admission_token(
        b64_array(candidate_key.public_key), std::chrono::seconds{600});
    ASSERT_TRUE(token.has_value());

    // An unknown key the installer must preserve, and a mode the replacement
    // must keep.
    {
        std::ofstream f(candidate_config_path);
        f << "{\n  \"release_signing_pubkey\": \"U0FNVExFUEtWSU5HTEVLV0FZSQ==\",\n"
           "  \"log_level\": \"debug\"\n}\n";
    }
    const auto pre_mode = fs::status(candidate_config_path).permissions();

    auto candidate = candidate_config(token->first);
    auto rc = core::run_onboard_server(candidate);
    ASSERT_EQ(rc, 0) << "supported onboarding flow failed";

    // --- Persisted state: the exact anchors, atomically, metadata kept. ---
    const auto reloaded = load_config_file(candidate_config_path);
    EXPECT_EQ(reloaded.root_pubkey, config.root_pubkey);
    EXPECT_EQ(reloaded.genesis_pubkey, config.genesis_pubkey);
    EXPECT_EQ(reloaded.release_signing_pubkey, "U0FNVExFUEtWSU5HTEVLV0FZSQ==");
    EXPECT_EQ(reloaded.log_level, "debug");
    ASSERT_FALSE(reloaded.seed_peers.empty());
    EXPECT_EQ(fs::status(candidate_config_path).permissions(), pre_mode);
    EXPECT_FALSE(fs::exists(candidate_config_path.string() + ".tmp"));

    // --- Installed certificate: Tier 2 (no evidence on this host), bound to
    // --- the network the anchor derives.
    storage::FileStorageService cstorage{candidate_dir};
    cstorage.start();
    auto cert_env = cstorage.read_file("identity", "server_cert.json");
    cstorage.stop();
    ASSERT_TRUE(cert_env.has_value());
    auto cert = nlohmann::json::parse(cert_env->data).get<gossip::ServerCertificate>();
    EXPECT_EQ(cert.platform_class, "");  // Tier 2: no TEE prerequisite was applied
    EXPECT_EQ(cert.server_pubkey, b64_array(candidate_key.public_key));
    EXPECT_EQ(cert.network_id, derived_network_hex(gossip->keypair().public_key));

    // Restart: the production startup function, fed only the persisted config and data dir.
    asio::io_context io2;
    storage::FileStorageService rstorage{candidate_dir};
    rstorage.start();
    crypto::KeyWrappingService rkw{*crypto, rstorage};
    rkw.start();
    gossip::GossipService rgossip{io2, 0, rstorage, *crypto};
    rgossip.start();

    std::string mesh_error;
    auto startup = core::start_security_mesh(io2, reloaded, rgossip, rkw,
                                             security::PlatformEvidenceSource{}, mesh_error);
    ASSERT_TRUE(startup.has_value()) << mesh_error;
    EXPECT_EQ(startup->network_id_hex, derived_network_hex(gossip->keypair().public_key));
    // Not the anchor: a Tier 2 candidate runs the lifecycle with no assumed role.
    EXPECT_EQ(startup->service->driver().phase(), security::DriverPhase::Idle);

    startup->service->stop();
    rgossip.stop();
    rkw.stop();
    rstorage.stop();
}

// The anchor node's restart: the persisted anchor is its own gossip identity,
// so the driver enters GenesisCollecting.
TEST_F(GenesisAnchorOnboarding, AnchorNodeRestartFromPersistedConfigCollectsGenesis) {
    const fs::path operator_config = root / "root" / "operator-config.json";
    {
        std::ofstream f(operator_config);
        nlohmann::json j;
        j["data_root"] = config.data_root;
        j["root_pubkey"] = config.root_pubkey;
        j["genesis_pubkey"] = config.genesis_pubkey;
        j["release_signing_pubkey"] = config.root_pubkey;
        f << j.dump(2) << "\n";
    }

    const auto reloaded = load_config_file(operator_config);
    ASSERT_EQ(reloaded.genesis_pubkey, config.genesis_pubkey);

    asio::io_context io2;
    storage::FileStorageService rstorage{root / "root"};
    rstorage.start();
    crypto::KeyWrappingService rkw{*crypto, rstorage};
    rkw.start();
    gossip::GossipService rgossip{io2, 0, rstorage, *crypto};
    rgossip.start();
    EXPECT_EQ(rgossip.keypair().public_key, gossip->keypair().public_key);

    std::string mesh_error;
    auto startup = core::start_security_mesh(io2, reloaded, rgossip, rkw,
                                             security::PlatformEvidenceSource{}, mesh_error);
    ASSERT_TRUE(startup.has_value()) << mesh_error;
    EXPECT_EQ(startup->service->driver().phase(),
              security::DriverPhase::GenesisCollecting);

    startup->service->stop();
    rgossip.stop();
    rkw.stop();
    rstorage.stop();
}

// A stored approval whose certificate names a different network than the
// configured anchor derives is not served as a bundle.
TEST_F(GenesisAnchorOnboarding, TamperedAdmissionStoreIsNotServedAsApprovedBundle) {
    auto other_genesis = crypto->ed25519_keygen();

    gossip::CertIssueParams params;
    params.network_id = derived_network_hex(other_genesis.public_key);
    params.server_pubkey_b64 = b64_array(candidate_key.public_key);
    params.server_id = "e2e-node-1";
    auto root_identity = kw->load_identity_pubkey();
    auto root_priv = kw->unlock_identity({});
    ASSERT_TRUE(root_identity.has_value() && root_priv.has_value());
    auto foreign_cert =
        gossip::issue_server_certificate(params, *crypto, *root_priv, *root_identity);

    core::AdmissionRecord record;
    record.request_id = std::string(32, 'a');
    record.candidate_pubkey = b64_array(candidate_key.public_key);
    record.server_id = "e2e-node-1";
    record.state = core::AdmissionState::Approved;
    record.created_at = now_unix();
    record.expires_at = now_unix() + 3600;
    record.issued_cert_json = nlohmann::json(foreign_cert).dump();
    record.decision_mode = "sole";

    // Persist the tampered store BEFORE the service reloads it.
    admission->stop();
    core::AdmissionStoreDocument document;
    document.ever_approved = true;
    document.admissions.push_back(record);
    storage::SignedEnvelope env;
    env.type = "admissions";
    env.data = document.toJson().dump();
    env.timestamp = now_unix();
    ASSERT_TRUE(storage->write_file("onboarding", "admissions.json", env));
    admission->start();  // loads the tampered store

    uint64_t ts = now_unix();
    core::PollRequest poll;
    poll.request_id = record.request_id;
    poll.candidate_pubkey = record.candidate_pubkey;
    poll.timestamp = ts;
    auto msg = core::canonical_onboarding_status(core::kOnboardPollTag, record.request_id,
                                                 ts);
    auto sig = crypto->ed25519_sign(candidate_key.private_key,
                                    std::span<const uint8_t>(msg));
    poll.signature = b64(std::vector<uint8_t>(sig.begin(), sig.end()));

    httplib::SSLClient client("localhost", tls_port);
    client.set_ca_cert_path(ca_pem.string());
    auto res = client.Post("/api/onboard/poll", poll.toJson().dump(), "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 500);
    auto decoded = core::poll_response_from_json(nlohmann::json::parse(res->body, nullptr, false));
    const bool is_bundle =
        static_cast<bool>(decoded) &&
        std::get_if<core::ApprovedOnboardingBundle>(&*decoded.value) != nullptr;
    EXPECT_FALSE(is_bundle);
}

// A pre-existing config that does not parse as a JSON object is never
// overwritten by onboarding: the run fails and the bytes stay untouched.
TEST_F(GenesisAnchorOnboarding, MalformedExistingConfigRefusedAndUntouched) {
    REQUIRE_DEFAULT_TRUST();
    auto token = admission->mint_admission_token(
        b64_array(candidate_key.public_key), std::chrono::seconds{600});
    ASSERT_TRUE(token.has_value());

    const std::string broken = "{ this is not json\n";
    { std::ofstream f(candidate_config_path); f << broken; }

    auto candidate = candidate_config(token->first);
    auto rc = core::run_onboard_server(candidate);
    EXPECT_NE(rc, 0);
    // The refusal must be the config install, not the transport.
    auto env = storage->read_file("onboarding", "admissions.json");
    ASSERT_TRUE(env.has_value());
    auto doc = core::admission_store_from_json(nlohmann::json::parse(env->data));
    ASSERT_TRUE(static_cast<bool>(doc));
    EXPECT_TRUE(std::any_of(doc.value->admissions.begin(),
                            doc.value->admissions.end(),
                            [&](const auto& r) {
                                return r.candidate_pubkey ==
                                       b64_array(candidate_key.public_key);
                            }));
    std::ifstream f(candidate_config_path);
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    EXPECT_EQ(content, broken);
}

// If the process cannot safely replace the config, onboarding fails closed
// and leaves the config unmodified.
TEST_F(GenesisAnchorOnboarding, UnwritableConfigDirectoryRefusedAndUntouched) {
    REQUIRE_DEFAULT_TRUST();
    auto token = admission->mint_admission_token(
        b64_array(candidate_key.public_key), std::chrono::seconds{600});
    ASSERT_TRUE(token.has_value());

    const fs::path ro_dir = root / "ro-config";
    fs::create_directory(ro_dir);
    const fs::path ro_config = ro_dir / "config.json";
    { std::ofstream f(ro_config); f << "{}\n"; }
    fs::permissions(ro_dir, fs::perms::owner_read | fs::perms::owner_exec);

    auto candidate = candidate_config(token->first);
    candidate.config_path = ro_config.string();
    auto rc = core::run_onboard_server(candidate);
    EXPECT_NE(rc, 0);

    // The refusal must be the config install, not the transport.
    auto env = storage->read_file("onboarding", "admissions.json");
    ASSERT_TRUE(env.has_value());
    auto doc = core::admission_store_from_json(nlohmann::json::parse(env->data));
    ASSERT_TRUE(static_cast<bool>(doc));
    const bool reached = std::any_of(doc.value->admissions.begin(),
                                     doc.value->admissions.end(),
                                     [&](const auto& r) {
                                         return r.candidate_pubkey ==
                                                b64_array(candidate_key.public_key);
                                     });
    EXPECT_TRUE(reached);

    std::ifstream f(ro_config);
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    EXPECT_EQ(content, "{}\n");
    EXPECT_FALSE(fs::exists(ro_config.string() + ".tmp"));
    fs::permissions(ro_dir, fs::perms::owner_all);
}

// ===========================================================================
// The production startup function itself fails closed
// ===========================================================================

TEST(SecurityMeshStartup, MalformedAnchorRefused) {
    asio::io_context io;
    crypto::SodiumCryptoService c;
    c.start();
    auto tmp = fs::temp_directory_path() / ("nexus_test_meshstart_" + std::to_string(getpid()));
    fs::create_directories(tmp);
    storage::FileStorageService s{tmp};
    s.start();
    crypto::KeyWrappingService kw{c, s};
    kw.start();
    gossip::GossipService g{io, 0, s, c};
    g.start();

    core::ServerConfig config;
    config.data_root = tmp.string();
    config.genesis_pubkey = "not-a-key";
    std::string error;
    EXPECT_FALSE(core::start_security_mesh(io, config, g, kw,
                                           security::PlatformEvidenceSource{}, error)
                     .has_value());
    EXPECT_FALSE(error.empty());

    g.stop();
    kw.stop();
    s.stop();
    c.stop();
    fs::remove_all(tmp);
}

// ===========================================================================
// Atomic config install keeps operator file metadata
// ===========================================================================

TEST(DurableWritePreserving, ExistingFileKeepsModeAndContentReplaced) {
    auto tmp = fs::temp_directory_path() / ("nexus_test_durwrite_" + std::to_string(getpid()));
    fs::create_directories(tmp);
    const auto path = tmp / "config.json";
    { std::ofstream f(path); f << "old\n"; }
    fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write |
                             fs::perms::group_read);

    ASSERT_TRUE(security::write_durable_preserving(path, "new\n"));
    std::ifstream f(path);
    std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    EXPECT_EQ(content, "new\n");
    EXPECT_EQ(fs::status(path).permissions(),
              fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read);
    EXPECT_FALSE(fs::exists(path.string() + ".tmp"));

    // A brand-new file gets the conservative mode.
    const auto fresh = tmp / "fresh.json";
    ASSERT_TRUE(security::write_durable_preserving(fresh, "x\n"));
    EXPECT_EQ(fs::status(fresh).permissions(),
              fs::perms::owner_read | fs::perms::owner_write);
    fs::remove_all(tmp);
}

// ===========================================================================
// Normal startup requires the Genesis anchor
// ===========================================================================

namespace {

core::ServerConfig full_normal_config() {
    core::ServerConfig c;
    c.data_root = "/tmp/nexus-startup-test";
    c.root_pubkey = std::string(64, 'a');
    c.release_signing_pubkey = "QUtUSU5OEUFL";
    return c;
}

std::string valid_anchor_b64() {
    return b64(std::vector<uint8_t>(32, 1));
}

}  // namespace

TEST(StartupGenesisGate, NormalStartWithoutAnchorRefused) {
    auto c = full_normal_config();
    EXPECT_FALSE(core::validate_config(c));
}

TEST(StartupGenesisGate, NormalStartWithAnchorAccepted) {
    auto c = full_normal_config();
    c.genesis_pubkey = valid_anchor_b64();
    EXPECT_TRUE(core::validate_config(c));
}

TEST(StartupGenesisGate, MalformedAnchorRefused) {
    auto c = full_normal_config();
    c.genesis_pubkey = "short";
    EXPECT_FALSE(core::validate_config(c));
}

TEST(StartupGenesisGate, CliModesExempt) {
    core::ServerConfig c;  // defaults; nothing anchored yet
    c.first_run = true;
    EXPECT_TRUE(core::validate_config(c));

    c = core::ServerConfig{};
    c.onboard_server = true;
    c.root_pubkey = std::string(64, 'a');
    EXPECT_TRUE(core::validate_config(c));
}
