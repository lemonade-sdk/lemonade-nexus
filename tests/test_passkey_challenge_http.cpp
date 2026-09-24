// HTTP-level coverage for the passkey challenge flow: issuance,
// error handling, and passkey authentication through the real
// AuthApiHandler routes with a live HttpServer.

#include <LemonadeNexus/Network/HttpServer.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
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

#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <span>
#include <string>
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

namespace {

[[nodiscard]] EVP_PKEY* generate_p256() {
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

void p256_coordinates(EVP_PKEY* pkey, std::vector<uint8_t>& x, std::vector<uint8_t>& y) {
    BIGNUM* x_bn = nullptr;
    BIGNUM* y_bn = nullptr;
    EVP_PKEY_get_bn_param(pkey, "qx", &x_bn);
    EVP_PKEY_get_bn_param(pkey, "qy", &y_bn);
    x.assign(32, 0);
    y.assign(32, 0);
    BN_bn2binpad(x_bn, x.data(), 32);
    BN_bn2binpad(y_bn, y.data(), 32);
    BN_free(x_bn);
    BN_free(y_bn);
}

std::string b64url(const std::vector<uint8_t>& bytes) {
    std::string out = crypto::to_base64(std::span<const uint8_t>(bytes));
    for (auto& ch : out) {
        if (ch == '+') ch = '-';
        else if (ch == '/') ch = '_';
    }
    out.erase(std::remove(out.begin(), out.end(), '='), out.end());
    return out;
}

std::vector<uint8_t> sha256(crypto::SodiumCryptoService& c, const std::string_view in) {
    auto hash = c.sha256(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(in.data()), in.size()));
    return {hash.begin(), hash.end()};
}

std::vector<uint8_t> sign_p256(EVP_PKEY* pkey, const std::vector<uint8_t>& data) {
    size_t sig_len = 0;
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mctx, nullptr, EVP_sha256(), nullptr, pkey);
    EVP_DigestSign(mctx, nullptr, &sig_len, data.data(), data.size());
    std::vector<uint8_t> sig(sig_len);
    EVP_DigestSign(mctx, sig.data(), &sig_len, data.data(), data.size());
    EVP_MD_CTX_free(mctx);
    sig.resize(sig_len);
    return sig;
}

json make_assertion(crypto::SodiumCryptoService& c, const std::string& rp_id,
                    EVP_PKEY* pkey, const std::string& credential_id,
                    const std::string& challenge_encoded,
                    uint32_t sign_count) {
    std::vector<uint8_t> auth_data;
    auto h = sha256(c, rp_id);
    auth_data.insert(auth_data.end(), h.begin(), h.end());
    auth_data.push_back(0x01);
    auth_data.push_back(static_cast<uint8_t>(sign_count >> 24));
    auth_data.push_back(static_cast<uint8_t>(sign_count >> 16));
    auth_data.push_back(static_cast<uint8_t>(sign_count >> 8));
    auth_data.push_back(static_cast<uint8_t>(sign_count));

    json cdj = {{"type", "webauthn.get"}, {"origin", rp_id}, {"challenge", challenge_encoded}};
    auto cdj_dump = cdj.dump();
    auto cdj_bytes = std::vector<uint8_t>(cdj_dump.begin(), cdj_dump.end());

    std::vector<uint8_t> signed_data = auth_data;
    auto cdj_hash = sha256(c, cdj_dump);
    signed_data.insert(signed_data.end(), cdj_hash.begin(), cdj_hash.end());

    return {
        {"method", "passkey"},
        {"assertion", {
            {"credential_id", credential_id},
            {"authenticator_data", b64url(auth_data)},
            {"client_data_json", b64url(cdj_bytes)},
            {"signature", b64url(sign_p256(pkey, signed_data))},
        }},
    };
}

}  // namespace

// The AuthApiHandler holds a reference into the ApiContext, which must
// outlive every route lambda it registers. Keep both process-lifetime (the
// fixture runs sequentially in one gtest process); services are stopped in
// TearDown before any route could be invoked again.
struct ApiContextHolder {
    api::ApiContext* ctx = nullptr;
    api::AuthApiHandler* handler = nullptr;
    ~ApiContextHolder() {
        delete handler;
        delete ctx;
    }
};
static ApiContextHolder& holder() {
    static ApiContextHolder h;
    return h;
}

class PasskeyChallengeHttpTest : public ::testing::Test {
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
    std::string root_pubkey_str;
    std::string jwt_secret;

    static constexpr std::string_view kRpId = "lemonade-nexus.local";

    void SetUp() override {
        test_port_ = static_cast<uint16_t>(19200 + (getpid() % 10000));
        temp_dir = fs::temp_directory_path() / ("nexus_test_passkey_http_" + std::to_string(getpid()));
        fs::create_directories(temp_dir);

        crypto = std::make_unique<crypto::SodiumCryptoService>();
        crypto->start();

        storage = std::make_unique<storage::FileStorageService>(temp_dir);
        storage->start();

        key_wrapping = std::make_unique<crypto::KeyWrappingService>(*crypto, *storage);
        key_wrapping->start();

        root_keypair = crypto->ed25519_keygen();
        root_pubkey_str = "ed25519:" + crypto::to_base64(root_keypair.public_key);

        tree = std::make_unique<tree::PermissionTreeService>(*storage, *crypto);
        tree->start();

        std::array<uint8_t, 32> secret_bytes{};
        crypto->random_bytes(std::span<uint8_t>(secret_bytes));
        jwt_secret = crypto::to_hex(std::span<const uint8_t>(secret_bytes));

        auth = std::make_unique<auth::AuthService>(*storage, *crypto, std::string(kRpId), jwt_secret);
        auth->start();

        ipam = std::make_unique<ipam::IPAMService>(*storage);
        ipam->start();

        http = std::make_unique<network::HttpServer>(test_port_);

        // Unstarted stand-ins for ApiContext reference members; the routes
        // under test only touch auth.
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
        holder().handler = new api::AuthApiHandler(*holder().ctx);
        holder().handler->register_routes(http->server(), http->server());
        http->start();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    void TearDown() override {
        if (http) http->stop();
        // Route lambdas are dead with the server; drop the handler and
        // context before tearing down the services they reference.
        delete holder().handler;
        holder().handler = nullptr;
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

    // Register a passkey credential over the real /api/auth/register route
    // with the caller's session: the credential binds to that identity.
    bool register_credential(EVP_PKEY* pkey, const std::string& user_id,
                             const std::string& credential_id,
                             const std::string& session_token) {
        std::vector<uint8_t> x, y;
        p256_coordinates(pkey, x, y);
        json body = {
            {"user_id", user_id},
            {"credential_id", credential_id},
            {"public_key_x", crypto::to_hex(x)},
            {"public_key_y", crypto::to_hex(y)},
        };
        httplib::Headers headers{{"Authorization", "Bearer " + session_token}};
        auto cli = make_client();
        auto res = cli.Post("/api/auth/register", headers, body.dump(),
                            "application/json");
        return res && res->status == 200;
    }

    bool credential_file_exists(const std::string& user_id) const {
        return fs::exists(temp_dir / "credentials" / (user_id + ".json"));
    }

    // Raw stored credential file contents for mutation comparisons.
    std::string stored_credentials_file(const std::string& user_id) const {
        std::ifstream ifs(temp_dir / "credentials" / (user_id + ".json"));
        std::ostringstream ss;
        ss << ifs.rdbuf();
        return ss.str();
    }
};

TEST_F(PasskeyChallengeHttpTest, ChallengeIssuanceReturnsCanonicalBase64Url) {
    auto cli = make_client();
    auto res = cli.Post("/api/auth/challenge",
                        json{{"type", "passkey"}, {"user_id", "alice"}}.dump(),
                        "application/json");
    ASSERT_TRUE(res);
    ASSERT_EQ(res->status, 200);

    auto body = json::parse(res->body);
    const auto challenge = body.value("challenge", std::string{});
    ASSERT_EQ(challenge.size(), 43u);  // unpadded base64url of 32 bytes
    EXPECT_EQ(challenge.find('+'), std::string::npos);
    EXPECT_EQ(challenge.find('/'), std::string::npos);
    EXPECT_EQ(challenge.find('='), std::string::npos);
    EXPECT_GT(body.value("expires_at", 0), 0);
}

TEST_F(PasskeyChallengeHttpTest, ChallengeIssuanceErrorHandling) {
    auto cli = make_client();

    // Missing body / missing type / missing user_id all refuse.
    for (const auto& payload : {std::string{"{}"},
                                std::string{R"json({"type":"passkey"})json"},
                                std::string{R"json({"type":"passkey","user_id":""})json"}}) {
        auto res = cli.Post("/api/auth/challenge", payload, "application/json");
        ASSERT_TRUE(res) << payload;
        EXPECT_EQ(res->status, 400) << payload;
    }

    // Oversized user_id is a client error, not a capacity error.
    auto res = cli.Post("/api/auth/challenge",
                        json{{"type", "passkey"}, {"user_id", std::string(129, 'u')}}.dump(),
                        "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 400);

    // Malformed JSON body.
    res = cli.Post("/api/auth/challenge", "not json", "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 400);
}

TEST_F(PasskeyChallengeHttpTest, Ed25519ChallengeFlowUnchanged) {
    auto cli = make_client();
    auto res = cli.Post("/api/auth/challenge",
                        json{{"pubkey", root_pubkey_str}}.dump(), "application/json");
    ASSERT_TRUE(res);
    ASSERT_EQ(res->status, 200);
    EXPECT_FALSE(json::parse(res->body).value("challenge", std::string{}).empty());

    // The ed25519 path still refuses a missing pubkey.
    res = cli.Post("/api/auth/challenge", "{}", "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 400);
}

TEST_F(PasskeyChallengeHttpTest, PasskeyAuthenticationWithIssuedChallengeSucceeds) {
    auto login = login_ed25519(root_keypair);
    ASSERT_TRUE(login.has_value());
    auto* pkey = generate_p256();
    ASSERT_TRUE(register_credential(pkey, login->second, "cred_alice",
                                    login->first));

    auto cli = make_client();
    auto res = cli.Post("/api/auth/challenge",
                        json{{"type", "passkey"}, {"user_id", login->second}}.dump(),
                        "application/json");
    ASSERT_TRUE(res);
    ASSERT_EQ(res->status, 200);
    const auto challenge = json::parse(res->body).at("challenge").get<std::string>();

    auto auth_res = cli.Post("/api/auth",
                             make_assertion(*crypto, std::string(kRpId), pkey, "cred_alice", challenge, 0)
                                 .dump(),
                             "application/json");
    ASSERT_TRUE(auth_res);
    ASSERT_EQ(auth_res->status, 200);
    auto body = json::parse(auth_res->body);
    EXPECT_TRUE(body.value("authenticated", false));
    EXPECT_EQ(body.value("user_id", ""), login->second);
    EXPECT_FALSE(body.value("session_token", std::string{}).empty());
    EVP_PKEY_free(pkey);
}

TEST_F(PasskeyChallengeHttpTest, ChallengeReplayRejectedOverHttp) {
    auto login = login_ed25519(root_keypair);
    ASSERT_TRUE(login.has_value());
    auto* pkey = generate_p256();
    ASSERT_TRUE(register_credential(pkey, login->second, "cred_alice",
                                    login->first));

    auto cli = make_client();
    auto res = cli.Post("/api/auth/challenge",
                        json{{"type", "passkey"}, {"user_id", login->second}}.dump(),
                        "application/json");
    ASSERT_TRUE(res);
    ASSERT_EQ(res->status, 200);
    const auto challenge = json::parse(res->body).at("challenge").get<std::string>();
    const auto assertion =
        make_assertion(*crypto, std::string(kRpId), pkey, "cred_alice", challenge, 0);

    auto first = cli.Post("/api/auth", assertion.dump(), "application/json");
    ASSERT_TRUE(first);
    ASSERT_EQ(first->status, 200);

    // Identical bytes, second flight: single-use challenge is spent.
    auto second = cli.Post("/api/auth", assertion.dump(), "application/json");
    ASSERT_TRUE(second);
    EXPECT_EQ(second->status, 401);
    EVP_PKEY_free(pkey);
}

TEST_F(PasskeyChallengeHttpTest, UnissuedChallengeRejectedOverHttp) {
    auto login = login_ed25519(root_keypair);
    ASSERT_TRUE(login.has_value());
    auto* pkey = generate_p256();
    ASSERT_TRUE(register_credential(pkey, login->second, "cred_alice",
                                    login->first));

    std::array<uint8_t, 32> forged{};
    for (auto& b : forged) b = 0x2A;
    auto cli = make_client();
    auto res = cli.Post("/api/auth",
                        make_assertion(*crypto, std::string(kRpId), pkey, "cred_alice",
                                       crypto::to_base64(forged), 0)
                            .dump(),
                        "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 401);
    EVP_PKEY_free(pkey);
}

// ============================================================================
// Registration authorization (F-34c): /api/auth/register requires a valid
// session and binds the credential to that session's verified identity.
// ============================================================================

TEST_F(PasskeyChallengeHttpTest, RegisterWithoutSessionRejectedNoMutation) {
    auto* pkey = generate_p256();
    std::vector<uint8_t> x, y;
    p256_coordinates(pkey, x, y);
    json body = {
        {"user_id", "mallory"},
        {"credential_id", "cred_mallory"},
        {"public_key_x", crypto::to_hex(x)},
        {"public_key_y", crypto::to_hex(y)},
    };
    auto cli = make_client();
    auto res = cli.Post("/api/auth/register", body.dump(), "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 401);
    EXPECT_FALSE(credential_file_exists("mallory"));
    EVP_PKEY_free(pkey);
}

TEST_F(PasskeyChallengeHttpTest, RegisterWithForgedSessionRejectedNoMutation) {
    auto* pkey = generate_p256();
    std::vector<uint8_t> x, y;
    p256_coordinates(pkey, x, y);
    json body = {
        {"user_id", "mallory"},
        {"credential_id", "cred_mallory"},
        {"public_key_x", crypto::to_hex(x)},
        {"public_key_y", crypto::to_hex(y)},
    };
    httplib::Headers headers{{"Authorization", "Bearer not-a-real-jwt"}};
    auto cli = make_client();
    auto res = cli.Post("/api/auth/register", headers, body.dump(),
                        "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 401);
    EXPECT_FALSE(credential_file_exists("mallory"));
    EVP_PKEY_free(pkey);
}

TEST_F(PasskeyChallengeHttpTest, RegisterBindsToSessionIdentityNotBodyUserId) {
    auto login = login_ed25519(root_keypair);
    ASSERT_TRUE(login.has_value());
    auto* pkey = generate_p256();
    // Body asks for a foreign identity; the session identity must win.
    std::vector<uint8_t> x, y;
    p256_coordinates(pkey, x, y);
    json body = {
        {"user_id", "mallory"},
        {"credential_id", "cred_foreign"},
        {"public_key_x", crypto::to_hex(x)},
        {"public_key_y", crypto::to_hex(y)},
    };
    httplib::Headers headers{{"Authorization", "Bearer " + login->first}};
    auto cli = make_client();
    auto res = cli.Post("/api/auth/register", headers, body.dump(),
                        "application/json");
    ASSERT_TRUE(res);
    ASSERT_EQ(res->status, 200) << res->body;
    auto j = json::parse(res->body);
    EXPECT_EQ(j.value("user_id", ""), login->second);

    // Stored under the session identity only, never under the spoofed one.
    EXPECT_FALSE(credential_file_exists("mallory"));
    EXPECT_NE(stored_credentials_file(login->second).find("cred_foreign"),
              std::string::npos);
    EVP_PKEY_free(pkey);
}

TEST_F(PasskeyChallengeHttpTest, RegisterCannotReplaceAnotherIdentityCredential) {
    // Identity B registers a real credential under its own session.
    auto kp_b = crypto->ed25519_keygen();
    auto login_b = login_ed25519(kp_b);
    ASSERT_TRUE(login_b.has_value());
    auto* pkey_b = generate_p256();
    ASSERT_TRUE(register_credential(pkey_b, login_b->second, "cred_b",
                                    login_b->first));
    const auto before = stored_credentials_file(login_b->second);

    // Identity A tries to take cred_b by spoofing B's user_id in the body.
    // The credential_id is already owned by B, so the registration is
    // rejected before disk or cache changes.
    auto login_a = login_ed25519(root_keypair);
    ASSERT_TRUE(login_a.has_value());
    auto* pkey_a = generate_p256();
    std::vector<uint8_t> x, y;
    p256_coordinates(pkey_a, x, y);
    json body = {
        {"user_id", login_b->second},
        {"credential_id", "cred_b"},
        {"public_key_x", crypto::to_hex(x)},
        {"public_key_y", crypto::to_hex(y)},
    };
    httplib::Headers headers{{"Authorization", "Bearer " + login_a->first}};
    auto cli = make_client();
    auto res = cli.Post("/api/auth/register", headers, body.dump(),
                        "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 400);

    // B's credential file is byte-identical to before, and A's file never
    // gains the foreign credential id.
    EXPECT_EQ(stored_credentials_file(login_b->second), before);
    EXPECT_EQ(stored_credentials_file(login_a->second).find("cred_b"),
              std::string::npos);

    // The original credential still authenticates as its original user.
    auto ch_res = cli.Post("/api/auth/challenge",
                           json{{"type", "passkey"}, {"user_id", login_b->second}}.dump(),
                           "application/json");
    ASSERT_TRUE(ch_res);
    ASSERT_EQ(ch_res->status, 200);
    const auto challenge = json::parse(ch_res->body).at("challenge").get<std::string>();
    auto auth_res = cli.Post("/api/auth",
                             make_assertion(*crypto, std::string(kRpId), pkey_b,
                                            "cred_b", challenge, 0).dump(),
                             "application/json");
    ASSERT_TRUE(auth_res);
    ASSERT_EQ(auth_res->status, 200) << auth_res->body;
    EXPECT_EQ(json::parse(auth_res->body).value("user_id", ""), login_b->second);
    EVP_PKEY_free(pkey_a);
    EVP_PKEY_free(pkey_b);
}

TEST_F(PasskeyChallengeHttpTest, RegisterInvalidBodyWithSessionRejectedNoMutation) {
    auto login = login_ed25519(root_keypair);
    ASSERT_TRUE(login.has_value());
    // The ed25519 login persists the caller's own identity file; a rejected
    // registration must leave its contents unchanged.
    const auto before = stored_credentials_file(login->second);
    json body = {
        {"user_id", login->second},
        {"credential_id", "cred_x"},
        // missing public_key_x / public_key_y
    };
    httplib::Headers headers{{"Authorization", "Bearer " + login->first}};
    auto cli = make_client();
    auto res = cli.Post("/api/auth/register", headers, body.dump(),
                        "application/json");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 400);
    EXPECT_EQ(stored_credentials_file(login->second), before);
}
