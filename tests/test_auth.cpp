#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/PasskeyAuthProvider.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <gtest/gtest.h>

#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

using namespace nexus;
namespace fs = std::filesystem;

class AuthTest : public ::testing::Test {
protected:
    fs::path temp_dir;
    std::unique_ptr<crypto::SodiumCryptoService> crypto;
    std::unique_ptr<storage::FileStorageService> storage;
    std::unique_ptr<auth::AuthService> auth;

    std::string rp_id = "lemonade-nexus.local";
    std::string jwt_secret;

    void SetUp() override {
        temp_dir = fs::temp_directory_path() / ("nexus_test_auth_" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()));
        fs::create_directories(temp_dir);

        crypto = std::make_unique<crypto::SodiumCryptoService>();
        crypto->start();

        // Generate random JWT secret
        std::array<uint8_t, 32> secret_bytes{};
        crypto->random_bytes(std::span<uint8_t>(secret_bytes));
        jwt_secret = crypto::to_hex(std::span<const uint8_t>(secret_bytes));

        storage = std::make_unique<storage::FileStorageService>(temp_dir);
        storage->start();

        auth = std::make_unique<auth::AuthService>(*storage, *crypto, rp_id, jwt_secret);
        auth->start();
    }

    void TearDown() override {
        auth->stop();
        storage->stop();
        crypto->stop();
        fs::remove_all(temp_dir);
    }
};

// --- Auth dispatch ---

TEST_F(AuthTest, UnknownMethodReturnsError) {
    nlohmann::json req = {{"method", "unknown"}};
    auto result = auth->authenticate(req);
    EXPECT_FALSE(result.authenticated);
    EXPECT_NE(result.error_message.find("Unknown"), std::string::npos);
}

TEST_F(AuthTest, MissingMethodReturnsError) {
    nlohmann::json req = {{"foo", "bar"}};
    auto result = auth->authenticate(req);
    EXPECT_FALSE(result.authenticated);
}

// --- Password auth (currently always fails - TODO in code) ---

TEST_F(AuthTest, PasswordAuthMissingFields) {
    nlohmann::json req = {{"method", "password"}};
    auto result = auth->authenticate(req);
    EXPECT_FALSE(result.authenticated);
    EXPECT_NE(result.error_message.find("Missing"), std::string::npos);
}

TEST_F(AuthTest, PasswordAuthCurrentlyFails) {
    nlohmann::json req = {
        {"method", "password"},
        {"username", "alice"},
        {"password", "secret123"}
    };
    auto result = auth->authenticate(req);
    // Password provider currently returns false (TODO in code)
    EXPECT_FALSE(result.authenticated);
}

// --- Passkey registration ---

TEST_F(AuthTest, PasskeyRegisterMissingFields) {
    nlohmann::json reg = {{"user_id", "bob"}};
    auto result = auth->register_passkey(reg);
    EXPECT_FALSE(result.authenticated);
    EXPECT_NE(result.error_message.find("Missing"), std::string::npos);
}

TEST_F(AuthTest, PasskeyRegisterInvalidHex) {
    nlohmann::json reg = {
        {"user_id", "bob"},
        {"credential_id", "test_cred_id"},
        {"public_key_x", "ZZZZ"},  // invalid hex
        {"public_key_y", "ZZZZ"},
    };
    auto result = auth->register_passkey(reg);
    EXPECT_FALSE(result.authenticated);
}

TEST_F(AuthTest, PasskeyRegisterValidCredential) {
    // Generate an ECDSA P-256 key pair using OpenSSL
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    // Extract X and Y coordinates
    BIGNUM* x_bn = nullptr;
    BIGNUM* y_bn = nullptr;
    EVP_PKEY_get_bn_param(pkey, "qx", &x_bn);
    EVP_PKEY_get_bn_param(pkey, "qy", &y_bn);

    std::vector<uint8_t> x_bytes(32, 0);
    std::vector<uint8_t> y_bytes(32, 0);
    BN_bn2binpad(x_bn, x_bytes.data(), 32);
    BN_bn2binpad(y_bn, y_bytes.data(), 32);

    BN_free(x_bn);
    BN_free(y_bn);
    EVP_PKEY_free(pkey);

    nlohmann::json reg = {
        {"user_id", "bob"},
        {"credential_id", "cred_abc123"},
        {"public_key_x", crypto::to_hex(x_bytes)},
        {"public_key_y", crypto::to_hex(y_bytes)},
    };

    auto result = auth->register_passkey(reg);
    EXPECT_TRUE(result.authenticated);
    EXPECT_EQ(result.user_id, "bob");
    EXPECT_FALSE(result.session_token.empty());
}

// --- JWT session validation ---

TEST_F(AuthTest, ValidateValidJWT) {
    // Register a passkey to get a valid JWT
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1);
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);

    BIGNUM* x_bn = nullptr;
    BIGNUM* y_bn = nullptr;
    EVP_PKEY_get_bn_param(pkey, "qx", &x_bn);
    EVP_PKEY_get_bn_param(pkey, "qy", &y_bn);

    std::vector<uint8_t> x(32, 0), y(32, 0);
    BN_bn2binpad(x_bn, x.data(), 32);
    BN_bn2binpad(y_bn, y.data(), 32);

    BN_free(x_bn);
    BN_free(y_bn);
    EVP_PKEY_free(pkey);

    nlohmann::json reg = {
        {"user_id", "alice"},
        {"credential_id", "cred_xyz"},
        {"public_key_x", crypto::to_hex(x)},
        {"public_key_y", crypto::to_hex(y)},
    };

    auto result = auth->register_passkey(reg);
    ASSERT_TRUE(result.authenticated);
    ASSERT_FALSE(result.session_token.empty());

    // Validate the JWT
    EXPECT_TRUE(auth->validate_session(result.session_token));
}

TEST_F(AuthTest, ValidateInvalidJWT) {
    EXPECT_FALSE(auth->validate_session("invalid.jwt.token"));
}

TEST_F(AuthTest, ValidateTamperedJWT) {
    EXPECT_FALSE(auth->validate_session(
        "eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJmYWtlIn0.invalid_signature"));
}

// --- Passkey auth without assertion ---

TEST_F(AuthTest, PasskeyAuthMissingAssertion) {
    nlohmann::json req = {{"method", "passkey"}};
    auto result = auth->authenticate(req);
    EXPECT_FALSE(result.authenticated);
    EXPECT_NE(result.error_message.find("assertion"), std::string::npos);
}

TEST_F(AuthTest, PasskeyAuthUnknownCredential) {
    nlohmann::json req = {
        {"method", "passkey"},
        {"assertion", {
            {"credential_id", "nonexistent"},
            {"authenticator_data", "AAAA"},
            {"client_data_json", "AAAA"},
            {"signature", "AAAA"},
        }}
    };
    auto result = auth->authenticate(req);
    EXPECT_FALSE(result.authenticated);
}

// --- Service interface ---

TEST_F(AuthTest, ServiceName) {
    EXPECT_EQ(auth->service_name(), "AuthService");
}
