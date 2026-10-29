#include <LemonadeNexus/Auth/AuthMiddleware.hpp>   // complete SessionClaims
#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/LinkTokenLedger.hpp>
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
#include <ctime>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif
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
        temp_dir = fs::temp_directory_path() / ("nexus_test_auth_" + std::to_string(getpid()));
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

// --- Token-link device linking ---

TEST_F(AuthTest, LinkTokenMintAndConsume) {
    auto minted = auth->mint_link_token("owner-user", "ed25519:AAAA",
                                        "customer-owner", std::chrono::seconds{600});
    ASSERT_TRUE(minted.has_value());
    EXPECT_TRUE(minted->token.starts_with("lnk_"));
    EXPECT_EQ(minted->token.size(), 4u + 64u);
    EXPECT_TRUE(auth::is_link_code(minted->code));
    EXPECT_EQ(minted->record.group_node_id, "customer-owner");
    EXPECT_GT(minted->record.expires_at, minted->record.created_at);
    ASSERT_TRUE(minted->record.grant.has_value());
    EXPECT_EQ(minted->record.grant->code_hash, auth::link_code_hash_hex(minted->code));

    auto consumed = auth->consume_link_token(minted->token);
    ASSERT_TRUE(consumed.has_value());
    EXPECT_EQ(consumed->owner_user_id, "owner-user");
    EXPECT_EQ(consumed->owner_pubkey, "ed25519:AAAA");
    EXPECT_EQ(consumed->group_node_id, "customer-owner");

    // Single use — a second consume fails
    EXPECT_FALSE(auth->consume_link_token(minted->token).has_value());
}

TEST_F(AuthTest, LinkTokenUnknownRejected) {
    EXPECT_FALSE(auth->consume_link_token("lnk_deadbeef").has_value());
    EXPECT_FALSE(auth->consume_link_token("").has_value());
}

TEST_F(AuthTest, LinkTokenExpiredRejected) {
    auto minted = auth->mint_link_token("owner-user", "ed25519:BBBB",
                                        "customer-owner", std::chrono::seconds{60});
    ASSERT_TRUE(minted.has_value());
    const auto& token = minted->token;
    const auto now = static_cast<uint64_t>(std::time(nullptr));

    auth->set_link_token_clock_for_testing([now] { return now + 61; });
    EXPECT_FALSE(auth->verify_link_token(token).has_value());
    EXPECT_FALSE(auth->consume_link_token(token).has_value());
    // The refused consume spent nothing: on time, the token still works.
    auth->set_link_token_clock_for_testing([now] { return now; });
    EXPECT_TRUE(auth->consume_link_token(token).has_value());
}

// Neither the token nor the code is ever stored: only their domain-separated
// hashes.
TEST_F(AuthTest, LinkTokenLedgerStoresOnlyTheHash) {
    auto minted = auth->mint_link_token("owner-user", "ed25519:AAAA",
                                        "customer-owner", std::chrono::seconds{600});
    ASSERT_TRUE(minted.has_value());
    const auto env = storage->read_file("link_tokens", "ledger.json");
    ASSERT_TRUE(env.has_value());
    EXPECT_EQ(env->data.find(minted->token.substr(4)), std::string::npos);
    EXPECT_NE(env->data.find(auth::link_token_hash_hex(minted->token)), std::string::npos);
    EXPECT_EQ(minted->record.token_hash, auth::link_token_hash_hex(minted->token));
    EXPECT_EQ(env->data.find("\"" + minted->code + "\""), std::string::npos);
    EXPECT_NE(env->data.find(auth::link_code_hash_hex(minted->code)), std::string::npos);
}

namespace {

/// A different code of the same length: the last digit changed.
std::string wrong_code(const std::string& code) {
    auto other = code;
    other.back() = other.back() == '9' ? '0' : static_cast<char>(other.back() + 1);
    return other;
}

}  // namespace

// The code and the token name one invite: whichever is used spends the
// generation, and the other is refused until a refund opens the next one.
TEST_F(AuthTest, AnInviteCodeSpendsTheSameGenerationAsTheToken) {
    auto minted = auth->mint_link_token("owner-user", "ed25519:AAAA", "customer-owner",
                                        std::chrono::seconds{600});
    ASSERT_TRUE(minted.has_value());
    const auto& token = minted->token;
    const auto& code = minted->code;

    EXPECT_TRUE(auth->verify_link_token(code).has_value());
    auto by_code = auth->consume_link_token(code);
    ASSERT_TRUE(by_code.has_value());
    EXPECT_EQ(by_code->generation, 0u);
    EXPECT_EQ(by_code->token_hash, auth::link_token_hash_hex(token));
    EXPECT_EQ(by_code->group_node_id, "customer-owner");
    EXPECT_FALSE(auth->consume_link_token(code).has_value()) << "a code is single use";
    EXPECT_FALSE(auth->consume_link_token(token).has_value()) << "the token shares the spend";
    EXPECT_FALSE(auth->verify_link_token(token).has_value());

    // A refund by code restores the invite for both forms.
    EXPECT_FALSE(auth->refund_link_token(wrong_code(code), *by_code)) << "the record names the code";
    EXPECT_TRUE(auth->refund_link_token(code, *by_code));
    auto by_token = auth->consume_link_token(token);
    ASSERT_TRUE(by_token.has_value());
    EXPECT_EQ(by_token->generation, 1u);
    EXPECT_FALSE(auth->consume_link_token(code).has_value());
    EXPECT_TRUE(auth->refund_link_token(token, *by_token));
    auto again = auth->consume_link_token(code);
    ASSERT_TRUE(again.has_value());
    EXPECT_EQ(again->generation, 2u);
}

// An address that makes kLinkCodeMaxFailuresPerSource wrong code attempts
// within the window has its code attempts refused for the window: right or
// wrong, verify or consume. Other addresses and the token are not affected,
// and the lock ends with the window.
TEST_F(AuthTest, WrongCodeAttemptsLockTheSourceAddress) {
    const auto now = static_cast<uint64_t>(std::time(nullptr));
    auth->set_link_token_clock_for_testing([now] { return now; });
    auto minted = auth->mint_link_token("owner-user", "ed25519:AAAA", "customer-owner",
                                        std::chrono::seconds{600});
    ASSERT_TRUE(minted.has_value());
    const auto bad = wrong_code(minted->code);
    for (uint32_t i = 0; i + 1 < auth::kLinkCodeMaxFailuresPerSource; ++i) {
        EXPECT_FALSE(auth->consume_link_token(bad, "10.0.0.1").has_value());
    }
    EXPECT_TRUE(auth->verify_link_token(minted->code, "10.0.0.1").has_value())
        << "one attempt left; a right code counts nothing";
    EXPECT_FALSE(auth->verify_link_token(bad, "10.0.0.1").has_value()) << "a wrong verify counts";
    EXPECT_FALSE(auth->verify_link_token(minted->code, "10.0.0.1").has_value()) << "locked";
    EXPECT_FALSE(auth->consume_link_token(minted->code, "10.0.0.1").has_value()) << "locked";
    EXPECT_TRUE(auth->verify_link_token(minted->token, "10.0.0.1").has_value())
        << "the token is never locked";
    EXPECT_TRUE(auth->verify_link_token(minted->code, "10.0.0.2").has_value())
        << "another address is not affected";

    // The lock ends with the window, which is as long as a code lives: the
    // locked code is gone by then, and a new one redeems from the address.
    auth->set_link_token_clock_for_testing(
        [now] { return now + auth::kLinkCodeFailureWindowSec; });
    auto later = auth->mint_link_token("owner-user", "ed25519:AAAA", "customer-owner",
                                       std::chrono::seconds{600});
    ASSERT_TRUE(later.has_value());
    EXPECT_FALSE(auth->verify_link_token(minted->code, "10.0.0.2").has_value()) << "expired";
    EXPECT_TRUE(auth->verify_link_token(later->code, "10.0.0.1").has_value());
    EXPECT_FALSE(auth->consume_link_token(wrong_code(later->code), "10.0.0.1").has_value());
    EXPECT_TRUE(auth->consume_link_token(later->code, "10.0.0.1").has_value());
}

// After kLinkCodeMaxFailuresPerServer wrong code attempts from any addresses
// within the window the server refuses every code until the window passes.
// Attempts from a locked address count toward neither limit, so one address
// cannot reach the ceiling.
TEST_F(AuthTest, AServerCeilingOnWrongCodeAttemptsRefusesCodesUntilTheWindowPasses) {
    const auto now = static_cast<uint64_t>(std::time(nullptr));
    auth->set_link_token_clock_for_testing([now] { return now; });
    auto minted = auth->mint_link_token("owner-user", "ed25519:AAAA", "customer-owner",
                                        std::chrono::seconds{600});
    ASSERT_TRUE(minted.has_value());
    const auto bad = wrong_code(minted->code);

    // One address, locked after its share: many more attempts change nothing.
    for (uint32_t i = 0; i < 3 * auth::kLinkCodeMaxFailuresPerServer; ++i) {
        EXPECT_FALSE(auth->consume_link_token(bad, "10.0.0.1").has_value());
    }
    EXPECT_TRUE(auth->verify_link_token(minted->code, "10.0.0.2").has_value())
        << "a locked address does not count toward the server ceiling";

    // Enough addresses reach the ceiling, with one attempt to spare. The
    // first address's share already counts.
    const auto per_source = auth::kLinkCodeMaxFailuresPerSource;
    uint32_t wrong = per_source;
    for (uint32_t addr = 0; wrong + 1 < auth::kLinkCodeMaxFailuresPerServer; ++addr) {
        const auto source = "10.1.0." + std::to_string(addr);
        for (uint32_t i = 0; i < per_source && wrong + 1 < auth::kLinkCodeMaxFailuresPerServer;
             ++i, ++wrong) {
            EXPECT_FALSE(auth->consume_link_token(bad, source).has_value());
        }
    }
    EXPECT_TRUE(auth->verify_link_token(minted->code, "10.0.0.2").has_value())
        << "below the ceiling another address still redeems";
    EXPECT_FALSE(auth->consume_link_token(bad, "10.0.0.3").has_value()) << "the ceiling";
    EXPECT_FALSE(auth->verify_link_token(minted->code, "10.0.0.2").has_value())
        << "every code is refused on this server";
    EXPECT_FALSE(auth->consume_link_token(minted->code, "10.0.0.4").has_value());
    EXPECT_TRUE(auth->verify_link_token(minted->token, "10.0.0.2").has_value())
        << "tokens are never refused by the ceiling";

    // The window passes: codes work again (the earlier code has expired by
    // then; a new one redeems).
    auth->set_link_token_clock_for_testing(
        [now] { return now + auth::kLinkCodeFailureWindowSec; });
    auto later = auth->mint_link_token("owner-user", "ed25519:AAAA", "customer-owner",
                                       std::chrono::seconds{600});
    ASSERT_TRUE(later.has_value());
    EXPECT_TRUE(auth->consume_link_token(later->code, "10.0.0.2").has_value());
}

// A code lives at most kLinkCodeMaxTtlSec; a longer token outlives it. A
// shorter token takes its code with it.
TEST_F(AuthTest, AnInviteCodeExpiresWithItsTokenAndAfterTenMinutesAtMost) {
    const auto now = static_cast<uint64_t>(std::time(nullptr));
    auto hour = auth->mint_link_token("owner-user", "ed25519:AAAA", "customer-owner",
                                      std::chrono::seconds{3600});
    auto minute = auth->mint_link_token("owner-user", "ed25519:AAAA", "customer-owner",
                                        std::chrono::seconds{60});
    ASSERT_TRUE(hour && minute);
    ASSERT_TRUE(hour->record.grant.has_value());
    EXPECT_EQ(auth::link_code_expires_at(*hour->record.grant),
              hour->record.created_at + auth::kLinkCodeMaxTtlSec);
    EXPECT_EQ(auth::link_code_expires_at(*minute->record.grant), minute->record.expires_at);

    auth->set_link_token_clock_for_testing([now] { return now + auth::kLinkCodeMaxTtlSec + 1; });
    EXPECT_FALSE(auth->verify_link_token(hour->code).has_value());
    EXPECT_FALSE(auth->consume_link_token(hour->code).has_value());
    EXPECT_TRUE(auth->verify_link_token(hour->token).has_value());
    EXPECT_FALSE(auth->verify_link_token(minute->code).has_value());
    EXPECT_FALSE(auth->verify_link_token(minute->token).has_value());
    auth->set_link_token_clock_for_testing([now] { return now; });
    EXPECT_TRUE(auth->consume_link_token(hour->code).has_value()) << "nothing was spent";
}

// A token an earlier release minted (one plaintext file named by plain
// SHA-256 of the token) is still redeemed once on this server, and an expired
// one is removed on sight.
TEST_F(AuthTest, LegacyLinkTokenFilesStillRedeem) {
    const auto write_legacy = [&](const std::string& token, uint64_t expires_at) {
        auto hash = crypto->sha256(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(token.data()), token.size()));
        auto path = temp_dir / "link_tokens" /
                    (crypto::to_hex(std::span<const uint8_t>(hash)) + ".json");
        fs::create_directories(path.parent_path());
        std::ofstream ofs(path, std::ios::trunc);
        ofs << nlohmann::json{{"owner_user_id", "owner-user"},
                              {"owner_pubkey", "ed25519:CCCC"},
                              {"group_node_id", "customer-owner"},
                              {"created_at", 1},
                              {"expires_at", expires_at}}
                   .dump();
        return path;
    };
    const auto now = static_cast<uint64_t>(std::time(nullptr));
    write_legacy("lnk_legacy_live", now + 600);
    auto consumed = auth->consume_link_token("lnk_legacy_live");
    ASSERT_TRUE(consumed.has_value());
    EXPECT_TRUE(consumed->token_hash.empty());
    EXPECT_EQ(consumed->group_node_id, "customer-owner");
    EXPECT_FALSE(auth->consume_link_token("lnk_legacy_live").has_value());
    EXPECT_TRUE(auth->refund_link_token("lnk_legacy_live", *consumed));
    EXPECT_TRUE(auth->consume_link_token("lnk_legacy_live").has_value());

    const auto expired = write_legacy("lnk_legacy_old", 1);
    EXPECT_FALSE(auth->consume_link_token("lnk_legacy_old").has_value());
    EXPECT_FALSE(fs::exists(expired));
}

TEST_F(AuthTest, ARefundRestoresTheTokenOnce) {
    auto minted = auth->mint_link_token("owner-user", "ed25519:AAAA",
                                        "customer-owner", std::chrono::seconds{600});
    ASSERT_TRUE(minted.has_value());
    const auto& token = minted->token;
    auto first = auth->consume_link_token(token);
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(first->generation, 0u);
    EXPECT_FALSE(auth->consume_link_token(token).has_value());

    EXPECT_TRUE(auth->refund_link_token(token, *first));
    EXPECT_FALSE(auth->refund_link_token(token, *first)) << "a spend is restored once";
    auto second = auth->consume_link_token(token);
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second->generation, 1u);
    EXPECT_FALSE(auth->refund_link_token("lnk_other", *second)) << "the record names the token";
}

TEST_F(AuthTest, LinkTokensSurviveARestart) {
    auto live = auth->mint_link_token("owner-user", "ed25519:AAAA", "customer-owner",
                                      std::chrono::seconds{600});
    auto spent = auth->mint_link_token("owner-user", "ed25519:AAAA", "customer-owner",
                                       std::chrono::seconds{600});
    ASSERT_TRUE(live && spent);
    ASSERT_TRUE(auth->consume_link_token(spent->token).has_value());

    auth->stop();
    auth = std::make_unique<auth::AuthService>(*storage, *crypto, rp_id, jwt_secret);
    auth->start();
    EXPECT_FALSE(auth->consume_link_token(spent->token).has_value());
    EXPECT_TRUE(auth->consume_link_token(live->token).has_value());
}

TEST_F(AuthTest, AnOwnerHoldsABoundedNumberOfLiveTokens) {
    for (std::size_t i = 0; i < auth::kLinkTokenMaxPerOwner; ++i) {
        ASSERT_TRUE(auth->mint_link_token("busy", "ed25519:AAAA", "customer-busy",
                                          std::chrono::seconds{600})
                        .has_value());
    }
    EXPECT_FALSE(auth->mint_link_token("busy", "ed25519:AAAA", "customer-busy",
                                       std::chrono::seconds{600})
                     .has_value());
    EXPECT_TRUE(auth->mint_link_token("other", "ed25519:BBBB", "customer-other",
                                      std::chrono::seconds{600})
                    .has_value());
}

namespace {

/// Signs link token events the way GossipService::sign_link_token_event does,
/// with a fixed origin key.
struct TestSigner {
    crypto::SodiumCryptoService& crypto;
    crypto::Ed25519Keypair       key;
    uint64_t                     seq = 0;

    std::string origin() const { return crypto::to_base64(key.public_key); }

    bool sign(auth::LinkTokenEvent& e) {
        e.network_id = std::string(64, 'a');
        e.origin_pubkey = origin();
        e.origin_seq = ++seq;
        const auto bytes = auth::link_token_event_signing_bytes(e);
        e.signature = crypto::to_base64(
            crypto.ed25519_sign(key.private_key, std::span<const uint8_t>(bytes)));
        e.code_signature.clear();
        if (!e.code_hash.empty()) {
            const auto binding = auth::link_code_binding_bytes(e);
            e.code_signature = crypto::to_base64(
                crypto.ed25519_sign(key.private_key, std::span<const uint8_t>(binding)));
        }
        return true;
    }

    /// A signed mint from another server, with `code_hash` when given.
    auth::LinkTokenEvent mint(const std::string& token, uint64_t now,
                              const std::string& code_hash = {}) {
        auth::LinkTokenEvent e;
        e.kind = auth::LinkTokenEventKind::Mint;
        e.token_hash = auth::link_token_hash_hex(token);
        e.expires_at = now + 600;
        e.group_node_id = "customer-peer";
        e.permissions = {"read"};
        e.owner_user_id = "peer-owner";
        e.owner_pubkey = "ed25519:PEER";
        e.created_at = now;
        e.timestamp = now;
        e.code_hash = code_hash;
        sign(e);
        return e;
    }
};

}  // namespace

// A mint from a server that issues no codes (an earlier release) redeems by
// token only. Two mints that share a code (minted on two servers in the same
// window) make the code unusable, and both tokens stay redeemable.
TEST_F(AuthTest, MintsWithoutACodeAndMintsThatShareOneRedeemByTokenOnly) {
    TestSigner self{*crypto, crypto->ed25519_keygen()};
    TestSigner peer{*crypto, crypto->ed25519_keygen()};
    auth->set_link_token_replication([&](auth::LinkTokenEvent& e) { return self.sign(e); },
                                     [](const auth::LinkTokenEvent&) -> std::size_t { return 0; });
    const auto now = static_cast<uint64_t>(std::time(nullptr));

    const auto plain = peer.mint("lnk_plain", now);
    ASSERT_TRUE(plain.code_hash.empty());
    ASSERT_TRUE(auth->apply_replicated_link_token(plain));
    EXPECT_TRUE(auth->verify_link_token("lnk_plain").has_value());

    const std::string code = "31415926";
    const auto shared_a = peer.mint("lnk_shared_a", now, auth::link_code_hash_hex(code));
    const auto shared_b = peer.mint("lnk_shared_b", now, auth::link_code_hash_hex(code));
    ASSERT_TRUE(auth->apply_replicated_link_token(shared_a));
    EXPECT_TRUE(auth->verify_link_token(code).has_value()) << "one mint: the code resolves";
    ASSERT_TRUE(auth->apply_replicated_link_token(shared_b));
    EXPECT_FALSE(auth->verify_link_token(code).has_value()) << "two mints: refused, not chosen";
    EXPECT_FALSE(auth->consume_link_token(code).has_value());
    EXPECT_TRUE(auth->consume_link_token("lnk_shared_a").has_value());
    EXPECT_TRUE(auth->consume_link_token("lnk_shared_b").has_value());
    EXPECT_TRUE(auth->consume_link_token("lnk_plain").has_value());

    // A code binding changed after signing does not verify; the gossip
    // receiver drops such a mint before it reaches the provider.
    auto forged = peer.mint("lnk_forged", now, auth::link_code_hash_hex("27182818"));
    EXPECT_TRUE(auth::link_token_event_signature_valid(*crypto, forged));
    forged.code_hash = auth::link_code_hash_hex("16180339");
    EXPECT_FALSE(auth::link_token_event_signature_valid(*crypto, forged));
}

// A refund by a server whose spend does not count never revives the token.
TEST_F(AuthTest, ARefundByTheLosingServerDoesNotRestore) {
    TestSigner self{*crypto, crypto->ed25519_keygen()};
    TestSigner other{*crypto, crypto->ed25519_keygen()};
    while (!(other.origin() < self.origin())) other.key = crypto->ed25519_keygen();
    auth->set_link_token_replication([&](auth::LinkTokenEvent& e) { return self.sign(e); },
                                     [](const auth::LinkTokenEvent&) -> std::size_t { return 0; });
    auto minted = auth->mint_link_token("owner-user", "ed25519:AAAA", "customer-owner",
                                        std::chrono::seconds{600});
    ASSERT_TRUE(minted.has_value());
    auto consumed = auth->consume_link_token(minted->token);
    ASSERT_TRUE(consumed.has_value());

    auth::LinkTokenEvent competing;
    competing.kind = auth::LinkTokenEventKind::Spend;
    competing.token_hash = consumed->token_hash;
    competing.generation = 0;
    competing.expires_at = consumed->expires_at;
    competing.timestamp = consumed->created_at;
    ASSERT_TRUE(other.sign(competing));
    ASSERT_TRUE(auth->apply_replicated_link_token(competing));

    EXPECT_FALSE(auth->refund_link_token(minted->token, *consumed));
    EXPECT_FALSE(auth->consume_link_token(minted->token).has_value());

    // An unsigned or malformed event is never taken from a peer.
    auto unsigned_event = competing;
    unsigned_event.signature.clear();
    unsigned_event.generation = 1;
    EXPECT_FALSE(auth->apply_replicated_link_token(unsigned_event));
    auto malformed = competing;
    malformed.token_hash = "not-hex";
    EXPECT_FALSE(auth->apply_replicated_link_token(malformed));
}

TEST_F(AuthTest, LinkTokenMintRequiresGroup) {
    EXPECT_FALSE(auth->mint_link_token("owner-user", "ed25519:CCCC", "",
                                       std::chrono::seconds{600}).has_value());
}

TEST_F(AuthTest, TokenLinkIsNotStandaloneAuth) {
    nlohmann::json req = {{"method", "token-link"}, {"link_token", "lnk_x"}};
    auto result = auth->authenticate(req);
    EXPECT_FALSE(result.authenticated);
    EXPECT_NE(result.error_message.find("/api/join"), std::string::npos);
}

// --- Ed25519 device revocation ---

namespace {
// Full challenge-response login for `kp`, presenting `pk_str` as the pubkey.
auto ed25519_login_as(auth::AuthService& svc, crypto::SodiumCryptoService& c,
                      const crypto::Ed25519Keypair& kp, const std::string& pk_str) {
    auto challenge_b64 = svc.issue_ed25519_challenge(pk_str)
                            .value("challenge", std::string{});
    auto challenge = crypto::from_base64(challenge_b64);
    auto sig = c.ed25519_sign(kp.private_key, std::span<const uint8_t>(challenge));
    return svc.authenticate({
        {"method",    "ed25519"},
        {"pubkey",    pk_str},
        {"challenge", challenge_b64},
        {"signature", crypto::to_base64(
                          std::span<const uint8_t>(sig.data(), sig.size()))},
    });
}

std::string canonical_b64(const crypto::Ed25519Keypair& kp) {
    return crypto::to_base64(
        std::span<const uint8_t>(kp.public_key.data(), kp.public_key.size()));
}

// Full challenge-response login for `kp` (the only way to obtain a session).
auto ed25519_login(auth::AuthService& svc, crypto::SodiumCryptoService& c,
                   const crypto::Ed25519Keypair& kp) {
    return ed25519_login_as(svc, c, kp, canonical_b64(kp));
}

// The same 32 bytes in url-safe unpadded form. from_base64 accepts both, so an
// exact-string blocklist keyed on the standard form would miss this one.
std::string url_safe_unpadded(const std::string& std_b64) {
    std::string out;
    for (char ch : std_b64) {
        if (ch == '=') continue;
        else if (ch == '+') out.push_back('-');
        else if (ch == '/') out.push_back('_');
        else out.push_back(ch);
    }
    return out;
}
}  // namespace

TEST_F(AuthTest, RevokedKeyCannotAuthenticate) {
    auto kp = crypto->ed25519_keygen();
    auto pk_b64 = crypto::to_base64(
        std::span<const uint8_t>(kp.public_key.data(), kp.public_key.size()));

    ASSERT_TRUE(ed25519_login(*auth, *crypto, kp).authenticated);
    ASSERT_TRUE(auth->revoke_ed25519(pk_b64));

    auto after = ed25519_login(*auth, *crypto, kp);
    EXPECT_FALSE(after.authenticated);
    EXPECT_TRUE(after.session_token.empty());
}

TEST_F(AuthTest, RevokedKeyInvalidatesExistingSession) {
    auto kp = crypto->ed25519_keygen();
    auto pk_b64 = crypto::to_base64(
        std::span<const uint8_t>(kp.public_key.data(), kp.public_key.size()));

    auto login = ed25519_login(*auth, *crypto, kp);
    ASSERT_TRUE(login.authenticated);
    ASSERT_TRUE(auth->validate_session_claims(login.session_token).has_value());

    ASSERT_TRUE(auth->revoke_ed25519(pk_b64));

    // The already-issued JWT must stop validating immediately, not at expiry.
    EXPECT_FALSE(auth->validate_session_claims(login.session_token).has_value());
}

// A revoked key must stay revoked in every textual form it can be presented in.
TEST_F(AuthTest, RevokedKeyCannotReauthenticateUnderAltBase64) {
    auto kp = crypto->ed25519_keygen();
    auto pk_b64 = canonical_b64(kp);
    auto alt    = url_safe_unpadded(pk_b64);
    ASSERT_NE(alt, pk_b64);   // the two encodings really are different strings

    ASSERT_TRUE(ed25519_login(*auth, *crypto, kp).authenticated);
    ASSERT_TRUE(auth->revoke_ed25519(pk_b64));

    auto after = ed25519_login_as(*auth, *crypto, kp, alt);
    EXPECT_FALSE(after.authenticated);
    EXPECT_TRUE(after.session_token.empty());
}

// ...and revoking via the alternate form must block the standard form too.
TEST_F(AuthTest, RevokingAltBase64BlocksCanonicalForm) {
    auto kp = crypto->ed25519_keygen();
    auto pk_b64 = canonical_b64(kp);

    ASSERT_TRUE(ed25519_login(*auth, *crypto, kp).authenticated);
    ASSERT_TRUE(auth->revoke_ed25519(url_safe_unpadded(pk_b64)));

    EXPECT_FALSE(ed25519_login(*auth, *crypto, kp).authenticated);
}

// A session obtained under one encoding dies when the key is revoked under another.
TEST_F(AuthTest, AltBase64SessionDiesOnCanonicalRevoke) {
    auto kp = crypto->ed25519_keygen();
    auto pk_b64 = canonical_b64(kp);

    auto login = ed25519_login_as(*auth, *crypto, kp, url_safe_unpadded(pk_b64));
    ASSERT_TRUE(login.authenticated);
    ASSERT_TRUE(auth->validate_session_claims(login.session_token).has_value());

    ASSERT_TRUE(auth->revoke_ed25519(pk_b64));
    EXPECT_FALSE(auth->validate_session_claims(login.session_token).has_value());
}

// Revoking must scrub the stale identity: the credential file entry and the
// in-memory warm cache, while the blocklist stays authoritative.
TEST_F(AuthTest, RevokeScrubsCredentialFileAndCache) {
    auto kp = crypto->ed25519_keygen();
    auto pk_b64 = canonical_b64(kp);

    auto login = ed25519_login(*auth, *crypto, kp);
    ASSERT_TRUE(login.authenticated);
    auto user_id = login.user_id;

    auto cred_path = temp_dir / "credentials" / (user_id + ".json");
    auto revoked_path = temp_dir / "credentials" / "revoked.json";

    nlohmann::json cred;
    {
        std::ifstream ifs(cred_path);
        ASSERT_TRUE(static_cast<bool>(ifs));
        ifs >> cred;
    }
    auto pubkeys_before = cred.value("ed25519_pubkeys", nlohmann::json::array());
    ASSERT_EQ(pubkeys_before.size(), 1u);
    EXPECT_EQ(pubkeys_before[0].value("pubkey", std::string{}), pk_b64);

    ASSERT_TRUE(auth->revoke_ed25519(pk_b64));

    // The blocklist still lists the key (it stays authoritative).
    nlohmann::json revoked;
    {
        std::ifstream ifs(revoked_path);
        ASSERT_TRUE(static_cast<bool>(ifs));
        ifs >> revoked;
    }
    EXPECT_TRUE(revoked.is_array());
    bool in_blocklist = false;
    for (const auto& e : revoked) {
        if (e == pk_b64) in_blocklist = true;
    }
    EXPECT_TRUE(in_blocklist);

    // The credential file no longer holds the revoked key.
    nlohmann::json scrubbed;
    {
        std::ifstream ifs(cred_path);
        ASSERT_TRUE(static_cast<bool>(ifs));
        ifs >> scrubbed;
    }
    auto arr = scrubbed.value("ed25519_pubkeys", nlohmann::json::array());
    EXPECT_EQ(arr.size(), 0u);
}

// After an un-revoke the key authenticates again, and the credential file is
// rebuilt. If the in-memory pubkey→user map had not been erased on revoke,
// re-login would hit the stale cache entry, skip auto-registration, and the
// scrubbed credential file would still be empty — so this double-checks that
// the cache was scrubbed too.
TEST_F(AuthTest, UnrevokeRestoresAuthentication) {
    auto kp = crypto->ed25519_keygen();
    auto pk_b64 = canonical_b64(kp);

    auto login = ed25519_login(*auth, *crypto, kp);
    ASSERT_TRUE(login.authenticated);
    auto user_id = login.user_id;

    ASSERT_TRUE(auth->revoke_ed25519(pk_b64));
    EXPECT_FALSE(ed25519_login(*auth, *crypto, kp).authenticated);

    ASSERT_TRUE(auth->unrevoke_ed25519(pk_b64));

    auto after = ed25519_login(*auth, *crypto, kp);
    ASSERT_TRUE(after.authenticated);
    EXPECT_EQ(after.user_id, user_id);

    // The blocklist no longer lists the key.
    nlohmann::json revoked;
    {
        std::ifstream ifs(temp_dir / "credentials" / "revoked.json");
        ASSERT_TRUE(static_cast<bool>(ifs));
        ifs >> revoked;
    }
    for (const auto& e : revoked) {
        EXPECT_NE(e, pk_b64);
    }

    // Re-registration rewrote the credential file with the key.
    nlohmann::json cred;
    {
        std::ifstream ifs(temp_dir / "credentials" / (user_id + ".json"));
        ASSERT_TRUE(static_cast<bool>(ifs));
        ifs >> cred;
    }
    bool restored = false;
    for (const auto& e : cred.value("ed25519_pubkeys", nlohmann::json::array())) {
        if (e.value("pubkey", std::string{}) == pk_b64) restored = true;
    }
    EXPECT_TRUE(restored);
}

// Un-revoking a key that was never revoked must fail.
TEST_F(AuthTest, UnrevokeNeverRevokedFails) {
    auto kp = crypto->ed25519_keygen();
    auto pk_b64 = canonical_b64(kp);

    EXPECT_FALSE(auth->unrevoke_ed25519(pk_b64));
    EXPECT_FALSE(auth->unrevoke_ed25519(""));

    // Revoking a different key does not make this one un-revocable-in-reverse.
    auto kp2 = crypto->ed25519_keygen();
    auto pk2 = canonical_b64(kp2);
    ASSERT_TRUE(auth->revoke_ed25519(pk2));
    EXPECT_FALSE(auth->unrevoke_ed25519(pk_b64));
}

// --- Service interface ---

TEST_F(AuthTest, ServiceName) {
    EXPECT_EQ(auth->service_name(), "AuthService");
}
