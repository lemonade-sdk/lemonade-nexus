// WebAuthn assertion challenge verification: server-issued, user-bound,
// expiring (monotonic clock), single-use, capacity-bounded — including
// concurrent replay of one challenge and the explicit consume-before-sign
// behavior.

#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/PasskeyAuthProvider.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <gtest/gtest.h>

#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <barrier>
#include <chrono>
#include <cstring>
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

// WebAuthn transmits base64url without padding; the server compares decoded
// bytes, so encode in the url form to exercise that path.
std::string b64url(const std::vector<uint8_t>& bytes) {
    std::string out = crypto::to_base64(std::span<const uint8_t>(bytes));
    for (auto& ch : out) {
        if (ch == '+') ch = '-';
        else if (ch == '/') ch = '_';
    }
    out.erase(std::remove(out.begin(), out.end(), '='), out.end());
    return out;
}

std::vector<uint8_t> decode_challenge(const std::string& encoded) {
    std::string b64 = encoded;
    std::replace(b64.begin(), b64.end(), '-', '+');
    std::replace(b64.begin(), b64.end(), '_', '/');
    while (b64.size() % 4 != 0) b64.push_back('=');
    return crypto::from_base64(b64);
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

// A complete assertion request: authenticator_data = SHA-256(rp_id) | UP flag
// | sign count, signed over authenticator_data || SHA-256(clientDataJSON).
nlohmann::json make_assertion_request(crypto::SodiumCryptoService& c,
                                      EVP_PKEY* pkey,
                                      const std::string& rp_id,
                                      const std::string& credential_id,
                                      const std::string& challenge_encoded,
                                      uint32_t sign_count,
                                      bool include_challenge = true,
                                      std::string type = "webauthn.get",
                                      std::string origin = "") {
    if (origin.empty()) origin = rp_id;

    std::vector<uint8_t> auth_data = sha256(c, rp_id);
    auth_data.push_back(0x01);  // user-present
    auth_data.push_back(static_cast<uint8_t>(sign_count >> 24));
    auth_data.push_back(static_cast<uint8_t>(sign_count >> 16));
    auth_data.push_back(static_cast<uint8_t>(sign_count >> 8));
    auth_data.push_back(static_cast<uint8_t>(sign_count));

    nlohmann::json cdj = {{"type", type}, {"origin", origin}};
    if (include_challenge) cdj["challenge"] = challenge_encoded;
    auto cdj_dump = cdj.dump();
    auto cdj_bytes = std::vector<uint8_t>(cdj_dump.begin(), cdj_dump.end());

    std::vector<uint8_t> signed_data = auth_data;
    auto cdj_hash = c.sha256(std::span<const uint8_t>(cdj_bytes));
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

class PasskeyChallengeTest : public ::testing::Test {
protected:
    fs::path temp_dir;
    std::unique_ptr<crypto::SodiumCryptoService> crypto;
    std::unique_ptr<storage::FileStorageService> storage;
    std::unique_ptr<auth::PasskeyAuthProvider> passkey;
    std::unique_ptr<auth::AuthService> auth;

    std::string rp_id = "lemonade-nexus.local";
    std::string jwt_secret;

    void SetUp() override {
        temp_dir = fs::temp_directory_path() / ("nexus_test_passkey_ch_" + std::to_string(getpid()));
        fs::create_directories(temp_dir);

        crypto = std::make_unique<crypto::SodiumCryptoService>();
        crypto->start();
        std::array<uint8_t, 32> secret{};
        crypto->random_bytes(std::span<uint8_t>(secret));
        jwt_secret = crypto::to_hex(std::span<const uint8_t>(secret));

        storage = std::make_unique<storage::FileStorageService>(temp_dir);
        storage->start();
        passkey = std::make_unique<auth::PasskeyAuthProvider>(*storage, *crypto, rp_id, jwt_secret);
        auth = std::make_unique<auth::AuthService>(*storage, *crypto, rp_id, jwt_secret);
        auth->start();
    }

    void TearDown() override {
        auth->stop();
        storage->stop();
        crypto->stop();
        fs::remove_all(temp_dir);
    }

    // Register a credential for `user_id` and return the signing key.
    EVP_PKEY* register_credential(const std::string& user_id, const std::string& credential_id) {
        auto* pkey = generate_p256();
        std::vector<uint8_t> x, y;
        p256_coordinates(pkey, x, y);
        auto result = passkey->do_register({
            {"user_id", user_id},
            {"credential_id", credential_id},
            {"public_key_x", crypto::to_hex(x)},
            {"public_key_y", crypto::to_hex(y)},
        });
        EXPECT_TRUE(result.authenticated);
        return pkey;
    }

    // Issue and return the encoded challenge (friend access to the store).
    std::string issue(const std::string& user_id) {
        auto issued = passkey->issue_challenge(user_id);
        EXPECT_TRUE(issued.has_value());
        return issued->at("challenge").get<std::string>();
    }

    // Store population helpers live in the friend class itself: friendship
    // is not inherited by the TEST_F-generated derived class.
    void populate_pending_table(bool expired) {
        std::lock_guard lock(passkey->challenge_mutex_);
        passkey->pending_challenges_.clear();
        const auto deadline = expired
            ? std::chrono::steady_clock::now() - std::chrono::seconds(1)
            : std::chrono::steady_clock::now() + std::chrono::seconds(60);
        for (std::size_t i = 0; i < auth::PasskeyAuthProvider::kMaxPendingChallenges; ++i) {
            passkey->pending_challenges_["live_" + std::to_string(i)] =
                auth::PasskeyAuthProvider::PendingChallenge{"user", deadline};
        }
    }

    void expire_pending_entries(std::size_t n) {
        std::lock_guard lock(passkey->challenge_mutex_);
        const auto past = std::chrono::steady_clock::now() - std::chrono::seconds(1);
        for (std::size_t i = 0; i < n; ++i) {
            passkey->pending_challenges_["live_" + std::to_string(i)].deadline = past;
        }
    }

    // Rewind the stored deadline so the challenge reads as expired.
    void expire(const std::string& challenge_encoded) {
        auto bytes = decode_challenge(challenge_encoded);
        auto key = crypto::to_base64(std::span<const uint8_t>(bytes));
        auto& entry = passkey->pending_challenges_.at(key);
        entry.deadline = std::chrono::steady_clock::now() - std::chrono::seconds(1);
    }
};

TEST_F(PasskeyChallengeTest, IssuedChallengeIsCanonicalBase64Url) {
    auto encoded = issue("alice");
    EXPECT_EQ(encoded.find('+'), std::string::npos);
    EXPECT_EQ(encoded.find('/'), std::string::npos);
    EXPECT_EQ(encoded.find('='), std::string::npos);
    EXPECT_EQ(decode_challenge(encoded).size(), 32u);
}

TEST_F(PasskeyChallengeTest, IssueThenAuthenticateSucceeds) {
    auto* pkey = register_credential("alice", "cred_alice");
    auto issued = passkey->issue_challenge("alice");
    ASSERT_TRUE(issued.has_value());
    ASSERT_GT(issued->value("expires_at", 0), 0);

    auto result = passkey->do_authenticate(make_assertion_request(
        *crypto, pkey, rp_id, "cred_alice", issued->at("challenge").get<std::string>(), 1));
    EXPECT_TRUE(result.authenticated);
    EXPECT_EQ(result.user_id, "alice");
    EXPECT_FALSE(result.session_token.empty());
    EVP_PKEY_free(pkey);
}

TEST_F(PasskeyChallengeTest, MissingChallengeRejected) {
    auto* pkey = register_credential("alice", "cred_alice");
    auto result = passkey->do_authenticate(make_assertion_request(
        *crypto, pkey, rp_id, "cred_alice", "", 1, /*include_challenge=*/false));
    EXPECT_FALSE(result.authenticated);
    EXPECT_NE(result.error_message.find("challenge"), std::string::npos);
    EVP_PKEY_free(pkey);
}

TEST_F(PasskeyChallengeTest, UnissuedChallengeRejected) {
    auto* pkey = register_credential("alice", "cred_alice");
    std::array<uint8_t, 32> forged{};
    for (auto& b : forged) b = 0x42;
    auto result = passkey->do_authenticate(make_assertion_request(
        *crypto, pkey, rp_id, "cred_alice", crypto::to_base64(forged), 1));
    EXPECT_FALSE(result.authenticated);
    EXPECT_NE(result.error_message.find("challenge"), std::string::npos);
    EVP_PKEY_free(pkey);
}

TEST_F(PasskeyChallengeTest, MalformedChallengeEncodingRejected) {
    auto* pkey = register_credential("alice", "cred_alice");
    // 17 chars: inside the encoded-length bound, invalid base64.
    auto result = passkey->do_authenticate(make_assertion_request(
        *crypto, pkey, rp_id, "cred_alice", "!!!not-base64!!!", 1));
    EXPECT_FALSE(result.authenticated);
    EXPECT_NE(result.error_message.find("challenge"), std::string::npos);
    EVP_PKEY_free(pkey);
}

TEST_F(PasskeyChallengeTest, WrongLengthChallengeRejected) {
    auto* pkey = register_credential("alice", "cred_alice");
    std::array<uint8_t, 16> short_nonce{};
    for (auto& b : short_nonce) b = 0x7;
    auto result = passkey->do_authenticate(make_assertion_request(
        *crypto, pkey, rp_id, "cred_alice",
        b64url({short_nonce.begin(), short_nonce.end()}), 1));
    EXPECT_FALSE(result.authenticated);
    EXPECT_NE(result.error_message.find("challenge"), std::string::npos);
    EVP_PKEY_free(pkey);
}

TEST_F(PasskeyChallengeTest, OversizedChallengeStringRejected) {
    auto* pkey = register_credential("alice", "cred_alice");
    // Valid base64 alphabet, far beyond any 32-byte encoding.
    std::string huge(256, 'A');
    auto result = passkey->do_authenticate(
        make_assertion_request(*crypto, pkey, rp_id, "cred_alice", huge, 1));
    EXPECT_FALSE(result.authenticated);
    EXPECT_NE(result.error_message.find("challenge"), std::string::npos);
    EVP_PKEY_free(pkey);
}

TEST_F(PasskeyChallengeTest, SameBytesDifferentEncodingAccepted) {
    // The server compares decoded bytes, not the encoding: the issued
    // unpadded base64url nonce presented as standard padded base64 must pass.
    auto* pkey = register_credential("alice", "cred_alice");
    const auto issued = issue("alice");
    auto bytes = decode_challenge(issued);
    const auto standard_padded = crypto::to_base64(std::span<const uint8_t>(bytes));
    ASSERT_NE(issued, standard_padded);

    auto result = passkey->do_authenticate(make_assertion_request(
        *crypto, pkey, rp_id, "cred_alice", standard_padded, 1));
    EXPECT_TRUE(result.authenticated);
    EXPECT_EQ(result.user_id, "alice");
    EVP_PKEY_free(pkey);
}

TEST_F(PasskeyChallengeTest, ExpiredChallengeRejected) {
    auto* pkey = register_credential("alice", "cred_alice");
    const auto challenge = issue("alice");
    expire(challenge);  // monotonic deadline rewound; no sleep

    auto result = passkey->do_authenticate(make_assertion_request(
        *crypto, pkey, rp_id, "cred_alice", challenge, 1));
    EXPECT_FALSE(result.authenticated);
    EXPECT_NE(result.error_message.find("challenge"), std::string::npos);
    EVP_PKEY_free(pkey);
}

// Single-use semantics with nonzero counters (the sign-count tests below
// cover counter behavior; these use counters 1 and 2 deliberately).
TEST_F(PasskeyChallengeTest, ChallengeIsSingleUse) {
    auto* pkey = register_credential("alice", "cred_alice");
    const auto challenge = issue("alice");

    EXPECT_TRUE(passkey->do_authenticate(
        make_assertion_request(*crypto, pkey, rp_id, "cred_alice", challenge, 1)).authenticated);

    // Same challenge, fresh valid signature, higher sign count: the
    // assertion itself is fine, only the challenge is spent.
    auto replay = passkey->do_authenticate(
        make_assertion_request(*crypto, pkey, rp_id, "cred_alice", challenge, 2));
    EXPECT_FALSE(replay.authenticated);
    EXPECT_NE(replay.error_message.find("challenge"), std::string::npos);
    EVP_PKEY_free(pkey);
}

// Counter 1 was just stored, so a fresh challenge presented with the OLD
// counter 1 must fail the sign-count check, not the challenge check: proof
// the counter advanced independently of the challenge gate.
TEST_F(PasskeyChallengeTest, StaleNonZeroCounterRejectedOnFreshChallenge) {
    auto* pkey = register_credential("alice", "cred_alice");
    const auto c1 = issue("alice");
    EXPECT_TRUE(passkey->do_authenticate(
        make_assertion_request(*crypto, pkey, rp_id, "cred_alice", c1, 1)).authenticated);

    const auto c2 = issue("alice");
    auto stale = passkey->do_authenticate(
        make_assertion_request(*crypto, pkey, rp_id, "cred_alice", c2, /*sign_count=*/1));
    EXPECT_FALSE(stale.authenticated);
    EXPECT_NE(stale.error_message.find("sign count"), std::string::npos);
    EVP_PKEY_free(pkey);
}

// sign_count 0 is allowed by the monotonicity rule (0 is non-informative),
// so a counter-0 assertion's replay protection comes from the single-use
// challenge. Sequential: first login succeeds, an exact replay fails on the
// spent challenge, and a fresh challenge with counter 0 succeeds again.
TEST_F(PasskeyChallengeTest, ZeroCounterSequentialReplay) {
    auto* pkey = register_credential("alice", "cred_alice");

    const auto c1 = issue("alice");
    auto first = passkey->do_authenticate(make_assertion_request(
        *crypto, pkey, rp_id, "cred_alice", c1, /*sign_count=*/0));
    EXPECT_TRUE(first.authenticated);

    auto replay = passkey->do_authenticate(make_assertion_request(
        *crypto, pkey, rp_id, "cred_alice", c1, /*sign_count=*/0));
    EXPECT_FALSE(replay.authenticated);
    EXPECT_NE(replay.error_message.find("challenge"), std::string::npos);

    const auto c2 = issue("alice");
    auto fresh = passkey->do_authenticate(make_assertion_request(
        *crypto, pkey, rp_id, "cred_alice", c2, /*sign_count=*/0));
    EXPECT_TRUE(fresh.authenticated);
    EVP_PKEY_free(pkey);
}

// Concurrent submission of one identical counter-0 assertion, with
// synchronized thread starts: exactly one submission may win the single-use
// challenge. A fresh challenge with counter 0 must then authenticate.
TEST_F(PasskeyChallengeTest, ZeroCounterConcurrentSubmissionSucceedsExactlyOnce) {
    auto* pkey = register_credential("alice", "cred_alice");
    const auto challenge = issue("alice");
    auto request = make_assertion_request(
        *crypto, pkey, rp_id, "cred_alice", challenge, /*sign_count=*/0);

    constexpr int kThreads = 8;
    std::atomic<int> successes{0};
    std::barrier sync_point{kThreads};
    std::vector<std::thread> workers;
    workers.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        workers.emplace_back([&] {
            sync_point.arrive_and_wait();  // start together
            if (passkey->do_authenticate(request).authenticated) successes++;
        });
    }
    for (auto& w : workers) w.join();

    EXPECT_EQ(successes.load(), 1);

    const auto fresh = issue("alice");
    auto after = passkey->do_authenticate(make_assertion_request(
        *crypto, pkey, rp_id, "cred_alice", fresh, /*sign_count=*/0));
    EXPECT_TRUE(after.authenticated);
    EVP_PKEY_free(pkey);
}

TEST_F(PasskeyChallengeTest, ChallengeBoundToIssuedUser) {
    auto* bob = register_credential("bob", "cred_bob");
    auto* alice = register_credential("alice", "cred_alice");
    const auto challenge = issue("alice");

    // Bob's credential cannot spend a challenge issued for alice...
    auto cross_user = passkey->do_authenticate(
        make_assertion_request(*crypto, bob, rp_id, "cred_bob", challenge, 1));
    EXPECT_FALSE(cross_user.authenticated);
    EXPECT_NE(cross_user.error_message.find("challenge"), std::string::npos);

    // ...and the refusal must not have burned it for the bound user.
    auto legit = passkey->do_authenticate(
        make_assertion_request(*crypto, alice, rp_id, "cred_alice", challenge, 1));
    EXPECT_TRUE(legit.authenticated);
    EXPECT_EQ(legit.user_id, "alice");
    EVP_PKEY_free(bob);
    EVP_PKEY_free(alice);
}

TEST_F(PasskeyChallengeTest, ConcurrentReplaySucceedsExactlyOnce) {
    auto* pkey = register_credential("alice", "cred_alice");
    const auto challenge = issue("alice");
    auto request = make_assertion_request(*crypto, pkey, rp_id, "cred_alice", challenge, 1);

    constexpr int kThreads = 8;
    std::atomic<int> successes{0};
    std::vector<std::thread> workers;
    workers.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        workers.emplace_back([&] {
            if (passkey->do_authenticate(request).authenticated) successes++;
        });
    }
    for (auto& w : workers) w.join();

    EXPECT_EQ(successes.load(), 1);

    // The winner's counter (1) must now be stored, so the original counter
    // is refused on a fresh challenge (sign-count gate, not challenge gate).
    const auto fresh = issue("alice");
    auto stale = passkey->do_authenticate(
        make_assertion_request(*crypto, pkey, rp_id, "cred_alice", fresh, /*sign_count=*/1));
    EXPECT_FALSE(stale.authenticated);
    EXPECT_NE(stale.error_message.find("sign count"), std::string::npos);
    EVP_PKEY_free(pkey);
}

// Explicit behavior: the challenge is consumed before signature
// verification, so a failed assertion still spends it.
TEST_F(PasskeyChallengeTest, FailedAssertionConsumesChallenge) {
    auto* alice = register_credential("alice", "cred_alice");
    auto* other = generate_p256();
    const auto challenge = issue("alice");

    // Valid challenge, signature by a key that does not own the credential.
    auto forged = passkey->do_authenticate(make_assertion_request(
        *crypto, other, rp_id, "cred_alice", challenge, 1));
    EXPECT_FALSE(forged.authenticated);
    EXPECT_NE(forged.error_message.find("signature"), std::string::npos);

    // The correct assertion now fails on the consumed challenge, not the
    // signature.
    auto late = passkey->do_authenticate(
        make_assertion_request(*crypto, alice, rp_id, "cred_alice", challenge, 1));
    EXPECT_FALSE(late.authenticated);
    EXPECT_NE(late.error_message.find("challenge"), std::string::npos);
    EVP_PKEY_free(alice);
    EVP_PKEY_free(other);
}

TEST_F(PasskeyChallengeTest, TypeAndOriginStillEnforced) {
    auto* pkey = register_credential("alice", "cred_alice");

    auto wrong_type = passkey->do_authenticate(make_assertion_request(
        *crypto, pkey, rp_id, "cred_alice", issue("alice"), 1, true,
        /*type=*/"webauthn.create"));
    EXPECT_FALSE(wrong_type.authenticated);

    auto wrong_origin = passkey->do_authenticate(make_assertion_request(
        *crypto, pkey, rp_id, "cred_alice", issue("alice"), 1, true,
        /*type=*/"webauthn.get", /*origin=*/"https://evil.example"));
    EXPECT_FALSE(wrong_origin.authenticated);
    EVP_PKEY_free(pkey);
}

TEST_F(PasskeyChallengeTest, CapacityExhaustionRefusesIssuance) {
    // Fill the table with live (unexpired) entries: eviction cannot help.
    populate_pending_table(/*expired=*/false);
    EXPECT_FALSE(passkey->issue_challenge("alice").has_value());

    // Expire some entries: eviction brings the table under the cap and
    // issuance succeeds again.
    expire_pending_entries(5);
    EXPECT_TRUE(passkey->issue_challenge("alice").has_value());
}

TEST_F(PasskeyChallengeTest, IssuanceRejectsInvalidUserIds) {
    EXPECT_FALSE(passkey->issue_challenge("").has_value());
    EXPECT_FALSE(passkey->issue_challenge(std::string(129, 'u')).has_value());
    EXPECT_TRUE(passkey->issue_challenge(std::string(128, 'u')).has_value());
}

TEST_F(PasskeyChallengeTest, ChallengeIssuedThroughAuthService) {
    auto* pkey = register_credential("alice", "cred_alice");
    auto issued = auth->issue_passkey_challenge("alice");
    ASSERT_TRUE(issued.has_value());
    ASSERT_FALSE(issued->value("challenge", std::string{}).empty());

    auto result = auth->authenticate(make_assertion_request(
        *crypto, pkey, rp_id, "cred_alice", issued->at("challenge").get<std::string>(), 1));
    EXPECT_TRUE(result.authenticated);
    EXPECT_EQ(result.user_id, "alice");
    EVP_PKEY_free(pkey);
}
