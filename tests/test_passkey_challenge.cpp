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
#include <functional>
#include <fstream>
#include <span>
#include <string>
#include <thread>
#include <utility>
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

    // Private store access via the fixture (friendship is not inherited by
    // the TEST_F-generated derived class). Works on any provider instance,
    // including a fresh one standing in for a restart.
    static std::optional<auth::StoredCredential>
    lookup(auth::PasskeyAuthProvider& pk, const std::string& credential_id) {
        return pk.lookup_credential(credential_id);
    }

    static std::string issue_for(auth::PasskeyAuthProvider& pk, const std::string& user_id) {
        auto issued = pk.issue_challenge(user_id);
        EXPECT_TRUE(issued.has_value());
        return issued->at("challenge").get<std::string>();
    }

    // Register with a caller-supplied P-256 key (returns the result, no EXPECT).
    static auth::AuthResult register_with_key(auth::PasskeyAuthProvider& pk,
                                              crypto::SodiumCryptoService& c,
                                              const std::string& user_id,
                                              const std::string& credential_id,
                                              EVP_PKEY* pkey) {
        std::vector<uint8_t> x, y;
        p256_coordinates(pkey, x, y);
        return pk.do_register({
            {"user_id", user_id},
            {"credential_id", credential_id},
            {"public_key_x", crypto::to_hex(std::span<const uint8_t>(x))},
            {"public_key_y", crypto::to_hex(std::span<const uint8_t>(y))},
        });
    }

    // Write a user credential file directly (pre-existing on-disk state).
    void seed_credential_file(const std::string& user_id,
                               const std::vector<std::pair<std::string, EVP_PKEY*>>& creds) {
        nlohmann::json file;
        file["user_id"] = user_id;
        file["credentials"] = nlohmann::json::array();
        for (const auto& [cid, pkey] : creds) {
            std::vector<uint8_t> x, y;
            p256_coordinates(pkey, x, y);
            nlohmann::json c;
            c["credential_id"] = cid;
            c["public_key_x"] = crypto::to_hex(std::span<const uint8_t>(x));
            c["public_key_y"] = crypto::to_hex(std::span<const uint8_t>(y));
            c["sign_count"] = 0;
            c["created_at"] = 1;
            file["credentials"].push_back(c);
        }
        fs::create_directories(temp_dir / "credentials");
        std::ofstream ofs(temp_dir / "credentials" / (user_id + ".json"));
        ofs << file.dump(2);
    }

    // Arm the injected persistence failure (friend access).
    void arm_persist_failure() { passkey->test_fail_next_persist_ = true; }

    // Set the pre-mutation test hook (friend access).
    void set_sign_count_hook(std::function<void()> hook) {
        passkey->test_hook_before_sign_count_update_ = std::move(hook);
    }

    nlohmann::json read_user_file(const std::string& user_id) {
        std::ifstream ifs(temp_dir / "credentials" / (user_id + ".json"));
        std::ostringstream ss;
        ss << ifs.rdbuf();
        return nlohmann::json::parse(ss.str());
    }

    static std::string file_bytes(const fs::path& path) {
        std::ifstream ifs(path, std::ios::binary);
        std::ostringstream ss;
        ss << ifs.rdbuf();
        return ss.str();
    }

    // Write a prebuilt credential file (for quarantine fixture data).
    void write_raw_credential_file(const std::string& user_id,
                                   const nlohmann::json& file) {
        fs::create_directories(temp_dir / "credentials");
        std::ofstream ofs(temp_dir / "credentials" / (user_id + ".json"));
        ofs << file.dump(2);
    }

    // Build a credential entry; key == nullptr writes an unreadable key.
    static nlohmann::json cred_entry(const std::string& credential_id,
                                     EVP_PKEY* key) {
        nlohmann::json e;
        e["credential_id"] = credential_id;
        e["sign_count"] = 0;
        e["created_at"] = 1;
        if (key) {
            std::vector<uint8_t> x, y;
            p256_coordinates(key, x, y);
            e["public_key_x"] = nexus::crypto::to_hex(x);
            e["public_key_y"] = nexus::crypto::to_hex(y);
        } else {
            e["public_key_x"] = "zz";
            e["public_key_y"] = "zz";
        }
        return e;
    }
};

// --- Credential ownership conflicts and persistence correctness ---

// Two identities persisted the same credential_id (a pre-fix registration
// race). After restart the id must stay unavailable for authentication AND
// unregistrable by anyone — including both claimants (no silent owner).
TEST_F(PasskeyChallengeTest, ConflictingPersistedIdsUnavailableAfterRestart) {
    auto* ka = generate_p256();
    auto* kb = generate_p256();
    seed_credential_file("alice", {{"cred_shared", ka}});
    seed_credential_file("bob",   {{"cred_shared", kb}});

    // The provider loads on first use and must quarantine the shared id.
    EXPECT_FALSE(lookup(*passkey, "cred_shared").has_value());

    // Re-registration is refused for a third identity...
    auto* kc = generate_p256();
    auto third = register_with_key(*passkey, *crypto, "carol", "cred_shared", kc);
    EXPECT_FALSE(third.authenticated);
    EXPECT_NE(third.error_message.find("conflict"), std::string::npos);

    // ...and for both claimants.
    EXPECT_FALSE(register_with_key(*passkey, *crypto, "alice", "cred_shared", ka).authenticated);
    EXPECT_FALSE(register_with_key(*passkey, *crypto, "bob", "cred_shared", kb).authenticated);

    // Authentication is impossible: the credential is unknown.
    const auto challenge = issue_for(*passkey, "alice");
    auto auth = passkey->do_authenticate(make_assertion_request(
        *crypto, ka, rp_id, "cred_shared", challenge, 1));
    EXPECT_FALSE(auth.authenticated);
    EXPECT_NE(auth.error_message.find("Unknown credential"), std::string::npos);

    EVP_PKEY_free(ka); EVP_PKEY_free(kb); EVP_PKEY_free(kc);
}

// A second identity cannot take over a registered credential, and the
// refusal survives restart.
TEST_F(PasskeyChallengeTest, SecondIdentityCannotTakeOverCredentialAfterRestart) {
    auto* ka = register_credential("alice", "cred_a");
    auto* kb = generate_p256();

    auto reject = register_with_key(*passkey, *crypto, "bob", "cred_a", kb);
    EXPECT_FALSE(reject.authenticated);
    ASSERT_TRUE(lookup(*passkey, "cred_a").has_value());
    EXPECT_EQ(lookup(*passkey, "cred_a")->user_id, "alice");

    // Restart: a fresh provider over the same storage.
    auto passkey2 = std::make_unique<auth::PasskeyAuthProvider>(*storage, *crypto, rp_id, jwt_secret);
    ASSERT_TRUE(lookup(*passkey2, "cred_a").has_value());
    EXPECT_EQ(lookup(*passkey2, "cred_a")->user_id, "alice");
    EXPECT_FALSE(register_with_key(*passkey2, *crypto, "bob", "cred_a", kb).authenticated);

    // Alice still authenticates after the restart.
    const auto challenge = issue_for(*passkey2, "alice");
    auto auth = passkey2->do_authenticate(make_assertion_request(
        *crypto, ka, rp_id, "cred_a", challenge, 1));
    EXPECT_TRUE(auth.authenticated);
    EXPECT_EQ(auth.user_id, "alice");

    EVP_PKEY_free(ka); EVP_PKEY_free(kb);
}

// A failed registration persist must leave no in-memory or on-disk state,
// and must not block the retry.
TEST_F(PasskeyChallengeTest, RegistrationPersistenceFailureLeavesNoState) {
    auto* k = generate_p256();
    arm_persist_failure();
    auto result = register_with_key(*passkey, *crypto, "alice", "cred_fail", k);
    EXPECT_FALSE(result.authenticated);
    EXPECT_FALSE(lookup(*passkey, "cred_fail").has_value());
    EXPECT_FALSE(fs::exists(temp_dir / "credentials" / "alice.json"));

    // No fault left armed: the retry succeeds.
    auto ok = register_with_key(*passkey, *crypto, "alice", "cred_fail", k);
    EXPECT_TRUE(ok.authenticated);
    EVP_PKEY_free(k);
}

// A failed same-owner key rotation must keep the previous key usable: the
// cache is not published over the un-updated file, and the previous file
// state survives a restart.
TEST_F(PasskeyChallengeTest, KeyRotationPersistenceFailureKeepsOldKey) {
    auto* k1 = register_credential("alice", "cred_rot");
    auto* k2 = generate_p256();

    arm_persist_failure();
    auto fail = register_with_key(*passkey, *crypto, "alice", "cred_rot", k2);
    EXPECT_FALSE(fail.authenticated);

    // Old key still in cache and still authenticates; new key does not.
    ASSERT_TRUE(lookup(*passkey, "cred_rot").has_value());
    auto c1 = issue("alice");
    EXPECT_TRUE(passkey->do_authenticate(make_assertion_request(
        *crypto, k1, rp_id, "cred_rot", c1, 1)).authenticated);
    auto c2 = issue("alice");
    EXPECT_FALSE(passkey->do_authenticate(make_assertion_request(
        *crypto, k2, rp_id, "cred_rot", c2, 1)).authenticated);

    // Restart: the file was never overwritten, so the old key still works.
    auto passkey2 = std::make_unique<auth::PasskeyAuthProvider>(*storage, *crypto, rp_id, jwt_secret);
    auto c3 = issue_for(*passkey2, "alice");
    EXPECT_TRUE(passkey2->do_authenticate(make_assertion_request(
        *crypto, k1, rp_id, "cred_rot", c3, 2)).authenticated);

    EVP_PKEY_free(k1); EVP_PKEY_free(k2);
}

// A sign-count advance that cannot be persisted must reject the
// authentication and leave the stored counter unchanged; the same counter
// still advances on the next attempt.
TEST_F(PasskeyChallengeTest, SignCountPersistenceFailureRejectsAuthentication) {
    auto* k = register_credential("alice", "cred_pf");

    auto c1 = issue("alice");
    EXPECT_TRUE(passkey->do_authenticate(make_assertion_request(
        *crypto, k, rp_id, "cred_pf", c1, 1)).authenticated);

    arm_persist_failure();
    auto c2 = issue("alice");
    auto fail = passkey->do_authenticate(make_assertion_request(
        *crypto, k, rp_id, "cred_pf", c2, 2));
    EXPECT_FALSE(fail.authenticated);
    EXPECT_NE(fail.error_message.find("sign count"), std::string::npos);
    ASSERT_TRUE(lookup(*passkey, "cred_pf").has_value());
    EXPECT_EQ(lookup(*passkey, "cred_pf")->sign_count, 1u);

    auto c3 = issue("alice");
    EXPECT_TRUE(passkey->do_authenticate(make_assertion_request(
        *crypto, k, rp_id, "cred_pf", c3, 2)).authenticated);
    EXPECT_EQ(lookup(*passkey, "cred_pf")->sign_count, 2u);

    EVP_PKEY_free(k);
}

// The explicit counter rules: advance accepted and persisted; replay, lower
// counter, and 0-after-nonzero all rejected; a later higher counter accepted.
TEST_F(PasskeyChallengeTest, CounterRegressionRules) {
    auto* k = register_credential("alice", "cred_ctr");

    auto attempt = [&](uint32_t count) {
        auto c = issue("alice");
        return passkey->do_authenticate(make_assertion_request(
            *crypto, k, rp_id, "cred_ctr", c, count));
    };

    EXPECT_TRUE(attempt(5).authenticated);
    EXPECT_EQ(lookup(*passkey, "cred_ctr")->sign_count, 5u);

    auto replay = attempt(5);
    EXPECT_FALSE(replay.authenticated);
    EXPECT_NE(replay.error_message.find("sign count"), std::string::npos);

    auto lower = attempt(4);
    EXPECT_FALSE(lower.authenticated);
    EXPECT_NE(lower.error_message.find("sign count"), std::string::npos);

    // 0 after a nonzero counter is a regression, not a no-counter reset.
    auto zero = attempt(0);
    EXPECT_FALSE(zero.authenticated);
    EXPECT_NE(zero.error_message.find("sign count"), std::string::npos);
    EXPECT_EQ(lookup(*passkey, "cred_ctr")->sign_count, 5u);

    EXPECT_TRUE(attempt(6).authenticated);
    EXPECT_EQ(lookup(*passkey, "cred_ctr")->sign_count, 6u);

    // The advanced counter is on disk, not only in the cache.
    auto file = read_user_file("alice");
    for (const auto& c : file["credentials"]) {
        if (c["credential_id"] == "cred_ctr") {
            EXPECT_EQ(c["sign_count"], 6u);
        }
    }

    EVP_PKEY_free(k);
}

// Competing mutations of the same user file: a registration racing a
// controlled burst of sign-count updates. Both operations start together at
// a barrier, both MUST execute to completion, and both results are asserted —
// the test cannot pass with zero competing counter updates. No update may be
// lost: both credentials and the full counter advance end up in cache and
// file.
TEST_F(PasskeyChallengeTest, ConcurrentRegistrationAndSignCountUpdateNoLostUpdate) {
    auto* k1 = register_credential("alice", "cred_c1");
    auto* k2 = generate_p256();

    // Counter 1 before the race so the file has one advanced entry.
    auto c0 = issue("alice");
    EXPECT_TRUE(passkey->do_authenticate(make_assertion_request(
        *crypto, k1, rp_id, "cred_c1", c0, 1)).authenticated);

    constexpr uint32_t kUpdates = 8;
    std::barrier sync{2};
    std::atomic<bool> reg_ok{false};
    std::atomic<uint32_t> counter_updates{0};

    std::thread registrar([&] {
        sync.arrive_and_wait();
        reg_ok = register_with_key(*passkey, *crypto, "alice", "cred_c2", k2)
                     .authenticated;
    });
    std::thread authenticator([&] {
        sync.arrive_and_wait();
        for (uint32_t i = 2; i <= 1 + kUpdates; ++i) {
            auto c = issue("alice");
            if (passkey->do_authenticate(make_assertion_request(
                    *crypto, k1, rp_id, "cred_c1", c, i)).authenticated) {
                counter_updates++;
            }
        }
    });
    registrar.join();
    authenticator.join();

    // Both operations actually executed.
    EXPECT_TRUE(reg_ok.load());
    EXPECT_EQ(counter_updates.load(), kUpdates);

    ASSERT_TRUE(lookup(*passkey, "cred_c1").has_value());
    ASSERT_TRUE(lookup(*passkey, "cred_c2").has_value());
    const auto cached_count = lookup(*passkey, "cred_c1")->sign_count;
    EXPECT_EQ(cached_count, 1u + kUpdates);

    // The file must agree with the cache: no lost update from the race.
    auto file = read_user_file("alice");
    bool has_c1 = false, has_c2 = false;
    for (const auto& c : file["credentials"]) {
        if (c["credential_id"] == "cred_c1") {
            has_c1 = true;
            EXPECT_EQ(c["sign_count"], 1u + kUpdates);
        }
        if (c["credential_id"] == "cred_c2") has_c2 = true;
    }
    EXPECT_TRUE(has_c1);
    EXPECT_TRUE(has_c2);

    EVP_PKEY_free(k1); EVP_PKEY_free(k2);
}

// Deterministic mutation-boundary regression: authentication verifies the
// OLD key, the credential is then replaced (same ID, same owner, new key),
// and the mutation boundary must see the change and refuse — no session,
// no counter change to the replacement credential.
TEST_F(PasskeyChallengeTest, CredentialChangedDuringAuthenticationRejected) {
    auto* k1 = register_credential("alice", "cred_swap");
    auto* k2 = generate_p256();
    const auto challenge = issue("alice");
    auto request = make_assertion_request(
        *crypto, k1, rp_id, "cred_swap", challenge, /*sign_count=*/1);

    // Pause between signature verification and the sign-count mutation;
    // complete the same-ID key replacement while paused.
    set_sign_count_hook([this, k2] {
        auto swapped = register_with_key(*passkey, *crypto, "alice", "cred_swap", k2);
        EXPECT_TRUE(swapped.authenticated);
    });
    auto result = passkey->do_authenticate(request);
    set_sign_count_hook(nullptr);

    EXPECT_FALSE(result.authenticated);
    EXPECT_TRUE(result.session_token.empty());
    EXPECT_NE(result.error_message.find("sign count"), std::string::npos);

    // The replacement credential is untouched: new key, counter unchanged.
    ASSERT_TRUE(lookup(*passkey, "cred_swap").has_value());
    EXPECT_EQ(lookup(*passkey, "cred_swap")->sign_count, 0u);
    std::vector<uint8_t> x2, y2;
    p256_coordinates(k2, x2, y2);
    EXPECT_EQ(lookup(*passkey, "cred_swap")->public_key_x, x2);
    EXPECT_EQ(lookup(*passkey, "cred_swap")->public_key_y, y2);

    // The replacement remains healthy, and the old key is dead.
    auto c2 = issue("alice");
    EXPECT_TRUE(passkey->do_authenticate(make_assertion_request(
        *crypto, k2, rp_id, "cred_swap", c2, 1)).authenticated);
    EXPECT_EQ(lookup(*passkey, "cred_swap")->sign_count, 1u);
    auto c3 = issue("alice");
    EXPECT_FALSE(passkey->do_authenticate(make_assertion_request(
        *crypto, k1, rp_id, "cred_swap", c3, 2)).authenticated);

    EVP_PKEY_free(k1); EVP_PKEY_free(k2);
}

// An existing credential file that cannot be read or parsed must refuse the
// mutation without being replaced: no loss of the other credentials, no
// cache change, and the file is byte-identical after the refusal.
TEST_F(PasskeyChallengeTest, InvalidExistingCredentialFileRefusesMutation) {
    register_credential("alice", "keep_1");
    register_credential("alice", "keep_2");

    const auto path = temp_dir / "credentials" / "alice.json";
    const auto original = file_bytes(path);
    ASSERT_FALSE(original.empty());
    {
        std::ofstream ofs(path, std::ios::trunc | std::ios::binary);
        ofs << "\x01\x02not json";
    }
    const auto corrupted = file_bytes(path);
    ASSERT_NE(corrupted, original);

    auto* k = generate_p256();
    // Same-owner update of an existing id: refused...
    EXPECT_FALSE(register_with_key(*passkey, *crypto, "alice", "keep_1", k).authenticated);
    // ...as is a brand-new id for the same user.
    EXPECT_FALSE(register_with_key(*passkey, *crypto, "alice", "keep_3", k).authenticated);

    // The file is byte-identical to the corrupted state: a refused mutation
    // must not reset it (which would drop keep_2) or "repair" it silently.
    EXPECT_EQ(file_bytes(path), corrupted);
    // The cache is unchanged too.
    EXPECT_TRUE(lookup(*passkey, "keep_1").has_value());
    EXPECT_TRUE(lookup(*passkey, "keep_2").has_value());
    EXPECT_FALSE(lookup(*passkey, "keep_3").has_value());
    EVP_PKEY_free(k);
}

// An existing file with a structurally invalid "credentials" field must be
// refused, not silently reset to an array.
TEST_F(PasskeyChallengeTest, InvalidCredentialsArrayRefusesMutation) {
    register_credential("alice", "keep_1");

    const auto path = temp_dir / "credentials" / "alice.json";
    {
        std::ofstream ofs(path, std::ios::trunc);
        ofs << R"({"user_id":"alice","credentials":{"bogus":true}})";
    }
    const auto before = file_bytes(path);

    auto* k = generate_p256();
    EXPECT_FALSE(register_with_key(*passkey, *crypto, "alice", "keep_1", k).authenticated);
    EXPECT_FALSE(register_with_key(*passkey, *crypto, "alice", "keep_9", k).authenticated);
    EXPECT_EQ(file_bytes(path), before);
    EVP_PKEY_free(k);
}

// Startup load with one corrupt file: the store is degraded, so NO
// registration is authorized (absence of ownership cannot be assumed), even
// for identities with perfectly readable files. Authentication of readable
// credentials is unaffected.
TEST_F(PasskeyChallengeTest, DegradedStoreRefusesRegistrationAtStartup) {
    auto* ka = generate_p256();
    seed_credential_file("alice", {{"cred_a_ok", ka}});
    {
        std::ofstream ofs(temp_dir / "credentials" / "carol.json",
                          std::ios::trunc | std::ios::binary);
        ofs << "\xff\xfe garbage";
    }

    // First use loads the store: alice's file is fine, carol's is not.
    EXPECT_TRUE(lookup(*passkey, "cred_a_ok").has_value());

    auto* kb = generate_p256();
    auto res = register_with_key(*passkey, *crypto, "bob", "cred_b_new", kb);
    EXPECT_FALSE(res.authenticated);
    EXPECT_NE(res.error_message.find("degraded"), std::string::npos);

    // Even the healthy identity cannot register on an assumed absence.
    auto res2 = register_with_key(*passkey, *crypto, "alice", "cred_a2", ka);
    EXPECT_FALSE(res2.authenticated);

    // Readable credentials still authenticate (no over-refusal).
    const auto c = issue("alice");
    EXPECT_TRUE(passkey->do_authenticate(make_assertion_request(
        *crypto, ka, rp_id, "cred_a_ok", c, 1)).authenticated);

    EVP_PKEY_free(ka); EVP_PKEY_free(kb);
}

// A single credential entry with an unusable key inside an otherwise valid
// file: that credential_id's ownership is indeterminate, so it is quarantined
// exactly like a cross-identity conflict; the valid entries still load.
TEST_F(PasskeyChallengeTest, UnreadableCredentialEntryQuarantined) {
    auto* ka = generate_p256();
    nlohmann::json file;
    file["user_id"] = "alice";
    file["credentials"] = nlohmann::json::array();
    {
        std::vector<uint8_t> x, y;
        p256_coordinates(ka, x, y);
        file["credentials"].push_back({
            {"credential_id", "cred_ok"},
            {"public_key_x", crypto::to_hex(std::span<const uint8_t>(x))},
            {"public_key_y", crypto::to_hex(std::span<const uint8_t>(y))},
            {"sign_count", 0}, {"created_at", 1},
        });
    }
    file["credentials"].push_back({
        {"credential_id", "cred_badkey"},
        {"public_key_x", "zz"}, {"public_key_y", "zz"},
        {"sign_count", 0}, {"created_at", 1},
    });
    fs::create_directories(temp_dir / "credentials");
    {
        std::ofstream ofs(temp_dir / "credentials" / "alice.json");
        ofs << file.dump(2);
    }

    EXPECT_TRUE(lookup(*passkey, "cred_ok").has_value());
    EXPECT_FALSE(lookup(*passkey, "cred_badkey").has_value());

    // Nobody — including the file's own identity — may register the id.
    auto* kb = generate_p256();
    auto res = register_with_key(*passkey, *crypto, "bob", "cred_badkey", kb);
    EXPECT_FALSE(res.authenticated);
    EXPECT_NE(res.error_message.find("conflict"), std::string::npos);
    auto res2 = register_with_key(*passkey, *crypto, "alice", "cred_badkey", kb);
    EXPECT_FALSE(res2.authenticated);

    EVP_PKEY_free(ka); EVP_PKEY_free(kb);
}

// An invalid-key entry quarantines a credential_id. A VALID entry for the
// same id persisted under a DIFFERENT identity file must not lift the
// quarantine: lookup and authentication reject the id, registration stays
// refused, and unrelated valid credentials keep working.
TEST_F(PasskeyChallengeTest, QuarantinedIdValidDuplicateAcrossFilesRefused) {
    auto* ka = generate_p256();  // alice's valid cred_shared key
    auto* kc = generate_p256();  // carol's unrelated credential

    nlohmann::json carol;
    carol["user_id"] = "carol";
    carol["credentials"] = nlohmann::json::array();
    carol["credentials"].push_back(cred_entry("cred_shared", nullptr));
    carol["credentials"].push_back(cred_entry("cred_carol_ok", kc));
    write_raw_credential_file("carol", carol);

    nlohmann::json alice;
    alice["user_id"] = "alice";
    alice["credentials"] = nlohmann::json::array();
    alice["credentials"].push_back(cred_entry("cred_shared", ka));
    write_raw_credential_file("alice", alice);

    // The valid duplicate does not clear the quarantine.
    EXPECT_FALSE(lookup(*passkey, "cred_shared").has_value());
    // An unrelated valid entry in the quarantining file still loads.
    EXPECT_TRUE(lookup(*passkey, "cred_carol_ok").has_value());

    // Registration of the shared id remains refused.
    auto res = register_with_key(*passkey, *crypto, "bob", "cred_shared", kc);
    EXPECT_FALSE(res.authenticated);
    EXPECT_NE(res.error_message.find("conflict"), std::string::npos);

    // Even a correctly signed assertion cannot authenticate the id.
    const auto c = issue("alice");
    EXPECT_FALSE(passkey->do_authenticate(make_assertion_request(
        *crypto, ka, rp_id, "cred_shared", c, 1)).authenticated);

    // The unrelated valid credential still authenticates.
    const auto c2 = issue("carol");
    EXPECT_TRUE(passkey->do_authenticate(make_assertion_request(
        *crypto, kc, rp_id, "cred_carol_ok", c2, 1)).authenticated);

    EVP_PKEY_free(ka); EVP_PKEY_free(kc);
}

// Same regression within ONE file: a valid entry and an invalid entry share
// a credential_id; the id must stay quarantined.
TEST_F(PasskeyChallengeTest, QuarantinedIdValidDuplicateSameFileRefused) {
    auto* ka = generate_p256();  // valid key for cred_shared
    auto* kb = generate_p256();  // unrelated credential

    nlohmann::json alice;
    alice["user_id"] = "alice";
    alice["credentials"] = nlohmann::json::array();
    alice["credentials"].push_back(cred_entry("cred_shared", nullptr));
    alice["credentials"].push_back(cred_entry("cred_shared", ka));
    alice["credentials"].push_back(cred_entry("cred_alice_ok", kb));
    write_raw_credential_file("alice", alice);

    EXPECT_FALSE(lookup(*passkey, "cred_shared").has_value());
    EXPECT_TRUE(lookup(*passkey, "cred_alice_ok").has_value());

    auto res = register_with_key(*passkey, *crypto, "bob", "cred_shared", kb);
    EXPECT_FALSE(res.authenticated);
    EXPECT_NE(res.error_message.find("conflict"), std::string::npos);

    const auto c = issue("alice");
    EXPECT_FALSE(passkey->do_authenticate(make_assertion_request(
        *crypto, ka, rp_id, "cred_shared", c, 1)).authenticated);

    const auto c2 = issue("alice");
    EXPECT_TRUE(passkey->do_authenticate(make_assertion_request(
        *crypto, kb, rp_id, "cred_alice_ok", c2, 1)).authenticated);

    EVP_PKEY_free(ka); EVP_PKEY_free(kb);
}

// Both entry orders, each loaded by a FRESH provider over the same
// directory (a restart). The quarantine must not depend on entry order or
// on which provider instance happened to see the file first.
TEST_F(PasskeyChallengeTest, QuarantinedIdBothOrdersAndFreshProviderRestart) {
    auto* ka = generate_p256();  // valid key for cred_shared
    auto* kb = generate_p256();  // unrelated credential

    const auto run_case = [&](bool invalid_first) {
        fs::remove_all(temp_dir / "credentials");
        nlohmann::json file;
        file["user_id"] = "alice";
        file["credentials"] = nlohmann::json::array();
        if (invalid_first) {
            file["credentials"].push_back(cred_entry("cred_shared", nullptr));
            file["credentials"].push_back(cred_entry("cred_shared", ka));
        } else {
            file["credentials"].push_back(cred_entry("cred_shared", ka));
            file["credentials"].push_back(cred_entry("cred_shared", nullptr));
        }
        file["credentials"].push_back(cred_entry("cred_alice_ok", kb));
        write_raw_credential_file("alice", file);

        // A fresh provider over the same directory: a restart.
        storage::FileStorageService storage2(temp_dir);
        storage2.start();
        auto provider2 = std::make_unique<auth::PasskeyAuthProvider>(
            storage2, *crypto, rp_id, jwt_secret);

        EXPECT_FALSE(lookup(*provider2, "cred_shared").has_value());
        EXPECT_TRUE(lookup(*provider2, "cred_alice_ok").has_value());

        std::vector<uint8_t> xb, yb;
        p256_coordinates(kb, xb, yb);
        auto res = provider2->do_register({
            {"user_id", "bob"}, {"credential_id", "cred_shared"},
            {"public_key_x", nexus::crypto::to_hex(xb)},
            {"public_key_y", nexus::crypto::to_hex(yb)},
        });
        EXPECT_FALSE(res.authenticated);
        EXPECT_NE(res.error_message.find("conflict"), std::string::npos);
        EXPECT_FALSE(lookup(*provider2, "cred_shared").has_value());

        auto ch = provider2->issue_challenge("alice");
        ASSERT_TRUE(ch.has_value());
        EXPECT_FALSE(provider2->do_authenticate(make_assertion_request(
            *crypto, ka, rp_id, "cred_shared", ch->at("challenge").get<std::string>(), 1))
            .authenticated);

        auto ch2 = provider2->issue_challenge("alice");
        ASSERT_TRUE(ch2.has_value());
        EXPECT_TRUE(provider2->do_authenticate(make_assertion_request(
            *crypto, kb, rp_id, "cred_alice_ok", ch2->at("challenge").get<std::string>(), 1))
            .authenticated);

        provider2 = nullptr;
        storage2.stop();
    };

    run_case(true);
    run_case(false);

    EVP_PKEY_free(ka); EVP_PKEY_free(kb);
}

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

// ============================================================================
// Credential ownership: one credential_id belongs to at most one identity.
// ============================================================================

namespace {

// Write a credential file directly, simulating persisted state.
void write_credential_file(const fs::path& root, const std::string& user_id,
                           const std::vector<std::string>& credential_ids,
                           crypto::SodiumCryptoService& c) {
    nlohmann::json creds = nlohmann::json::array();
    for (const auto& id : credential_ids) {
        std::array<uint8_t, 32> x{};
        std::array<uint8_t, 32> y{};
        c.random_bytes(std::span<uint8_t>(x));
        c.random_bytes(std::span<uint8_t>(y));
        creds.push_back({
            {"credential_id", id},
            {"public_key_x", crypto::to_hex(std::span<const uint8_t>(x))},
            {"public_key_y", crypto::to_hex(std::span<const uint8_t>(y))},
            {"sign_count", 0},
            {"created_at", 1},
        });
    }
    auto dir = root / "credentials";
    fs::create_directories(dir);
    std::ofstream ofs(dir / (user_id + ".json"), std::ios::trunc);
    ofs << nlohmann::json{{"user_id", user_id}, {"credentials", creds}}.dump(2);
}

}  // namespace

TEST_F(PasskeyChallengeTest, SecondUserCannotTakeExistingCredentialId) {
    auto* pkey = register_credential("alice", "cred_x");

    auto* pkey_b = generate_p256();
    std::vector<uint8_t> xb, yb;
    p256_coordinates(pkey_b, xb, yb);
    auto rejected = passkey->do_register({
        {"user_id", "bob"},
        {"credential_id", "cred_x"},
        {"public_key_x", crypto::to_hex(xb)},
        {"public_key_y", crypto::to_hex(yb)},
    });
    EXPECT_FALSE(rejected.authenticated);
    EXPECT_NE(rejected.error_message.find("owned"), std::string::npos);

    // The original owner still authenticates as the original user, and the
    // rejected registration wrote nothing for the second user.
    auto issued = auth->issue_passkey_challenge("alice");
    ASSERT_TRUE(issued.has_value());
    auto result = auth->authenticate(make_assertion_request(
        *crypto, pkey, rp_id, "cred_x", issued->at("challenge").get<std::string>(), 1));
    EXPECT_TRUE(result.authenticated);
    EXPECT_EQ(result.user_id, "alice");
    EXPECT_FALSE(fs::exists(temp_dir / "credentials" / "bob.json"));
    EVP_PKEY_free(pkey_b);
}

TEST_F(PasskeyChallengeTest, ConflictingOwnershipSurvivesRestart) {
    auto* pkey = register_credential("alice", "cred_x");

    auto* pkey_b = generate_p256();
    std::vector<uint8_t> xb, yb;
    p256_coordinates(pkey_b, xb, yb);
    auto rejected = passkey->do_register({
        {"user_id", "bob"},
        {"credential_id", "cred_x"},
        {"public_key_x", crypto::to_hex(xb)},
        {"public_key_y", crypto::to_hex(yb)},
    });
    EXPECT_FALSE(rejected.authenticated);
    EVP_PKEY_free(pkey_b);

    // Restart: fresh provider + service over the same persisted storage.
    auto auth2 = std::make_unique<auth::AuthService>(*storage, *crypto, rp_id, jwt_secret);
    auth2->start();
    auto issued = auth2->issue_passkey_challenge("alice");
    ASSERT_TRUE(issued.has_value());
    auto result = auth2->authenticate(make_assertion_request(
        *crypto, pkey, rp_id, "cred_x", issued->at("challenge").get<std::string>(), 1));
    EXPECT_TRUE(result.authenticated);
    EXPECT_EQ(result.user_id, "alice");
}

TEST_F(PasskeyChallengeTest, ConcurrentConflictingRegistrationsSingleOwner) {
    auto* pkey_a = generate_p256();
    auto* pkey_b = generate_p256();
    std::vector<uint8_t> xa, ya, xb, yb;
    p256_coordinates(pkey_a, xa, ya);
    p256_coordinates(pkey_b, xb, yb);

    bool ok_a = false;
    bool ok_b = false;
    std::barrier sync(2);
    std::thread ta([&] {
        sync.arrive_and_wait();
        ok_a = passkey->do_register({
            {"user_id", "alice"},
            {"credential_id", "cred_race"},
            {"public_key_x", crypto::to_hex(xa)},
            {"public_key_y", crypto::to_hex(ya)},
        }).authenticated;
    });
    std::thread tb([&] {
        sync.arrive_and_wait();
        ok_b = passkey->do_register({
            {"user_id", "bob"},
            {"credential_id", "cred_race"},
            {"public_key_x", crypto::to_hex(xb)},
            {"public_key_y", crypto::to_hex(yb)},
        }).authenticated;
    });
    ta.join();
    tb.join();

    // Exactly one registration may win; both succeeding is the bug.
    EXPECT_EQ(static_cast<int>(ok_a) + static_cast<int>(ok_b), 1);

    EVP_PKEY* owner_pkey = ok_a ? pkey_a : pkey_b;
    const char* owner = ok_a ? "alice" : "bob";
    const char* loser = ok_a ? "bob" : "alice";

    auto loaded = lookup(*passkey, "cred_race");
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->user_id, owner);
    EXPECT_FALSE(fs::exists(temp_dir / "credentials" / (std::string(loser) + ".json")));

    // The winner authenticates as the winner.
    auto issued = auth->issue_passkey_challenge(owner);
    ASSERT_TRUE(issued.has_value());
    auto result = auth->authenticate(make_assertion_request(
        *crypto, owner_pkey, rp_id, "cred_race", issued->at("challenge").get<std::string>(), 1));
    EXPECT_TRUE(result.authenticated);
    EXPECT_EQ(result.user_id, owner);
    EVP_PKEY_free(pkey_a);
    EVP_PKEY_free(pkey_b);
}

TEST_F(PasskeyChallengeTest, RestartRefusesConflictingPersistedEntries) {
    // Pre-fix corruption: the same credential_id persisted under two users.
    write_credential_file(temp_dir, "alice", {"cred_dup", "cred_alice_only"}, *crypto);
    write_credential_file(temp_dir, "bob", {"cred_dup", "cred_bob_only"}, *crypto);

    // Fresh provider over the same storage must not pick an owner from the
    // conflicting entries; non-conflicting entries still load.
    // Fresh provider over the same storage = a restart. It must not pick an
    // owner from the conflicting entries; non-conflicting entries load.
    auto passkey2 = std::make_unique<auth::PasskeyAuthProvider>(*storage, *crypto, rp_id, jwt_secret);
    EXPECT_FALSE(lookup(*passkey2, "cred_dup").has_value());

    auto alice_cred = lookup(*passkey2, "cred_alice_only");
    ASSERT_TRUE(alice_cred.has_value());
    EXPECT_EQ(alice_cred->user_id, "alice");
    auto bob_cred = lookup(*passkey2, "cred_bob_only");
    ASSERT_TRUE(bob_cred.has_value());
    EXPECT_EQ(bob_cred->user_id, "bob");
}
