// The per-user identity store (lnsdk::IdentityStore and the ln_identity_user_*
// C ABI). An in-memory keystore stands in for the OS keystore, and the store
// directory is a temporary directory, so no test touches the real user
// store. One test exercises the platform backend of this host in a temporary
// directory: on a host without a keystore it must refuse and write nothing.

#include <LemonadeNexusSDK/lemonade_nexus.h>

#include <LemonadeNexusSDK/Identity.hpp>
#include <LemonadeNexusSDK/IdentityStore.hpp>

#include <LemonadeNexus/Crypto/SecureBuffer.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <new>
#include <string>
#include <vector>

#ifndef _WIN32
#include <sys/stat.h>
#endif

namespace fs = std::filesystem;
using nlohmann::json;
using lnsdk::Identity;
using lnsdk::IdentityStore;
using lnsdk::KeystoreBackend;
using lnsdk::KeystoreStatus;
using lnsdk::StoreResult;

namespace {

/// In-memory keystore. Failure modes are set by the test.
class FakeKeystore final : public KeystoreBackend {
public:
    bool is_available{true};
    KeystoreStatus put_result{KeystoreStatus::Ok};
    KeystoreStatus get_result{KeystoreStatus::Ok};
    std::map<std::string, std::vector<uint8_t>> items;

    std::string name() const override { return "fake"; }
    bool available() const override { return is_available; }

    KeystoreStatus put(std::span<const uint8_t> kek, const std::string& pubkey_b64,
                       json& kek_ref) override {
        if (!is_available) return KeystoreStatus::Unavailable;
        if (put_result != KeystoreStatus::Ok) return put_result;
        const std::string ref = "kek:" + pubkey_b64;
        items[ref].assign(kek.begin(), kek.end());
        kek_ref = ref;
        return KeystoreStatus::Ok;
    }

    KeystoreStatus get(const json& kek_ref, nexus::crypto::SecureBuffer& kek) override {
        if (!is_available) return KeystoreStatus::Unavailable;
        if (get_result != KeystoreStatus::Ok) return get_result;
        if (!kek_ref.is_string()) return KeystoreStatus::NotFound;
        const auto it = items.find(kek_ref.get<std::string>());
        if (it == items.end()) return KeystoreStatus::NotFound;
        kek = nexus::crypto::SecureBuffer(std::span<const uint8_t>(it->second));
        return KeystoreStatus::Ok;
    }

    KeystoreStatus remove(const json& kek_ref) override {
        if (!is_available) return KeystoreStatus::Unavailable;
        if (!kek_ref.is_string()) return KeystoreStatus::NotFound;
        return items.erase(kek_ref.get<std::string>()) ? KeystoreStatus::Ok : KeystoreStatus::NotFound;
    }

    /// Replace every stored key with a different one.
    void corrupt_all() {
        for (auto& [ref, kek] : items) {
            for (auto& byte : kek) byte ^= 0x5a;
        }
    }
};

std::string read_text(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void write_text(const fs::path& path, const std::string& text) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << text;
}

json take_json(char* out) {
    auto parsed = json::parse(out ? out : "null", nullptr, false);
    ln_free(out);
    return parsed;
}

std::string take_str(char* out) {
    std::string s = out ? out : "";
    ln_free(out);
    return s;
}

std::string utf8(const fs::path& path) {
    const auto u8 = path.u8string();
    return std::string(u8.begin(), u8.end());
}

struct IdentityHandle {
    ln_identity_t* id{nullptr};
    explicit IdentityHandle(ln_identity_t* p = nullptr) : id(p) {}
    ~IdentityHandle() { ln_identity_destroy(id); }
    IdentityHandle(const IdentityHandle&) = delete;
    IdentityHandle& operator=(const IdentityHandle&) = delete;
};

std::string pubkey_of(ln_identity_t* id) {
    return take_str(ln_identity_pubkey(id));
}

std::vector<uint8_t> sign_probe(const Identity& id) {
    static const uint8_t message[] = "identity store probe";
    return id.sign(std::span<const uint8_t>(message, sizeof message - 1));
}

bool contains_bytes(std::span<const unsigned char> haystack, std::span<const uint8_t> needle) {
    return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end()) != haystack.end();
}

#ifndef _WIN32
mode_t mode_of(const fs::path& path) {
    struct stat st {};
    EXPECT_EQ(::stat(path.c_str(), &st), 0);
    return st.st_mode & 0777;
}
#endif

class SdkIdentityStoreTest : public ::testing::Test {
protected:
    fs::path root;
    fs::path dir;
    std::shared_ptr<FakeKeystore> keystore = std::make_shared<FakeKeystore>();
    std::unique_ptr<IdentityStore> store;
    std::unique_ptr<IdentityStore::ScopedOverride> override_;

    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        root = fs::temp_directory_path() /
               ("nexus_sdk_identity_store_" +
                std::to_string(::testing::UnitTest::GetInstance()->random_seed()) + "_" +
                std::to_string(reinterpret_cast<uintptr_t>(this)));
        fs::create_directories(root);
        dir = root / "identity";  // the store creates this one
        store = std::make_unique<IdentityStore>(dir, keystore);
        override_ = std::make_unique<IdentityStore::ScopedOverride>(dir, keystore);
    }

    void TearDown() override {
        override_.reset();
        std::error_code ec;
        fs::remove_all(root, ec);
    }

    fs::path file() const { return dir / IdentityStore::kFileName; }
};

}  // namespace

TEST_F(SdkIdentityStoreTest, CreateThenLoadRoundTrips) {
    Identity created;
    ASSERT_EQ(store->create(created), StoreResult::Ok);
    ASSERT_TRUE(created.is_valid());
    ASSERT_TRUE(fs::exists(file()));
    EXPECT_EQ(keystore->items.size(), 1u);

    Identity loaded;
    ASSERT_EQ(store->load(loaded), StoreResult::Ok);
    EXPECT_EQ(loaded.pubkey_string(), created.pubkey_string());
    EXPECT_EQ(loaded.private_key(), created.private_key());
    EXPECT_EQ(sign_probe(loaded), sign_probe(created));

#ifndef _WIN32
    EXPECT_EQ(mode_of(dir), 0700u);
    EXPECT_EQ(mode_of(file()), 0600u);
#endif

    // The file carries the public key and ciphertext only.
    const std::string text = read_text(file());
    const json j = json::parse(text);
    EXPECT_EQ(j.at("v").get<int>(), 2);
    EXPECT_EQ(j.at("backend").get<std::string>(), "fake");
    EXPECT_EQ(j.at("public_key").get<std::string>(), Identity::to_base64(created.public_key()));
    EXPECT_TRUE(j.at("wrapped_seed").contains("nonce"));
    EXPECT_TRUE(j.at("wrapped_seed").contains("ct"));
    EXPECT_FALSE(j.contains("seed"));
    EXPECT_FALSE(j.contains("private_key"));
    EXPECT_EQ(text.find(Identity::to_base64(created.seed())), std::string::npos);
    EXPECT_EQ(text.find(Identity::to_base64(created.private_key())), std::string::npos);
    for (const auto& [ref, kek] : keystore->items) {
        EXPECT_EQ(text.find(Identity::to_base64(kek)), std::string::npos);
    }

    // The same store through the C ABI.
    ln_error_t err = LN_ERR_INTERNAL;
    IdentityHandle via_abi(ln_identity_user_load(&err));
    ASSERT_EQ(err, LN_OK);
    ASSERT_NE(via_abi.id, nullptr);
    EXPECT_EQ(pubkey_of(via_abi.id), created.pubkey_string());
    EXPECT_EQ(take_str(ln_identity_user_dir()), utf8(dir));
}

TEST_F(SdkIdentityStoreTest, StatusCarriesNoSecretFields) {
    char* out = nullptr;
    ASSERT_EQ(ln_identity_user_status(&out), LN_OK);
    json before = take_json(out);
    EXPECT_FALSE(before.at("present").get<bool>());
    EXPECT_FALSE(before.at("unlocked").get<bool>());
    EXPECT_EQ(before.at("backend").get<std::string>(), "fake");
    EXPECT_FALSE(before.contains("public_key"));

    ln_error_t err = LN_ERR_INTERNAL;
    IdentityHandle created(ln_identity_user_create(&err));
    ASSERT_EQ(err, LN_OK);
    ASSERT_NE(created.id, nullptr);

    ASSERT_EQ(ln_identity_user_status(&out), LN_OK);
    const std::string raw = take_str(out);
    json after = json::parse(raw);
    EXPECT_TRUE(after.at("present").get<bool>());
    EXPECT_TRUE(after.at("unlocked").get<bool>());
    EXPECT_EQ(after.at("public_key").get<std::string>(), pubkey_of(created.id));
    EXPECT_EQ(after.at("dir").get<std::string>(), utf8(dir));
    for (const char* forbidden : {"seed", "private_key", "ct", "kek", "kek_ref", "nonce", "wrapped_seed"}) {
        EXPECT_FALSE(after.contains(forbidden)) << forbidden;
        EXPECT_EQ(raw.find(forbidden), std::string::npos) << forbidden;
    }
    for (const auto& [ref, kek] : keystore->items) {
        EXPECT_EQ(raw.find(Identity::to_base64(kek)), std::string::npos);
    }

    // Status via the C++ class says the same.
    const auto status = store->status();
    EXPECT_TRUE(status.present);
    EXPECT_TRUE(status.unlocked);
    EXPECT_EQ(status.public_key, pubkey_of(created.id));
}

TEST_F(SdkIdentityStoreTest, CreateRefusesWhenPresent) {
    Identity first;
    ASSERT_EQ(store->create(first), StoreResult::Ok);
    const std::string text = read_text(file());

    Identity second;
    EXPECT_EQ(store->create(second), StoreResult::Exists);
    EXPECT_FALSE(second.is_valid());

    ln_error_t err = LN_OK;
    IdentityHandle via_abi(ln_identity_user_create(&err));
    EXPECT_EQ(via_abi.id, nullptr);
    EXPECT_EQ(err, LN_ERR_REJECTED);

    EXPECT_EQ(read_text(file()), text);
    EXPECT_EQ(keystore->items.size(), 1u);
}

TEST_F(SdkIdentityStoreTest, ImportStoresOnceAndRefusesOverwrite) {
    Identity migrated;
    migrated.generate();
    ASSERT_EQ(store->import(migrated), StoreResult::Ok);

    Identity loaded;
    ASSERT_EQ(store->load(loaded), StoreResult::Ok);
    EXPECT_EQ(loaded.private_key(), migrated.private_key());

    Identity other;
    other.generate();
    EXPECT_EQ(store->import(other), StoreResult::Exists);
    IdentityHandle other_abi(ln_identity_generate());
    EXPECT_EQ(ln_identity_user_import(other_abi.id), LN_ERR_REJECTED);
    EXPECT_EQ(keystore->items.size(), 1u);

    Identity still;
    ASSERT_EQ(store->load(still), StoreResult::Ok);
    EXPECT_EQ(still.private_key(), migrated.private_key());

    Identity invalid;
    EXPECT_EQ(store->import(invalid), StoreResult::Invalid);
}

TEST_F(SdkIdentityStoreTest, TamperedFileFails) {
    Identity created;
    ASSERT_EQ(store->create(created), StoreResult::Ok);
    const std::string original = read_text(file());

    // One flipped ciphertext byte.
    json j = json::parse(original);
    auto ct = Identity::from_base64(j["wrapped_seed"]["ct"].get<std::string>());
    ct[ct.size() / 2] ^= 0x01;
    j["wrapped_seed"]["ct"] = Identity::to_base64(ct);
    write_text(file(), j.dump());
    Identity loaded;
    EXPECT_EQ(store->load(loaded), StoreResult::Invalid);
    EXPECT_FALSE(loaded.is_valid());
    ln_error_t err = LN_OK;
    IdentityHandle via_abi(ln_identity_user_load(&err));
    EXPECT_EQ(via_abi.id, nullptr);
    EXPECT_EQ(err, LN_ERR_REJECTED);

    // A substituted public key does not match the wrapped seed.
    j = json::parse(original);
    Identity other;
    other.generate();
    j["public_key"] = Identity::to_base64(other.public_key());
    write_text(file(), j.dump());
    EXPECT_EQ(store->load(loaded), StoreResult::Invalid);

    // A different nonce.
    j = json::parse(original);
    auto nonce = Identity::from_base64(j["wrapped_seed"]["nonce"].get<std::string>());
    nonce[0] ^= 0x80;
    j["wrapped_seed"]["nonce"] = Identity::to_base64(nonce);
    write_text(file(), j.dump());
    EXPECT_EQ(store->load(loaded), StoreResult::Invalid);

    // Not the current format.
    j = json::parse(original);
    j["v"] = 1;
    write_text(file(), j.dump());
    EXPECT_EQ(store->load(loaded), StoreResult::Invalid);

    write_text(file(), "not json");
    EXPECT_EQ(store->load(loaded), StoreResult::Invalid);

    write_text(file(), original);
    EXPECT_EQ(store->load(loaded), StoreResult::Ok);
}

TEST_F(SdkIdentityStoreTest, WrongKekFails) {
    Identity created;
    ASSERT_EQ(store->create(created), StoreResult::Ok);
    keystore->corrupt_all();
    Identity loaded;
    EXPECT_EQ(store->load(loaded), StoreResult::Invalid);
    EXPECT_FALSE(loaded.is_valid());
    EXPECT_FALSE(store->status().unlocked);
}

TEST_F(SdkIdentityStoreTest, MissingKeystoreItemFails) {
    Identity created;
    ASSERT_EQ(store->create(created), StoreResult::Ok);
    keystore->items.clear();
    Identity loaded;
    EXPECT_EQ(store->load(loaded), StoreResult::Invalid);
    ln_error_t err = LN_OK;
    IdentityHandle via_abi(ln_identity_user_load(&err));
    EXPECT_EQ(via_abi.id, nullptr);
    EXPECT_EQ(err, LN_ERR_REJECTED);
}

TEST_F(SdkIdentityStoreTest, FileWrappedForAnotherBackendIsUnsupported) {
    Identity created;
    ASSERT_EQ(store->create(created), StoreResult::Ok);
    json j = json::parse(read_text(file()));
    j["backend"] = "keychain";
    write_text(file(), j.dump());
    Identity loaded;
    EXPECT_EQ(store->load(loaded), StoreResult::Unsupported);
}

TEST_F(SdkIdentityStoreTest, RemoveClearsFileAndKeystoreItem) {
    Identity created;
    ASSERT_EQ(store->create(created), StoreResult::Ok);
    ASSERT_EQ(keystore->items.size(), 1u);

    EXPECT_EQ(ln_identity_user_remove(), LN_OK);
    EXPECT_FALSE(fs::exists(file()));
    EXPECT_TRUE(keystore->items.empty());

    EXPECT_EQ(ln_identity_user_remove(), LN_ERR_NOT_FOUND);
    EXPECT_EQ(store->remove(), StoreResult::NotFound);

    char* out = nullptr;
    ASSERT_EQ(ln_identity_user_status(&out), LN_OK);
    EXPECT_FALSE(take_json(out).at("present").get<bool>());

    // A new identity can be created afterwards.
    Identity next;
    ASSERT_EQ(store->create(next), StoreResult::Ok);
    EXPECT_NE(next.pubkey_string(), created.pubkey_string());
}

TEST_F(SdkIdentityStoreTest, RemoveKeepsFileWhenKeystoreRefuses) {
    Identity created;
    ASSERT_EQ(store->create(created), StoreResult::Ok);
    // The fake refuses removals while unavailable items are simulated via a
    // backend that reports Denied for every operation except put.
    struct Denying final : KeystoreBackend {
        std::shared_ptr<FakeKeystore> inner;
        explicit Denying(std::shared_ptr<FakeKeystore> i) : inner(std::move(i)) {}
        std::string name() const override { return inner->name(); }
        bool available() const override { return true; }
        KeystoreStatus put(std::span<const uint8_t> k, const std::string& p, json& r) override {
            return inner->put(k, p, r);
        }
        KeystoreStatus get(const json&, nexus::crypto::SecureBuffer&) override { return KeystoreStatus::Denied; }
        KeystoreStatus remove(const json&) override { return KeystoreStatus::Denied; }
    };
    IdentityStore denying(dir, std::make_shared<Denying>(keystore));
    EXPECT_EQ(denying.remove(), StoreResult::Denied);
    EXPECT_TRUE(fs::exists(file()));
    EXPECT_EQ(keystore->items.size(), 1u);
    Identity loaded;
    EXPECT_EQ(denying.load(loaded), StoreResult::Denied);
}

TEST_F(SdkIdentityStoreTest, UnavailableBackendIsUnsupportedAndWritesNothing) {
    keystore->is_available = false;

    Identity created;
    EXPECT_EQ(store->create(created), StoreResult::Unsupported);
    EXPECT_FALSE(created.is_valid());
    Identity migrated;
    migrated.generate();
    EXPECT_EQ(store->import(migrated), StoreResult::Unsupported);

    ln_error_t err = LN_OK;
    IdentityHandle via_abi(ln_identity_user_create(&err));
    EXPECT_EQ(via_abi.id, nullptr);
    EXPECT_EQ(err, LN_ERR_UNSUPPORTED);
    IdentityHandle to_import(ln_identity_generate());
    EXPECT_EQ(ln_identity_user_import(to_import.id), LN_ERR_UNSUPPORTED);

    EXPECT_FALSE(fs::exists(dir)) << "nothing is written without a keystore";
    EXPECT_TRUE(keystore->items.empty());

    char* out = nullptr;
    ASSERT_EQ(ln_identity_user_status(&out), LN_OK);
    const json status = take_json(out);
    EXPECT_EQ(status.at("backend").get<std::string>(), "none");
    EXPECT_FALSE(status.at("present").get<bool>());

    // A file that exists cannot be served either.
    keystore->is_available = true;
    ASSERT_EQ(store->create(created), StoreResult::Ok);
    keystore->is_available = false;
    Identity loaded;
    EXPECT_EQ(store->load(loaded), StoreResult::Unsupported);
    IdentityHandle loaded_abi(ln_identity_user_load(&err));
    EXPECT_EQ(loaded_abi.id, nullptr);
    EXPECT_EQ(err, LN_ERR_UNSUPPORTED);
}

TEST_F(SdkIdentityStoreTest, DeniedKeystoreIsAuth) {
    keystore->put_result = KeystoreStatus::Denied;
    Identity created;
    EXPECT_EQ(store->create(created), StoreResult::Denied);
    EXPECT_FALSE(fs::exists(file()));
    ln_error_t err = LN_OK;
    IdentityHandle via_abi(ln_identity_user_create(&err));
    EXPECT_EQ(via_abi.id, nullptr);
    EXPECT_EQ(err, LN_ERR_AUTH);

    keystore->put_result = KeystoreStatus::Ok;
    ASSERT_EQ(store->create(created), StoreResult::Ok);
    keystore->get_result = KeystoreStatus::Denied;
    Identity loaded;
    EXPECT_EQ(store->load(loaded), StoreResult::Denied);
    IdentityHandle loaded_abi(ln_identity_user_load(&err));
    EXPECT_EQ(loaded_abi.id, nullptr);
    EXPECT_EQ(err, LN_ERR_AUTH);
    const auto status = store->status();
    EXPECT_TRUE(status.present);
    EXPECT_FALSE(status.unlocked);
}

TEST_F(SdkIdentityStoreTest, LoadWithoutFileIsNotFound) {
    Identity loaded;
    EXPECT_EQ(store->load(loaded), StoreResult::NotFound);
    ln_error_t err = LN_OK;
    IdentityHandle via_abi(ln_identity_user_load(&err));
    EXPECT_EQ(via_abi.id, nullptr);
    EXPECT_EQ(err, LN_ERR_NOT_FOUND);
    EXPECT_EQ(ln_identity_user_load(nullptr), nullptr) << "out_err may be NULL";
}

TEST_F(SdkIdentityStoreTest, FromJsonEqualsFileLoad) {
    Identity id;
    id.generate();
    const fs::path path = root / "identity.json";
    ASSERT_TRUE(id.save(path));
    const std::string text = read_text(path);

    IdentityHandle from_file(ln_identity_load(utf8(path).c_str()));
    IdentityHandle from_json(ln_identity_from_json(text.c_str()));
    ASSERT_NE(from_file.id, nullptr);
    ASSERT_NE(from_json.id, nullptr);
    EXPECT_EQ(pubkey_of(from_json.id), pubkey_of(from_file.id));
    EXPECT_EQ(pubkey_of(from_json.id), id.pubkey_string());

    // Same private key: the two produce the same deterministic signature.
    Identity parsed;
    ASSERT_TRUE(parsed.from_json_text(text));
    EXPECT_EQ(sign_probe(parsed), sign_probe(id));

    // Importing the parsed identity stores that key.
    EXPECT_EQ(ln_identity_user_import(from_json.id), LN_OK);
    Identity loaded;
    ASSERT_EQ(store->load(loaded), StoreResult::Ok);
    EXPECT_EQ(loaded.private_key(), id.private_key());

    EXPECT_EQ(ln_identity_from_json("{\"public_key\":\"\"}"), nullptr);
    EXPECT_EQ(ln_identity_from_json("not json"), nullptr);
    EXPECT_EQ(ln_identity_from_json(nullptr), nullptr);
}

TEST_F(SdkIdentityStoreTest, CApiNullArguments) {
    EXPECT_EQ(ln_identity_user_status(nullptr), LN_ERR_NULL_ARG);
    EXPECT_EQ(ln_identity_user_import(nullptr), LN_ERR_NULL_ARG);
    EXPECT_EQ(ln_identity_from_json(nullptr), nullptr);
    IdentityHandle created(ln_identity_user_create(nullptr));
    EXPECT_NE(created.id, nullptr) << "out_err may be NULL";
    EXPECT_TRUE(fs::exists(file()));
}

TEST(SdkIdentityStoreDirTest, UserDirFollowsThePlatformRule) {
    const auto dir = IdentityStore::user_dir();
    ASSERT_TRUE(dir.has_value());
    EXPECT_TRUE(dir->is_absolute());
    EXPECT_EQ(dir->filename(), "identity");
#if defined(__APPLE__)
    EXPECT_EQ(dir->parent_path().filename(), "LemonadeNexus");
    EXPECT_EQ(dir->parent_path().parent_path().filename(), "Application Support");
#elif defined(_WIN32)
    EXPECT_EQ(dir->parent_path().filename(), "LemonadeNexus");
#else
    EXPECT_EQ(dir->parent_path().filename(), "lemonade-nexus");
#endif
    // Not created by resolving it, and the C ABI agrees.
    EXPECT_EQ(take_str(ln_identity_user_dir()), utf8(*dir));
}

TEST(SdkIdentityStoreDirTest, UserDirIgnoresSudoUser) {
    // The result depends on the effective uid only; SUDO_USER changes nothing.
    const auto before = IdentityStore::user_dir();
#ifndef _WIN32
    ::setenv("SUDO_USER", "someone-else", 1);
    const auto after = IdentityStore::user_dir();
    ::unsetenv("SUDO_USER");
    EXPECT_EQ(before, after);
#else
    EXPECT_TRUE(before.has_value());
#endif
}

/// The keystore of this host, in a temporary directory. On a Linux host
/// without the Secret Service the store must refuse and write nothing. On
/// macOS and Windows the round trip uses the real login keychain or DPAPI and
/// removes what it created.
TEST(SdkIdentityStorePlatformTest, PlatformBackendRoundTripOrUnsupported) {
    ASSERT_GE(sodium_init(), 0);
    const fs::path root = fs::temp_directory_path() /
        ("nexus_sdk_identity_platform_" +
         std::to_string(::testing::UnitTest::GetInstance()->random_seed()));
    std::error_code ec;
    fs::remove_all(root, ec);
    const fs::path dir = root / "identity";
    auto backend = IdentityStore::platform_backend();
    ASSERT_NE(backend, nullptr);
    IdentityStore store(dir, backend);

#if defined(__APPLE__)
    EXPECT_EQ(backend->name(), "keychain");
#elif defined(_WIN32)
    EXPECT_EQ(backend->name(), "dpapi");
#elif defined(__linux__)
    EXPECT_EQ(backend->name(), "libsecret");
#endif

    if (!backend->available()) {
        Identity created;
        EXPECT_EQ(store.create(created), StoreResult::Unsupported);
        EXPECT_FALSE(created.is_valid());
        EXPECT_FALSE(fs::exists(dir));
        EXPECT_EQ(store.status().backend, "none");
        fs::remove_all(root, ec);
#if defined(__linux__)
        return;  // the expected state on a host without a Secret Service
#else
        FAIL() << "the platform keystore must be available on this host";
#endif
    }

#if defined(__linux__)
    GTEST_SKIP() << "a Secret Service is running; the round trip is not run against a real keyring";
#else
    Identity created;
    ASSERT_EQ(store.create(created), StoreResult::Ok);
    Identity loaded;
    EXPECT_EQ(store.load(loaded), StoreResult::Ok);
    EXPECT_EQ(loaded.private_key(), created.private_key());
    const auto status = store.status();
    EXPECT_TRUE(status.present);
    EXPECT_TRUE(status.unlocked);
    EXPECT_EQ(status.backend, backend->name());
    EXPECT_EQ(store.remove(), StoreResult::Ok);
    EXPECT_FALSE(fs::exists(dir / IdentityStore::kFileName));
    EXPECT_EQ(store.load(loaded), StoreResult::NotFound);
    fs::remove_all(root, ec);
#endif
}

TEST(SdkIdentityStoreHygieneTest, IdentityDestructorWipesThePrivateKey) {
    ASSERT_GE(sodium_init(), 0);
    alignas(Identity) unsigned char raw[sizeof(Identity)];
    auto* id = new (raw) Identity();
    id->generate();
    ASSERT_TRUE(id->is_valid());
    const std::vector<uint8_t> probe(id->private_key().begin(), id->private_key().begin() + 16);
    ASSERT_TRUE(contains_bytes(raw, probe));
    id->~Identity();
    EXPECT_FALSE(contains_bytes(raw, probe));
}

TEST(SdkIdentityStoreHygieneTest, MovedFromIdentityIsWiped) {
    ASSERT_GE(sodium_init(), 0);
    Identity source;
    source.generate();
    const auto key = source.private_key();
    Identity target = std::move(source);
    EXPECT_TRUE(target.is_valid());
    EXPECT_EQ(target.private_key(), key);
    EXPECT_FALSE(source.is_valid());  // NOLINT(bugprone-use-after-move): the contract under test
    EXPECT_TRUE(std::all_of(source.private_key().begin(), source.private_key().end(),
                            [](uint8_t b) { return b == 0; }));

    Identity assigned;
    assigned = std::move(target);
    EXPECT_EQ(assigned.private_key(), key);
    EXPECT_FALSE(target.is_valid());  // NOLINT(bugprone-use-after-move)
    EXPECT_TRUE(std::all_of(target.private_key().begin(), target.private_key().end(),
                            [](uint8_t b) { return b == 0; }));
}
