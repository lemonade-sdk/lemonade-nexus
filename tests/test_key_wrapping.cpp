#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

using namespace nexus::crypto;
namespace fs = std::filesystem;

class KeyWrappingTest : public ::testing::Test {
protected:
    fs::path temp_dir;
    std::unique_ptr<SodiumCryptoService> crypto;
    std::unique_ptr<nexus::storage::FileStorageService> storage;
    std::unique_ptr<KeyWrappingService> kw;

    void SetUp() override {
        temp_dir = fs::temp_directory_path() / ("nexus_test_kw_" + std::to_string(getpid()));
        fs::create_directories(temp_dir);

        crypto = std::make_unique<SodiumCryptoService>();
        crypto->start();

        storage = std::make_unique<nexus::storage::FileStorageService>(temp_dir);
        storage->start();

        kw = std::make_unique<KeyWrappingService>(*crypto, *storage);
        kw->start();
    }

    void TearDown() override {
        kw->stop();
        storage->stop();
        crypto->stop();
        fs::remove_all(temp_dir);
    }
};

TEST_F(KeyWrappingTest, WrapUnwrapRoundTrip) {
    if (!crypto_aead_aes256gcm_is_available()) {
        GTEST_SKIP() << "AES-256-GCM not available on this CPU (requires AES-NI)";
    }
    auto keypair = crypto->ed25519_keygen();
    std::string passphrase = "test-passphrase-123";
    auto pp_bytes = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(passphrase.data()), passphrase.size());

    auto wrapped = kw->wrap_key(keypair.private_key, pp_bytes, keypair.public_key);
    auto unwrapped = kw->unwrap_key(wrapped, pp_bytes, keypair.public_key);

    ASSERT_TRUE(unwrapped.has_value());
    EXPECT_EQ(*unwrapped, keypair.private_key);
}

TEST_F(KeyWrappingTest, UnwrapFailsWithWrongPassphrase) {
    if (!crypto_aead_aes256gcm_is_available()) {
        GTEST_SKIP() << "AES-256-GCM not available on this CPU (requires AES-NI)";
    }
    auto keypair = crypto->ed25519_keygen();
    std::string pass1 = "correct-passphrase";
    std::string pass2 = "wrong-passphrase";
    auto pp1 = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(pass1.data()), pass1.size());
    auto pp2 = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(pass2.data()), pass2.size());

    auto wrapped = kw->wrap_key(keypair.private_key, pp1, keypair.public_key);
    auto unwrapped = kw->unwrap_key(wrapped, pp2, keypair.public_key);
    EXPECT_FALSE(unwrapped.has_value());
}

TEST_F(KeyWrappingTest, GenerateAndStoreIdentity) {
    if (!crypto_aead_aes256gcm_is_available()) {
        GTEST_SKIP() << "AES-256-GCM not available on this CPU (requires AES-NI)";
    }
    std::string passphrase = "identity-pass";
    auto pp = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(passphrase.data()), passphrase.size());

    auto keypair = kw->generate_and_store_identity(pp);

    // Public key should be stored on disk
    auto loaded_pk = kw->load_identity_pubkey();
    ASSERT_TRUE(loaded_pk.has_value());
    EXPECT_EQ(*loaded_pk, keypair.public_key);

    // Should be able to unlock private key
    auto unlocked = kw->unlock_identity(pp);
    ASSERT_TRUE(unlocked.has_value());
    EXPECT_EQ(*unlocked, keypair.private_key);
}

TEST_F(KeyWrappingTest, UnlockIdentityFailsWithWrongPassphrase) {
    if (!crypto_aead_aes256gcm_is_available()) {
        GTEST_SKIP() << "AES-256-GCM not available on this CPU (requires AES-NI)";
    }
    std::string pass1 = "correct";
    std::string pass2 = "wrong";
    auto pp1 = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(pass1.data()), pass1.size());
    auto pp2 = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(pass2.data()), pass2.size());

    kw->generate_and_store_identity(pp1);
    auto unlocked = kw->unlock_identity(pp2);
    EXPECT_FALSE(unlocked.has_value());
}

TEST_F(KeyWrappingTest, LoadIdentityPubkeyReturnsNulloptWhenNoneStored) {
    auto pk = kw->load_identity_pubkey();
    EXPECT_FALSE(pk.has_value());
}

TEST_F(KeyWrappingTest, DelegateKeyProducesValidResult) {
    if (!crypto_aead_aes256gcm_is_available()) {
        GTEST_SKIP() << "AES-256-GCM not available on this CPU (requires AES-NI)";
    }
    std::string passphrase = "delegate-pass";
    auto pp = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(passphrase.data()), passphrase.size());

    kw->generate_and_store_identity(pp);
    auto result = kw->delegate_key(pp);

    EXPECT_TRUE(result.success);

    // Child keypair should be valid
    Ed25519PublicKey zeros{};
    EXPECT_NE(result.child_keypair.public_key, zeros);

    // Wrapped child key should have non-empty ciphertext
    EXPECT_FALSE(result.wrapped_child_key.ciphertext.ciphertext.empty());
}

// Helpers for the machine-binding / migration tests below.
namespace {
std::string read_file(const fs::path& p) {
    std::ifstream ifs(p, std::ios::binary);
    std::string s((std::istreambuf_iterator<char>(ifs)), std::istreambuf_iterator<char>());
    return s;
}
}  // namespace

// A freshly stored identity uses the machine binding ("v2:" prefix) and round-trips.
TEST_F(KeyWrappingTest, MachineBoundIdentityRoundTrip) {
    auto keypair = kw->generate_and_store_identity({});

    // keypair.enc must be the new machine-bound format, and the per-install secret
    // must have been created.
    auto enc = read_file(temp_dir / "identity" / "keypair.enc");
    EXPECT_EQ(enc.rfind("v2:", 0), 0u) << "stored blob must use the machine binding";
    EXPECT_TRUE(fs::exists(temp_dir / "identity" / "wrap_local.key"));

    auto unlocked = kw->unlock_identity({});
    ASSERT_TRUE(unlocked.has_value());
    EXPECT_EQ(*unlocked, keypair.private_key);
}

// A stolen keypair.enc is useless without the host's wrap_local.key (simulates
// copying the encrypted key to another machine).
TEST_F(KeyWrappingTest, StolenEncFailsWithoutLocalSecret) {
    kw->generate_and_store_identity({});
    ASSERT_TRUE(kw->unlock_identity({}).has_value());

    // Overwrite the per-install secret with a different value (as if the attacker
    // copied keypair.enc to a box whose wrap_local.key differs).
    auto secret_path = temp_dir / "identity" / "wrap_local.key";
    {
        std::ofstream ofs(secret_path, std::ios::binary | std::ios::trunc);
        ofs << std::string(64, 'a');  // 32 bytes of 0xaa in hex
    }

    auto unlocked = kw->unlock_identity({});
    EXPECT_FALSE(unlocked.has_value())
        << "keypair.enc must not unlock under a different local secret";
}

// A legacy (pre-hardening) keypair.enc — HKDF(empty, salt, info=pubkey), no prefix —
// is transparently migrated to the machine binding on first unlock, with a backup.
TEST_F(KeyWrappingTest, LegacyBlobMigratesToV2OnUnlock) {
    auto keypair = crypto->ed25519_keygen();

    // Reproduce the original (legacy) derivation exactly: HKDF over an empty
    // passphrase, salt "lemonade-nexus-mgmt-key", info = pubkey.
    static constexpr std::string_view kSalt = "lemonade-nexus-mgmt-key";
    auto derived = crypto->hkdf_sha256(
        std::span<const uint8_t>{},
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(kSalt.data()), kSalt.size()),
        std::span<const uint8_t>(keypair.public_key.data(), keypair.public_key.size()),
        kAesGcmKeySize);
    AesGcmKey legacy_key{};
    std::memcpy(legacy_key.data(), derived.data(), kAesGcmKeySize);

    auto ct = crypto->aes_gcm_encrypt(
        legacy_key,
        std::span<const uint8_t>(keypair.private_key.data(), keypair.private_key.size()),
        std::span<const uint8_t>(keypair.public_key.data(), keypair.public_key.size()));

    auto id_dir = temp_dir / "identity";
    fs::create_directories(id_dir);
    {
        std::ofstream ofs(id_dir / "keypair.pub", std::ios::binary);
        ofs << to_hex(std::span<const uint8_t>(keypair.public_key));
    }
    {
        // Legacy on-disk format: nonce_hex:ct_hex with NO "v2:" prefix.
        std::ofstream ofs(id_dir / "keypair.enc", std::ios::binary);
        ofs << to_hex(std::span<const uint8_t>(ct.nonce.data(), ct.nonce.size()))
            << ":" << to_hex(std::span<const uint8_t>(ct.ciphertext));
    }

    // First unlock returns the real key AND migrates the blob.
    auto unlocked = kw->unlock_identity({});
    ASSERT_TRUE(unlocked.has_value());
    EXPECT_EQ(*unlocked, keypair.private_key);

    auto enc_after = read_file(id_dir / "keypair.enc");
    EXPECT_EQ(enc_after.rfind("v2:", 0), 0u) << "blob must be migrated to machine binding";
    EXPECT_TRUE(fs::exists(id_dir / "keypair.enc.legacy.bak"))
        << "original legacy blob must be backed up for rollback";

    // Second unlock now goes through the machine-bound path and still works.
    auto unlocked2 = kw->unlock_identity({});
    ASSERT_TRUE(unlocked2.has_value());
    EXPECT_EQ(*unlocked2, keypair.private_key);
}

TEST_F(KeyWrappingTest, ServiceName) {
    EXPECT_EQ(kw->service_name(), "KeyWrappingService");
}
