#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <cstring>
#include <filesystem>
#include <string>

using namespace nexus::crypto;
namespace fs = std::filesystem;

class KeyWrappingTest : public ::testing::Test {
protected:
    fs::path temp_dir;
    std::unique_ptr<SodiumCryptoService> crypto;
    std::unique_ptr<nexus::storage::FileStorageService> storage;
    std::unique_ptr<KeyWrappingService> kw;

    void SetUp() override {
        temp_dir = fs::temp_directory_path() / ("nexus_test_kw_" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()));
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

TEST_F(KeyWrappingTest, ServiceName) {
    EXPECT_EQ(kw->service_name(), "KeyWrappingService");
}
