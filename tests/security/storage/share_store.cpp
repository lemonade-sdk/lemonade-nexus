// The storage share store (design B6 seam until Phase 6 sealing lands): the
// file-backed store with and without the machine-bound wrapping, and the
// share bundle encoding.

#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Security/Storage/StorageShareStore.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <filesystem>
#include <fstream>
#include <unistd.h>

using namespace nexus::security;
namespace fs = std::filesystem;

namespace {

class ShareStoreTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        root = fs::temp_directory_path() / ("nexus_share_store_" + std::to_string(::getpid()));
        fs::remove_all(root);
        fs::create_directories(root);
        crypto.start();
        files = std::make_unique<nexus::storage::FileStorageService>((root / "data").string());
        files->start();
        wrapping = std::make_unique<nexus::crypto::KeyWrappingService>(crypto, *files);
        wrapping->start();
        crypto_sign_keypair(identity.public_key.data(), identity.private_key.data());
    }

    void TearDown() override {
        wrapping->stop();
        files->stop();
        crypto.stop();
        fs::remove_all(root);
    }

    static std::vector<uint8_t> secret() {
        std::vector<uint8_t> bytes(100);
        randombytes_buf(bytes.data(), bytes.size());
        return bytes;
    }

    fs::path root;
    nexus::crypto::SodiumCryptoService crypto;
    std::unique_ptr<nexus::storage::FileStorageService> files;
    std::unique_ptr<nexus::crypto::KeyWrappingService> wrapping;
    nexus::crypto::Ed25519Keypair identity{};
};

TEST_F(ShareStoreTest, WrappedStoreRoundTripsAndKeepsNoPlaintextOnDisk) {
    FileStorageShareStore store(root / "sealed", &crypto, wrapping.get(), identity.public_key);
    EXPECT_EQ(store.unseal(kStorageShareDomain).status, ShareStoreStatus::Missing);
    const auto value = secret();
    ASSERT_EQ(store.seal(kStorageShareDomain, value), ShareStoreStatus::Ok);
    const auto back = store.unseal(kStorageShareDomain);
    ASSERT_EQ(back.status, ShareStoreStatus::Ok);
    EXPECT_EQ(std::vector<uint8_t>(back.plaintext.data(), back.plaintext.data() + back.plaintext.size()),
              value);
    // Owner-only and without the plaintext in it.
    const auto path = store.path_of(kStorageShareDomain);
    const auto perms = fs::status(path).permissions();
    EXPECT_EQ(perms & (fs::perms::group_all | fs::perms::others_all), fs::perms::none);
    std::ifstream in(path, std::ios::binary);
    const std::string text((std::istreambuf_iterator<char>(in)), {});
    EXPECT_EQ(text.find(nexus::crypto::to_base64(value)), std::string::npos);

    // Another identity's binding cannot open it.
    nexus::crypto::Ed25519Keypair other{};
    crypto_sign_keypair(other.public_key.data(), other.private_key.data());
    FileStorageShareStore wrong(root / "sealed", &crypto, wrapping.get(), other.public_key);
    EXPECT_EQ(wrong.unseal(kStorageShareDomain).status, ShareStoreStatus::Corrupt);

    EXPECT_TRUE(store.remove(kStorageShareDomain));
    EXPECT_EQ(store.unseal(kStorageShareDomain).status, ShareStoreStatus::Missing);
}

TEST_F(ShareStoreTest, AWrappingStoreRefusesAPlantedPlaintextFile) {
    FileStorageShareStore plain(root / "sealed");
    ASSERT_EQ(plain.seal(kStorageShareDomain, secret()), ShareStoreStatus::Ok);
    ASSERT_EQ(plain.unseal(kStorageShareDomain).status, ShareStoreStatus::Ok);
    FileStorageShareStore wrapped(root / "sealed", &crypto, wrapping.get(), identity.public_key);
    EXPECT_EQ(wrapped.unseal(kStorageShareDomain).status, ShareStoreStatus::Corrupt);
    // A malformed domain name is refused before any file access.
    EXPECT_EQ(plain.seal("../escape", secret()), ShareStoreStatus::Failed);
}

TEST(ShareBundle, EncodingIsExactAndBounded) {
    StorageShareBundle bundle;
    Digest a{};
    a.fill(1);
    Digest b{};
    b.fill(2);
    const std::vector<uint8_t> one(40, 0x11);
    const std::vector<uint8_t> two(50, 0x22);
    bundle.emplace(a, nexus::crypto::SecureBuffer(std::span<const uint8_t>(one)));
    bundle.emplace(b, nexus::crypto::SecureBuffer(std::span<const uint8_t>(two)));
    const auto encoded = encode_share_bundle(bundle);
    ASSERT_FALSE(encoded.empty());
    const auto back = decode_share_bundle(encoded.span());
    ASSERT_TRUE(back.has_value());
    ASSERT_EQ(back->size(), 2u);
    EXPECT_EQ(std::vector<uint8_t>(back->at(b).data(), back->at(b).data() + back->at(b).size()),
              two);
    std::vector<uint8_t> bytes(encoded.data(), encoded.data() + encoded.size());
    bytes.push_back(0);
    EXPECT_FALSE(decode_share_bundle(bytes).has_value());
    bytes.pop_back();
    bytes.pop_back();
    EXPECT_FALSE(decode_share_bundle(bytes).has_value());
    bytes[0] ^= 0x01;
    EXPECT_FALSE(decode_share_bundle(bytes).has_value());
}

}  // namespace
