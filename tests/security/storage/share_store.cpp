// The storage share store (design B6): the sealed adapter over SealedBlobStore
// (with FakeSealer, not a TPM), the file-backed store with and without the
// machine-bound wrapping, and the share bundle encoding.

#include "support/fake_sealer.hpp"

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

// --- Sealed adapter (B6, B7 step 1) ----------------------------------------------

TEST_F(ShareStoreTest, SealedAdapterRoundTripsUnderTheStorageShareDomain) {
    seal_test::FakeSealer sealer;
    SealedBlobStore blobs(root / "boot-sealed", sealer.backend());
    SealedStorageShareStore store(blobs);
    const auto value = secret();
    ASSERT_EQ(store.seal(kStorageShareDomain, value), ShareStoreStatus::Ok);
    EXPECT_TRUE(fs::exists(blobs.current_path(kStorageShareDomain)));
    const auto back = store.unseal(kStorageShareDomain);
    ASSERT_EQ(back.status, ShareStoreStatus::Ok);
    EXPECT_EQ(std::vector<uint8_t>(back.plaintext.data(), back.plaintext.data() + back.plaintext.size()),
              value);
    EXPECT_TRUE(store.remove(kStorageShareDomain));
    EXPECT_EQ(store.unseal(kStorageShareDomain).status, ShareStoreStatus::Missing);
}

TEST_F(ShareStoreTest, SealedAdapterFailsClosedOnMissingAndPolicyMismatch) {
    seal_test::FakeSealer sealer;
    SealedBlobStore blobs(root / "boot-sealed", sealer.backend());
    SealedStorageShareStore store(blobs);
    // Missing: nothing sealed; no plaintext is invented.
    const auto missing = store.unseal(kStorageShareDomain);
    EXPECT_EQ(missing.status, ShareStoreStatus::Missing);
    EXPECT_TRUE(missing.plaintext.empty());
    // PolicyMismatch: the boot chain changed and nothing was staged.
    ASSERT_EQ(store.seal(kStorageShareDomain, secret()), ShareStoreStatus::Ok);
    sealer.pcrs = seal_test::pcrs_of(0x33, 0x44);
    const auto mismatch = store.unseal(kStorageShareDomain);
    EXPECT_EQ(mismatch.status, ShareStoreStatus::PolicyMismatch);
    EXPECT_TRUE(mismatch.plaintext.empty());
    EXPECT_TRUE(fs::exists(blobs.current_path(kStorageShareDomain)));
    // Unreachable daemon: reported, not treated as Missing.
    sealer.reachable = false;
    EXPECT_EQ(store.unseal(kStorageShareDomain).status, ShareStoreStatus::Unreachable);
}

// --- Sealed adapter with the durable copy ----------------------------------------

namespace {

std::vector<uint8_t> bytes_of(const nexus::crypto::SecureBuffer& buffer) {
    return {buffer.data(), buffer.data() + buffer.size()};
}

}  // namespace

TEST_F(ShareStoreTest, SealedAdapterWritesBothCopiesAndRemovesBoth) {
    FileStorageShareStore durable(root / "sealed", &crypto, wrapping.get(), identity.public_key);
    seal_test::FakeSealer sealer;
    SealedBlobStore blobs(root / "boot-sealed", sealer.backend());
    SealedStorageShareStore store(blobs, &durable);
    const auto value = secret();
    ASSERT_EQ(store.seal(kStorageShareDomain, value), ShareStoreStatus::Ok);
    EXPECT_TRUE(fs::exists(blobs.current_path(kStorageShareDomain)));
    EXPECT_TRUE(fs::exists(durable.path_of(kStorageShareDomain)));
    // The durable copy is the machine-bound wrapping, not plaintext.
    std::ifstream in(durable.path_of(kStorageShareDomain), std::ios::binary);
    const std::string text((std::istreambuf_iterator<char>(in)), {});
    EXPECT_EQ(text.find(nexus::crypto::to_base64(value)), std::string::npos);
    const auto back = store.unseal(kStorageShareDomain);
    ASSERT_EQ(back.status, ShareStoreStatus::Ok);
    EXPECT_EQ(bytes_of(back.plaintext), value);
    EXPECT_TRUE(store.remove(kStorageShareDomain));
    EXPECT_FALSE(fs::exists(blobs.current_path(kStorageShareDomain)));
    EXPECT_FALSE(fs::exists(durable.path_of(kStorageShareDomain)));
    EXPECT_EQ(store.unseal(kStorageShareDomain).status, ShareStoreStatus::Missing);
}

// The failure of 2026-11-05: every holder rebooted and every virtual TPM came
// back without its state, so every sealed share reported Corrupt. The durable
// copy opens, the share is sealed again under the new TPM, and the next start
// unseals the sealed copy.
TEST_F(ShareStoreTest, SealedAdapterRecoversTheShareWhenTheTpmLosesItsState) {
    FileStorageShareStore durable(root / "sealed", &crypto, wrapping.get(), identity.public_key);
    seal_test::FakeSealer sealer;
    SealedBlobStore blobs(root / "boot-sealed", sealer.backend());
    SealedStorageShareStore store(blobs, &durable);
    const auto value = secret();
    ASSERT_EQ(store.seal(kStorageShareDomain, value), ShareStoreStatus::Ok);

    sealer.owner_seed = "owner-seed-B";  // a new TPM: the old blob does not load
    {
        SealedStorageShareStore sealed_only(blobs);
        EXPECT_EQ(sealed_only.unseal(kStorageShareDomain).status, ShareStoreStatus::Corrupt);
    }
    const auto recovered = store.unseal(kStorageShareDomain);
    ASSERT_EQ(recovered.status, ShareStoreStatus::Ok);
    EXPECT_EQ(bytes_of(recovered.plaintext), value);
    // Sealed again under the new TPM: the sealed copy alone opens now.
    SealedStorageShareStore sealed_only(blobs);
    const auto resealed = sealed_only.unseal(kStorageShareDomain);
    ASSERT_EQ(resealed.status, ShareStoreStatus::Ok);
    EXPECT_EQ(bytes_of(resealed.plaintext), value);
    EXPECT_TRUE(fs::exists(durable.path_of(kStorageShareDomain)));
}

TEST_F(ShareStoreTest, SealedAdapterRecoversTheShareOnAPolicyMismatch) {
    FileStorageShareStore durable(root / "sealed", &crypto, wrapping.get(), identity.public_key);
    seal_test::FakeSealer sealer;
    SealedBlobStore blobs(root / "boot-sealed", sealer.backend());
    SealedStorageShareStore store(blobs, &durable);
    const auto value = secret();
    ASSERT_EQ(store.seal(kStorageShareDomain, value), ShareStoreStatus::Ok);
    sealer.pcrs = seal_test::pcrs_of(0x55, 0x66);  // a boot chain nothing was staged for
    const auto recovered = store.unseal(kStorageShareDomain);
    ASSERT_EQ(recovered.status, ShareStoreStatus::Ok);
    EXPECT_EQ(bytes_of(recovered.plaintext), value);
    SealedStorageShareStore sealed_only(blobs);
    EXPECT_EQ(sealed_only.unseal(kStorageShareDomain).status, ShareStoreStatus::Ok);
}

// A holder updated from a release that kept the sealed copy alone: the first
// unseal writes the durable copy. A durable copy that does not open is
// rewritten the same way and never read.
TEST_F(ShareStoreTest, SealedAdapterWritesTheDurableCopyWhenOnlyTheSealedCopyExists) {
    FileStorageShareStore durable(root / "sealed", &crypto, wrapping.get(), identity.public_key);
    seal_test::FakeSealer sealer;
    SealedBlobStore blobs(root / "boot-sealed", sealer.backend());
    const auto value = secret();
    {
        SealedStorageShareStore sealed_only(blobs);
        ASSERT_EQ(sealed_only.seal(kStorageShareDomain, value), ShareStoreStatus::Ok);
    }
    EXPECT_FALSE(fs::exists(durable.path_of(kStorageShareDomain)));
    SealedStorageShareStore store(blobs, &durable);
    const auto first = store.unseal(kStorageShareDomain);
    ASSERT_EQ(first.status, ShareStoreStatus::Ok);
    EXPECT_EQ(bytes_of(first.plaintext), value);
    ASSERT_TRUE(fs::exists(durable.path_of(kStorageShareDomain)));
    const auto copy = durable.unseal(kStorageShareDomain);
    ASSERT_EQ(copy.status, ShareStoreStatus::Ok);
    EXPECT_EQ(bytes_of(copy.plaintext), value);

    // A planted plaintext file in place of the durable copy is replaced, and
    // the sealed copy's bytes are what the store returns.
    FileStorageShareStore plain(root / "sealed");
    ASSERT_EQ(plain.seal(kStorageShareDomain, secret()), ShareStoreStatus::Ok);
    EXPECT_EQ(durable.unseal(kStorageShareDomain).status, ShareStoreStatus::Corrupt);
    const auto second = store.unseal(kStorageShareDomain);
    ASSERT_EQ(second.status, ShareStoreStatus::Ok);
    EXPECT_EQ(bytes_of(second.plaintext), value);
    EXPECT_EQ(bytes_of(durable.unseal(kStorageShareDomain).plaintext), value);
}

// With no copy that opens, nothing is invented: the sealed status stands when
// the durable copy is missing, and a damaged durable copy is reported when the
// sealed copy is gone too.
TEST_F(ShareStoreTest, SealedAdapterFailsClosedWhenNeitherCopyOpens) {
    FileStorageShareStore durable(root / "sealed", &crypto, wrapping.get(), identity.public_key);
    seal_test::FakeSealer sealer;
    SealedBlobStore blobs(root / "boot-sealed", sealer.backend());
    SealedStorageShareStore store(blobs, &durable);
    EXPECT_EQ(store.unseal(kStorageShareDomain).status, ShareStoreStatus::Missing);
    ASSERT_EQ(store.seal(kStorageShareDomain, secret()), ShareStoreStatus::Ok);
    ASSERT_TRUE(durable.remove(kStorageShareDomain));
    sealer.pcrs = seal_test::pcrs_of(0x55, 0x66);
    EXPECT_EQ(store.unseal(kStorageShareDomain).status, ShareStoreStatus::PolicyMismatch);
    sealer.owner_seed = "owner-seed-C";
    EXPECT_EQ(store.unseal(kStorageShareDomain).status, ShareStoreStatus::Corrupt);
    // Unreachable daemon with a durable copy: the copy is used and no seal is
    // attempted until the daemon answers.
    sealer.owner_seed = "owner-seed-A";
    sealer.pcrs = seal_test::pcrs_of(0x11, 0x22);
    const auto value = secret();
    ASSERT_EQ(store.seal(kStorageShareDomain, value), ShareStoreStatus::Ok);
    sealer.reachable = false;
    const int seals_before = sealer.seal_calls;
    const auto offline = store.unseal(kStorageShareDomain);
    ASSERT_EQ(offline.status, ShareStoreStatus::Ok);
    EXPECT_EQ(bytes_of(offline.plaintext), value);
    EXPECT_EQ(sealer.seal_calls, seals_before);
}

}  // namespace
