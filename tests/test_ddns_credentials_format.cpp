// DDNS credentials at rest carry the same encrypted-object format as everything
// else, so a record written before the format existed must fail closed rather
// than be reinterpreted. There is no AES decryption left to fall back to.

#include <LemonadeNexus/Core/BinaryAttestation.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Network/DdnsService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <asio.hpp>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <filesystem>
#include <string>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;
using namespace nexus;

namespace {

struct DdnsCredentialFormat : ::testing::Test {
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        dir = fs::temp_directory_path() /
              ("nexus_ddns_fmt_" + std::to_string(::getpid()) + "_" +
               ::testing::UnitTest::GetInstance()->current_test_info()->name());
        fs::remove_all(dir);
        fs::create_directories(dir);

        crypto.start();
        storage.emplace(dir);
        storage->start();
        attestation.emplace(crypto, *storage);
        gossip.emplace(io, static_cast<uint16_t>(0), *storage, crypto);
        gossip->start();
    }

    void TearDown() override {
        if (gossip) gossip->stop();
        if (storage) storage->stop();
        crypto.stop();
        std::error_code ec;
        fs::remove_all(dir, ec);
    }

    /// The identity DdnsService reads. Without it the loader bails before any
    /// format check, which would make every assertion below vacuous.
    void seed_identity() {
        identity = crypto.ed25519_keygen();
        nlohmann::json kp;
        kp["public_key"] = crypto::to_base64(
            std::span<const uint8_t>(identity.public_key.data(), identity.public_key.size()));
        kp["private_key"] = crypto::to_base64(
            std::span<const uint8_t>(identity.private_key.data(), identity.private_key.size()));
        storage::SignedEnvelope env;
        env.data = kp.dump();
        ASSERT_TRUE(storage->write_file("identity", "keypair.json", env));
    }

    /// Exactly the key DdnsService derives for at-rest credentials.
    crypto::AeadKey at_rest_key() {
        const std::string salt_str = "lemonade-nexus-ddns-at-rest";
        const std::string info_str = "ddns-credentials-encryption";
        auto bytes = crypto.hkdf_sha256(
            std::span<const uint8_t>(identity.private_key.data(), identity.private_key.size()),
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(salt_str.data()),
                                     salt_str.size()),
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(info_str.data()),
                                     info_str.size()),
            crypto::kAeadKeySize);
        crypto::AeadKey key{};
        EXPECT_EQ(bytes.size(), crypto::kAeadKeySize);
        if (bytes.size() == crypto::kAeadKeySize) {
            std::memcpy(key.data(), bytes.data(), key.size());
        }
        return key;
    }

    void write_record(const nlohmann::json& stored) {
        storage::SignedEnvelope env;
        env.data = stored.dump();
        ASSERT_TRUE(storage->write_file("identity", "ddns_credentials.enc", env));
    }

    crypto::Ed25519Keypair identity;

    asio::io_context io;
    fs::path dir;
    crypto::SodiumCryptoService crypto;
    std::optional<storage::FileStorageService> storage;
    std::optional<core::BinaryAttestationService> attestation;
    std::optional<gossip::GossipService> gossip;
};

}  // namespace

// Positive control. Without this the refusals below could pass for the wrong
// reason — an absent identity or an unreadable file, rather than the format.
TEST_F(DdnsCredentialFormat, ACurrentRecordLoads) {
    seed_identity();
    const auto aad = crypto::aead_aad(crypto::aead_purpose::kDdnsAtRest);
    const std::string creds = R"({"provider":"namecheap","password":"x"})";
    const auto blob = crypto.aead_encrypt(
        at_rest_key(),
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(creds.data()), creds.size()),
        std::span<const uint8_t>{aad});

    nlohmann::json stored;
    stored["crypto_version"] = static_cast<unsigned>(blob.version);
    stored["nonce"] = crypto::to_base64(blob.nonce);
    stored["ciphertext"] = crypto::to_base64(blob.ciphertext);
    write_record(stored);

    network::DdnsService ddns{io, crypto, *storage, *attestation, *gossip};
    ddns.start();
    EXPECT_TRUE(ddns.has_credentials()) << "a current record must load, or the "
                                           "refusal tests below prove nothing";
    ddns.stop();
}

// A pre-change record: no crypto_version, and a 12-byte AES-GCM nonce. The
// service must start with no credentials rather than decode it.
TEST_F(DdnsCredentialFormat, APreChangeAesRecordIsRefused) {
    seed_identity();
    nlohmann::json stored;
    stored["nonce"] = crypto::to_base64(std::vector<uint8_t>(12, 0xAB));
    stored["ciphertext"] = crypto::to_base64(std::vector<uint8_t>(48, 0xCD));
    // crypto_version deliberately absent, as the old writer left it.
    write_record(stored);

    network::DdnsService ddns{io, crypto, *storage, *attestation, *gossip};
    ddns.start();
    EXPECT_FALSE(ddns.has_credentials()) << "a pre-change AES record must not load";
    ddns.stop();
}

// The version field alone is not enough: a record carrying the right version but
// the old nonce width is still refused, before the nonce reaches the AEAD.
TEST_F(DdnsCredentialFormat, AVersionedRecordWithTheOldNonceWidthIsRefused) {
    seed_identity();
    nlohmann::json stored;
    stored["crypto_version"] = static_cast<unsigned>(crypto::kEncryptedBlobVersion);
    stored["nonce"] = crypto::to_base64(std::vector<uint8_t>(12, 0xAB));
    stored["ciphertext"] = crypto::to_base64(std::vector<uint8_t>(48, 0xCD));
    write_record(stored);

    network::DdnsService ddns{io, crypto, *storage, *attestation, *gossip};
    ddns.start();
    EXPECT_FALSE(ddns.has_credentials());
    ddns.stop();
}
