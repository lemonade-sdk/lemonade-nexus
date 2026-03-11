#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

using namespace nexus::crypto;

class SodiumCryptoTest : public ::testing::Test {
protected:
    SodiumCryptoService crypto;

    void SetUp() override {
        crypto.start();
    }

    void TearDown() override {
        crypto.stop();
    }
};

// --- Ed25519 keygen ---

TEST_F(SodiumCryptoTest, Ed25519KeygenProducesValidKeypair) {
    auto kp = crypto.ed25519_keygen();
    // Keys should not be all zeros
    Ed25519PublicKey zeros{};
    EXPECT_NE(kp.public_key, zeros);
}

TEST_F(SodiumCryptoTest, Ed25519KeygenProducesUniqueKeys) {
    auto kp1 = crypto.ed25519_keygen();
    auto kp2 = crypto.ed25519_keygen();
    EXPECT_NE(kp1.public_key, kp2.public_key);
    EXPECT_NE(kp1.private_key, kp2.private_key);
}

// --- Ed25519 sign / verify ---

TEST_F(SodiumCryptoTest, Ed25519SignVerifyRoundTrip) {
    auto kp = crypto.ed25519_keygen();
    std::string message = "Hello, Lemonade-Nexus!";
    auto msg_bytes = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(message.data()), message.size());

    auto sig = crypto.ed25519_sign(kp.private_key, msg_bytes);
    EXPECT_TRUE(crypto.ed25519_verify(kp.public_key, msg_bytes, sig));
}

TEST_F(SodiumCryptoTest, Ed25519VerifyRejectsWrongMessage) {
    auto kp = crypto.ed25519_keygen();
    std::string message = "Original message";
    auto msg_bytes = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(message.data()), message.size());
    auto sig = crypto.ed25519_sign(kp.private_key, msg_bytes);

    std::string tampered = "Tampered message";
    auto tampered_bytes = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(tampered.data()), tampered.size());
    EXPECT_FALSE(crypto.ed25519_verify(kp.public_key, tampered_bytes, sig));
}

TEST_F(SodiumCryptoTest, Ed25519VerifyRejectsWrongKey) {
    auto kp1 = crypto.ed25519_keygen();
    auto kp2 = crypto.ed25519_keygen();
    std::string message = "Test message";
    auto msg_bytes = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(message.data()), message.size());

    auto sig = crypto.ed25519_sign(kp1.private_key, msg_bytes);
    EXPECT_FALSE(crypto.ed25519_verify(kp2.public_key, msg_bytes, sig));
}

TEST_F(SodiumCryptoTest, Ed25519SignEmptyMessage) {
    auto kp = crypto.ed25519_keygen();
    std::span<const uint8_t> empty;
    auto sig = crypto.ed25519_sign(kp.private_key, empty);
    EXPECT_TRUE(crypto.ed25519_verify(kp.public_key, empty, sig));
}

// --- X25519 keygen ---

TEST_F(SodiumCryptoTest, X25519KeygenProducesValidKeypair) {
    auto kp = crypto.x25519_keygen();
    X25519PublicKey zeros{};
    EXPECT_NE(kp.public_key, zeros);
}

// --- X25519 DH ---

TEST_F(SodiumCryptoTest, X25519DHProducesSharedSecret) {
    auto alice = crypto.x25519_keygen();
    auto bob   = crypto.x25519_keygen();

    auto shared_ab = crypto.x25519_dh(alice.private_key, bob.public_key);
    auto shared_ba = crypto.x25519_dh(bob.private_key, alice.public_key);

    // Both sides should derive the same shared secret
    EXPECT_EQ(shared_ab, shared_ba);
}

TEST_F(SodiumCryptoTest, X25519DHDifferentPeersProduceDifferentSecrets) {
    auto alice = crypto.x25519_keygen();
    auto bob   = crypto.x25519_keygen();
    auto carol = crypto.x25519_keygen();

    auto shared_ab = crypto.x25519_dh(alice.private_key, bob.public_key);
    auto shared_ac = crypto.x25519_dh(alice.private_key, carol.public_key);
    EXPECT_NE(shared_ab, shared_ac);
}

// --- AES-256-GCM ---

TEST_F(SodiumCryptoTest, AesGcmEncryptDecryptRoundTrip) {

    AesGcmKey key{};
    crypto.random_bytes(std::span<uint8_t>(key));

    std::string plaintext = "Secret data for Lemonade-Nexus";
    auto pt_bytes = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());

    auto ct = crypto.aes_gcm_encrypt(key, pt_bytes);
    auto result = crypto.aes_gcm_decrypt(key, ct);

    ASSERT_TRUE(result.has_value());
    std::string decrypted(result->begin(), result->end());
    EXPECT_EQ(decrypted, plaintext);
}

TEST_F(SodiumCryptoTest, AesGcmWithAAD) {
    AesGcmKey key{};
    crypto.random_bytes(std::span<uint8_t>(key));

    std::string plaintext = "Secret data";
    std::string aad = "Associated data";
    auto pt_bytes = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());
    auto aad_bytes = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(aad.data()), aad.size());

    auto ct = crypto.aes_gcm_encrypt(key, pt_bytes, aad_bytes);
    auto result = crypto.aes_gcm_decrypt(key, ct, aad_bytes);

    ASSERT_TRUE(result.has_value());
    std::string decrypted(result->begin(), result->end());
    EXPECT_EQ(decrypted, plaintext);
}

TEST_F(SodiumCryptoTest, AesGcmDecryptFailsWithWrongKey) {
    AesGcmKey key1{}, key2{};
    crypto.random_bytes(std::span<uint8_t>(key1));
    crypto.random_bytes(std::span<uint8_t>(key2));

    std::string plaintext = "Secret data";
    auto pt_bytes = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());

    auto ct = crypto.aes_gcm_encrypt(key1, pt_bytes);
    auto result = crypto.aes_gcm_decrypt(key2, ct);
    EXPECT_FALSE(result.has_value());
}

TEST_F(SodiumCryptoTest, AesGcmDecryptFailsWithWrongAAD) {
    AesGcmKey key{};
    crypto.random_bytes(std::span<uint8_t>(key));

    std::string plaintext = "Secret data";
    std::string aad1 = "Correct AAD";
    std::string aad2 = "Wrong AAD";
    auto pt_bytes = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());
    auto aad1_bytes = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(aad1.data()), aad1.size());
    auto aad2_bytes = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(aad2.data()), aad2.size());

    auto ct = crypto.aes_gcm_encrypt(key, pt_bytes, aad1_bytes);
    auto result = crypto.aes_gcm_decrypt(key, ct, aad2_bytes);
    EXPECT_FALSE(result.has_value());
}

TEST_F(SodiumCryptoTest, AesGcmDecryptFailsWithTamperedCiphertext) {
    AesGcmKey key{};
    crypto.random_bytes(std::span<uint8_t>(key));

    std::string plaintext = "Secret data";
    auto pt_bytes = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size());

    auto ct = crypto.aes_gcm_encrypt(key, pt_bytes);
    // Tamper with ciphertext
    if (!ct.ciphertext.empty()) {
        ct.ciphertext[0] ^= 0xFF;
    }
    auto result = crypto.aes_gcm_decrypt(key, ct);
    EXPECT_FALSE(result.has_value());
}

// --- HKDF-SHA256 ---

TEST_F(SodiumCryptoTest, HkdfSha256ProducesDeterministicOutput) {
    std::vector<uint8_t> ikm = {0x0b, 0x0b, 0x0b, 0x0b, 0x0b};
    std::vector<uint8_t> salt = {0x00, 0x01, 0x02, 0x03};
    std::vector<uint8_t> info = {0xf0, 0xf1, 0xf2};

    auto out1 = crypto.hkdf_sha256(ikm, salt, info, 32);
    auto out2 = crypto.hkdf_sha256(ikm, salt, info, 32);
    EXPECT_EQ(out1, out2);
}

TEST_F(SodiumCryptoTest, HkdfSha256DifferentInfoProducesDifferentOutput) {
    std::vector<uint8_t> ikm = {0x0b, 0x0b, 0x0b};
    std::vector<uint8_t> salt = {0x00, 0x01};
    std::vector<uint8_t> info1 = {0xf0};
    std::vector<uint8_t> info2 = {0xf1};

    auto out1 = crypto.hkdf_sha256(ikm, salt, info1, 32);
    auto out2 = crypto.hkdf_sha256(ikm, salt, info2, 32);
    EXPECT_NE(out1, out2);
}

TEST_F(SodiumCryptoTest, HkdfSha256EmptySalt) {
    std::vector<uint8_t> ikm = {0x01, 0x02, 0x03};
    std::vector<uint8_t> empty_salt;
    std::vector<uint8_t> info = {0xaa};

    auto out = crypto.hkdf_sha256(ikm, empty_salt, info, 32);
    EXPECT_EQ(out.size(), 32u);
}

TEST_F(SodiumCryptoTest, HkdfSha256OutputLengthVariations) {
    std::vector<uint8_t> ikm = {0x01, 0x02, 0x03};
    std::vector<uint8_t> salt = {0x04};
    std::vector<uint8_t> info = {0x05};

    auto out16 = crypto.hkdf_sha256(ikm, salt, info, 16);
    auto out64 = crypto.hkdf_sha256(ikm, salt, info, 64);
    EXPECT_EQ(out16.size(), 16u);
    EXPECT_EQ(out64.size(), 64u);
}

TEST_F(SodiumCryptoTest, HkdfSha256InvalidOutputLenThrows) {
    std::vector<uint8_t> ikm = {0x01};
    std::vector<uint8_t> salt = {0x02};
    std::vector<uint8_t> info = {0x03};

    EXPECT_THROW(crypto.hkdf_sha256(ikm, salt, info, 0), std::runtime_error);
}

// --- SHA-256 ---

TEST_F(SodiumCryptoTest, Sha256ProducesCorrectSize) {
    std::string data = "test";
    auto hash = crypto.sha256(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(data.data()), data.size()));
    EXPECT_EQ(hash.size(), kHash256Size);
}

TEST_F(SodiumCryptoTest, Sha256Deterministic) {
    std::string data = "Lemonade-Nexus";
    auto bytes = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(data.data()), data.size());
    auto hash1 = crypto.sha256(bytes);
    auto hash2 = crypto.sha256(bytes);
    EXPECT_EQ(hash1, hash2);
}

TEST_F(SodiumCryptoTest, Sha256DifferentInputProducesDifferentHash) {
    std::string d1 = "foo";
    std::string d2 = "bar";
    auto h1 = crypto.sha256(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(d1.data()), d1.size()));
    auto h2 = crypto.sha256(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(d2.data()), d2.size()));
    EXPECT_NE(h1, h2);
}

// --- Random bytes ---

TEST_F(SodiumCryptoTest, RandomBytesProducesNonZero) {
    std::array<uint8_t, 32> buf{};
    crypto.random_bytes(std::span<uint8_t>(buf));

    bool all_zero = std::all_of(buf.begin(), buf.end(), [](auto b) { return b == 0; });
    EXPECT_FALSE(all_zero);
}

// --- Ed25519 <-> X25519 conversion ---

TEST_F(SodiumCryptoTest, Ed25519ToX25519ConversionWorks) {
    auto ed_kp = crypto.ed25519_keygen();
    auto x_pk = SodiumCryptoService::ed25519_pk_to_x25519(ed_kp.public_key);
    auto x_sk = SodiumCryptoService::ed25519_sk_to_x25519(ed_kp.private_key);

    // The converted keys should not be zero
    X25519PublicKey zeros_pk{};
    X25519PrivateKey zeros_sk{};
    EXPECT_NE(x_pk, zeros_pk);
    EXPECT_NE(x_sk, zeros_sk);
}

TEST_F(SodiumCryptoTest, Ed25519ToX25519DHWorks) {
    auto alice_ed = crypto.ed25519_keygen();
    auto bob_ed = crypto.ed25519_keygen();

    auto alice_x_sk = SodiumCryptoService::ed25519_sk_to_x25519(alice_ed.private_key);
    auto bob_x_pk   = SodiumCryptoService::ed25519_pk_to_x25519(bob_ed.public_key);
    auto bob_x_sk   = SodiumCryptoService::ed25519_sk_to_x25519(bob_ed.private_key);
    auto alice_x_pk = SodiumCryptoService::ed25519_pk_to_x25519(alice_ed.public_key);

    auto shared_ab = crypto.x25519_dh(alice_x_sk, bob_x_pk);
    auto shared_ba = crypto.x25519_dh(bob_x_sk, alice_x_pk);
    EXPECT_EQ(shared_ab, shared_ba);
}

// --- Service interface ---

TEST_F(SodiumCryptoTest, ServiceName) {
    EXPECT_EQ(crypto.service_name(), "SodiumCryptoService");
}
