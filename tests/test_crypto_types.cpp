#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>

#include <gtest/gtest.h>

#include <sodium.h>

#include <cstring>
#include <string>
#include <vector>

using namespace nexus::crypto;

class CryptoTypesTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0) << "libsodium init failed";
    }
};

// --- Base64 round-trip ---

TEST_F(CryptoTypesTest, Base64RoundTripEmpty) {
    std::vector<uint8_t> empty;
    auto encoded = to_base64(empty);
    auto decoded = from_base64(encoded);
    EXPECT_TRUE(decoded.empty());
}

TEST_F(CryptoTypesTest, Base64RoundTripSimple) {
    std::vector<uint8_t> data = {0x48, 0x65, 0x6c, 0x6c, 0x6f}; // "Hello"
    auto encoded = to_base64(data);
    EXPECT_EQ(encoded, "SGVsbG8=");
    auto decoded = from_base64(encoded);
    EXPECT_EQ(decoded, data);
}

TEST_F(CryptoTypesTest, Base64RoundTrip32Bytes) {
    std::vector<uint8_t> data(32);
    randombytes_buf(data.data(), data.size());
    auto encoded = to_base64(data);
    auto decoded = from_base64(encoded);
    EXPECT_EQ(decoded, data);
}

TEST_F(CryptoTypesTest, Base64RoundTrip64Bytes) {
    std::vector<uint8_t> data(64);
    randombytes_buf(data.data(), data.size());
    auto encoded = to_base64(data);
    auto decoded = from_base64(encoded);
    EXPECT_EQ(decoded, data);
}

TEST_F(CryptoTypesTest, Base64InvalidInputThrows) {
    EXPECT_THROW(from_base64("!!!invalid!!!"), std::runtime_error);
}

// --- Hex round-trip ---

TEST_F(CryptoTypesTest, HexRoundTripEmpty) {
    std::vector<uint8_t> empty;
    auto encoded = to_hex(empty);
    EXPECT_TRUE(encoded.empty());
    auto decoded = from_hex(encoded);
    EXPECT_TRUE(decoded.empty());
}

TEST_F(CryptoTypesTest, HexRoundTripSimple) {
    std::vector<uint8_t> data = {0xDE, 0xAD, 0xBE, 0xEF};
    auto hex = to_hex(data);
    EXPECT_EQ(hex, "deadbeef");
    auto decoded = from_hex(hex);
    EXPECT_EQ(decoded, data);
}

TEST_F(CryptoTypesTest, HexRoundTrip32Bytes) {
    std::vector<uint8_t> data(32);
    randombytes_buf(data.data(), data.size());
    auto hex = to_hex(data);
    EXPECT_EQ(hex.size(), 64u);
    auto decoded = from_hex(hex);
    EXPECT_EQ(decoded, data);
}

TEST_F(CryptoTypesTest, HexInvalidInputThrows) {
    EXPECT_THROW(from_hex("ZZZZ"), std::runtime_error);
}

// --- Type sizes ---

TEST_F(CryptoTypesTest, KeySizeConstants) {
    EXPECT_EQ(kEd25519PublicKeySize, 32u);
    EXPECT_EQ(kEd25519PrivateKeySize, 64u);
    EXPECT_EQ(kEd25519SignatureSize, 64u);
    EXPECT_EQ(kX25519PublicKeySize, 32u);
    EXPECT_EQ(kX25519PrivateKeySize, 32u);
    EXPECT_EQ(kX25519SharedSize, 32u);
    EXPECT_EQ(kAesGcmKeySize, 32u);
    EXPECT_EQ(kAesGcmNonceSize, 12u);
    EXPECT_EQ(kAesGcmTagSize, 16u);
    EXPECT_EQ(kHash256Size, 32u);
}

TEST_F(CryptoTypesTest, KeypairStructSizes) {
    Ed25519Keypair kp;
    EXPECT_EQ(kp.public_key.size(), kEd25519PublicKeySize);
    EXPECT_EQ(kp.private_key.size(), kEd25519PrivateKeySize);

    X25519Keypair xkp;
    EXPECT_EQ(xkp.public_key.size(), kX25519PublicKeySize);
    EXPECT_EQ(xkp.private_key.size(), kX25519PrivateKeySize);
}
