// Regression tests for lnsdk::BoringtunMesh mesh-key derivation.
//
// derive_keypair() must be a STABLE, deterministic function of the device
// seed so a client re-join presents the same Curve25519 key the server
// already knows (a fresh key each launch left a stale server peer and broke
// the tunnel after the first session). These tests pin: determinism, the
// X25519 clamp, pub == scalarmult_base(priv), seed-sensitivity, and that the
// key is the domain-separated keyed-BLAKE2b of the seed (not the RNG path).

#include <gtest/gtest.h>
#include <LemonadeNexusSDK/BoringtunMesh.hpp>
#include <sodium.h>

#include <array>
#include <cstdint>
#include <cstring>

using lnsdk::BoringtunMesh;

namespace {

std::array<uint8_t, 32> decode32(const std::string& b64) {
    std::array<uint8_t, 32> out{};
    EXPECT_EQ(sodium_base642bin(out.data(), out.size(), b64.c_str(), b64.size(),
                                nullptr, nullptr, nullptr,
                                sodium_base64_VARIANT_ORIGINAL),
              0);
    return out;
}

std::array<uint8_t, 32> filled_seed(uint8_t byte) {
    std::array<uint8_t, 32> seed{};
    seed.fill(byte);
    return seed;
}

} // namespace

TEST(BoringtunKeys, DeriveIsDeterministic) {
    ASSERT_GE(sodium_init(), 0);
    auto seed = filled_seed(0x11);
    auto k1 = BoringtunMesh::derive_keypair(seed);
    auto k2 = BoringtunMesh::derive_keypair(seed);
    EXPECT_EQ(k1.first, k2.first);    // same private key
    EXPECT_EQ(k1.second, k2.second);  // same public key
}

TEST(BoringtunKeys, DerivedPrivateKeyIsClamped) {
    ASSERT_GE(sodium_init(), 0);
    auto priv = decode32(BoringtunMesh::derive_keypair(filled_seed(0x22)).first);
    EXPECT_EQ(priv[0] & 0x07, 0);       // low 3 bits cleared
    EXPECT_EQ(priv[31] & 0x80, 0);      // top bit cleared
    EXPECT_EQ(priv[31] & 0x40, 0x40);   // bit 6 set
}

TEST(BoringtunKeys, PublicKeyMatchesScalarmultBase) {
    ASSERT_GE(sodium_init(), 0);
    auto kp = BoringtunMesh::derive_keypair(filled_seed(0x33));
    auto priv = decode32(kp.first);
    auto pub = decode32(kp.second);
    unsigned char expect[32];
    ASSERT_EQ(crypto_scalarmult_base(expect, priv.data()), 0);
    EXPECT_EQ(std::memcmp(expect, pub.data(), 32), 0);
}

TEST(BoringtunKeys, DifferentSeedsDeriveDifferentKeys) {
    ASSERT_GE(sodium_init(), 0);
    EXPECT_NE(BoringtunMesh::derive_keypair(filled_seed(0x01)).first,
              BoringtunMesh::derive_keypair(filled_seed(0x02)).first);
}

// The private key is the domain-separated keyed-BLAKE2b of the seed under the
// "ln-mesh-x25519" context, then X25519-clamped — not a random key and not the
// seed used verbatim for another purpose. Recompute it independently.
TEST(BoringtunKeys, DerivesViaKeyedBlake2bContext) {
    ASSERT_GE(sodium_init(), 0);
    auto seed = filled_seed(0x44);
    unsigned char key[crypto_generichash_KEYBYTES] = {
        'l', 'n', '-', 'm', 'e', 's', 'h', '-', 'x', '2', '5', '5', '1', '9'};
    unsigned char expect[32];
    ASSERT_EQ(crypto_generichash(expect, sizeof expect, seed.data(), seed.size(),
                                 key, sizeof key),
              0);
    expect[0] &= 248;
    expect[31] &= 127;
    expect[31] |= 64;
    auto priv = decode32(BoringtunMesh::derive_keypair(seed).first);
    EXPECT_EQ(std::memcmp(expect, priv.data(), 32), 0);
}
