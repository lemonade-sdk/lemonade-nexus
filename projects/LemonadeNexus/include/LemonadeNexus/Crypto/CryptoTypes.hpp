#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace nexus::crypto {

// --- Ed25519 ---
static constexpr std::size_t kEd25519PublicKeySize  = 32;
static constexpr std::size_t kEd25519PrivateKeySize = 64; // libsodium stores seed+pk
static constexpr std::size_t kEd25519SeedSize       = 32;
static constexpr std::size_t kEd25519SignatureSize   = 64;

using Ed25519PublicKey  = std::array<uint8_t, kEd25519PublicKeySize>;
using Ed25519PrivateKey = std::array<uint8_t, kEd25519PrivateKeySize>;
using Ed25519Seed       = std::array<uint8_t, kEd25519SeedSize>;
using Ed25519Signature  = std::array<uint8_t, kEd25519SignatureSize>;

struct Ed25519Keypair {
    Ed25519PublicKey  public_key{};
    Ed25519PrivateKey private_key{};
};

// --- X25519 (Diffie-Hellman) ---
static constexpr std::size_t kX25519PublicKeySize  = 32;
static constexpr std::size_t kX25519PrivateKeySize = 32;
static constexpr std::size_t kX25519SharedSize     = 32;

using X25519PublicKey  = std::array<uint8_t, kX25519PublicKeySize>;
using X25519PrivateKey = std::array<uint8_t, kX25519PrivateKeySize>;
using X25519SharedSecret = std::array<uint8_t, kX25519SharedSize>;

struct X25519Keypair {
    X25519PublicKey  public_key{};
    X25519PrivateKey private_key{};
};

// --- AES-256-GCM / XChaCha20-Poly1305 AEAD ---
static constexpr std::size_t kAesGcmKeySize        = 32;
static constexpr std::size_t kAesGcmNonceSize       = 12;
static constexpr std::size_t kAesGcmTagSize         = 16;
using AesGcmKey   = std::array<uint8_t, kAesGcmKeySize>;
using AesGcmNonce = std::array<uint8_t, kAesGcmNonceSize>;

struct AesGcmCiphertext {
    std::vector<uint8_t> ciphertext; // includes appended tag
    std::vector<uint8_t> nonce;      // 12 bytes
};

// --- HKDF ---
static constexpr std::size_t kHkdfSaltSize = 32;
using HkdfSalt = std::array<uint8_t, kHkdfSaltSize>;

// --- Hashing ---
static constexpr std::size_t kHash256Size = 32;
using Hash256 = std::array<uint8_t, kHash256Size>;

// --- Base64 helpers ---
[[nodiscard]] std::string to_base64(std::span<const uint8_t> data);
[[nodiscard]] std::vector<uint8_t> from_base64(std::string_view encoded);

// --- Hex helpers ---
[[nodiscard]] std::string to_hex(std::span<const uint8_t> data);
[[nodiscard]] std::vector<uint8_t> from_hex(std::string_view hex);

} // namespace nexus::crypto
