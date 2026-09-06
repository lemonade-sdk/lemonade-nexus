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

// --- Application AEAD: XChaCha20-Poly1305-IETF, and nothing else -------------
//
// One algorithm on every cpu. The cipher is NOT chosen from hardware
// capability: a ciphertext written anywhere must open anywhere with the same
// key, so AES-NI, cpu model, VM host and architecture are not inputs to the
// format. libsodium ships AES-256-GCM only as aesni/armcrypto, so an
// AES-encrypted object is unreadable on a machine without those instructions —
// which is exactly the property this rules out.
static constexpr std::size_t kAeadKeySize   = 32;
static constexpr std::size_t kAeadNonceSize = 24;
static constexpr std::size_t kAeadTagSize   = 16;
using AeadKey = std::array<uint8_t, kAeadKeySize>;

/// The one encrypted-object format. `version` names an exact construction, so a
/// reader never infers the algorithm from field widths.
///
///   version 1 = XChaCha20-Poly1305-IETF, 24-byte random nonce, 16-byte tag
///
/// Unknown versions fail closed. There is deliberately no algorithm field:
/// negotiation would put the choice back on the wire.
static constexpr uint8_t kEncryptedBlobVersion = 1;

struct EncryptedBlob {
    uint8_t              version{kEncryptedBlobVersion};
    std::vector<uint8_t> nonce;       // exactly kAeadNonceSize
    std::vector<uint8_t> ciphertext;  // includes the appended tag
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

// from_base64 accepts standard AND url-safe-unpadded, to_base64 emits only
// standard — so one key has several textual forms. Any string used as a security
// identity (revocation, lookup, ACL principal) MUST be canonicalized first,
// otherwise an exact-string compare is bypassed by re-encoding the same key.
// Returns empty on undecodable input; strips an optional "ed25519:" prefix.
[[nodiscard]] std::string canonical_key_b64(std::string_view encoded);

// --- Hex helpers ---
[[nodiscard]] std::string to_hex(std::span<const uint8_t> data);
[[nodiscard]] std::vector<uint8_t> from_hex(std::string_view hex);

} // namespace nexus::crypto
