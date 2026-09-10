#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>

#include <spdlog/spdlog.h>
#include <sodium.h>

#include <stdexcept>

namespace nexus::crypto {

void SodiumCryptoService::on_start() {
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }

    spdlog::info("[{}] libsodium initialized (version {})", name(), sodium_version_string());
}

void SodiumCryptoService::on_stop() {
    spdlog::info("[{}] stopped", name());
}

// --- Ed25519 ---

Ed25519Keypair SodiumCryptoService::do_ed25519_keygen() {
    Ed25519Keypair kp;
    crypto_sign_ed25519_keypair(kp.public_key.data(), kp.private_key.data());
    return kp;
}

Ed25519Signature SodiumCryptoService::do_ed25519_sign(const Ed25519PrivateKey& privkey,
                                                       std::span<const uint8_t> message) {
    Ed25519Signature sig;
    crypto_sign_ed25519_detached(sig.data(), nullptr,
                                  message.data(), message.size(),
                                  privkey.data());
    return sig;
}

bool SodiumCryptoService::do_ed25519_verify(const Ed25519PublicKey& pubkey,
                                              std::span<const uint8_t> message,
                                              const Ed25519Signature& signature) {
    return crypto_sign_ed25519_verify_detached(signature.data(),
                                                message.data(), message.size(),
                                                pubkey.data()) == 0;
}

// --- X25519 ---

X25519Keypair SodiumCryptoService::do_x25519_keygen() {
    X25519Keypair kp;
    crypto_box_keypair(kp.public_key.data(), kp.private_key.data());
    return kp;
}

X25519SharedSecret SodiumCryptoService::do_x25519_dh(const X25519PrivateKey& our_priv,
                                                       const X25519PublicKey& their_pub) {
    X25519SharedSecret shared;
    if (crypto_scalarmult(shared.data(), our_priv.data(), their_pub.data()) != 0) {
        throw std::runtime_error("X25519 DH failed (low-order point)");
    }
    return shared;
}

// --- Application AEAD: XChaCha20-Poly1305-IETF only ---------------------------
//
// One construction, chosen at compile time rather than from the cpu, so a
// ciphertext is portable across every supported machine. See EncryptedBlob.

EncryptedBlob SodiumCryptoService::do_aead_encrypt(const AeadKey& key,
                                                    std::span<const uint8_t> plaintext,
                                                    std::span<const uint8_t> aad) {
    EncryptedBlob result;
    result.version = kEncryptedBlobVersion;
    result.nonce.resize(kAeadNonceSize);
    result.ciphertext.resize(plaintext.size() + kAeadTagSize);

    // A fresh random nonce per encryption. 24 bytes is wide enough that random
    // selection needs no counter and no coordination to stay collision-free.
    randombytes_buf(result.nonce.data(), result.nonce.size());

    unsigned long long ciphertext_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            result.ciphertext.data(), &ciphertext_len,
            plaintext.data(), plaintext.size(),
            aad.data(), aad.size(),
            nullptr, result.nonce.data(), key.data()) != 0) {
        throw std::runtime_error("XChaCha20-Poly1305 encryption failed");
    }
    result.ciphertext.resize(static_cast<std::size_t>(ciphertext_len));
    return result;
}

std::optional<std::vector<uint8_t>> SodiumCryptoService::do_aead_decrypt(
        const AeadKey& key,
        const EncryptedBlob& blob,
        std::span<const uint8_t> aad) {

    // Version first: one version means one exact construction, so nothing here
    // guesses an algorithm from a field width.
    if (blob.version != kEncryptedBlobVersion) {
        spdlog::warn("[{}] refusing encrypted blob of version {}", name(),
                     static_cast<unsigned>(blob.version));
        return std::nullopt;
    }
    // libsodium reads NPUBBYTES from the nonce with no length argument, so the
    // size must be exact BEFORE the pointer is handed over — a short nonce is a
    // heap over-read, not a decrypt failure.
    if (blob.nonce.size() != kAeadNonceSize) {
        return std::nullopt;
    }
    if (blob.ciphertext.size() < kAeadTagSize) {
        return std::nullopt;
    }

    std::vector<uint8_t> plaintext(blob.ciphertext.size() - kAeadTagSize);
    unsigned long long plaintext_len = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr,
            blob.ciphertext.data(), blob.ciphertext.size(),
            aad.data(), aad.size(),
            blob.nonce.data(), key.data()) != 0) {
        return std::nullopt;
    }
    plaintext.resize(static_cast<std::size_t>(plaintext_len));
    return plaintext;
}

// --- HKDF-SHA256 ---

std::vector<uint8_t> SodiumCryptoService::do_hkdf_sha256(std::span<const uint8_t> ikm,
                                                           std::span<const uint8_t> salt,
                                                           std::span<const uint8_t> info,
                                                           std::size_t output_len) {
    // RFC 5869: output_len must be <= 255 * HashLen (255 * 32 = 8160)
    constexpr std::size_t kMaxHkdfOutput = 255 * crypto_auth_hmacsha256_BYTES;
    if (output_len == 0 || output_len > kMaxHkdfOutput) {
        throw std::runtime_error("HKDF output_len out of range (0, " +
                                 std::to_string(kMaxHkdfOutput) + "]");
    }

    // HKDF extract: PRK = HMAC-SHA256(salt, ikm)
    uint8_t prk[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256_state extract_state;

    if (!salt.empty()) {
        crypto_auth_hmacsha256_init(&extract_state, salt.data(), salt.size());
    } else {
        // RFC 5869: if salt not provided, use string of HashLen zeros
        const uint8_t zero_salt[crypto_auth_hmacsha256_BYTES] = {};
        crypto_auth_hmacsha256_init(&extract_state, zero_salt, sizeof(zero_salt));
    }
    crypto_auth_hmacsha256_update(&extract_state, ikm.data(), ikm.size());
    crypto_auth_hmacsha256_final(&extract_state, prk);

    // HKDF expand
    std::vector<uint8_t> output(output_len);
    uint8_t t_block[crypto_auth_hmacsha256_BYTES] = {};
    std::size_t t_len = 0;
    std::size_t offset = 0;

    for (uint8_t counter = 1; offset < output_len; ++counter) {
        crypto_auth_hmacsha256_state expand_state;
        crypto_auth_hmacsha256_init(&expand_state, prk, sizeof(prk));

        if (t_len > 0) {
            crypto_auth_hmacsha256_update(&expand_state, t_block, t_len);
        }
        if (!info.empty()) {
            crypto_auth_hmacsha256_update(&expand_state, info.data(), info.size());
        }
        crypto_auth_hmacsha256_update(&expand_state, &counter, 1);
        crypto_auth_hmacsha256_final(&expand_state, t_block);
        t_len = sizeof(t_block);

        const auto copy_len = std::min(sizeof(t_block), output_len - offset);
        std::memcpy(output.data() + offset, t_block, copy_len);
        offset += copy_len;
    }

    sodium_memzero(prk, sizeof(prk));
    sodium_memzero(t_block, sizeof(t_block));
    return output;
}

// --- Random ---

void SodiumCryptoService::do_random_bytes(std::span<uint8_t> output) {
    randombytes_buf(output.data(), output.size());
}

// --- SHA-256 ---

Hash256 SodiumCryptoService::do_sha256(std::span<const uint8_t> data) {
    Hash256 hash;
    crypto_hash_sha256(hash.data(), data.data(), data.size());
    return hash;
}

// --- Ed25519 <-> X25519 conversion ---

X25519PublicKey SodiumCryptoService::ed25519_pk_to_x25519(const Ed25519PublicKey& ed_pk) {
    X25519PublicKey x_pk;
    if (crypto_sign_ed25519_pk_to_curve25519(x_pk.data(), ed_pk.data()) != 0) {
        throw std::runtime_error("Failed to convert Ed25519 pk to X25519");
    }
    return x_pk;
}

X25519PrivateKey SodiumCryptoService::ed25519_sk_to_x25519(const Ed25519PrivateKey& ed_sk) {
    X25519PrivateKey x_sk;
    if (crypto_sign_ed25519_sk_to_curve25519(x_sk.data(), ed_sk.data()) != 0) {
        throw std::runtime_error("Failed to convert Ed25519 sk to X25519");
    }
    return x_sk;
}

} // namespace nexus::crypto
