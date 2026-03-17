#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>

#include <spdlog/spdlog.h>
#include <sodium.h>

#include <stdexcept>

namespace nexus::crypto {

void SodiumCryptoService::on_start() {
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialize libsodium");
    }

    // AES-256-GCM requires hardware support (AES-NI on x86, ARM crypto on ARM64)
    aes_gcm_available_ = (crypto_aead_aes256gcm_is_available() != 0);
    if (!aes_gcm_available_) {
        spdlog::warn("[{}] AES-256-GCM not available — using XChaCha20-Poly1305 fallback "
                     "(equally secure, software-only)", name());
    } else {
        spdlog::info("[{}] AES-256-GCM hardware support confirmed", name());
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

// --- AEAD: AES-256-GCM (hardware) or XChaCha20-Poly1305 (software fallback) ---
//
// Both use 32-byte keys and 16-byte auth tags.  We distinguish them by nonce
// size: AES-GCM uses 12 bytes, XChaCha20-Poly1305 uses 24 bytes.  This makes
// the stored format backward-compatible: old ciphertexts with 12-byte nonces
// decrypt with AES-GCM, new ciphertexts written on non-AES-GCM CPUs have
// 24-byte nonces and are decrypted with XChaCha20-Poly1305.

AesGcmCiphertext SodiumCryptoService::do_aes_gcm_encrypt(const AesGcmKey& key,
                                                           std::span<const uint8_t> plaintext,
                                                           std::span<const uint8_t> aad) {
    AesGcmCiphertext result;

    if (aes_gcm_available_) {
        // Hardware AES-256-GCM path
        result.nonce.resize(crypto_aead_aes256gcm_NPUBBYTES); // 12 bytes
        result.ciphertext.resize(plaintext.size() + crypto_aead_aes256gcm_ABYTES);
        randombytes_buf(result.nonce.data(), result.nonce.size());

        unsigned long long ciphertext_len = 0;
        if (crypto_aead_aes256gcm_encrypt(
                result.ciphertext.data(), &ciphertext_len,
                plaintext.data(), plaintext.size(),
                aad.data(), aad.size(),
                nullptr, result.nonce.data(), key.data()) != 0) {
            throw std::runtime_error("AES-256-GCM encryption failed");
        }
        result.ciphertext.resize(static_cast<std::size_t>(ciphertext_len));
    } else {
        // XChaCha20-Poly1305 software fallback
        result.nonce.resize(crypto_aead_xchacha20poly1305_ietf_NPUBBYTES); // 24 bytes
        result.ciphertext.resize(plaintext.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
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
    }

    return result;
}

std::optional<std::vector<uint8_t>> SodiumCryptoService::do_aes_gcm_decrypt(
        const AesGcmKey& key,
        const AesGcmCiphertext& ct,
        std::span<const uint8_t> aad) {

    // Detect cipher by nonce size: 12 = AES-GCM, 24 = XChaCha20-Poly1305
    if (ct.nonce.size() == crypto_aead_xchacha20poly1305_ietf_NPUBBYTES) {
        // XChaCha20-Poly1305 path (24-byte nonce)
        if (ct.ciphertext.size() < crypto_aead_xchacha20poly1305_ietf_ABYTES) {
            return std::nullopt;
        }
        std::vector<uint8_t> plaintext(
            ct.ciphertext.size() - crypto_aead_xchacha20poly1305_ietf_ABYTES);
        unsigned long long plaintext_len = 0;

        if (crypto_aead_xchacha20poly1305_ietf_decrypt(
                plaintext.data(), &plaintext_len,
                nullptr,
                ct.ciphertext.data(), ct.ciphertext.size(),
                aad.data(), aad.size(),
                ct.nonce.data(), key.data()) != 0) {
            return std::nullopt;
        }
        plaintext.resize(static_cast<std::size_t>(plaintext_len));
        return plaintext;
    }

    // AES-256-GCM path (12-byte nonce)
    if (!aes_gcm_available_) {
        spdlog::error("[{}] Cannot decrypt AES-256-GCM ciphertext: no hardware support. "
                      "This data was encrypted on a CPU with AES-NI.", name());
        return std::nullopt;
    }

    if (ct.ciphertext.size() < crypto_aead_aes256gcm_ABYTES) {
        return std::nullopt;
    }

    std::vector<uint8_t> plaintext(ct.ciphertext.size() - crypto_aead_aes256gcm_ABYTES);
    unsigned long long plaintext_len = 0;

    if (crypto_aead_aes256gcm_decrypt(
            plaintext.data(), &plaintext_len,
            nullptr,
            ct.ciphertext.data(), ct.ciphertext.size(),
            aad.data(), aad.size(),
            ct.nonce.data(), key.data()) != 0) {
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
