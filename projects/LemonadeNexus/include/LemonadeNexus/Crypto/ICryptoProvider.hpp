#pragma once

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <concepts>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace nexus::crypto {

/// CRTP base for cryptographic operations.
/// Derived must implement:
///   Ed25519Keypair do_ed25519_keygen()
///   Ed25519Signature do_ed25519_sign(const Ed25519PrivateKey&, std::span<const uint8_t>)
///   bool do_ed25519_verify(const Ed25519PublicKey&, std::span<const uint8_t>, const Ed25519Signature&)
///   X25519Keypair do_x25519_keygen()
///   X25519SharedSecret do_x25519_dh(const X25519PrivateKey&, const X25519PublicKey&)
///   EncryptedBlob do_aead_encrypt(const AeadKey&, std::span<const uint8_t>, std::span<const uint8_t>)
///   std::optional<std::vector<uint8_t>> do_aead_decrypt(const AeadKey&, const EncryptedBlob&, std::span<const uint8_t>)
///   std::vector<uint8_t> do_hkdf_sha256(std::span<const uint8_t>, std::span<const uint8_t>, std::span<const uint8_t>, std::size_t)
///   void do_random_bytes(std::span<uint8_t>)
///   Hash256 do_sha256(std::span<const uint8_t>)
template <typename Derived>
class ICryptoProvider {
public:
    [[nodiscard]] Ed25519Keypair ed25519_keygen() {
        return self().do_ed25519_keygen();
    }

    [[nodiscard]] Ed25519Signature ed25519_sign(const Ed25519PrivateKey& privkey,
                                                 std::span<const uint8_t> message) {
        return self().do_ed25519_sign(privkey, message);
    }

    [[nodiscard]] bool ed25519_verify(const Ed25519PublicKey& pubkey,
                                       std::span<const uint8_t> message,
                                       const Ed25519Signature& signature) {
        return self().do_ed25519_verify(pubkey, message, signature);
    }

    [[nodiscard]] X25519Keypair x25519_keygen() {
        return self().do_x25519_keygen();
    }

    [[nodiscard]] X25519SharedSecret x25519_dh(const X25519PrivateKey& our_priv,
                                                const X25519PublicKey& their_pub) {
        return self().do_x25519_dh(our_priv, their_pub);
    }

    [[nodiscard]] EncryptedBlob aead_encrypt(const AeadKey& key,
                                                     std::span<const uint8_t> plaintext,
                                                     std::span<const uint8_t> aad = {}) {
        return self().do_aead_encrypt(key, plaintext, aad);
    }

    [[nodiscard]] std::optional<std::vector<uint8_t>> aead_decrypt(
            const AeadKey& key,
            const EncryptedBlob& blob,
            std::span<const uint8_t> aad = {}) {
        return self().do_aead_decrypt(key, blob, aad);
    }

    [[nodiscard]] std::vector<uint8_t> hkdf_sha256(std::span<const uint8_t> ikm,
                                                     std::span<const uint8_t> salt,
                                                     std::span<const uint8_t> info,
                                                     std::size_t output_len) {
        return self().do_hkdf_sha256(ikm, salt, info, output_len);
    }

    void random_bytes(std::span<uint8_t> output) {
        self().do_random_bytes(output);
    }

    [[nodiscard]] Hash256 sha256(std::span<const uint8_t> data) {
        return self().do_sha256(data);
    }

protected:
    ~ICryptoProvider() = default;

private:
    [[nodiscard]] Derived& self() { return static_cast<Derived&>(*this); }
    [[nodiscard]] const Derived& self() const { return static_cast<const Derived&>(*this); }
};

/// Concept constraining a valid ICryptoProvider implementation.
template <typename T>
concept CryptoProviderType = requires(T t,
                                       const Ed25519PrivateKey& ed_priv,
                                       const Ed25519PublicKey& ed_pub,
                                       const Ed25519Signature& ed_sig,
                                       const X25519PrivateKey& x_priv,
                                       const X25519PublicKey& x_pub,
                                       const AeadKey& aes_key,
                                       const EncryptedBlob& aes_ct,
                                       std::span<const uint8_t> data,
                                       std::span<uint8_t> out) {
    { t.do_ed25519_keygen() } -> std::same_as<Ed25519Keypair>;
    { t.do_ed25519_sign(ed_priv, data) } -> std::same_as<Ed25519Signature>;
    { t.do_ed25519_verify(ed_pub, data, ed_sig) } -> std::same_as<bool>;
    { t.do_x25519_keygen() } -> std::same_as<X25519Keypair>;
    { t.do_x25519_dh(x_priv, x_pub) } -> std::same_as<X25519SharedSecret>;
    { t.do_aead_encrypt(aes_key, data, data) } -> std::same_as<EncryptedBlob>;
    { t.do_aead_decrypt(aes_key, aes_ct, data) } -> std::same_as<std::optional<std::vector<uint8_t>>>;
    { t.do_hkdf_sha256(data, data, data, std::size_t{}) } -> std::same_as<std::vector<uint8_t>>;
    { t.do_random_bytes(out) } -> std::same_as<void>;
    { t.do_sha256(data) } -> std::same_as<Hash256>;
};

} // namespace nexus::crypto
