#pragma once

#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Crypto/ICryptoProvider.hpp>

namespace nexus::crypto {

/// Concrete libsodium-backed crypto service.
/// Inherits IService for lifecycle and ICryptoProvider for crypto operations.
class SodiumCryptoService : public core::IService<SodiumCryptoService>,
                             public ICryptoProvider<SodiumCryptoService> {
    friend class core::IService<SodiumCryptoService>;
    friend class ICryptoProvider<SodiumCryptoService>;

public:
    SodiumCryptoService() = default;

    // IService
    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "SodiumCryptoService"; }

    // ICryptoProvider
    [[nodiscard]] Ed25519Keypair do_ed25519_keygen();
    [[nodiscard]] Ed25519Signature do_ed25519_sign(const Ed25519PrivateKey& privkey,
                                                    std::span<const uint8_t> message);
    [[nodiscard]] bool do_ed25519_verify(const Ed25519PublicKey& pubkey,
                                          std::span<const uint8_t> message,
                                          const Ed25519Signature& signature);

    [[nodiscard]] X25519Keypair do_x25519_keygen();
    [[nodiscard]] X25519SharedSecret do_x25519_dh(const X25519PrivateKey& our_priv,
                                                    const X25519PublicKey& their_pub);

    [[nodiscard]] AesGcmCiphertext do_aes_gcm_encrypt(const AesGcmKey& key,
                                                        std::span<const uint8_t> plaintext,
                                                        std::span<const uint8_t> aad);
    [[nodiscard]] std::optional<std::vector<uint8_t>> do_aes_gcm_decrypt(
            const AesGcmKey& key,
            const AesGcmCiphertext& ciphertext,
            std::span<const uint8_t> aad);

    [[nodiscard]] std::vector<uint8_t> do_hkdf_sha256(std::span<const uint8_t> ikm,
                                                        std::span<const uint8_t> salt,
                                                        std::span<const uint8_t> info,
                                                        std::size_t output_len);

    void do_random_bytes(std::span<uint8_t> output);

    [[nodiscard]] Hash256 do_sha256(std::span<const uint8_t> data);

    // Utility: convert Ed25519 keypair to X25519 (for hybrid encryption in key wrapping)
    [[nodiscard]] static X25519PublicKey ed25519_pk_to_x25519(const Ed25519PublicKey& ed_pk);
    [[nodiscard]] static X25519PrivateKey ed25519_sk_to_x25519(const Ed25519PrivateKey& ed_sk);

};

} // namespace nexus::crypto
