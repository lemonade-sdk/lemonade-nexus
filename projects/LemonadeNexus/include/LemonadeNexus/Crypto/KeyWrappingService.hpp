#pragma once

#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace nexus::crypto {

/// A wrapped Ed25519 private key: AES-256-GCM ciphertext + nonce.
struct WrappedKey {
    AesGcmCiphertext ciphertext;  // encrypted Ed25519PrivateKey (64 bytes)
    std::string      label;       // human-readable identifier
};

/// Result of a key delegation operation.
struct DelegationResult {
    Ed25519Keypair   child_keypair;       // child's new Ed25519 keypair
    WrappedKey       wrapped_child_key;   // child privkey wrapped with a random wrapping key
    AesGcmCiphertext encrypted_wk;       // wrapping key encrypted to child's X25519 pubkey
    X25519PublicKey  ephemeral_pubkey{};  // ephemeral X25519 pubkey needed by child to derive DH
    bool             success{false};
    std::string      error_message;
};

/// Service for wrapping / unwrapping Ed25519 management keys.
///
/// Key unlock flow:
///   1. WebAuthn assertion provides a credential secret
///   2. HKDF-SHA256(secret, salt="lemonade-nexus-mgmt-key", info=pubkey) → AES-256 key
///   3. AES-GCM decrypt the wrapped Ed25519 private key
///
/// Delegation flow:
///   1. Generate child Ed25519 keypair
///   2. Generate random wrapping key (WK)
///   3. AES-GCM(WK, child privkey) → wrapped child key
///   4. X25519-encrypt WK to child's public key (derived from Ed25519 via Curve25519)
class KeyWrappingService : public core::IService<KeyWrappingService> {
    friend class core::IService<KeyWrappingService>;

public:
    KeyWrappingService(SodiumCryptoService& crypto,
                       storage::FileStorageService& storage);

    // IService
    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "KeyWrappingService"; }

    /// Wrap an Ed25519 private key using a passphrase-derived AES key.
    /// @param privkey     The private key to wrap
    /// @param passphrase  Raw bytes from WebAuthn credential or password
    /// @param pubkey      The corresponding public key (used as HKDF info)
    [[nodiscard]] WrappedKey wrap_key(const Ed25519PrivateKey& privkey,
                                      std::span<const uint8_t> passphrase,
                                      const Ed25519PublicKey& pubkey);

    /// Unwrap an Ed25519 private key.
    /// @param wrapped     The wrapped key ciphertext
    /// @param passphrase  Raw bytes from WebAuthn credential or password
    /// @param pubkey      The corresponding public key (used as HKDF info)
    [[nodiscard]] std::optional<Ed25519PrivateKey> unwrap_key(
            const WrappedKey& wrapped,
            std::span<const uint8_t> passphrase,
            const Ed25519PublicKey& pubkey);

    /// Generate a new Ed25519 keypair and wrap the private key.
    /// Stores the wrapped key and public key to disk under data/identity/.
    [[nodiscard]] Ed25519Keypair generate_and_store_identity(
            std::span<const uint8_t> passphrase);

    /// Load the server's identity public key from disk.
    [[nodiscard]] std::optional<Ed25519PublicKey> load_identity_pubkey() const;

    /// Unlock the server's identity private key from disk.
    [[nodiscard]] std::optional<Ed25519PrivateKey> unlock_identity(
            std::span<const uint8_t> passphrase);

    /// Delegate authority: generate a child keypair, wrap it, and encrypt
    /// the wrapping key to the child's derived X25519 public key.
    [[nodiscard]] DelegationResult delegate_key(
            std::span<const uint8_t> parent_passphrase);

private:
    /// How a wrapping key is bound to this machine.
    ///   Legacy  — HKDF(passphrase, salt, info=pubkey). Reproduces the original
    ///             (pre-hardening) derivation. Used ONLY to read & migrate old
    ///             keypair.enc files; never written for new keys.
    ///   Machine — HKDF(passphrase ‖ local_secret, salt, info=pubkey ‖ machine_id).
    ///             Mixes in a per-install random secret (data/identity/wrap_local.key,
    ///             owner-only) and /etc/machine-id, so a copied keypair.enc is useless
    ///             on another host and useless without the separate local-secret file.
    ///             This closes the "empty passphrase ⇒ keypair.enc is plaintext-
    ///             equivalent" weakness. (A TPM-sealed binding is the stronger future
    ///             layer — see docs/TEE-Attestation-Hardening-Plan.md §2 / wrap_seal TODO.)
    enum class WrapBinding { Legacy, Machine };

    /// Derive an AES-256 key from a passphrase using HKDF-SHA256, bound per `binding`.
    [[nodiscard]] AesGcmKey derive_wrapping_key(
            std::span<const uint8_t> passphrase,
            const Ed25519PublicKey& pubkey,
            WrapBinding binding) const;

    [[nodiscard]] WrappedKey wrap_with_binding(const Ed25519PrivateKey& privkey,
                                               std::span<const uint8_t> passphrase,
                                               const Ed25519PublicKey& pubkey,
                                               WrapBinding binding);
    [[nodiscard]] std::optional<Ed25519PrivateKey> unwrap_with_binding(
            const WrappedKey& wrapped,
            std::span<const uint8_t> passphrase,
            const Ed25519PublicKey& pubkey,
            WrapBinding binding);

    /// Per-install 32-byte secret, created (owner-only) on first use and reused.
    [[nodiscard]] std::vector<uint8_t> machine_binding_secret() const;
    /// Raw /etc/machine-id bytes (trimmed), or empty if unavailable.
    [[nodiscard]] std::vector<uint8_t> machine_id_bytes() const;

    /// Re-wrap a successfully-unlocked legacy keypair.enc under the machine binding,
    /// preserving the original as a ".legacy.bak" for rollback safety.
    void migrate_legacy_identity(const std::filesystem::path& enc_path,
                                 const Ed25519PrivateKey& privkey,
                                 std::span<const uint8_t> passphrase,
                                 const Ed25519PublicKey& pubkey);

    SodiumCryptoService&        crypto_;
    storage::FileStorageService& storage_;
};

} // namespace nexus::crypto
