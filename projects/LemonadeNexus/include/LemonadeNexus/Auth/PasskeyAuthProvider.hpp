#pragma once

#include <LemonadeNexus/Auth/IAuthProvider.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <nlohmann/json.hpp>

#include <atomic>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

// Forward declarations — avoid pulling full headers into every TU
namespace nexus::crypto  { class SodiumCryptoService; }
namespace nexus::storage { class FileStorageService; }

namespace nexus::auth {

/// A single stored WebAuthn credential (ECDSA-P256).
struct StoredCredential {
    std::string credential_id;   // base64url-encoded
    std::string user_id;
    std::vector<uint8_t> public_key_x;  // 32 bytes, P-256 affine X
    std::vector<uint8_t> public_key_y;  // 32 bytes, P-256 affine Y
    uint32_t sign_count{0};
    uint64_t created_at{0};
};

/// PassKey/FIDO2 authentication provider.
/// Implements real WebAuthn assertion verification using ECDSA-P256 (OpenSSL)
/// and file-based credential storage.
class PasskeyAuthProvider : public IAuthProvider<PasskeyAuthProvider> {
    friend class IAuthProvider<PasskeyAuthProvider>;
public:
    /// Construct with dependencies.
    /// @param storage   File storage for credential persistence
    /// @param crypto    Sodium crypto for SHA-256 hashing
    /// @param rp_id     Relying Party ID (e.g. "lemonade-nexus.local")
    /// @param jwt_secret  HMAC secret for JWT session tokens
    PasskeyAuthProvider(nexus::storage::FileStorageService& storage,
                        nexus::crypto::SodiumCryptoService& crypto,
                        std::string rp_id,
                        std::string jwt_secret);

    /// Register a new WebAuthn credential.
    /// Expected JSON:
    ///   { "user_id": "...",
    ///     "credential_id": "base64url...",
    ///     "public_key_x": "hex...",
    ///     "public_key_y": "hex..." }
    [[nodiscard]] AuthResult do_register(const nlohmann::json& registration);

    /// Authenticate via WebAuthn assertion response.
    /// Expected JSON:
    ///   { "assertion": {
    ///       "credential_id": "base64url...",
    ///       "authenticator_data": "base64...",
    ///       "client_data_json": "base64...",
    ///       "signature": "base64..."
    ///     } }
    [[nodiscard]] AuthResult do_authenticate(const nlohmann::json& credentials);

    [[nodiscard]] static constexpr std::string_view auth_provider_name() { return "passkey/fido2"; }

private:
    // --- credential storage ---
    [[nodiscard]] bool save_credential(const StoredCredential& cred);
    [[nodiscard]] std::optional<StoredCredential> lookup_credential(const std::string& credential_id);
    void load_credentials_from_disk();

    // --- WebAuthn assertion verification ---
    [[nodiscard]] bool verify_rp_id_hash(const std::vector<uint8_t>& authenticator_data);
    [[nodiscard]] static bool verify_user_present_flag(const std::vector<uint8_t>& authenticator_data);
    [[nodiscard]] bool verify_ecdsa_p256(const std::vector<uint8_t>& public_key_x,
                                          const std::vector<uint8_t>& public_key_y,
                                          const std::vector<uint8_t>& signed_data,
                                          const std::vector<uint8_t>& der_signature);

    // --- JWT ---
    [[nodiscard]] std::string generate_jwt(const std::string& user_id);

    // --- base64url helpers ---
    [[nodiscard]] static std::vector<uint8_t> base64url_decode(const std::string& input);

    // --- dependencies ---
    nexus::storage::FileStorageService& storage_;
    nexus::crypto::SodiumCryptoService& crypto_;
    std::string rp_id_;
    std::string jwt_secret_;

    // --- WebAuthn clientDataJSON verification ---
    [[nodiscard]] bool verify_client_data_json(const std::vector<uint8_t>& client_data_json_bytes);

    // --- credential persistence ---
    void persist_sign_count(const std::string& credential_id, uint32_t sign_count);

    // --- credential cache (credential_id -> StoredCredential) ---
    mutable std::mutex cache_mutex_;
    std::unordered_map<std::string, StoredCredential> credential_cache_;
    std::atomic<bool> cache_loaded_{false};
};

} // namespace nexus::auth
