#pragma once

#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Auth/IAuthProvider.hpp>
#include <LemonadeNexus/Auth/PasswordAuthProvider.hpp>
#include <LemonadeNexus/Auth/PasskeyAuthProvider.hpp>
#include <LemonadeNexus/Auth/TokenLinkAuthProvider.hpp>
#include <LemonadeNexus/Auth/Ed25519AuthProvider.hpp>

#include <nlohmann/json.hpp>

#include <chrono>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

// Forward declarations
namespace nexus::crypto  { class SodiumCryptoService; }
namespace nexus::storage { class FileStorageService; }

namespace nexus::auth {

// Forward declaration — full definition in AuthMiddleware.hpp
struct SessionClaims;

/// Dispatches authentication requests to the appropriate provider.
class AuthService : public core::IService<AuthService> {
    friend class core::IService<AuthService>;
public:
    /// Construct with dependencies needed by PasskeyAuthProvider.
    /// @param storage     File storage service for credential persistence
    /// @param crypto      Sodium crypto service for SHA-256
    /// @param rp_id       WebAuthn relying party ID (e.g. "lemonade-nexus.local")
    /// @param jwt_secret  HMAC-SHA256 secret for JWT session tokens
    /// @param jwt_secret MUST be provided — no default for security.
    ///                   Use a strong random secret (e.g. 32+ bytes hex).
    AuthService(storage::FileStorageService& storage,
                crypto::SodiumCryptoService& crypto,
                std::string rp_id,
                std::string jwt_secret);

    /// Route an authentication request to the correct provider based on "method" field.
    [[nodiscard]] AuthResult authenticate(const nlohmann::json& request);

    /// Register a new passkey/FIDO2 credential.
    [[nodiscard]] AuthResult register_passkey(const nlohmann::json& registration);

    /// Issue an Ed25519 challenge nonce for the given pubkey.
    [[nodiscard]] nlohmann::json issue_ed25519_challenge(const std::string& pubkey_b64);

    /// Revoke an Ed25519 identity (e.g. on device deletion): future
    /// authentication attempts for this key are rejected. pubkey_b64 is the raw
    /// base64 key (no "ed25519:" prefix). Idempotent.
    bool revoke_ed25519(const std::string& pubkey_b64);

    /// Mint a single-use device-link token bound to the owner's Customer group.
    [[nodiscard]] std::optional<std::pair<std::string, LinkTokenRecord>>
    mint_link_token(const std::string& owner_user_id, const std::string& owner_pubkey,
                    const std::string& group_node_id, std::chrono::seconds ttl);

    /// Verify and burn a device-link token (single use).
    [[nodiscard]] std::optional<LinkTokenRecord> consume_link_token(std::string_view token);

    /// Validate an existing session token (JWT).
    [[nodiscard]] bool validate_session(std::string_view token);

    /// Validate a JWT and extract all claims from it.
    /// Returns std::nullopt if the token is invalid or expired.
    [[nodiscard]] std::optional<SessionClaims> validate_session_claims(const std::string& token);

    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "AuthService"; }

private:
    using ProviderVariant = std::variant<
        PasswordAuthProvider,
        PasskeyAuthProvider,
        TokenLinkAuthProvider,
        Ed25519AuthProvider
    >;

    PasswordAuthProvider  password_provider_;
    PasskeyAuthProvider   passkey_provider_;
    TokenLinkAuthProvider token_link_provider_;
    Ed25519AuthProvider   ed25519_provider_;
    std::string           jwt_secret_;
};

} // namespace nexus::auth
