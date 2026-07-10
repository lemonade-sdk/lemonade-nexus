#pragma once

#include <LemonadeNexus/Auth/IAuthProvider.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

// Forward declarations
namespace nexus::crypto  { class SodiumCryptoService; }
namespace nexus::storage { class FileStorageService; }

namespace nexus::auth {

/// A minted device-link token: binds the bearer to the owner's Customer group.
struct LinkTokenRecord {
    std::string owner_user_id;
    std::string owner_pubkey;   // "ed25519:base64..." of the minting session
    std::string group_node_id;  // Customer group the joining device lands under
    uint64_t    created_at{0};
    uint64_t    expires_at{0};
};

/// Discord/WhatsApp-style device-link tokens: an authenticated owner mints a
/// one-time short-lived token out-of-band (link, QR code); the joining device
/// presents it in POST /api/join (`link_token`) to be placed under the owner's
/// Customer group. Tokens are single-use and stored hashed at rest under
/// <data_root>/link_tokens/.
class TokenLinkAuthProvider : public IAuthProvider<TokenLinkAuthProvider> {
    friend class IAuthProvider<TokenLinkAuthProvider>;
public:
    TokenLinkAuthProvider(storage::FileStorageService& storage,
                          crypto::SodiumCryptoService& crypto);

    [[nodiscard]] AuthResult do_authenticate(const nlohmann::json& credentials);
    [[nodiscard]] static constexpr std::string_view auth_provider_name() { return "token-link"; }

    /// Mint a single-use link token bound to the owner's group.
    /// Returns the plaintext token (only ever returned here) and its record.
    [[nodiscard]] std::optional<std::pair<std::string, LinkTokenRecord>>
    mint(const std::string& owner_user_id, const std::string& owner_pubkey,
         const std::string& group_node_id, std::chrono::seconds ttl);

    /// Look up a token without consuming it. Expired tokens are removed.
    [[nodiscard]] std::optional<LinkTokenRecord> verify(std::string_view token);

    /// Verify and burn a token (single use).
    [[nodiscard]] std::optional<LinkTokenRecord> consume(std::string_view token);

    static constexpr std::chrono::seconds kDefaultTtl{600};
    static constexpr std::chrono::seconds kMaxTtl{3600};

private:
    [[nodiscard]] std::filesystem::path token_path(std::string_view token) const;

    storage::FileStorageService& storage_;
    crypto::SodiumCryptoService& crypto_;
};

} // namespace nexus::auth
