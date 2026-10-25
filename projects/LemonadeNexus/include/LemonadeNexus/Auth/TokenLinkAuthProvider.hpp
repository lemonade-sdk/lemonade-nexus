#pragma once

#include <LemonadeNexus/Auth/IAuthProvider.hpp>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// Forward declarations
namespace nexus::crypto  { class SodiumCryptoService; }
namespace nexus::storage { class FileStorageService; }

namespace nexus::auth {

/// A minted link token (an invite): binds the bearer to a target group.
struct LinkTokenRecord {
    std::string owner_user_id;
    std::string owner_pubkey;   // "ed25519:base64..." of the minting session (the inviter)
    std::string group_node_id;  // target group: a new device lands under it; an
                                // existing identity becomes a member of it
    uint64_t    created_at{0};
    uint64_t    expires_at{0};
    /// Permissions an existing identity gets on the target when it accepts
    /// (see tree::rules::invite_acceptance_refusal). Not used to place a new
    /// device. A record stored without the field reads as
    /// tree::rules::kDefaultInvitePermissions; acceptance re-checks them.
    std::vector<std::string> permissions;
};

/// Discord/WhatsApp-style link tokens (invites): an authenticated owner mints
/// a one-time short-lived token out-of-band (link, QR code) for a target
/// group. A new device presents it in POST /api/join (`link_token`) to be
/// placed under the target; an identity that already joined presents it in
/// POST /api/link/accept (or POST /api/join) to become a member of the target.
/// Tokens are single-use and stored hashed at rest under
/// <data_root>/link_tokens/ on the server that minted them.
class TokenLinkAuthProvider : public IAuthProvider<TokenLinkAuthProvider> {
    friend class IAuthProvider<TokenLinkAuthProvider>;
public:
    TokenLinkAuthProvider(storage::FileStorageService& storage,
                          crypto::SodiumCryptoService& crypto);

    [[nodiscard]] AuthResult do_authenticate(const nlohmann::json& credentials);
    [[nodiscard]] static constexpr std::string_view auth_provider_name() { return "token-link"; }

    /// Mint a single-use link token bound to `group_node_id` that carries
    /// `permissions` for an accepting member. The caller checks that the owner
    /// may invite into the group with those permissions. Returns the
    /// plaintext token (only ever returned here) and its record.
    [[nodiscard]] std::optional<std::pair<std::string, LinkTokenRecord>>
    mint(const std::string& owner_user_id, const std::string& owner_pubkey,
         const std::string& group_node_id, std::chrono::seconds ttl,
         std::vector<std::string> permissions = {});

    /// Look up a token without consuming it. Expired tokens are removed.
    [[nodiscard]] std::optional<LinkTokenRecord> verify(std::string_view token);

    /// Verify and burn a token (single use).
    [[nodiscard]] std::optional<LinkTokenRecord> consume(std::string_view token);

    /// Restore a token that consume() burned for a join that did not use it
    /// (the join was refused, failed, or did not place a new device). The
    /// token keeps its original record and expiry. Returns false, and restores
    /// nothing, when the record has expired, when a file for the token
    /// already exists, or when the write fails. Call it at most once per
    /// consume(), with the record consume() returned.
    bool refund(std::string_view token, const LinkTokenRecord& record);

    static constexpr std::chrono::seconds kDefaultTtl{600};
    static constexpr std::chrono::seconds kMaxTtl{3600};

private:
    [[nodiscard]] std::filesystem::path token_path(std::string_view token) const;

    storage::FileStorageService& storage_;
    crypto::SodiumCryptoService& crypto_;
};

} // namespace nexus::auth
