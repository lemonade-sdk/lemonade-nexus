#pragma once

#include <LemonadeNexus/Auth/IAuthProvider.hpp>
#include <LemonadeNexus/Auth/LinkTokenLedger.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
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

    /// link_token_hash_hex of the token. Empty for a token that an earlier
    /// release minted and stored only on this server (a legacy file).
    std::string token_hash;
    /// The generation consume() spent (see LinkTokenLedger).
    uint32_t generation{0};
    /// Origin of the spend consume() made; refund() needs it.
    std::string spent_by;
    /// The mint event. Signed by the minting Tier 1 server when replication
    /// is wired; a tree operation carries it only when signed.
    std::optional<LinkTokenEvent> grant;
};

/// Discord/WhatsApp-style link tokens (invites): an authenticated owner mints
/// a one-time short-lived token out-of-band (link, QR code) for a target
/// group. A new device presents it in POST /api/join (`link_token`) to be
/// placed under the target; an identity that already joined presents it in
/// POST /api/link/accept (or POST /api/join) to become a member of the target.
/// Tokens are single-use. No server stores a token itself: each token is a
/// set of signed events keyed by link_token_hash_hex(token) (LinkTokenLedger),
/// kept in <data_root>/link_tokens/ledger.json (a storage-vault file) and,
/// with replication wired, sent to every other Tier 1 server so that any of
/// them can redeem it.
///
/// Thread safety: every member function is safe to call concurrently.
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

    /// Look up a token without consuming it. nullopt when it is unknown,
    /// expired, or spent.
    [[nodiscard]] std::optional<LinkTokenRecord> verify(std::string_view token);

    /// Verify and burn a token (single use). Records a Spend event and
    /// publishes it. With a settle window set (set_replication), waits that
    /// long after publishing and refuses the token when another server's
    /// spend of the same generation counts instead (the spend with the
    /// smallest origin key). Blocks the calling thread for the window.
    [[nodiscard]] std::optional<LinkTokenRecord> consume(std::string_view token);

    /// Restore a token that consume() burned for a join that did not use it
    /// (the join was refused, failed, or did not place a new device). Records
    /// and publishes a Refund event, which opens the next generation. The
    /// token keeps its original grant and expiry. Returns false, and restores
    /// nothing, when the token has expired, when this server's spend does not
    /// count, when the generation limit is reached, when it was already
    /// restored, or when the write fails. Call it at most once per consume(),
    /// with the record consume() returned.
    bool refund(std::string_view token, const LinkTokenRecord& record);

    /// Signs a locally made event: sets network_id, origin_pubkey,
    /// origin_seq, and signature. Returns false when it cannot sign.
    using EventSigner = std::function<bool(LinkTokenEvent&)>;
    /// Sends a signed event to the other Tier 1 servers. Returns the number
    /// of servers it was sent to.
    using EventPublisher = std::function<std::size_t(const LinkTokenEvent&)>;

    /// Wire replication. Call before the provider serves requests. Without a
    /// signer, events stay local and unsigned (origin kLinkTokenLocalOrigin).
    /// `settle_window` is the consume() wait described there; zero disables
    /// it (tree operations order the redemption instead).
    void set_replication(EventSigner signer, EventPublisher publisher,
                         std::chrono::milliseconds settle_window);

    /// Add an event another Tier 1 server made. The caller has verified its
    /// origin signature, network, and that the sender is Tier 1. Returns true
    /// when the event is held (new or already held).
    [[nodiscard]] bool apply_replicated(const LinkTokenEvent& event);

    /// Forget every token and delete the token files (this server left
    /// Tier 1).
    void purge();

    /// Test seam: Unix seconds source used in place of the system clock.
    void set_clock_for_testing(std::function<uint64_t()> now_sec);

    /// Default consume() wait without tree operations: long enough for a
    /// spend to cross the backbone between Tier 1 servers.
    static constexpr std::chrono::milliseconds kDefaultSettleWindow{500};

    static constexpr std::chrono::seconds kDefaultTtl{600};
    static constexpr std::chrono::seconds kMaxTtl{
        static_cast<std::chrono::seconds::rep>(kLinkTokenMaxTtlSec)};

private:
    [[nodiscard]] uint64_t now_sec() const;
    /// Set the event time, then sign `e` when `sign` is true and the signer
    /// succeeds; otherwise mark it local and unsigned. Caller holds mutex_.
    void author_locked(LinkTokenEvent& e, bool sign);
    /// Persist the ledger. Caller holds mutex_.
    [[nodiscard]] bool save_locked();
    void load();
    [[nodiscard]] static LinkTokenRecord record_from_grant(const LinkTokenEvent& mint);

    // Tokens minted by an earlier release: one plaintext file per token,
    // named by plain SHA-256 of the token, valid on this server only.
    [[nodiscard]] std::filesystem::path legacy_token_path(std::string_view token) const;
    [[nodiscard]] std::optional<LinkTokenRecord> legacy_verify(std::string_view token);
    [[nodiscard]] std::optional<LinkTokenRecord> legacy_consume(std::string_view token);
    bool legacy_refund(std::string_view token, const LinkTokenRecord& record);

    storage::FileStorageService& storage_;
    crypto::SodiumCryptoService& crypto_;

    mutable std::mutex           mutex_;
    LinkTokenLedger              ledger_;
    EventSigner                  signer_;
    EventPublisher               publisher_;
    std::chrono::milliseconds    settle_window_{0};
    std::string                  self_origin_;   ///< origin of the last signed local event
    uint64_t                     local_seq_{0};
    std::function<uint64_t()>    clock_;
};

} // namespace nexus::auth
