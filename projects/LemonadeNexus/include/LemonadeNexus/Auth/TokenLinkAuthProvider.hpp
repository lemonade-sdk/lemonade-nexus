#pragma once

#include <LemonadeNexus/Auth/IAuthProvider.hpp>
#include <LemonadeNexus/Auth/LinkTokenLedger.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
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

/// What mint() hands the inviter, once: the token, the invite code that
/// names the same token, and the record. Neither secret is stored or logged.
struct MintedLinkToken {
    std::string     token;  ///< "lnk_" + 64 hex
    std::string     code;   ///< kLinkCodeDigits decimal digits
    LinkTokenRecord record;
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
/// Every mint also issues an invite code: kLinkCodeDigits decimal digits
/// that name the same token. The mint carries link_code_hash_hex(code), so
/// every replica redeems the code as it redeems the token, against the same
/// single-use generation. A string of exactly kLinkCodeDigits digits in a
/// token position is a code (is_link_code). A code lives at most
/// kLinkCodeMaxTtlSec. Two limits bound guessing, both per server and in
/// memory: a source address that makes kLinkCodeMaxFailuresPerSource wrong
/// code attempts within kLinkCodeFailureWindowSec has its code attempts
/// refused for that long, and after kLinkCodeMaxFailuresPerServer wrong
/// attempts from any addresses within the window the server refuses codes
/// until the window passes. Refused attempts count toward neither limit, so
/// a locked address cannot close codes for everyone. An attacker with N
/// addresses gets at most min(5N, 100) guesses per ten minutes per server.
/// The token is never locked out.
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
    /// `permissions` for an accepting member, and the invite code that names
    /// it. The caller checks that the owner may invite into the group with
    /// those permissions. The code is unique among the unexpired codes this
    /// server holds (it draws again on a collision, a bounded number of
    /// times). Returns the plaintext token and code (only ever returned here)
    /// and the record; nullopt when the owner is at its limit, no free code
    /// was drawn, or the write failed.
    [[nodiscard]] std::optional<MintedLinkToken>
    mint(const std::string& owner_user_id, const std::string& owner_pubkey,
         const std::string& group_node_id, std::chrono::seconds ttl,
         std::vector<std::string> permissions = {});

    /// Look up a token, or the token an invite code names, without consuming
    /// it. nullopt when it is unknown, expired, spent, or (a code) shared by
    /// two unexpired mints or refused by the wrong-code limits. `source` is
    /// the requester's address (empty when unknown); a code that resolves to
    /// nothing counts as a wrong attempt for it. Ignored for a token.
    [[nodiscard]] std::optional<LinkTokenRecord> verify(std::string_view token_or_code,
                                                        std::string_view source = {});

    /// Verify and burn a token on this server, presented as the token or as
    /// its invite code; both spend the same generation. Records a Spend event
    /// and publishes it. Single use across servers is enforced by the tree
    /// operation that redeems the token: it carries the signed grant, and
    /// consensus refuses a second redemption on every replica (TreeOps.hpp).
    /// `source` as in verify().
    [[nodiscard]] std::optional<LinkTokenRecord> consume(std::string_view token_or_code,
                                                         std::string_view source = {});

    /// Restore a token that consume() burned for a join that did not use it
    /// (the join was refused, failed, or did not place a new device). Records
    /// and publishes a Refund event, which opens the next generation. The
    /// token keeps its original grant and expiry. Returns false, and restores
    /// nothing, when the token has expired, when this server's spend does not
    /// count, when the generation limit is reached, when it was already
    /// restored, or when the write fails. Call it at most once per consume(),
    /// with the record consume() returned and the same token or code.
    bool refund(std::string_view token_or_code, const LinkTokenRecord& record);

    /// Signs a locally made event: sets network_id, origin_pubkey,
    /// origin_seq, and signature, and code_signature when the event carries
    /// a code_hash. Returns false when it cannot sign.
    using EventSigner = std::function<bool(LinkTokenEvent&)>;
    /// Sends a signed event to the other Tier 1 servers. Returns the number
    /// of servers it was sent to.
    using EventPublisher = std::function<std::size_t(const LinkTokenEvent&)>;

    /// Wire replication. Call before the provider serves requests. Without a
    /// signer, events stay local and unsigned (origin kLinkTokenLocalOrigin).
    void set_replication(EventSigner signer, EventPublisher publisher);

    /// Add an event another Tier 1 server made. The caller has verified its
    /// origin signature, network, and that the sender is Tier 1. Returns true
    /// when the event is held (new or already held).
    [[nodiscard]] bool apply_replicated(const LinkTokenEvent& event);

    /// Forget every token and delete the token files (this server left
    /// Tier 1).
    void purge();

    /// Test seam: Unix seconds source used in place of the system clock.
    void set_clock_for_testing(std::function<uint64_t()> now_sec);

    /// Revoke every token whose record matches `match` (only the owner and
    /// target fields are reliable). Used when an account is deleted. A
    /// replicated token gets a Revoke event, which is published, so the token
    /// stops being redeemable on every Tier 1 server; a token file from an
    /// earlier release is deleted (one that does not parse stays). Returns
    /// the number of tokens revoked.
    std::size_t revoke_where(const std::function<bool(const LinkTokenRecord&)>& match);

    static constexpr std::chrono::seconds kDefaultTtl{600};
    static constexpr std::chrono::seconds kMaxTtl{
        static_cast<std::chrono::seconds::rep>(kLinkTokenMaxTtlSec)};

private:
    [[nodiscard]] uint64_t now_sec() const;
    /// Set the event time, then sign `e` when `sign` is true and the signer
    /// succeeds; otherwise mark it local and unsigned. Caller holds mutex_.
    void author_locked(LinkTokenEvent& e, bool sign);
    /// The live token `code` names here, unless the wrong-code limits refuse
    /// `source`; a miss counts as a wrong attempt. Caller holds mutex_.
    [[nodiscard]] std::optional<LinkTokenLedger::Live> live_by_code_locked(std::string_view code,
                                                                           std::string_view source,
                                                                           uint64_t now);
    /// Persist the ledger. Caller holds mutex_.
    [[nodiscard]] bool save_locked();
    void load();
    [[nodiscard]] static LinkTokenRecord record_from_grant(const LinkTokenEvent& mint);

    // Tokens minted by a release before v2026.10.26: one file per token, named
    // by plain SHA-256 of the token, valid on this server only. Read, written,
    // and removed through the storage vault when it covers them; an
    // unreadable file refuses redemption and is never removed or replaced.
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
    std::string                  self_origin_;   ///< origin of the last signed local event
    uint64_t                     local_seq_{0};
    std::function<uint64_t()>    clock_;

    /// Wrong code attempts within one window, for one source address or for
    /// the whole server.
    struct CodeFailures {
        uint64_t window_start{0};  ///< Unix seconds of the first failure in the window
        uint32_t count{0};
        uint64_t locked_until{0};  ///< Unix seconds; source entries only
    };
    std::map<std::string, CodeFailures, std::less<>> code_failures_by_source_;
    CodeFailures                 code_failures_all_;
};

} // namespace nexus::auth
