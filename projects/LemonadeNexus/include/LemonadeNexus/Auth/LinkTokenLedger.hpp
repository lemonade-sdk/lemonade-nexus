#pragma once

// Replicated link token (invite) records.
//
// A link token is a bearer secret. No server stores or sends the token
// itself: every record names it by link_token_hash_hex(token), a
// domain-separated SHA-256. A token's life is a set of events, each made and
// signed by one Tier 1 server:
//
//   Mint    the minting server's grant: target group, permissions, inviter,
//           network, issue and expiry times (generation 0), and, when the
//           server issued an invite code too, the code's hash.
//   Spend   a server consumed generation g of the token.
//   Refund  the server whose spend of generation g counts restored the token
//           as generation g + 1 (the join that consumed it did not use it).
//   Revoke  a server ended the token for good (its inviter's account or its
//           target group was deleted).
//
// The set only grows, so replicas that hold the same events reach the same
// state in any arrival order (LinkTokenLedger::live). When two servers spend
// the same generation, the spend with the smallest origin key counts. A
// Revoke from any origin ends the token, whatever its generation.

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::crypto { class SodiumCryptoService; }

namespace nexus::auth {

/// Domain of the token hash (link_token_hash_hex).
inline constexpr std::string_view kLinkTokenHashDomain = "lemonade-nexus/link-token-hash:v1";
/// Domain of the bytes an origin signs (link_token_event_signing_bytes).
inline constexpr std::string_view kLinkTokenEventDomain = "lemonade-nexus/link-token-event:v1";
/// Domain of the invite code hash (link_code_hash_hex).
inline constexpr std::string_view kLinkCodeHashDomain = "lemonade-nexus/link-code-hash:v1";
/// Domain of the code binding an origin signs (link_code_binding_bytes).
inline constexpr std::string_view kLinkCodeBindingDomain = "lemonade-nexus/link-code-binding:v1";

/// Longest token lifetime, from issue to expiry (TokenLinkAuthProvider::kMaxTtl).
inline constexpr uint64_t kLinkTokenMaxTtlSec = 3600;
/// Length of an invite code: decimal digits.
inline constexpr std::size_t kLinkCodeDigits = 8;
/// Longest life of an invite code, from the mint's created_at. A code whose
/// token lives longer stops working at this bound; the token goes on.
inline constexpr uint64_t kLinkCodeMaxTtlSec = 600;
/// Wrong code attempts a server tolerates while a code is live; from the
/// next one on that code is refused for the rest of its life on that server.
inline constexpr uint32_t kLinkCodeMaxFailures = 5;
/// Records stay this long after expiry, so a late copy of a mint cannot
/// outlive the spend that consumed it on a server with a slower clock.
inline constexpr uint64_t kLinkTokenRetentionSec = 600;
/// Allowed clock lead of an origin over the receiver.
inline constexpr uint64_t kLinkTokenMaxFutureSec = 300;
/// Highest generation: a token is restored at most this many times.
inline constexpr uint32_t kLinkTokenMaxGeneration = 8;
/// Events held for one token. Each generation holds at most one spend and
/// one refund per origin.
inline constexpr std::size_t kLinkTokenMaxEventsPerToken = 64;
/// Tokens held by one server, live and retained.
inline constexpr std::size_t kLinkTokenMaxTokens = 16384;
/// Live tokens one owner may hold when it mints a new one.
inline constexpr std::size_t kLinkTokenMaxPerOwner = 64;
/// Bound on every text field (ids, keys, network id, signature).
inline constexpr std::size_t kLinkTokenMaxFieldBytes = 256;
/// Bound on the permissions a grant carries.
inline constexpr std::size_t kLinkTokenMaxPermissions = 8;

enum class LinkTokenEventKind : uint8_t { Mint = 1, Spend = 2, Refund = 3, Revoke = 4 };

/// One signed event in a token's life. Grant fields are set on a Mint and
/// empty (zero) on a Spend or Refund. Every event carries the token's
/// network and expiry, so a spend can be bounded and pruned without its mint.
struct LinkTokenEvent {
    LinkTokenEventKind       kind{LinkTokenEventKind::Mint};
    std::string              token_hash;     ///< 64 lowercase hex (link_token_hash_hex)
    uint32_t                 generation{0};  ///< Mint, Revoke: 0. Spend/Refund: the generation spent
    std::string              network_id;     ///< hex network id the origin belongs to
    uint64_t                 expires_at{0};  ///< Unix seconds; the token is invalid from here on

    // Grant (Mint only).
    std::string              group_node_id;  ///< target group
    std::vector<std::string> permissions;    ///< granted to an accepting member
    std::string              owner_user_id;  ///< inviter's session subject
    std::string              owner_pubkey;   ///< inviter's key ("ed25519:<base64>")
    uint64_t                 created_at{0};  ///< Unix seconds

    // Invite code binding (Mint only, optional). A short decimal code names
    // the same token: the mint carries link_code_hash_hex(code), and the
    // origin signs the binding separately (link_code_binding_bytes), so the
    // event signature and every encoding a release before the code existed
    // computes stay as they are. A replica from such a release drops both
    // fields and redeems the token only.
    std::string              code_hash;      ///< 64 lowercase hex, or empty (no code)
    std::string              code_signature; ///< base64 Ed25519 by origin_pubkey; empty when local

    // Authorship.
    uint64_t                 timestamp{0};   ///< Unix seconds when the origin made the event
    std::string              origin_pubkey;  ///< base64 Ed25519 gossip key of the origin server
    uint64_t                 origin_seq{0};  ///< origin-assigned, strictly increasing, never 0
    std::string              signature;      ///< base64 Ed25519 by origin_pubkey; empty when local

    bool operator==(const LinkTokenEvent&) const = default;
};

/// Origin name of an event that was not signed (no replication wired). Such
/// an event is never replicated and is never valid in a tree operation.
inline constexpr std::string_view kLinkTokenLocalOrigin = "local";

/// Lowercase hex of SHA-256 over the canonical encoding of `token` under
/// kLinkTokenHashDomain.
[[nodiscard]] std::string link_token_hash_hex(std::string_view token);

/// True when `secret` has the form of an invite code: exactly kLinkCodeDigits
/// ASCII digits. Anything else presented in a token position is a token.
[[nodiscard]] bool is_link_code(std::string_view secret);

/// Lowercase hex of SHA-256 over the canonical encoding of `code` under
/// kLinkCodeHashDomain. Distinct from link_token_hash_hex even for equal input.
[[nodiscard]] std::string link_code_hash_hex(std::string_view code);

/// The bytes an origin signs for a mint's code binding: token_hash,
/// code_hash, network_id, expires_at, origin_pubkey, and origin_seq under
/// kLinkCodeBindingDomain. The origin and sequence tie the binding to one
/// signed mint.
[[nodiscard]] std::vector<uint8_t> link_code_binding_bytes(const LinkTokenEvent& e);

/// Unix second from which the code of `mint` is refused:
/// min(expires_at, created_at + kLinkCodeMaxTtlSec).
[[nodiscard]] uint64_t link_code_expires_at(const LinkTokenEvent& mint);

/// The bytes an origin signs: every field except `signature` and the code
/// binding, canonically encoded under kLinkTokenEventDomain.
[[nodiscard]] std::vector<uint8_t> link_token_event_signing_bytes(const LinkTokenEvent& e);

/// True when `e.signature` is origin_pubkey's Ed25519 signature over
/// link_token_event_signing_bytes(e) and, when the event carries a code
/// binding, `e.code_signature` is the same key's signature over
/// link_code_binding_bytes(e). Says nothing about whether the origin is a
/// certified or Tier 1 server; callers check that.
[[nodiscard]] bool link_token_event_signature_valid(crypto::SodiumCryptoService& crypto,
                                                    const LinkTokenEvent& e);

/// Structural check: field formats and bounds, kind and generation, grant
/// fields present on a Mint and absent otherwise, lifetime at most
/// kLinkTokenMaxTtlSec, a code binding only on a signed Mint. nullopt when
/// well formed.
[[nodiscard]] std::optional<std::string> link_token_event_shape_error(const LinkTokenEvent& e);

/// Time check against the receiver's clock: the event is still retained
/// (now < expires_at + kLinkTokenRetentionSec), and its expiry and timestamp
/// are not further ahead than the lifetime and clock-lead bounds allow.
/// nullopt when acceptable.
[[nodiscard]] std::optional<std::string> link_token_event_time_error(const LinkTokenEvent& e,
                                                                     uint64_t now_sec);

/// Replica key: one per (token, kind, generation, origin), so no event ever
/// replaces another.
[[nodiscard]] std::string link_token_event_key(const LinkTokenEvent& e);

/// Wire and storage form (a JSON object; msgpack on the backbone). The code
/// binding fields are present only when set, so an event without a code has
/// the form an earlier release writes.
[[nodiscard]] nlohmann::json link_token_event_to_wire(const LinkTokenEvent& e);

/// Parse the wire form. nullopt when a field is missing, of the wrong type,
/// or beyond its bound. The code binding fields are optional. Unknown fields
/// are ignored. Does not run the shape, time, or signature checks.
[[nodiscard]] std::optional<LinkTokenEvent> link_token_event_from_wire(const nlohmann::json& j);

/// The events of every token one server holds, and the state they imply.
/// Deterministic and independent of arrival order. Not thread-safe; the
/// owner serializes access.
class LinkTokenLedger {
public:
    enum class AddResult {
        Added,      ///< the event is new and now held
        Duplicate,  ///< an equal event is already held
        Refused,    ///< malformed, outside the retention window, or inconsistent
        Full,       ///< a token or per-token cap is reached
    };

    /// A token that a redeemer may consume now.
    struct Live {
        LinkTokenEvent mint;
        uint32_t       generation{0};  ///< the generation a spend now consumes
    };

    /// Add `e` after the shape and time checks. An event whose network or
    /// expiry differs from the token's earlier events is refused. A Mint
    /// equal to the held one except that it carries the code binding the
    /// held copy lacks (the held copy came through a replica that drops the
    /// binding) replaces it and counts as Added.
    AddResult add(const LinkTokenEvent& e, uint64_t now_sec);

    /// The token's current state when it can be consumed: a mint is held,
    /// no revoke is held, now < expires_at, and the current generation has no
    /// counting spend.
    [[nodiscard]] std::optional<Live> live(std::string_view token_hash, uint64_t now_sec) const;

    /// The token an invite code names, when it can be consumed now. Fails
    /// closed: nullopt unless exactly one held mint carries `code_hash` with
    /// now < link_code_expires_at(mint), and that token is live. Two mints
    /// with one code (minted on different servers at the same time) make the
    /// code unusable; both tokens stay redeemable.
    [[nodiscard]] std::optional<Live> live_by_code(std::string_view code_hash,
                                                   uint64_t now_sec) const;

    /// True when a held mint carries `code_hash` and its code has not
    /// expired (now < link_code_expires_at). The minting server draws another
    /// code while this holds.
    [[nodiscard]] bool code_in_use(std::string_view code_hash, uint64_t now_sec) const;

    /// True when any held mint carries `code_hash`.
    [[nodiscard]] bool holds_code(std::string_view code_hash) const {
        return codes_.find(code_hash) != codes_.end();
    }

    /// Origin of the spend that counts for `generation`: the smallest origin
    /// among the spends of that generation. nullopt when none is held.
    [[nodiscard]] std::optional<std::string> spend_winner(std::string_view token_hash,
                                                          uint32_t generation) const;

    /// Number of live tokens minted for `owner_user_id`.
    [[nodiscard]] std::size_t live_count_for_owner(std::string_view owner_user_id,
                                                   uint64_t now_sec) const;

    /// Drop every token whose retention ended (expires_at +
    /// kLinkTokenRetentionSec <= now). Returns the number of tokens removed.
    std::size_t prune(uint64_t now_sec);

    /// Every held event, ordered by token and replica key.
    [[nodiscard]] std::vector<LinkTokenEvent> events() const;

    /// True when a Revoke of the token is held.
    [[nodiscard]] bool revoked(std::string_view token_hash) const;

    /// The mint of every held token that has one, ordered by token hash.
    [[nodiscard]] std::vector<LinkTokenEvent> mints() const;

    /// True when any event of the token is held.
    [[nodiscard]] bool holds(std::string_view token_hash) const {
        return tokens_.find(token_hash) != tokens_.end();
    }

    [[nodiscard]] std::size_t token_count() const { return tokens_.size(); }

    void clear() {
        tokens_.clear();
        codes_.clear();
    }

private:
    struct Token {
        std::string network_id;
        uint64_t    expires_at{0};
        std::optional<LinkTokenEvent> mint;
        std::map<std::string, LinkTokenEvent> events;  ///< by replica key, mint included
    };

    std::map<std::string, Token, std::less<>> tokens_;
    /// code_hash -> token hashes of the held mints that carry it.
    std::map<std::string, std::set<std::string>, std::less<>> codes_;
};

}  // namespace nexus::auth
