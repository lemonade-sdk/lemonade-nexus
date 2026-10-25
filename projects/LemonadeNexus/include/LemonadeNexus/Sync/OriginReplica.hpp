#pragma once

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace nexus::sync {

/// Bounds applied to everything decoded from a peer. A digest or request
/// beyond these limits is refused whole.
inline constexpr std::size_t kMaxWireOrigins     = 1024;
inline constexpr std::size_t kMaxOriginIdBytes   = 128;
inline constexpr std::size_t kMaxStreamNameBytes = 32;
/// A digest is split across at most this many pages (datagrams).
inline constexpr uint32_t    kMaxDigestPages     = 256;

/// Default cap on stored entries per replica.
inline constexpr std::size_t kDefaultMaxReplicaEntries = 65536;

/// One replicated entry: ordering metadata plus the module's opaque payload.
///
/// The payload is the module's origin-signed wire form. The replica never
/// parses or re-signs it; catch-up replays it so the receiver runs the same
/// verification as for a live update.
struct ReplicaEntry {
    std::string          key;        ///< unique per stream, e.g. "A:host.example"
    std::string          origin;     ///< author identity (base64 Ed25519 public key)
    uint64_t             seq{0};     ///< origin-assigned, strictly increasing per origin; 0 = legacy (untracked)
    uint64_t             timestamp{0}; ///< author's clock in seconds; primary order key
    bool                 tombstone{false}; ///< true when the entry records a removal
    std::vector<uint8_t> payload;
};

/// Summary of everything one origin authored that this replica holds.
/// Two replicas hold the same entries for an origin when the summaries match.
struct OriginSummary {
    uint64_t max_seq{0};
    uint64_t count{0};
    uint64_t hash{0};   ///< XOR of per-entry XXH3 hashes over (key, seq, tombstone)

    bool operator==(const OriginSummary&) const = default;
};

/// Per-origin summaries, ordered by origin for deterministic encoding.
using Digest = std::map<std::string, OriginSummary>;

/// One page of a digest. A digest larger than one datagram is split into
/// `pages` pages that share a `round`; each page carries whole origin rows.
struct DigestPage {
    std::string stream;
    uint64_t    round{0};   ///< sender's digest round; a newer round supersedes
    uint32_t    page{0};    ///< 0-based index
    uint32_t    pages{1};   ///< total pages in this round
    Digest      origins;    ///< the origin rows on this page
};

/// "Send me the entries `origin` authored with seq greater than `since`."
/// `since == 0` requests every entry the responder holds for that origin.
struct CatchUpRequest {
    std::string origin;
    uint64_t    since{0};

    bool operator==(const CatchUpRequest&) const = default;
};

/// How a peer compared with this replica at its last digest.
struct PeerSyncStatus {
    uint64_t    last_digest_ms{0};   ///< caller clock at the last digest from the peer
    bool        in_sync{false};      ///< every origin summary matched
    std::size_t origins_we_lack{0};  ///< origins where the peer holds entries we do not
    std::size_t origins_peer_lacks{0}; ///< origins where we hold entries the peer does not
};

enum class OfferResult {
    Stored,   ///< the entry is now the newest for its key
    Stale,    ///< an entry at least as new is already held; nothing changed
    Full,     ///< new key refused: the replica is at its entry cap
    Invalid,  ///< empty key or origin
};

/// Last-writer-wins replica of origin-sequenced entries, with the digest and
/// catch-up planning needed to converge with peers.
///
/// Each origin numbers its own changes (next_local_seq), similar to a log
/// sequence number. The replica keeps only the newest entry per key,
/// tombstones included, ordered by (timestamp, seq). Peers exchange
/// digests, and plan_catch_up names the origins and ranges to request.
///
/// The replica does no I/O and no cryptography. Callers verify and authorize
/// an entry before offer() and transport digests, requests and payloads.
/// Clocks are passed in, so behavior is deterministic under test.
///
/// Thread safety: every member function is safe to call concurrently.
class OriginReplica {
public:
    /// @param local_origin  this node's origin id; its entries are summarized
    ///                      like any other origin's
    /// @param max_entries   cap on stored keys; offers of new keys beyond it
    ///                      return OfferResult::Full
    explicit OriginReplica(std::string local_origin,
                           std::size_t max_entries = kDefaultMaxReplicaEntries);

    [[nodiscard]] const std::string& local_origin() const { return local_origin_; }

    /// Next sequence number for a local change: max(previous + 1, now_ms).
    /// Strictly increasing within a process. Across restarts it keeps
    /// increasing while the wall clock moves forward, so nothing is persisted.
    [[nodiscard]] uint64_t next_local_seq(uint64_t now_ms);

    /// True when an entry already held for `key` is strictly newer than
    /// (timestamp, seq). Callers drop such an incoming update before applying
    /// it, which keeps a tombstone from being undone by an older entry.
    [[nodiscard]] bool holds_newer(const std::string& key, uint64_t timestamp,
                                   uint64_t seq) const;

    /// Store `entry` when it is newer than the entry held for its key.
    /// Entries with seq 0 take part in ordering but not in digests or
    /// catch-up (they predate origin sequencing).
    OfferResult offer(ReplicaEntry entry);

    /// Summaries of every origin with at least one sequenced entry.
    [[nodiscard]] Digest digest() const;

    /// Requests that bring this replica up to `peer`:
    ///  - the peer has a higher max_seq for an origin: request after ours;
    ///  - same max_seq but different count or hash (a lost update below the
    ///    maximum): request that origin in full (since = 0).
    /// Origins where this replica is ahead produce nothing; the peer requests
    /// them when it receives our digest.
    [[nodiscard]] std::vector<CatchUpRequest> plan_catch_up(const Digest& peer) const;

    /// Sequenced entries authored by `origin` with seq > `since`, ascending by
    /// seq, at most `max` of them. Ascending order means a truncated answer
    /// never skips an entry below one the requester receives.
    [[nodiscard]] std::vector<ReplicaEntry> entries_since(const std::string& origin,
                                                          uint64_t since,
                                                          std::size_t max) const;

    /// Record a peer's complete digest. Returns true when the peer's in-sync
    /// state changed (including the first digest from that peer).
    bool record_peer_digest(const std::string& peer, Digest peer_digest, uint64_t now_ms);

    /// Record one page of a peer's digest. Pages of the same round accumulate;
    /// the peer's digest is replaced once every page of the round has arrived.
    /// A page from an older round than the one being collected is ignored, and
    /// a newer round discards an incomplete one. Returns true when the peer's
    /// in-sync state changed on completing a round. Catch-up planning does not
    /// need the whole round: plan_catch_up(page.origins) is valid per page.
    bool record_peer_digest_page(const std::string& peer, const DigestPage& page,
                                 uint64_t now_ms);

    /// Drop tombstones whose timestamp is older than `cutoff_timestamp`
    /// (seconds, author clock). Every replica applying the same cutoff ends up
    /// with the same entries. A peer that was offline longer than the window
    /// can still hold the entry the tombstone superseded and hand it back.
    /// Returns the number removed.
    std::size_t prune_tombstones(uint64_t cutoff_timestamp);

    /// Drop every entry, tombstone or not, whose timestamp is older than
    /// `cutoff_timestamp`. For a stream whose entries carry their expiry as
    /// the timestamp (link tokens). Returns the number removed.
    std::size_t prune_expired(uint64_t cutoff_timestamp);

    /// Status of every peer that sent a digest, compared with the current
    /// local state.
    [[nodiscard]] std::map<std::string, PeerSyncStatus> peer_status() const;

    /// Number of stored entries, legacy and tombstones included.
    [[nodiscard]] std::size_t size() const;

    /// Copy of every stored entry, for persistence. Restore by offering each.
    [[nodiscard]] std::vector<ReplicaEntry> snapshot() const;

    /// Counter that changes whenever the stored entries change; callers save
    /// a snapshot when it differs from the value at their last save.
    [[nodiscard]] uint64_t version() const;

    /// Drop every entry and every peer record. The next digest is empty.
    void clear();

private:
    struct PeerRecord {
        Digest   digest;
        uint64_t last_digest_ms{0};
        bool     in_sync{false};
        // Round being collected from pages.
        uint64_t           pending_round{0};
        uint32_t           pending_pages{0};
        std::set<uint32_t> pending_seen;
        Digest             pending;
    };

    bool apply_peer_digest_locked(PeerRecord& rec, Digest peer_digest, uint64_t now_ms,
                                  bool first);

    [[nodiscard]] Digest digest_locked() const;
    [[nodiscard]] static PeerSyncStatus compare(const Digest& ours, const Digest& theirs);

    const std::string local_origin_;
    const std::size_t max_entries_;

    mutable std::mutex mutex_;
    uint64_t last_local_seq_{0};
    uint64_t version_{0};
    std::unordered_map<std::string, ReplicaEntry> entries_;
    std::map<std::string, PeerRecord> peers_;
};

/// Wire form of one digest page:
/// {"v":1,"stream":<name>,"round":R,"page":i,"pages":N,
///  "origins":[[origin,max_seq,count,hash],...]}.
[[nodiscard]] nlohmann::json encode_digest_page(const DigestPage& page);

/// Split `digest` into pages whose msgpack encoding is at most
/// `max_page_bytes` each. An empty digest is one page with no rows. Returns
/// an empty vector when a single origin row cannot fit, or more than
/// kMaxDigestPages pages would be needed.
[[nodiscard]] std::vector<nlohmann::json> encode_digest_pages(std::string_view stream,
                                                              const Digest& digest,
                                                              uint64_t round,
                                                              std::size_t max_page_bytes);

/// Decoded page, or nullopt when the message is malformed, has an unknown
/// version, exceeds a bound, has page >= pages, or repeats an origin.
[[nodiscard]] std::optional<DigestPage> decode_digest_page(const nlohmann::json& j);

/// Wire form of a catch-up request:
/// {"v":1,"stream":<name>,"since":[[origin,since],...]}.
[[nodiscard]] nlohmann::json encode_catch_up(std::string_view stream,
                                             const std::vector<CatchUpRequest>& requests);

/// Decoded requests and their stream name, or nullopt under the same rules
/// as decode_digest.
[[nodiscard]] std::optional<std::pair<std::string, std::vector<CatchUpRequest>>>
decode_catch_up(const nlohmann::json& j);

} // namespace nexus::sync
