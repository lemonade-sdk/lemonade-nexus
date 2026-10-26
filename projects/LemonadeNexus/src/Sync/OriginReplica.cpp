#include <LemonadeNexus/Sync/OriginReplica.hpp>

#define XXH_INLINE_ALL
#include <xxhash/xxhash.h>

#include <algorithm>
#include <set>
#include <tuple>
#include <utility>

namespace nexus::sync {

namespace {

// Stable across builds and platforms: replicas on different binaries must
// compute equal hashes for equal entries, which rules out std::hash.
uint64_t entry_hash(const ReplicaEntry& e) {
    std::string buf;
    buf.reserve(e.key.size() + 10);
    buf.append(e.key);
    buf.push_back('\0');
    for (int i = 0; i < 8; ++i) {
        buf.push_back(static_cast<char>((e.seq >> (8 * i)) & 0xFF));
    }
    buf.push_back(e.tombstone ? '\1' : '\0');
    return XXH3_64bits(buf.data(), buf.size());
}

bool newer(uint64_t ts_a, uint64_t seq_a, uint64_t ts_b, uint64_t seq_b) {
    return std::tie(ts_a, seq_a) > std::tie(ts_b, seq_b);
}

// Non-negative integer: a JSON literal parses as signed, a msgpack positive
// integer as unsigned. Floats, negatives and other types are refused.
bool as_u64(const nlohmann::json& v, uint64_t& out) {
    if (v.is_number_unsigned()) {
        out = v.get<uint64_t>();
        return true;
    }
    if (v.is_number_integer() && v.get<int64_t>() >= 0) {
        out = static_cast<uint64_t>(v.get<int64_t>());
        return true;
    }
    return false;
}

bool valid_stream(const nlohmann::json& j, std::string& out) {
    uint64_t version = 0;
    if (!j.is_object() || !j.contains("v") || !as_u64(j["v"], version) || version != 1) {
        return false;
    }
    if (!j.contains("stream") || !j["stream"].is_string()) return false;
    out = j["stream"].get<std::string>();
    return !out.empty() && out.size() <= kMaxStreamNameBytes;
}

bool valid_origin(const nlohmann::json& v, std::string& out) {
    if (!v.is_string()) return false;
    out = v.get<std::string>();
    return !out.empty() && out.size() <= kMaxOriginIdBytes;
}

}  // namespace

OriginReplica::OriginReplica(std::string local_origin, std::size_t max_entries)
    : local_origin_(std::move(local_origin)), max_entries_(max_entries) {}

uint64_t OriginReplica::next_local_seq(uint64_t now_ms) {
    std::lock_guard lock(mutex_);
    last_local_seq_ = std::max(last_local_seq_ + 1, now_ms);
    return last_local_seq_;
}

bool OriginReplica::holds_newer(const std::string& key, uint64_t timestamp,
                                uint64_t seq) const {
    std::lock_guard lock(mutex_);
    const auto it = entries_.find(key);
    return it != entries_.end() &&
           newer(it->second.timestamp, it->second.seq, timestamp, seq);
}

OfferResult OriginReplica::offer(ReplicaEntry entry) {
    if (entry.key.empty() || entry.origin.empty()) return OfferResult::Invalid;

    std::lock_guard lock(mutex_);
    auto it = entries_.find(entry.key);
    if (it == entries_.end()) {
        if (entries_.size() >= max_entries_) return OfferResult::Full;
        const auto key = entry.key;
        entries_.emplace(key, std::move(entry));
        ++version_;
        return OfferResult::Stored;
    }
    if (!newer(entry.timestamp, entry.seq, it->second.timestamp, it->second.seq)) {
        return OfferResult::Stale;
    }
    it->second = std::move(entry);
    ++version_;
    return OfferResult::Stored;
}

Digest OriginReplica::digest() const {
    std::lock_guard lock(mutex_);
    return digest_locked();
}

Digest OriginReplica::digest_locked() const {
    Digest d;
    for (const auto& [key, e] : entries_) {
        if (e.seq == 0) continue;
        auto& s = d[e.origin];
        s.max_seq = std::max(s.max_seq, e.seq);
        ++s.count;
        s.hash ^= entry_hash(e);
    }
    return d;
}

std::vector<CatchUpRequest> OriginReplica::plan_catch_up(const Digest& peer) const {
    const Digest ours = digest();
    std::vector<CatchUpRequest> out;
    for (const auto& [origin, theirs] : peer) {
        if (theirs.count == 0) continue;
        const auto it = ours.find(origin);
        const OriginSummary mine = it != ours.end() ? it->second : OriginSummary{};
        if (theirs.max_seq > mine.max_seq) {
            out.push_back({origin, mine.max_seq});
        } else if (theirs.max_seq == mine.max_seq && theirs != mine) {
            out.push_back({origin, 0});
        }
    }
    return out;
}

std::vector<ReplicaEntry> OriginReplica::entries_since(const std::string& origin,
                                                       uint64_t since,
                                                       std::size_t max) const {
    std::vector<ReplicaEntry> out;
    {
        std::lock_guard lock(mutex_);
        for (const auto& [key, e] : entries_) {
            if (e.seq != 0 && e.seq > since && e.origin == origin) out.push_back(e);
        }
    }
    std::sort(out.begin(), out.end(),
              [](const ReplicaEntry& a, const ReplicaEntry& b) { return a.seq < b.seq; });
    if (out.size() > max) out.resize(max);
    return out;
}

bool OriginReplica::apply_peer_digest_locked(PeerRecord& rec, Digest peer_digest,
                                             uint64_t now_ms, bool first) {
    const bool in_sync = compare(digest_locked(), peer_digest).in_sync;
    const bool changed = first || rec.in_sync != in_sync;
    rec.digest         = std::move(peer_digest);
    rec.last_digest_ms = now_ms;
    rec.in_sync        = in_sync;
    return changed;
}

bool OriginReplica::record_peer_digest(const std::string& peer, Digest peer_digest,
                                       uint64_t now_ms) {
    std::lock_guard lock(mutex_);
    auto [it, inserted] = peers_.try_emplace(peer);
    return apply_peer_digest_locked(it->second, std::move(peer_digest), now_ms, inserted);
}

bool OriginReplica::record_peer_digest_page(const std::string& peer, const DigestPage& page,
                                            uint64_t now_ms) {
    if (page.pages == 0 || page.page >= page.pages || page.pages > kMaxDigestPages) return false;

    std::lock_guard lock(mutex_);
    auto [it, inserted] = peers_.try_emplace(peer);
    auto& rec = it->second;
    const bool collecting = rec.pending_pages != 0;
    if (collecting && page.round < rec.pending_round) return false;
    if (!collecting || page.round > rec.pending_round || page.pages != rec.pending_pages) {
        rec.pending_round = page.round;
        rec.pending_pages = page.pages;
        rec.pending_seen.clear();
        rec.pending.clear();
    }
    if (!rec.pending_seen.insert(page.page).second) return false;  // duplicate page
    for (const auto& [origin, s] : page.origins) rec.pending[origin] = s;
    if (rec.pending_seen.size() < rec.pending_pages) return false;

    Digest complete = std::move(rec.pending);
    rec.pending.clear();
    rec.pending_seen.clear();
    rec.pending_pages = 0;
    const bool first = inserted || rec.last_digest_ms == 0;
    return apply_peer_digest_locked(rec, std::move(complete), now_ms, first);
}

std::size_t OriginReplica::prune_tombstones(uint64_t cutoff_timestamp) {
    std::lock_guard lock(mutex_);
    const auto removed = std::erase_if(entries_, [cutoff_timestamp](const auto& kv) {
        return kv.second.tombstone && kv.second.timestamp < cutoff_timestamp;
    });
    if (removed) ++version_;
    return removed;
}

std::size_t OriginReplica::prune_expired(uint64_t cutoff_timestamp) {
    std::lock_guard lock(mutex_);
    const auto removed = std::erase_if(entries_, [cutoff_timestamp](const auto& kv) {
        return kv.second.timestamp < cutoff_timestamp;
    });
    if (removed) ++version_;
    return removed;
}

std::size_t OriginReplica::erase_keys(const std::function<bool(const std::string&)>& match) {
    std::lock_guard lock(mutex_);
    const auto removed =
        std::erase_if(entries_, [&match](const auto& kv) { return match(kv.first); });
    if (removed) ++version_;
    return removed;
}

std::map<std::string, PeerSyncStatus> OriginReplica::peer_status() const {
    std::lock_guard lock(mutex_);
    const Digest ours = digest_locked();
    std::map<std::string, PeerSyncStatus> out;
    for (const auto& [peer, rec] : peers_) {
        auto s = compare(ours, rec.digest);
        s.last_digest_ms = rec.last_digest_ms;
        out.emplace(peer, s);
    }
    return out;
}

PeerSyncStatus OriginReplica::compare(const Digest& ours, const Digest& theirs) {
    PeerSyncStatus s;
    std::set<std::string> origins;
    for (const auto& [o, _] : ours) origins.insert(o);
    for (const auto& [o, _] : theirs) origins.insert(o);
    for (const auto& o : origins) {
        const auto mi = ours.find(o);
        const auto ti = theirs.find(o);
        const OriginSummary mine = mi != ours.end() ? mi->second : OriginSummary{};
        const OriginSummary peer = ti != theirs.end() ? ti->second : OriginSummary{};
        if (mine == peer) continue;
        if (peer.max_seq > mine.max_seq) {
            ++s.origins_we_lack;
        } else if (mine.max_seq > peer.max_seq) {
            ++s.origins_peer_lacks;
        } else {
            // Same maximum, different contents: each side lacks something.
            ++s.origins_we_lack;
            ++s.origins_peer_lacks;
        }
    }
    s.in_sync = s.origins_we_lack == 0 && s.origins_peer_lacks == 0;
    return s;
}

std::size_t OriginReplica::size() const {
    std::lock_guard lock(mutex_);
    return entries_.size();
}

std::vector<ReplicaEntry> OriginReplica::snapshot() const {
    std::lock_guard lock(mutex_);
    std::vector<ReplicaEntry> out;
    out.reserve(entries_.size());
    for (const auto& [key, e] : entries_) out.push_back(e);
    return out;
}

uint64_t OriginReplica::version() const {
    std::lock_guard lock(mutex_);
    return version_;
}

void OriginReplica::clear() {
    std::lock_guard lock(mutex_);
    entries_.clear();
    peers_.clear();
    ++version_;
}

static nlohmann::json origin_row(const std::string& origin, const OriginSummary& s) {
    return nlohmann::json::array({origin, s.max_seq, s.count, s.hash});
}

nlohmann::json encode_digest_page(const DigestPage& page) {
    nlohmann::json origins = nlohmann::json::array();
    for (const auto& [origin, s] : page.origins) origins.push_back(origin_row(origin, s));
    return {{"v", 1},            {"stream", page.stream}, {"round", page.round},
            {"page", page.page}, {"pages", page.pages},   {"origins", std::move(origins)}};
}

std::vector<nlohmann::json> encode_digest_pages(std::string_view stream, const Digest& digest,
                                                uint64_t round, std::size_t max_page_bytes) {
    // Page index and total are filled in last; size the header with their
    // widest msgpack form so the final encoding stays within the budget.
    const std::size_t header_bytes =
        nlohmann::json::to_msgpack(encode_digest_page(
            {std::string(stream), round, 0xFFFFFFFFu, 0xFFFFFFFFu, {}})).size();
    if (header_bytes >= max_page_bytes) return {};

    std::vector<Digest> groups(1);
    std::size_t used = header_bytes;
    for (const auto& [origin, s] : digest) {
        const std::size_t row = nlohmann::json::to_msgpack(origin_row(origin, s)).size();
        if (header_bytes + row > max_page_bytes) return {};
        if (used + row > max_page_bytes || groups.back().size() >= kMaxWireOrigins) {
            groups.emplace_back();
            used = header_bytes;
        }
        groups.back().emplace(origin, s);
        used += row;
    }
    if (groups.size() > kMaxDigestPages) return {};

    std::vector<nlohmann::json> out;
    out.reserve(groups.size());
    const auto pages = static_cast<uint32_t>(groups.size());
    for (uint32_t i = 0; i < pages; ++i) {
        out.push_back(encode_digest_page(
            {std::string(stream), round, i, pages, std::move(groups[i])}));
    }
    return out;
}

std::optional<DigestPage> decode_digest_page(const nlohmann::json& j) {
    DigestPage page;
    if (!valid_stream(j, page.stream)) return std::nullopt;
    uint64_t index = 0, pages = 0;
    if (!j.contains("round") || !as_u64(j["round"], page.round) ||
        !j.contains("page") || !as_u64(j["page"], index) ||
        !j.contains("pages") || !as_u64(j["pages"], pages) ||
        pages == 0 || pages > kMaxDigestPages || index >= pages) {
        return std::nullopt;
    }
    page.page  = static_cast<uint32_t>(index);
    page.pages = static_cast<uint32_t>(pages);
    if (!j.contains("origins") || !j["origins"].is_array() ||
        j["origins"].size() > kMaxWireOrigins) {
        return std::nullopt;
    }
    for (const auto& row : j["origins"]) {
        std::string origin;
        OriginSummary s;
        if (!row.is_array() || row.size() != 4 || !valid_origin(row[0], origin) ||
            !as_u64(row[1], s.max_seq) || !as_u64(row[2], s.count) || !as_u64(row[3], s.hash)) {
            return std::nullopt;
        }
        if (!page.origins.emplace(std::move(origin), s).second) return std::nullopt;
    }
    return page;
}

nlohmann::json encode_catch_up(std::string_view stream,
                               const std::vector<CatchUpRequest>& requests) {
    nlohmann::json since = nlohmann::json::array();
    for (const auto& r : requests) since.push_back({r.origin, r.since});
    return {{"v", 1}, {"stream", std::string(stream)}, {"since", std::move(since)}};
}

std::optional<std::pair<std::string, std::vector<CatchUpRequest>>>
decode_catch_up(const nlohmann::json& j) {
    std::string stream;
    if (!valid_stream(j, stream)) return std::nullopt;
    if (!j.contains("since") || !j["since"].is_array() ||
        j["since"].size() > kMaxWireOrigins) {
        return std::nullopt;
    }
    std::vector<CatchUpRequest> out;
    std::set<std::string> seen;
    for (const auto& row : j["since"]) {
        std::string origin;
        uint64_t since = 0;
        if (!row.is_array() || row.size() != 2 || !valid_origin(row[0], origin) ||
            !as_u64(row[1], since) || !seen.insert(origin).second) {
            return std::nullopt;
        }
        out.push_back({std::move(origin), since});
    }
    return std::make_pair(std::move(stream), std::move(out));
}

} // namespace nexus::sync
