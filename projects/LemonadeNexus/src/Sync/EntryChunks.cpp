#include <LemonadeNexus/Sync/EntryChunks.hpp>

#include <LemonadeNexus/Sync/OriginReplica.hpp>

#include <sodium.h>

#include <algorithm>

namespace nexus::sync {

namespace {

std::array<uint8_t, 32> sha256(std::span<const uint8_t> bytes) {
    std::array<uint8_t, 32> out{};
    crypto_hash_sha256(out.data(), bytes.data(), bytes.size());
    return out;
}

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

bool as_bytes(const nlohmann::json& v, std::vector<uint8_t>& out) {
    if (!v.is_binary()) return false;
    out.assign(v.get_binary().begin(), v.get_binary().end());
    return true;
}

}  // namespace

std::vector<nlohmann::json> encode_entry_chunks(std::string_view stream, uint64_t seq,
                                                std::span<const uint8_t> entry,
                                                std::size_t chunk_bytes) {
    if (entry.empty() || chunk_bytes == 0) return {};
    const std::size_t count = (entry.size() + chunk_bytes - 1) / chunk_bytes;
    if (count > kMaxEntryChunks) return {};
    const auto digest = sha256(entry);
    std::vector<nlohmann::json> out;
    out.reserve(count);
    for (std::size_t i = 0; i < count; ++i) {
        const auto part = entry.subspan(i * chunk_bytes,
                                        std::min(chunk_bytes, entry.size() - i * chunk_bytes));
        out.push_back({{"v", 1},
                       {"stream", std::string(stream)},
                       {"seq", seq},
                       {"digest", nlohmann::json::binary({digest.begin(), digest.end()})},
                       {"index", i},
                       {"count", count},
                       {"size", entry.size()},
                       {"data", nlohmann::json::binary({part.begin(), part.end()})}});
    }
    return out;
}

std::optional<EntryChunk> decode_entry_chunk(const nlohmann::json& j, std::size_t max_size) {
    if (!j.is_object()) return std::nullopt;
    EntryChunk c;
    uint64_t version = 0, index = 0, count = 0;
    std::vector<uint8_t> digest;
    if (!j.contains("v") || !as_u64(j["v"], version) || version != 1 ||
        !j.contains("stream") || !j["stream"].is_string() || !j.contains("seq") ||
        !as_u64(j["seq"], c.seq) || !j.contains("digest") || !as_bytes(j["digest"], digest) ||
        digest.size() != c.digest.size() || !j.contains("index") || !as_u64(j["index"], index) ||
        !j.contains("count") || !as_u64(j["count"], count) || !j.contains("size") ||
        !as_u64(j["size"], c.size) || !j.contains("data") || !as_bytes(j["data"], c.data)) {
        return std::nullopt;
    }
    c.stream = j["stream"].get<std::string>();
    if (c.stream.empty() || c.stream.size() > kMaxStreamNameBytes || count == 0 ||
        count > kMaxEntryChunks || index >= count || c.size == 0 || c.size > max_size ||
        c.data.empty() || c.data.size() > c.size) {
        return std::nullopt;
    }
    std::copy(digest.begin(), digest.end(), c.digest.begin());
    c.index = static_cast<uint32_t>(index);
    c.count = static_cast<uint32_t>(count);
    return c;
}

EntryAssembler::EntryAssembler(std::size_t max_buffered_bytes, uint64_t max_age_ms)
    : max_buffered_bytes_(max_buffered_bytes), max_age_ms_(max_age_ms) {}

void EntryAssembler::drop_locked(std::map<Key, Partial>::iterator it) {
    buffered_ -= it->second.bytes;
    partial_.erase(it);
}

std::optional<std::vector<uint8_t>> EntryAssembler::add(const std::string& sender,
                                                         const EntryChunk& chunk,
                                                         uint64_t now_ms) {
    if (chunk.data.empty() || chunk.data.size() > max_buffered_bytes_ || chunk.count == 0 ||
        chunk.index >= chunk.count) {
        return std::nullopt;
    }
    if (chunk.count == 1) {
        if (chunk.data.size() != chunk.size || sha256(chunk.data) != chunk.digest) {
            return std::nullopt;
        }
        return chunk.data;
    }

    std::lock_guard lock(mutex_);
    for (auto it = partial_.begin(); it != partial_.end();) {
        auto next = std::next(it);
        if (now_ms - it->second.first_ms > max_age_ms_) drop_locked(it);
        it = next;
    }

    const Key key{sender, chunk.stream, chunk.seq, chunk.digest};
    auto it = partial_.find(key);
    if (it == partial_.end()) {
        it = partial_.emplace(key, Partial{chunk.count, chunk.size, now_ms, 0, {}}).first;
    } else if (it->second.count != chunk.count || it->second.size != chunk.size) {
        drop_locked(it);
        return std::nullopt;
    }
    if (it->second.chunks.contains(chunk.index)) return std::nullopt;  // duplicate

    while (buffered_ + chunk.data.size() > max_buffered_bytes_ && partial_.size() > 1) {
        // Make room, but never by dropping the entry this chunk belongs to.
        auto oldest = partial_.end();
        for (auto p = partial_.begin(); p != partial_.end(); ++p) {
            if (p == it) continue;
            if (oldest == partial_.end() || p->second.first_ms < oldest->second.first_ms) {
                oldest = p;
            }
        }
        if (oldest == partial_.end()) break;
        drop_locked(oldest);
    }
    if (buffered_ + chunk.data.size() > max_buffered_bytes_) {
        drop_locked(it);
        return std::nullopt;
    }
    it->second.chunks.emplace(chunk.index, chunk.data);
    it->second.bytes += chunk.data.size();
    buffered_ += chunk.data.size();
    if (it->second.bytes > it->second.size) {
        drop_locked(it);
        return std::nullopt;
    }
    if (it->second.chunks.size() < it->second.count) return std::nullopt;

    std::vector<uint8_t> whole;
    whole.reserve(it->second.size);
    for (const auto& [index, data] : it->second.chunks) whole.insert(whole.end(), data.begin(), data.end());
    const bool ok = whole.size() == it->second.size && sha256(whole) == chunk.digest;
    drop_locked(it);
    if (!ok) return std::nullopt;
    return whole;
}

std::size_t EntryAssembler::buffered_bytes() const {
    std::lock_guard lock(mutex_);
    return buffered_;
}

}  // namespace nexus::sync
