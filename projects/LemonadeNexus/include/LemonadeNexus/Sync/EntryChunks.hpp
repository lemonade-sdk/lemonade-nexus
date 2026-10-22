#pragma once

// Chunked transport for sync entries larger than one datagram.
//
// A stream whose entries can exceed one backbone datagram (the "tree" stream:
// a committed tree block with its commit proof, or the merge commit) sends
// each entry as numbered chunks that share the entry's key, sequence number,
// and SHA-256 digest. The assembler joins them back and checks the digest.
// The digest protects reassembly only: the stream verifies the assembled
// entry exactly as a live update, so a chunk grants nothing.
//
// Wire form of one chunk (msgpack):
//   {"v":1,"stream":<name>,"seq":S,"digest":<32 bytes>,"index":i,"count":N,
//    "size":<total bytes>,"data":<bytes>}

#include <nlohmann/json.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace nexus::sync {

/// Most chunks one entry may claim.
inline constexpr uint32_t kMaxEntryChunks = 1024;

struct EntryChunk {
    std::string stream;
    uint64_t seq{0};                ///< the entry's sequence number (tree: log height)
    std::array<uint8_t, 32> digest{};  ///< SHA-256 of the whole entry
    uint32_t index{0};
    uint32_t count{1};
    uint64_t size{0};               ///< total entry bytes
    std::vector<uint8_t> data;
};

/// Split `entry` into chunks of at most `chunk_bytes` data bytes each. Empty
/// when the entry is empty, `chunk_bytes` is 0, or more than kMaxEntryChunks
/// chunks would be needed.
[[nodiscard]] std::vector<nlohmann::json> encode_entry_chunks(std::string_view stream,
                                                              uint64_t seq,
                                                              std::span<const uint8_t> entry,
                                                              std::size_t chunk_bytes);

/// Decoded chunk, or nullopt when the message is malformed, has an unknown
/// version, a bad stream name, index >= count, count > kMaxEntryChunks, a data
/// field larger than the declared size, or a declared size above `max_size`.
[[nodiscard]] std::optional<EntryChunk> decode_entry_chunk(const nlohmann::json& j,
                                                           std::size_t max_size);

/// Joins chunks back into entries, within fixed memory bounds.
///
/// Partial entries are keyed by (sender, stream, seq, digest). The total of
/// buffered chunk bytes never exceeds `max_buffered_bytes`; when a chunk
/// would exceed it, the oldest partial entries are dropped first. A partial
/// entry older than `max_age_ms` is dropped on the next add. Memory grows
/// only with chunk bytes actually received, never with a claimed size.
///
/// Thread safety: every member function is safe to call concurrently.
class EntryAssembler {
public:
    EntryAssembler(std::size_t max_buffered_bytes, uint64_t max_age_ms);

    /// Add one chunk from `sender`. Returns the whole entry once every chunk
    /// of it arrived and the bytes hash to the chunk digest; nullopt
    /// otherwise. A chunk that contradicts earlier chunks of the same entry
    /// (another count or size, or a different chunk length) drops the entry.
    [[nodiscard]] std::optional<std::vector<uint8_t>> add(const std::string& sender,
                                                          const EntryChunk& chunk,
                                                          uint64_t now_ms);

    /// Bytes currently buffered.
    [[nodiscard]] std::size_t buffered_bytes() const;

private:
    using Key = std::tuple<std::string, std::string, uint64_t, std::array<uint8_t, 32>>;
    struct Partial {
        uint32_t count{0};
        uint64_t size{0};
        uint64_t first_ms{0};
        std::size_t bytes{0};
        std::map<uint32_t, std::vector<uint8_t>> chunks;
    };

    void drop_locked(std::map<Key, Partial>::iterator it);

    const std::size_t max_buffered_bytes_;
    const uint64_t max_age_ms_;
    mutable std::mutex mutex_;
    std::map<Key, Partial> partial_;
    std::size_t buffered_{0};
};

}  // namespace nexus::sync
