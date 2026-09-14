#pragma once

// The daemon's response framing, and the bounds that make it safe to read.
//
// These are LOCAL resource bounds, deliberately not the mesh's
// kMaxPlatformEvidenceWireBytes. Whether a bundle can be gossiped is decided by
// the process that gossips it; a bundle too large for the mesh is still the
// right answer to "what does this platform measure". Nor is there a "worst case
// IMA log" to size a single cap against — the log grows for as long as the host
// executes things. So the local path is bounded the way streaming protocols are:
// frame size, frame count, total, deadline.
//
// Wire form, big-endian, one frame after another:
//
//     u32 length   checked against kMaxLocalFrameBytes BEFORE anything is read
//     u8  kind     FrameKind
//     u8  payload[length]
//
// One Header (or one Refusal), then chunks in order, then one End. The reader
// stops at End and never reads to EOF. Chunks carry the canonical
// encode_snp_vtpm_evidence() bytes verbatim, so the client decodes exactly what
// the daemon encoded.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace nexus::attestd {

/// Largest single frame payload, and so the most a reader ever holds at once.
inline constexpr std::size_t kMaxLocalFrameBytes = 64 * 1024;

/// Most chunks in one response: 2 MiB of evidence. Past that, producing it is
/// no longer a bounded operation and becomes the checkpoint protocol's problem.
inline constexpr std::size_t kMaxLocalChunks = 32;

/// Total bytes per operation, frame headers included. A running sum, so no
/// combination of legal frames exceeds it.
inline constexpr std::size_t kMaxLocalResponseBytes =
    kMaxLocalFrameBytes * (kMaxLocalChunks + 2);

/// Wall clock for one exchange, quote included. Bounds a caller that connects
/// and then does nothing.
inline constexpr int kLocalStreamDeadlineSeconds = 30;

enum class FrameKind : uint8_t {
    Header = 1,         ///< challenge digest and the length of what follows, as JSON
    EvidenceChunk = 2,  ///< one slice of the canonical evidence bytes, in order
    End = 3,            ///< chunk count and digest of the reassembled bytes, as JSON
    Refusal = 4,        ///< a typed Refusal instead of a bundle; terminates the stream
};

/// Bytes of one frame. Empty when `payload` is over the frame bound; a caller
/// must treat that as a refusal, never emit a short frame.
[[nodiscard]] std::string encode_frame(FrameKind kind, std::string_view payload);

inline constexpr std::size_t kFrameHeaderBytes = 5;

/// Transport faults on the local socket — not decisions the daemon made.
enum class FrameError : uint8_t {
    None = 0,
    Truncated,     ///< the peer stopped writing, or the deadline expired
    Oversized,     ///< a frame declared more than kMaxLocalFrameBytes
    TooManyChunks, ///< more chunks than kMaxLocalChunks
    TooLarge,      ///< the running total passed kMaxLocalResponseBytes
    Malformed,     ///< unknown kind, bad JSON, or a frame the grammar disallows here
};

[[nodiscard]] std::string_view frame_error_name(FrameError e);

}  // namespace nexus::attestd
