#pragma once

// The ordered batch of tree operations one consensus block carries (design
// A3), and its wire form.
//
// Wire layout (all integers little-endian):
//   u16 count
//   count times: u32 length, `length` bytes of encode_tree_op, 64-byte signature
//
// The layout is canonical: decode_tree_batch accepts only bytes that
// encode_tree_batch would produce for the decoded batch, so the digest of the
// bytes (the block's ops digest) identifies exactly one batch.

#include <LemonadeNexus/Tree/TreeOps.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace nexus::tree {

/// Most ops in one batch. Equal to constants::kMaxTransitionsPerBlock.
inline constexpr std::size_t kMaxTreeBatchOps = 128;

/// Most bytes of canonical op encodings in one batch (the sum over the ops of
/// encode_tree_op). Equal to constants::kMaxConsensusBlockBytes. Framing and
/// signatures add at most kMaxTreeBatchOps * 68 + 2 bytes on the wire.
inline constexpr std::size_t kMaxTreeBatchOpBytes = 48000;

/// An ordered batch of signed ops. Order is significant: each op validates
/// against the state the earlier ops in the batch produced.
struct TreeBatch {
    std::vector<TreeOp> ops;
};

/// Sum of the canonical encoding sizes of the batch's ops.
[[nodiscard]] std::size_t tree_batch_op_bytes(const TreeBatch& batch);

/// Wire form of the batch. nullopt when the batch is empty, exceeds
/// kMaxTreeBatchOps or kMaxTreeBatchOpBytes, or holds an op whose signature is
/// not 64 bytes of base64.
[[nodiscard]] std::optional<std::vector<uint8_t>> encode_tree_batch(const TreeBatch& batch);

/// Parse a wire batch. Bounds are checked before any allocation that depends
/// on a claimed length. nullopt unless the bytes are exactly the encoding of a
/// non-empty batch within both limits whose every op decodes
/// (decode_tree_op). Signatures are not verified here.
[[nodiscard]] std::optional<TreeBatch> decode_tree_batch(std::span<const uint8_t> bytes);

}  // namespace nexus::tree
