#include <LemonadeNexus/Tree/TreeBatch.hpp>

#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <cstring>

namespace nexus::tree {

static_assert(kMaxTreeBatchOps == security::constants::kMaxTransitionsPerBlock);
static_assert(kMaxTreeBatchOpBytes == security::constants::kMaxConsensusBlockBytes);
static_assert(kMaxTreeOpEncodedBytes == kMaxTreeBatchOpBytes,
              "any valid op must fit in one batch");

namespace {

void put_u16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>(v & 0xFF));
    out.push_back(static_cast<uint8_t>(v >> 8));
}

void put_u32(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
}

}  // namespace

std::size_t tree_batch_op_bytes(const TreeBatch& batch) {
    std::size_t total = 0;
    for (const auto& op : batch.ops) total += encode_tree_op(op).size();
    return total;
}

std::optional<std::vector<uint8_t>> encode_tree_batch(const TreeBatch& batch) {
    if (batch.ops.empty() || batch.ops.size() > kMaxTreeBatchOps) return std::nullopt;
    std::vector<uint8_t> out;
    put_u16(out, static_cast<uint16_t>(batch.ops.size()));
    std::size_t op_bytes = 0;
    for (const auto& op : batch.ops) {
        const auto signature = tree_op_signature_bytes(op);
        if (!signature) return std::nullopt;
        const auto encoded = encode_tree_op(op);
        op_bytes += encoded.size();
        if (op_bytes > kMaxTreeBatchOpBytes) return std::nullopt;
        put_u32(out, static_cast<uint32_t>(encoded.size()));
        out.insert(out.end(), encoded.begin(), encoded.end());
        out.insert(out.end(), signature->begin(), signature->end());
    }
    return out;
}

std::optional<TreeBatch> decode_tree_batch(std::span<const uint8_t> bytes) {
    std::size_t pos = 0;
    const auto remaining = [&] { return bytes.size() - pos; };
    if (remaining() < 2) return std::nullopt;
    const uint16_t count = static_cast<uint16_t>(bytes[0] | (bytes[1] << 8));
    pos = 2;
    if (count == 0 || count > kMaxTreeBatchOps) return std::nullopt;

    TreeBatch batch;
    batch.ops.reserve(count);
    std::size_t op_bytes = 0;
    for (uint16_t i = 0; i < count; ++i) {
        if (remaining() < 4) return std::nullopt;
        uint32_t length = 0;
        for (int b = 0; b < 4; ++b) length |= uint32_t{bytes[pos + static_cast<std::size_t>(b)]} << (8 * b);
        pos += 4;
        // The batch limit bounds every op before its bytes are touched.
        if (length > kMaxTreeBatchOpBytes - op_bytes) return std::nullopt;
        if (remaining() < std::size_t{length} + crypto::kEd25519SignatureSize) return std::nullopt;
        op_bytes += length;
        const auto encoding = bytes.subspan(pos, length);
        pos += length;
        crypto::Ed25519Signature signature{};
        std::memcpy(signature.data(), bytes.data() + pos, signature.size());
        pos += signature.size();
        auto op = decode_tree_op(encoding, signature);
        if (!op) return std::nullopt;
        batch.ops.push_back(std::move(*op));
    }
    if (pos != bytes.size()) return std::nullopt;
    return batch;
}

}  // namespace nexus::tree
