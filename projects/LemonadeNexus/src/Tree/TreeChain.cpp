#include <LemonadeNexus/Tree/TreeChain.hpp>

#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Security/CanonicalEncoding.hpp>

#include <algorithm>

namespace nexus::tree {

namespace {

TreeOpVerdict refuse(TreeOpRefusal refusal, std::string reason) {
    return TreeOpVerdict{refusal, std::move(reason)};
}

/// Batch-level checks shared by validation and certified application.
TreeOpVerdict batch_shape(const TreeBatch& batch, uint64_t block_time_ms,
                          const TreeChainState& state) {
    if (batch.ops.empty()) return refuse(TreeOpRefusal::Malformed, "empty tree batch");
    if (batch.ops.size() > kMaxTreeBatchOps) {
        return refuse(TreeOpRefusal::Oversize, "tree batch holds too many ops");
    }
    if (tree_batch_op_bytes(batch) > kMaxTreeBatchOpBytes) {
        return refuse(TreeOpRefusal::Oversize, "tree batch is too large");
    }
    if (block_time_ms <= state.last_block_time_ms) {
        return refuse(TreeOpRefusal::Stale, "block time does not advance past the last tree block");
    }
    return {};
}

/// Close a block: prune ids that can no longer pass freshness, record the
/// block time, and chain the root.
void finish_block(TreeChainState& next, uint64_t block_time_ms,
                  const security::Digest& ops_digest, TreeBlockResult& out) {
    next.committed.prune_signed_before(committed_id_cutoff(block_time_ms / 1000));
    next.last_block_time_ms = block_time_ms;
    out.tree_digest = compute_tree_digest(next.nodes);
    out.root = tree_state_root(next.root, ops_digest, out.tree_digest);
    next.root = out.root;
}

}  // namespace

security::Digest tree_state_root(const security::Digest& previous_root,
                                 const security::Digest& ops_digest,
                                 const security::Digest& tree_digest) {
    security::CanonicalEncoder enc(kTreeStateRootDomain);
    enc.add_bytes(previous_root);
    enc.add_bytes(ops_digest);
    enc.add_bytes(tree_digest);
    return enc.digest();
}

security::Digest base_state_root(const security::Digest& tree_digest) {
    security::CanonicalEncoder enc(kTreeBaseRootDomain);
    enc.add_bytes(tree_digest);
    return enc.digest();
}

TreeBlockResult apply_certified_batch(TreeChainState& state, const TreeBatch& batch,
                                      uint64_t block_time_ms,
                                      const security::Digest& ops_digest) {
    TreeBlockResult out;
    out.verdict = batch_shape(batch, block_time_ms, state);
    if (!out.verdict.ok()) return out;
    TreeChainState next = state;
    for (std::size_t i = 0; i < batch.ops.size(); ++i) {
        TreeOpEffect effect;
        out.verdict = plan_op(batch.ops[i], next.nodes, effect);
        if (!out.verdict.ok()) {
            out.failed_index = i;
            out.effects.clear();
            return out;
        }
        apply_effect(next.nodes, effect);
        record_committed(next.committed, batch.ops[i]);
        out.effects.push_back(std::move(effect));
    }
    finish_block(next, block_time_ms, ops_digest, out);
    state = std::move(next);
    return out;
}

TreeBlockResult check_batch(crypto::SodiumCryptoService& crypto, TreeChainState& state,
                            const TreeBatch& batch, uint64_t block_time_ms,
                            const security::Digest& ops_digest, const TreeOpPolicy& policy) {
    TreeBlockResult out;
    out.verdict = batch_shape(batch, block_time_ms, state);
    if (!out.verdict.ok()) return out;
    TreeChainState next = state;
    const uint64_t block_time_sec = block_time_ms / 1000;
    for (std::size_t i = 0; i < batch.ops.size(); ++i) {
        const TreeOp& op = batch.ops[i];
        out.verdict = validate_op(crypto, op, TreeState(next.nodes, policy), block_time_sec,
                                  next.committed);
        TreeOpEffect effect;
        if (out.verdict.ok()) out.verdict = plan_op(op, next.nodes, effect);
        if (!out.verdict.ok()) {
            out.failed_index = i;
            out.effects.clear();
            return out;
        }
        apply_effect(next.nodes, effect);
        record_committed(next.committed, op);
        out.effects.push_back(std::move(effect));
    }
    finish_block(next, block_time_ms, ops_digest, out);
    state = std::move(next);
    return out;
}

TreeBatchSelection select_batch(crypto::SodiumCryptoService& crypto,
                                const TreeChainState& state,
                                const std::vector<TreeOp>& candidates, uint64_t block_time_ms,
                                const TreeOpPolicy& policy, std::size_t max_ops,
                                std::size_t max_wire_bytes) {
    TreeBatchSelection out;
    if (block_time_ms <= state.last_block_time_ms) return out;
    const std::size_t op_limit = std::min(max_ops, kMaxTreeBatchOps);
    TreeChainState next = state;
    const uint64_t block_time_sec = block_time_ms / 1000;
    std::size_t op_bytes = 0;
    std::size_t wire_bytes = 2;  // the u16 count
    for (const TreeOp& op : candidates) {
        if (out.batch.ops.size() >= op_limit) break;
        const std::size_t size = encode_tree_op(op).size();
        const std::size_t wire = 4 + size + crypto::kEd25519SignatureSize;
        if (op_bytes + size > kMaxTreeBatchOpBytes || wire_bytes + wire > max_wire_bytes) {
            continue;  // a smaller op later in the list may still fit
        }
        auto verdict = validate_op(crypto, op, TreeState(next.nodes, policy), block_time_sec,
                                   next.committed);
        TreeOpEffect effect;
        if (verdict.ok()) verdict = plan_op(op, next.nodes, effect);
        if (!verdict.ok()) {
            out.refused.emplace_back(op_id_hex(op), std::move(verdict));
            continue;
        }
        apply_effect(next.nodes, effect);
        record_committed(next.committed, op);
        out.batch.ops.push_back(op);
        op_bytes += size;
        wire_bytes += wire;
    }
    return out;
}

}  // namespace nexus::tree
