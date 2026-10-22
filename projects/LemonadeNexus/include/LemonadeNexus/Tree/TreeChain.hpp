#pragma once

// Deterministic evaluation of tree batches along a consensus chain (design
// A4 and A5).
//
// TreeChainState is the tree at one point of the tree log: the nodes, the
// committed op ids, the block time of the last tree block, and the state root
// of that block. Every function here is a pure function of its arguments; the
// block time comes from the block header, never from a local clock.
//
// State roots form a hash chain over the tree log:
//   root(n) = H(kTreeStateRootDomain, root(n-1), ops_digest(n), tree_digest(n),
//               committed_digest(n))
// where tree_digest(n) is compute_tree_digest of the tree after block n,
// committed_digest(n) is compute_committed_digest of the committed op ids
// after block n, and root(0) is base_state_root(tree_digest(0)). A replica
// that missed a tree block cannot match the next block's previous root, so it
// never applies a later block on top of a gap. The root covers the committed
// ids, so a snapshot's ids are checked against a certified root too.

#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>
#include <LemonadeNexus/Tree/TreeBatch.hpp>
#include <LemonadeNexus/Tree/TreeOps.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace nexus::crypto { class SodiumCryptoService; }

namespace nexus::tree {

inline constexpr std::string_view kTreeStateRootDomain = "lemonade-nexus/tree-state-root:v2";
inline constexpr std::string_view kTreeBaseRootDomain = "lemonade-nexus/tree-base-root:v1";
inline constexpr std::string_view kTreeCommittedIdsDomain = "lemonade-nexus/tree-committed-ids:v1";

/// Most a tree block time may differ from a replica's own clock, in either
/// direction, before the replica withholds its vote (design A4).
inline constexpr uint64_t kTreeBlockClockSkewMs = 60'000;

/// The tree at one point of the tree log.
struct TreeChainState {
    rules::NodeMap   nodes;
    CommittedOpIds   committed;
    /// Block time (Unix milliseconds) of the last tree block applied; 0 at the
    /// base. Tree block times strictly increase along the log.
    uint64_t         last_block_time_ms = 0;
    /// State root after the last tree block applied (base_state_root at the
    /// base).
    security::Digest root{};
};

/// Deterministic digest of a committed op id set: the count, then every id
/// with its signed time, in id order.
[[nodiscard]] security::Digest compute_committed_digest(const CommittedOpIds& committed);

/// root(n) from root(n-1), the block's ops digest, the tree digest after it,
/// and the committed id digest after it.
[[nodiscard]] security::Digest tree_state_root(const security::Digest& previous_root,
                                               const security::Digest& ops_digest,
                                               const security::Digest& tree_digest,
                                               const security::Digest& committed_digest);

/// The state root of `state` after a block with `ops_digest` on top of
/// `previous_root`: tree_state_root over its tree and committed ids.
[[nodiscard]] security::Digest chain_state_root(const security::Digest& previous_root,
                                                const security::Digest& ops_digest,
                                                const TreeChainState& state);

/// root(0) for a log that starts from a tree with digest `tree_digest`.
[[nodiscard]] security::Digest base_state_root(const security::Digest& tree_digest);

/// What a block did to a chain state.
struct TreeBlockResult {
    TreeOpVerdict verdict;
    /// Index of the op that failed, when verdict is not ok.
    std::size_t failed_index = 0;
    security::Digest tree_digest{};
    security::Digest root{};
    /// One effect per op, in batch order (for the persistent tree).
    std::vector<TreeOpEffect> effects;
};

/// Apply a batch from a block a quorum certified, without validation (the
/// quorum validated it). Each op is planned against the state the earlier ops
/// produced; a plan that fails means this state is not the one the quorum
/// evaluated, and `state` is left unchanged. On success `state` holds the
/// tree after the block, its ids (pruned to the block time), the block time,
/// and the new root.
[[nodiscard]] TreeBlockResult apply_certified_batch(TreeChainState& state,
                                                    const TreeBatch& batch,
                                                    uint64_t block_time_ms,
                                                    const security::Digest& ops_digest);

/// Decide whether a proposed batch is valid against `state` at
/// `block_time_ms`: a non-empty batch inside both batch limits, a block time
/// later than state.last_block_time_ms, and every op passing validate_op in
/// order against the state the earlier ops produced. On success `state` is
/// advanced exactly as apply_certified_batch would advance it; on refusal it
/// is left unchanged.
[[nodiscard]] TreeBlockResult check_batch(crypto::SodiumCryptoService& crypto,
                                          TreeChainState& state, const TreeBatch& batch,
                                          uint64_t block_time_ms,
                                          const security::Digest& ops_digest,
                                          const TreeOpPolicy& policy);

/// A leader's batch: the longest prefix-ordered selection of `candidates`
/// that validates in order, within the limits.
struct TreeBatchSelection {
    TreeBatch batch;
    /// Candidates refused against the running state, with the verdict. A
    /// refusal here can be transient (an uncommitted ancestor may not commit),
    /// so the caller decides what to do with them.
    std::vector<std::pair<std::string, TreeOpVerdict>> refused;
};

/// Pick ops from `candidates` (in order) for a block at `block_time_ms` on top
/// of `state`, skipping ops that do not validate against the running state.
/// Stops when the next op would exceed `max_ops`, kMaxTreeBatchOpBytes, or
/// `max_wire_bytes` of batch wire form. `state` is not changed.
[[nodiscard]] TreeBatchSelection select_batch(crypto::SodiumCryptoService& crypto,
                                              const TreeChainState& state,
                                              const std::vector<TreeOp>& candidates,
                                              uint64_t block_time_ms,
                                              const TreeOpPolicy& policy,
                                              std::size_t max_ops,
                                              std::size_t max_wire_bytes);

}  // namespace nexus::tree
