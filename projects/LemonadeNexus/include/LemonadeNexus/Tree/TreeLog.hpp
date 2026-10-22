#pragma once

// The durable log of committed tree blocks (design A6).
//
// Layout under the log directory (data/tree/log):
//   <height>.json           one committed tree block per height, from 1
//   snapshot-<height>.json  the tree after <height>; snapshot-0 is the base
//   applied.json            the height the persistent tree reflects
//
// The log height is independent of consensus views and continues across
// epochs. Every entry chains to the previous one through its state root
// (TreeChain.hpp), so open() verifies the whole log from the latest snapshot
// and fails closed on any break. Every write is crash-atomic
// (security::write_durable), and an entry is on disk before its block is
// applied to the persistent tree.
//
// Not thread-safe; the owner serializes access (TreeConsensus runs it on the
// security io thread).

#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>
#include <LemonadeNexus/Tree/TreeChain.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace nexus::tree {

/// Format version of every tree log file. open() refuses any other value.
inline constexpr uint32_t kTreeLogFormatVersion = 1;

/// A snapshot is written at every multiple of this height, so open() replays
/// at most this many entries.
inline constexpr uint64_t kTreeLogSnapshotInterval = 1000;

/// One committed tree block.
struct TreeLogEntry {
    uint64_t             height = 0;          ///< tree log height, from 1
    uint64_t             block_time_ms = 0;   ///< the block's binding time
    std::vector<uint8_t> batch;               ///< TreeBatch wire form
    security::Digest     ops_digest{};        ///< block_payload_digest of the batch
    security::Digest     previous_root{};     ///< state root of height - 1
    security::Digest     tree_digest{};       ///< compute_tree_digest after the block
    security::Digest     state_root{};        ///< tree_state_root(previous, ops, tree)
    /// Consensus evidence for the commit: epoch, consensus height and view,
    /// proposal digest and QC digest, the proposal header ("proposal",
    /// security::proposal_to_json), and the commit proof ("proof",
    /// security::commit_proof_to_json). The log stores it for replication.
    /// open() checks only that a recorded header states this entry's block
    /// time, ops digest, and roots; it does not verify certificates.
    nlohmann::json       commit = nlohmann::json::object();
};

class TreeLog {
public:
    explicit TreeLog(std::filesystem::path directory);

    enum class OpenResult { Ok, Corrupt };

    /// Load the latest valid snapshot and replay every entry after it,
    /// verifying each entry's ops digest, previous root, tree digest, and
    /// state root. An empty directory starts a new log whose base (height 0)
    /// is `base_nodes`, written as snapshot-0. Corrupt means the log cannot be
    /// trusted; the caller must not apply or validate tree blocks.
    [[nodiscard]] OpenResult open(const rules::NodeMap& base_nodes);

    /// The committed tree state at the log head.
    [[nodiscard]] const TreeChainState& state() const { return state_; }
    [[nodiscard]] uint64_t height() const { return height_; }
    /// The height applied.json records (0 when absent).
    [[nodiscard]] uint64_t applied_height() const { return applied_height_; }

    /// Durably write `entry` as height() + 1, then a snapshot when the new
    /// height is a multiple of kTreeLogSnapshotInterval. `next` is the state
    /// after the block (apply_certified_batch on a copy of state()); its root
    /// must equal entry.state_root. On success state() becomes `next`. False
    /// leaves the log unchanged.
    [[nodiscard]] bool append(const TreeLogEntry& entry, TreeChainState next);

    /// Durably record that the persistent tree reflects `height`.
    [[nodiscard]] bool mark_applied(uint64_t height);

    /// The entry at `height`, or nullopt when absent or unreadable.
    [[nodiscard]] std::optional<TreeLogEntry> read_entry(uint64_t height) const;

    [[nodiscard]] const std::filesystem::path& directory() const { return directory_; }

private:
    [[nodiscard]] std::filesystem::path entry_path(uint64_t height) const;
    [[nodiscard]] std::filesystem::path snapshot_path(uint64_t height) const;
    [[nodiscard]] bool write_snapshot(uint64_t height, const TreeChainState& state) const;
    [[nodiscard]] std::optional<TreeChainState> read_snapshot(uint64_t height) const;

    std::filesystem::path directory_;
    TreeChainState        state_;
    uint64_t              height_ = 0;
    uint64_t              applied_height_ = 0;
};

/// The JSON form of an entry, and its inverse (nullopt on any malformed
/// field).
[[nodiscard]] nlohmann::json tree_log_entry_to_json(const TreeLogEntry& entry);
[[nodiscard]] std::optional<TreeLogEntry> tree_log_entry_from_json(const nlohmann::json& doc);

}  // namespace nexus::tree
