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
// and fails closed on any break.
//
// An entry is a consensus block (kind Batch, certified by a commit proof) or
// the one merge commit (kind Merge, height 1 only, signed by the root
// management key; TreeMerge.hpp, design A9). Every write is crash-atomic
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

namespace nexus::security { class StorageVault; }

namespace nexus::tree {

/// Format version of every tree log file. open() refuses any other value.
/// Version 2: state roots cover the committed op ids, and entries carry a
/// kind. A version 1 log does not open; delete it and let replication refill
/// it (Configuration.md, tree operations).
inline constexpr uint32_t kTreeLogFormatVersion = 2;

/// What a log entry records.
enum class TreeLogEntryKind : uint8_t {
    /// A committed consensus block: `batch` is a TreeBatch wire form and
    /// `commit` holds the consensus evidence.
    Batch,
    /// The merge commit (design A9): `batch` is a merge body
    /// (encode_merge_body) and `commit` holds the root management key's
    /// signature. Valid only at height 1, on top of the empty base.
    Merge,
};

/// A snapshot is written at every multiple of this height, so open() replays
/// at most this many entries.
inline constexpr uint64_t kTreeLogSnapshotInterval = 1000;

/// One committed tree block.
struct TreeLogEntry {
    TreeLogEntryKind     kind = TreeLogEntryKind::Batch;
    uint64_t             height = 0;          ///< tree log height, from 1
    uint64_t             block_time_ms = 0;   ///< the block's binding time
    std::vector<uint8_t> batch;               ///< TreeBatch wire form, or a merge body
    /// block_payload_digest of the batch, or merge_body_digest of a merge body.
    security::Digest     ops_digest{};
    security::Digest     previous_root{};     ///< state root of height - 1
    security::Digest     tree_digest{};       ///< compute_tree_digest after the block
    /// tree_state_root(previous, ops, tree, committed ids) after the block.
    security::Digest     state_root{};
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

    /// True when the directory holds an entry or a snapshot file, so open()
    /// would load an existing log instead of starting a new one. It checks
    /// file names only and creates nothing. A directory that cannot be listed
    /// counts as holding a log, so a caller that refuses to start a new log
    /// lets open() report the fault instead.
    [[nodiscard]] bool exists() const;

    /// Drop the in-memory state: height 0 and an empty tree. Touches no file;
    /// open() loads the log again.
    void close() {
        state_ = TreeChainState{};
        height_ = 0;
        applied_height_ = 0;
    }

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

    /// The entry at `height`, or nullopt when absent or unreadable. Reads the
    /// file only, so it is safe from another thread while the owner appends
    /// later heights (each write is an atomic rename).
    [[nodiscard]] std::optional<TreeLogEntry> read_entry(uint64_t height) const;

    [[nodiscard]] const std::filesystem::path& directory() const { return directory_; }

    /// Phase 7: entries, snapshots, and the applied marker are read and
    /// written through `vault` when it covers them. Not owning; set before
    /// open().
    void set_vault(security::StorageVault* vault) { vault_ = vault; }

private:
    [[nodiscard]] std::optional<nlohmann::json> read_doc(const std::filesystem::path& path) const;
    [[nodiscard]] bool write_doc(const std::filesystem::path& path, const std::string& text) const;
    [[nodiscard]] std::filesystem::path entry_path(uint64_t height) const;
    [[nodiscard]] std::filesystem::path snapshot_path(uint64_t height) const;
    [[nodiscard]] bool write_snapshot(uint64_t height, const TreeChainState& state) const;
    [[nodiscard]] std::optional<TreeChainState> read_snapshot(uint64_t height) const;

    std::filesystem::path directory_;
    security::StorageVault* vault_ = nullptr;
    TreeChainState        state_;
    uint64_t              height_ = 0;
    uint64_t              applied_height_ = 0;
};

/// The JSON form of an entry, and its inverse (nullopt on any malformed
/// field).
[[nodiscard]] nlohmann::json tree_log_entry_to_json(const TreeLogEntry& entry);
[[nodiscard]] std::optional<TreeLogEntry> tree_log_entry_from_json(const nlohmann::json& doc);

/// The state root of a log's base (height 0) when the log starts from the
/// empty tree. The merge commit chains to it.
[[nodiscard]] security::Digest empty_base_root();

/// Apply `entry` on top of `state`, which must be the state at height
/// entry.height - 1. Checks the structure only, not the authority: the entry
/// must chain (previous_root equals state.root), its ops digest must match its
/// content, its content must apply, and the resulting tree digest and state
/// root must equal the recorded ones. A recorded consensus header, when
/// present, must state the same block time, ops digest, and roots. A merge
/// entry is accepted only at height 1 on top of the empty base. On success
/// `state` is the state after the entry and the result's effects hold the
/// batch's node writes (empty for a merge). On refusal `state` is unchanged
/// and the verdict says why. Authority is checked separately: the commit
/// proof (verify_certified_entry) or the merge signature
/// (verify_merge_signature).
[[nodiscard]] TreeBlockResult replay_entry(TreeChainState& state, const TreeLogEntry& entry);

}  // namespace nexus::tree
