#pragma once

#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Storage/IStorageProvider.hpp>

#include <filesystem>
#include <mutex>
#include <optional>
#include <string>

namespace nexus::storage {

/// File-based storage service. All state is stored as signed JSON files.
///
/// Directory layout under data_root:
///   tree/nodes/<node_id>.json     — permission tree nodes
///   tree/deltas/<sequence>.json   — sequential delta log
///   tree/retained_deltas/         — delta transfer pool (record primitives)
///   identity/                     — server keypair, peers
///   credentials/<user_id>.json    — WebAuthn credentials
///   ipam/allocations.json         — IP allocations
///   certs/<domain>/               — TLS certificates
class FileStorageService : public core::IService<FileStorageService>,
                            public IStorageProvider<FileStorageService> {
    friend class core::IService<FileStorageService>;
    friend class IStorageProvider<FileStorageService>;

public:
    // --- Delta transfer pool primitives ---
    //
    // File primitives only: identity verification, indexing, and capacity
    // accounting are the caller's responsibility. A record file is
    //   <record_hash>.json  (record_hash = hex SHA-256 of the canonical
    //   author-signed statement, computed by the caller).
    //
    // Writes are atomic (temp + rename) with file and directory
    // synchronization. A successful return means the bytes are durable per
    // the platform's fsync semantics; it is not a stronger durability claim.

    /// Pool directory entry. `temporary` marks in-flight temp files, which
    /// count toward storage bounds but are never indexed.
    struct PoolEntry {
        std::string hash;
        uint64_t    size_bytes{0};
        bool        record{false};
        bool        temporary{false};
    };

    /// Result of a pool directory scan. An incomplete scan must never be
    /// presented as an empty or complete pool: `truncated` marks a scan that
    /// stopped at the entry cap, `error` an I/O failure that interrupted it.
    struct PoolList {
        std::vector<PoolEntry> entries;
        bool truncated{false};
        bool error{false};
    };

    /// Result of a bounded pool record read.
    enum class PoolRead { Ok, Absent, Oversized, IoError };

    /// State of a record path without following symbolic links. Any directory
    /// entry at the path is Present, even when it is not a readable regular
    /// file, so callers never overwrite evidence after an uncertain check.
    enum class PoolFileState { Present, Absent, IoError };

    /// State of the generation metadata file. Absent means no metadata has
    /// ever been written; IoError means it exists but could not be read —
    /// the caller must not treat unreadable metadata as absent.
    enum class PoolMetaRead { Ok, Absent, IoError };

    /// Outcome of a pool record write. Uncertain means the rename succeeded
    /// but the directory sync failed: the destination file may exist and
    /// its durability is not confirmed. The caller must neither treat the
    /// write as failed (the bytes may be there) nor as confirmed (they may
    /// not be).
    enum class PoolWrite { Ok, Failed, Uncertain };

    /// The pool's log generation, or nullopt when absent or unreadable.
    /// `result` distinguishes the three states.
    [[nodiscard]] std::optional<std::string> read_pool_generation(PoolMetaRead& result) const;
    /// Persist the log generation (atomic). Refuses malformed values.
    [[nodiscard]] bool write_pool_generation(const std::string& generation);
    /// Every physical pool entry except the generation meta file. Record and
    /// temp files are classified; other files still count toward storage
    /// bounds. Nothing is read beyond the directory entry. A scan that is
    /// interrupted (entry cap, I/O failure) reports itself; it is never
    /// presented as complete.
    [[nodiscard]] PoolList list_pool_entries() const;
    /// Read one record file, refusing to read more than max_bytes (returns
    /// Oversized without reading). Absent for a missing file, IoError when
    /// an existing file cannot be read.
    [[nodiscard]] std::optional<std::string> read_pool_record(const std::string& hash,
                                                              uint64_t max_bytes,
                                                              PoolRead& result) const;
    /// Write one record file (atomic + synchronized). The hash must be a
    /// 64-character lowercase hex identifier.
    [[nodiscard]] PoolWrite write_pool_record(const std::string& hash, const std::string& text);
    /// Synchronize the pool directory (durability of the directory entries
    /// it holds). False when the directory is missing or the sync failed.
    [[nodiscard]] bool sync_pool_directory();
    /// Inspect a record path without following symbolic links. Invalid
    /// identifiers and inspection failures report IoError.
    [[nodiscard]] PoolFileState pool_record_state(const std::string& hash) const;
    /// Convenience presence check for diagnostics and tests. Mutation paths
    /// must use pool_record_state() so I/O failure is not treated as absence.
    [[nodiscard]] bool pool_record_exists(const std::string& hash) const {
        return pool_record_state(hash) == PoolFileState::Present;
    }

    /// Test seam: the next pool record write succeeds through the rename
    /// but fails the post-rename directory sync, producing an uncertain
    /// write outcome at the real durability boundary.
    void test_arm_pool_dirsync_failure();
    /// Test seam: the next pool directory synchronization (the
    /// reconstruction durability reconciliation) fails.
    void test_arm_pool_sync_failure();
    /// Test seam: the next read of this record file appends bytes between the
    /// size inspection and the bounded read, simulating a concurrent writer.
    void test_arm_pool_record_growth(const std::string& hash,
                                     std::size_t bytes = 1);
    /// Test seam: the next inspection of this record path reports an I/O
    /// failure, rather than absence.
    void test_arm_pool_record_state_failure(const std::string& hash);
    /// Test seam: remove this listed record immediately before its next read.
    void test_arm_pool_record_disappearance(const std::string& hash);

    /// Test seam: cap for the pool directory enumeration (0 = production
    /// bound).
    void test_set_pool_list_cap(std::size_t cap);
    [[nodiscard]] const std::filesystem::path& pool_dir() const { return pool_dir_; }

    /// An author-signed delta record retained in the transfer pool.
    /// `record_hash` is hex(SHA-256(canonical author-signed statement)),
    /// recomputed from content at every boundary. `position` is a transport
    /// pool position, stored alongside the statement — never signed content.
    struct RetainedDelta {
        uint64_t    position{0};
        std::string record_hash;
        std::string operation;
        std::string target_node_id;
        std::string data;          // node_data JSON
        std::string signer_pubkey; // "ed25519:base64..."
        std::string signature;     // base64 Ed25519
        uint64_t    timestamp{0};

        [[nodiscard]] std::string to_json() const;
        [[nodiscard]] static std::optional<RetainedDelta> from_json(std::string_view text);
    };

public:
    explicit FileStorageService(std::filesystem::path data_root);

    // IService
    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "FileStorageService"; }

    // IStorageProvider — tree nodes
    [[nodiscard]] bool do_write_node(std::string_view node_id, const SignedEnvelope& envelope);
    [[nodiscard]] std::optional<SignedEnvelope> do_read_node(std::string_view node_id) const;
    [[nodiscard]] bool do_delete_node(std::string_view node_id);
    [[nodiscard]] std::vector<std::string> do_list_nodes() const;

    // IStorageProvider — delta log
    [[nodiscard]] uint64_t do_append_delta(const SignedDelta& delta);
    [[nodiscard]] std::optional<SignedDelta> do_read_delta(uint64_t seq) const;
    [[nodiscard]] uint64_t do_latest_delta_seq() const;
    [[nodiscard]] std::vector<SignedDelta> do_read_deltas_since(uint64_t seq) const;

    // IStorageProvider — generic file storage
    [[nodiscard]] bool do_write_file(std::string_view category, std::string_view name,
                                      const SignedEnvelope& envelope);
    [[nodiscard]] std::optional<SignedEnvelope> do_read_file(std::string_view category,
                                                              std::string_view name) const;
    [[nodiscard]] bool do_delete_file(std::string_view category, std::string_view name);
    [[nodiscard]] std::vector<std::string> do_list_files(std::string_view category) const;
    void do_ensure_directories();

    [[nodiscard]] const std::filesystem::path& data_root() const { return data_root_; }

private:
    [[nodiscard]] std::filesystem::path node_path(std::string_view node_id) const;
    [[nodiscard]] std::filesystem::path delta_path(uint64_t seq) const;
    [[nodiscard]] std::filesystem::path file_path(std::string_view category,
                                                    std::string_view file_name) const;
    [[nodiscard]] std::filesystem::path pool_record_path(std::string_view hash) const;

    /// Sync a file descriptor (POSIX fsync / FlushFileBuffers). False on error.
    static bool synchronize_file(int fd);
    /// Sync the directory containing path so the rename itself is durable.
    static bool synchronize_directory(const std::filesystem::path& path);

    /// Write text to path atomically: temp sibling, sync, rename, dir sync.
    /// Uncertain when the rename succeeded but the directory sync failed.
    enum class AtomicWrite { Ok, Failed, Uncertain };
    static AtomicWrite atomic_write_synced(const std::filesystem::path& path,
                                           const std::string& text,
                                           bool force_dirsync_fail = false);

    /// Validate that a user-supplied path component contains no traversal sequences.
    [[nodiscard]] static bool is_safe_path_component(std::string_view component);

    [[nodiscard]] static std::string envelope_to_json(const SignedEnvelope& envelope);
    [[nodiscard]] static std::optional<SignedEnvelope> json_to_envelope(std::string_view json);
    [[nodiscard]] static std::string delta_to_json(const SignedDelta& delta);
    [[nodiscard]] static std::optional<SignedDelta> json_to_delta(std::string_view json);

    std::filesystem::path data_root_;
    std::filesystem::path pool_dir_;
    mutable std::mutex    mutex_;
    uint64_t              next_delta_seq_{1};

    // Test seams.
    std::size_t test_fail_next_pool_dirsync_{0};
    std::size_t test_fail_next_pool_sync_{0};
    mutable std::string test_grow_record_;  // consumed by the const read path
    mutable std::size_t test_grow_record_bytes_{0};
    mutable std::string test_fail_record_state_;
    mutable std::string test_remove_record_;
    std::size_t test_pool_list_cap_{0};
};

} // namespace nexus::storage
