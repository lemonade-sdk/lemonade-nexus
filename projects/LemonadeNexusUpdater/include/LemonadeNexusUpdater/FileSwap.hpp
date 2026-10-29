#pragma once

// Atomic replacement of the release files, with the previous files kept.
//
// Each target is replaced by rename(2) of a fully written, fsynced file in
// the same directory, so a reader sees the old file or the new one, never a
// partial one. Before the first target changes, every current target is
// copied to the backup directory and the journal records the plan. The
// journal makes the swap resumable: after a crash or power loss, resume()
// finishes the swap, and rollback() restores the backups. Both are
// idempotent.
//
// A swap of several files is not one atomic step; the journal is what makes
// the set consistent. The server is stopped while the set changes.

#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace nexus::updater {

struct SwapFile {
    /// Absolute installed path.
    std::filesystem::path target;
    /// Verified file to install.
    std::filesystem::path staged;
    /// Hex SHA-256 the staged file must have.
    std::string sha256;
    /// Permission bits for the installed file.
    std::filesystem::perms mode{std::filesystem::perms::owner_all |
                                std::filesystem::perms::group_read |
                                std::filesystem::perms::group_exec |
                                std::filesystem::perms::others_read |
                                std::filesystem::perms::others_exec};
};

struct SwapPlan {
    std::string release_tag;
    std::vector<SwapFile> files;
    /// Where the previous files are kept.
    std::filesystem::path backup_dir;
};

enum class SwapPhase { None, BackedUp, Swapped, RolledBack };

class FileSwapper {
public:
    explicit FileSwapper(std::filesystem::path journal_path);

    /// Test seam: called before each rename with the file index. Returning
    /// false stops the swap there, as a crash would, and apply() fails.
    std::function<bool(std::size_t)> before_rename;

    /// Back up, journal, and swap every file. Fails closed on a staged file
    /// whose hash differs from the plan.
    [[nodiscard]] bool apply(const SwapPlan& plan, std::string& error);

    /// Finish a swap the journal shows as started. True when no swap was in
    /// progress or it is now complete.
    [[nodiscard]] bool resume(std::string& error);

    /// Restore every backed-up file from the journaled plan. A target that
    /// did not exist before is removed.
    [[nodiscard]] bool rollback(std::string& error);

    /// Phase and plan from the journal; nullopt when there is no journal.
    [[nodiscard]] std::optional<std::pair<SwapPhase, SwapPlan>> load() const;

    /// Remove the journal after the caller has committed the result.
    void clear();

private:
    [[nodiscard]] bool write_journal(SwapPhase phase, const SwapPlan& plan, std::string& error);
    [[nodiscard]] bool swap_files(const SwapPlan& plan, std::string& error);

    std::filesystem::path journal_path_;
};

/// Copy `source` to `target` via a temporary file in the target directory
/// and an atomic, durable rename. `mode` is applied before the rename.
[[nodiscard]] bool install_file_atomic(const std::filesystem::path& source,
                                       const std::filesystem::path& target,
                                       std::filesystem::perms mode, std::string& error);

/// Write `content` to `target` the same way: a temporary file in the target
/// directory, fsync, `mode`, and an atomic, durable rename.
[[nodiscard]] bool write_file_atomic(std::string_view content,
                                     const std::filesystem::path& target,
                                     std::filesystem::perms mode, std::string& error);

}  // namespace nexus::updater
