#pragma once

// Crash-atomic durable write, in one place.
//
// A vote, an epoch handoff and an eligibility record may only be acted on after
// they are on disk. A torn write that survives a crash would let a node vote
// twice, so the ordering is not negotiable: write a temp file beside the final
// name, flush it to the device, then atomically replace, then make the
// replacement itself durable.
//
// ofstream cannot flush to the device, so this is platform code. It lived as
// three drifted copies in the consensus, epoch and eligibility stores; two of
// them skipped the final durability step and all three were POSIX-only, which
// is why the security layer did not build on Windows.

#include <filesystem>
#include <string_view>

namespace nexus::security {

/// Write `payload` to `final_path` so that a crash leaves either the previous
/// content or the new content, never a partial file. False on any failure,
/// including a failure to make the result durable — the caller must treat a
/// false as "this state is not committed".
[[nodiscard]] bool write_durable(const std::filesystem::path& final_path,
                                 std::string_view payload);

/// Like write_durable, but a replacement for an existing file keeps that
/// file's ownership and mode; a failure to reproduce the metadata aborts
/// the write. On Windows (no uid/gid) this is write_durable's behavior.
[[nodiscard]] bool write_durable_preserving(const std::filesystem::path& final_path,
                                            std::string_view payload);

/// Atomically replace `final_path` with `source_path` (same directory), then
/// make the directory entry durable. False on any failure; `final_path` then
/// holds either its previous content or the source content.
[[nodiscard]] bool rename_durable(const std::filesystem::path& source_path,
                                  const std::filesystem::path& final_path);

/// Overwrite the content of `path` with zeros and flush it to the device. Best
/// effort: a journaling or copy-on-write file system, LVM snapshots, or SSD
/// remapping can keep older blocks. A missing file is not an error.
void overwrite_contents(const std::filesystem::path& path);

/// overwrite_contents(), then remove the file. True when the file is gone.
[[nodiscard]] bool scrub_file(const std::filesystem::path& path);

}  // namespace nexus::security
