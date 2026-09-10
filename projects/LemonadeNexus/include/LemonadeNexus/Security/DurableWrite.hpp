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

}  // namespace nexus::security
