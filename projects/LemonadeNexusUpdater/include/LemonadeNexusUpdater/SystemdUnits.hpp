#pragma once

// The updater's own systemd units, built in from packaging/systemd, and the
// refresh that keeps the installed copies current.
//
// The fleet receives a release through nexus-updater, which swaps the
// binaries and installs no package. A unit file changed in a release would
// otherwise reach a server only through a hand-installed .deb. Each cycle
// therefore compares the built-in units with the installed copies, rewrites
// the ones that are missing or differ, reloads the manager, and enables the
// path unit. The refresh touches no other unit and never restarts the timer
// or the service that runs the cycle. A failure is logged and never stops an
// upgrade.

#include <LemonadeNexusUpdater/Transport.hpp>

#include <filesystem>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::updater {

struct SystemdUnit {
    /// File name under kSystemdUnitDirectory, such as "nexus-updater.path".
    std::string_view name;
    /// The file as packaging/systemd held it when this binary was built.
    std::string_view content;
};

/// nexus-updater.service, nexus-updater.timer, and nexus-updater.path
/// (generated at configure time from packaging/systemd).
[[nodiscard]] std::span<const SystemdUnit> embedded_systemd_units();

/// Where the package installs the units (install prefix /usr).
inline constexpr std::string_view kSystemdUnitDirectory = "/usr/lib/systemd/system";
inline constexpr std::string_view kUpdaterPathUnit = "nexus-updater.path";

struct UnitRefreshResult {
    /// "<name> (missing)" or "<name> (changed)" for each unit written, in
    /// order.
    std::vector<std::string> refreshed;
    /// Set when a write or a systemctl call failed. What was written stays;
    /// the next cycle retries what differs.
    std::string error;
};

/// Compares every embedded unit with `root`/usr/lib/systemd/system/<name>
/// and writes the missing and differing ones atomically (mode 0644). When
/// anything was written, runs `systemctl daemon-reload` and `systemctl enable
/// --now nexus-updater.path` through `run`. Never throws.
[[nodiscard]] UnitRefreshResult refresh_systemd_units(const std::filesystem::path& root,
                                                      const CommandRunner& run);

}  // namespace nexus::updater
