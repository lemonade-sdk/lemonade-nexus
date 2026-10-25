#pragma once

// The release's OS package set (release/os-packages.lock) and the boot-chain
// decision (design: OS updates and reboot).
//
// Lock format, one record per line; '#' starts a comment line:
//
//   format 1
//   package <name> <version> <role>
//
// role is one of:
//   boot     part of the measured boot chain (kernel, GRUB, shim). A change
//            changes PCR 8/9, so it needs re-measured PCRs in the approval
//            and a reboot.
//   library  provides a system library the approval pins by hash.
//   system   any other pinned package.
//
// The updater installs exactly these versions with apt and nothing else. It
// never runs a distribution upgrade.

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::updater {

enum class PackageRole : uint8_t { Boot, Library, System };

struct OsPackage {
    std::string name;
    std::string version;
    PackageRole role{PackageRole::System};
};

struct OsPackageLock {
    std::vector<OsPackage> packages;
};

inline constexpr std::size_t kMaxOsLockBytes = 64 * 1024;

/// Strict parse. Names follow Debian policy ([a-z0-9][a-z0-9+.-]+), versions
/// use the Debian version character set. Duplicates fail.
[[nodiscard]] std::optional<OsPackageLock> parse_os_package_lock(std::string_view text,
                                                                 std::string& error);

struct OsPackagePlan {
    /// Packages whose installed version differs from the lock.
    std::vector<OsPackage> install;
    /// The versions installed before, for rollback. Empty version: the
    /// package was not installed.
    std::vector<OsPackage> previous;
    bool boot_chain_changed{false};
};

/// `installed` maps package name to installed version (absent: not installed).
[[nodiscard]] OsPackagePlan plan_os_packages(const OsPackageLock& lock,
                                             const std::map<std::string, std::string>& installed);

/// argv for dpkg-query that lists the installed version of each name.
[[nodiscard]] std::vector<std::string> dpkg_query_argv(const OsPackageLock& lock);

/// Parse "name<TAB>version<TAB>status" lines from dpkg_query_argv(). Only
/// packages in state "ii" count as installed.
[[nodiscard]] std::map<std::string, std::string> parse_dpkg_query(std::string_view output);

/// argv for apt-get that installs exactly `packages` (name=version). Empty
/// when `packages` is empty. Downgrades are allowed so a rollback can
/// reinstall the previous versions.
[[nodiscard]] std::vector<std::string> apt_install_argv(const std::vector<OsPackage>& packages);

struct RebootDecision {
    bool reboot{false};
    /// Set when the release is inconsistent; the update must stop.
    std::string error;
};

/// A boot-chain change and a PCR change must come together. A lock that
/// changes a boot package with unchanged PCRs, or PCRs that change with no
/// boot package change, is refused: either the reboot would fail attestation
/// or the PCR values were not measured for this package set.
[[nodiscard]] RebootDecision decide_reboot(bool lock_boot_changed, bool approval_pcrs_changed);

// ---------------------------------------------------------------------------
// GRUB
// ---------------------------------------------------------------------------

/// True when /etc/default/grub sets GRUB_DEFAULT=saved. grub-reboot (a
/// one-time boot entry) works only then, so a boot-chain update requires it.
[[nodiscard]] bool grub_default_is_saved(std::string_view etc_default_grub);

/// The grub-reboot entry path ("submenu-id>entry-id" or "entry-id") of the
/// menu entry that boots /boot/vmlinuz-<kernel_release>, from grub.cfg.
[[nodiscard]] std::optional<std::string> grub_entry_for_kernel(std::string_view grub_cfg,
                                                               std::string_view kernel_release);

}  // namespace nexus::updater
