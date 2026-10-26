#pragma once

// nexus-updater: one update cycle (design Phase 4 and "OS updates and
// reboot").
//
//   1. Resume an operation the state file shows as interrupted.
//   2. Read the latest GitHub release. Stop when it is not newer than the
//      installed release or when it is the release that halted.
//   3. Fetch manifest.json, its signature, and release-approval.json; verify
//      them (ReleaseVerifier). Fetch the server files and the OS package
//      lock; check each hash against the signed manifest. Verify the Sigstore
//      provenance of every consumed asset. Any failure stops the cycle.
//   4. Stage the verified files under the state directory.
//   5. Offer the approval to the server (its release chain must accept it),
//      report the staged release, and ask for the upgrade turn. Without "go",
//      stop and wait; on "halted", halt this release.
//   6. Take a health baseline. Plan the OS packages and decide whether the
//      boot chain changes. For a reboot, have the server stage the sealed
//      boot set for the new PCRs first.
//   7. Stop the services, swap the files atomically (backups kept), install
//      the exact package versions. Before a package install, keep a copy of
//      the running kernel's initramfs: PCR 9 measures it, and a package can
//      rebuild it through a dpkg trigger. Without a boot-chain change the
//      approval keeps PCR 8/9, so the measured image is put back after the
//      install. A rollback puts it back in every case.
//   8. Without a reboot: start the services and run the health gate. With a
//      reboot: reboot; the next cycle after boot runs the health gate.
//   9. Healthy: record the release as installed and report "upgraded".
//      Otherwise restore the previous files (and packages, and GRUB entry),
//      report "failed", and halt this release until a newer one appears.
//
// The updater holds no server keys. It reads the Genesis public key from the
// server's root-owned configuration and talks to the server only through the
// upgrade control socket (Core/UpgradeControl.hpp, docs/Upgrade-Control.md).

#include <LemonadeNexusUpdater/ControlClient.hpp>
#include <LemonadeNexusUpdater/HealthGate.hpp>
#include <LemonadeNexusUpdater/OsPackages.hpp>
#include <LemonadeNexusUpdater/ReleaseVerifier.hpp>
#include <LemonadeNexusUpdater/Transport.hpp>

#include <chrono>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace nexus::updater {

/// Fixed asset names the release workflow publishes.
inline constexpr std::string_view kManifestAsset = "manifest.json";
inline constexpr std::string_view kManifestSignatureAsset = "manifest.json.sig";
inline constexpr std::string_view kApprovalAsset = "release-approval.json";
/// Provenance bundle of asset X is published as X + this suffix.
inline constexpr std::string_view kProvenanceSuffix = ".sigstore.json";

/// Units the updater stops and starts around a swap, in stop order.
inline constexpr std::string_view kServerUnit = "lemonade-nexus.service";
inline constexpr std::string_view kAttestdUnit = "nexus-attestd.service";

/// Verifies one provenance bundle for an artifact digest.
using ProvenanceCheck = std::function<bool(std::string_view bundle_json,
                                           std::string_view sha256_hex, std::string& error)>;

struct UpdaterEnv {
    HttpGet http;
    /// One control-socket exchange: request line in, response line out.
    std::function<std::optional<std::string>(std::string_view request)> control;
    CommandRunner run;
    ProvenanceCheck provenance;
    std::function<void(std::chrono::seconds)> sleep;
    std::function<std::chrono::steady_clock::time_point()> now;
    /// `uname -r`.
    std::function<std::string()> kernel_release;
};

struct UpdaterConfig {
    /// Prefix for every host path. "/" in production; a temporary directory
    /// in tests.
    std::filesystem::path root{"/"};
    ReleaseTrust trust;
    std::chrono::seconds health_timeout{std::chrono::minutes(15)};
    std::chrono::seconds health_poll{std::chrono::seconds(10)};
    std::size_t max_asset_bytes{256u * 1024 * 1024};
};

enum class CycleOutcome {
    NoUpdate,
    /// Verified and staged; the turn gate has not said "go".
    Waiting,
    Upgraded,
    /// Rolled back after a failure; the release is halted.
    Failed,
    /// A reboot into the new boot chain was started.
    Rebooting,
    /// The latest release halted: this server's rollback, or a finalized Halt.
    Halted,
    /// Verification or an environment check failed; nothing was changed.
    Refused,
};

[[nodiscard]] std::string_view cycle_outcome_name(CycleOutcome outcome);

struct CycleResult {
    CycleOutcome outcome{CycleOutcome::Refused};
    std::string detail;
};

class Updater {
public:
    Updater(UpdaterConfig config, UpdaterEnv env);

    /// Run one cycle. Never throws.
    [[nodiscard]] CycleResult run_once();

    /// Host paths under config.root.
    [[nodiscard]] std::filesystem::path host_path(std::string_view absolute) const;
    [[nodiscard]] std::filesystem::path state_dir() const;

private:
    struct State;
    struct Release;

    CycleResult cycle();
    CycleResult resume(State& state);
    CycleResult start_update(State& state, const Release& release);
    CycleResult finish_without_reboot(State& state);
    CycleResult run_health_gate(State& state);
    CycleResult roll_back(State& state, const std::string& reason, bool restart_services);
    CycleResult commit(State& state, const std::string& detail);

    /// Copy the running kernel's initramfs to the backup of this release and
    /// record it in `state`. A host with no image at that path records none.
    bool back_up_measured_initrd(State& state, std::string& error);
    /// Put the recorded initramfs back when its bytes changed. Fails when the
    /// backup is missing or the restored file does not match it.
    bool restore_measured_initrd(const State& state, std::string& error);

    std::optional<Release> fetch_and_verify(const State& state, std::string& error);
    std::optional<std::string> fetch_asset(const std::string& tag, const std::string& name,
                                           const std::string& url, std::string& error);
    /// The health reply line as received, when it decodes.
    std::optional<std::string> server_health_line();
    std::optional<ServerHealth> server_health();
    void report(const State& state, bool upgraded, const std::string& detail);
    bool systemctl(const std::vector<std::string>& args, std::string& error);
    /// After a package install: every approved path the updater does not
    /// replace must hash to a value the installed approval lists.
    bool check_library_hashes(std::string& error);
    uint64_t installed_release_number(const State& state) const;

    std::optional<State> load_state();
    bool save_state(const State& state);

    UpdaterConfig config_;
    UpdaterEnv env_;
};

}  // namespace nexus::updater
