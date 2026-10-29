#pragma once

// The local control interface between the server and nexus-updater
// (Design-Auto-Update Phase 4 and 5).
//
// Transport: a Unix stream socket. The server accepts a connection only when
// the peer's kernel-reported user id is root (SO_PEERCRED on Linux,
// getpeereid elsewhere); every other peer is closed before it can send a
// byte. The socket file is mode 0600. There is no network listener.
//
// Protocol: one JSON object per line in each direction, at most
// kMaxUpgradeControlLine bytes. Requests (field "op"):
//
//   {"op":"status"}
//   {"op":"health"}
//   {"op":"offer_approval","bundle":"<release approval bundle JSON text>"}
//   {"op":"stage","release_number":N}
//   {"op":"turn","release_number":N}
//   {"op":"report","release_number":N,"result":"failed"|"upgraded"}
//   {"op":"stage_boot_chain","bundle":"<release approval bundle JSON text>"}
//   {"op":"tree_merge_<step>", ...}   the one-time tree merge
//                                     (TreeMigrationControl.hpp)
//
// Every reply has "ok" (bool); a refusal adds "error". docs/Upgrade-Control.md
// lists the reply fields. The gate answers come only from finalized upgrade
// records (UpgradeService::gate); a report is a request, never a grant.
// stage_boot_chain acts only on the approval the release chain already
// accepted, so the caller cannot choose the PCR values.

#include <LemonadeNexus/Core/BootChainStaging.hpp>
#include <LemonadeNexus/Security/Upgrade/UpgradeService.hpp>

#include <asio.hpp>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace nexus::core {

/// The production socket path. The directory is the service's runtime
/// directory.
inline constexpr std::string_view kUpgradeControlSocketPath = "/run/lemonade-nexus/upgrade.sock";
/// The marker the server touches when a rollout it takes part in starts and
/// when its upgrade turn opens (UpgradeService). nexus-updater.path watches
/// it and starts an updater cycle; nexus-updater.timer is the fallback.
inline constexpr std::string_view kUpdaterWakePath = "/run/lemonade-nexus/updater-wake";
/// Largest request or reply line. The tree merge requests carry every
/// server's tree export, so the limit is larger than an approval bundle
/// needs. Only a root peer can send a line.
inline constexpr std::size_t kMaxUpgradeControlLine = 32 * 1024 * 1024;

/// The tree log progress for the health report (Design-Auto-Update Phase 4
/// step 7).
struct UpgradeTreeStatus {
    bool healthy = false;
    uint64_t height = 0;
    uint64_t applied_height = 0;
    /// A committed block did not follow the local log.
    bool behind = false;
    /// Replicated entries held for a later height.
    uint64_t held = 0;
};

/// Facts and actions the control interface serves from outside
/// UpgradeService. Each member may be unset; the reply then says so. Both run
/// on the security io thread.
struct UpgradeControlHooks {
    /// The tree log progress, or nullopt while the tree log is off. Must be
    /// thread-safe against the owner of the tree log.
    std::function<std::optional<UpgradeTreeStatus>()> tree_status;
    /// Answers a tree_merge_* request (handle_tree_migration_request). Unset,
    /// those requests are refused.
    std::function<nlohmann::json(const nlohmann::json& request)> tree_merge;
    /// Seals a second copy of the boot set to the PCR 8/9 of `accepted`, an
    /// approval the release chain already accepted and verified.
    std::function<BootChainStageResult(const security::ReleaseApprovalBundleV1& accepted)>
        stage_boot_chain;
};

/// Handles one request line and returns one reply line (without the newline).
/// Call on the security io thread: it calls into `service` and `hooks`.
[[nodiscard]] std::string handle_upgrade_control_request(security::UpgradeService& service,
                                                         std::string_view line,
                                                         const UpgradeControlHooks& hooks = {});

#if defined(ASIO_HAS_LOCAL_SOCKETS) && !defined(_WIN32)
#define LEMONADE_HAVE_UPGRADE_CONTROL 1

struct UpgradeControlConfig {
    std::filesystem::path socket_path{kUpgradeControlSocketPath};
    /// The only peer user id accepted. Production passes 0 (root); a test
    /// passes its own user id.
    uint32_t allowed_uid = 0;
    UpgradeControlHooks hooks;
};

/// Accepts root-only connections and runs each request on the security io
/// thread through `post`. Not thread-safe; start and stop on the io thread
/// that runs `io`.
class UpgradeControlServer {
public:
    using Post = std::function<void(std::function<void()>)>;

    /// Not owning: `service` must outlive the server, and work handed to
    /// `post` must run on the thread that owns `service`.
    UpgradeControlServer(asio::io_context& io, UpgradeControlConfig config, Post post,
                         security::UpgradeService& service);
    ~UpgradeControlServer();

    UpgradeControlServer(const UpgradeControlServer&) = delete;
    UpgradeControlServer& operator=(const UpgradeControlServer&) = delete;

    /// Binds the socket. False with `error` set when it cannot.
    [[nodiscard]] bool start(std::string& error);
    void stop();

private:
    class Session;
    void accept();

    asio::io_context& io_;
    UpgradeControlConfig config_;
    Post post_;
    security::UpgradeService& service_;
    asio::local::stream_protocol::acceptor acceptor_;
    /// Cleared on stop; sessions check it before touching the service.
    std::shared_ptr<bool> alive_;
};
#endif

}  // namespace nexus::core
