#pragma once

// The local control interface between the server and nexus-updater.
//
// Transport: one unix domain socket, owned by the server's account, mode
// 0600, in the server's runtime directory. Only that account and root can
// connect. root is the updater; there is no group ACL and no TCP listener.
// One request per connection: one JSON object and a newline, then one JSON
// object and a newline back, then close.
//
// Operations:
//   status            What the health gate reads: version, installed approval,
//                     epoch role, storage unlock, tree log progress.
//   may_restart       The upgrade turn. The server answers from finalized
//                     consensus state (design Phase 5). Until Phase 5 lands
//                     the server runs RefusingTurnGate, which refuses.
//   report            The updater's "upgraded" or "failed" for one release.
//                     Recorded as finalized state by Phase 5; refused today.
//   stage_boot_chain  Seal a second copy of the boot set to the PCR 8/9 of a
//                     verified release approval, before a reboot into a new
//                     boot chain. The server verifies the approval itself
//                     against its Genesis anchor; the updater is not trusted
//                     for it.
//
// Socket access is not authority. A caller cannot change Tier 1 membership,
// finalized state, or keys through this interface. stage_boot_chain writes
// only the staged ("next") sealed slot, for PCR values a Genesis-delegated
// release key signed.

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::update {

/// Fixed path: the unit's RuntimeDirectory= creates /run/lemonade-nexus.
inline constexpr std::string_view kUpdateControlSocketPath =
    "/run/lemonade-nexus/update-control.sock";

/// A request carries at most one release approval bundle (a few KiB).
inline constexpr std::size_t kMaxControlRequestBytes = 64 * 1024;
inline constexpr std::size_t kMaxControlResponseBytes = 64 * 1024;

/// Wall clock for one exchange. Boot-chain staging talks to the TPM through
/// nexus-attestd, so it gets the longest bound.
inline constexpr int kControlDeadlineSeconds = 90;

/// What the server reports about itself. The health gate compares two of
/// these: one before the swap and one after.
struct UpdateServerStatus {
    /// Compiled version (NEXUS_VERSION).
    std::string version;
    /// release_id and canonical digest of the installed, verified approval.
    /// Empty when the server has no verified approval.
    std::string release_id;
    std::string approval_digest_hex;

    /// Epoch role. Tier 1 membership is decided by the mesh after it verifies
    /// this node's attestation; it is the attestation result the gate reads.
    bool epoch_known{false};
    uint64_t epoch{0};
    bool tier1_member{false};

    /// Storage unlock: false only while files are encrypted and the data key
    /// is not in memory.
    bool storage_files_ready{false};
    std::string storage_phase;

    /// Tree log progress. tree_enabled is false when the log is off.
    bool tree_enabled{false};
    bool tree_healthy{false};
    uint64_t tree_height{0};
    uint64_t tree_applied_height{0};
    bool tree_behind{false};
    uint64_t tree_held{0};
};

struct TurnRequest {
    uint64_t release_number{0};
    std::string release_id;
};

struct TurnDecision {
    bool granted{false};
    std::string reason;
};

enum class UpgradeOutcome : uint8_t { Upgraded, Failed };

struct UpgradeReport {
    uint64_t release_number{0};
    std::string release_id;
    UpgradeOutcome outcome{UpgradeOutcome::Failed};
    std::string detail;
};

struct ReportAck {
    bool accepted{false};
    std::string reason;
};

struct BootChainStageResult {
    bool ok{false};
    /// Sealing domains that now have a next blob for the approval's PCRs.
    std::vector<std::string> staged;
    std::string detail;
};

/// The upgrade-turn gate (design Phase 5). CRTP, like the other services.
/// Implementations answer from finalized consensus state only; local
/// observations do not grant a turn.
template <typename Derived>
class IUpgradeTurnGate {
public:
    [[nodiscard]] TurnDecision may_restart(const TurnRequest& request) {
        return self().do_may_restart(request);
    }
    [[nodiscard]] ReportAck report(const UpgradeReport& report) {
        return self().do_report(report);
    }

protected:
    ~IUpgradeTurnGate() = default;

private:
    Derived& self() { return static_cast<Derived&>(*this); }
};

/// The gate until Phase 5 exists: it never grants a turn and records no
/// report. A server that cannot prove its turn must not restart.
class RefusingTurnGate : public IUpgradeTurnGate<RefusingTurnGate> {
    friend class IUpgradeTurnGate<RefusingTurnGate>;
    TurnDecision do_may_restart(const TurnRequest&) {
        return {false, "the consensus upgrade turn is not implemented on this server"};
    }
    ReportAck do_report(const UpgradeReport&) {
        return {false, "upgrade reports are not recorded on this server yet"};
    }
};

/// Server-side handlers. Every member must be set; the socket answers an
/// unset handler with an error.
struct UpdateControlHandlers {
    std::function<UpdateServerStatus()> status;
    std::function<TurnDecision(const TurnRequest&)> may_restart;
    std::function<ReportAck(const UpgradeReport&)> report;
    /// Argument: the release approval bundle JSON text.
    std::function<BootChainStageResult(std::string_view)> stage_boot_chain;
};

/// Bind a gate's two operations into handlers. The gate must outlive them.
template <typename Gate>
void bind_turn_gate(UpdateControlHandlers& handlers, Gate& gate) {
    handlers.may_restart = [&gate](const TurnRequest& r) { return gate.may_restart(r); };
    handlers.report = [&gate](const UpgradeReport& r) { return gate.report(r); };
}

// ---------------------------------------------------------------------------
// Codec. Strict: unknown operations, wrong types, and oversized input fail.
// ---------------------------------------------------------------------------

/// Serve one request line with `handlers`. Always returns one response line
/// (newline included); malformed input gets {"error": "..."}.
[[nodiscard]] std::string handle_control_request(std::string_view request,
                                                 const UpdateControlHandlers& handlers);

[[nodiscard]] std::string encode_status_request();
[[nodiscard]] std::string encode_turn_request(const TurnRequest& request);
[[nodiscard]] std::string encode_report_request(const UpgradeReport& report);
[[nodiscard]] std::string encode_stage_request(std::string_view approval_json);

[[nodiscard]] std::optional<UpdateServerStatus> decode_status_response(std::string_view line);
[[nodiscard]] std::optional<TurnDecision> decode_turn_response(std::string_view line);
[[nodiscard]] std::optional<ReportAck> decode_report_response(std::string_view line);
[[nodiscard]] std::optional<BootChainStageResult> decode_stage_response(std::string_view line);

// ---------------------------------------------------------------------------
// Transport (POSIX only; on other platforms open() fails and exchange()
// returns nullopt).
// ---------------------------------------------------------------------------

/// Send one request line and read one response line, bounded by
/// kMaxControlResponseBytes and `deadline_seconds`. nullopt on any transport
/// failure, including a server that is not running.
[[nodiscard]] std::optional<std::string> control_exchange(const std::filesystem::path& socket,
                                                          std::string_view request,
                                                          int deadline_seconds);

/// The server's listener. One thread, one request at a time.
class UpdateControlSocket {
public:
    UpdateControlSocket() = default;
    ~UpdateControlSocket();
    UpdateControlSocket(const UpdateControlSocket&) = delete;
    UpdateControlSocket& operator=(const UpdateControlSocket&) = delete;

    /// Bind `path` (mode 0600; a stale socket file is replaced), listen, and
    /// start the serving thread. False with a reason when it cannot.
    [[nodiscard]] bool start(const std::filesystem::path& path, UpdateControlHandlers handlers,
                             std::string& why);

    /// Stop the thread, close the socket, and remove the file. Idempotent.
    void stop();

    /// Listener state, shared with the serving thread. Implementation detail.
    struct State;

private:
    std::shared_ptr<State> state_;
};

}  // namespace nexus::update
