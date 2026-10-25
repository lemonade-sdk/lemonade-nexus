#pragma once

// The updater side of the server's upgrade control socket
// (Core/UpgradeControl.hpp, docs/Upgrade-Control.md).
//
// The server owns the protocol: one JSON object per line in each direction,
// root peers only. This file encodes the requests the updater sends and
// decodes the replies strictly: a reply with a missing or mistyped field is
// nullopt, never a default. The updater treats nullopt like no answer.

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::updater {

/// Wall clock for one exchange. Boot-chain staging talks to the TPM through
/// nexus-attestd on the server's security thread, so it gets the longest bound.
inline constexpr int kControlDeadlineSeconds = 90;

/// The tree log progress in a health reply.
struct ControlTreeStatus {
    bool healthy = false;
    uint64_t height = 0;
    uint64_t applied_height = 0;
    bool behind = false;
    uint64_t held = 0;
};

/// The reply to {"op":"health"}.
struct ServerHealth {
    /// The release number of the running binary's packaged approval.
    uint64_t running_release = 0;
    /// The highest release number the release chain accepted.
    uint64_t accepted_release = 0;
    std::string driver_phase;
    bool driver_failed = false;
    bool verified_authority = false;
    bool tier1_member = false;
    std::optional<uint64_t> epoch;
    /// Informational only: "locked" during a rollout is pending quorum, never
    /// a failure (Upgrade-Control.md, Health).
    std::string data_key;
    /// Verified epoch authority and a driver that has not failed.
    bool healthy = false;
    /// nullopt while the server runs no tree log.
    std::optional<ControlTreeStatus> tree;
};

/// The turn gate (Upgrade-Control.md, Gate).
enum class TurnGate : uint8_t { Go, Wait, Done, Halted, NotStarted };

[[nodiscard]] std::string_view turn_gate_name(TurnGate gate);

/// The reply to offer_approval: `result` is the server's word ("adopted",
/// "current", "stale", ...). `ok` is true only for adopted and current.
struct OfferReply {
    bool ok = false;
    std::string result;
    uint64_t accepted_release = 0;
};

struct BootChainReply {
    bool ok = false;
    std::vector<std::string> staged;
    std::string detail;
};

[[nodiscard]] std::string encode_health_request();
[[nodiscard]] std::string encode_offer_request(std::string_view bundle_json);
[[nodiscard]] std::string encode_stage_request(uint64_t release_number);
[[nodiscard]] std::string encode_turn_request(uint64_t release_number);
/// `upgraded` false reports "failed": the health gate failed and the updater
/// rolled back. "upgraded" is informational on the server.
[[nodiscard]] std::string encode_report_request(uint64_t release_number, bool upgraded);
[[nodiscard]] std::string encode_stage_boot_chain_request(std::string_view bundle_json);

[[nodiscard]] std::optional<ServerHealth> decode_health_reply(std::string_view line);
[[nodiscard]] std::optional<OfferReply> decode_offer_reply(std::string_view line);
/// nullopt for a refusal or a malformed reply.
[[nodiscard]] std::optional<TurnGate> decode_turn_reply(std::string_view line);
/// True when the server answered "ok": true.
[[nodiscard]] bool decode_ok_reply(std::string_view line);
[[nodiscard]] std::optional<BootChainReply> decode_stage_boot_chain_reply(std::string_view line);
/// The "error" of a refusal, or empty.
[[nodiscard]] std::string reply_error(std::string_view line);

/// Send one request line and read one reply line on a fresh connection,
/// bounded by kMaxUpgradeControlLine and `deadline_seconds`. nullopt on any
/// transport failure, including a server that is not running.
[[nodiscard]] std::optional<std::string> control_exchange(const std::filesystem::path& socket,
                                                          std::string_view request,
                                                          int deadline_seconds);

}  // namespace nexus::updater
