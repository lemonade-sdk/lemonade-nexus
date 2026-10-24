#include <LemonadeNexus/Update/UpdateControl.hpp>

#include <nlohmann/json.hpp>

namespace nexus::update {
namespace {

using json = nlohmann::json;

std::string line(const json& j) { return j.dump() + "\n"; }

std::string error_line(std::string_view reason) {
    return line(json{{"error", std::string(reason)}});
}

/// Parse one line: a JSON object, optionally newline-terminated, within the
/// bound. Anything else is nullopt.
std::optional<json> parse_line(std::string_view text, std::size_t bound) {
    if (text.size() > bound) return std::nullopt;
    if (!text.empty() && text.back() == '\n') text.remove_suffix(1);
    if (text.find('\n') != std::string_view::npos) return std::nullopt;
    json j = json::parse(text, nullptr, false);
    if (j.is_discarded() || !j.is_object() || j.contains("error")) return std::nullopt;
    return j;
}

template <typename T>
bool get(const json& j, std::string_view key, T& out) {
    const auto it = j.find(std::string(key));
    if (it == j.end()) return false;
    if constexpr (std::is_same_v<T, bool>) {
        if (!it->is_boolean()) return false;
    } else if constexpr (std::is_same_v<T, uint64_t>) {
        if (!it->is_number_unsigned()) return false;
    } else if constexpr (std::is_same_v<T, std::string>) {
        if (!it->is_string()) return false;
    }
    out = it->get<T>();
    return true;
}

json status_json(const UpdateServerStatus& s) {
    return {
        {"version", s.version},
        {"release_id", s.release_id},
        {"approval_digest", s.approval_digest_hex},
        {"epoch", {{"known", s.epoch_known}, {"epoch", s.epoch}, {"tier1_member", s.tier1_member}}},
        {"storage", {{"files_ready", s.storage_files_ready}, {"phase", s.storage_phase}}},
        {"tree",
         {{"enabled", s.tree_enabled},
          {"healthy", s.tree_healthy},
          {"height", s.tree_height},
          {"applied_height", s.tree_applied_height},
          {"behind", s.tree_behind},
          {"held", s.tree_held}}},
    };
}

}  // namespace

std::string handle_control_request(std::string_view request,
                                   const UpdateControlHandlers& handlers) {
    const auto j = parse_line(request, kMaxControlRequestBytes);
    std::string op;
    if (!j || !get(*j, "op", op)) return error_line("malformed request");

    if (op == "status") {
        if (!handlers.status) return error_line("status is not available");
        return line(status_json(handlers.status()));
    }
    if (op == "may_restart") {
        TurnRequest r;
        if (!get(*j, "release_number", r.release_number) || !get(*j, "release_id", r.release_id)) {
            return error_line("malformed may_restart request");
        }
        if (!handlers.may_restart) return error_line("the turn gate is not available");
        const auto d = handlers.may_restart(r);
        return line(json{{"granted", d.granted}, {"reason", d.reason}});
    }
    if (op == "report") {
        UpgradeReport r;
        std::string outcome;
        if (!get(*j, "release_number", r.release_number) || !get(*j, "release_id", r.release_id) ||
            !get(*j, "outcome", outcome) || !get(*j, "detail", r.detail) ||
            (outcome != "upgraded" && outcome != "failed")) {
            return error_line("malformed report request");
        }
        r.outcome = outcome == "upgraded" ? UpgradeOutcome::Upgraded : UpgradeOutcome::Failed;
        if (!handlers.report) return error_line("reports are not available");
        const auto a = handlers.report(r);
        return line(json{{"accepted", a.accepted}, {"reason", a.reason}});
    }
    if (op == "stage_boot_chain") {
        std::string approval;
        if (!get(*j, "approval", approval) || approval.empty()) {
            return error_line("malformed stage_boot_chain request");
        }
        if (!handlers.stage_boot_chain) return error_line("boot-chain staging is not available");
        const auto r = handlers.stage_boot_chain(approval);
        return line(json{{"ok", r.ok}, {"staged", r.staged}, {"detail", r.detail}});
    }
    return error_line("unknown operation");
}

std::string encode_status_request() { return line(json{{"op", "status"}}); }

std::string encode_turn_request(const TurnRequest& r) {
    return line(json{{"op", "may_restart"},
                     {"release_number", r.release_number},
                     {"release_id", r.release_id}});
}

std::string encode_report_request(const UpgradeReport& r) {
    return line(json{{"op", "report"},
                     {"release_number", r.release_number},
                     {"release_id", r.release_id},
                     {"outcome", r.outcome == UpgradeOutcome::Upgraded ? "upgraded" : "failed"},
                     {"detail", r.detail}});
}

std::string encode_stage_request(std::string_view approval_json) {
    return line(json{{"op", "stage_boot_chain"}, {"approval", std::string(approval_json)}});
}

std::optional<UpdateServerStatus> decode_status_response(std::string_view text) {
    const auto j = parse_line(text, kMaxControlResponseBytes);
    if (!j) return std::nullopt;
    UpdateServerStatus s;
    const auto ep = j->find("epoch");
    const auto st = j->find("storage");
    const auto tr = j->find("tree");
    if (!get(*j, "version", s.version) || !get(*j, "release_id", s.release_id) ||
        !get(*j, "approval_digest", s.approval_digest_hex) || ep == j->end() ||
        !ep->is_object() || st == j->end() || !st->is_object() || tr == j->end() ||
        !tr->is_object()) {
        return std::nullopt;
    }
    if (!get(*ep, "known", s.epoch_known) || !get(*ep, "epoch", s.epoch) ||
        !get(*ep, "tier1_member", s.tier1_member) ||
        !get(*st, "files_ready", s.storage_files_ready) || !get(*st, "phase", s.storage_phase) ||
        !get(*tr, "enabled", s.tree_enabled) || !get(*tr, "healthy", s.tree_healthy) ||
        !get(*tr, "height", s.tree_height) || !get(*tr, "applied_height", s.tree_applied_height) ||
        !get(*tr, "behind", s.tree_behind) || !get(*tr, "held", s.tree_held)) {
        return std::nullopt;
    }
    return s;
}

std::optional<TurnDecision> decode_turn_response(std::string_view text) {
    const auto j = parse_line(text, kMaxControlResponseBytes);
    TurnDecision d;
    if (!j || !get(*j, "granted", d.granted) || !get(*j, "reason", d.reason)) return std::nullopt;
    return d;
}

std::optional<ReportAck> decode_report_response(std::string_view text) {
    const auto j = parse_line(text, kMaxControlResponseBytes);
    ReportAck a;
    if (!j || !get(*j, "accepted", a.accepted) || !get(*j, "reason", a.reason)) {
        return std::nullopt;
    }
    return a;
}

std::optional<BootChainStageResult> decode_stage_response(std::string_view text) {
    const auto j = parse_line(text, kMaxControlResponseBytes);
    BootChainStageResult r;
    if (!j || !get(*j, "ok", r.ok) || !get(*j, "detail", r.detail)) return std::nullopt;
    const auto staged = j->find("staged");
    if (staged == j->end() || !staged->is_array()) return std::nullopt;
    for (const auto& name : *staged) {
        if (!name.is_string()) return std::nullopt;
        r.staged.push_back(name.get<std::string>());
    }
    return r;
}

}  // namespace nexus::update
