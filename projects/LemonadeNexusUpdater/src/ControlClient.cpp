#include <LemonadeNexusUpdater/ControlClient.hpp>

#include <LemonadeNexus/Core/UpgradeControl.hpp>

#include <nlohmann/json.hpp>

#include <cerrno>
#include <chrono>
#include <cstring>

#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace nexus::updater {

namespace {

using json = nlohmann::json;
using Clock = std::chrono::steady_clock;

std::string line(const json& j) { return j.dump() + "\n"; }

/// One reply object within the bound, with or without the trailing newline.
std::optional<json> parse_reply(std::string_view text) {
    if (text.size() > core::kMaxUpgradeControlLine + 1) return std::nullopt;
    if (!text.empty() && text.back() == '\n') text.remove_suffix(1);
    if (text.find('\n') != std::string_view::npos) return std::nullopt;
    json j = json::parse(text, nullptr, false);
    if (j.is_discarded() || !j.is_object()) return std::nullopt;
    const auto ok = j.find("ok");
    if (ok == j.end() || !ok->is_boolean()) return std::nullopt;
    return j;
}

template <typename T>
bool get(const json& j, const char* key, T& out) {
    const auto it = j.find(key);
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

int remaining_ms(Clock::time_point deadline) {
    const auto left =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
    return left > 0 ? static_cast<int>(left) : 0;
}

std::optional<std::string> read_line(int fd, std::size_t bound, Clock::time_point deadline) {
    std::string out;
    char buf[4096];
    while (true) {
        pollfd p{fd, POLLIN, 0};
        const int ms = remaining_ms(deadline);
        if (ms == 0 || ::poll(&p, 1, ms) <= 0) return std::nullopt;
        const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) return std::nullopt;
        out.append(buf, static_cast<std::size_t>(n));
        if (const auto nl = out.find('\n'); nl != std::string::npos) {
            // One request, one reply: bytes after the newline are an error.
            if (nl + 1 != out.size()) return std::nullopt;
            return out;
        }
        if (out.size() > bound) return std::nullopt;
    }
}

bool write_all(int fd, std::string_view data, Clock::time_point deadline) {
    while (!data.empty()) {
        pollfd p{fd, POLLOUT, 0};
        const int ms = remaining_ms(deadline);
        if (ms == 0 || ::poll(&p, 1, ms) <= 0) return false;
#ifdef MSG_NOSIGNAL
        const ssize_t n = ::send(fd, data.data(), data.size(), MSG_NOSIGNAL);
#else
        const ssize_t n = ::send(fd, data.data(), data.size(), 0);
#endif
        if (n <= 0) return false;
        data.remove_prefix(static_cast<std::size_t>(n));
    }
    return true;
}

}  // namespace

std::string_view turn_gate_name(TurnGate gate) {
    switch (gate) {
        case TurnGate::Go: return "go";
        case TurnGate::Wait: return "wait";
        case TurnGate::Done: return "done";
        case TurnGate::Halted: return "halted";
        case TurnGate::NotStarted: return "not_started";
    }
    return "unknown";
}

std::string encode_health_request() { return line({{"op", "health"}}); }

std::string encode_offer_request(std::string_view bundle_json) {
    return line({{"op", "offer_approval"}, {"bundle", std::string(bundle_json)}});
}

std::string encode_stage_request(uint64_t release_number) {
    return line({{"op", "stage"}, {"release_number", release_number}});
}

std::string encode_turn_request(uint64_t release_number) {
    return line({{"op", "turn"}, {"release_number", release_number}});
}

std::string encode_report_request(uint64_t release_number, bool upgraded) {
    return line({{"op", "report"},
                 {"release_number", release_number},
                 {"result", upgraded ? "upgraded" : "failed"}});
}

std::string encode_stage_boot_chain_request(std::string_view bundle_json) {
    return line({{"op", "stage_boot_chain"}, {"bundle", std::string(bundle_json)}});
}

std::optional<ServerHealth> decode_health_reply(std::string_view text) {
    const auto j = parse_reply(text);
    bool ok = false;
    if (!j || !get(*j, "ok", ok) || !ok) return std::nullopt;
    ServerHealth h;
    if (!get(*j, "running_release", h.running_release) ||
        !get(*j, "accepted_release", h.accepted_release) ||
        !get(*j, "driver_phase", h.driver_phase) || !get(*j, "driver_failed", h.driver_failed) ||
        !get(*j, "verified_authority", h.verified_authority) ||
        !get(*j, "tier1_member", h.tier1_member) || !get(*j, "data_key", h.data_key) ||
        !get(*j, "healthy", h.healthy)) {
        return std::nullopt;
    }
    const auto epoch = j->find("epoch");
    if (epoch == j->end()) return std::nullopt;
    if (!epoch->is_null()) {
        if (!epoch->is_number_unsigned()) return std::nullopt;
        h.epoch = epoch->get<uint64_t>();
    }
    const auto tree = j->find("tree");
    if (tree == j->end()) return std::nullopt;
    if (!tree->is_null()) {
        if (!tree->is_object()) return std::nullopt;
        ControlTreeStatus t;
        if (!get(*tree, "healthy", t.healthy) || !get(*tree, "height", t.height) ||
            !get(*tree, "applied_height", t.applied_height) || !get(*tree, "behind", t.behind) ||
            !get(*tree, "held", t.held)) {
            return std::nullopt;
        }
        h.tree = t;
    }
    return h;
}

std::optional<OfferReply> decode_offer_reply(std::string_view text) {
    const auto j = parse_reply(text);
    OfferReply r;
    if (!j || !get(*j, "ok", r.ok) || !get(*j, "result", r.result)) return std::nullopt;
    (void)get(*j, "accepted_release", r.accepted_release);
    return r;
}

std::optional<TurnGate> decode_turn_reply(std::string_view text) {
    const auto j = parse_reply(text);
    bool ok = false;
    std::string gate;
    if (!j || !get(*j, "ok", ok) || !ok || !get(*j, "gate", gate)) return std::nullopt;
    if (gate == "go") return TurnGate::Go;
    if (gate == "wait") return TurnGate::Wait;
    if (gate == "done") return TurnGate::Done;
    if (gate == "halted") return TurnGate::Halted;
    if (gate == "not_started") return TurnGate::NotStarted;
    return std::nullopt;
}

bool decode_ok_reply(std::string_view text) {
    const auto j = parse_reply(text);
    bool ok = false;
    return j && get(*j, "ok", ok) && ok;
}

std::optional<BootChainReply> decode_stage_boot_chain_reply(std::string_view text) {
    const auto j = parse_reply(text);
    BootChainReply r;
    if (!j || !get(*j, "ok", r.ok)) return std::nullopt;
    if (!r.ok) {
        r.detail = reply_error(text);
        return r;
    }
    const auto staged = j->find("staged");
    if (!get(*j, "detail", r.detail) || staged == j->end() || !staged->is_array()) {
        return std::nullopt;
    }
    for (const auto& name : *staged) {
        if (!name.is_string()) return std::nullopt;
        r.staged.push_back(name.get<std::string>());
    }
    return r;
}

std::string reply_error(std::string_view text) {
    const auto j = parse_reply(text);
    std::string error;
    if (j) (void)get(*j, "error", error);
    return error;
}

std::optional<std::string> control_exchange(const std::filesystem::path& socket,
                                            std::string_view request, int deadline_seconds) {
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    const auto path = socket.string();
    if (path.empty() || path.size() >= sizeof(addr.sun_path) ||
        request.size() > core::kMaxUpgradeControlLine + 1) {
        return std::nullopt;
    }
    std::memcpy(addr.sun_path, path.c_str(), path.size());
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return std::nullopt;
#ifdef SO_NOSIGPIPE
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
    const auto deadline = Clock::now() + std::chrono::seconds(deadline_seconds);
    std::optional<std::string> out;
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0 &&
        write_all(fd, request, deadline)) {
        out = read_line(fd, core::kMaxUpgradeControlLine + 1, deadline);
    }
    ::close(fd);
    return out;
}

}  // namespace nexus::updater
