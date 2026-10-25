#include <LemonadeNexus/Core/UpgradeControl.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <optional>
#include <system_error>

#if defined(LEMONADE_HAVE_UPGRADE_CONTROL)
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace nexus::core {

namespace {

using json = nlohmann::json;

std::string refuse(std::string_view error) {
    return json{{"ok", false}, {"error", error}}.dump();
}

std::optional<uint64_t> release_number_of(const json& request) {
    const auto it = request.find("release_number");
    if (it == request.end() || !it->is_number_unsigned()) return std::nullopt;
    const auto value = it->get<uint64_t>();
    if (value == 0 || value > security::kMaxReleaseNumber) return std::nullopt;
    return value;
}

json tree_json(const UpgradeControlHooks& hooks) {
    const auto tree = hooks.tree_status ? hooks.tree_status() : std::nullopt;
    if (!tree) return nullptr;
    return {{"healthy", tree->healthy},
            {"height", tree->height},
            {"applied_height", tree->applied_height},
            {"behind", tree->behind},
            {"held", tree->held}};
}

}  // namespace

std::string handle_upgrade_control_request(security::UpgradeService& service,
                                           std::string_view line,
                                           const UpgradeControlHooks& hooks) {
    if (line.size() > kMaxUpgradeControlLine) return refuse("request too large");
    const json request = json::parse(line.begin(), line.end(), nullptr, false);
    if (request.is_discarded() || !request.is_object()) {
        return refuse("request is not a JSON object");
    }
    const auto op_it = request.find("op");
    if (op_it == request.end() || !op_it->is_string()) return refuse("missing op");
    const auto op = op_it->get<std::string>();

    if (op == "status") {
        const auto& state = service.state();
        json rollout = nullptr;
        if (state.active()) {
            rollout = {{"release_number", state.release_number},
                       {"sequence", state.sequence},
                       {"halted", state.halted},
                       {"participants", state.order.size()},
                       {"upgraded", state.upgraded.size()},
                       {"complete", state.complete()},
                       {"in_turn", state.in_turn ? json(crypto::to_hex(state.in_turn->bytes))
                                                 : json(nullptr)}};
        }
        const auto health = service.health();
        return json{{"ok", true},
                    {"running_release", health.running_release},
                    {"accepted_release", health.accepted_release},
                    {"staged_release", service.staged_release()},
                    {"rollout", std::move(rollout)}}
            .dump();
    }
    if (op == "health") {
        const auto health = service.health();
        return json{{"ok", true},
                    {"running_release", health.running_release},
                    {"accepted_release", health.accepted_release},
                    {"driver_phase", health.driver_phase},
                    {"driver_failed", health.driver_failed},
                    {"verified_authority", health.verified_authority},
                    {"tier1_member", health.tier1_member},
                    {"epoch", health.epoch ? json(*health.epoch) : json(nullptr)},
                    {"data_key", health.data_key_state},
                    {"healthy", health.healthy},
                    {"tree", tree_json(hooks)}}
            .dump();
    }
    if (op == "offer_approval") {
        const auto bundle = request.find("bundle");
        if (bundle == request.end() || !bundle->is_string()) return refuse("missing bundle");
        const auto result = service.offer_approval(bundle->get<std::string>());
        const bool accepted = result == security::ReleaseOfferResult::Adopted ||
                              result == security::ReleaseOfferResult::Current;
        return json{{"ok", accepted},
                    {"result", security::release_offer_result_name(result)},
                    {"accepted_release", service.health().accepted_release}}
            .dump();
    }
    if (op == "stage_boot_chain") {
        const auto bundle = request.find("bundle");
        if (bundle == request.end() || !bundle->is_string()) return refuse("missing bundle");
        const auto& text = bundle->get_ref<const std::string&>();
        if (text.size() > security::kMaxReleaseApprovalBytes) return refuse("bundle too large");
        if (!hooks.stage_boot_chain) return refuse("boot-chain staging is not available");
        std::string error;
        const auto offered = security::parse_release_approval_bundle(text, error);
        const auto& accepted = service.accepted_approval();
        // Only the approval the release chain accepted (signer pinned, number
        // monotonic) names PCRs this server seals to.
        if (!offered || !accepted ||
            security::release_approval_digest(offered->approval) !=
                security::release_approval_digest(accepted->approval)) {
            return refuse("not the accepted release approval; offer it first");
        }
        const auto result = hooks.stage_boot_chain(*accepted);
        json reply = {{"ok", result.ok}, {"staged", result.staged}, {"detail", result.detail}};
        if (!result.ok) reply["error"] = result.detail;
        return reply.dump();
    }
    const auto release_number = release_number_of(request);
    if (op == "stage") {
        if (!release_number) return refuse("invalid release_number");
        service.stage(*release_number);
        return json{{"ok", true}}.dump();
    }
    if (op == "turn") {
        if (!release_number) return refuse("invalid release_number");
        const auto gate = service.gate(*release_number);
        return json{{"ok", true}, {"gate", security::upgrade_gate_name(gate)}}.dump();
    }
    if (op == "report") {
        if (!release_number) return refuse("invalid release_number");
        const auto result = request.find("result");
        if (result == request.end() || !result->is_string()) return refuse("missing result");
        if (result->get<std::string>() == "failed") {
            service.report_failed(*release_number);
            return json{{"ok", true}}.dump();
        }
        if (result->get<std::string>() == "upgraded") {
            // Informational: "upgraded" counts only through a witness quorum.
            return json{{"ok", true}, {"counted", false}}.dump();
        }
        return refuse("result must be failed or upgraded");
    }
    return refuse("unknown op");
}

#if defined(LEMONADE_HAVE_UPGRADE_CONTROL)

namespace {

bool peer_uid(int fd, uint32_t& uid) {
#if defined(__linux__)
    struct ucred credentials {};
    socklen_t length = sizeof(credentials);
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 ||
        length != sizeof(credentials)) {
        return false;
    }
    uid = static_cast<uint32_t>(credentials.uid);
    return true;
#else
    uid_t peer = 0;
    gid_t group = 0;
    if (getpeereid(fd, &peer, &group) != 0) return false;
    uid = static_cast<uint32_t>(peer);
    return true;
#endif
}

}  // namespace

class UpgradeControlServer::Session : public std::enable_shared_from_this<Session> {
public:
    Session(asio::local::stream_protocol::socket socket, Post post,
            security::UpgradeService& service, const UpgradeControlHooks& hooks,
            std::shared_ptr<bool> alive)
        : socket_(std::move(socket)),
          post_(std::move(post)),
          service_(service),
          hooks_(hooks),
          alive_(std::move(alive)),
          buffer_(kMaxUpgradeControlLine + 1) {}

    void read() {
        auto self = shared_from_this();
        asio::async_read_until(
            socket_, buffer_, '\n', [self](const asio::error_code& ec, std::size_t length) {
                if (ec || !*self->alive_) return;  // closed, oversize, or stopped
                std::string line(length > 0 ? length - 1 : 0, '\0');
                std::istream stream(&self->buffer_);
                stream.read(line.data(), static_cast<std::streamsize>(line.size()));
                self->buffer_.consume(1);  // the newline
                self->post_([self, line = std::move(line)] {
                    if (!*self->alive_) return;
                    auto reply = handle_upgrade_control_request(self->service_, line,
                                                                self->hooks_);
                    reply.push_back('\n');
                    self->write(std::move(reply));
                });
            });
    }

private:
    void write(std::string reply) {
        auto self = shared_from_this();
        auto owned = std::make_shared<std::string>(std::move(reply));
        asio::post(socket_.get_executor(), [self, owned] {
            asio::async_write(self->socket_, asio::buffer(*owned),
                              [self, owned](const asio::error_code& ec, std::size_t) {
                                  if (!ec && *self->alive_) self->read();
                              });
        });
    }

    asio::local::stream_protocol::socket socket_;
    Post post_;
    security::UpgradeService& service_;
    /// Owned by the server, which outlives every session that sees alive_.
    const UpgradeControlHooks& hooks_;
    std::shared_ptr<bool> alive_;
    asio::streambuf buffer_;
};

UpgradeControlServer::UpgradeControlServer(asio::io_context& io, UpgradeControlConfig config,
                                           Post post, security::UpgradeService& service)
    : io_(io),
      config_(std::move(config)),
      post_(std::move(post)),
      service_(service),
      acceptor_(io),
      alive_(std::make_shared<bool>(true)) {}

UpgradeControlServer::~UpgradeControlServer() { stop(); }

bool UpgradeControlServer::start(std::string& error) {
    std::error_code fs_error;
    std::filesystem::create_directories(config_.socket_path.parent_path(), fs_error);
    // A stale socket from an earlier run blocks bind; remove only a socket.
    if (std::filesystem::is_socket(config_.socket_path, fs_error)) {
        std::filesystem::remove(config_.socket_path, fs_error);
    }
    asio::error_code ec;
    const asio::local::stream_protocol::endpoint endpoint(config_.socket_path.string());
    acceptor_.open(endpoint.protocol(), ec);
    if (!ec) acceptor_.bind(endpoint, ec);
    if (!ec && ::chmod(config_.socket_path.c_str(), S_IRUSR | S_IWUSR) != 0) {
        ec = asio::error_code(errno, asio::system_category());
    }
    if (!ec) acceptor_.listen(asio::socket_base::max_listen_connections, ec);
    if (ec) {
        error = config_.socket_path.string() + ": " + ec.message();
        asio::error_code ignored;
        acceptor_.close(ignored);
        return false;
    }
    accept();
    return true;
}

void UpgradeControlServer::stop() {
    if (!*alive_) return;
    *alive_ = false;
    asio::error_code ignored;
    if (acceptor_.is_open()) {
        acceptor_.close(ignored);
        std::error_code fs_error;
        std::filesystem::remove(config_.socket_path, fs_error);
    }
}

void UpgradeControlServer::accept() {
    acceptor_.async_accept(
        [this, alive = alive_](const asio::error_code& ec,
                               asio::local::stream_protocol::socket socket) {
            if (!*alive) return;
            if (!ec) {
                uint32_t uid = 0;
                if (!peer_uid(socket.native_handle(), uid) || uid != config_.allowed_uid) {
                    spdlog::warn("[upgrade] control socket refused a peer that is not root");
                    asio::error_code ignored;
                    socket.close(ignored);
                } else {
                    std::make_shared<Session>(std::move(socket), post_, service_, config_.hooks,
                                              alive)
                        ->read();
                }
            }
            accept();
        });
}

#endif

}  // namespace nexus::core
