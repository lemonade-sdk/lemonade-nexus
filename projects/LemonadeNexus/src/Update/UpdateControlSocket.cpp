#include <LemonadeNexus/Update/UpdateControl.hpp>

#include <spdlog/spdlog.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <thread>

#ifndef _WIN32
#  include <cerrno>
#  include <poll.h>
#  include <sys/socket.h>
#  include <sys/stat.h>
#  include <sys/un.h>
#  include <unistd.h>
#endif

namespace nexus::update {

struct UpdateControlSocket::State {
    int fd{-1};
    std::filesystem::path path;
    UpdateControlHandlers handlers;
    std::atomic<bool> stop{false};
    std::thread thread;
};

#ifndef _WIN32
namespace {

using Clock = std::chrono::steady_clock;

int remaining_ms(Clock::time_point deadline) {
    const auto left =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
    return left > 0 ? static_cast<int>(left) : 0;
}

/// Read up to and including the first newline, within `bound` bytes and the
/// deadline. nullopt on EOF before a newline, overflow, or timeout.
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
            // One line per connection: bytes after the newline are a protocol error.
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
#  ifdef MSG_NOSIGNAL
        const ssize_t n = ::send(fd, data.data(), data.size(), MSG_NOSIGNAL);
#  else
        const ssize_t n = ::send(fd, data.data(), data.size(), 0);
#  endif
        if (n <= 0) return false;
        data.remove_prefix(static_cast<std::size_t>(n));
    }
    return true;
}

bool fill_address(const std::filesystem::path& path, sockaddr_un& addr) {
    std::memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    const auto s = path.string();
    if (s.empty() || s.size() >= sizeof(addr.sun_path)) return false;
    std::memcpy(addr.sun_path, s.c_str(), s.size());
    return true;
}

void serve(const std::shared_ptr<UpdateControlSocket::State>& state) {
    while (!state->stop.load()) {
        pollfd p{state->fd, POLLIN, 0};
        if (::poll(&p, 1, 250) <= 0) continue;
        const int client = ::accept(state->fd, nullptr, nullptr);
        if (client < 0) continue;
#  ifdef SO_NOSIGPIPE
        int one = 1;
        ::setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#  endif
        const auto deadline = Clock::now() + std::chrono::seconds(kControlDeadlineSeconds);
        const auto request = read_line(client, kMaxControlRequestBytes, deadline);
        std::string response;
        try {
            response = request ? handle_control_request(*request, state->handlers)
                               : std::string("{\"error\":\"malformed request\"}\n");
        } catch (const std::exception& e) {
            // A handler fault must not stop the listener or reach the caller raw.
            spdlog::warn("[update-control] request failed: {}", e.what());
            response = "{\"error\":\"internal error\"}\n";
        }
        (void)write_all(client, response, deadline);
        ::close(client);
    }
}

}  // namespace

std::optional<std::string> control_exchange(const std::filesystem::path& socket,
                                            std::string_view request, int deadline_seconds) {
    sockaddr_un addr{};
    if (!fill_address(socket, addr) || request.size() > kMaxControlRequestBytes) {
        return std::nullopt;
    }
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return std::nullopt;
#  ifdef SO_NOSIGPIPE
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#  endif
    const auto deadline = Clock::now() + std::chrono::seconds(deadline_seconds);
    std::optional<std::string> out;
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr)) == 0 &&
        write_all(fd, request, deadline)) {
        out = read_line(fd, kMaxControlResponseBytes, deadline);
    }
    ::close(fd);
    return out;
}

bool UpdateControlSocket::start(const std::filesystem::path& path, UpdateControlHandlers handlers,
                                std::string& why) {
    stop();
    sockaddr_un addr{};
    if (!fill_address(path, addr)) {
        why = "socket path is empty or too long";
        return false;
    }
    std::error_code ec;
    if (std::filesystem::is_symlink(path, ec)) {
        why = "socket path is a symbolic link";
        return false;
    }
    std::filesystem::remove(path, ec);
    auto state = std::make_shared<State>();
    state->path = path;
    state->handlers = std::move(handlers);
    state->fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (state->fd < 0) {
        why = std::string("socket: ") + std::strerror(errno);
        return false;
    }
    // Owner-only from creation: the umask covers the window before chmod.
    const mode_t old_mask = ::umask(0177);
    const int bound = ::bind(state->fd, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
    ::umask(old_mask);
    if (bound != 0 || ::chmod(path.c_str(), 0600) != 0 || ::listen(state->fd, 4) != 0) {
        why = std::string("bind ") + path.string() + ": " + std::strerror(errno);
        ::close(state->fd);
        std::filesystem::remove(path, ec);
        return false;
    }
    state->thread = std::thread([state] { serve(state); });
    state_ = std::move(state);
    return true;
}

void UpdateControlSocket::stop() {
    if (!state_) return;
    state_->stop = true;
    if (state_->thread.joinable()) state_->thread.join();
    if (state_->fd >= 0) ::close(state_->fd);
    std::error_code ec;
    std::filesystem::remove(state_->path, ec);
    state_.reset();
}

#else  // _WIN32

std::optional<std::string> control_exchange(const std::filesystem::path&, std::string_view, int) {
    return std::nullopt;
}

bool UpdateControlSocket::start(const std::filesystem::path&, UpdateControlHandlers,
                                std::string& why) {
    why = "the update control socket is POSIX-only";
    return false;
}

void UpdateControlSocket::stop() { state_.reset(); }

#endif

UpdateControlSocket::~UpdateControlSocket() { stop(); }

}  // namespace nexus::update
