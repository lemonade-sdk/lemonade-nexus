#include <LemonadeNexusAttestd/AttestdSocket.hpp>

#include <LemonadeNexusAttestd/AttestdCodec.hpp>

#include <spdlog/spdlog.h>

#include <cerrno>
#include <cstring>
#include <string>

#ifndef _WIN32
#  include <grp.h>
#  include <poll.h>
#  include <sys/socket.h>
#  include <sys/stat.h>
#  include <sys/types.h>
#  include <sys/un.h>
#  include <unistd.h>
#endif

namespace nexus::attestd {

namespace {

#ifndef _WIN32

/// How long an accepted connection may take to send its request or read its
/// reply. Bounded so one wedged local client cannot hold the single-threaded
/// server forever.
constexpr int kPeerTimeoutSeconds = 10;

/// Accept wakes at this cadence to notice a shutdown request.
constexpr int kAcceptPollMs = 250;

void set_timeouts(int fd) {
    ::timeval tv{};
    tv.tv_sec = kPeerTimeoutSeconds;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/// Best-effort peer identity, for the log only. The access decision was already
/// made by the kernel when it checked the socket's mode against the caller.
std::string peer_description(int fd) {
    uid_t uid = 0;
    gid_t gid = 0;
    if (::getpeereid(fd, &uid, &gid) == 0) {
        return "uid=" + std::to_string(uid) + " gid=" + std::to_string(gid);
    }
    return "uid=? gid=?";
}

/// Read one newline-terminated (or EOF-terminated) request, capped.
bool read_request(int fd, std::string& out) {
    out.clear();
    char buffer[1024];
    while (out.size() <= kMaxRequestBytes) {
        const ssize_t n = ::read(fd, buffer, sizeof(buffer));
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) return !out.empty();  // peer closed its write side
        out.append(buffer, static_cast<std::size_t>(n));
        if (const auto nl = out.find('\n'); nl != std::string::npos) {
            out.resize(nl);
            return true;
        }
    }
    // Over the cap. Returning what we have lets the codec answer with a typed
    // MalformedRequest instead of a silent disconnect.
    out.resize(kMaxRequestBytes + 1);
    return true;
}

bool write_all(int fd, std::string_view data) {
    while (!data.empty()) {
        const ssize_t n = ::write(fd, data.data(), data.size());
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        data.remove_prefix(static_cast<std::size_t>(n));
    }
    return true;
}

#endif  // !_WIN32

}  // namespace

UnixRequestSocket::~UnixRequestSocket() { close(); }

#ifndef _WIN32

bool UnixRequestSocket::open(const AttestdSocketConfig& config, std::string* why) {
    const std::string path = config.path.string();
    ::sockaddr_un addr{};
    if (path.size() + 1 > sizeof(addr.sun_path)) {
        if (why) *why = "socket path is too long for sockaddr_un: " + path;
        return false;
    }

    // The group IS the access control list, so an unresolvable group is a
    // configuration error, not something to shrug off — see AttestdSocket.hpp.
    const ::group* grp = ::getgrnam(config.group.c_str());
    if (grp == nullptr) {
        if (why) {
            *why = "group '" + config.group +
                   "' does not exist; the socket's only access control is its group, so refusing "
                   "to create one nobody can use";
        }
        return false;
    }
    const gid_t gid = grp->gr_gid;

    fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd_ < 0) {
        if (why) *why = std::string("socket(AF_UNIX): ") + std::strerror(errno);
        return false;
    }

    // A leftover socket from a crashed run would make bind fail with EADDRINUSE.
    // /run is tmpfs, so anything here is ours from this boot.
    ::unlink(path.c_str());

    addr.sun_family = AF_UNIX;
    std::memcpy(addr.sun_path, path.c_str(), path.size() + 1);

    // Bind under a restrictive umask so the socket is never, even briefly, more
    // open than intended; chmod afterwards sets the exact mode.
    const mode_t previous = ::umask(0177);
    const int rc = ::bind(fd_, reinterpret_cast<const ::sockaddr*>(&addr), sizeof(addr));
    ::umask(previous);
    if (rc != 0) {
        if (why) *why = "bind(" + path + "): " + std::strerror(errno);
        close();
        return false;
    }
    path_ = config.path;

    if (::chown(path.c_str(), static_cast<uid_t>(-1), gid) != 0) {
        if (why) *why = "chown(" + path + ", :" + config.group + "): " + std::strerror(errno);
        close();
        return false;
    }
    if (::chmod(path.c_str(), static_cast<mode_t>(config.mode)) != 0) {
        if (why) *why = "chmod(" + path + "): " + std::strerror(errno);
        close();
        return false;
    }

    // Depth 8: requests are served one at a time and a quote is slow, so a deep
    // queue would only let a caller build a backlog it cannot be served from.
    if (::listen(fd_, 8) != 0) {
        if (why) *why = "listen(" + path + "): " + std::strerror(errno);
        close();
        return false;
    }

    spdlog::info("[attestd] listening on {} mode {:o} group {} (gid {})", path, config.mode,
                 config.group, gid);
    return true;
}

void UnixRequestSocket::serve(const RequestHandler& handler, const std::atomic<bool>& stop) {
    while (!stop.load()) {
        ::pollfd pfd{fd_, POLLIN, 0};
        const int ready = ::poll(&pfd, 1, kAcceptPollMs);
        if (ready < 0) {
            if (errno == EINTR) continue;
            spdlog::error("[attestd] poll: {}", std::strerror(errno));
            return;
        }
        if (ready == 0) continue;

        const int peer = ::accept(fd_, nullptr, nullptr);
        if (peer < 0) {
            if (errno == EINTR || errno == ECONNABORTED) continue;
            spdlog::error("[attestd] accept: {}", std::strerror(errno));
            return;
        }
        set_timeouts(peer);

        std::string request;
        if (read_request(peer, request)) {
            spdlog::debug("[attestd] request from {} ({} bytes)", peer_description(peer),
                          request.size());
            std::string response = handler(request);
            response.push_back('\n');
            if (!write_all(peer, response)) {
                spdlog::warn("[attestd] peer {} closed before reading the response",
                             peer_description(peer));
            }
        } else {
            spdlog::debug("[attestd] peer {} sent nothing", peer_description(peer));
        }
        ::close(peer);
    }
}

void UnixRequestSocket::close() {
    if (fd_ >= 0) {
        ::close(fd_);
        fd_ = -1;
    }
    if (!path_.empty()) {
        ::unlink(path_.c_str());
        path_.clear();
    }
}

#else  // _WIN32 — no unix domain socket transport, and no TPM prover either

bool UnixRequestSocket::open(const AttestdSocketConfig&, std::string* why) {
    if (why) *why = "nexus-attestd has no transport on Windows";
    return false;
}

void UnixRequestSocket::serve(const RequestHandler&, const std::atomic<bool>&) {}

void UnixRequestSocket::close() {}

#endif

}  // namespace nexus::attestd
