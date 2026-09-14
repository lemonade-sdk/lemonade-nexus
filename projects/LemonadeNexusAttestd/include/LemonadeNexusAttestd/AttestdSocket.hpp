#pragma once

// The daemon's transport: one unix domain socket, and nothing else.
//
// WHY NOT A TCP PORT. This daemon is the only component on the host trusted with
// the TPM and the root-only IMA log. A TCP listener — even on 127.0.0.1 — is
// reachable by every local process regardless of user, by a browser through DNS
// rebinding, and by anything that gets a route to the host if a bind address is
// ever mistyped. It would also need its own authentication scheme, which means
// its own key material and its own bugs. A unix socket moves the whole access
// decision into filesystem permissions the kernel already enforces: mode 0660,
// owner root, group nexus. Membership in one group is the entire ACL, it is
// visible with `ls -l`, and it cannot be reached from off-host at all.
//
// Even so, socket access is not privilege. A caller that owns the socket can ask
// this node to attest ITSELF against a challenge — the same thing any mesh peer
// can ask for over the wire. It cannot choose what gets quoted, cannot get
// arbitrary bytes signed, and cannot obtain an eligibility decision.
//
// One request per connection: a JSON challenge terminated by a newline or by
// end-of-stream, then a framed response (AttestdFraming.hpp), then close. Served
// ONE AT A TIME — a vTPM does one quote at a time anyway.
//
// The request keeps newline framing: it is already bounded at 8 KiB by a closed
// grammar. The RESPONSE is framed, because it carries a measurement log whose
// size the daemon does not choose.

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>

namespace nexus::attestd {

struct AttestdSocketConfig {
    /// Fixed path so the unit file, the socket permissions and the client all
    /// name the same thing. /run is tmpfs, so a stale socket cannot survive a
    /// reboot and be squatted. The extra directory level is not decoration:
    /// ProtectSystem=strict makes /run itself read-only, so the daemon needs a
    /// directory of its own (systemd RuntimeDirectory=) to bind in.
    std::filesystem::path path{"/run/nexus-attestd/nexus-attestd.sock"};

    /// The one group allowed to ask for evidence. Resolution failure is fatal:
    /// a socket that falls back to the daemon's own group would silently serve
    /// nobody, and an operator would debug it as a hung server.
    std::string group{"nexus"};

    /// rw for owner and group, nothing for others. The owner is the daemon's own
    /// dedicated user rather than root — the unit runs unprivileged, and a
    /// non-root process cannot chown away from itself. The group is the ACL.
    uint32_t mode{0660};
};

/// Writes one frame. False once the peer is gone or the deadline has passed,
/// which stops the handler where it stands.
using ResponseWriter = std::function<bool(std::string_view bytes)>;

/// Serves one request by writing frames, so the socket knows nothing about
/// attestation and no whole response is buffered on either side.
using RequestHandler = std::function<void(std::string_view request, const ResponseWriter& write)>;

class UnixRequestSocket {
public:
    UnixRequestSocket() = default;
    ~UnixRequestSocket();

    UnixRequestSocket(const UnixRequestSocket&) = delete;
    UnixRequestSocket& operator=(const UnixRequestSocket&) = delete;

    /// Create, bind, permission and listen. `why` receives the reason on
    /// failure. Fails closed on anything it cannot make exactly right —
    /// including a group it cannot resolve.
    [[nodiscard]] bool open(const AttestdSocketConfig& config, std::string* why);

    /// Accept and serve until `stop` is set. Blocks the calling thread.
    void serve(const RequestHandler& handler, const std::atomic<bool>& stop);

    void close();

private:
    int fd_{-1};
    std::filesystem::path path_;
};

}  // namespace nexus::attestd
