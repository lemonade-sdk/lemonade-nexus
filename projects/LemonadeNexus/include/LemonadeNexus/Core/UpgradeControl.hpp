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
//
// Every reply has "ok" (bool); a refusal adds "error". docs/Upgrade-Control.md
// lists the reply fields. The gate answers come only from finalized upgrade
// records (UpgradeService::gate); a report is a request, never a grant.

#include <LemonadeNexus/Security/Upgrade/UpgradeService.hpp>

#include <asio.hpp>

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
/// Largest request or reply line, including an approval bundle.
inline constexpr std::size_t kMaxUpgradeControlLine = 64 * 1024;

/// Handles one request line and returns one reply line (without the newline).
/// Call on the security io thread: it calls into `service`.
[[nodiscard]] std::string handle_upgrade_control_request(security::UpgradeService& service,
                                                         std::string_view line);

#if defined(ASIO_HAS_LOCAL_SOCKETS) && !defined(_WIN32)
#define LEMONADE_HAVE_UPGRADE_CONTROL 1

struct UpgradeControlConfig {
    std::filesystem::path socket_path{kUpgradeControlSocketPath};
    /// The only peer user id accepted. Production passes 0 (root); a test
    /// passes its own user id.
    uint32_t allowed_uid = 0;
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
