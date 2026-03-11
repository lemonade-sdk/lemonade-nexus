#pragma once

#include <LemonadeNexus/Core/IService.hpp>

#include <httplib.h>

#include <cstdint>
#include <string>
#include <string_view>
#include <thread>

namespace nexus::network {

/// HTTP/HTTPS server for the control plane (auth, ACL, coordination endpoints).
/// Wraps cpp-httplib and runs in its own thread.
class HttpServer : public core::IService<HttpServer> {
    friend class core::IService<HttpServer>;
public:
    explicit HttpServer(uint16_t port, std::string bind_address = "0.0.0.0");

    /// Set the bind address (must be called before start()).
    void set_bind_address(const std::string& addr) { bind_address_ = addr; }

    /// Access the underlying httplib::Server to register routes before starting.
    [[nodiscard]] httplib::Server& server() { return server_; }

    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "HttpServer"; }

private:
    httplib::Server server_;
    uint16_t        port_;
    std::string     bind_address_;
    std::thread     listen_thread_;
};

} // namespace nexus::network
