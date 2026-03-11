#pragma once

#include <asio.hpp>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <atomic>

namespace nexus::core {

/// Central coordinator that owns the ASIO io_context and orchestrates all services.
class Coordinator {
public:
    explicit Coordinator(uint16_t tcp_port, uint16_t udp_port);
    ~Coordinator();

    Coordinator(const Coordinator&) = delete;
    Coordinator& operator=(const Coordinator&) = delete;

    void run();
    void shutdown();

    [[nodiscard]] asio::io_context& io_context() { return io_context_; }
    [[nodiscard]] uint16_t tcp_port() const { return tcp_port_; }
    [[nodiscard]] uint16_t udp_port() const { return udp_port_; }

private:
    asio::io_context io_context_;
    asio::signal_set signals_;
    uint16_t tcp_port_;
    uint16_t udp_port_;
    std::atomic<bool> running_{false};
};

} // namespace nexus::core
