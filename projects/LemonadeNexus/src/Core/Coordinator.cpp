#include <LemonadeNexus/Core/Coordinator.hpp>

namespace nexus::core {

Coordinator::Coordinator(uint16_t tcp_port, uint16_t udp_port)
    : io_context_{}
    , signals_{io_context_, SIGINT, SIGTERM}
    , tcp_port_{tcp_port}
    , udp_port_{udp_port}
{
    signals_.async_wait([this](const asio::error_code&, int) {
        shutdown();
    });
}

Coordinator::~Coordinator() {
    shutdown();
}

void Coordinator::run() {
    running_ = true;
    spdlog::info("Lemonade-Nexus coordinator starting on TCP:{} UDP:{}", tcp_port_, udp_port_);
    io_context_.run();
}

void Coordinator::shutdown() {
    if (running_.exchange(false)) {
        spdlog::info("Lemonade-Nexus coordinator shutting down");
        io_context_.stop();
    }
}

} // namespace nexus::core
