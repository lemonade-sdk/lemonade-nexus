#include <LemonadeNexus/Network/HttpServer.hpp>

#include <spdlog/spdlog.h>

#include <utility>

namespace nexus::network {

HttpServer::HttpServer(uint16_t port, std::string bind_address)
    : port_{port}
    , bind_address_{std::move(bind_address)}
{
}

void HttpServer::on_start() {
    listen_thread_ = std::thread([this]() {
        spdlog::info("HttpServer listening on {}:{}", bind_address_, port_);
        server_.listen(bind_address_, port_);
    });
}

void HttpServer::on_stop() {
    server_.stop();
    if (listen_thread_.joinable()) {
        listen_thread_.join();
    }
    spdlog::info("HttpServer stopped (was {}:{})", bind_address_, port_);
}

} // namespace nexus::network
