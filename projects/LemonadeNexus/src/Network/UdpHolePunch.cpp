#include <LemonadeNexus/Network/UdpHolePunch.hpp>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

namespace nexus::network {

HolePunchService::HolePunchService(asio::io_context& io, uint16_t port)
    : socket_{io, asio::ip::udp::endpoint{asio::ip::udp::v4(), port}}
{
}

void HolePunchService::on_start() {
    spdlog::info("HolePunchService listening on UDP port {}",
                 socket_.local_endpoint().port());
    start_receive();
}

void HolePunchService::on_stop() {
    spdlog::info("HolePunchService stopped");
    socket_.close();
}

void HolePunchService::do_register_peer(std::string_view peer_id, const PeerEndpoint& endpoint) {
    peer_registry_[std::string(peer_id)] = endpoint;
    spdlog::debug("Registered peer {} at {}:{}", peer_id, endpoint.address, endpoint.port);
}

std::optional<PeerEndpoint> HolePunchService::do_lookup_peer(std::string_view peer_id) const {
    auto it = peer_registry_.find(std::string(peer_id));
    if (it != peer_registry_.end()) {
        return it->second;
    }
    return std::nullopt;
}

void HolePunchService::start_receive() {
    socket_.async_receive_from(
        asio::buffer(recv_buffer_), remote_endpoint_,
        [this](const asio::error_code& ec, std::size_t bytes) {
            if (!ec) {
                handle_receive(bytes);
                start_receive();
            } else {
                spdlog::error("UDP receive error: {}", ec.message());
            }
        });
}

void HolePunchService::handle_receive(std::size_t bytes_received) {
    // Parse incoming UDP packet as JSON
    // Expected: {"action": "register"|"lookup", "peer_id": "...", ...}
    try {
        auto msg = nlohmann::json::parse(
            std::string_view{recv_buffer_.data(), bytes_received});

        const auto action  = msg.value("action", std::string{});
        const auto peer_id = msg.value("peer_id", std::string{});

        if (action == "register") {
            PeerEndpoint ep{
                .address = remote_endpoint_.address().to_string(),
                .port    = remote_endpoint_.port(),
            };
            do_register_peer(peer_id, ep);

            // Respond with the observed public endpoint
            nlohmann::json resp = {
                {"status", "registered"},
                {"public_address", ep.address},
                {"public_port", ep.port},
            };
            auto resp_str = resp.dump();
            socket_.async_send_to(
                asio::buffer(resp_str), remote_endpoint_,
                [](const asio::error_code&, std::size_t) {});

        } else if (action == "lookup") {
            const auto target_id = msg.value("target_peer_id", std::string{});
            auto target = do_lookup_peer(target_id);

            nlohmann::json resp;
            if (target) {
                resp = {
                    {"status", "found"},
                    {"address", target->address},
                    {"port", target->port},
                };
            } else {
                resp = {{"status", "not_found"}};
            }
            auto resp_str = resp.dump();
            socket_.async_send_to(
                asio::buffer(resp_str), remote_endpoint_,
                [](const asio::error_code&, std::size_t) {});
        }
    } catch (const nlohmann::json::parse_error& e) {
        spdlog::warn("Invalid UDP packet from {}:{}: {}",
                     remote_endpoint_.address().to_string(),
                     remote_endpoint_.port(), e.what());
    }
}

} // namespace nexus::network
