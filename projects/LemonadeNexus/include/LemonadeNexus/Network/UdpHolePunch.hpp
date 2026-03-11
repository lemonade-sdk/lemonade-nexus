#pragma once

#include <LemonadeNexus/Core/IService.hpp>

#include <asio.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>

namespace nexus::network {

/// Represents a peer's public endpoint as observed by the coordination server.
struct PeerEndpoint {
    std::string address;
    uint16_t    port{0};
};

/// CRTP-based UDP hole punching facilitator.
/// Derived must implement:
///   void do_register_peer(std::string_view peer_id, const PeerEndpoint& endpoint)
///   std::optional<PeerEndpoint> do_lookup_peer(std::string_view peer_id) const
template <typename Derived>
class IHolePunchProvider {
public:
    void register_peer(std::string_view peer_id, const PeerEndpoint& endpoint) {
        self().do_register_peer(peer_id, endpoint);
    }

    [[nodiscard]] auto lookup_peer(std::string_view peer_id) const {
        return self().do_lookup_peer(peer_id);
    }

protected:
    ~IHolePunchProvider() = default;

private:
    [[nodiscard]] Derived& self() { return static_cast<Derived&>(*this); }
    [[nodiscard]] const Derived& self() const { return static_cast<const Derived&>(*this); }
};

/// The coordination server's UDP hole-punch service.
/// Listens on a UDP port, records peer public endpoints, and exchanges
/// endpoint information between peers so they can punch through NATs.
class HolePunchService : public core::IService<HolePunchService>,
                         public IHolePunchProvider<HolePunchService> {
    friend class core::IService<HolePunchService>;
    friend class IHolePunchProvider<HolePunchService>;
public:
    explicit HolePunchService(asio::io_context& io, uint16_t port);

    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "HolePunchService"; }

    void do_register_peer(std::string_view peer_id, const PeerEndpoint& endpoint);
    [[nodiscard]] std::optional<PeerEndpoint> do_lookup_peer(std::string_view peer_id) const;

private:
    void start_receive();
    void handle_receive(std::size_t bytes_received);

    asio::ip::udp::socket   socket_;
    asio::ip::udp::endpoint remote_endpoint_;
    std::array<char, 4096>  recv_buffer_{};

    std::unordered_map<std::string, PeerEndpoint> peer_registry_;
};

} // namespace nexus::network
