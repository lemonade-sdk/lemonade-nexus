#pragma once

#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Network/IStunProvider.hpp>

#include <asio.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace nexus::network {

/// Simplified RFC 5389 STUN service with Ed25519-signed reflexive addresses.
/// Listens on a UDP port (default 3478), processes Binding Requests, and
/// returns XOR-MAPPED-ADDRESS responses signed by the server's Ed25519 key.
class StunService : public core::IService<StunService>,
                     public IStunProvider<StunService> {
    friend class core::IService<StunService>;
    friend class IStunProvider<StunService>;

public:
    StunService(asio::io_context& io, uint16_t port,
                crypto::SodiumCryptoService& crypto,
                std::string server_id);

    // IService
    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "StunService"; }

    // IStunProvider
    [[nodiscard]] StunResponse do_handle_binding_request(const asio::ip::udp::endpoint& client,
                                                          std::span<const uint8_t> request);
    void do_sign_response(StunResponse& response);
    [[nodiscard]] bool do_verify_response(const StunResponse& response,
                                           std::string_view server_pubkey) const;

private:
    /// Start an asynchronous UDP receive.
    void start_receive();

    /// Process a received UDP datagram.
    void handle_receive(std::size_t bytes_received);

    /// Build a raw STUN Binding Response with XOR-MAPPED-ADDRESS.
    [[nodiscard]] std::vector<uint8_t> build_binding_response(
        const asio::ip::udp::endpoint& client,
        std::span<const uint8_t> request_header) const;

    /// Serialize a StunResponse into bytes for signing / verification.
    [[nodiscard]] static std::vector<uint8_t> response_to_signable_bytes(
        const StunResponse& response);

    asio::ip::udp::socket        socket_;
    asio::ip::udp::endpoint      remote_endpoint_;
    std::array<uint8_t, 4096>    recv_buffer_{};
    crypto::SodiumCryptoService& crypto_;
    std::string                  server_id_;
    crypto::Ed25519Keypair       identity_keypair_{}; // persistent per-process identity

    // STUN constants
    static constexpr uint16_t kBindingRequest  = 0x0001;
    static constexpr uint16_t kBindingResponse = 0x0101;
    static constexpr uint32_t kMagicCookie     = 0x2112A442;
    static constexpr uint16_t kAttrXorMappedAddress = 0x0020;
    static constexpr std::size_t kStunHeaderSize = 20; // 2 type + 2 length + 4 cookie + 12 txn id
};

} // namespace nexus::network
