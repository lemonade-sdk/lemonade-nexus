#pragma once

#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Relay/IRelayProvider.hpp>
#include <LemonadeNexus/Relay/RelayTypes.hpp>

#include <asio.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace nexus::relay {

/// A live relay session binding two peer endpoints.
struct RelaySession {
    SessionId                  session_id{};
    asio::ip::udp::endpoint    peer_a_endpoint;
    asio::ip::udp::endpoint    peer_b_endpoint;
    bool                       peer_a_bound{false};
    bool                       peer_b_bound{false};
    std::atomic<uint64_t>      bytes_forwarded{0};
    std::atomic<uint64_t>      packets_forwarded{0};
    std::atomic<uint32_t>      packets_dropped{0};
    std::chrono::steady_clock::time_point created_at;
    uint32_t                   ttl_seconds{300};
};

/// Concrete relay service that listens on a UDP port, multiplexing STUN
/// (magic 0x0001) and Relay (magic 0x4C52) by inspecting the first two bytes
/// of each datagram.
///
/// Ticket verification uses the central server's Ed25519 public key.
class RelayService : public core::IService<RelayService>,
                      public IRelayProvider<RelayService> {
    friend class core::IService<RelayService>;
    friend class IRelayProvider<RelayService>;

public:
    /// @param io            ASIO io_context driving the socket
    /// @param port          UDP port to listen on (default 51820)
    /// @param crypto        Reference to the crypto service for verification
    /// @param central_pubkey Ed25519 public key of the central server
    RelayService(asio::io_context& io,
                 uint16_t port,
                 crypto::SodiumCryptoService& crypto,
                 crypto::Ed25519PublicKey central_pubkey);

    // -- IService --
    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "RelayService"; }

    // -- IRelayProvider --
    [[nodiscard]] RelayAllocation do_allocate(const RelayTicket& ticket);
    [[nodiscard]] RelayBindResult do_bind(const SessionId& session_id,
                                          const asio::ip::udp::endpoint& peer_endpoint);
    [[nodiscard]] bool do_forward(const SessionId& session_id,
                                  std::span<const uint8_t> data,
                                  const asio::ip::udp::endpoint& from);
    void do_teardown(const SessionId& session_id);
    [[nodiscard]] bool do_verify_ticket(const RelayTicket& ticket) const;

    /// Return statistics for a session.
    [[nodiscard]] std::optional<RelaySessionStats> get_session_stats(const SessionId& session_id) const;

private:
    /// Begin asynchronous receive loop.
    void start_receive();

    /// Dispatch an incoming datagram based on the first two bytes.
    void handle_receive(std::size_t bytes_received,
                        const asio::ip::udp::endpoint& remote);

    /// Process a relay-protocol datagram.
    void handle_relay_packet(std::span<const uint8_t> data,
                             const asio::ip::udp::endpoint& remote);

    /// Generate a fresh random SessionId.
    [[nodiscard]] SessionId generate_session_id();

    /// Serialise ticket fields into the canonical byte buffer for verification.
    [[nodiscard]] static std::vector<uint8_t> ticket_canonical_bytes(const RelayTicket& ticket);

    /// Start periodic TTL enforcement timer.
    void start_ttl_timer();

    /// Purge sessions that have exceeded their TTL.
    void purge_expired_sessions();

    // Dependencies
    asio::io_context&            io_;
    asio::ip::udp::socket        socket_;
    uint16_t                     port_;
    crypto::SodiumCryptoService& crypto_;
    crypto::Ed25519PublicKey      central_pubkey_;

    // Receive buffer (max UDP datagram)
    static constexpr std::size_t kMaxDatagram = 65535;
    std::array<uint8_t, kMaxDatagram> recv_buf_{};
    asio::ip::udp::endpoint           remote_endpoint_;

    // Session table
    mutable std::mutex mutex_;
    std::unordered_map<SessionId, std::shared_ptr<RelaySession>, SessionIdHash> sessions_;

    // TTL enforcement timer (fires every 30 seconds)
    asio::steady_timer ttl_timer_{io_};
};

} // namespace nexus::relay
