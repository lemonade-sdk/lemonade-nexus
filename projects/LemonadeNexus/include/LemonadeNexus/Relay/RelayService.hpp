#pragma once

#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Relay/IRelayProvider.hpp>
#include <LemonadeNexus/Relay/RelayTicketAuth.hpp>
#include <LemonadeNexus/Relay/RelayTypes.hpp>

#include <asio.hpp>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
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
/// Tickets are verified against the verified Tier 1 membership
/// (set_ticket_authority), so a relay needs no tree and no session state.
class RelayService : public core::IService<RelayService>,
                      public IRelayProvider<RelayService> {
    friend class core::IService<RelayService>;
    friend class IRelayProvider<RelayService>;

public:
    /// @param io            ASIO io_context driving the socket
    /// @param port          UDP port to listen on (default 9103)
    /// @param crypto        Reference to the crypto service
    RelayService(asio::io_context& io,
                 uint16_t port,
                 crypto::SodiumCryptoService& crypto);

    /// Where the verified Tier 1 membership comes from: the network, the
    /// current epoch, and its members, as the security mesh verified them
    /// from the authority chain. nullopt while none is verified. Unset, or
    /// nullopt, refuses every ticket. Must be thread-safe. Set before start.
    void set_ticket_authority(std::function<std::optional<RelayTicketAuthority>()> source) {
        ticket_authority_ = std::move(source);
    }

    // -- IService --
    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "RelayService"; }

    // -- IRelayProvider --
    [[nodiscard]] RelayAllocation do_allocate(const RelayTicket& ticket);
    /// Bind a peer to a session slot. Requires a single-use, side-bound token
    /// (compute_bind_token) so that knowing the session_id alone is not enough
    /// to hijack a slot. A token binds exactly one side, exactly once.
    [[nodiscard]] RelayBindResult do_bind(const SessionId& session_id,
                                          const asio::ip::udp::endpoint& peer_endpoint,
                                          std::span<const uint8_t> bind_token);

    /// Derive the 16-byte bind token for a session side (0 = A, 1 = B). Keyed by
    /// a per-process secret, so only this relay can produce valid tokens; the
    /// coordinator obtains them at allocation time and hands them to each peer
    /// over the authenticated control channel.
    [[nodiscard]] std::array<uint8_t, 16> compute_bind_token(const SessionId& session_id,
                                                             uint8_t side) const;
    [[nodiscard]] bool do_forward(const SessionId& session_id,
                                  std::span<const uint8_t> data,
                                  const asio::ip::udp::endpoint& from);
    void do_teardown(const SessionId& session_id);
    /// True when the ticket is valid now against the verified Tier 1
    /// membership (check_relay_ticket). Replay is checked by do_allocate.
    [[nodiscard]] bool do_verify_ticket(const RelayTicket& ticket) const;

    /// Why a ticket is refused, or Valid.
    [[nodiscard]] RelayTicketCheck check_ticket(const RelayTicket& ticket) const;

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

    /// Start periodic TTL enforcement timer.
    void start_ttl_timer();

    /// Purge sessions that have exceeded their TTL.
    void purge_expired_sessions();

    // Dependencies
    asio::io_context&            io_;
    asio::ip::udp::socket        socket_;
    uint16_t                     port_;
    crypto::SodiumCryptoService& crypto_;
    std::function<std::optional<RelayTicketAuthority>()> ticket_authority_;

    // Receive buffer (max UDP datagram)
    static constexpr std::size_t kMaxDatagram = 65535;
    std::array<uint8_t, kMaxDatagram> recv_buf_{};
    asio::ip::udp::endpoint           remote_endpoint_;

    // Per-process secret keying the bind tokens (random at on_start).
    crypto::Hash256 bind_secret_{};

    // Session table
    mutable std::mutex mutex_;
    std::unordered_map<SessionId, std::shared_ptr<RelaySession>, SessionIdHash> sessions_;

    // Issuer and session nonce of every ticket already allocated, with its
    // expiry: a ticket allocates at most one session. An entry is dropped only
    // after its ticket expired, when the ticket is refused anyway.
    std::unordered_map<std::string, uint64_t> seen_tickets_;

    // TTL enforcement timer (fires every 30 seconds)
    asio::steady_timer ttl_timer_{io_};
};

} // namespace nexus::relay
