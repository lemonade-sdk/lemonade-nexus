#pragma once

#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Network/RateLimiter.hpp>
#include <LemonadeNexus/Relay/IRelayProvider.hpp>
#include <LemonadeNexus/Relay/RelayTicketAuth.hpp>
#include <LemonadeNexus/Relay/RelayTypes.hpp>
#include <LemonadeNexus/Relay/RelayWire.hpp>

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
#include <vector>

namespace nexus::relay {

/// A live relay session binding two peer endpoints.
///
/// The endpoints, bound flags, holders, and rendezvous fields are guarded by
/// RelayService's mutex. The counters are atomic.
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
    /// Steady-clock milliseconds of the last packet from a bound endpoint.
    std::atomic<int64_t>       last_activity_ms{0};
    /// Idle timeout reported to the peers, in seconds.
    uint32_t                   ttl_seconds{0};

    /// The ticket holders (ticket peer_id) of side A and side B. Empty for a
    /// side that no ticket allocated.
    std::string                holder_a;
    std::string                holder_b;

    /// Set when a wire Allocate request allocated the session.
    bool                       has_rendezvous{false};
    RendezvousId               rendezvous{};
    /// Commitment to side A's proof, and the commitment side B must open.
    RelayCommitment            a_commitment{};
    RelayCommitment            b_expected{};
};

/// Resource limits of a relay. Every map the relay keeps is bounded by them.
struct RelayLimits {
    /// Live sessions, waiting and paired.
    std::size_t max_sessions{4096};
    /// Sessions one ticket holder (ticket peer_id) may be bound to.
    std::size_t max_sessions_per_holder{16};
    /// Used-ticket records kept for replay rejection.
    std::size_t max_seen_tickets{16384};
    /// How long a session waits for its second side, in seconds.
    uint32_t pending_timeout_sec{30};
    /// How long a session lives with no packet from a bound endpoint, in seconds.
    uint32_t idle_timeout_sec{90};
    /// Longest life of any session, in seconds. The peers then allocate again
    /// with new tickets, so their authorization is checked again.
    uint32_t max_lifetime_sec{3600};
    /// Allocate requests the relay checks per minute, across all senders, and
    /// the burst it allows. A request over the limit is refused before its
    /// ticket signature is verified.
    uint32_t allocate_per_minute{6000};
    uint32_t allocate_burst{200};
};

/// The result of a wire Allocate request (allocate_rendezvous).
struct RelayRendezvousResult {
    /// Set when the request is refused. No session state changed.
    std::optional<RelayErrorCode> error;
    /// Why, for logs. Contains no secret.
    std::string error_message;
    SessionId session_id{};
    /// True when both sides are bound.
    bool paired{false};
    /// Set when this request paired the session: the endpoint of the side
    /// that waited, which the relay tells with a Bound message.
    std::optional<asio::ip::udp::endpoint> notify;
};

/// Concrete relay service that listens on a UDP port, multiplexing STUN
/// (magic 0x0001) and Relay (magic 0x4C52) by inspecting the first two bytes
/// of each datagram.
///
/// Tickets are verified against the verified Tier 1 membership
/// (set_ticket_authority) and the relay's own id (set_relay_id), so a relay
/// needs no tree and no session state. Two peers join one session with one
/// wire Allocate request each (RelayWire.hpp). The relay forwards Data only
/// between the two endpoints those requests bound. It drops a session when
/// the session is idle, when its second side does not join in time, or at its
/// maximum lifetime.
class RelayService : public core::IService<RelayService>,
                      public IRelayProvider<RelayService> {
    friend class core::IService<RelayService>;
    friend class IRelayProvider<RelayService>;

public:
    /// @param io            ASIO io_context driving the socket
    /// @param port          UDP port to listen on (default 9103). The socket is
    ///                      dual-stack, so IPv4 clients reach it too.
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

    /// This relay's id: its base64 node identity key. A ticket must name it.
    /// Empty (the default) refuses every ticket. Set before start.
    void set_relay_id(std::string relay_id) { relay_id_ = std::move(relay_id); }

    /// Replace the resource limits. Set before start.
    void set_limits(const RelayLimits& limits);

    /// The UDP port the socket is bound to (useful when constructed with 0).
    [[nodiscard]] uint16_t local_port() const;

    // -- IService --
    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "RelayService"; }

    // -- IRelayProvider --
    /// Allocate an unbound session in process (no rendezvous). Its sides are
    /// bound with do_bind. Wire clients use allocate_rendezvous instead.
    [[nodiscard]] RelayAllocation do_allocate(const RelayTicket& ticket);
    /// Bind a peer to a session slot. Requires a single-use, side-bound token
    /// (compute_bind_token) so that knowing the session_id alone is not enough
    /// to hijack a slot. A token binds exactly one side, exactly once.
    [[nodiscard]] RelayBindResult do_bind(const SessionId& session_id,
                                          const asio::ip::udp::endpoint& peer_endpoint,
                                          std::span<const uint8_t> bind_token);

    /// Derive the 16-byte bind token for a session side (0 = A, 1 = B). Keyed by
    /// a per-process secret, so only this relay can produce valid tokens; an
    /// in-process coordinator obtains them at allocation time and hands them
    /// to each peer over an authenticated control channel.
    [[nodiscard]] std::array<uint8_t, 16> compute_bind_token(const SessionId& session_id,
                                                             uint8_t side) const;
    /// Forward `data` from one bound side to the other. False when the session
    /// is unknown, not fully bound, or `from` is not one of its endpoints.
    [[nodiscard]] bool do_forward(const SessionId& session_id,
                                  std::span<const uint8_t> data,
                                  const asio::ip::udp::endpoint& from);
    void do_teardown(const SessionId& session_id);
    /// True when the ticket is valid now against the verified Tier 1
    /// membership and this relay's id (check_relay_ticket). Replay is checked
    /// by do_allocate and allocate_rendezvous.
    [[nodiscard]] bool do_verify_ticket(const RelayTicket& ticket) const;

    /// Why a ticket is refused, or Valid.
    [[nodiscard]] RelayTicketCheck check_ticket(const RelayTicket& ticket) const;

    /// Return statistics for a session.
    [[nodiscard]] std::optional<RelaySessionStats> get_session_stats(const SessionId& session_id) const;

    /// Handle a decoded wire Allocate request from `remote`.
    ///
    /// The first request for a rendezvous id creates a waiting session bound
    /// to `remote`. A second request joins it only when its proof opens the
    /// first request's commitment, its commitment matches the first request's
    /// proof, it comes from another ticket holder, and it comes from another
    /// endpoint. A repeat from the same side and endpoint returns the same
    /// session. Every accepted request consumes its ticket. Thread-safe.
    [[nodiscard]] RelayRendezvousResult allocate_rendezvous(const RelayAllocateRequest& request,
                                                            const asio::ip::udp::endpoint& remote);

    /// Drop every session that, at `now`, waited longer than the pending
    /// timeout for its second side, was idle longer than the idle timeout, or
    /// lived longer than the maximum lifetime. Also drop used-ticket records
    /// whose ticket can no longer be accepted. Returns the number of sessions
    /// dropped. The service calls it every 5 seconds. Thread-safe.
    std::size_t expire_sessions(std::chrono::steady_clock::time_point now);

    /// Number of live sessions. Thread-safe.
    [[nodiscard]] std::size_t session_count() const;

private:
    using SessionMap = std::unordered_map<SessionId, std::shared_ptr<RelaySession>, SessionIdHash>;

    /// Begin asynchronous receive loop.
    void start_receive();

    /// Dispatch an incoming datagram based on the first two bytes.
    void handle_receive(std::size_t bytes_received,
                        const asio::ip::udp::endpoint& remote);

    /// Process a relay-protocol datagram.
    void handle_relay_packet(std::span<const uint8_t> data,
                             const asio::ip::udp::endpoint& remote);

    /// Process a wire Allocate request and send the reply.
    void handle_allocate(const RelayPacketHeader& header, std::span<const uint8_t> payload,
                         const asio::ip::udp::endpoint& remote);

    /// Send a reply datagram.
    void send_reply(RelayMsgType type, const SessionId& session, uint32_t sequence,
                    std::span<const uint8_t> payload, const asio::ip::udp::endpoint& to);
    void send_error(RelayErrorCode code, const SessionId& session, uint32_t sequence,
                    const asio::ip::udp::endpoint& to);

    /// True when `from` is a bound endpoint of the session. Refreshes the
    /// session's activity time.
    [[nodiscard]] bool touch_if_bound(const SessionId& session_id,
                                      const asio::ip::udp::endpoint& from);

    /// Generate a fresh random SessionId.
    [[nodiscard]] SessionId generate_session_id();

    /// Erase a session and release its holder counts and rendezvous entry.
    /// Caller holds mutex_. Returns the next iterator.
    SessionMap::iterator erase_session_locked(SessionMap::iterator it);

    /// True when `holder` may be bound to one more session. Caller holds mutex_.
    [[nodiscard]] bool holder_has_room_locked(const std::string& holder) const;
    void add_holder_locked(const std::string& holder);

    /// Start periodic TTL enforcement timer.
    void start_ttl_timer();

    // Dependencies
    asio::io_context&            io_;
    asio::ip::udp::socket        socket_;
    uint16_t                     port_;
    crypto::SodiumCryptoService& crypto_;
    std::function<std::optional<RelayTicketAuthority>()> ticket_authority_;
    std::string                  relay_id_;
    RelayLimits                  limits_;

    // Receive buffer (max UDP datagram)
    static constexpr std::size_t kMaxDatagram = 65535;
    std::array<uint8_t, kMaxDatagram> recv_buf_{};
    asio::ip::udp::endpoint           remote_endpoint_;

    // Per-process secret keying the bind tokens (random at on_start).
    crypto::Hash256 bind_secret_{};

    // Session table
    mutable std::mutex mutex_;
    SessionMap sessions_;

    // Waiting sessions by rendezvous id (hex). An entry exists only while its
    // session waits for its second side.
    std::unordered_map<std::string, SessionId> pending_;

    // Sessions each ticket holder is bound to. An entry exists only while the
    // count is nonzero, so the map is bounded by twice max_sessions.
    std::unordered_map<std::string, std::size_t> holder_sessions_;

    // A ticket already allocated: its expiry, the session it allocated, and
    // the endpoint that sent it (a retransmission from that endpoint gets the
    // same session). A ticket allocates at most one session. An entry is
    // dropped only after its ticket expired, when the ticket is refused anyway.
    struct SeenTicket {
        uint64_t                expires_at{0};
        SessionId               session_id{};
        asio::ip::udp::endpoint remote;
    };
    std::unordered_map<std::string, SeenTicket> seen_tickets_;

    // Global Allocate rate limit, checked before the ticket signature. It
    // uses one bucket, so it holds no per-sender state.
    std::unique_ptr<network::RateLimiter> allocate_limiter_;

    // TTL enforcement timer (fires every 5 seconds)
    asio::steady_timer ttl_timer_{io_};
};

} // namespace nexus::relay
