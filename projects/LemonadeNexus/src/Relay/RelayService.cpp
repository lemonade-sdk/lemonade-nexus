#include <LemonadeNexus/Relay/RelayService.hpp>

#include <spdlog/spdlog.h>
#include <sodium.h>

#include <algorithm>
#include <chrono>
#include <cstring>

namespace nexus::relay {

namespace {

uint64_t unix_now() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                     std::chrono::system_clock::now().time_since_epoch())
                                     .count());
}

int64_t steady_ms(std::chrono::steady_clock::time_point t) {
    return std::chrono::duration_cast<std::chrono::milliseconds>(t.time_since_epoch()).count();
}

/// Replay key of a ticket: one allocation per issuer and session nonce.
std::string ticket_key(const RelayTicket& ticket) {
    return crypto::to_hex(std::span<const uint8_t>(ticket.issuer)) + ":" +
           crypto::to_hex(std::span<const uint8_t>(ticket.session_nonce));
}

bool equal_ct(const RelayCommitment& a, const RelayCommitment& b) {
    return sodium_memcmp(a.data(), b.data(), a.size()) == 0;
}

asio::ip::udp::socket open_dual_stack(asio::io_context& io, uint16_t port) {
    asio::ip::udp::socket socket(io);
    socket.open(asio::ip::udp::v6());
    // The client dataplane is IPv4, so the relay must accept IPv4 senders
    // even where the host defaults IPv6 sockets to IPv6 only.
    asio::error_code ec;
    socket.set_option(asio::ip::v6_only(false), ec);
    socket.bind(asio::ip::udp::endpoint(asio::ip::udp::v6(), port));
    return socket;
}

network::RateLimitConfig limiter_config(const RelayLimits& limits) {
    return network::RateLimitConfig{limits.allocate_per_minute, limits.allocate_burst};
}

}  // namespace

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

RelayService::RelayService(asio::io_context& io,
                           uint16_t port,
                           crypto::SodiumCryptoService& crypto)
    : io_(io)
    , socket_(open_dual_stack(io, port))
    , port_(port)
    , crypto_(crypto)
    , allocate_limiter_(std::make_unique<network::RateLimiter>(limiter_config(limits_)))
{
}

void RelayService::set_limits(const RelayLimits& limits) {
    std::lock_guard lock(mutex_);
    limits_ = limits;
    allocate_limiter_ = std::make_unique<network::RateLimiter>(limiter_config(limits_));
}

uint16_t RelayService::local_port() const {
    asio::error_code ec;
    const auto endpoint = socket_.local_endpoint(ec);
    return ec ? 0 : endpoint.port();
}

// ---------------------------------------------------------------------------
// IService
// ---------------------------------------------------------------------------

void RelayService::on_start() {
    crypto_.random_bytes(std::span<uint8_t>(bind_secret_));
    if (relay_id_.empty()) {
        spdlog::warn("[{}] no relay id is set: every ticket is refused", name());
    }
    spdlog::info("[{}] listening on UDP port {}", name(), local_port());
    start_receive();
    start_ttl_timer();
}

void RelayService::on_stop() {
    spdlog::info("[{}] stopping -- closing socket", name());
    ttl_timer_.cancel();
    asio::error_code ec;
    socket_.close(ec);
    if (ec) {
        spdlog::warn("[{}] socket close error: {}", name(), ec.message());
    }

    std::lock_guard lock(mutex_);
    const auto session_count = sessions_.size();
    sessions_.clear();
    pending_.clear();
    holder_sessions_.clear();
    spdlog::info("[{}] cleared {} sessions", name(), session_count);
}

// ---------------------------------------------------------------------------
// Session bookkeeping
// ---------------------------------------------------------------------------

bool RelayService::holder_has_room_locked(const std::string& holder) const {
    const auto it = holder_sessions_.find(holder);
    return it == holder_sessions_.end() || it->second < limits_.max_sessions_per_holder;
}

void RelayService::add_holder_locked(const std::string& holder) {
    if (!holder.empty()) ++holder_sessions_[holder];
}

RelayService::SessionMap::iterator RelayService::erase_session_locked(SessionMap::iterator it) {
    const auto& session = *it->second;
    for (const auto* holder : {&session.holder_a, &session.holder_b}) {
        if (holder->empty()) continue;
        auto count = holder_sessions_.find(*holder);
        if (count != holder_sessions_.end() && --count->second == 0) {
            holder_sessions_.erase(count);
        }
    }
    if (session.has_rendezvous) {
        const auto key = crypto::to_hex(std::span<const uint8_t>(session.rendezvous));
        auto pending = pending_.find(key);
        if (pending != pending_.end() && pending->second == session.session_id) {
            pending_.erase(pending);
        }
    }
    return sessions_.erase(it);
}

// ---------------------------------------------------------------------------
// IRelayProvider -- allocate
// ---------------------------------------------------------------------------

RelayAllocation RelayService::do_allocate(const RelayTicket& ticket) {
    RelayAllocation result;

    const auto check = check_ticket(ticket);
    if (check != RelayTicketCheck::Valid) {
        result.error_message = check == RelayTicketCheck::Expired
                                   ? "ticket expired"
                                   : "ticket verification failed: " +
                                         std::string(relay_ticket_check_name(check));
        spdlog::warn("[{}] allocation denied: {}", name(), result.error_message);
        return result;
    }

    const auto now = std::chrono::steady_clock::now();
    auto session = std::make_shared<RelaySession>();
    session->session_id = generate_session_id();
    session->created_at = now;
    session->last_activity_ms.store(steady_ms(now));
    session->holder_a = ticket.peer_id;

    std::lock_guard lock(mutex_);
    session->ttl_seconds = limits_.idle_timeout_sec;
    if (seen_tickets_.contains(ticket_key(ticket))) {
        result.error_message = "ticket already used";
        spdlog::warn("[{}] allocation denied: replayed ticket nonce", name());
        return result;
    }
    if (sessions_.size() >= limits_.max_sessions ||
        seen_tickets_.size() >= limits_.max_seen_tickets ||
        !holder_has_room_locked(ticket.peer_id)) {
        result.error_message = "relay capacity exceeded";
        spdlog::warn("[{}] allocation denied: {}", name(), result.error_message);
        return result;
    }
    seen_tickets_.emplace(ticket_key(ticket), SeenTicket{ticket.expires_at, session->session_id, {}});
    add_holder_locked(ticket.peer_id);

    result.session_id = session->session_id;
    result.relay_endpoint = "[::]:" + std::to_string(port_);
    result.ttl_seconds = session->ttl_seconds;
    sessions_.emplace(session->session_id, std::move(session));
    spdlog::info("[{}] allocated session for peer={}", name(), ticket.peer_id);
    return result;
}

// ---------------------------------------------------------------------------
// Wire allocation (rendezvous)
// ---------------------------------------------------------------------------

RelayRendezvousResult RelayService::allocate_rendezvous(const RelayAllocateRequest& request,
                                                        const asio::ip::udp::endpoint& remote) {
    RelayRendezvousResult result;
    const auto refuse = [&result](RelayErrorCode code, std::string message) {
        result.error = code;
        result.error_message = std::move(message);
        return result;
    };

    {
        // The limiter object is replaced only by set_limits, under the lock.
        std::lock_guard lock(mutex_);
        if (!allocate_limiter_->allow("allocate")) {
            return refuse(RelayErrorCode::RateLimited, "allocate rate limit reached");
        }
    }

    const auto check = check_ticket(request.ticket);
    if (check != RelayTicketCheck::Valid) {
        return refuse(RelayErrorCode::TicketRefused,
                      "ticket refused: " + std::string(relay_ticket_check_name(check)));
    }

    const auto& holder = request.ticket.peer_id;
    const auto key = ticket_key(request.ticket);
    const auto own_commitment = relay_proof_commitment(request.proof);
    const auto now = std::chrono::steady_clock::now();

    std::lock_guard lock(mutex_);

    if (auto seen = seen_tickets_.find(key); seen != seen_tickets_.end()) {
        // A retransmission from the endpoint that sent the ticket learns its
        // session again. Anyone else replaying it is refused.
        auto it = sessions_.find(seen->second.session_id);
        if (seen->second.remote == remote && it != sessions_.end()) {
            result.session_id = it->first;
            result.paired = it->second->peer_a_bound && it->second->peer_b_bound;
            return result;
        }
        return refuse(RelayErrorCode::TicketReplayed, "ticket already used");
    }
    if (seen_tickets_.size() >= limits_.max_seen_tickets) {
        return refuse(RelayErrorCode::CapacityExceeded, "replay set full");
    }

    const auto rendezvous_key = crypto::to_hex(std::span<const uint8_t>(request.rendezvous));
    const auto pending = pending_.find(rendezvous_key);

    if (pending == pending_.end()) {
        if (sessions_.size() >= limits_.max_sessions) {
            return refuse(RelayErrorCode::CapacityExceeded, "session limit reached");
        }
        if (!holder_has_room_locked(holder)) {
            return refuse(RelayErrorCode::CapacityExceeded, "holder session limit reached");
        }
        auto session = std::make_shared<RelaySession>();
        session->session_id = generate_session_id();
        session->created_at = now;
        session->last_activity_ms.store(steady_ms(now));
        session->ttl_seconds = limits_.idle_timeout_sec;
        session->peer_a_endpoint = remote;
        session->peer_a_bound = true;
        session->holder_a = holder;
        session->has_rendezvous = true;
        session->rendezvous = request.rendezvous;
        session->a_commitment = own_commitment;
        session->b_expected = request.peer_commitment;

        result.session_id = session->session_id;
        seen_tickets_.emplace(key, SeenTicket{request.ticket.expires_at, session->session_id, remote});
        add_holder_locked(holder);
        pending_.emplace(rendezvous_key, session->session_id);
        sessions_.emplace(session->session_id, std::move(session));
        spdlog::debug("[{}] session waiting for its second side (holder={})", name(), holder);
        return result;
    }

    auto it = sessions_.find(pending->second);
    if (it == sessions_.end()) {
        pending_.erase(pending);
        return refuse(RelayErrorCode::RendezvousBusy, "rendezvous state lost; retry");
    }
    auto& session = *it->second;

    if (equal_ct(own_commitment, session.a_commitment)) {
        // The waiting side again, with a fresh ticket. Only its own holder at
        // its own endpoint may repeat; anyone who merely saw its request may not.
        if (holder != session.holder_a || remote != session.peer_a_endpoint) {
            return refuse(RelayErrorCode::RendezvousBusy, "rendezvous slot is taken");
        }
        seen_tickets_.emplace(key, SeenTicket{request.ticket.expires_at, session.session_id, remote});
        session.last_activity_ms.store(steady_ms(now));
        result.session_id = session.session_id;
        return result;
    }

    if (!equal_ct(own_commitment, session.b_expected) ||
        !equal_ct(request.peer_commitment, session.a_commitment)) {
        return refuse(RelayErrorCode::ProofMismatch, "rendezvous proof does not match");
    }
    if (holder == session.holder_a) {
        return refuse(RelayErrorCode::RendezvousBusy, "both sides name the same ticket holder");
    }
    if (remote == session.peer_a_endpoint) {
        return refuse(RelayErrorCode::RendezvousBusy, "both sides use the same endpoint");
    }
    if (!holder_has_room_locked(holder)) {
        return refuse(RelayErrorCode::CapacityExceeded, "holder session limit reached");
    }

    session.peer_b_endpoint = remote;
    session.peer_b_bound = true;
    session.holder_b = holder;
    session.last_activity_ms.store(steady_ms(now));
    seen_tickets_.emplace(key, SeenTicket{request.ticket.expires_at, session.session_id, remote});
    add_holder_locked(holder);
    pending_.erase(pending);

    result.session_id = session.session_id;
    result.paired = true;
    result.notify = session.peer_a_endpoint;
    spdlog::info("[{}] relay session paired ({} live)", name(), sessions_.size());
    return result;
}

// ---------------------------------------------------------------------------
// IRelayProvider -- bind
// ---------------------------------------------------------------------------

std::array<uint8_t, 16> RelayService::compute_bind_token(const SessionId& session_id,
                                                         uint8_t side) const {
    // token = HKDF-SHA256(ikm=bind_secret_, salt=session_id, info=side)[0..16]
    const uint8_t info[1] = {side};
    auto out = crypto_.hkdf_sha256(
        std::span<const uint8_t>(bind_secret_),
        std::span<const uint8_t>(session_id),
        std::span<const uint8_t>(info, 1),
        16);
    std::array<uint8_t, 16> token{};
    std::copy_n(out.begin(), token.size(), token.begin());
    return token;
}

RelayBindResult RelayService::do_bind(const SessionId& session_id,
                                       const asio::ip::udp::endpoint& peer_endpoint,
                                       std::span<const uint8_t> bind_token) {
    RelayBindResult result;
    result.session_id = session_id;

    std::lock_guard lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        result.error_message = "session not found";
        spdlog::warn("[{}] bind failed: {}", name(), result.error_message);
        return result;
    }
    auto& session = *it->second;

    // The presented token must equal exactly one side's secret-derived token,
    // and that side must be unbound. This makes knowledge of the session_id
    // alone insufficient to hijack a slot, and each token binds its side once.
    const auto token_a = compute_bind_token(session_id, 0);
    const auto token_b = compute_bind_token(session_id, 1);
    const bool match_a = bind_token.size() == token_a.size() &&
        sodium_memcmp(bind_token.data(), token_a.data(), token_a.size()) == 0;
    const bool match_b = bind_token.size() == token_b.size() &&
        sodium_memcmp(bind_token.data(), token_b.data(), token_b.size()) == 0;

    if (match_a && !session.peer_a_bound) {
        session.peer_a_endpoint = peer_endpoint;
        session.peer_a_bound = true;
        spdlog::info("[{}] peer_a bound to session", name());
    } else if (match_b && !session.peer_b_bound) {
        session.peer_b_endpoint = peer_endpoint;
        session.peer_b_bound = true;
        spdlog::info("[{}] peer_b bound to session", name());
    } else {
        result.error_message = "invalid or already-used bind token";
        spdlog::warn("[{}] bind failed: {}", name(), result.error_message);
        return result;
    }

    session.last_activity_ms.store(steady_ms(std::chrono::steady_clock::now()));
    result.success = true;
    return result;
}

// ---------------------------------------------------------------------------
// IRelayProvider -- forward
// ---------------------------------------------------------------------------

bool RelayService::do_forward(const SessionId& session_id,
                               std::span<const uint8_t> data,
                               const asio::ip::udp::endpoint& from) {
    std::shared_ptr<RelaySession> session;
    asio::ip::udp::endpoint dest;
    bool sender_bound = false;
    bool fully_bound = false;
    {
        std::lock_guard lock(mutex_);
        auto it = sessions_.find(session_id);
        if (it == sessions_.end()) {
            spdlog::debug("[{}] forward: session not found", name());
            return false;
        }
        session = it->second;
        fully_bound = session->peer_a_bound && session->peer_b_bound;
        // Forward only between the two endpoints the session bound.
        if (fully_bound && from == session->peer_a_endpoint) {
            dest = session->peer_b_endpoint;
            sender_bound = true;
        } else if (fully_bound && from == session->peer_b_endpoint) {
            dest = session->peer_a_endpoint;
            sender_bound = true;
        }
    }

    if (!fully_bound) {
        session->packets_dropped.fetch_add(1, std::memory_order_relaxed);
        spdlog::debug("[{}] forward: session not fully bound", name());
        return false;
    }
    if (!sender_bound) {
        session->packets_dropped.fetch_add(1, std::memory_order_relaxed);
        spdlog::debug("[{}] forward: sender not bound to session", name());
        return false;
    }
    // The receiver tells relay control messages from forwarded data by the
    // relay magic, so a peer may not forward bytes that look like control.
    // A BoringTun datagram never starts with it.
    if (data.size() >= 2 && data[0] == 0x52 && data[1] == 0x4C) {
        session->packets_dropped.fetch_add(1, std::memory_order_relaxed);
        return false;
    }

    asio::error_code ec;
    socket_.send_to(asio::buffer(data.data(), data.size()), dest, 0, ec);
    if (ec) {
        session->packets_dropped.fetch_add(1, std::memory_order_relaxed);
        spdlog::debug("[{}] forward send_to error: {}", name(), ec.message());
        return false;
    }

    session->last_activity_ms.store(steady_ms(std::chrono::steady_clock::now()),
                                    std::memory_order_relaxed);
    session->bytes_forwarded.fetch_add(data.size(), std::memory_order_relaxed);
    session->packets_forwarded.fetch_add(1, std::memory_order_relaxed);
    return true;
}

// ---------------------------------------------------------------------------
// IRelayProvider -- teardown
// ---------------------------------------------------------------------------

void RelayService::do_teardown(const SessionId& session_id) {
    std::lock_guard lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it != sessions_.end()) {
        erase_session_locked(it);
        spdlog::info("[{}] session torn down", name());
    } else {
        spdlog::debug("[{}] teardown: session not found", name());
    }
}

// ---------------------------------------------------------------------------
// IRelayProvider -- verify_ticket
// ---------------------------------------------------------------------------

bool RelayService::do_verify_ticket(const RelayTicket& ticket) const {
    return check_ticket(ticket) == RelayTicketCheck::Valid;
}

RelayTicketCheck RelayService::check_ticket(const RelayTicket& ticket) const {
    return check_relay_ticket(
        ticket, ticket_authority_ ? ticket_authority_() : std::optional<RelayTicketAuthority>{},
        relay_id_, unix_now());
}

// ---------------------------------------------------------------------------
// Session stats
// ---------------------------------------------------------------------------

std::optional<RelaySessionStats> RelayService::get_session_stats(const SessionId& session_id) const {
    std::lock_guard lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) {
        return std::nullopt;
    }

    const auto& s = *it->second;
    RelaySessionStats stats;
    stats.session_id = s.session_id;
    stats.bytes_forwarded = s.bytes_forwarded.load(std::memory_order_relaxed);
    stats.packets_forwarded = s.packets_forwarded.load(std::memory_order_relaxed);
    stats.packets_dropped = s.packets_dropped.load(std::memory_order_relaxed);
    return stats;
}

std::size_t RelayService::session_count() const {
    std::lock_guard lock(mutex_);
    return sessions_.size();
}

bool RelayService::touch_if_bound(const SessionId& session_id,
                                  const asio::ip::udp::endpoint& from) {
    std::lock_guard lock(mutex_);
    auto it = sessions_.find(session_id);
    if (it == sessions_.end()) return false;
    auto& session = *it->second;
    const bool bound = (session.peer_a_bound && from == session.peer_a_endpoint) ||
                       (session.peer_b_bound && from == session.peer_b_endpoint);
    if (bound) session.last_activity_ms.store(steady_ms(std::chrono::steady_clock::now()));
    return bound;
}

// ---------------------------------------------------------------------------
// Async receive loop
// ---------------------------------------------------------------------------

void RelayService::start_receive() {
    socket_.async_receive_from(
        asio::buffer(recv_buf_), remote_endpoint_,
        [this](const asio::error_code& ec, std::size_t bytes_received) {
            if (ec) {
                if (ec != asio::error::operation_aborted) {
                    spdlog::warn("[{}] receive error: {}", name(), ec.message());
                    start_receive(); // keep listening
                }
                return;
            }
            handle_receive(bytes_received, remote_endpoint_);
            start_receive();
        });
}

// ---------------------------------------------------------------------------
// Datagram dispatch
// ---------------------------------------------------------------------------

void RelayService::handle_receive(std::size_t bytes_received,
                                   const asio::ip::udp::endpoint& remote) {
    if (bytes_received < 2) {
        return;
    }

    // The relay magic is little-endian on the wire: 0x52 0x4C.
    const uint16_t magic = static_cast<uint16_t>(recv_buf_[0] | (recv_buf_[1] << 8));

    if (magic == kRelayMagic) {
        handle_relay_packet(
            std::span<const uint8_t>(recv_buf_.data(), bytes_received), remote);
    } else if (magic == 0x0100) {
        // STUN Binding Request (type 0x0001 in network byte order) -- ignored
        // here (handled by a co-located StunProvider)
        spdlog::debug("[{}] received STUN packet ({} bytes)", name(), bytes_received);
    } else {
        spdlog::debug("[{}] unknown protocol magic 0x{:04X}", name(), magic);
    }
}

// ---------------------------------------------------------------------------
// Relay protocol handler
// ---------------------------------------------------------------------------

void RelayService::send_reply(RelayMsgType type, const SessionId& session, uint32_t sequence,
                              std::span<const uint8_t> payload,
                              const asio::ip::udp::endpoint& to) {
    const auto datagram = make_relay_datagram(type, session, sequence, payload);
    asio::error_code ec;
    socket_.send_to(asio::buffer(datagram), to, 0, ec);
    if (ec) {
        spdlog::debug("[{}] reply send_to error: {}", name(), ec.message());
    }
}

void RelayService::send_error(RelayErrorCode code, const SessionId& session, uint32_t sequence,
                              const asio::ip::udp::endpoint& to) {
    const uint8_t payload[1] = {static_cast<uint8_t>(code)};
    send_reply(RelayMsgType::Error, session, sequence, payload, to);
}

void RelayService::handle_allocate(const RelayPacketHeader& header,
                                   std::span<const uint8_t> payload,
                                   const asio::ip::udp::endpoint& remote) {
    const auto request = decode_relay_allocate(payload);
    if (!request) {
        send_error(RelayErrorCode::Malformed, header.session_id, header.sequence_number, remote);
        return;
    }
    const auto result = allocate_rendezvous(*request, remote);
    if (result.error) {
        spdlog::debug("[{}] allocate refused: {}", name(), result.error_message);
        send_error(*result.error, header.session_id, header.sequence_number, remote);
        return;
    }

    uint32_t idle_timeout = 0;
    {
        std::lock_guard lock(mutex_);
        idle_timeout = limits_.idle_timeout_sec;
    }
    const auto reply = encode_relay_allocated(RelayAllocatedReply{
        result.paired ? RelayAllocationState::Paired : RelayAllocationState::Waiting,
        idle_timeout});
    send_reply(RelayMsgType::Allocated, result.session_id, header.sequence_number, reply, remote);
    if (result.notify) {
        send_reply(RelayMsgType::Bound, result.session_id, 0, {}, *result.notify);
    }
}

void RelayService::handle_relay_packet(std::span<const uint8_t> data,
                                        const asio::ip::udp::endpoint& remote) {
    const auto parsed = decode_relay_header(data);
    if (!parsed) {
        spdlog::debug("[{}] malformed relay packet ({} bytes)", name(), data.size());
        return;
    }
    const auto& header = *parsed;
    const auto payload = data.subspan(kRelayHeaderSize, header.payload_length);

    switch (header.msg_type) {
        case RelayMsgType::Allocate:
            handle_allocate(header, payload, remote);
            break;

        case RelayMsgType::Bind: {
            // Bind payload carries the 16-byte bind token.
            std::span<const uint8_t> token;
            if (payload.size() >= 16) token = payload.subspan(0, 16);
            const auto result = do_bind(header.session_id, remote, token);
            if (result.success) {
                send_reply(RelayMsgType::Bound, header.session_id, header.sequence_number, {},
                           remote);
            } else {
                send_error(RelayErrorCode::BindFailed, header.session_id,
                           header.sequence_number, remote);
            }
            break;
        }

        case RelayMsgType::Data:
            (void)do_forward(header.session_id, payload, remote);
            break;

        case RelayMsgType::Heartbeat:
            // Only a bound endpoint keeps a session alive or learns it exists.
            if (touch_if_bound(header.session_id, remote)) {
                send_reply(RelayMsgType::HeartbeatAck, header.session_id,
                           header.sequence_number, {}, remote);
            } else {
                send_error(RelayErrorCode::SessionUnknown, header.session_id,
                           header.sequence_number, remote);
            }
            break;

        case RelayMsgType::Teardown:
            // Only a bound endpoint may end its own session.
            if (touch_if_bound(header.session_id, remote)) {
                do_teardown(header.session_id);
            }
            break;

        default:
            spdlog::debug("[{}] unhandled relay msg_type 0x{:02X}",
                          name(), static_cast<uint8_t>(header.msg_type));
            break;
    }
}

// ---------------------------------------------------------------------------
// TTL enforcement
// ---------------------------------------------------------------------------

void RelayService::start_ttl_timer() {
    ttl_timer_.expires_after(std::chrono::seconds(5));
    ttl_timer_.async_wait([this](const asio::error_code& ec) {
        if (ec) return; // cancelled or error
        (void)expire_sessions(std::chrono::steady_clock::now());
        start_ttl_timer(); // reschedule
    });
}

std::size_t RelayService::expire_sessions(std::chrono::steady_clock::time_point now) {
    using std::chrono::seconds;
    const int64_t now_ms = steady_ms(now);
    std::lock_guard lock(mutex_);

    std::size_t purged = 0;
    for (auto it = sessions_.begin(); it != sessions_.end();) {
        const auto& session = *it->second;
        const auto age = now - session.created_at;
        const bool paired = session.peer_a_bound && session.peer_b_bound;
        const int64_t idle_ms = now_ms - session.last_activity_ms.load();
        const bool expired =
            (!paired && age > seconds(limits_.pending_timeout_sec)) ||
            (paired && idle_ms > static_cast<int64_t>(limits_.idle_timeout_sec) * 1000) ||
            age > seconds(limits_.max_lifetime_sec);
        if (expired) {
            it = erase_session_locked(it);
            ++purged;
        } else {
            ++it;
        }
    }

    if (purged > 0) {
        spdlog::info("[{}] expired {} sessions ({} remaining)",
                     name(), purged, sessions_.size());
    }

    // A replay entry outlives its ticket by the clock skew allowance.
    const auto unix = unix_now();
    for (auto it = seen_tickets_.begin(); it != seen_tickets_.end();) {
        it = it->second.expires_at + kRelayTicketClockSkewSec < unix ? seen_tickets_.erase(it)
                                                                     : ++it;
    }
    return purged;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

SessionId RelayService::generate_session_id() {
    SessionId id{};
    crypto_.random_bytes(std::span<uint8_t>(id));
    return id;
}

} // namespace nexus::relay
