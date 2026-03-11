#include <LemonadeNexus/Relay/RelayService.hpp>

#include <spdlog/spdlog.h>
#include <sodium.h>

#include <chrono>
#include <cstring>

namespace nexus::relay {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

RelayService::RelayService(asio::io_context& io,
                           uint16_t port,
                           crypto::SodiumCryptoService& crypto,
                           crypto::Ed25519PublicKey central_pubkey)
    : io_(io)
    , socket_(io, asio::ip::udp::endpoint(asio::ip::udp::v6(), port))
    , port_(port)
    , crypto_(crypto)
    , central_pubkey_(central_pubkey)
{
}

// ---------------------------------------------------------------------------
// IService
// ---------------------------------------------------------------------------

void RelayService::on_start() {
    spdlog::info("[{}] listening on UDP port {}", name(), port_);
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
    spdlog::info("[{}] cleared {} sessions", name(), session_count);
}

// ---------------------------------------------------------------------------
// IRelayProvider -- allocate
// ---------------------------------------------------------------------------

RelayAllocation RelayService::do_allocate(const RelayTicket& ticket) {
    RelayAllocation result;

    if (!do_verify_ticket(ticket)) {
        result.error_message = "ticket verification failed";
        spdlog::warn("[{}] allocation denied: {}", name(), result.error_message);
        return result;
    }

    // Check ticket expiry
    const auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch())
        .count());
    if (ticket.expires_at != 0 && ticket.expires_at < now) {
        result.error_message = "ticket expired";
        spdlog::warn("[{}] allocation denied: {}", name(), result.error_message);
        return result;
    }

    // Create a new session
    auto session = std::make_shared<RelaySession>();
    session->session_id = generate_session_id();
    session->created_at = std::chrono::steady_clock::now();
    session->ttl_seconds = 300;

    result.session_id = session->session_id;
    result.relay_endpoint = "[::]:" + std::to_string(port_);
    result.ttl_seconds = session->ttl_seconds;

    {
        std::lock_guard lock(mutex_);
        sessions_.emplace(session->session_id, std::move(session));
    }

    spdlog::info("[{}] allocated session for peer={}", name(), ticket.peer_id);
    return result;
}

// ---------------------------------------------------------------------------
// IRelayProvider -- bind
// ---------------------------------------------------------------------------

RelayBindResult RelayService::do_bind(const SessionId& session_id,
                                       const asio::ip::udp::endpoint& peer_endpoint) {
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
    if (!session.peer_a_bound) {
        session.peer_a_endpoint = peer_endpoint;
        session.peer_a_bound = true;
        spdlog::info("[{}] peer_a bound to session", name());
    } else if (!session.peer_b_bound) {
        session.peer_b_endpoint = peer_endpoint;
        session.peer_b_bound = true;
        spdlog::info("[{}] peer_b bound to session", name());
    } else {
        result.error_message = "session already has two peers bound";
        spdlog::warn("[{}] bind failed: {}", name(), result.error_message);
        return result;
    }

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
    {
        std::lock_guard lock(mutex_);
        auto it = sessions_.find(session_id);
        if (it == sessions_.end()) {
            spdlog::debug("[{}] forward: session not found", name());
            return false;
        }
        session = it->second;
    }

    if (!session->peer_a_bound || !session->peer_b_bound) {
        session->packets_dropped.fetch_add(1, std::memory_order_relaxed);
        spdlog::debug("[{}] forward: session not fully bound", name());
        return false;
    }

    // Determine the destination: forward to the other peer
    asio::ip::udp::endpoint dest;
    if (from == session->peer_a_endpoint) {
        dest = session->peer_b_endpoint;
    } else if (from == session->peer_b_endpoint) {
        dest = session->peer_a_endpoint;
    } else {
        session->packets_dropped.fetch_add(1, std::memory_order_relaxed);
        spdlog::warn("[{}] forward: sender not bound to session", name());
        return false;
    }

    asio::error_code ec;
    socket_.send_to(asio::buffer(data.data(), data.size()), dest, 0, ec);
    if (ec) {
        session->packets_dropped.fetch_add(1, std::memory_order_relaxed);
        spdlog::warn("[{}] forward send_to error: {}", name(), ec.message());
        return false;
    }

    session->bytes_forwarded.fetch_add(data.size(), std::memory_order_relaxed);
    session->packets_forwarded.fetch_add(1, std::memory_order_relaxed);
    return true;
}

// ---------------------------------------------------------------------------
// IRelayProvider -- teardown
// ---------------------------------------------------------------------------

void RelayService::do_teardown(const SessionId& session_id) {
    std::lock_guard lock(mutex_);
    auto erased = sessions_.erase(session_id);
    if (erased > 0) {
        spdlog::info("[{}] session torn down", name());
    } else {
        spdlog::debug("[{}] teardown: session not found", name());
    }
}

// ---------------------------------------------------------------------------
// IRelayProvider -- verify_ticket
// ---------------------------------------------------------------------------

bool RelayService::do_verify_ticket(const RelayTicket& ticket) const {
    auto canonical = ticket_canonical_bytes(ticket);
    crypto::Ed25519Signature sig;
    std::memcpy(sig.data(), ticket.signature.data(), sig.size());

    return crypto_.ed25519_verify(
        central_pubkey_,
        std::span<const uint8_t>(canonical),
        sig);
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

    // Read the first two bytes to determine protocol
    uint16_t magic = 0;
    std::memcpy(&magic, recv_buf_.data(), sizeof(magic));

    if (magic == kRelayMagic) {
        handle_relay_packet(
            std::span<const uint8_t>(recv_buf_.data(), bytes_received), remote);
    } else if (magic == 0x0001) {
        // STUN Binding Request -- log and ignore (handled by a co-located StunProvider)
        spdlog::debug("[{}] received STUN packet from {} ({} bytes)",
                      name(), remote.address().to_string(), bytes_received);
    } else {
        spdlog::debug("[{}] unknown protocol magic 0x{:04X} from {}",
                      name(), magic, remote.address().to_string());
    }
}

// ---------------------------------------------------------------------------
// Relay protocol handler
// ---------------------------------------------------------------------------

void RelayService::handle_relay_packet(std::span<const uint8_t> data,
                                        const asio::ip::udp::endpoint& remote) {
    if (data.size() < kRelayHeaderSize) {
        spdlog::warn("[{}] relay packet too short ({} bytes)", name(), data.size());
        return;
    }

    RelayPacketHeader header;
    std::memcpy(&header, data.data(), sizeof(header));

    if (header.version != kRelayVersion) {
        spdlog::warn("[{}] unsupported relay version {}", name(), header.version);
        return;
    }

    const auto payload = data.subspan(kRelayHeaderSize);
    if (payload.size() < header.payload_length) {
        spdlog::warn("[{}] payload truncated: expected {} got {}",
                     name(), header.payload_length, payload.size());
        return;
    }

    switch (header.msg_type) {
        case RelayMsgType::Bind: {
            auto result = do_bind(header.session_id, remote);
            // Build a Bound response
            RelayPacketHeader resp_header{};
            resp_header.magic = kRelayMagic;
            resp_header.version = kRelayVersion;
            resp_header.msg_type = result.success ? RelayMsgType::Bound : RelayMsgType::Error;
            resp_header.session_id = header.session_id;
            resp_header.sequence_number = header.sequence_number;
            resp_header.payload_length = 0;

            asio::error_code ec;
            socket_.send_to(
                asio::buffer(&resp_header, sizeof(resp_header)), remote, 0, ec);
            if (ec) {
                spdlog::warn("[{}] failed to send Bound response: {}", name(), ec.message());
            }
            break;
        }

        case RelayMsgType::Data: {
            auto fwd_payload = payload.subspan(0, header.payload_length);
            (void)do_forward(header.session_id, fwd_payload, remote);
            break;
        }

        case RelayMsgType::Heartbeat: {
            // Echo back a HeartbeatAck
            RelayPacketHeader ack{};
            ack.magic = kRelayMagic;
            ack.version = kRelayVersion;
            ack.msg_type = RelayMsgType::HeartbeatAck;
            ack.session_id = header.session_id;
            ack.sequence_number = header.sequence_number;
            ack.payload_length = 0;

            asio::error_code ec;
            socket_.send_to(asio::buffer(&ack, sizeof(ack)), remote, 0, ec);
            break;
        }

        case RelayMsgType::Teardown: {
            do_teardown(header.session_id);
            break;
        }

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
    ttl_timer_.expires_after(std::chrono::seconds(30));
    ttl_timer_.async_wait([this](const asio::error_code& ec) {
        if (ec) return; // cancelled or error
        purge_expired_sessions();
        start_ttl_timer(); // reschedule
    });
}

void RelayService::purge_expired_sessions() {
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard lock(mutex_);

    std::size_t purged = 0;
    for (auto it = sessions_.begin(); it != sessions_.end(); ) {
        const auto& session = *it->second;
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(
            now - session.created_at).count();
        if (elapsed > session.ttl_seconds) {
            it = sessions_.erase(it);
            ++purged;
        } else {
            ++it;
        }
    }

    if (purged > 0) {
        spdlog::info("[{}] purged {} expired sessions ({} remaining)",
                     name(), purged, sessions_.size());
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

SessionId RelayService::generate_session_id() {
    SessionId id{};
    crypto_.random_bytes(std::span<uint8_t>(id));
    return id;
}

std::vector<uint8_t> RelayService::ticket_canonical_bytes(const RelayTicket& ticket) {
    // Canonical form: peer_id || relay_id || session_nonce || issued_at(8-LE) || expires_at(8-LE)
    std::vector<uint8_t> buf;
    buf.reserve(ticket.peer_id.size() + ticket.relay_id.size() + 16 + 8 + 8);

    buf.insert(buf.end(), ticket.peer_id.begin(), ticket.peer_id.end());
    buf.insert(buf.end(), ticket.relay_id.begin(), ticket.relay_id.end());
    buf.insert(buf.end(), ticket.session_nonce.begin(), ticket.session_nonce.end());

    auto push_u64_le = [&buf](uint64_t v) {
        for (int i = 0; i < 8; ++i) {
            buf.push_back(static_cast<uint8_t>(v & 0xFF));
            v >>= 8;
        }
    };
    push_u64_le(ticket.issued_at);
    push_u64_le(ticket.expires_at);

    return buf;
}

} // namespace nexus::relay
