#pragma once

#include <LemonadeNexus/Relay/RelayTypes.hpp>

#include <asio.hpp>

#include <concepts>
#include <span>

namespace nexus::relay {

/// CRTP base for relay-forwarding operations.
/// Derived must implement:
///   RelayAllocation do_allocate(const RelayTicket& ticket)
///   RelayBindResult do_bind(const SessionId& session_id,
///                           const asio::ip::udp::endpoint& peer_endpoint)
///   bool do_forward(const SessionId& session_id,
///                   std::span<const uint8_t> data,
///                   const asio::ip::udp::endpoint& from)
///   void do_teardown(const SessionId& session_id)
///   bool do_verify_ticket(const RelayTicket& ticket) const
template <typename Derived>
class IRelayProvider {
public:
    /// Allocate a relay session for the given ticket.
    [[nodiscard]] RelayAllocation allocate(const RelayTicket& ticket) {
        return self().do_allocate(ticket);
    }

    /// Bind a peer endpoint to an existing session.
    [[nodiscard]] RelayBindResult bind(const SessionId& session_id,
                                       const asio::ip::udp::endpoint& peer_endpoint) {
        return self().do_bind(session_id, peer_endpoint);
    }

    /// Forward data within a session from the given source endpoint.
    [[nodiscard]] bool forward(const SessionId& session_id,
                               std::span<const uint8_t> data,
                               const asio::ip::udp::endpoint& from) {
        return self().do_forward(session_id, data, from);
    }

    /// Tear down a relay session.
    void teardown(const SessionId& session_id) {
        self().do_teardown(session_id);
    }

    /// Verify a relay ticket's Ed25519 signature.
    [[nodiscard]] bool verify_ticket(const RelayTicket& ticket) const {
        return self().do_verify_ticket(ticket);
    }

protected:
    ~IRelayProvider() = default;

private:
    [[nodiscard]] Derived& self() { return static_cast<Derived&>(*this); }
    [[nodiscard]] const Derived& self() const { return static_cast<const Derived&>(*this); }
};

/// Concept constraining a valid IRelayProvider implementation.
template <typename T>
concept RelayProviderType = requires(T t, const T ct,
                                      const RelayTicket& ticket,
                                      const SessionId& sid,
                                      const asio::ip::udp::endpoint& ep,
                                      std::span<const uint8_t> data) {
    { t.do_allocate(ticket) } -> std::same_as<RelayAllocation>;
    { t.do_bind(sid, ep) } -> std::same_as<RelayBindResult>;
    { t.do_forward(sid, data, ep) } -> std::same_as<bool>;
    { t.do_teardown(sid) } -> std::same_as<void>;
    { ct.do_verify_ticket(ticket) } -> std::same_as<bool>;
};

} // namespace nexus::relay
