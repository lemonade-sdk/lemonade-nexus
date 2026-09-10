#pragma once

// The boundary between the security protocol and the mesh transport.
//
// The transport authenticates the sending peer, applies the byte bound, and
// delivers the envelope bytes. It never parses the envelope beyond its size
// and never relays a security message on its own: the security layer decides
// every fan-out, so no transport path can amplify or reorder protocol truth.

#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <span>

namespace nexus::security {

class ISecurityTransport {
public:
    virtual ~ISecurityTransport() = default;

    /// Delivers one envelope to one peer. Returns false when the peer is
    /// unknown or the bytes exceed the transport bound.
    [[nodiscard]] virtual bool send_to(const NodeId& peer, std::span<const uint8_t> envelope) = 0;

    /// Delivers one envelope to every connected peer. Returns the number of
    /// peers the envelope was sent to.
    virtual std::size_t broadcast(std::span<const uint8_t> envelope) = 0;
};

/// Inbound delivery: the transport passes the peer it authenticated (the
/// packet signer) and the raw envelope bytes. The security layer binds the
/// envelope sender to this identity before any other work.
using SecuritySink = std::function<void(const NodeId& authenticated_sender,
                                        std::span<const uint8_t> envelope)>;

}  // namespace nexus::security
