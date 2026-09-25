#pragma once

// The security mesh is not optional in normal daemon operation. This is the
// one place that turns a loaded config into a running SecurityMeshService.

#include <LemonadeNexus/Security/Attestation/PlatformEvidenceProducer.hpp>

#include <asio.hpp>

#include <memory>
#include <optional>
#include <string>

namespace nexus::crypto { class KeyWrappingService; }
namespace nexus::gossip { class GossipService; }
namespace nexus::security { class SecurityMeshService; }
namespace nexus::core   { struct ServerConfig; }

namespace nexus::core {

struct SecurityMeshStartup {
    std::unique_ptr<security::SecurityMeshService> service;
    /// Hex network id the pinned anchor derives; certificate issuance binds to it.
    std::string network_id_hex;
};

/// Decode the pinned Genesis anchor, derive the network it names, gate gossip
/// on that network id, and start the SecurityMeshService. nullopt with
/// `error` set when the anchor is malformed.
[[nodiscard]] std::optional<SecurityMeshStartup> start_security_mesh(
    asio::io_context& io,
    const ServerConfig& config,
    gossip::GossipService& gossip,
    crypto::KeyWrappingService& key_wrapping,
    security::PlatformEvidenceSource platform_source,
    std::string& error);

}  // namespace nexus::core
