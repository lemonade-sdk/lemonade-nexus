#pragma once

// The security mesh is not optional in normal daemon operation. This is the
// one place that turns a loaded config into a running SecurityMeshService.

#include <LemonadeNexus/Security/Attestation/PlatformEvidenceProducer.hpp>
#include <LemonadeNexus/Security/Sealing/SealedBlobStore.hpp>

#include <asio.hpp>

#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace nexus::crypto { class KeyWrappingService; }
namespace nexus::gossip { class GossipService; }
namespace nexus::security { class SecurityMeshService; class StorageVault; }
namespace nexus::core   { struct ServerConfig; }

namespace nexus::core {

struct SecurityMeshStartup {
    std::unique_ptr<security::SecurityMeshService> service;
    /// Hex network id the pinned anchor derives; certificate issuance binds to it.
    std::string network_id_hex;
    /// Present only after Genesis delegation and release signature verification.
    std::string release_signing_pubkey_b64;
    std::string release_approval_digest_hex;
};

/// Storage inputs of the mesh. Used only with storage_key_enabled.
struct SecurityMeshStorageInputs {
    /// The boot set's seal backend; empty when this build or host cannot seal.
    security::SealBackend seal_backend;
    /// Files under the data key (storage_files_enabled), or nullptr. Not
    /// owning; must outlive the returned service.
    security::StorageVault* vault = nullptr;
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
    security::PlatformActivationSource activation_source,
    std::string& error,
    std::function<void()> on_epoch_established = {},
    const SecurityMeshStorageInputs& storage = {});

}  // namespace nexus::core
