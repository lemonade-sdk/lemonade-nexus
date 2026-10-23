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

/// Storage inputs of the mesh. The threshold storage key always runs; the
/// vault is nullptr when this server keeps no files under a data key.
struct SecurityMeshStorageInputs {
    /// The boot set's seal backend; empty when this build or host cannot seal.
    security::SealBackend seal_backend;
    /// Files under the data key (Phase 7), or nullptr. Not owning; must
    /// outlive the returned service.
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

/// Runs `io` until `vault` reports files_ready() (the data key is in memory)
/// or `stop()` returns true, and returns files_ready(). Only the handlers
/// already on `io` run meanwhile: gossip, attestation, the security mesh, and
/// holder duties (B8). Nothing that needs the files is constructed yet, so
/// nothing is served. Call before Coordinator::run(); `io` is restarted
/// before return so it can run again.
[[nodiscard]] bool wait_for_storage_unlock(asio::io_context& io,
                                           const security::StorageVault& vault,
                                           const std::function<bool()>& stop);

}  // namespace nexus::core
