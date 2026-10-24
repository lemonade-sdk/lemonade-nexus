#pragma once

// Wires the server's state into the update control socket
// (Update/UpdateControl.hpp). Reads go to the thread that owns each value:
// security state on the security io thread, the vault and the tree log
// through their thread-safe accessors.

#include <LemonadeNexus/Core/BootChainStaging.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>
#include <LemonadeNexus/Update/UpdateControl.hpp>

#include <atomic>
#include <string>

namespace nexus::security {
class SecurityMeshService;
class StorageVault;
}  // namespace nexus::security

namespace nexus::tree {
class TreeConsensus;
}  // namespace nexus::tree

namespace nexus::core {

struct UpdateStatusSources {
    /// Not owning; nullptr when the security mesh is not running. Must
    /// outlive the socket.
    security::SecurityMeshService* mesh{nullptr};
    security::NodeId self{};
    /// Not owning; nullptr when this server keeps no files under a data key.
    const security::StorageVault* vault{nullptr};
    /// Set once the tree log starts; nullptr while it is off. Not owning.
    const std::atomic<tree::TreeConsensus*>* tree{nullptr};
    std::string release_id;
    std::string approval_digest_hex;
};

/// Handlers for the update control socket. The turn gate and the report go
/// to `gate`, which must outlive the handlers.
[[nodiscard]] update::UpdateControlHandlers make_update_control_handlers(
    UpdateStatusSources sources, BootChainStagingInputs staging,
    update::RefusingTurnGate& gate);

}  // namespace nexus::core
