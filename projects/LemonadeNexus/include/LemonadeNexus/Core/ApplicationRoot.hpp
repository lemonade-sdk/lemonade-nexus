#pragma once

// Post-epoch application-root establishment. The public root-claim surface is
// closed; this is the deferred authority: once a node first holds finalized
// epoch authority, the permission root is created from the configured root
// management key. One-shot, idempotent, and never reachable by a caller.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>

#include <spdlog/spdlog.h>

#include <span>
#include <string>

namespace nexus::core {

/// Create the application root owned by `root_pubkey_hex` (the configured
/// root management key) unless a root already exists. Returns true only when
/// this call created it. An empty or malformed key establishes nothing:
/// /api/join keeps refusing with 409, never a default owner.
inline bool ensure_application_root(tree::PermissionTreeService& tree,
                                    const std::string& root_pubkey_hex) {
    if (tree.get_node("root")) return false;
    const auto bytes = crypto::from_hex(root_pubkey_hex);
    if (bytes.size() != crypto::kEd25519PublicKeySize) {
        spdlog::warn("[tree] application root not established: root_pubkey is "
                     "not a 32-byte Ed25519 hex key");
        return false;
    }
    tree::TreeNode root;
    root.id          = "root";
    root.parent_id   = "";
    root.type        = tree::NodeType::Root;
    root.hostname    = "root";
    root.mgmt_pubkey = "ed25519:" +
        crypto::to_base64(std::span<const uint8_t>(bytes.data(), bytes.size()));
    root.assignments = {{.management_pubkey = root.mgmt_pubkey,
                         .permissions = {"read", "write", "add_child",
                                         "delete_node", "edit_node", "admin"}}};
    return tree.bootstrap_root(root);
}

}  // namespace nexus::core
