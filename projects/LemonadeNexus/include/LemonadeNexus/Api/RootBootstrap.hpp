#pragma once

#include <string>

namespace nexus::core  { struct ServerConfig; }
namespace nexus::tree  { class PermissionTreeService; }

namespace nexus::api {

/// Result of attempting to establish or verify application-root ownership.
enum class RootBootstrapOutcome {
    OwnerRootCreated,    // caller is the configured owner; the root was created by this call
    OwnerRootExisting,   // caller is the configured owner; the root already exists and matches
    NotOwner,            // caller authenticated but is not the configured owner; no changes made
    OwnerNotConfigured,  // root_pubkey missing or invalid in local config; root creation refused
    OwnershipConflict,   // an existing root is owned by a key other than the configured owner
};

/// Establish or verify application-root ownership for `caller_pubkey`, whose
/// Ed25519 proof of possession was already completed through the normal
/// authentication flow. Ownership is bound to the locally configured owner
/// key (ServerConfig::root_pubkey, hex Ed25519). `caller_pubkey` is base64
/// with an optional "ed25519:" prefix; both are normalized before comparison.
///
/// Guarantees:
///  - No root is created unless the caller is the configured owner.
///  - Non-owner callers receive no root claim or automatic grants.
///  - An existing root owned by another key is never transferred, rewritten,
///    or stripped of assignments; the conflict is logged and reported.
///  - Repeated owner calls are idempotent (the owner assignment is
///    re-granted only when missing).
[[nodiscard]] RootBootstrapOutcome bootstrap_root_for_owner(
    tree::PermissionTreeService& tree,
    const core::ServerConfig& config,
    const std::string& caller_pubkey);

}  // namespace nexus::api
