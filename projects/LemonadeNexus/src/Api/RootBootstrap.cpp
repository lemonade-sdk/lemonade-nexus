#include <LemonadeNexus/Api/RootBootstrap.hpp>

#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>

#include <spdlog/spdlog.h>

#include <string_view>

namespace nexus::api {

namespace {

constexpr const char* kRootId = "root";

const std::vector<std::string> kRootOwnerPermissions{
    "read", "write", "add_child", "delete_node", "edit_node", "admin"};

/// Canonical "ed25519:base64" form of the configured application owner, empty
/// when the configuration is missing or invalid. Deliberately distinct from
/// root_pubkey (the mesh trust anchor): the two must never be conflated.
std::string configured_owner(const core::ServerConfig& config) {
    try {
        auto bytes = crypto::from_hex(config.application_owner_pubkey);
        if (bytes.size() != crypto::kEd25519PublicKeySize) return {};
        return std::string("ed25519:") + crypto::to_base64(bytes);
    } catch (const std::exception&) {
        return {};
    }
}

}  // namespace

RootBootstrapOutcome bootstrap_root_for_owner(tree::PermissionTreeService& tree,
                                              const core::ServerConfig& config,
                                              const std::string& caller_pubkey) {
    const auto owner = configured_owner(config);
    if (owner.empty()) {
        spdlog::error("[root-bootstrap] refused: root_pubkey missing or invalid in "
                      "local config; the application root cannot be created");
        return RootBootstrapOutcome::OwnerNotConfigured;
    }

    // Normalize prefix and base64 spelling; undecodable input is returned
    // as-is by canonical_principal and therefore never matches.
    std::string pk = caller_pubkey;
    constexpr std::string_view prefix = "ed25519:";
    if (!pk.starts_with(prefix)) pk.insert(0, prefix);
    const auto caller = tree::canonical_principal(pk);
    if (caller != owner) {
        return RootBootstrapOutcome::NotOwner;
    }

    auto existing = tree.get_node(kRootId);
    if (existing) {
        if (tree::canonical_principal(existing->mgmt_pubkey) != owner) {
            // Established ownership by another key: report, never transfer.
            spdlog::error("[root-bootstrap] ownership conflict: existing root is owned "
                          "by a key other than the configured application owner; "
                          "no changes made");
            return RootBootstrapOutcome::OwnershipConflict;
        }
        // One-time bootstrap: the owner assignment was created with the root.
        // Login verification must not modify an existing root in any way.
        return RootBootstrapOutcome::OwnerRootExisting;
    }

    tree::TreeNode root_node;
    root_node.id          = kRootId;
    root_node.parent_id   = "";
    root_node.type        = tree::NodeType::Root;
    root_node.hostname    = kRootId;
    root_node.mgmt_pubkey = owner;
    root_node.assignments = {{.management_pubkey = owner,
                              .permissions = kRootOwnerPermissions}};

    if (tree.bootstrap_root(root_node)) {
        return RootBootstrapOutcome::OwnerRootCreated;
    }

    // Lost a concurrent bootstrap race (or persistence failed): re-verify
    // instead of assuming. Whoever won created the owner assignment; a loser
    // never modifies the root.
    existing = tree.get_node(kRootId);
    if (!existing) {
        spdlog::error("[root-bootstrap] bootstrap failed and no root node exists");
        return RootBootstrapOutcome::OwnershipConflict;
    }
    if (tree::canonical_principal(existing->mgmt_pubkey) != owner) {
        spdlog::error("[root-bootstrap] ownership conflict: existing root is owned "
                      "by a key other than the configured application owner; "
                      "no changes made");
        return RootBootstrapOutcome::OwnershipConflict;
    }
    return RootBootstrapOutcome::OwnerRootExisting;
}

}  // namespace nexus::api
