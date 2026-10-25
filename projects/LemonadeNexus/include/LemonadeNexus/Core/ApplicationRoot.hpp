#pragma once

// Post-epoch application-root establishment. The public root-claim surface is
// closed; this is the deferred authority: when a server enters Tier 1 by
// finalized epoch membership (Tree/TreeRole.hpp), the permission root is
// created from the configured root management key. Only Tier 1 members hold
// the tree, so no other server creates a root. One-shot, idempotent, and
// never reachable by a caller.
//
// With tree operations on, the root is an EstablishRoot tree operation that
// Tier 1 commits through consensus instead (TreeConsensus::set_root_request);
// ensure_application_root is the direct path for the setting off.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeOps.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <optional>
#include <span>
#include <string>

namespace nexus::core {

/// The configured root management key as a tree principal
/// ("ed25519:<base64>"), or nullopt when `root_pubkey_hex` is not a 32-byte
/// Ed25519 key in hex. Never throws.
inline std::optional<std::string> root_principal_from_hex(const std::string& root_pubkey_hex) {
    // Validate before decoding: from_hex throws, and callers run on the io
    // thread.
    const bool well_formed =
        root_pubkey_hex.size() == 2 * crypto::kEd25519PublicKeySize &&
        std::all_of(root_pubkey_hex.begin(), root_pubkey_hex.end(),
                    [](unsigned char c) { return std::isxdigit(c) != 0; });
    if (!well_formed) return std::nullopt;
    const auto bytes = crypto::from_hex(root_pubkey_hex);
    return "ed25519:" + crypto::to_base64(std::span<const uint8_t>(bytes.data(), bytes.size()));
}

/// Create the application root owned by `root_pubkey_hex` (the configured
/// root management key) unless a root already exists. Returns true only when
/// this call created it. An empty or malformed key establishes nothing:
/// /api/join keeps refusing with 409, never a default owner.
inline bool ensure_application_root(tree::PermissionTreeService& tree,
                                    const std::string& root_pubkey_hex) {
    if (tree.get_node("root")) return false;
    const auto root_key = root_principal_from_hex(root_pubkey_hex);
    if (!root_key) {
        spdlog::warn("[tree] application root not established: root_pubkey is "
                     "not a 32-byte Ed25519 hex key");
        return false;
    }
    return tree.bootstrap_root(tree::make_root_node(*root_key));
}

}  // namespace nexus::core
