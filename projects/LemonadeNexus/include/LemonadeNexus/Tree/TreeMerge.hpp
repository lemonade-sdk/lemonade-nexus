#pragma once

// The tree merge ceremony (design A9).
//
// Before tree operations, each server kept its own tree. The ceremony exports
// every server's tree, unions the exports by a fixed rule, and commits the
// result as tree log height 1. The root management key signs that commit
// offline. Every server verifies the signature against its own configured
// root_pubkey before it applies the commit, so the commit carries authority
// only through that signature, never through the server that delivers it.
//
// Merge rule, per node id:
//   1. An admin resolution in the merge spec decides (a server's copy, or
//      "drop").
//   2. The root comes from the root server's export.
//   3. A node that one export holds, or that every holding export holds with
//      the same encoding, is taken as is.
//   4. A device (Endpoint) comes from the server it joined: the export whose
//      IPAM file records the device's tunnel allocation.
//   5. A group (Customer) comes from its creator's record: the export whose
//      delta log records the group's create_node delta.
//   6. Anything else is a conflict for an admin to resolve.
// After selection, a node whose parent is not in the merged tree, and two
// nodes that share an endpoint identifier, mesh key, or tunnel address, are
// conflicts too. The tool writes a commit only when no conflict remains.
//
// The merge commit is the only height-1 entry that does not come from
// consensus. A log accepts it only on top of the empty base (height 0, empty
// tree), so it is one-shot: no later entry can replace the tree wholesale.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>
#include <LemonadeNexus/Tree/TreeLog.hpp>
#include <LemonadeNexus/Tree/TreeRules.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>

#include <nlohmann/json.hpp>

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::crypto { class SodiumCryptoService; }

namespace nexus::tree {

/// Domain of the merge body digest (the merge entry's ops digest).
inline constexpr std::string_view kTreeMergeBodyDomain = "lemonade-nexus/tree-merge-body:v1";
/// The "type" field of the signed merge preimage and of a tree export.
inline constexpr std::string_view kTreeMergePreimageType = "lemonade-nexus/tree-merge:v1";
inline constexpr std::string_view kTreeExportType = "lemonade-nexus/tree-export:v1";

/// Most nodes and most bytes in one merge body. Bounds are checked before any
/// allocation that depends on a claimed length.
inline constexpr std::size_t kMaxTreeMergeNodes = 100'000;
inline constexpr std::size_t kMaxTreeMergeBodyBytes = 12u * 1024u * 1024u;

// --- Merge body and commit ---------------------------------------------------

/// Canonical merge body: u32 node count, then for each node in id order a u32
/// length and encode_tree_node. Little-endian. nullopt when the tree exceeds
/// either bound.
[[nodiscard]] std::optional<std::vector<uint8_t>> encode_merge_body(const rules::NodeMap& nodes);

/// Parse a merge body. nullopt unless the bytes are exactly what
/// encode_merge_body produces for the decoded nodes (ids strictly increasing,
/// every node canonical, no trailing bytes).
[[nodiscard]] std::optional<rules::NodeMap> decode_merge_body(std::span<const uint8_t> body);

/// The merge entry's ops digest: CanonicalEncoder(kTreeMergeBodyDomain) over
/// the body bytes. Domain-separated from every consensus payload digest.
[[nodiscard]] security::Digest merge_body_digest(std::span<const uint8_t> body);

/// The exact bytes the root management key signs for `entry` on network
/// `network_id`: canonical JSON (sorted keys, no whitespace) with the type,
/// network id (hex), height, block time, previous root, merge digest, tree
/// digest, state root (base64), and node count. Human-readable, so the signer
/// can check what it signs.
[[nodiscard]] std::string merge_preimage(const TreeLogEntry& entry,
                                         const security::NetworkId& network_id,
                                         std::size_t node_count);

/// The unsigned height-1 merge entry for `nodes` at `block_time_ms` (Unix
/// milliseconds), with the roots computed on top of the empty base and
/// `commit` naming the network and the signer `root_key`
/// ("ed25519:<base64>"). nullopt when the body exceeds a bound.
[[nodiscard]] std::optional<TreeLogEntry> build_merge_entry(const rules::NodeMap& nodes,
                                                            uint64_t block_time_ms,
                                                            const security::NetworkId& network_id,
                                                            const std::string& root_key);

/// `entry` with the root management key's signature (64 raw bytes) attached.
[[nodiscard]] TreeLogEntry attach_merge_signature(TreeLogEntry entry,
                                                  const crypto::Ed25519Signature& signature);

/// Why a merge entry is not authorized, or nullopt when it is: kind Merge at
/// height 1, the commit names `network_id` and a signer whose key bytes equal
/// `root_key` ("ed25519:<base64>"), the body decodes to the recorded node
/// count, and the signature verifies over merge_preimage. An empty or
/// malformed `root_key` refuses every entry. replay_entry checks the roots.
[[nodiscard]] std::optional<std::string> verify_merge_signature(
    crypto::SodiumCryptoService& crypto, const TreeLogEntry& entry,
    const security::NetworkId& network_id, const std::string& root_key);

// --- Exports and the merge rule ----------------------------------------------

/// One server's tree as the export step read it.
struct TreeExport {
    std::string server;            ///< operator label, unique per ceremony
    bool root_server = false;      ///< holds the root management key
    std::vector<TreeNode> nodes;
    /// Endpoint ids whose tunnel allocation this server's IPAM file records.
    std::set<std::string> joined_here;
    /// Node ids whose create_node delta this server's delta log records.
    std::set<std::string> created_here;
};

[[nodiscard]] nlohmann::json tree_export_to_json(const TreeExport& exported);
/// nullopt on a wrong type or format, a malformed field, or a repeated node id.
[[nodiscard]] std::optional<TreeExport> tree_export_from_json(const nlohmann::json& doc);

/// One problem the merge rule could not decide.
struct MergeConflict {
    std::string node_id;
    /// root_missing, divergent, orphan, duplicate_identifier,
    /// duplicate_mesh_key, duplicate_tunnel_address, bad_resolution, or
    /// bad_exports.
    std::string kind;
    std::string detail;
    std::vector<std::string> servers;  ///< servers involved, sorted
};

struct MergeResult {
    rules::NodeMap nodes;
    std::vector<MergeConflict> conflicts;  ///< sorted by node id, then kind
    /// How each node was decided ("<node id>: <rule> from <server>"), sorted.
    std::vector<std::string> decisions;
};

/// Union `exports` by the merge rule. `resolutions` maps a node id to a server
/// label (take that server's copy) or "drop". Deterministic: the order of
/// `exports` does not change the result.
[[nodiscard]] MergeResult merge_tree_exports(const std::vector<TreeExport>& exports,
                                             const std::map<std::string, std::string>& resolutions);

[[nodiscard]] nlohmann::json merge_conflicts_to_json(const std::vector<MergeConflict>& conflicts);

}  // namespace nexus::tree
