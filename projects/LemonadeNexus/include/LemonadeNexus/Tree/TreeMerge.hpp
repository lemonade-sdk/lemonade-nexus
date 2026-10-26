#pragma once

// The tree merge (design A9): the one-time migration from per-server trees to
// the tree log.
//
// Before tree operations, each server kept its own tree. The merge collects
// every server's tree as a signed export, unions the exports by a fixed rule,
// and commits the result as tree log height 1. The root management key signs
// that commit. Every server verifies the signature against its own configured
// root_pubkey before it applies the commit, so the commit carries authority
// only through that signature, never through the server that delivers it.
// docs/Tree-Merge-Ceremony.md is the runbook.
//
// Merge rule, per node id. The first rule that decides wins:
//   1. An operator resolution in the merge spec decides (a server's copy, or
//      "drop"). The supported migration passes none.
//   2. The root comes from the root server's export, when it holds one.
//   3. A node that one export holds, or that every holding export holds with
//      the same encoding, is taken as is.
//   4. A device (Endpoint) comes from the server it joined: the export whose
//      IPAM file records the device's tunnel allocation.
//   5. A group (Customer) comes from its creator's record: the export whose
//      delta log records the group's create_node delta.
//   6. Tie-break, among the copies with rule 4 or 5 evidence when two or more
//      have it, else among all copies: the highest version; then the copy
//      that the most exports hold with the same encoding; then the root
//      server's copy; then the copy whose encoding is first in byte order.
// Then, on the selected nodes:
//   7. Two nodes that share an endpoint identifier, a mesh key, or a tunnel
//      address: the root is kept; otherwise the node whose join an export
//      records, then the node the most exports hold, then the smallest id is
//      kept, and every other holder is dropped. The fields are checked in that
//      order.
//   8. Every node that does not reach the root through its parents (a missing
//      parent, a dropped parent, or a cycle) is dropped.
// Rules 1 to 8 always decide. The merge refuses to produce a commit only for
// malformed input: repeated server labels, more than one root server export,
// a bad resolution, or no root in any export. Every tie-break and
// every drop is reported, so the operator reviews them before signing.
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
namespace nexus::ipam { class IPAMService; }
namespace nexus::storage { class FileStorageService; }

namespace nexus::tree {

/// Domain of the merge body digest (the merge entry's ops digest).
inline constexpr std::string_view kTreeMergeBodyDomain = "lemonade-nexus/tree-merge-body:v1";
/// The "type" field of the signed merge preimage and of a tree export.
inline constexpr std::string_view kTreeMergePreimageType = "lemonade-nexus/tree-merge:v1";
inline constexpr std::string_view kTreeExportType = "lemonade-nexus/tree-export:v1";
/// Domain of a server's signature over its tree export.
inline constexpr std::string_view kTreeExportSignatureDomain =
    "lemonade-nexus/tree-export-signature:v1";
/// The "type" field of a root-signed tree export request.
inline constexpr std::string_view kTreeExportRequestType =
    "lemonade-nexus/tree-export-request:v1";
/// How far a tree export request's issue time may be from the receiver's
/// clock, in either direction.
inline constexpr uint64_t kTreeExportRequestWindowMs = 10ULL * 60 * 1000;

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

/// The export of a server's tree as it stands: every node in `nodes`, the
/// endpoints whose tunnel allocation `ipam` records with the node's tunnel
/// address (joined_here), and the nodes whose create_node delta the delta log
/// of `storage` records (created_here).
[[nodiscard]] TreeExport collect_tree_export(std::string server, bool root_server,
                                             const rules::NodeMap& nodes,
                                             const ipam::IPAMService& ipam,
                                             const storage::FileStorageService& storage);

/// `doc` (tree_export_to_json) bound to `network_id` and signed with
/// `keypair` (the exporting server's gossip identity): adds "network_id"
/// (hex) and "signer" ("ed25519:<base64>"), then "signature", the base64
/// Ed25519 signature over kTreeExportSignatureDomain, a newline, and the
/// canonical dump of the document without "signature".
[[nodiscard]] nlohmann::json sign_tree_export(crypto::SodiumCryptoService& crypto,
                                              nlohmann::json doc,
                                              const security::NetworkId& network_id,
                                              const crypto::Ed25519Keypair& keypair);

/// Why a signed export is refused, or nullopt when its signature verifies for
/// `network_id`. On success `signer` is the signer ("ed25519:<base64>").
/// Checks the signature only; tree_export_from_json checks the content.
[[nodiscard]] std::optional<std::string> verify_tree_export(crypto::SodiumCryptoService& crypto,
                                                            const nlohmann::json& doc,
                                                            const security::NetworkId& network_id,
                                                            std::string& signer);

/// The canonical text of a tree export request that the root management key
/// signs: the type, network id (hex), the target server ("ed25519:<base64>"
/// of its gossip identity), the issue time (Unix ms), and a nonce (hex).
[[nodiscard]] std::string tree_export_request(const security::NetworkId& network_id,
                                              const std::string& target, uint64_t issued_ms,
                                              const std::string& nonce_hex);

/// A verified tree export request.
struct TreeExportRequest {
    std::string nonce;
    uint64_t issued_ms = 0;
};

/// Check `body` = {"request": <tree_export_request text>, "signature":
/// <base64>} for the server `self` ("ed25519:<base64>"): the text is
/// canonical, has the request type, names `network_id` and `self`, was issued
/// within kTreeExportRequestWindowMs of `now_ms`, carries a 32-hex-digit
/// nonce, and is signed by `root_key` ("ed25519:<base64>"). On refusal
/// `refusal` says why and the result is nullopt. Replay inside the window is
/// the caller's check (TreeExportNonces).
[[nodiscard]] std::optional<TreeExportRequest> verify_tree_export_request(
    crypto::SodiumCryptoService& crypto, const nlohmann::json& body,
    const security::NetworkId& network_id, const std::string& root_key, const std::string& self,
    uint64_t now_ms, std::string& refusal);

/// The nonces of tree export requests served within the request window, so a
/// replayed request is refused. Bounded. Not thread-safe.
class TreeExportNonces {
public:
    /// True when `nonce` is new; records it until `issued_ms` leaves the
    /// window. False for a nonce already seen or when the record is full.
    [[nodiscard]] bool admit(const std::string& nonce, uint64_t issued_ms, uint64_t now_ms);

private:
    static constexpr std::size_t kMax = 1024;
    std::map<std::string, uint64_t> seen_;  // nonce -> issue time
};

/// One problem the merge rule cannot decide. The merge then produces no
/// commit.
struct MergeConflict {
    std::string node_id;
    /// root_missing, bad_resolution, or bad_exports.
    std::string kind;
    std::string detail;
    std::vector<std::string> servers;  ///< servers involved, sorted
};

/// One node the merge rule dropped (rules 7 and 8).
struct MergeDrop {
    std::string node_id;
    /// duplicate_identifier, duplicate_mesh_key, duplicate_tunnel_address,
    /// orphan, or unreachable.
    std::string reason;
    std::string detail;
    std::vector<std::string> servers;  ///< exports that hold the node, sorted
};

struct MergeResult {
    rules::NodeMap nodes;
    std::vector<MergeConflict> conflicts;  ///< sorted by node id, then kind
    std::vector<MergeDrop> dropped;        ///< sorted by node id
    /// How each node was decided ("<node id>: <rule> from <server>"), sorted.
    std::vector<std::string> decisions;
};

/// Union `exports` by the merge rule. `resolutions` maps a node id to a server
/// label (take that server's copy) or "drop". Deterministic: the order of
/// `exports` does not change the result.
[[nodiscard]] MergeResult merge_tree_exports(const std::vector<TreeExport>& exports,
                                             const std::map<std::string, std::string>& resolutions);

[[nodiscard]] nlohmann::json merge_conflicts_to_json(const std::vector<MergeConflict>& conflicts);

/// A review of `result` against each export: the node count, decisions,
/// drops, conflicts, and per server label the node ids the merge adds to,
/// removes from, and changes in that server's tree.
[[nodiscard]] nlohmann::json merge_report(const std::vector<TreeExport>& exports,
                                          const MergeResult& result);

// --- The supported migration (signed exports) --------------------------------

/// The facts a signed merge is checked against. The root holder's server
/// supplies them from its finalized membership and configuration.
struct SignedMergeInput {
    security::NetworkId network_id{};
    /// The configured root management key ("ed25519:<base64>").
    std::string root_key;
    /// The gossip identity of the server that holds the root key
    /// ("ed25519:<base64>"): the only signer of the root server export.
    std::string root_signer;
    /// The current Tier 1 members by finalized membership ("ed25519:<base64>").
    std::vector<std::string> members;
    /// The merge commit's block time (Unix ms).
    uint64_t block_time_ms = 0;
};

struct SignedMergeBuild {
    /// Non-empty when the exports are refused (a signature, the signer set, or
    /// the content); nothing else is set then.
    std::string refusal;
    std::vector<TreeExport> exports;
    MergeResult result;
    /// The unsigned height-1 entry, set only when no conflict remains.
    std::optional<TreeLogEntry> entry;
    /// The exact bytes the root management key signs for `entry`.
    std::string preimage;
    /// merge_report, plus "signers" (label -> signer), and "tree_digest",
    /// "state_root", and "block_time_ms" when `entry` is set.
    nlohmann::json report;
};

/// Check and merge signed exports (sign_tree_export) for the supported
/// migration: every export verifies for the network; the signers are exactly
/// the members, each once, so no current Tier 1 tree is left out, plus at most
/// one export by the root signer; the export marked root_server is the root
/// signer's, and only it. Without an export by the root signer (no backup),
/// the root server's copy of the root is make_root_node(root_key). Then
/// merge_tree_exports without resolutions, and build the entry when no
/// conflict remains.
[[nodiscard]] SignedMergeBuild build_signed_merge(crypto::SodiumCryptoService& crypto,
                                                  const std::vector<nlohmann::json>& docs,
                                                  const SignedMergeInput& input);

}  // namespace nexus::tree
