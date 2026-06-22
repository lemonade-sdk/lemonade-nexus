#pragma once

#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Tree/ITreeProvider.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>

#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace nexus::tree {

/// Manages the hierarchical permission tree.
/// Nodes are cached in-memory and persisted via FileStorageService.
/// Signatures are verified through SodiumCryptoService.
class PermissionTreeService : public core::IService<PermissionTreeService>,
                               public ITreeProvider<PermissionTreeService> {
    friend class core::IService<PermissionTreeService>;
    friend class ITreeProvider<PermissionTreeService>;

public:
    PermissionTreeService(storage::FileStorageService& storage,
                           crypto::SodiumCryptoService& crypto);

    /// Bootstrap the root node if none exists.  Called during join when
    /// the tree is empty — the first authenticated user becomes root.
    /// Returns true if created, false if root already exists.
    bool bootstrap_root(const TreeNode& root_node);

    /// Insert a node directly during the join flow.
    /// Bypasses the strict delta permission/signature checks because
    /// the join handler has already authenticated the caller.
    /// Returns true on success.
    bool insert_join_node(const TreeNode& node);

    /// Update a node directly, bypassing delta signing.
    /// The caller (HTTP handler) is responsible for permission checks.
    bool update_node_direct(const std::string& node_id, const TreeNode& updated);

    /// Atomically update only the listen_endpoint field of a node.
    /// Reads the current node, sets listen_endpoint, and persists — all under
    /// a single lock.  This avoids the TOCTOU race of read → modify → write.
    bool update_node_endpoint(const std::string& node_id,
                               const std::string& new_endpoint);

    /// Delete a node directly, bypassing delta signing.
    /// The caller (HTTP handler) is responsible for permission checks.
    bool delete_node_direct(const std::string& node_id);

    /// Grant an assignment (pubkey + permissions) on a node.
    /// Idempotent: no-op if the pubkey already has an assignment.
    /// Used after Ed25519 key registration to give new keys add_child on root.
    bool grant_assignment(const std::string& node_id, const Assignment& assignment);

    // --- Endpoint identifier resolution (routing layer) ---

    /// Re-derive the canonical identifier from a node's inputs (pure).
    [[nodiscard]] std::string derive_endpoint_identifier(const TreeNode& node) const;

    /// True iff the stored endpoint_identifier matches the re-derived value.
    [[nodiscard]] bool validate_identifier_binding(const TreeNode& node) const;

    /// Resolve an endpoint identifier to its node via the reverse index.
    [[nodiscard]] std::optional<TreeNode> resolve_by_identifier(
            std::string_view identifier) const;

    /// Descendants beneath `root_parent_id` (excluding it). Own cycle guard +
    /// depth/node caps so a malformed parent_id loop can't wedge the tree.
    /// Callers MUST still filter per node — permissions are not inherited.
    [[nodiscard]] std::vector<TreeNode> collect_subtree(
            std::string_view root_parent_id,
            std::size_t max_depth = 32,
            std::size_t max_nodes = 4096) const;

    /// True iff `node_id` lies strictly beneath `ancestor_id`.
    [[nodiscard]] bool is_descendant_of(std::string_view node_id,
                                        std::string_view ancestor_id) const;

    /// Routing-layer authorization chokepoint. Returns the target node only if
    /// the identifier resolves, its binding validates, the target is within the
    /// caller's parent-group subtree, and the caller holds ConnectPrivate or
    /// ConnectShared on it; nullopt otherwise. caller_pubkey must be normalized.
    [[nodiscard]] std::optional<TreeNode> resolve_authorized(
            std::string_view caller_pubkey,
            std::string_view caller_node_id,
            std::string_view identifier) const;

    // IService
    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "PermissionTreeService"; }

    // ITreeProvider
    [[nodiscard]] bool do_apply_delta(const TreeDelta& delta);
    [[nodiscard]] std::optional<TreeNode> do_get_node(std::string_view node_id) const;
    [[nodiscard]] std::vector<TreeNode> do_get_children(std::string_view parent_id) const;
    [[nodiscard]] bool do_validate_signature_chain(std::string_view node_id) const;
    [[nodiscard]] bool do_check_permission(std::string_view signer_pubkey,
                                            std::string_view node_id,
                                            acl::Permission perm) const;
    [[nodiscard]] crypto::Hash256 do_get_tree_hash() const;
    [[nodiscard]] std::vector<TreeNode> do_get_nodes_by_type(NodeType type) const;

private:
    /// Persist a tree node to storage wrapped in a SignedEnvelope.
    bool persist_node(const TreeNode& node);

    /// Remove a tree node from storage.
    bool remove_node(std::string_view node_id);

    /// Map a permission string (from assignments) to an acl::Permission flag.
    [[nodiscard]] static acl::Permission string_to_permission(std::string_view perm_str);

    /// Evict stale entries from the replay cache.
    void evict_replay_cache();

    storage::FileStorageService& storage_;
    crypto::SodiumCryptoService& crypto_;
    mutable std::mutex           mutex_;
    std::unordered_map<std::string, TreeNode> nodes_;

    // Reverse index: endpoint_identifier -> node_id. Kept in sync with nodes_ in
    // on_start / insert_join_node / update_node_direct / delete_node_direct so
    // resolve_by_identifier is O(1) and new colliding registrations are rejected.
    std::unordered_map<std::string, std::string> identifier_index_;

    // Replay protection: SHA-256 hash of canonical delta → timestamp of receipt
    std::unordered_map<std::string, uint64_t> recent_deltas_;
};

} // namespace nexus::tree
