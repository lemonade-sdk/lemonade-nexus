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

    // Replay protection: SHA-256 hash of canonical delta → timestamp of receipt
    std::unordered_map<std::string, uint64_t> recent_deltas_;
};

} // namespace nexus::tree
