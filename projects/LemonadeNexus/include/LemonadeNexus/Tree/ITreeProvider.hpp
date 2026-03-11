#pragma once

#include <LemonadeNexus/ACL/Permission.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>

#include <concepts>
#include <optional>
#include <string_view>
#include <vector>

namespace nexus::tree {

/// CRTP base for permission tree operations.
/// Derived must implement:
///   bool do_apply_delta(const TreeDelta& delta)
///   std::optional<TreeNode> do_get_node(std::string_view node_id) const
///   std::vector<TreeNode> do_get_children(std::string_view parent_id) const
///   bool do_validate_signature_chain(std::string_view node_id) const
///   bool do_check_permission(std::string_view signer_pubkey, std::string_view node_id, acl::Permission perm) const
///   crypto::Hash256 do_get_tree_hash() const
///   std::vector<TreeNode> do_get_nodes_by_type(NodeType type) const
template <typename Derived>
class ITreeProvider {
public:
    /// Validate and apply a signed delta to the tree.
    /// Returns true if the delta was valid and successfully applied.
    [[nodiscard]] bool apply_delta(const TreeDelta& delta) {
        return self().do_apply_delta(delta);
    }

    /// Retrieve a single node by ID.
    [[nodiscard]] std::optional<TreeNode> get_node(std::string_view node_id) const {
        return self().do_get_node(node_id);
    }

    /// Get all direct children of a node.
    [[nodiscard]] std::vector<TreeNode> get_children(std::string_view parent_id) const {
        return self().do_get_children(parent_id);
    }

    /// Verify the full signature chain from node up to root.
    [[nodiscard]] bool validate_signature_chain(std::string_view node_id) const {
        return self().do_validate_signature_chain(node_id);
    }

    /// Check whether a given signer has a specific permission on a node.
    [[nodiscard]] bool check_permission(std::string_view signer_pubkey,
                                         std::string_view node_id,
                                         acl::Permission perm) const {
        return self().do_check_permission(signer_pubkey, node_id, perm);
    }

    /// Compute a merkle-like hash of the entire tree (for gossip comparison).
    [[nodiscard]] crypto::Hash256 get_tree_hash() const {
        return self().do_get_tree_hash();
    }

    /// Get all nodes of a given type (e.g., all relays, all endpoints).
    [[nodiscard]] std::vector<TreeNode> get_nodes_by_type(NodeType type) const {
        return self().do_get_nodes_by_type(type);
    }

protected:
    ~ITreeProvider() = default;

private:
    [[nodiscard]] Derived& self() { return static_cast<Derived&>(*this); }
    [[nodiscard]] const Derived& self() const { return static_cast<const Derived&>(*this); }
};

/// Concept constraining a valid ITreeProvider implementation.
template <typename T>
concept TreeProviderType = requires(const T ct, T t,
                                     const TreeDelta& delta,
                                     std::string_view sv,
                                     acl::Permission perm,
                                     NodeType nt) {
    { t.do_apply_delta(delta) } -> std::same_as<bool>;
    { ct.do_get_node(sv) } -> std::same_as<std::optional<TreeNode>>;
    { ct.do_get_children(sv) } -> std::same_as<std::vector<TreeNode>>;
    { ct.do_validate_signature_chain(sv) } -> std::same_as<bool>;
    { ct.do_check_permission(sv, sv, perm) } -> std::same_as<bool>;
    { ct.do_get_tree_hash() } -> std::same_as<crypto::Hash256>;
    { ct.do_get_nodes_by_type(nt) } -> std::same_as<std::vector<TreeNode>>;
};

} // namespace nexus::tree
