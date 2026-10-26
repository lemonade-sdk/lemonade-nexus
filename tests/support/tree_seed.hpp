#pragma once

// Test fixtures put nodes into a PermissionTreeService through replace_all,
// the path the tree log uses to restore committed state. A server changes its
// tree only through committed tree operations; these helpers stand in for a
// log that already committed the nodes a test starts from.

#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeOps.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>

#include <string>
#include <vector>

namespace test_support {

/// Add `node`, or replace the node with its id. False when a write failed.
inline bool put_node(nexus::tree::PermissionTreeService& tree, const nexus::tree::TreeNode& node) {
    auto nodes = tree.nodes_snapshot();
    nodes[node.id] = node;
    return tree.replace_all(nodes, tree.committed_ids());
}

/// Add every node in `nodes`, replacing nodes with the same ids.
inline bool put_nodes(nexus::tree::PermissionTreeService& tree,
                      const std::vector<nexus::tree::TreeNode>& nodes) {
    auto all = tree.nodes_snapshot();
    for (const auto& node : nodes) all[node.id] = node;
    return tree.replace_all(all, tree.committed_ids());
}

/// Remove the node `id`. False when it is absent or a write failed.
inline bool remove_node(nexus::tree::PermissionTreeService& tree, const std::string& id) {
    auto nodes = tree.nodes_snapshot();
    if (nodes.erase(id) == 0) return false;
    return tree.replace_all(nodes, tree.committed_ids());
}

/// Put the application root owned by `root_principal` ("ed25519:<base64>"),
/// as an EstablishRoot op would create it, unless a root exists. True when
/// this call created it.
inline bool put_root(nexus::tree::PermissionTreeService& tree, const std::string& root_principal) {
    if (tree.get_node("root")) return false;
    return put_node(tree, nexus::tree::make_root_node(root_principal));
}

}  // namespace test_support
