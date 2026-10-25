#pragma once

// Authorization and content rules for tree writes, as pure functions of a node
// map. PermissionTreeService (delta and assignment paths) and validate_op
// (TreeOps.hpp) share these functions, so both paths enforce one rule set.
//
// Every function here is deterministic: the result depends only on its
// arguments, never on a clock, on local observations, or on the iteration
// order of the node map.

#include <LemonadeNexus/ACL/Permission.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace nexus::tree::rules {

/// The tree's node records, keyed by node id.
using NodeMap = std::unordered_map<std::string, TreeNode>;

/// Map an assignment permission name ("read", "admin", ...) to its flag.
/// Unknown names map to acl::Permission::None.
[[nodiscard]] acl::Permission permission_from_string(std::string_view perm_str);

/// The permission a delta operation requires. None for unknown operations.
[[nodiscard]] acl::Permission required_permission_for(std::string_view operation);

/// True when `signer_pubkey` holds a permission that implies `required` through
/// an assignment on `node`. Principals compare by key bytes
/// (canonical_principal), not by base64 spelling.
[[nodiscard]] bool signer_has_permission(const TreeNode& node,
                                         std::string_view signer_pubkey,
                                         acl::Permission required);

/// The nearest node, starting at `node_id` and walking up the parent chain, on
/// which the signer holds `admin`. nullopt when there is none. This anchor
/// bounds what the signer may administer: the anchor and its subtree. A parent
/// loop ends the walk unmatched.
[[nodiscard]] std::optional<std::string> admin_anchor(const NodeMap& nodes,
                                                      std::string_view node_id,
                                                      std::string_view signer_pubkey);

/// True when the signer holds `admin` on the top of the tree that holds
/// `node_id`: the node reached by walking up the parent chain to a node with
/// no parent (the root). False when the walk leaves the map or loops.
[[nodiscard]] bool administers_root(const NodeMap& nodes, std::string_view node_id,
                                    std::string_view signer_pubkey);

/// True when `principal` is the management key of a node at or beneath
/// `scope_id`: a joined identity, not an arbitrary key.
[[nodiscard]] bool principal_joined_under(const NodeMap& nodes,
                                          std::string_view scope_id,
                                          std::string_view principal);

/// True when a node other than `own_id` already stores exactly this mesh public
/// key. An empty key is never taken. This keeps the one-key-one-node invariant.
[[nodiscard]] bool mesh_pubkey_taken(const NodeMap& nodes,
                                     const std::string& mesh_pubkey,
                                     const std::string& own_id);

/// Content rules a delta must satisfy beyond the operation permission:
/// an update keeps the node's identity (id, parent, type, management key,
/// endpoint identifier); only an admin of the node or an ancestor changes
/// assignments, and only for joined identities in that admin's subtree;
/// only a root admin (administers_root) creates a Relay node or sets or
/// changes `tunnel_ip` or `private_subnet`, because these act on the whole
/// tunnel plane (the server assigns them for every other writer, including a
/// group admin); a create names no one but the signer unless the signer administers the
/// parent; the root is never created or deleted. Returns the refusal
/// reason, or nullopt when the delta is acceptable.
[[nodiscard]] std::optional<std::string> delta_content_refusal(const NodeMap& nodes,
                                                               const TreeDelta& delta);

/// Why an administrative assignment change is refused.
enum class AssignmentRefusal { NotFound, Forbidden, Invalid };

/// A refused assignment change and the reason text returned to the caller.
struct AssignmentRuling {
    AssignmentRefusal refusal;
    std::string       reason;
};

/// The rules for setting exactly the permissions `principal` holds on
/// `node_id`: the node exists; the principal and every permission name are
/// valid; `signer` holds `admin` on the node or an ancestor; a signer cannot
/// change its own entry on the node that grants its admin; and a principal
/// given any permission has joined inside that admin's subtree. nullopt when
/// the change is allowed. The checks run in this order, so the first failing
/// rule decides the reason.
[[nodiscard]] std::optional<AssignmentRuling> assignment_change_refusal(
        const NodeMap& nodes, std::string_view node_id, std::string_view signer,
        std::string_view principal, const std::vector<std::string>& permissions);

/// Replace every entry `principal` holds in `assignments` (matched by key
/// bytes) with one entry holding the sorted, de-duplicated `permissions`. An
/// empty list removes the principal. The new entry keeps the given spelling.
void replace_assignment(std::vector<Assignment>& assignments, std::string_view principal,
                        const std::vector<std::string>& permissions);

}  // namespace nexus::tree::rules
