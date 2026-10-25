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

#include <array>
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

/// Why an administrative assignment change, an invite, or a move is refused.
/// Conflict: the change contradicts the current placement (for example, the
/// invitee already belongs to the group).
enum class AssignmentRefusal { NotFound, Forbidden, Invalid, Conflict };

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
///
/// One change needs no admin: a principal removes its own entry (empty
/// `permissions`, `signer` equals `principal`) from a group (Customer node)
/// that it has not joined, when that entry does not hold `admin`. This is how
/// a member leaves a group it entered through an invite.
[[nodiscard]] std::optional<AssignmentRuling> assignment_change_refusal(
        const NodeMap& nodes, std::string_view node_id, std::string_view signer,
        std::string_view principal, const std::vector<std::string>& permissions);

/// Replace every entry `principal` holds in `assignments` (matched by key
/// bytes) with one entry holding the sorted, de-duplicated `permissions`. An
/// empty list removes the principal. The new entry keeps the given spelling.
void replace_assignment(std::vector<Assignment>& assignments, std::string_view principal,
                        const std::vector<std::string>& permissions);

/// True when `principal` lacks `read` or `connect_private` on `node`
/// (signer_has_permission, so `admin` covers both).
[[nodiscard]] bool link_peer_access_missing(const TreeNode& node, std::string_view principal);

/// The pairwise grant between devices of one group after a linked join: make
/// `principal` hold `read` and `connect_private` on `node`. The missing names
/// are appended to the first entry whose key matches by bytes, or a new entry
/// {read, connect_private} is appended. Never removes or reduces a
/// permission. Returns true when `node` changed. Deterministic.
bool grant_link_peer_access(TreeNode& node, std::string_view principal);

/// True when `signer` holds `perm` through its entry on `node_id`, or holds
/// `admin` on the node or an ancestor (admin_anchor). This is the authority
/// an inviter or a mover needs on a node.
[[nodiscard]] bool holds_or_administers(const NodeMap& nodes, std::string_view node_id,
                                        std::string_view signer, acl::Permission perm);

// --- Invites (link tokens that target a group) ------------------------------

/// The permission names an invite may grant. `admin`, `edit_node`, and
/// `delete_node` are never granted by an invite, so an invite cannot give
/// control over the inviter's group.
inline constexpr std::array<std::string_view, 5> kInvitePermissions = {
    "read", "write", "add_child", "connect_private", "connect_shared"};

/// The permissions an invite carries when the inviter names none, reduced to
/// those the inviter holds (see the link token route).
inline constexpr std::array<std::string_view, 2> kDefaultInvitePermissions = {
    "read", "connect_private"};

/// The rules for an invite into `target_id` minted by `inviter` with
/// `permissions`: the target exists and is a group (Customer node); the
/// inviter holds add_child on it or administers it (holds_or_administers);
/// every permission name is in kInvitePermissions; and the inviter holds
/// each permission on the target or administers it, so an invite never grants
/// more than the inviter holds. An empty list is allowed: such an invite can
/// place a new device but cannot make a member. nullopt when the invite is
/// allowed.
[[nodiscard]] std::optional<AssignmentRuling> invite_refusal(
        const NodeMap& nodes, std::string_view target_id, std::string_view inviter,
        const std::vector<std::string>& permissions);

/// The rules for `invitee` accepting an invite into `target_id`: the
/// invite_refusal rules, evaluated against the current tree (an inviter that
/// lost its permission voids the invite); the permissions include `read`; the
/// invitee is a valid principal; and the invitee neither joined inside the
/// target (principal_joined_under) nor administers it, because a member entry
/// would replace that home entry. nullopt when accepting is allowed.
/// Accepting sets exactly `permissions` as the invitee's entry on the target
/// (replace_assignment) and changes no other node.
[[nodiscard]] std::optional<AssignmentRuling> invite_acceptance_refusal(
        const NodeMap& nodes, std::string_view target_id, std::string_view invitee,
        std::string_view inviter, const std::vector<std::string>& permissions);

// --- Group membership reach --------------------------------------------------

/// True when `member` holds a literal `connect_private` or `connect_shared`
/// entry on a group (Customer node) that is a strict ancestor of `node`. An
/// `admin` entry does not count, so a root or group admin gets no connect
/// reach from this rule. This is the connect reach an accepted invite gives.
[[nodiscard]] bool membership_reaches(const NodeMap& nodes, std::string_view member,
                                      const TreeNode& node);

/// The connect rule for endpoint `from`, acting as `principal`, to node `to`.
/// It allows the connection when either:
///  - home scope: `to` is beneath `from`'s parent group and `principal` holds
///    ConnectPrivate or ConnectShared on `to` itself (`admin` includes both); or
///  - membership: `principal` is `from`'s own management key, and either
///    membership_reaches(principal, to) (a member's device reaches the
///    group's devices) or membership_reaches(to.mgmt_pubkey, from) (the
///    group's devices reach a member's device).
/// Never true for a node to itself or for a `from` without a parent.
[[nodiscard]] bool endpoint_may_connect(const NodeMap& nodes, std::string_view principal,
                                        const TreeNode& from, const TreeNode& to);

// --- Moves -------------------------------------------------------------------

/// The rules for moving `node_id` under `new_parent_id` by `signer`: the node
/// and the new parent exist; the node is an Endpoint or a Customer group; a
/// top-level group (a Customer node whose parent is a Root node) never moves,
/// so no one moves another user's network out from under its owner; the new
/// parent is a Customer group, differs from the current parent, and is not the
/// node or one of its descendants; for an Endpoint the signer holds
/// delete_node on it or administers it, and for a group the signer administers
/// it (delete_node alone cannot take over a subtree); and the signer holds
/// add_child on the new parent or administers it. nullopt when the move is
/// allowed.
[[nodiscard]] std::optional<AssignmentRuling> move_refusal(const NodeMap& nodes,
                                                           std::string_view node_id,
                                                           std::string_view new_parent_id,
                                                           std::string_view signer);

}  // namespace nexus::tree::rules
