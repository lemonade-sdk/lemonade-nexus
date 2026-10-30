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
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace nexus::tree::rules {

/// The tree's node records, keyed by node id.
using NodeMap = std::unordered_map<std::string, TreeNode>;

/// Map an assignment permission name ("read", "admin", ...) to its flag.
/// Unknown names, including service permissions, map to acl::Permission::None.
[[nodiscard]] acl::Permission permission_from_string(std::string_view perm_str);

// --- Service permissions -----------------------------------------------------
//
// A service permission is a name of the form "svc:<family>". The tree stores
// and replicates it like any other assignment name and attaches no permission
// bit to it, so it grants no tree or connect right on the server. The device
// that a peer connects to reads it from the peer list (peer_permissions,
// below) and enforces it.

/// The prefix of a service permission name.
inline constexpr std::string_view kServicePermissionPrefix = "svc:";

/// The longest family a service permission name may carry, in bytes.
inline constexpr std::size_t kServicePermissionFamilyMax = 63;

/// True when `name` is a well-formed service permission: the prefix and a
/// family of 1 to kServicePermissionFamilyMax bytes, the first in [a-z0-9]
/// and the rest in [a-z0-9_.-].
[[nodiscard]] bool is_service_permission(std::string_view name);

/// True when an assignment may hold `name`: a name permission_from_string
/// knows, or a well-formed service permission. Every other name is refused.
[[nodiscard]] bool permission_name_known(std::string_view name);

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

// --- Device names ------------------------------------------------------------
//
// The mesh port names a device by device_label(hostname) (DeviceLabel.hpp),
// so two devices of one group whose names fold to the same label are one
// name there. A create or a rename that would make that so is refused; a
// collision that already exists in the tree stays as it is.

/// True when `node` is a device (Endpoint) under `parent_id`, other than
/// `own_id`, whose name folds to `label`. An empty label never collides.
[[nodiscard]] bool device_label_collides(const TreeNode& node, std::string_view parent_id,
                                         std::string_view label, std::string_view own_id);

/// Ids of the devices under `parent_id`, other than `own_id`, whose name
/// folds to `label`, sorted. Deterministic.
[[nodiscard]] std::vector<std::string> device_label_conflicts(const NodeMap& nodes,
                                                              std::string_view parent_id,
                                                              std::string_view label,
                                                              std::string_view own_id);

/// Why a device may not take the name `hostname`: a nonempty name folds to
/// an empty label, or `conflict` (the sibling device with the lowest id whose
/// name folds to the same label; nullptr when there is none) already holds
/// it. The reason names the conflicting device and asks for another name.
/// nullopt when the name is free. An empty `hostname` is an unnamed device:
/// it has no label, collides with nothing, and is never refused.
[[nodiscard]] std::optional<std::string> device_name_refusal(std::string_view hostname,
                                                             const TreeNode* conflict);

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
/// valid (permission_name_known); `signer` holds `admin` on the node or an
/// ancestor; a signer cannot change its own entry on the node that grants its
/// admin; and a principal given any permission has joined inside that admin's
/// subtree. nullopt when the change is allowed. The checks run in this order,
/// so the first failing rule decides the reason.
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

/// True when `principal` may remove `node_id` as its own device without
/// holding delete_node: the node is the device (Endpoint) that the key joined
/// as, and nothing lies beneath it. `joined_as` is the principal's join node
/// id (derive_join_node_id in TreeOps.hpp); the node must have that id and
/// the principal as its management key. A device that joined through an
/// invite holds no delete_node on its own node, and this rule lets it leave.
/// It never covers another node, a group, or a node with children, so it
/// only reduces the principal's own presence. Deterministic.
[[nodiscard]] bool removes_own_device(const NodeMap& nodes, std::string_view node_id,
                                      std::string_view principal, std::string_view joined_as);

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
/// every permission name is in kInvitePermissions or is a service permission
/// (is_service_permission); and the inviter holds each permission on the
/// target or administers it, so an invite never grants more than the inviter
/// holds. A service permission has no flag, so the inviter passes it on only
/// when its own entry on the target names it, or when it administers the
/// target. An empty list is allowed: such an invite can place a new device
/// but cannot make a member. nullopt when the invite is allowed.
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

/// True when `member` holds a literal `connect_private` or `connect_shared`
/// entry on group `group_id` itself or on a group above it: the devices placed
/// in `group_id` are then reachable through an accepted invite
/// (membership_reaches for a node placed directly in `group_id`).
[[nodiscard]] bool membership_covers(const NodeMap& nodes, std::string_view member,
                                     std::string_view group_id);

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

// --- Peer permissions --------------------------------------------------------

/// What one key holds toward one device (peer_permissions).
struct PeerPermissions {
    /// Every name in the key's entries on the device and on each strict
    /// ancestor group (Customer node), plus "admin" when `admin` is true.
    /// Sorted, de-duplicated.
    std::vector<std::string> names;
    /// True when the key holds `admin` on the device or on an ancestor
    /// (admin_anchor).
    bool admin = false;
};

/// The permission names `principal` holds toward `device`. This is the one
/// definition of service permission reach: a `svc:` name on a group applies
/// to every device beneath it (the shape of membership_reaches), and `admin`
/// on the device or above it implies every service permission. The mesh peer
/// list reports this set to the device as `peer_permissions`, so the device
/// can enforce service permissions without reading the group's entries.
///
/// The set reports; it grants nothing on the server. A plain name on an
/// ancestor group appears as it is held and gives `principal` no right on the
/// device beyond what the other rules give it. An empty or invalid principal
/// holds nothing. `device` need not be in `nodes`. Deterministic; a parent
/// loop or a missing ancestor ends the walk.
[[nodiscard]] PeerPermissions peer_permissions(const NodeMap& nodes, std::string_view principal,
                                               const TreeNode& device);

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

// --- Account deletion ----------------------------------------------------------

/// What deleting the account whose management key is `principal` changes.
struct AccountScope {
    /// Ids of the nodes the deletion removes, sorted: every Customer or
    /// Endpoint node whose management key is the principal (compared by key
    /// bytes), and every node beneath one of them. This includes devices and
    /// subgroups that other identities placed in the account's groups. A Root
    /// node is never in the set, and a Root or Relay node owned by the
    /// principal does not add its subtree.
    std::vector<std::string> removed;
    /// Canonical keys whose assignments the deletion removes from every
    /// surviving node except a Root node, sorted: the principal, and the
    /// management key of each removed node that owns no surviving node.
    std::vector<std::string> swept_keys;
};

/// The account deletion scope of `principal` in `nodes`. A parent loop never
/// repeats a node. Deterministic: the result does not depend on the iteration
/// order of the node map. An empty principal gives an empty scope.
[[nodiscard]] AccountScope account_scope(const NodeMap& nodes, std::string_view principal);

}  // namespace nexus::tree::rules
