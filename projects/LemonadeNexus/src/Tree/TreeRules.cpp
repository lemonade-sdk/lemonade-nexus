#include <LemonadeNexus/Tree/TreeRules.hpp>

#include <LemonadeNexus/Tree/DeviceLabel.hpp>

#include <algorithm>
#include <unordered_map>
#include <unordered_set>

namespace nexus::tree::rules {

acl::Permission permission_from_string(std::string_view perm_str) {
    if (perm_str == "read")            return acl::Permission::Read;
    if (perm_str == "write")           return acl::Permission::Write;
    if (perm_str == "add_child")       return acl::Permission::AddChild;
    if (perm_str == "edit_node")       return acl::Permission::EditNode;
    if (perm_str == "delete_node")     return acl::Permission::DeleteNode;
    if (perm_str == "expand_subnet")   return acl::Permission::ExpandSubnet;
    if (perm_str == "connect_private") return acl::Permission::ConnectPrivate;
    if (perm_str == "connect_shared")  return acl::Permission::ConnectShared;
    if (perm_str == "relay_forward")   return acl::Permission::RelayForward;
    if (perm_str == "routing_coordinate") return acl::Permission::RoutingCoordinate;
    if (perm_str == "stun_respond")    return acl::Permission::StunRespond;
    if (perm_str == "relay_register")  return acl::Permission::RelayRegister;
    if (perm_str == "allocate_ip")     return acl::Permission::AllocateIP;
    if (perm_str == "admin")           return acl::Permission::Admin;
    return acl::Permission::None;
}

bool is_service_permission(std::string_view name) {
    if (!name.starts_with(kServicePermissionPrefix)) return false;
    const auto family = name.substr(kServicePermissionPrefix.size());
    if (family.empty() || family.size() > kServicePermissionFamilyMax) return false;
    // Byte checks, not <cctype>: the result must not depend on the locale.
    const auto lower_alnum = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
    };
    if (!lower_alnum(family.front())) return false;
    return std::all_of(family.begin(), family.end(), [&](char c) {
        return lower_alnum(c) || c == '_' || c == '.' || c == '-';
    });
}

bool permission_name_known(std::string_view name) {
    return permission_from_string(name) != acl::Permission::None || is_service_permission(name);
}

acl::Permission required_permission_for(std::string_view op) {
    if (op == "create_node") return acl::Permission::AddChild;
    if (op == "update_node" || op == "allocate_ip" || op == "register_relay" ||
        op == "update_assignment") return acl::Permission::EditNode;
    if (op == "delete_node") return acl::Permission::DeleteNode;
    return acl::Permission::None;
}

bool signer_has_permission(const TreeNode& node, std::string_view signer_pubkey,
                           acl::Permission required) {
    // Same key-bytes match as check_permission, or reads and writes disagree
    // on who a principal is.
    const auto signer_canon = canonical_principal(signer_pubkey);
    for (const auto& assignment : node.assignments) {
        if (canonical_principal(assignment.management_pubkey) != signer_canon) continue;
        for (const auto& perm_str : assignment.permissions) {
            if (acl::has_permission(permission_from_string(perm_str), required)) {
                return true;
            }
        }
    }
    return false;
}

std::optional<std::string> admin_anchor(const NodeMap& nodes, std::string_view node_id,
                                        std::string_view signer_pubkey) {
    std::unordered_set<std::string> visited;
    std::string current(node_id);
    while (!current.empty() && visited.insert(current).second) {
        auto it = nodes.find(current);
        if (it == nodes.end()) return std::nullopt;
        if (signer_has_permission(it->second, signer_pubkey, acl::Permission::Admin)) {
            return current;
        }
        current = it->second.parent_id;
    }
    return std::nullopt;
}

bool administers_root(const NodeMap& nodes, std::string_view node_id,
                      std::string_view signer_pubkey) {
    std::unordered_set<std::string> visited;
    std::string current(node_id);
    while (visited.insert(current).second) {
        auto it = nodes.find(current);
        if (it == nodes.end()) return false;
        if (it->second.parent_id.empty()) {
            return signer_has_permission(it->second, signer_pubkey, acl::Permission::Admin);
        }
        current = it->second.parent_id;
    }
    return false;
}

bool principal_joined_under(const NodeMap& nodes, std::string_view scope_id,
                            std::string_view principal) {
    const auto principal_canon = canonical_principal(principal);
    if (principal_canon.empty()) return false;
    for (const auto& [id, node] : nodes) {
        if (canonical_principal(node.mgmt_pubkey) != principal_canon) continue;
        // Walk up from the candidate; a parent loop ends the walk unmatched.
        std::unordered_set<std::string> visited;
        std::string current = id;
        while (!current.empty() && visited.insert(current).second) {
            if (current == scope_id) return true;
            auto it = nodes.find(current);
            if (it == nodes.end()) break;
            current = it->second.parent_id;
        }
    }
    return false;
}

bool mesh_pubkey_taken(const NodeMap& nodes, const std::string& mesh_pubkey,
                       const std::string& own_id) {
    if (mesh_pubkey.empty()) return false;
    for (const auto& [id, node] : nodes) {
        if (id != own_id && node.mesh_pubkey == mesh_pubkey) return true;
    }
    return false;
}

bool device_label_collides(const TreeNode& node, std::string_view parent_id,
                           std::string_view label, std::string_view own_id) {
    if (label.empty()) return false;
    return node.type == NodeType::Endpoint && node.parent_id == parent_id && node.id != own_id &&
           device_label(node.hostname) == label;
}

std::vector<std::string> device_label_conflicts(const NodeMap& nodes, std::string_view parent_id,
                                                std::string_view label, std::string_view own_id) {
    std::vector<std::string> ids;
    for (const auto& [id, node] : nodes) {
        if (device_label_collides(node, parent_id, label, own_id)) ids.push_back(id);
    }
    std::sort(ids.begin(), ids.end());
    return ids;
}

std::optional<std::string> device_name_refusal(std::string_view hostname,
                                               const TreeNode* conflict) {
    if (hostname.empty()) return std::nullopt;
    if (device_label(hostname).empty()) {
        return "device name '" + std::string(hostname) +
               "' has no letter or digit; pick another name";
    }
    if (conflict) {
        return "device name '" + std::string(hostname) + "' is the same as device '" +
               conflict->hostname + "' (" + conflict->id + ") on the mesh port; pick another name";
    }
    return std::nullopt;
}

namespace {

/// Principal -> sorted permission strings, keyed by key bytes so the two
/// base64 spellings of one key are the same principal.
std::unordered_map<std::string, std::vector<std::string>>
assignment_map(const std::vector<Assignment>& assignments) {
    std::unordered_map<std::string, std::vector<std::string>> out;
    for (const auto& a : assignments) {
        auto& perms = out[canonical_principal(a.management_pubkey)];
        perms.insert(perms.end(), a.permissions.begin(), a.permissions.end());
    }
    for (auto& [_, perms] : out) {
        std::sort(perms.begin(), perms.end());
        perms.erase(std::unique(perms.begin(), perms.end()), perms.end());
    }
    return out;
}

} // namespace

std::optional<std::string> delta_content_refusal(const NodeMap& nodes,
                                                 const TreeDelta& delta) {
    const auto& op = delta.operation;
    const auto& data = delta.node_data;

    if (op == "delete_node") {
        auto it = nodes.find(delta.target_node_id);
        if (it != nodes.end() && it->second.parent_id.empty()) {
            return std::string{"the root node cannot be deleted"};
        }
        return std::nullopt;
    }

    if (op == "create_node") {
        if (data.type == NodeType::Root || data.parent_id.empty()) {
            return std::string{"a root node cannot be created"};
        }
        // Plane addresses and the relay role decide what the forwarding policy
        // lets through across the whole network, not only inside one group,
        // so the server assigns them. Only a root admin may set them; a group
        // admin, or a creator with admin on its own new node, may not.
        if ((!data.tunnel_ip.empty() || !data.private_subnet.empty() ||
             data.type == NodeType::Relay) &&
            !administers_root(nodes, data.parent_id, delta.signer_pubkey)) {
            return std::string{"only a root admin may create a relay or set node addresses"};
        }
        // A creator owns what it creates, and the new node's own management
        // key joins with it. Naming anyone else is a grant, and grants belong
        // to an administrator of the parent.
        const auto signer_canon = canonical_principal(delta.signer_pubkey);
        const auto own_canon = canonical_principal(data.mgmt_pubkey);
        bool names_others = false;
        for (const auto& a : data.assignments) {
            const auto canon = canonical_principal(a.management_pubkey);
            if (canon != signer_canon && canon != own_canon) {
                names_others = true;
                break;
            }
        }
        if (!names_others) return std::nullopt;
        const auto anchor = admin_anchor(nodes, data.parent_id, delta.signer_pubkey);
        if (!anchor) {
            return std::string{"only an admin of the parent may assign other identities"};
        }
        for (const auto& a : data.assignments) {
            const auto canon = canonical_principal(a.management_pubkey);
            if (canon == signer_canon || canon == own_canon) continue;
            if (!principal_joined_under(nodes, *anchor, a.management_pubkey)) {
                return std::string{"assignment names an identity that has not joined"};
            }
        }
        return std::nullopt;
    }

    // Update operations replace the stored node. The replacement must be the
    // same node: without this an edit_node holder could rename the record onto
    // another node's id (overwriting that node on disk) or reparent itself
    // into another group.
    auto it = nodes.find(delta.target_node_id);
    if (it == nodes.end()) return std::nullopt;  // reported by the apply step
    const TreeNode& current = it->second;
    if (data.id != current.id) return std::string{"node id cannot change"};
    if (data.parent_id != current.parent_id) return std::string{"node parent cannot change"};
    if (data.type != current.type) return std::string{"node type cannot change"};
    if (canonical_principal(data.mgmt_pubkey) != canonical_principal(current.mgmt_pubkey)) {
        return std::string{"node management key cannot change"};
    }
    if (data.endpoint_identifier != current.endpoint_identifier) {
        return std::string{"endpoint identifier cannot change"};
    }
    // Addresses are network-wide resources, so only a root admin moves them
    // (see the create rule above).
    if ((data.tunnel_ip != current.tunnel_ip || data.private_subnet != current.private_subnet) &&
        !administers_root(nodes, current.id, delta.signer_pubkey)) {
        return std::string{"only a root admin may change node addresses"};
    }

    const auto before = assignment_map(current.assignments);
    const auto after = assignment_map(data.assignments);
    if (before == after) return std::nullopt;

    // Changing who holds what is administration: edit_node alone never
    // grants it, so no holder can raise its own or anyone else's access.
    const auto anchor = admin_anchor(nodes, current.id, delta.signer_pubkey);
    if (!anchor) {
        return std::string{"only an admin of this node or an ancestor may change assignments"};
    }
    for (const auto& [principal, perms] : after) {
        auto prev = before.find(principal);
        if (prev != before.end() && prev->second == perms) continue;
        if (!principal_joined_under(nodes, *anchor, principal)) {
            return std::string{"assignment names an identity that has not joined"};
        }
    }
    return std::nullopt;
}

std::optional<AssignmentRuling> assignment_change_refusal(
        const NodeMap& nodes, std::string_view node_id, std::string_view signer,
        std::string_view principal, const std::vector<std::string>& permissions) {
    if (!nodes.contains(std::string(node_id))) {
        return AssignmentRuling{AssignmentRefusal::NotFound, "node not found"};
    }
    const auto principal_canon = canonical_principal(principal);
    if (principal_canon.empty()) {
        return AssignmentRuling{AssignmentRefusal::Invalid, "invalid principal"};
    }
    for (const auto& p : permissions) {
        if (!permission_name_known(p)) {
            return AssignmentRuling{AssignmentRefusal::Invalid, "unknown permission '" + p + "'"};
        }
    }

    // A member leaves a group it entered through an invite. Its own entry is
    // the whole membership, so removing it needs no admin. A home entry (the
    // principal joined inside the group) or an admin entry stays with the
    // admin rules below, so no one locks a group out of its own management.
    const TreeNode& node = nodes.at(std::string(node_id));
    if (permissions.empty() && canonical_principal(signer) == principal_canon &&
        node.type == NodeType::Customer &&
        !signer_has_permission(node, signer, acl::Permission::Admin) &&
        !principal_joined_under(nodes, node_id, principal)) {
        return std::nullopt;
    }

    const auto anchor = admin_anchor(nodes, node_id, signer);
    if (!anchor) {
        return AssignmentRuling{AssignmentRefusal::Forbidden,
                                "only an admin of this node or an ancestor may change assignments"};
    }
    if (*anchor == node_id && canonical_principal(signer) == principal_canon) {
        return AssignmentRuling{AssignmentRefusal::Forbidden,
                                "an admin cannot change its own entry on the node that grants it"};
    }
    if (!permissions.empty() && !principal_joined_under(nodes, *anchor, principal)) {
        return AssignmentRuling{AssignmentRefusal::Forbidden,
                                "the identity has not joined this group"};
    }
    return std::nullopt;
}

void replace_assignment(std::vector<Assignment>& list, std::string_view principal,
                        const std::vector<std::string>& permissions) {
    const auto principal_canon = canonical_principal(principal);
    list.erase(std::remove_if(list.begin(), list.end(), [&](const Assignment& a) {
                   return canonical_principal(a.management_pubkey) == principal_canon;
               }),
               list.end());
    if (!permissions.empty()) {
        std::vector<std::string> perms = permissions;
        std::sort(perms.begin(), perms.end());
        perms.erase(std::unique(perms.begin(), perms.end()), perms.end());
        list.push_back({std::string(principal), std::move(perms)});
    }
}

bool link_peer_access_missing(const TreeNode& node, std::string_view principal) {
    return !signer_has_permission(node, principal, acl::Permission::Read) ||
           !signer_has_permission(node, principal, acl::Permission::ConnectPrivate);
}

bool grant_link_peer_access(TreeNode& node, std::string_view principal) {
    if (!link_peer_access_missing(node, principal)) return false;
    const auto canon = canonical_principal(principal);
    for (auto& a : node.assignments) {
        if (canonical_principal(a.management_pubkey) != canon) continue;
        for (const char* p : {"read", "connect_private"}) {
            if (std::find(a.permissions.begin(), a.permissions.end(), p) == a.permissions.end()) {
                a.permissions.emplace_back(p);
            }
        }
        return true;
    }
    node.assignments.push_back({std::string(principal), {"read", "connect_private"}});
    return true;
}

bool holds_or_administers(const NodeMap& nodes, std::string_view node_id,
                          std::string_view signer, acl::Permission perm) {
    auto it = nodes.find(std::string(node_id));
    if (it == nodes.end()) return false;
    return signer_has_permission(it->second, signer, perm) ||
           admin_anchor(nodes, node_id, signer).has_value();
}

namespace {

/// True when `node_id` is `ancestor_id` or lies beneath it. A parent loop or
/// a missing node ends the walk unmatched.
bool at_or_under(const NodeMap& nodes, std::string_view node_id, std::string_view ancestor_id) {
    std::unordered_set<std::string> visited;
    std::string current(node_id);
    while (!current.empty() && visited.insert(current).second) {
        if (current == ancestor_id) return true;
        auto it = nodes.find(current);
        if (it == nodes.end()) return false;
        current = it->second.parent_id;
    }
    return false;
}

bool invite_permission_allowed(std::string_view perm) {
    return is_service_permission(perm) ||
           std::find(kInvitePermissions.begin(), kInvitePermissions.end(), perm) !=
               kInvitePermissions.end();
}

/// True when `principal`'s entry on `node` names `name` literally. An `admin`
/// entry implies every bit but names only "admin".
bool holds_literal_name(const TreeNode& node, std::string_view principal, std::string_view name) {
    const auto canon = canonical_principal(principal);
    if (canon.empty()) return false;
    for (const auto& a : node.assignments) {
        if (canonical_principal(a.management_pubkey) != canon) continue;
        if (std::find(a.permissions.begin(), a.permissions.end(), name) != a.permissions.end()) {
            return true;
        }
    }
    return false;
}

/// True when `principal`'s entry on `node` names a connect permission
/// literally. `admin` is not a membership grant.
bool holds_literal_connect(const TreeNode& node, std::string_view principal) {
    return holds_literal_name(node, principal, "connect_private") ||
           holds_literal_name(node, principal, "connect_shared");
}

}  // namespace

std::optional<AssignmentRuling> invite_refusal(const NodeMap& nodes, std::string_view target_id,
                                               std::string_view inviter,
                                               const std::vector<std::string>& permissions) {
    auto it = nodes.find(std::string(target_id));
    if (it == nodes.end()) {
        return AssignmentRuling{AssignmentRefusal::NotFound, "invite target not found"};
    }
    if (it->second.type != NodeType::Customer) {
        return AssignmentRuling{AssignmentRefusal::Invalid, "an invite targets a group"};
    }
    if (canonical_principal(inviter).empty()) {
        return AssignmentRuling{AssignmentRefusal::Invalid, "invalid inviter"};
    }
    for (const auto& p : permissions) {
        if (!invite_permission_allowed(p)) {
            return AssignmentRuling{AssignmentRefusal::Invalid,
                                    "an invite cannot grant '" + p + "'"};
        }
    }
    if (!holds_or_administers(nodes, target_id, inviter, acl::Permission::AddChild)) {
        return AssignmentRuling{AssignmentRefusal::Forbidden,
                                "the inviter needs add_child on the invite target"};
    }
    for (const auto& p : permissions) {
        // A service permission maps to no flag (every key "holds" None), so
        // it passes on only through a literal entry or administration.
        const bool held =
            is_service_permission(p)
                ? holds_literal_name(it->second, inviter, p) ||
                      admin_anchor(nodes, target_id, inviter).has_value()
                : holds_or_administers(nodes, target_id, inviter, permission_from_string(p));
        if (!held) {
            return AssignmentRuling{AssignmentRefusal::Forbidden,
                                    "the inviter does not hold '" + p + "' on the invite target"};
        }
    }
    return std::nullopt;
}

std::optional<AssignmentRuling> invite_acceptance_refusal(
        const NodeMap& nodes, std::string_view target_id, std::string_view invitee,
        std::string_view inviter, const std::vector<std::string>& permissions) {
    if (auto ruling = invite_refusal(nodes, target_id, inviter, permissions)) return ruling;
    if (std::find(permissions.begin(), permissions.end(), "read") == permissions.end()) {
        return AssignmentRuling{AssignmentRefusal::Invalid,
                                "the invite grants no membership (read is missing)"};
    }
    if (canonical_principal(invitee).empty() || !invitee.starts_with("ed25519:")) {
        return AssignmentRuling{AssignmentRefusal::Invalid, "invalid invitee"};
    }
    if (principal_joined_under(nodes, target_id, invitee) ||
        admin_anchor(nodes, target_id, invitee)) {
        return AssignmentRuling{AssignmentRefusal::Conflict,
                                "the identity already belongs to this group"};
    }
    return std::nullopt;
}

bool membership_reaches(const NodeMap& nodes, std::string_view member, const TreeNode& node) {
    std::unordered_set<std::string> visited{node.id};
    std::string current = node.parent_id;
    while (!current.empty() && visited.insert(current).second) {
        auto it = nodes.find(current);
        if (it == nodes.end()) return false;
        if (it->second.type == NodeType::Customer && holds_literal_connect(it->second, member)) {
            return true;
        }
        current = it->second.parent_id;
    }
    return false;
}

bool endpoint_may_connect(const NodeMap& nodes, std::string_view principal, const TreeNode& from,
                          const TreeNode& to) {
    if (from.id == to.id || from.parent_id.empty()) return false;
    if (to.id != from.parent_id && at_or_under(nodes, to.id, from.parent_id) &&
        (signer_has_permission(to, principal, acl::Permission::ConnectPrivate) ||
         signer_has_permission(to, principal, acl::Permission::ConnectShared))) {
        return true;
    }
    const auto principal_canon = canonical_principal(principal);
    if (principal_canon.empty() || principal_canon != canonical_principal(from.mgmt_pubkey)) {
        return false;
    }
    return membership_reaches(nodes, principal, to) ||
           (!to.mgmt_pubkey.empty() && membership_reaches(nodes, to.mgmt_pubkey, from));
}

PeerPermissions peer_permissions(const NodeMap& nodes, std::string_view principal,
                                 const TreeNode& device) {
    PeerPermissions out;
    const auto canon = canonical_principal(principal);
    if (canon.empty()) return out;
    const auto collect = [&](const TreeNode& node) {
        for (const auto& a : node.assignments) {
            if (canonical_principal(a.management_pubkey) != canon) continue;
            out.names.insert(out.names.end(), a.permissions.begin(), a.permissions.end());
        }
    };
    collect(device);
    std::unordered_set<std::string> visited{device.id};
    std::string current = device.parent_id;
    while (!current.empty() && visited.insert(current).second) {
        auto it = nodes.find(current);
        if (it == nodes.end()) break;
        if (it->second.type == NodeType::Customer) collect(it->second);
        current = it->second.parent_id;
    }
    out.admin = signer_has_permission(device, principal, acl::Permission::Admin) ||
                (!device.parent_id.empty() && admin_anchor(nodes, device.parent_id, principal));
    if (out.admin) out.names.emplace_back("admin");
    std::sort(out.names.begin(), out.names.end());
    out.names.erase(std::unique(out.names.begin(), out.names.end()), out.names.end());
    return out;
}

std::optional<AssignmentRuling> move_refusal(const NodeMap& nodes, std::string_view node_id,
                                             std::string_view new_parent_id,
                                             std::string_view signer) {
    auto node_it = nodes.find(std::string(node_id));
    if (node_it == nodes.end()) {
        return AssignmentRuling{AssignmentRefusal::NotFound, "node not found"};
    }
    auto parent_it = nodes.find(std::string(new_parent_id));
    if (parent_it == nodes.end()) {
        return AssignmentRuling{AssignmentRefusal::NotFound, "new parent not found"};
    }
    const TreeNode& node = node_it->second;
    if (node.parent_id.empty() || node.type == NodeType::Root) {
        return AssignmentRuling{AssignmentRefusal::Forbidden, "the root node cannot move"};
    }
    if (node.type != NodeType::Endpoint && node.type != NodeType::Customer) {
        return AssignmentRuling{AssignmentRefusal::Invalid, "only devices and groups move"};
    }
    if (node.type == NodeType::Customer) {
        auto current_parent = nodes.find(node.parent_id);
        if (current_parent == nodes.end() || current_parent->second.type == NodeType::Root) {
            return AssignmentRuling{AssignmentRefusal::Forbidden, "a top-level group cannot move"};
        }
    }
    if (parent_it->second.type != NodeType::Customer) {
        return AssignmentRuling{AssignmentRefusal::Invalid, "a node moves only under a group"};
    }
    if (node.parent_id == new_parent_id) {
        return AssignmentRuling{AssignmentRefusal::Conflict, "the node is already under that group"};
    }
    if (at_or_under(nodes, new_parent_id, node_id)) {
        return AssignmentRuling{AssignmentRefusal::Invalid,
                                "a node cannot move under itself or its descendants"};
    }
    const bool may_remove =
        node.type == NodeType::Endpoint
            ? holds_or_administers(nodes, node_id, signer, acl::Permission::DeleteNode)
            : admin_anchor(nodes, node_id, signer).has_value();
    if (!may_remove) {
        return AssignmentRuling{AssignmentRefusal::Forbidden,
                                node.type == NodeType::Endpoint
                                    ? "moving a device needs delete_node on it or admin above it"
                                    : "moving a group needs admin on it or above it"};
    }
    if (!holds_or_administers(nodes, new_parent_id, signer, acl::Permission::AddChild)) {
        return AssignmentRuling{AssignmentRefusal::Forbidden,
                                "moving needs add_child on the new parent"};
    }
    return std::nullopt;
}

AccountScope account_scope(const NodeMap& nodes, std::string_view principal) {
    AccountScope scope;
    const auto key = canonical_principal(principal);
    if (key.empty()) return scope;

    std::vector<std::string> ids;
    ids.reserve(nodes.size());
    for (const auto& [id, node] : nodes) ids.push_back(id);
    std::sort(ids.begin(), ids.end());

    std::unordered_map<std::string, std::vector<std::string>> children;
    for (const auto& id : ids) children[nodes.at(id).parent_id].push_back(id);

    // Breadth-first from every node the account owns. The visited set ends a
    // parent loop, and a Root node is never taken.
    std::unordered_set<std::string> doomed;
    std::vector<std::string> queue;
    for (const auto& id : ids) {
        const auto& node = nodes.at(id);
        if (node.type != NodeType::Customer && node.type != NodeType::Endpoint) continue;
        if (node.parent_id.empty()) continue;
        if (canonical_principal(node.mgmt_pubkey) != key) continue;
        if (doomed.insert(id).second) queue.push_back(id);
    }
    for (std::size_t i = 0; i < queue.size(); ++i) {
        auto it = children.find(queue[i]);
        if (it == children.end()) continue;
        for (const auto& child : it->second) {
            if (nodes.at(child).type == NodeType::Root) continue;
            if (doomed.insert(child).second) queue.push_back(child);
        }
    }
    scope.removed.assign(doomed.begin(), doomed.end());
    std::sort(scope.removed.begin(), scope.removed.end());

    std::unordered_set<std::string> surviving_owners;
    for (const auto& id : ids) {
        if (!doomed.contains(id)) surviving_owners.insert(canonical_principal(nodes.at(id).mgmt_pubkey));
    }
    std::unordered_set<std::string> swept{key};
    for (const auto& id : scope.removed) {
        const auto owner = canonical_principal(nodes.at(id).mgmt_pubkey);
        if (!owner.empty() && !surviving_owners.contains(owner)) swept.insert(owner);
    }
    scope.swept_keys.assign(swept.begin(), swept.end());
    std::sort(scope.swept_keys.begin(), scope.swept_keys.end());
    return scope;
}

}  // namespace nexus::tree::rules
