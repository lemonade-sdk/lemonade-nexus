#include <LemonadeNexus/Tree/TreeRules.hpp>

#include <algorithm>
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
        if (permission_from_string(p) == acl::Permission::None) {
            return AssignmentRuling{AssignmentRefusal::Invalid, "unknown permission '" + p + "'"};
        }
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

}  // namespace nexus::tree::rules
