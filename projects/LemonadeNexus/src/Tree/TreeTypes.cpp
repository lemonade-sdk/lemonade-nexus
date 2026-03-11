#include <LemonadeNexus/Tree/TreeTypes.hpp>

#include <stdexcept>

namespace nexus::tree {

using json = nlohmann::json;

// --- NodeType <-> string ---

std::string node_type_to_string(NodeType type) {
    switch (type) {
        case NodeType::Root:     return "root";
        case NodeType::Customer: return "customer";
        case NodeType::Endpoint: return "endpoint";
        case NodeType::Relay:    return "relay";
    }
    throw std::invalid_argument("Unknown NodeType value: " +
                                 std::to_string(static_cast<uint8_t>(type)));
}

NodeType string_to_node_type(std::string_view s) {
    if (s == "root")     return NodeType::Root;
    if (s == "customer") return NodeType::Customer;
    if (s == "endpoint") return NodeType::Endpoint;
    if (s == "relay")    return NodeType::Relay;
    throw std::invalid_argument("Unknown NodeType string: " + std::string(s));
}

// --- Assignment ---

void to_json(json& j, const Assignment& a) {
    j = json{
        {"management_pubkey", a.management_pubkey},
        {"permissions",       a.permissions},
    };
}

void from_json(const json& j, Assignment& a) {
    j.at("management_pubkey").get_to(a.management_pubkey);
    j.at("permissions").get_to(a.permissions);
}

// --- TreeNode ---

void to_json(json& j, const TreeNode& n) {
    j = json{
        {"id",                       n.id},
        {"parent_id",                n.parent_id},
        {"type",                     node_type_to_string(n.type)},
        {"hostname",                 n.hostname},
        {"tunnel_ip",                n.tunnel_ip},
        {"private_subnet",           n.private_subnet},
        {"private_shared_addresses", n.private_shared_addresses},
        {"shared_domain",            n.shared_domain},
        {"mgmt_pubkey",              n.mgmt_pubkey},
        {"wrapped_mgmt_privkey",     n.wrapped_mgmt_privkey},
        {"wg_pubkey",                n.wg_pubkey},
        {"assignments",              n.assignments},
        {"signature",                n.signature},
        {"listen_endpoint",          n.listen_endpoint},
        {"region",                   n.region},
        {"capacity_mbps",            n.capacity_mbps},
        {"reputation_score",         n.reputation_score},
        {"expires_at",               n.expires_at},
    };
}

void from_json(const json& j, TreeNode& n) {
    j.at("id").get_to(n.id);
    j.at("parent_id").get_to(n.parent_id);
    n.type = string_to_node_type(j.at("type").get<std::string>());
    if (j.contains("hostname")) j.at("hostname").get_to(n.hostname);
    j.at("tunnel_ip").get_to(n.tunnel_ip);
    j.at("private_subnet").get_to(n.private_subnet);
    j.at("private_shared_addresses").get_to(n.private_shared_addresses);
    j.at("shared_domain").get_to(n.shared_domain);
    j.at("mgmt_pubkey").get_to(n.mgmt_pubkey);
    j.at("wrapped_mgmt_privkey").get_to(n.wrapped_mgmt_privkey);
    j.at("wg_pubkey").get_to(n.wg_pubkey);
    j.at("assignments").get_to(n.assignments);
    j.at("signature").get_to(n.signature);
    j.at("listen_endpoint").get_to(n.listen_endpoint);
    j.at("region").get_to(n.region);
    j.at("capacity_mbps").get_to(n.capacity_mbps);
    j.at("reputation_score").get_to(n.reputation_score);
    j.at("expires_at").get_to(n.expires_at);
}

// --- TreeDelta ---

void to_json(json& j, const TreeDelta& d) {
    j = json{
        {"operation",      d.operation},
        {"target_node_id", d.target_node_id},
        {"node_data",      d.node_data},
        {"signer_pubkey",  d.signer_pubkey},
        {"signature",      d.signature},
        {"timestamp",      d.timestamp},
    };
}

void from_json(const json& j, TreeDelta& d) {
    j.at("operation").get_to(d.operation);
    j.at("target_node_id").get_to(d.target_node_id);
    j.at("node_data").get_to(d.node_data);
    j.at("signer_pubkey").get_to(d.signer_pubkey);
    j.at("signature").get_to(d.signature);
    j.at("timestamp").get_to(d.timestamp);
}

// --- Canonical JSON for signing ---

std::string canonical_node_json(const TreeNode& node) {
    // Build a sorted JSON object excluding the "signature" field.
    // nlohmann::json uses sorted keys (std::map) by default,
    // so the output is deterministic.
    json j;
    j["id"]                       = node.id;
    j["parent_id"]                = node.parent_id;
    j["type"]                     = node_type_to_string(node.type);
    j["hostname"]                 = node.hostname;
    j["tunnel_ip"]                = node.tunnel_ip;
    j["private_subnet"]           = node.private_subnet;
    j["private_shared_addresses"] = node.private_shared_addresses;
    j["shared_domain"]            = node.shared_domain;
    j["mgmt_pubkey"]              = node.mgmt_pubkey;
    j["wrapped_mgmt_privkey"]     = node.wrapped_mgmt_privkey;
    j["wg_pubkey"]                = node.wg_pubkey;
    j["assignments"]              = node.assignments;
    j["listen_endpoint"]          = node.listen_endpoint;
    j["region"]                   = node.region;
    j["capacity_mbps"]            = node.capacity_mbps;
    j["reputation_score"]         = node.reputation_score;
    j["expires_at"]               = node.expires_at;
    // "signature" intentionally excluded for canonical form
    return j.dump();
}

std::string canonical_delta_json(const TreeDelta& delta) {
    // Build a sorted JSON object excluding the "signature" field.
    json j;
    j["node_data"]      = delta.node_data;
    j["operation"]      = delta.operation;
    j["signer_pubkey"]  = delta.signer_pubkey;
    j["target_node_id"] = delta.target_node_id;
    j["timestamp"]      = delta.timestamp;
    // "signature" intentionally excluded for canonical form
    return j.dump();
}

} // namespace nexus::tree
