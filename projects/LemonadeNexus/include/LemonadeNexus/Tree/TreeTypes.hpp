#pragma once

#include <LemonadeNexus/ACL/Permission.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace nexus::tree {

/// The type of a tree node.
enum class NodeType : uint8_t {
    Root,
    Customer,
    Endpoint,
    Relay,
};

/// A single permission assignment within a tree node.
struct Assignment {
    std::string              management_pubkey; // "ed25519:base64..."
    std::vector<std::string> permissions;       // ["read","write","add_child",...]
};

/// A node in the hierarchical permission tree.
struct TreeNode {
    std::string              id;
    std::string              parent_id;
    NodeType                 type{NodeType::Customer};
    std::string              hostname;                    // DNS-resolvable name (e.g. "my-laptop")

    // Network allocations
    std::string              tunnel_ip;                  // e.g. "10.64.4.210/32"
    std::string              private_subnet;             // e.g. "10.128.17.4/30"
    std::string              private_shared_addresses;   // e.g. "172.20.68.12/30"
    std::string              shared_domain;               // e.g. "demo.acmecorp.example.com"

    // Crypto
    std::string              mgmt_pubkey;                // "ed25519:base64..."
    std::string              wrapped_mgmt_privkey;       // "aeskw:base64blob..."
    std::string              wg_pubkey;                  // WireGuard Curve25519 pubkey

    // Assignments (explicit per-user permissions)
    std::vector<Assignment>  assignments;

    // Signature by parent's management key
    std::string              signature;                  // base64 Ed25519 signature

    // Relay-specific fields (only for NodeType::Relay)
    std::string              listen_endpoint;            // "ip:port"
    std::string              region;
    uint32_t                 capacity_mbps{0};
    float                    reputation_score{1.0f};
    uint64_t                 expires_at{0};              // Unix timestamp, 0 = no expiry
};

/// A delta operation to apply to the tree.
struct TreeDelta {
    std::string operation;        // "create_node", "update_node", "delete_node",
                                   // "allocate_ip", "register_relay", "update_assignment"
    std::string target_node_id;
    TreeNode    node_data;        // Full or partial node data depending on operation
    std::string signer_pubkey;    // Who signed this delta
    std::string signature;        // Ed25519 signature over canonical(operation + target + data)
    uint64_t    timestamp{0};
};

// --- JSON serialization ---

[[nodiscard]] std::string node_type_to_string(NodeType type);
[[nodiscard]] NodeType string_to_node_type(std::string_view s);

void to_json(nlohmann::json& j, const Assignment& a);
void from_json(const nlohmann::json& j, Assignment& a);
void to_json(nlohmann::json& j, const TreeNode& n);
void from_json(const nlohmann::json& j, TreeNode& n);
void to_json(nlohmann::json& j, const TreeDelta& d);
void from_json(const nlohmann::json& j, TreeDelta& d);

/// Produce a canonical (deterministic) JSON string for signing.
/// Excludes the "signature" field itself.
[[nodiscard]] std::string canonical_node_json(const TreeNode& node);
[[nodiscard]] std::string canonical_delta_json(const TreeDelta& delta);

} // namespace nexus::tree
