#pragma once

#include <LemonadeNexus/Relay/RelayTypes.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>

#include <concepts>
#include <cstdint>
#include <string>
#include <vector>

namespace nexus::client {

// ---------------------------------------------------------------------------
// Domain types
// ---------------------------------------------------------------------------

/// Descriptor for a Lemonade-Nexus coordination server or relay that a client
/// can connect to.
struct ServerEndpoint {
    std::string address;           // IP or hostname
    uint16_t    http_port{9100};   // HTTP control plane
    uint16_t    udp_port{51940};   // WireGuard + hole punch (shared UDP port)
    uint16_t    stun_port{3478};   // STUN
    uint16_t    gossip_port{9102}; // Gossip
    std::string pubkey;            // server's Ed25519 pubkey (base64)
    bool        is_central{false};
};

/// Result returned when an endpoint joins the network.
struct JoinResult {
    bool        success{false};
    std::string node_id;           // our assigned node ID in the tree
    std::string tunnel_ip;         // our tunnel IP
    std::string private_subnet;
    std::string error_message;
};

/// Result returned after submitting a tree delta.
struct TreeModifyResult {
    bool        success{false};
    uint64_t    delta_sequence{0};
    std::string error_message;
};

// ---------------------------------------------------------------------------
// CRTP interface
// ---------------------------------------------------------------------------

/// CRTP base for client-side network operations.
///
/// Derived must implement:
///   std::vector<ServerEndpoint>     do_discover_servers(const std::vector<ServerEndpoint>&)
///   JoinResult                      do_join_network(const ServerEndpoint&, const nlohmann::json&)
///   bool                            do_leave_network()
///   TreeModifyResult                do_submit_delta(const tree::TreeDelta&)
///   TreeModifyResult                do_create_child_node(const std::string&, const tree::TreeNode&)
///   TreeModifyResult                do_update_node(const std::string&, const nlohmann::json&)
///   std::vector<relay::RelayNodeInfo> do_get_available_relays(const relay::RelaySelectionCriteria&)
///   std::vector<std::string>        do_get_my_permissions(const std::string&)
template <typename Derived>
class IClientProvider {
public:
    /// Probe a set of bootstrap endpoints, then use their relay-list API to
    /// discover additional servers / relays on the mesh.
    [[nodiscard]] std::vector<ServerEndpoint>
    discover_servers(const std::vector<ServerEndpoint>& bootstrap_endpoints) {
        return self().do_discover_servers(bootstrap_endpoints);
    }

    /// Authenticate with a coordination server and receive a tree node +
    /// tunnel IP allocation.
    [[nodiscard]] JoinResult
    join_network(const ServerEndpoint& server, const nlohmann::json& credentials_json) {
        return self().do_join_network(server, credentials_json);
    }

    /// Gracefully leave the network (notify the server, tear down state).
    [[nodiscard]] bool leave_network() {
        return self().do_leave_network();
    }

    /// Sign a tree delta with our Ed25519 identity key and submit it to a
    /// known server.
    [[nodiscard]] TreeModifyResult submit_delta(const tree::TreeDelta& delta) {
        return self().do_submit_delta(delta);
    }

    /// Convenience: build a "create_node" delta for a new child under
    /// @p parent_id and submit it.
    [[nodiscard]] TreeModifyResult
    create_child_node(const std::string& parent_id, const tree::TreeNode& child_node) {
        return self().do_create_child_node(parent_id, child_node);
    }

    /// Convenience: build an "update_node" delta for @p node_id and submit it.
    [[nodiscard]] TreeModifyResult
    update_node(const std::string& node_id, const nlohmann::json& updates_json) {
        return self().do_update_node(node_id, updates_json);
    }

    /// Query available relay nodes, filtered by @p criteria.
    [[nodiscard]] std::vector<relay::RelayNodeInfo>
    get_available_relays(const relay::RelaySelectionCriteria& criteria) {
        return self().do_get_available_relays(criteria);
    }

    /// Return the permission strings our identity pubkey holds on @p node_id,
    /// according to the locally-cached tree.
    [[nodiscard]] std::vector<std::string>
    get_my_permissions(const std::string& node_id) {
        return self().do_get_my_permissions(node_id);
    }

protected:
    ~IClientProvider() = default;

private:
    [[nodiscard]] Derived& self() { return static_cast<Derived&>(*this); }
    [[nodiscard]] const Derived& self() const { return static_cast<const Derived&>(*this); }
};

// ---------------------------------------------------------------------------
// Concept
// ---------------------------------------------------------------------------

/// Concept constraining a valid IClientProvider implementation.
template <typename T>
concept ClientProviderType = requires(
        T t,
        const std::vector<ServerEndpoint>& bootstrap,
        const ServerEndpoint& server,
        const nlohmann::json& creds,
        const tree::TreeDelta& delta,
        const std::string& id,
        const tree::TreeNode& node,
        const nlohmann::json& updates,
        const relay::RelaySelectionCriteria& criteria) {
    { t.do_discover_servers(bootstrap) }       -> std::same_as<std::vector<ServerEndpoint>>;
    { t.do_join_network(server, creds) }       -> std::same_as<JoinResult>;
    { t.do_leave_network() }                   -> std::same_as<bool>;
    { t.do_submit_delta(delta) }               -> std::same_as<TreeModifyResult>;
    { t.do_create_child_node(id, node) }       -> std::same_as<TreeModifyResult>;
    { t.do_update_node(id, updates) }          -> std::same_as<TreeModifyResult>;
    { t.do_get_available_relays(criteria) }    -> std::same_as<std::vector<relay::RelayNodeInfo>>;
    { t.do_get_my_permissions(id) }            -> std::same_as<std::vector<std::string>>;
};

} // namespace nexus::client
