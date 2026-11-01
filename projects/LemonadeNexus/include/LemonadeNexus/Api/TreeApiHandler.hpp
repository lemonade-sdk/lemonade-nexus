#pragma once

#include <LemonadeNexus/Api/IRequestHandler.hpp>

#include <nlohmann/json.hpp>

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace nexus::tree {
struct TreeNode;
struct RemovedNode;
} // namespace nexus::tree

namespace nexus::tree {
class PermissionTreeService;
} // namespace nexus::tree

namespace nexus::auth {
struct SessionClaims;
} // namespace nexus::auth

namespace nexus::api {

class PendingJoins;

/// The answer of GET /api/tree/devices/{group} for a session.
struct GroupDevicesAnswer {
    int            status{200};  ///< 200, or 403, 404 or 400 with `error`
    std::string    error;        ///< Empty on 200.
    nlohmann::json body;         ///< {"group_id", "devices"} on 200.
};

/// The devices of `group_id` that the session `claims` may see, as GET
/// /api/tree/devices/{group} answers them: the group's devices and those of
/// its readable subgroups, and the member devices the caller administers,
/// may edit, owns or may connect to. Reads a snapshot of `tree`; thread-safe.
[[nodiscard]] GroupDevicesAnswer tree_group_devices(const tree::PermissionTreeService& tree,
                                                    const auth::SessionClaims& claims,
                                                    const std::string& group_id);

/// The groups the session's identity belongs to, as GET /api/tree/memberships
/// answers them: {"memberships": [{node_id, hostname, parent_id,
/// owner_pubkey, role ("home" or "member"), permissions}]}, with only the
/// identity's own permissions. Reads a snapshot of `tree`; thread-safe.
[[nodiscard]] nlohmann::json tree_memberships(const tree::PermissionTreeService& tree,
                                              const auth::SessionClaims& claims);

/// Handles tree and IPAM endpoints: join and the device-name check (public),
/// node/delta/children (private), IPAM allocate (private).
class TreeApiHandler : public IRequestHandler<TreeApiHandler> {
    friend class IRequestHandler<TreeApiHandler>;

public:
    /// Registers cleanup_removed_nodes as the tree's removed-nodes hook. With
    /// tree operations on, the post-delete cleanup then runs on every server
    /// that applies a delete, not only on the server that took the request.
    /// Construct one handler per tree. `ctx` must outlive this object.
    explicit TreeApiHandler(ApiContext& ctx);

    /// Clears the removed-nodes hook this object registered.
    ~TreeApiHandler();

    TreeApiHandler(const TreeApiHandler&)            = delete;
    TreeApiHandler& operator=(const TreeApiHandler&) = delete;

    /// Run the post-delete cleanup for nodes an applied tree operation
    /// removed. `removed` holds each node as it was before the delete. A node
    /// its own device removed (own_device_left) keeps its key valid; every
    /// other removal revokes a key that no surviving node owns.
    /// Thread-safe to the same degree as the delete routes.
    void cleanup_removed_nodes(const std::vector<tree::RemovedNode>& removed);

private:
    void do_register_routes(httplib::Server& pub, httplib::Server& priv);

    // Post-delete cleanup that cleanup_removed_nodes runs for every node a
    // committed op removed: (1) credential revocation (owner-protected, and
    // skipped when `revoke_key` is false), (2) IPAM releases,
    // (3) mesh peer removal, (4) private EP DNS record removal, (5) removal of
    // the stored device or group loopback certificate. All steps are
    // best-effort; a failure never aborts the cascade. `doomed` is the
    // pre-delete snapshot of the node.
    void cascade_node_cleanup(const std::string& node_id,
                              const std::optional<tree::TreeNode>& doomed, bool revoke_key);

    // The dataplane and DNS steps of a join that wrote the node: drop the
    // stale peer named by `rekey`, add the client peer for `tunnel_cidr`, and
    // register the private EP record. Returns the registered FQDN (empty
    // without DNS). A join that commits after its request answered runs this
    // when the commit arrives.
    std::string finish_join_dataplane(const std::string& node_id,
                                      const std::string& tunnel_cidr,
                                      const std::string& client_mesh_pubkey,
                                      bool remove_stale_peer,
                                      const std::string& stale_peer_key);

    ApiContext& ctx_;
    /// Join operations this server submitted that have not committed yet.
    std::shared_ptr<PendingJoins> pending_joins_;
};

} // namespace nexus::api
