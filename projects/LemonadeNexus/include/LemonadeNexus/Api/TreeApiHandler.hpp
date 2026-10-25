#pragma once

#include <LemonadeNexus/Api/IRequestHandler.hpp>

#include <optional>
#include <string>
#include <vector>

namespace nexus::tree {
struct TreeNode;
} // namespace nexus::tree

namespace nexus::api {

/// Handles tree and IPAM endpoints: join (public), node/delta/children (private), IPAM allocate (private).
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
    /// removed. `removed` holds each node as it was before the delete.
    /// Thread-safe to the same degree as the delete routes.
    void cleanup_removed_nodes(const std::vector<tree::TreeNode>& removed);

private:
    void do_register_routes(httplib::Server& pub, httplib::Server& priv);

    // Post-delete cleanup shared by both delete routes (tree operations off)
    // and cleanup_removed_nodes (tree operations on), so they stay
    // behaviorally identical: (1) credential revocation (owner-protected), (2) IPAM releases,
    // (3) mesh peer removal, (4) private EP DNS record removal, (5) removal of
    // the stored device or group loopback certificate. All steps are
    // best-effort; a failure never aborts the cascade. `doomed` is the
    // pre-delete snapshot of the node.
    void cascade_node_cleanup(const std::string& node_id,
                              const std::optional<tree::TreeNode>& doomed);

    // The dataplane and DNS steps of a join that wrote the node: drop the
    // stale peer named by `rekey`, add the client peer for `tunnel_cidr`, and
    // register the private EP record. Returns the registered FQDN (empty
    // without DNS). With tree operations on, a join that commits after its
    // request answered runs this when the commit arrives.
    std::string finish_join_dataplane(const std::string& node_id,
                                      const std::string& tunnel_cidr,
                                      const std::string& client_mesh_pubkey,
                                      bool remove_stale_peer,
                                      const std::string& stale_peer_key);

    ApiContext& ctx_;
};

} // namespace nexus::api
