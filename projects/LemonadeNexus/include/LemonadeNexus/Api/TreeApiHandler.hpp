#pragma once

#include <LemonadeNexus/Api/IRequestHandler.hpp>

#include <optional>
#include <string>

namespace nexus::tree {
struct TreeNode;
} // namespace nexus::tree

namespace nexus::api {

/// Handles tree and IPAM endpoints: join (public), node/delta/children (private), IPAM allocate (private).
class TreeApiHandler : public IRequestHandler<TreeApiHandler> {
    friend class IRequestHandler<TreeApiHandler>;

public:
    explicit TreeApiHandler(ApiContext& ctx) : ctx_(ctx) {}

private:
    void do_register_routes(httplib::Server& pub, httplib::Server& priv);

    // Post-delete cleanup shared by both delete routes so they stay behaviorally
    // identical: (1) credential revocation (owner-protected), (2) IPAM releases,
    // (3) mesh peer removal, (4) private EP DNS record removal. All steps are
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
