#pragma once

#include <LemonadeNexus/Api/IRequestHandler.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>

#include <string_view>

namespace nexus::api {

/// Decide whether the mesh peer list of `caller_pubkey` includes `peer`.
///
/// The client adds every listed peer to its dataplane, so a listed peer is a
/// peer the caller can reach. An Endpoint is listed only when the caller holds
/// ConnectPrivate or ConnectShared on that node. This is the per-node rule of
/// PermissionTreeService::resolve_authorized. Read alone lets the caller see a
/// node in the tree; it does not let the caller connect to it. Permissions are
/// not inherited, so an assignment on a parent group does not count.
///
/// A Relay is listed when the caller holds Read on it: a relay carries traffic
/// for others, and the relay protocol authorizes each relay session.
///
/// The caller must already limit `peer` to the requester's parent-group
/// subtree and exclude the requester's own node. `caller_pubkey` must be
/// normalized. Returns false for every other node type. Thread-safe.
[[nodiscard]] bool mesh_peer_listed(const tree::PermissionTreeService& tree,
                                    std::string_view caller_pubkey,
                                    const tree::TreeNode& peer);

/// Handles mesh networking endpoints: peer discovery and heartbeat reporting.
class MeshApiHandler : public IRequestHandler<MeshApiHandler> {
    friend class IRequestHandler<MeshApiHandler>;

public:
    explicit MeshApiHandler(ApiContext& ctx) : ctx_(ctx) {}

private:
    void do_register_routes(httplib::Server& pub, httplib::Server& priv);

    /// Build the server peer JSON entry (always included in peer lists).
    [[nodiscard]] nlohmann::json build_server_peer() const;

    ApiContext& ctx_;
};

} // namespace nexus::api
