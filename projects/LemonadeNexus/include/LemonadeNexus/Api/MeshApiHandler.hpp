#pragma once

#include <LemonadeNexus/Api/IRequestHandler.hpp>

namespace nexus::api {

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
