#pragma once

#include <LemonadeNexus/Api/IRequestHandler.hpp>

namespace nexus::api {

/// Routing-layer control plane (private API): profile discovery, request-by-
/// identifier, endpoint register/ready, client connect directive, and session
/// state. All routes require auth; every identifier resolution funnels through
/// the tree's resolve_authorized chokepoint.
class RoutingApiHandler : public IRequestHandler<RoutingApiHandler> {
    friend class IRequestHandler<RoutingApiHandler>;

public:
    explicit RoutingApiHandler(ApiContext& ctx) : ctx_(ctx) {}

private:
    void do_register_routes(httplib::Server& pub, httplib::Server& priv);

    ApiContext& ctx_;
};

} // namespace nexus::api
