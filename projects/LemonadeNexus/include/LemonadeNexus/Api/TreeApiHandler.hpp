#pragma once

#include <LemonadeNexus/Api/IRequestHandler.hpp>

namespace nexus::api {

/// Handles tree and IPAM endpoints: join (public), node/delta/children (private), IPAM allocate (private).
class TreeApiHandler : public IRequestHandler<TreeApiHandler> {
    friend class IRequestHandler<TreeApiHandler>;

public:
    explicit TreeApiHandler(ApiContext& ctx) : ctx_(ctx) {}

private:
    void do_register_routes(httplib::Server& pub, httplib::Server& priv);

    ApiContext& ctx_;
};

} // namespace nexus::api
