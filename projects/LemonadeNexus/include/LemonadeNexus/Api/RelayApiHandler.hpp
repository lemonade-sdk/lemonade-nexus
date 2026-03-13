#pragma once

#include <LemonadeNexus/Api/IRequestHandler.hpp>

namespace nexus::api {

/// Handles relay endpoints: list, nearest, ticket, register (all private/auth required).
class RelayApiHandler : public IRequestHandler<RelayApiHandler> {
    friend class IRequestHandler<RelayApiHandler>;

public:
    explicit RelayApiHandler(ApiContext& ctx) : ctx_(ctx) {}

private:
    void do_register_routes(httplib::Server& pub, httplib::Server& priv);

    ApiContext& ctx_;
};

} // namespace nexus::api
