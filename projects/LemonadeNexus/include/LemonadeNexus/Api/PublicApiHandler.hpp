#pragma once

#include <LemonadeNexus/Api/IRequestHandler.hpp>

namespace nexus::api {

/// Handles unauthenticated public endpoints: health, TLS status, stats, servers.
class PublicApiHandler : public IRequestHandler<PublicApiHandler> {
    friend class IRequestHandler<PublicApiHandler>;

public:
    explicit PublicApiHandler(ApiContext& ctx) : ctx_(ctx) {}

private:
    void do_register_routes(httplib::Server& pub, httplib::Server& priv);

    ApiContext& ctx_;
};

} // namespace nexus::api
