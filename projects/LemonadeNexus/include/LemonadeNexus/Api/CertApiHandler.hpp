#pragma once

#include <LemonadeNexus/Api/IRequestHandler.hpp>

namespace nexus::api {

/// Handles TLS certificate management and ACME certificate issuance endpoints.
/// All routes are private (auth required).
class CertApiHandler : public IRequestHandler<CertApiHandler> {
    friend class IRequestHandler<CertApiHandler>;

public:
    explicit CertApiHandler(ApiContext& ctx) : ctx_(ctx) {}

private:
    void do_register_routes(httplib::Server& pub, httplib::Server& priv);

    ApiContext& ctx_;
};

} // namespace nexus::api
