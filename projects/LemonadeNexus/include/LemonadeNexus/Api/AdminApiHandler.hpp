#pragma once

#include <LemonadeNexus/Api/IRequestHandler.hpp>

#include <string>

namespace nexus::api {

/// Handles administrative endpoints: DDNS credentials and binary attestation
/// manifests. All routes are private (auth required). Trust, enrollment, and
/// governance surfaces are gone: mesh authority lives in the security system.
class AdminApiHandler : public IRequestHandler<AdminApiHandler> {
    friend class IRequestHandler<AdminApiHandler>;

public:
    explicit AdminApiHandler(ApiContext& ctx) : ctx_(ctx) {}

private:
    void do_register_routes(httplib::Server& pub, httplib::Server& priv);

    ApiContext& ctx_;
};

} // namespace nexus::api
