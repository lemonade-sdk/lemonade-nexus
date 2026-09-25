#pragma once

#include <LemonadeNexus/Api/IRequestHandler.hpp>

#include <string>

namespace nexus::api {

/// Handles unauthenticated auth endpoints: login, passkey registration,
/// Ed25519 challenge issuance, and Ed25519 key registration.
class AuthApiHandler : public IRequestHandler<AuthApiHandler> {
    friend class IRequestHandler<AuthApiHandler>;

public:
    explicit AuthApiHandler(ApiContext& ctx) : ctx_(ctx) {}

private:
    void do_register_routes(httplib::Server& pub, httplib::Server& priv);

    ApiContext& ctx_;
};

} // namespace nexus::api
