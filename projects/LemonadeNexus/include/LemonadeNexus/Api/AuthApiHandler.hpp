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

    /// Bootstrap or grant permissions on the root node for an Ed25519 pubkey.
    /// If the root node does not exist, creates it with the given key as owner.
    /// If the root node already exists, grants read + add_child on it.
    void ensure_root_node(const std::string& pubkey);

    ApiContext& ctx_;
};

} // namespace nexus::api
