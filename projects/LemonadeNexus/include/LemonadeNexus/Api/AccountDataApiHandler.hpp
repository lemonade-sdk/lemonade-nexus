#pragma once

#include <LemonadeNexus/Api/IRequestHandler.hpp>

namespace nexus::api {

/// Zero-knowledge account data sync over the PRIVATE mesh API. Stores opaque,
/// client-encrypted blobs owned by the caller's Customer group and never reads
/// their contents:
///   - group-key envelopes: /api/account/keys/envelope, /api/account/keys/pending
///   - encrypted chat blobs: /api/chats[/{id}[/delete]]
/// Ownership is structural (the on-disk category is derived from the caller's
/// own group, never from client input) and additionally gated by tree
/// Read/Write on the Customer node. All routes are private + auth-required.
class AccountDataApiHandler : public IRequestHandler<AccountDataApiHandler> {
    friend class IRequestHandler<AccountDataApiHandler>;

public:
    explicit AccountDataApiHandler(ApiContext& ctx) : ctx_(ctx) {}

private:
    void do_register_routes(httplib::Server& pub, httplib::Server& priv);

    ApiContext& ctx_;
};

} // namespace nexus::api
