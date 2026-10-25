#pragma once

#include <LemonadeNexus/Api/IRequestHandler.hpp>

namespace nexus::api {

/// Public endpoints that let a client find and verify Tier 1 servers. Clients
/// send every tree read and write to a Tier 1 server, so they must learn the
/// finalized membership without trusting the server that answers.
///
///   GET /api/tier1/authority?have_epoch=N
///     One authority chain page after epoch N (N = 0 starts at Genesis):
///     {"have_epoch":N,"page":"<base64 encode_authority_chain_page>"}.
///     Any server answers; the page is candidate data that the client
///     verifies against its pinned Genesis key (Security/Epoch/
///     Tier1Membership.hpp). 404 when the server stores nothing after N.
///
///   GET /api/tier1/proof?nonce=<64 hex characters>
///     A current Tier 1 member's signed endpoint proof over the client nonce:
///     {"node_id","epoch","host","port","signature"} (node_id and signature
///     in base64). The host is the name the server's public certificate
///     covers. Any other server answers 421 with no data.
class Tier1ApiHandler : public IRequestHandler<Tier1ApiHandler> {
    friend class IRequestHandler<Tier1ApiHandler>;

public:
    explicit Tier1ApiHandler(ApiContext& ctx) : ctx_(ctx) {}

private:
    void do_register_routes(httplib::Server& pub, httplib::Server& priv);

    ApiContext& ctx_;
};

}  // namespace nexus::api
