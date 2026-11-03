#pragma once

#include <LemonadeNexus/Api/IRequestHandler.hpp>

#include <cstdint>
#include <string_view>

namespace nexus::api {

/// GET /api/tier1/authority requests allowed per minute per client address,
/// and the burst, counted apart from the API's general rate limit. A client
/// that starts at Genesis fetches the whole chain page by page before it can
/// send any tree request; under the general burst (20) a chain longer than
/// about 80 epochs at 4 links per page could not be walked in one go. The
/// burst covers 120 pages: 480 epochs at 4 links, 3840 at kMaxHttpChainLinks.
inline constexpr uint32_t kAuthorityPagesPerMinute = 600;
inline constexpr uint32_t kAuthorityPageBurst = 120;

/// True for the path whose requests count against the authority page limit.
[[nodiscard]] inline bool is_authority_chain_path(std::string_view path) {
    return path == "/api/tier1/authority";
}

/// Public endpoints that let a client find and verify Tier 1 servers. Clients
/// send every tree read and write to a Tier 1 server, so they must learn the
/// finalized membership without trusting the server that answers.
///
///   GET /api/tier1/authority?have_epoch=N[&max_links=M]
///     One authority chain page after epoch N (N = 0 starts at Genesis):
///     {"have_epoch":N,"page":"<base64 encode_authority_chain_page>"}.
///     At most M links (clamped to kMaxHttpChainLinks); without max_links,
///     kMaxHandoffChainLinks, the size every SDK decodes. 400 for an M that
///     is not a positive decimal number.
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
