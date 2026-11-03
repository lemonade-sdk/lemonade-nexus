#include <LemonadeNexus/Api/RequestBudget.hpp>

#include <LemonadeNexus/Api/Tier1ApiHandler.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>

namespace nexus::api {

RequestBudget::RequestBudget(const network::RateLimitConfig& addresses,
                             auth::AuthService& auth)
    : addresses_(addresses),
      nodes_({kNodeRequestsPerMinute, kNodeRequestBurst}),
      authority_({kAuthorityPagesPerMinute, kAuthorityPageBurst}),
      auth_(auth) {}

RequestBudget::Charge RequestBudget::charge_for(const httplib::Request& req) {
    if (is_authority_chain_path(req.path)) {
        return {RequestBucket::Authority, req.remote_addr};
    }
    if (const auto token = auth::bearer_token(req); !token.empty()) {
        // Validation is the same HMAC check the route repeats; a forged or
        // expired token falls back to the address bucket, so a token that
        // does not verify buys nothing.
        if (const auto claims = auth_.validate_session_claims(token)) {
            return {RequestBucket::Node,
                    claims->node_id.empty() ? claims->user_id : claims->node_id};
        }
    }
    return {RequestBucket::Address, req.remote_addr};
}

bool RequestBudget::allow(const httplib::Request& req) {
    const Charge charge = charge_for(req);
    switch (charge.bucket) {
        case RequestBucket::Authority: return authority_.allow(charge.key);
        case RequestBucket::Node: return nodes_.allow(charge.key);
        case RequestBucket::Address: break;
    }
    return addresses_.allow(charge.key);
}

}  // namespace nexus::api
