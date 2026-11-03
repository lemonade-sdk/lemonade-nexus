#pragma once

#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Network/RateLimiter.hpp>

#include <httplib.h>

#include <cstdint>
#include <string>

namespace nexus::api {

/// Budget of a device that holds a valid session: requests per minute and
/// the burst it may spend at once. A join or a resume is a burst by nature
/// (join, memberships, routing, DNS, a relay ticket per peer, the device
/// list, the event socket), so the burst covers one of those with room for
/// a retry.
inline constexpr uint32_t kNodeRequestsPerMinute = 600;
inline constexpr uint32_t kNodeRequestBurst = 60;

/// Which bucket a public request spends.
enum class RequestBucket : uint8_t {
    /// Unauthenticated: the per-address bucket (ServerConfig rate_limit_*).
    Address,
    /// A valid session: the per-node bucket (kNodeRequests*).
    Node,
    /// GET /api/tier1/authority: its own per-address bucket
    /// (Tier1ApiHandler kAuthorityPages*).
    Authority,
};

/// The request budget of the public API. Three buckets:
///
/// - A request that carries a valid session token spends the budget of the
///   node the session names, never the address budget. Many devices share
///   one address behind a carrier NAT, and a device's own join burst would
///   otherwise refuse its last requests.
/// - A request without a valid session spends the per-address budget. That
///   is what the address budget is for: unauthenticated routes, probes, and
///   the challenge round-trip before a session exists.
/// - The authority chain walk keeps its own per-address budget, because a
///   client walks the chain before it has a session.
///
/// A valid session moves the request to the node bucket and nothing more:
/// every route still authenticates and authorizes on its own. Thread-safe.
class RequestBudget {
public:
    RequestBudget(const network::RateLimitConfig& addresses, auth::AuthService& auth);

    /// Spends one request from the bucket `req` belongs to. Returns false
    /// when that bucket is empty; the caller answers 429.
    [[nodiscard]] bool allow(const httplib::Request& req);

    /// The bucket `req` would spend, with the key it spends it under.
    struct Charge {
        RequestBucket bucket;
        std::string key;
    };
    [[nodiscard]] Charge charge_for(const httplib::Request& req);

private:
    network::RateLimiter addresses_;
    network::RateLimiter nodes_;
    network::RateLimiter authority_;
    auth::AuthService& auth_;
};

}  // namespace nexus::api
