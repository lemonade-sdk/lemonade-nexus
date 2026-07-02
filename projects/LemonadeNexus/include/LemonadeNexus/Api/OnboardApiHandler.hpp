#pragma once

#include <LemonadeNexus/Api/IRequestHandler.hpp>

namespace nexus::api {

/// Server onboarding endpoints. Public routes let a candidate prove possession
/// of its gossip key and request admission; private (JWT) routes let an admin
/// list and decide pending admissions below the vote threshold.
class OnboardApiHandler : public IRequestHandler<OnboardApiHandler> {
    friend class IRequestHandler<OnboardApiHandler>;

public:
    explicit OnboardApiHandler(ApiContext& ctx) : ctx_(ctx) {}

private:
    void do_register_routes(httplib::Server& pub, httplib::Server& priv);

    /// Assemble {certificate, root_pubkey, seed_peers, wg_*} for an approved poll.
    [[nodiscard]] nlohmann::json approved_bundle(const std::string& cert_json) const;

    ApiContext& ctx_;
};

} // namespace nexus::api
