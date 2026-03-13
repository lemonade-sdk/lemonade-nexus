#pragma once

#include <LemonadeNexus/Api/IRequestHandler.hpp>
#include <LemonadeNexus/Core/TrustTypes.hpp>
#include <LemonadeNexus/Gossip/GossipTypes.hpp>

#include <string>

namespace nexus::api {

/// Handles administrative endpoints: DDNS, binary attestation, trust status,
/// enrollment management, and governance.  All routes are private (auth required).
class AdminApiHandler : public IRequestHandler<AdminApiHandler> {
    friend class IRequestHandler<AdminApiHandler>;

public:
    explicit AdminApiHandler(ApiContext& ctx) : ctx_(ctx) {}

private:
    void do_register_routes(httplib::Server& pub, httplib::Server& priv);

    // --- Helper methods (moved from main.cpp lambdas) ---

    /// Human-readable name for a TrustTier enum value.
    [[nodiscard]] static std::string tier_name(core::TrustTier t);

    /// Human-readable name for an EnrollmentBallot::State enum value.
    [[nodiscard]] static std::string enrollment_state_name(
        gossip::EnrollmentBallot::State s);

    /// Human-readable name for a GovernanceBallot::State enum value.
    [[nodiscard]] static std::string governance_state_name(
        gossip::GovernanceBallot::State s);

    /// Convert an EnrollmentBallot to a serialisable EnrollmentEntry.
    /// @param include_detail  If true, includes certificate_json and vote signatures.
    [[nodiscard]] static network::EnrollmentEntry ballot_to_entry(
        const gossip::EnrollmentBallot& b, bool include_detail);

    ApiContext& ctx_;
};

} // namespace nexus::api
