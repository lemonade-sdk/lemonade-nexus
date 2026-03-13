#include <LemonadeNexus/Api/AdminApiHandler.hpp>

#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Core/BinaryAttestation.hpp>
#include <LemonadeNexus/Core/TeeAttestation.hpp>
#include <LemonadeNexus/Core/TrustPolicy.hpp>
#include <LemonadeNexus/Core/GovernanceService.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Network/DdnsService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>

#include <spdlog/spdlog.h>

namespace nexus::api {

using nexus::auth::require_auth;
using nexus::auth::SessionClaims;

// ---------------------------------------------------------------------------
// Static helper methods
// ---------------------------------------------------------------------------

std::string AdminApiHandler::tier_name(core::TrustTier t) {
    switch (t) {
        case core::TrustTier::Tier1: return "Tier1";
        case core::TrustTier::Tier2: return "Tier2";
        default: return "Untrusted";
    }
}

std::string AdminApiHandler::enrollment_state_name(
        gossip::EnrollmentBallot::State s) {
    switch (s) {
        case gossip::EnrollmentBallot::State::Collecting: return "Collecting";
        case gossip::EnrollmentBallot::State::Approved:   return "Approved";
        case gossip::EnrollmentBallot::State::Rejected:   return "Rejected";
        case gossip::EnrollmentBallot::State::TimedOut:   return "TimedOut";
        default: return "Unknown";
    }
}

std::string AdminApiHandler::governance_state_name(
        gossip::GovernanceBallot::State s) {
    switch (s) {
        case gossip::GovernanceBallot::State::Collecting: return "Collecting";
        case gossip::GovernanceBallot::State::Approved:   return "Approved";
        case gossip::GovernanceBallot::State::Rejected:   return "Rejected";
        case gossip::GovernanceBallot::State::TimedOut:   return "TimedOut";
        default: return "Unknown";
    }
}

network::EnrollmentEntry AdminApiHandler::ballot_to_entry(
        const gossip::EnrollmentBallot& b, bool include_detail) {
    network::EnrollmentEntry entry{
        .request_id          = b.request_id,
        .candidate_pubkey    = b.candidate_pubkey,
        .candidate_server_id = b.candidate_server_id,
        .sponsor_pubkey      = b.sponsor_pubkey,
        .state               = static_cast<uint8_t>(b.state),
        .state_name          = enrollment_state_name(b.state),
        .created_at          = b.created_at,
        .timeout_at          = b.timeout_at,
        .retries             = b.retries,
        .vote_count          = b.votes.size(),
    };
    if (include_detail) {
        entry.certificate_json = b.certificate_json;
    }
    entry.votes.reserve(b.votes.size());
    for (const auto& v : b.votes) {
        network::EnrollmentVoteEntry ve{
            .voter_pubkey = v.voter_pubkey,
            .approve      = v.approve,
            .reason       = v.reason,
            .timestamp    = v.timestamp,
        };
        if (include_detail) ve.signature = v.signature;
        entry.votes.push_back(std::move(ve));
    }
    return entry;
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

void AdminApiHandler::do_register_routes([[maybe_unused]] httplib::Server& pub,
                                         httplib::Server& priv) {
    // POST /api/credentials/request — DDNS credential distribution
    priv.Post("/api/credentials/request", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            nlohmann::json j = network::ErrorResponse{.error = "invalid json"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        auto root_privkey = ctx_.key_wrapping.unlock_identity({});
        auto root_pubkey = ctx_.key_wrapping.load_identity_pubkey();
        if (!root_privkey || !root_pubkey) {
            res.status = 503;
            nlohmann::json j = network::ErrorResponse{.error = "root identity not available"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        auto response = ctx_.ddns.handle_credential_request(body, *root_privkey, *root_pubkey);
        if (!response) {
            res.status = 403;
            nlohmann::json j = network::CredentialErrorResponse{.success = false, .error = "verification failed"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        res.set_content(*response, "application/json");
    }));

    // GET /api/ddns/status — DDNS status
    priv.Get("/api/ddns/status", require_auth(ctx_.auth,
        [this](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        network::DdnsStatusResponse resp{
            .has_credentials = ctx_.ddns.has_credentials(),
            .last_ip         = ctx_.ddns.last_ip(),
            .binary_hash     = ctx_.attestation.self_hash(),
            .binary_approved = ctx_.attestation.is_approved_binary(ctx_.attestation.self_hash()),
        };
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // POST /api/ddns/update — Force DDNS update
    priv.Post("/api/ddns/update", require_auth(ctx_.auth,
        [this](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        bool ok = ctx_.ddns.update_now();
        network::DdnsUpdateResponse resp{
            .success = ok,
            .ip      = ctx_.ddns.last_ip(),
        };
        res.status = ok ? 200 : 500;
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // GET /api/attestation/manifests — List binary attestation manifests
    priv.Get("/api/attestation/manifests", require_auth(ctx_.auth,
        [this](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        auto manifests = ctx_.attestation.get_manifests();
        network::AttestationManifestsResponse resp{
            .self_hash                   = ctx_.attestation.self_hash(),
            .self_approved               = ctx_.attestation.is_approved_binary(ctx_.attestation.self_hash()),
            .github_url                  = ctx_.config.github_releases_url,
            .minimum_version             = ctx_.config.minimum_version,
            .manifest_fetch_interval_sec = ctx_.config.manifest_fetch_interval_sec,
        };
        resp.manifests.reserve(manifests.size());
        for (const auto& m : manifests) {
            resp.manifests.push_back({
                .version       = m.version,
                .platform      = m.platform,
                .binary_sha256 = m.binary_sha256,
                .timestamp     = m.timestamp,
            });
        }
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // POST /api/attestation/fetch — Trigger GitHub manifest fetch
    priv.Post("/api/attestation/fetch", require_auth(ctx_.auth,
        [this](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        auto count = ctx_.attestation.fetch_github_manifests();
        network::AttestationFetchResponse resp{
            .success         = true,
            .new_manifests   = count,
            .total_manifests = ctx_.attestation.get_manifests().size(),
        };
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // GET /api/trust/status — Trust tier status
    priv.Get("/api/trust/status", require_auth(ctx_.auth,
        [this](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        auto our_tier = ctx_.trust_policy.our_tier();
        auto peer_states = ctx_.trust_policy.all_peer_states();

        network::TrustStatusResponse resp{
            .our_tier     = tier_name(our_tier),
            .our_platform = std::string(core::tee_platform_name(ctx_.tee.detected_platform())),
            .require_tee  = ctx_.config.require_tee_attestation,
            .binary_hash  = ctx_.attestation.self_hash(),
            .peer_count   = peer_states.size(),
        };
        resp.peers.reserve(peer_states.size());
        for (const auto& ps : peer_states) {
            resp.peers.push_back({
                .pubkey                = ps.pubkey,
                .tier                  = static_cast<uint8_t>(ps.tier),
                .tier_name             = tier_name(ps.tier),
                .platform              = std::string(core::tee_platform_name(ps.platform)),
                .last_verified         = ps.last_verified,
                .binary_hash           = ps.binary_hash,
                .failed_verifications  = ps.failed_verifications,
            });
        }
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // GET /api/trust/peer/{pubkey} — Peer trust detail
    priv.Get(R"(/api/trust/peer/(.+))", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        auto pubkey = req.matches[1].str();
        auto state = ctx_.trust_policy.peer_state(pubkey);

        network::TrustPeerDetailResponse resp{
            .pubkey                = state.pubkey,
            .tier                  = static_cast<uint8_t>(state.tier),
            .tier_name             = tier_name(state.tier),
            .platform              = std::string(core::tee_platform_name(state.platform)),
            .last_verified         = state.last_verified,
            .attestation_hash      = state.attestation_hash,
            .binary_hash           = state.binary_hash,
            .failed_verifications  = state.failed_verifications,
        };
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // GET /api/enrollment/status — List pending enrollments
    priv.Get("/api/enrollment/status", require_auth(ctx_.auth,
        [this](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        auto ballots = ctx_.gossip.pending_enrollments();
        network::EnrollmentStatusResponse resp{
            .enabled          = ctx_.config.require_peer_confirmation,
            .quorum_ratio     = ctx_.config.enrollment_quorum_ratio,
            .vote_timeout_sec = ctx_.config.enrollment_vote_timeout_sec,
            .pending_count    = ballots.size(),
        };
        resp.enrollments.reserve(ballots.size());
        for (const auto& b : ballots) {
            resp.enrollments.push_back(ballot_to_entry(b, false));
        }
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // GET /api/enrollment/{id} — Get specific enrollment
    priv.Get(R"(/api/enrollment/(.+))", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        auto request_id = req.matches[1].str();
        auto ballots = ctx_.gossip.pending_enrollments();

        for (const auto& b : ballots) {
            if (b.request_id == request_id) {
                auto entry = ballot_to_entry(b, true);
                nlohmann::json j = entry;
                res.set_content(j.dump(), "application/json");
                return;
            }
        }

        res.status = 404;
        nlohmann::json j = network::ErrorResponse{.error = "enrollment not found"};
        res.set_content(j.dump(), "application/json");
    }));

    // GET /api/governance/params — Current governance params
    priv.Get("/api/governance/params", require_auth(ctx_.auth,
        [this](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        res.set_content(ctx_.governance.current_params().dump(), "application/json");
    }));

    // GET /api/governance/proposals — List governance proposals
    priv.Get("/api/governance/proposals", require_auth(ctx_.auth,
        [this](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        auto proposals = ctx_.governance.all_proposals();
        std::vector<network::GovernanceProposalEntry> entries;
        entries.reserve(proposals.size());
        for (const auto& b : proposals) {
            network::GovernanceProposalEntry entry{
                .proposal_id     = b.proposal.proposal_id,
                .proposer_pubkey = b.proposal.proposer_pubkey,
                .parameter       = static_cast<uint8_t>(b.proposal.parameter),
                .new_value       = b.proposal.new_value,
                .old_value       = b.proposal.old_value,
                .rationale       = b.proposal.rationale,
                .created_at      = b.proposal.created_at,
                .expires_at      = b.proposal.expires_at,
                .state           = static_cast<uint8_t>(b.state),
                .state_name      = governance_state_name(b.state),
            };
            entry.votes.reserve(b.votes.size());
            for (const auto& v : b.votes) {
                entry.votes.push_back({
                    .voter_pubkey = v.voter_pubkey,
                    .approve      = v.approve,
                    .reason       = v.reason,
                    .timestamp    = v.timestamp,
                });
            }
            entries.push_back(std::move(entry));
        }
        nlohmann::json j = entries;
        res.set_content(j.dump(), "application/json");
    }));

    // POST /api/governance/propose — Create governance proposal
    priv.Post("/api/governance/propose", require_auth(ctx_.auth,
        [this](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        try {
            auto body = nlohmann::json::parse(req.body);
            auto propose_req = body.get<network::GovernanceProposeRequest>();

            if (propose_req.new_value.empty()) {
                res.status = 400;
                nlohmann::json j = network::ErrorResponse{.error = "new_value required"};
                res.set_content(j.dump(), "application/json");
                return;
            }

            auto param = static_cast<gossip::GovernableParam>(propose_req.parameter);
            auto proposal_id = ctx_.governance.create_proposal(param, propose_req.new_value, propose_req.rationale);
            if (proposal_id.empty()) {
                res.status = 400;
                nlohmann::json j = network::ErrorResponse{.error = "invalid proposal (check parameter and value)"};
                res.set_content(j.dump(), "application/json");
                return;
            }

            network::GovernanceProposeResponse resp{
                .proposal_id = proposal_id,
                .status      = "created",
            };
            nlohmann::json j = resp;
            res.set_content(j.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            nlohmann::json j = network::ErrorResponse{.error = e.what()};
            res.set_content(j.dump(), "application/json");
        }
    }));
}

} // namespace nexus::api
