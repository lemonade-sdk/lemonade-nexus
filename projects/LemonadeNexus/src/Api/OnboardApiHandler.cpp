#include <LemonadeNexus/Api/OnboardApiHandler.hpp>

#include <LemonadeNexus/ACL/Permission.hpp>
#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>
#include <LemonadeNexus/Core/AdmissionTokenStore.hpp>
#include <LemonadeNexus/Core/ServerAdmissionService.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>

#include <spdlog/spdlog.h>

#include <chrono>
#include <cstring>
#include <span>

namespace nexus::api {

namespace {

using core::ServerAdmissionService;

template <typename T>
std::optional<T> parse_typed_body(const httplib::Request& req, httplib::Response& res) {
    auto json = parse_body(req, res);
    if (!json) return std::nullopt;
    auto decoded = T::fromJson(*json);
    if (!decoded) {
        error_response(res, "invalid request " + decoded.error);
        return std::nullopt;
    }
    return std::move(*decoded.value);
}

/// Verify a candidate's signature over the poll/ack canonical bytes.
bool verify_poll_sig(crypto::SodiumCryptoService& crypto,
                     std::string_view tag,
                     const std::string& candidate_pubkey,
                     const std::string& request_id,
                     uint64_t timestamp,
                     const std::string& sig_b64) {
    auto pk = crypto::from_base64(candidate_pubkey);
    auto sig = crypto::from_base64(sig_b64);
    if (pk.size() != crypto::kEd25519PublicKeySize ||
        sig.size() != crypto::kEd25519SignatureSize) return false;
    crypto::Ed25519PublicKey pubkey{};
    crypto::Ed25519Signature signature{};
    std::memcpy(pubkey.data(), pk.data(), pk.size());
    std::memcpy(signature.data(), sig.data(), sig.size());
    auto msg = core::canonical_onboarding_status(tag, request_id, timestamp);
    return crypto.ed25519_verify(pubkey, std::span<const uint8_t>(msg), signature);
}

} // namespace

std::optional<core::ApprovedOnboardingBundle> OnboardApiHandler::approved_bundle(
        const std::string& cert_json) const {
    const auto certificate_json = nlohmann::json::parse(cert_json, nullptr, false);
    if (certificate_json.is_discarded()) return std::nullopt;

    core::ApprovedOnboardingBundle bundle;
    bundle.state = core::AdmissionState::Approved;
    try {
        bundle.certificate = certificate_json.get<gossip::ServerCertificate>();
    } catch (...) {
        return std::nullopt;
    }

    // Root anchor as hex, sourced from the configured trust anchor — NOT from
    // whichever local identity handled the request. This is what the candidate
    // persists as --root-pubkey. (Issuance is gated on being the root holder, so
    // these coincide, but the anchor is the authoritative source.)
    bundle.root_pubkey = ctx_.config.root_pubkey;
    // Server mesh public key (X25519), for the candidate's optional handshake probe.
    if (auto pk = ctx_.key_wrapping.load_identity_pubkey()) {
        auto x_pk = crypto::SodiumCryptoService::ed25519_pk_to_x25519(*pk);
        bundle.mesh_server_pubkey = crypto::to_base64(
            std::span<const uint8_t>(x_pk.data(), x_pk.size()));
    }

    // Seed peers: our own gossip endpoint plus every known peer's endpoint —
    // preferring what each peer advertises over the UDP source we observed,
    // which can be a NAT/VPN artifact only reachable from our vantage point.
    if (!ctx_.server_public_ip.empty())
        bundle.seed_peers.push_back(ctx_.server_public_ip + ":" +
                                    std::to_string(ctx_.config.gossip_port));
    for (const auto& p : ctx_.gossip.get_peers()) {
        // Only seed an advertised endpoint that gossip confirmed against the
        // peer's real UDP source; an unconfirmed advertisement is attacker-
        // controlled and would poison every future candidate's seed list. Fall
        // back to the observed source otherwise.
        const auto& ep = (p.advertised_confirmed && !p.advertised_endpoint.empty())
                             ? p.advertised_endpoint : p.endpoint;
        if (!ep.empty()) bundle.seed_peers.push_back(ep);
    }

    if (!ctx_.server_public_ip.empty())
        bundle.mesh_endpoint =
            ctx_.server_public_ip + ":" + std::to_string(ctx_.config.udp_port);
    // Lets the candidate seed the address it actually reached us on, which may
    // differ from our self-detected public IP (multihomed/NAT'd genesis).
    bundle.gossip_port = ctx_.config.gossip_port;
    return bundle;
}

void OnboardApiHandler::do_register_routes(httplib::Server& pub, httplib::Server& priv) {
    auto& admission = ctx_.admission;

    // Admitting servers into the mesh is a root-admin action; a valid JWT alone
    // is not enough.
    auto require_admin = [this](const auth::SessionClaims& claims,
                                httplib::Response& res) -> bool {
        if (ctx_.tree.check_permission(normalize_pubkey(claims.pubkey), "root",
                                       acl::Permission::Admin)) {
            return true;
        }
        error_response(res, "admin authorization required", 403);
        return false;
    };

    // ── GET /api/onboard/info (public) ──────────────────────────────────────
    pub.Get("/api/onboard/info", [this, &admission](const httplib::Request&,
                                                     httplib::Response& res) {
        core::OnboardingInfoResponse response;
        response.accepts_onboarding = admission.accepts_onboarding();
        response.dns_base_domain = ctx_.config.dns_base_domain;
        response.server_fqdn = ctx_.server_fqdn;
        json_response(res, response.toJson());
    });

    // ── POST /api/onboard/challenge (public) ────────────────────────────────
    pub.Post("/api/onboard/challenge", [this, &admission](const httplib::Request& req,
                                                          httplib::Response& res) {
        auto request = parse_typed_body<core::ChallengeRequest>(req, res);
        if (!request) return;
        if (!admission.accepts_onboarding()) {
            error_response(res, "this server is not accepting onboarding requests", 403); return;
        }
        core::ChallengeResponse response;
        response.nonce = admission.issue_challenge(request->candidate_pubkey);
        json_response(res, response.toJson());
    });

    // ── POST /api/onboard/request (public) ──────────────────────────────────
    pub.Post("/api/onboard/request", [this, &admission](const httplib::Request& req,
                                                        httplib::Response& res) {
        auto request = parse_typed_body<core::AdmissionRequest>(req, res);
        if (!request) return;
        auto r = admission.create_request(*request, req.remote_addr);
        if (!r.ok) { error_response(res, r.error, r.status); return; }
        core::AdmissionResponse response;
        response.request_id = r.request_id;
        json_response(res, response.toJson());
    });

    // ── POST /api/onboard/poll (public, candidate-signed) ───────────────────
    pub.Post("/api/onboard/poll", [this, &admission](const httplib::Request& req,
                                                     httplib::Response& res) {
        auto request = parse_typed_body<core::PollRequest>(req, res);
        if (!request) return;
        if (!verify_poll_sig(ctx_.crypto, core::kOnboardPollTag,
                             request->candidate_pubkey, request->request_id,
                             request->timestamp, request->signature)) {
            error_response(res, "invalid signature", 401); return;
        }
        auto a = admission.status(request->request_id, request->candidate_pubkey);
        if (!a) { error_response(res, "no such admission", 404); return; }
        if (a->state == core::AdmissionState::Approved) {
            auto response = approved_bundle(a->issued_cert_json);
            if (!response) {
                error_response(res, "stored certificate is invalid", 500);
                return;
            }
            json_response(res, response->toJson());
            return;
        }
        core::AdmissionStatusResponse response;
        response.state = a->state;
        response.reason = a->decision_reason;
        json_response(res, response.toJson());
    });

    // ── POST /api/onboard/ack (public, candidate-signed) ────────────────────
    pub.Post("/api/onboard/ack", [this, &admission](const httplib::Request& req,
                                                    httplib::Response& res) {
        auto request = parse_typed_body<core::AckRequest>(req, res);
        if (!request) return;
        if (!verify_poll_sig(ctx_.crypto, core::kOnboardAckTag,
                             request->candidate_pubkey, request->request_id,
                             request->timestamp, request->signature)) {
            error_response(res, "invalid signature", 401); return;
        }
        if (!admission.acknowledge(request->request_id, request->candidate_pubkey)) {
            error_response(res, "cannot acknowledge (not approved or unknown)", 409); return;
        }
        json_response(res, core::AckResponse{}.toJson());
    });

    // ── GET /api/onboard/pending (private, JWT) ─────────────────────────────
    priv.Get("/api/onboard/pending", auth::require_auth(ctx_.auth,
        [this, &admission, require_admin](const httplib::Request&, httplib::Response& res,
                           const auth::SessionClaims& claims) {
        if (!require_admin(claims, res)) return;
        core::PendingAdmissionsResponse response;
        for (const auto& a : admission.pending()) {
            core::PendingAdmissionSummary summary;
            summary.request_id = a.request_id;
            summary.server_id = a.server_id;
            summary.region = a.region;
            summary.candidate_pubkey = a.candidate_pubkey;
            summary.fingerprint = a.candidate_pubkey.substr(0, 16);
            summary.tier1_capable = !a.tpm_ak_pubkey.empty();
            summary.source_ip = a.source_ip;
            summary.created_at = a.created_at;
            response.pending.push_back(std::move(summary));
        }
        json_response(res, response.toJson());
    }));

    // ── POST /api/onboard/approve/<id> (private, JWT) ───────────────────────
    priv.Post(R"(/api/onboard/approve/([a-f0-9]+))", auth::require_auth(ctx_.auth,
        [this, &admission, require_admin](const httplib::Request& req, httplib::Response& res,
                           const auth::SessionClaims& claims) {
        if (!require_admin(claims, res)) return;
        auto request = parse_typed_body<core::ApprovalRequest>(req, res);
        if (!request) return;
        auto request_id = req.matches[1];
        auto fp = request->pubkey.value_or(request->fingerprint.value_or(""));
        bool supersede = request->supersede.value_or(false);
        auto r = admission.approve(request_id, fp, supersede);
        if (!r.ok) { error_response(res, r.error, r.status); return; }
        core::AdmissionDecisionResponse response;
        response.state = core::AdmissionState::Approved;
        response.request_id = r.request_id;
        json_response(res, response.toJson());
    }));

    // ── POST /api/onboard/deny/<id> (private, JWT) ──────────────────────────
    priv.Post(R"(/api/onboard/deny/([a-f0-9]+))", auth::require_auth(ctx_.auth,
        [this, &admission, require_admin](const httplib::Request& req, httplib::Response& res,
                           const auth::SessionClaims& claims) {
        if (!require_admin(claims, res)) return;
        auto request = parse_typed_body<core::DenialRequest>(req, res);
        if (!request) return;
        auto request_id = req.matches[1];
        auto reason = request->reason.value_or("denied by admin");
        auto r = admission.deny(request_id, reason);
        if (!r.ok) { error_response(res, r.error, r.status); return; }
        core::AdmissionDecisionResponse response;
        response.state = core::AdmissionState::Denied;
        response.request_id = r.request_id;
        json_response(res, response.toJson());
    }));

    // ── POST /api/onboard/token (private, JWT + root admin) ─────────────────
    // Mints a single-use server-admission enrollment token. The response is a
    // complete invitation payload (token + root anchor) for out-of-band handoff.
    priv.Post("/api/onboard/token", auth::require_auth(ctx_.auth,
        [this, &admission, require_admin](const httplib::Request& req, httplib::Response& res,
                           const auth::SessionClaims& claims) {
        if (!require_admin(claims, res)) return;
        auto request = parse_typed_body<core::AdmissionTokenRequest>(req, res);
        if (!request) return;
        auto ttl = std::chrono::seconds{request->ttl_sec.value_or(
            static_cast<uint64_t>(core::AdmissionTokenStore::kDefaultTtl.count()))};
        auto minted = admission.mint_admission_token(
            request->candidate_pubkey, ttl, request->server_id.value_or(""));
        if (!minted) {
            error_response(res, "this server does not hold the root key or "
                                "onboarding is disabled", 503); return;
        }
        core::AdmissionInvitation response;
        response.enrollment_token = minted->first;
        response.expires_at = minted->second.expires_at;
        response.candidate_pubkey = minted->second.candidate_pubkey;
        response.server_id = minted->second.server_id;
        response.root_pubkey = ctx_.config.root_pubkey;
        json_response(res, response.toJson());
    }));
}

} // namespace nexus::api
