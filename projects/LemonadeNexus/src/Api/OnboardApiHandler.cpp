#include <LemonadeNexus/Api/OnboardApiHandler.hpp>

#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>
#include <LemonadeNexus/Core/ServerAdmissionService.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>

#include <spdlog/spdlog.h>

#include <chrono>
#include <cstring>
#include <span>

namespace nexus::api {

namespace {

using core::ServerAdmissionService;

/// Verify a candidate's signature over the poll/ack canonical bytes.
bool verify_poll_sig(crypto::SodiumCryptoService& crypto,
                     const std::string& tag,
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
    auto msg = ServerAdmissionService::canonical_poll(tag, request_id, timestamp);
    return crypto.ed25519_verify(pubkey, std::span<const uint8_t>(msg), signature);
}

} // namespace

nlohmann::json OnboardApiHandler::approved_bundle(const std::string& cert_json) const {
    nlohmann::json bundle;
    bundle["state"] = "approved";
    bundle["certificate"] = nlohmann::json::parse(cert_json, nullptr, false);

    // Root anchor as hex — this is what the candidate persists as --root-pubkey.
    if (auto pk = ctx_.key_wrapping.load_identity_pubkey()) {
        bundle["root_pubkey"] = crypto::to_hex(
            std::span<const uint8_t>(pk->data(), pk->size()));
        // Server mesh WG pubkey (X25519), for the candidate's optional handshake probe.
        auto x_pk = crypto::SodiumCryptoService::ed25519_pk_to_x25519(*pk);
        bundle["wg_server_pubkey"] = crypto::to_base64(
            std::span<const uint8_t>(x_pk.data(), x_pk.size()));
    }

    // Seed peers: our own gossip endpoint plus every known peer's endpoint.
    nlohmann::json seeds = nlohmann::json::array();
    if (!ctx_.server_public_ip.empty())
        seeds.push_back(ctx_.server_public_ip + ":" + std::to_string(ctx_.config.gossip_port));
    for (const auto& p : ctx_.gossip.get_peers())
        if (!p.endpoint.empty()) seeds.push_back(p.endpoint);
    bundle["seed_peers"] = seeds;

    if (!ctx_.server_public_ip.empty())
        bundle["wg_endpoint"] =
            ctx_.server_public_ip + ":" + std::to_string(ctx_.config.udp_port);
    return bundle;
}

void OnboardApiHandler::do_register_routes(httplib::Server& pub, httplib::Server& priv) {
    auto& admission = ctx_.admission;

    // ── GET /api/onboard/info (public) ──────────────────────────────────────
    pub.Get("/api/onboard/info", [this, &admission](const httplib::Request&,
                                                     httplib::Response& res) {
        json_response(res, {
            {"accepts_onboarding", admission.accepts_onboarding()},
            {"regime",             admission.regime()},
            {"eligible_voters",    admission.eligible_voter_count()},
            {"dns_base_domain",    ctx_.config.dns_base_domain},
            {"server_fqdn",        ctx_.server_fqdn},
        });
    });

    // ── POST /api/onboard/challenge (public) ────────────────────────────────
    pub.Post("/api/onboard/challenge", [this, &admission](const httplib::Request& req,
                                                          httplib::Response& res) {
        auto body = parse_body(req, res);
        if (!body) return;
        auto candidate_pubkey = body->value("candidate_pubkey", std::string{});
        if (crypto::from_base64(candidate_pubkey).size() != crypto::kEd25519PublicKeySize) {
            error_response(res, "candidate_pubkey must be a base64 Ed25519 key"); return;
        }
        if (!admission.accepts_onboarding()) {
            error_response(res, "this server is not accepting onboarding requests", 403); return;
        }
        json_response(res, {{"nonce", admission.issue_challenge(candidate_pubkey)},
                            {"server_id_required", true}});
    });

    // ── POST /api/onboard/request (public) ──────────────────────────────────
    pub.Post("/api/onboard/request", [this, &admission](const httplib::Request& req,
                                                        httplib::Response& res) {
        auto body = parse_body(req, res);
        if (!body) return;
        ServerAdmissionService::RequestInput in;
        in.candidate_pubkey = body->value("candidate_pubkey", std::string{});
        in.server_id        = body->value("server_id", std::string{});
        in.region           = body->value("region", std::string{});
        in.tpm_ak_pubkey    = body->value("tpm_ak_pubkey", std::string{});
        in.tpm_ek_cert      = body->value("tpm_ek_cert", std::string{});
        in.nonce            = body->value("nonce", std::string{});
        in.timestamp        = body->value("timestamp", uint64_t{0});
        in.signature        = body->value("signature", std::string{});
        in.source_ip        = req.remote_addr;
        auto r = admission.create_request(in);
        if (!r.ok) { error_response(res, r.error, r.status); return; }
        if (r.needs_ballot) admission.start_pending_ballot(r.request_id);
        json_response(res, {{"request_id", r.request_id}, {"state", "pending"}});
    });

    // ── POST /api/onboard/poll (public, candidate-signed) ───────────────────
    pub.Post("/api/onboard/poll", [this, &admission](const httplib::Request& req,
                                                     httplib::Response& res) {
        auto body = parse_body(req, res);
        if (!body) return;
        auto request_id       = body->value("request_id", std::string{});
        auto candidate_pubkey = body->value("candidate_pubkey", std::string{});
        auto timestamp        = body->value("timestamp", uint64_t{0});
        auto signature        = body->value("signature", std::string{});
        if (!verify_poll_sig(ctx_.crypto, "ln-onboard-poll:v1", candidate_pubkey,
                             request_id, timestamp, signature)) {
            error_response(res, "invalid signature", 401); return;
        }
        auto a = admission.status(request_id, candidate_pubkey);
        if (!a) { error_response(res, "no such admission", 404); return; }
        if (a->state == ServerAdmissionService::State::Approved) {
            json_response(res, approved_bundle(a->issued_cert_json)); return;
        }
        json_response(res, {{"state", ServerAdmissionService::state_name(a->state)},
                            {"reason", a->decision_reason}});
    });

    // ── POST /api/onboard/ack (public, candidate-signed) ────────────────────
    pub.Post("/api/onboard/ack", [this, &admission](const httplib::Request& req,
                                                    httplib::Response& res) {
        auto body = parse_body(req, res);
        if (!body) return;
        auto request_id       = body->value("request_id", std::string{});
        auto candidate_pubkey = body->value("candidate_pubkey", std::string{});
        auto timestamp        = body->value("timestamp", uint64_t{0});
        auto signature        = body->value("signature", std::string{});
        if (!verify_poll_sig(ctx_.crypto, "ln-onboard-ack:v1", candidate_pubkey,
                             request_id, timestamp, signature)) {
            error_response(res, "invalid signature", 401); return;
        }
        if (!admission.acknowledge(request_id, candidate_pubkey)) {
            error_response(res, "cannot acknowledge (not approved or unknown)", 409); return;
        }
        json_response(res, {{"state", "completed"}});
    });

    // ── GET /api/onboard/pending (private, JWT) ─────────────────────────────
    priv.Get("/api/onboard/pending", auth::require_auth(ctx_.auth,
        [this, &admission](const httplib::Request&, httplib::Response& res,
                           const auth::SessionClaims&) {
        nlohmann::json arr = nlohmann::json::array();
        for (const auto& a : admission.pending()) {
            arr.push_back({
                {"request_id", a.request_id},
                {"server_id", a.server_id},
                {"region", a.region},
                {"candidate_pubkey", a.candidate_pubkey},
                {"fingerprint", a.candidate_pubkey.substr(0, 16)},
                {"tier1_capable", !a.tpm_ak_pubkey.empty()},
                {"source_ip", a.source_ip},
                {"created_at", a.created_at},
            });
        }
        json_response(res, {{"regime", admission.regime()}, {"pending", arr}});
    }));

    // ── POST /api/onboard/approve/<id> (private, JWT) ───────────────────────
    priv.Post(R"(/api/onboard/approve/([a-f0-9]+))", auth::require_auth(ctx_.auth,
        [this, &admission](const httplib::Request& req, httplib::Response& res,
                           const auth::SessionClaims&) {
        auto body = parse_body(req, res);
        if (!body) return;
        auto request_id = req.matches[1];
        auto fp = body->value("pubkey", body->value("fingerprint", std::string{}));
        bool supersede = body->value("supersede", false);
        auto r = admission.approve(request_id, fp, supersede);
        if (!r.ok) { error_response(res, r.error, r.status); return; }
        json_response(res, {{"state", "approved"}, {"request_id", r.request_id}});
    }));

    // ── POST /api/onboard/deny/<id> (private, JWT) ──────────────────────────
    priv.Post(R"(/api/onboard/deny/([a-f0-9]+))", auth::require_auth(ctx_.auth,
        [this, &admission](const httplib::Request& req, httplib::Response& res,
                           const auth::SessionClaims&) {
        auto body = parse_body(req, res);
        if (!body) return;
        auto request_id = req.matches[1];
        auto reason = body->value("reason", std::string{"denied by admin"});
        auto r = admission.deny(request_id, reason);
        if (!r.ok) { error_response(res, r.error, r.status); return; }
        json_response(res, {{"state", "denied"}, {"request_id", r.request_id}});
    }));
}

} // namespace nexus::api
