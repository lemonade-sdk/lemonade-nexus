#include <LemonadeNexus/Core/ServerAdmissionService.hpp>

#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Core/TrustPolicy.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Gossip/ServerCertificate.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <array>
#include <chrono>
#include <cstring>

namespace nexus::core {

using json = nlohmann::json;

namespace {

uint64_t now_unix() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

void put_lp(std::vector<uint8_t>& buf, const std::string& s) {
    uint32_t n = static_cast<uint32_t>(s.size());
    for (int i = 0; i < 4; ++i) buf.push_back((n >> (i * 8)) & 0xFF);
    buf.insert(buf.end(), s.begin(), s.end());
}

} // namespace

const char* ServerAdmissionService::state_name(State s) {
    switch (s) {
        case State::Pending:   return "pending";
        case State::Approved:  return "approved";
        case State::Denied:    return "denied";
        case State::Expired:   return "expired";
        case State::Completed: return "completed";
    }
    return "unknown";
}

ServerAdmissionService::ServerAdmissionService(
        const ServerConfig& config,
        crypto::SodiumCryptoService& crypto,
        crypto::KeyWrappingService& key_wrapping,
        storage::FileStorageService& storage,
        gossip::GossipService& gossip,
        TrustPolicyService* trust_policy)
    : config_(config), crypto_(crypto), key_wrapping_(key_wrapping),
      storage_(storage), gossip_(gossip), trust_policy_(trust_policy),
      tokens_(storage, crypto) {
    cfg_.enabled                = config.onboard_enabled;
    cfg_.admission_quorum_ratio  = config.admission_quorum_ratio;
    cfg_.min_tier1_for_vote      = config.onboard_min_tier1_for_vote;
    cfg_.request_ttl_sec         = config.onboard_request_ttl_sec;
    cfg_.max_pending             = config.onboard_max_pending;
}

std::vector<uint8_t> ServerAdmissionService::canonical_request(const RequestInput& in) {
    std::vector<uint8_t> buf;
    put_lp(buf, "ln-onboard:v1");
    put_lp(buf, in.nonce);
    put_lp(buf, in.candidate_pubkey);
    put_lp(buf, in.server_id);
    put_lp(buf, in.region);
    put_lp(buf, in.tpm_ak_pubkey);
    put_lp(buf, std::to_string(in.timestamp));
    return buf;
}

std::vector<uint8_t> ServerAdmissionService::canonical_poll(
        const std::string& tag, const std::string& request_id, uint64_t timestamp) {
    std::vector<uint8_t> buf;
    put_lp(buf, tag);
    put_lp(buf, request_id);
    put_lp(buf, std::to_string(timestamp));
    return buf;
}

void ServerAdmissionService::on_start() {
    load();

    // Only a server whose own identity IS the configured root anchor may issue
    // certificates. Compare the raw key bytes so hex casing never matters;
    // malformed config hex means not-the-holder, not a crash.
    auto lp = key_wrapping_.load_identity_pubkey();
    std::vector<uint8_t> want;
    try { want = crypto::from_hex(config_.root_pubkey); } catch (...) {}
    is_root_key_holder_ = lp && want.size() == crypto::kEd25519PublicKeySize &&
                          std::memcmp(lp->data(), want.data(), want.size()) == 0;

    spdlog::info("[ServerAdmissionService] started ({} persisted admission(s), accepts_onboarding={})",
                 admissions_.size(), accepts_onboarding());

    // A root holder without its own certificate never sends ServerHello, so
    // servers it admits can exchange digests with it but never verify it or
    // sync state — a confusing half-joined mesh.
    if (accepts_onboarding() && !storage_.read_file("identity", "server_cert.json")) {
        spdlog::warn("[ServerAdmissionService] this server issues certificates but has NO "
                     "certificate of its own — peers cannot verify it and state will not "
                     "sync. Self-enroll once: --enroll-server '<own gossip pubkey>' <server-id>");
    }
}

void ServerAdmissionService::on_stop() {
    persist();
}

bool ServerAdmissionService::accepts_onboarding() const {
    // No fail-open: onboarding is advertised/accepted only by the server whose
    // local identity actually holds the root key — not merely one that has a
    // root_pubkey configured (every enrolled server does).
    return cfg_.enabled && !config_.root_pubkey.empty() && is_root_key_holder_;
}

uint32_t ServerAdmissionService::eligible_voter_count() const {
    if (trust_policy_) {
        uint32_t n = 0;
        for (const auto& s : trust_policy_->all_peer_states())
            if (s.tier == TrustTier::Tier1) ++n;
        return n;
    }
    // Reduced assurance: without a trust policy, count cert-verified enrolled peers.
    uint32_t n = 0;
    for (const auto& p : gossip_.get_peers())
        if (!p.certificate_json.empty()) ++n;
    return n;
}

std::string ServerAdmissionService::regime() const {
    return eligible_voter_count() >= cfg_.min_tier1_for_vote ? "vote" : "sole_discretion";
}

bool ServerAdmissionService::verify_sig(const std::string& pubkey_b64,
                                        const std::vector<uint8_t>& msg,
                                        const std::string& sig_b64) const {
    auto pk = crypto::from_base64(pubkey_b64);
    auto sig = crypto::from_base64(sig_b64);
    if (pk.size() != crypto::kEd25519PublicKeySize ||
        sig.size() != crypto::kEd25519SignatureSize) {
        return false;
    }
    crypto::Ed25519PublicKey pubkey{};
    crypto::Ed25519Signature signature{};
    std::memcpy(pubkey.data(), pk.data(), pk.size());
    std::memcpy(signature.data(), sig.data(), sig.size());
    return crypto_.ed25519_verify(pubkey, std::span<const uint8_t>(msg), signature);
}

std::string ServerAdmissionService::issue_challenge(const std::string& candidate_pubkey) {
    std::lock_guard lock(mu_);
    std::array<uint8_t, 32> raw{};
    crypto_.random_bytes(std::span<uint8_t>(raw));
    auto nonce = crypto::to_base64(std::span<const uint8_t>(raw));
    nonces_[candidate_pubkey]       = now_unix() + cfg_.nonce_ttl_sec;
    nonce_values_[candidate_pubkey] = nonce;
    return nonce;
}

std::optional<std::pair<std::string, AdmissionTokenRecord>>
ServerAdmissionService::mint_admission_token(const std::string& candidate_pubkey,
                                             std::chrono::seconds ttl,
                                             const std::string& server_id) {
    // Only the root holder may pre-authorize admissions.
    if (!accepts_onboarding()) return std::nullopt;
    return tokens_.mint(candidate_pubkey, ttl, server_id);
}

ServerAdmissionService::Result ServerAdmissionService::create_request(const RequestInput& in) {
    if (!accepts_onboarding())
        return {false, 403, "this server is not accepting onboarding requests", ""};
    if (!gossip::valid_server_id_label(in.server_id))
        return {false, 400, "server_id must be a DNS label [a-z0-9-], 1-63 chars", ""};

    const auto now = now_unix();

    std::lock_guard lock(mu_);
    sweep_expired();

    // Replay/freshness window.
    if (in.timestamp + cfg_.nonce_ttl_sec < now || in.timestamp > now + cfg_.nonce_ttl_sec)
        return {false, 400, "stale request timestamp", ""};

    // Proof of possession: single-use nonce bound to the candidate pubkey.
    auto nv = nonce_values_.find(in.candidate_pubkey);
    if (nv == nonce_values_.end() || nv->second != in.nonce)
        return {false, 401, "missing or invalid challenge nonce", ""};
    if (!verify_sig(in.candidate_pubkey, canonical_request(in), in.signature))
        return {false, 401, "signature verification failed", ""};
    // Consume the nonce regardless of downstream outcome.
    nonces_.erase(in.candidate_pubkey);
    nonce_values_.erase(in.candidate_pubkey);

    // Denied-pubkey cooldown.
    if (auto it = denied_until_.find(in.candidate_pubkey);
        it != denied_until_.end() && it->second > now)
        return {false, 429, "this identity was recently denied; try again later", ""};

    // Enrollment token: below the vote threshold a valid token admits
    // immediately; in the vote regime the quorum ballot governs and the token
    // is neither honored nor consumed.
    const bool below_vote = eligible_voter_count() < cfg_.min_tier1_for_vote;
    bool token_admit = false;
    if (!in.enrollment_token.empty()) {
        if (below_vote) {
            auto rec = tokens_.verify(in.enrollment_token, in.candidate_pubkey);
            if (!rec)
                return {false, 403, "invalid, expired, or already-used enrollment token", ""};
            // The onboarding transport is not authenticated (cert verification
            // is disabled and plain HTTP is permitted), so a bearer token must
            // be bound to the candidate key — an intermediary must not be able
            // to capture an unbound token and spend it with its own key.
            if (rec->candidate_pubkey.empty())
                return {false, 403, "enrollment token is not bound to a candidate key", ""};
            // A token bound to a server_id may admit only that identity — the
            // candidate does not get to choose server_id freely.
            if (!rec->server_id.empty() && rec->server_id != in.server_id)
                return {false, 403, "enrollment token is bound to a different server_id", ""};
            token_admit = true;
        } else {
            // Vote regime: the ballot governs and the token cannot admit. Burn it
            // now regardless — an unspent token must never survive to be re-spent
            // if churn later drops the mesh below the vote threshold.
            (void)tokens_.consume(in.enrollment_token, in.candidate_pubkey);
            spdlog::info("[ServerAdmissionService] vote regime — enrollment token "
                         "consumed and ignored; ballot governs");
        }
    }

    // Never let a candidate claim THIS root server's own identity — our own
    // certificate is not in get_peers(), so the peer scan below cannot catch it.
    if (auto self = gossip_.our_server_id(); self && *self == in.server_id)
        return {false, 409, "server_id is reserved by the root server", ""};

    // server_id uniqueness vs enrolled peers — runs before any approval or
    // token consumption so a conflict never burns a token.
    for (const auto& p : gossip_.get_peers()) {
        if (p.certificate_json.empty()) continue;
        try {
            auto cj = json::parse(p.certificate_json);
            if (cj.value("server_id", "") == in.server_id &&
                cj.value("server_pubkey", "") != in.candidate_pubkey)
                return {false, 409, "server_id already in use by another server", ""};
        } catch (...) {}
    }

    // Also reject a collision with another in-flight or already-issued admission:
    // get_peers() only lists peers past ServerHello, so two candidates could race
    // for one server_id before either cert appears there.
    for (const auto& [rid, other] : admissions_) {
        if ((other.state == State::Pending || other.state == State::Approved) &&
            other.server_id == in.server_id && other.candidate_pubkey != in.candidate_pubkey)
            return {false, 409, "server_id already claimed by another admission", ""};
    }

    // Reuse an existing pending record for this candidate (idempotent retry),
    // else allocate a fresh request_id.
    std::string request_id;
    bool is_existing = false;
    for (const auto& [rid, a] : admissions_) {
        if (a.candidate_pubkey == in.candidate_pubkey && a.state == State::Pending) {
            request_id = rid; is_existing = true; break;
        }
    }

    // Capacity — only a brand-new, non-token pending record counts against it;
    // cheap self-signed pending spam must not lock out a valid token.
    if (!is_existing && !token_admit) {
        uint32_t pending_count = 0;
        for (const auto& [rid, a] : admissions_)
            if (a.state == State::Pending) ++pending_count;
        if (pending_count >= cfg_.max_pending)
            return {false, 429, "too many pending admissions; try again later", ""};
    }

    if (!is_existing) {
        std::array<uint8_t, 16> rid_raw{};
        crypto_.random_bytes(std::span<uint8_t>(rid_raw));
        request_id = crypto::to_hex(std::span<const uint8_t>(rid_raw));
    }

    // Build/refresh the record from the CURRENT signed request — never from a
    // stale earlier one, so the issued cert always binds the fields this
    // request proved possession of.
    Admission& a = admissions_[request_id];
    a.request_id       = request_id;
    a.candidate_pubkey = in.candidate_pubkey;
    a.server_id        = in.server_id;
    a.region           = in.region;
    a.tpm_ak_pubkey    = in.tpm_ak_pubkey;
    a.tpm_ek_cert      = in.tpm_ek_cert;
    a.source_ip        = in.source_ip;
    a.expires_at       = now + cfg_.request_ttl_sec;
    if (!is_existing) {
        a.state = State::Pending;
        a.created_at = now;
        // Fix the decision mode at creation and persist it — a later change in
        // the eligible-voter count (or a restart) must not turn a ballot-governed
        // request back into an admin-resolvable one.
        a.decision_mode = below_vote ? "sole" : "ballot";
    }

    // Token admission (sole-discretion regime only). Consume fail-closed:
    // spend the token BEFORE issuing and require it to actually be removed, so
    // a delete failure can never leave a reusable bearer credential. The
    // server_id-uniqueness 409 is already checked above, so the common failure
    // can't burn a token; a rarer issuance failure requires a fresh token.
    if (token_admit) {
        // A request created under the vote regime is ballot-governed for life
        // (decision_mode fixed + persisted). If churn later drops the mesh below
        // the vote threshold, re-submitting the still-unspent token must NOT
        // re-open it — only the ballot can resolve it.
        if (a.decision_mode == "ballot") {
            if (!is_existing) admissions_.erase(request_id);
            return {false, 409, "ballot governs this admission; a token cannot admit it", ""};
        }
        if (!tokens_.consume(in.enrollment_token, in.candidate_pubkey)) {
            if (!is_existing) admissions_.erase(request_id);  // no phantom record
            return {false, 403, "enrollment token already used", ""};
        }
        auto r = do_approve_locked(a, "token", /*supersede=*/false);
        if (!r.ok) {
            if (!is_existing) admissions_.erase(request_id);
            persist();
            return r;
        }
        spdlog::info("[ServerAdmissionService] admitted '{}' via enrollment token",
                     in.server_id);
        persist();
        return {true, 200, "", request_id};
    }

    // Non-token retry of an already-pending request: refresh only, no duplicate
    // ballot.
    if (is_existing) {
        persist();
        return {true, 200, "", request_id};
    }

    // New record above the vote threshold: defer to a governed Tier1 ballot.
    // Store the candidate's self-signed claim so peers can verify it; the
    // handler kicks the ballot after this call returns. The enrollment token is
    // deliberately excluded — the claim is gossip-replicated and must never
    // carry token material.
    if (!below_vote) {
        json claim{{"candidate_pubkey", in.candidate_pubkey}, {"server_id", in.server_id},
                   {"region", in.region}, {"tpm_ak_pubkey", in.tpm_ak_pubkey},
                   {"nonce", in.nonce}, {"timestamp", in.timestamp},
                   {"signature", in.signature}};
        a.ballot_claim_json = claim.dump();
    }

    persist();
    spdlog::info("[ServerAdmissionService] pending admission '{}' for server_id '{}' (regime={})",
                 request_id, in.server_id, regime());

    Result r{true, 200, "", request_id};
    r.needs_ballot = !below_vote;
    return r;
}

void ServerAdmissionService::start_pending_ballot(const std::string& request_id) {
    std::string cpk, sid, claim;
    float ratio;
    {
        std::lock_guard lock(mu_);
        auto it = admissions_.find(request_id);
        if (it == admissions_.end() || it->second.ballot_claim_json.empty()) return;
        cpk   = it->second.candidate_pubkey;
        sid   = it->second.server_id;
        claim = it->second.ballot_claim_json;
        ratio = cfg_.admission_quorum_ratio;
    }
    gossip_.start_admission_ballot(request_id, cpk, sid, claim, ratio);
}

void ServerAdmissionService::on_ballot_decision(const std::string& request_id,
                                                bool approved, const std::string& reason) {
    std::lock_guard lock(mu_);
    auto it = admissions_.find(request_id);
    if (it == admissions_.end()) return;   // not one of ours (e.g. legacy enrollment)
    auto& a = it->second;
    if (a.state != State::Pending) return;
    if (approved) {
        (void)do_approve_locked(a, "ballot", /*supersede=*/false);
    } else {
        a.state = State::Denied;
        a.decision_reason = reason;
        a.decided_by = "ballot";
        denied_until_[a.candidate_pubkey] = now_unix() + cfg_.denied_cooldown_sec;
    }
    persist();
}

ServerAdmissionService::Result ServerAdmissionService::do_approve_locked(
        Admission& a, const std::string& decided_by, bool supersede) {
    // Defense-in-depth invariant: a ballot-governed admission may only be
    // resolved by the ballot itself (decided_by=='ballot'). No token or admin
    // path may reach issuance for it, whatever the current regime.
    if (a.decision_mode == "ballot" && decided_by != "ballot")
        return {false, 409, "ballot governs this admission; cannot approve out of band",
                a.request_id};

    // Re-check at issuance: never sign a server certificate unless this server's
    // identity is the configured root anchor. The local identity below would
    // otherwise self-sign a cert peers reject, from a server that shouldn't issue.
    if (!is_root_key_holder_)
        return {false, 403, "not the root-key holder — cannot issue server certificate",
                a.request_id};

    auto root_sk = key_wrapping_.unlock_identity({});
    auto root_pk = key_wrapping_.load_identity_pubkey();
    if (!root_sk || !root_pk)
        return {false, 500, "root identity unavailable — cannot issue certificate", a.request_id};

    // Supersede: revoke any existing cert bound to this server_id under a
    // different pubkey before issuing the new one.
    for (const auto& p : gossip_.get_peers()) {
        if (p.certificate_json.empty()) continue;
        try {
            auto cj = json::parse(p.certificate_json);
            if (cj.value("server_id", "") == a.server_id &&
                cj.value("server_pubkey", "") != a.candidate_pubkey) {
                if (!supersede)
                    return {false, 409, "server_id bound to a different pubkey; pass supersede=true",
                            a.request_id};
                auto old_pk = cj.value("server_pubkey", "");
                // Route the revocation through GossipService so its in-memory
                // revoked set stays authoritative — a direct file write here is
                // silently clobbered the next time GossipService persists from
                // its own (stale) in-memory list.
                gossip_.add_revoked_server(old_pk);
                spdlog::warn("[ServerAdmissionService] superseded server_id '{}': revoked old pubkey {}",
                             a.server_id, old_pk);
            }
        } catch (...) {}
    }

    gossip::CertIssueParams params;
    params.server_pubkey_b64 = a.candidate_pubkey;
    params.server_id         = a.server_id;
    params.tpm_ak_pubkey     = a.tpm_ak_pubkey;
    params.tpm_ek_cert       = a.tpm_ek_cert;
    params.expires_at        = 0;  // no expiry (renewal machinery is a follow-up)

    auto cert = gossip::issue_server_certificate(params, crypto_, *root_sk, *root_pk);
    json cert_json = cert;
    a.issued_cert_json = cert_json.dump();
    a.state            = State::Approved;
    a.decided_by       = decided_by;
    ever_approved_     = true;

    spdlog::info("[ServerAdmissionService] approved '{}' (server_id '{}', by {}, tier {})",
                 a.request_id, a.server_id, decided_by,
                 a.tpm_ak_pubkey.empty() ? "2" : "1-capable");
    return {true, 200, "", a.request_id};
}

std::optional<ServerAdmissionService::Admission> ServerAdmissionService::status(
        const std::string& request_id, const std::string& candidate_pubkey) {
    std::lock_guard lock(mu_);
    sweep_expired();
    auto it = admissions_.find(request_id);
    if (it == admissions_.end()) return std::nullopt;
    if (it->second.candidate_pubkey != candidate_pubkey) return std::nullopt;
    return it->second;
}

bool ServerAdmissionService::acknowledge(const std::string& request_id,
                                         const std::string& candidate_pubkey) {
    std::lock_guard lock(mu_);
    auto it = admissions_.find(request_id);
    if (it == admissions_.end() || it->second.candidate_pubkey != candidate_pubkey)
        return false;
    if (it->second.state != State::Approved) return false;
    it->second.state = State::Completed;
    persist();
    return true;
}

std::vector<ServerAdmissionService::Admission> ServerAdmissionService::pending() const {
    std::lock_guard lock(mu_);
    std::vector<Admission> out;
    for (const auto& [rid, a] : admissions_)
        if (a.state == State::Pending) out.push_back(a);
    return out;
}

ServerAdmissionService::Result ServerAdmissionService::approve(
        const std::string& request_id, const std::string& pubkey_or_fingerprint, bool supersede) {
    std::lock_guard lock(mu_);
    auto it = admissions_.find(request_id);
    if (it == admissions_.end()) return {false, 404, "no such admission", request_id};
    auto& a = it->second;
    if (a.state != State::Pending) return {false, 409, "admission is not pending", request_id};

    // A ballot-governed admission (its decision mode was fixed at creation and
    // persisted) is resolved only by the Tier-1 quorum via on_ballot_decision().
    // An admin must not be able to admit ahead of the vote, or the quorum would
    // be advisory.
    if (a.decision_mode == "ballot")
        return {false, 409, "ballot governs this admission; only a Tier-1 quorum can resolve it",
                request_id};

    // Out-of-band verification duty: admin must echo the candidate's pubkey or
    // its first-16-hex fingerprint.
    const auto fp = a.candidate_pubkey.substr(0, 16);
    if (pubkey_or_fingerprint != a.candidate_pubkey &&
        pubkey_or_fingerprint != fp)
        return {false, 400, "pubkey/fingerprint does not match the pending candidate", request_id};

    auto r = do_approve_locked(a, "admin", supersede);
    persist();
    return r;
}

ServerAdmissionService::Result ServerAdmissionService::deny(
        const std::string& request_id, const std::string& reason) {
    std::lock_guard lock(mu_);
    auto it = admissions_.find(request_id);
    if (it == admissions_.end()) return {false, 404, "no such admission", request_id};
    auto& a = it->second;
    if (a.state != State::Pending) return {false, 409, "admission is not pending", request_id};

    // A ballot-governed admission is resolved only by the Tier-1 quorum; an admin
    // must not be able to terminate the pending ballot unilaterally.
    if (a.decision_mode == "ballot")
        return {false, 409, "ballot governs this admission; only a Tier-1 quorum can resolve it",
                request_id};

    a.state = State::Denied;
    a.decision_reason = reason;
    a.decided_by = "admin";
    denied_until_[a.candidate_pubkey] = now_unix() + cfg_.denied_cooldown_sec;
    persist();
    spdlog::info("[ServerAdmissionService] denied '{}' ({})", request_id, reason);
    return {true, 200, "", request_id};
}

void ServerAdmissionService::sweep_expired() {
    // caller holds mu_
    const auto now = now_unix();
    for (auto& [rid, a] : admissions_) {
        if (a.state == State::Pending && a.expires_at < now) {
            a.state = State::Expired;
            a.decision_reason = "request timed out";
        }
    }
    for (auto it = nonces_.begin(); it != nonces_.end();) {
        if (it->second < now) { nonce_values_.erase(it->first); it = nonces_.erase(it); }
        else ++it;
    }
    for (auto it = denied_until_.begin(); it != denied_until_.end();)
        it = (it->second < now) ? denied_until_.erase(it) : std::next(it);
}

void ServerAdmissionService::persist() {
    // caller holds mu_
    json arr = json::array();
    for (const auto& [rid, a] : admissions_) {
        arr.push_back({
            {"request_id", a.request_id}, {"candidate_pubkey", a.candidate_pubkey},
            {"server_id", a.server_id}, {"region", a.region},
            {"tpm_ak_pubkey", a.tpm_ak_pubkey}, {"tpm_ek_cert", a.tpm_ek_cert},
            {"source_ip", a.source_ip}, {"state", static_cast<int>(a.state)},
            {"created_at", a.created_at}, {"expires_at", a.expires_at},
            {"issued_cert_json", a.issued_cert_json},
            {"decision_reason", a.decision_reason}, {"decided_by", a.decided_by},
            {"decision_mode", a.decision_mode}, {"ballot_claim_json", a.ballot_claim_json},
        });
    }
    json denied = json::object();
    for (const auto& [pk, until] : denied_until_) denied[pk] = until;
    json root{{"ever_approved", ever_approved_}, {"admissions", arr},
              {"denied_until", denied}};
    storage::SignedEnvelope env;
    env.type = "admissions";
    env.data = root.dump();
    env.timestamp = now_unix();
    (void)storage_.write_file("onboarding", "admissions.json", env);
}

void ServerAdmissionService::load() {
    auto env = storage_.read_file("onboarding", "admissions.json");
    if (!env) return;
    try {
        auto root = json::parse(env->data);
        ever_approved_ = root.value("ever_approved", false);
        for (const auto& j : root.value("admissions", json::array())) {
            Admission a;
            a.request_id       = j.value("request_id", "");
            a.candidate_pubkey = j.value("candidate_pubkey", "");
            a.server_id        = j.value("server_id", "");
            a.region           = j.value("region", "");
            a.tpm_ak_pubkey    = j.value("tpm_ak_pubkey", "");
            a.tpm_ek_cert      = j.value("tpm_ek_cert", "");
            a.source_ip        = j.value("source_ip", "");
            a.state            = static_cast<State>(j.value("state", 0));
            a.created_at       = j.value("created_at", 0ULL);
            a.expires_at       = j.value("expires_at", 0ULL);
            a.issued_cert_json = j.value("issued_cert_json", "");
            a.decision_reason  = j.value("decision_reason", "");
            a.decided_by       = j.value("decided_by", "");
            a.decision_mode    = j.value("decision_mode", "");
            a.ballot_claim_json = j.value("ballot_claim_json", "");
            // Forward-compat: records persisted before decision_mode existed but
            // that carry a ballot claim are ballot-governed.
            if (a.decision_mode.empty() && !a.ballot_claim_json.empty())
                a.decision_mode = "ballot";
            if (!a.request_id.empty()) admissions_[a.request_id] = std::move(a);
        }
        // Restore denied-pubkey cooldowns; a restart must not clear an active
        // denial. Entries whose cooldown already elapsed are dropped.
        const auto now = now_unix();
        for (const auto& [pk, until] : root.value("denied_until", json::object()).items()) {
            if (until.is_number_unsigned() && until.get<uint64_t>() > now)
                denied_until_[pk] = until.get<uint64_t>();
        }
    } catch (const std::exception& e) {
        spdlog::warn("[ServerAdmissionService] failed to load admissions.json: {}", e.what());
    }
}

} // namespace nexus::core
