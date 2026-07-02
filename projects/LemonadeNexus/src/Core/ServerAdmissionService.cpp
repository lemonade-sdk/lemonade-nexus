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
      storage_(storage), gossip_(gossip), trust_policy_(trust_policy) {
    cfg_.enabled                = config.onboard_enabled;
    cfg_.auto_approve_bootstrap  = config.onboard_auto_approve_bootstrap;
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
    spdlog::info("[ServerAdmissionService] started ({} persisted admission(s), accepts_onboarding={})",
                 admissions_.size(), accepts_onboarding());
}

void ServerAdmissionService::on_stop() {
    persist();
}

bool ServerAdmissionService::accepts_onboarding() const {
    // No fail-open: only a root-anchored server that holds the root key may issue.
    return cfg_.enabled && !config_.root_pubkey.empty();
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

bool ServerAdmissionService::ever_approved() const {
    return ever_approved_;
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

    // Idempotent refresh of an existing pending request for the same pubkey.
    for (auto& [rid, a] : admissions_) {
        if (a.candidate_pubkey == in.candidate_pubkey && a.state == State::Pending) {
            a.expires_at = now + cfg_.request_ttl_sec;
            a.source_ip  = in.source_ip;
            persist();
            return {true, 200, "", rid};
        }
    }

    // server_id uniqueness vs enrolled peers.
    for (const auto& p : gossip_.get_peers()) {
        if (p.certificate_json.empty()) continue;
        try {
            auto cj = json::parse(p.certificate_json);
            if (cj.value("server_id", "") == in.server_id &&
                cj.value("server_pubkey", "") != in.candidate_pubkey)
                return {false, 409, "server_id already in use by another server", ""};
        } catch (...) {}
    }

    // Capacity.
    uint32_t pending_count = 0;
    for (const auto& [rid, a] : admissions_)
        if (a.state == State::Pending) ++pending_count;
    if (pending_count >= cfg_.max_pending)
        return {false, 429, "too many pending admissions; try again later", ""};

    // Create the record.
    std::array<uint8_t, 16> rid_raw{};
    crypto_.random_bytes(std::span<uint8_t>(rid_raw));
    auto request_id = crypto::to_hex(std::span<const uint8_t>(rid_raw));

    Admission a;
    a.request_id       = request_id;
    a.candidate_pubkey = in.candidate_pubkey;
    a.server_id        = in.server_id;
    a.region           = in.region;
    a.tpm_ak_pubkey    = in.tpm_ak_pubkey;
    a.tpm_ek_cert      = in.tpm_ek_cert;
    a.source_ip        = in.source_ip;
    a.state            = State::Pending;
    a.created_at       = now;
    a.expires_at       = now + cfg_.request_ttl_sec;

    const bool below_vote = eligible_voter_count() < cfg_.min_tier1_for_vote;

    // Bootstrap auto-approve: only while no admission has ever been approved and
    // we're below the voting threshold. Self-enrollment/manual enroll don't count.
    if (below_vote && cfg_.auto_approve_bootstrap && !ever_approved()) {
        spdlog::warn("[ServerAdmissionService] SECURITY: auto-approving '{}' (bootstrap window — "
                     "no prior admissions). Disable with onboard_auto_approve_bootstrap=false.",
                     in.server_id);
        auto r = do_approve_locked(a, "auto", /*supersede=*/false);
        admissions_[request_id] = a;
        persist();
        if (!r.ok) return r;
        return {true, 200, "", request_id};
    }

    // Above the vote threshold: defer to a governed Tier1 ballot. Store the
    // candidate's self-signed claim so peers can verify it; the handler kicks
    // the ballot after this call returns (the decision callback re-enters us).
    if (!below_vote) {
        json claim{{"candidate_pubkey", in.candidate_pubkey}, {"server_id", in.server_id},
                   {"region", in.region}, {"tpm_ak_pubkey", in.tpm_ak_pubkey},
                   {"nonce", in.nonce}, {"timestamp", in.timestamp},
                   {"signature", in.signature}};
        a.ballot_claim_json = claim.dump();
    }

    admissions_[request_id] = a;
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
                json revoked = json::array();
                if (auto env = storage_.read_file("identity", "revoked_servers.json"))
                    try { revoked = json::parse(env->data); } catch (...) {}
                revoked.push_back(old_pk);
                storage::SignedEnvelope rev;
                rev.type = "revocation_list";
                rev.data = revoked.dump();
                rev.timestamp = now_unix();
                (void)storage_.write_file("identity", "revoked_servers.json", rev);
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
        });
    }
    json root{{"ever_approved", ever_approved_}, {"admissions", arr}};
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
            if (!a.request_id.empty()) admissions_[a.request_id] = std::move(a);
        }
    } catch (const std::exception& e) {
        spdlog::warn("[ServerAdmissionService] failed to load admissions.json: {}", e.what());
    }
}

} // namespace nexus::core
