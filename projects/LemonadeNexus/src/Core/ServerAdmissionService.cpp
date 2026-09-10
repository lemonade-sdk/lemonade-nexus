#include <LemonadeNexus/Core/ServerAdmissionService.hpp>

#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Gossip/ServerCertificate.hpp>
#include <LemonadeNexus/Security/EvidenceSnpVtpm.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <array>
#include <chrono>
#include <cstring>
#include <stdexcept>

namespace nexus::core {

namespace {

uint64_t now_unix() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

} // namespace

ServerAdmissionService::ServerAdmissionService(
        const ServerConfig& config,
        crypto::SodiumCryptoService& crypto,
        crypto::KeyWrappingService& key_wrapping,
        storage::FileStorageService& storage,
        gossip::GossipService& gossip)
    : config_(config), crypto_(crypto), key_wrapping_(key_wrapping),
      storage_(storage), gossip_(gossip),
      tokens_(storage, crypto) {
    cfg_.enabled         = config.onboard_enabled;
    cfg_.request_ttl_sec = config.onboard_request_ttl_sec;
    cfg_.max_pending     = config.onboard_max_pending;
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

ServerAdmissionService::Result ServerAdmissionService::create_request(
        const AdmissionRequest& in, const std::string& source_ip) {
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
    if (!verify_sig(in.candidate_pubkey, canonical_admission_request(in), in.signature))
        return {false, 401, "signature verification failed", ""};
    // Consume the nonce regardless of downstream outcome.
    nonces_.erase(in.candidate_pubkey);
    nonce_values_.erase(in.candidate_pubkey);

    // The signature covers evidence_sha256, not the bundle, so tie the two here or
    // the bundle we store and later verify is not the one that was signed for.
    if (!in.evidence.empty() || !in.evidence_sha256.empty()) {
        const auto digest = crypto::to_hex(crypto_.sha256(
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(in.evidence.data()),
                                     in.evidence.size())));
        if (in.evidence.empty() || digest != in.evidence_sha256)
            return {false, 400, "evidence does not match the signed evidence_sha256", ""};
    }

    // Denied-pubkey cooldown.
    if (auto it = denied_until_.find(in.candidate_pubkey);
        it != denied_until_.end() && it->second > now)
        return {false, 429, "this identity was recently denied; try again later", ""};

    // Enrollment token: a valid, candidate-bound token admits immediately.
    bool token_admit = false;
    if (in.enrollment_token) {
        auto rec = tokens_.verify(*in.enrollment_token, in.candidate_pubkey);
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
            auto certificate = nlohmann::json::parse(p.certificate_json)
                                   .get<gossip::ServerCertificate>();
            if (certificate.server_id == in.server_id &&
                certificate.server_pubkey != in.candidate_pubkey)
                return {false, 409, "server_id already in use by another server", ""};
        } catch (...) {}
    }

    // Also reject a collision with another in-flight or already-issued admission:
    // get_peers() only lists peers past ServerHello, so two candidates could race
    // for one server_id before either cert appears there.
    for (const auto& [rid, other] : admissions_) {
        if ((other.state == AdmissionState::Pending ||
             other.state == AdmissionState::Approved) &&
            other.server_id == in.server_id && other.candidate_pubkey != in.candidate_pubkey)
            return {false, 409, "server_id already claimed by another admission", ""};
    }

    // Reuse an existing pending record for this candidate (idempotent retry),
    // else allocate a fresh request_id.
    std::string request_id;
    bool is_existing = false;
    for (const auto& [rid, a] : admissions_) {
        if (a.candidate_pubkey == in.candidate_pubkey &&
            a.state == AdmissionState::Pending) {
            request_id = rid; is_existing = true; break;
        }
    }

    // A pending admission is immutable: the record is what gets minted, so
    // refreshing it would let the admin verify claim A and a cert issue for
    // claim B. tpm_ek_cert is compared here because the signature doesn't cover it.
    if (is_existing) {
        const auto& cur = admissions_[request_id];
        std::string changed;
        auto diff = [&changed](const char* f, const std::string& a, const std::string& b) {
            if (a != b) changed += changed.empty() ? f : std::string(", ") + f;
        };
        diff("server_id",       cur.server_id,       in.server_id);
        diff("region",          cur.region,          in.region);
        diff("tpm_ak_pubkey",   cur.tpm_ak_pubkey,   in.tpm_ak_pubkey);
        diff("tpm_ek_cert",     cur.tpm_ek_cert,     in.tpm_ek_cert);
        diff("platform_class",  std::string(admission_platform_name(cur.platform_class)),
             std::string(admission_platform_name(in.platform_class)));
        diff("measurement",     cur.measurement,     in.measurement);
        diff("binary_hash",     cur.binary_hash,     in.binary_hash);
        diff("evidence_sha256", cur.evidence_sha256, in.evidence_sha256);
        if (!changed.empty()) {
            spdlog::warn("[ServerAdmissionService] rejected mutation of pending admission {} "
                         "(changed: {})", request_id, changed);
            return {false, 409,
                    "an admission is already pending for this key and cannot be modified; "
                    "wait for it to be decided or to expire", request_id};
        }
    }

    // Capacity — only a brand-new, non-token pending record counts against it;
    // cheap self-signed pending spam must not lock out a valid token.
    if (!is_existing && !token_admit) {
        uint32_t pending_count = 0;
        for (const auto& [rid, a] : admissions_)
            if (a.state == AdmissionState::Pending) ++pending_count;
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
    AdmissionRecord& a = admissions_[request_id];
    a.request_id       = request_id;
    a.candidate_pubkey = in.candidate_pubkey;
    a.server_id        = in.server_id;
    a.region           = in.region;
    a.tpm_ak_pubkey    = in.tpm_ak_pubkey;
    a.tpm_ek_cert      = in.tpm_ek_cert;
    a.platform_class   = in.platform_class;
    a.measurement      = in.measurement;
    a.binary_hash      = in.binary_hash;
    a.evidence_sha256  = in.evidence_sha256;
    a.evidence         = in.evidence;
    a.challenge_nonce  = in.nonce;
    a.source_ip        = source_ip;
    a.expires_at       = now + cfg_.request_ttl_sec;
    if (!is_existing) {
        a.state = AdmissionState::Pending;
        a.created_at = now;
        // Every admission is sole-discretion: the gossip admission ballot is
        // gone. Tier-1 authority lives in the mesh security system; this grants
        // transport membership only. "ballot" survives only in old records.
        a.decision_mode = "sole";
    }

    // Token admission. Consume fail-closed: spend the token BEFORE issuing and
    // require it to actually be removed, so a delete failure can never leave a
    // reusable bearer credential. The server_id-uniqueness 409 is already
    // checked above, so the common failure can't burn a token; a rarer
    // issuance failure requires a fresh token.
    if (token_admit) {
        if (!tokens_.consume(*in.enrollment_token, in.candidate_pubkey)) {
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

    // Non-token retry of an already-pending request: the record is unchanged.
    if (is_existing) {
        persist();
        return {true, 200, "", request_id};
    }

    persist();
    spdlog::info("[ServerAdmissionService] pending admission '{}' for server_id '{}'",
                 request_id, in.server_id);
    return {true, 200, "", request_id};
}

ServerAdmissionService::Result ServerAdmissionService::do_approve_locked(
        AdmissionRecord& a, const std::string& decided_by, bool supersede) {
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
            auto certificate = nlohmann::json::parse(p.certificate_json)
                                   .get<gossip::ServerCertificate>();
            if (certificate.server_id == a.server_id &&
                certificate.server_pubkey != a.candidate_pubkey) {
                if (!supersede)
                    return {false, 409, "server_id bound to a different pubkey; pass supersede=true",
                            a.request_id};
                const auto& old_pk = certificate.server_pubkey;
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

    // Verify the evidence BEFORE minting, so a Tier-1-class certificate is never
    // issued on the strength of an unchecked claim. A candidate that presents no
    // evidence gets a Tier-2 certificate rather than a rejection — that path is
    // still how a plain server joins.
    auto binding = verify_admission_evidence(a);
    if (!binding) {
        return {false, 403, "platform evidence did not verify: " + a.decision_reason,
                a.request_id};
    }

    if (network_id_hex_.empty()) {
        return {false, 503, "no network id configured; certificates cannot be issued",
                a.request_id};
    }
    gossip::CertIssueParams params;
    params.network_id        = network_id_hex_;
    params.server_pubkey_b64 = a.candidate_pubkey;
    params.server_id         = a.server_id;
    params.tpm_ak_pubkey     = binding->ak_pubkey;
    params.tpm_ek_cert       = a.tpm_ek_cert;
    params.platform_class    = binding->platform_class;
    params.expected_measurement = binding->expected_measurement;
    params.approved_binary_hash = binding->approved_binary_hash;
    params.expires_at        = 0;  // no expiry (renewal machinery is a follow-up)

    auto cert = gossip::issue_server_certificate(params, crypto_, *root_sk, *root_pk);
    a.issued_cert_json = nlohmann::json(cert).dump();
    a.state            = AdmissionState::Approved;
    a.decided_by       = decided_by;
    ever_approved_     = true;

    spdlog::info("[ServerAdmissionService] approved '{}' (server_id '{}', by {}, platform '{}')",
                 a.request_id, a.server_id, decided_by,
                 binding->platform_class.empty() ? "tier-2" : binding->platform_class);
    return {true, 200, "", a.request_id};
}

std::optional<PeerPlatformBinding> ServerAdmissionService::verify_admission_evidence(
        AdmissionRecord& a) const {
    PeerPlatformBinding binding;

    if (a.platform_class == AdmissionPlatform::None && a.evidence.empty()) {
        // A plain Tier 2 enrollment: nothing platform-related was claimed, so
        // nothing platform-related is minted. Admin say-so never converts a
        // candidate-supplied key into a verified platform fact — a Tier 1
        // claim exists only behind verified evidence.
        return binding;
    }

    if (a.platform_class != AdmissionPlatform::SnpVtpm) {
        a.decision_reason = "unsupported platform_class '" +
                            std::string(admission_platform_name(a.platform_class)) + "'";
        return std::nullopt;
    }

    auto evidence = security::decode_snp_vtpm_evidence(a.evidence);
    if (!evidence) {
        a.decision_reason = "the snp-vtpm evidence bundle did not decode";
        return std::nullopt;
    }

    std::vector<uint8_t> identity;
    std::vector<uint8_t> nonce;
    try {
        identity = crypto::from_base64(a.candidate_pubkey);
        nonce    = crypto::from_base64(a.challenge_nonce);
    } catch (...) {
        a.decision_reason = "candidate key or challenge nonce is not base64";
        return std::nullopt;
    }

    // The quote is bound to the challenge nonce this admission was issued, so an
    // evidence bundle captured from another node's join cannot be replayed here.
    security::EvidenceRequirements req;
    req.expected_measurement_hex = a.measurement;
    auto verdict = security::verify_snp_vtpm_evidence(*evidence, nonce, identity, req);
    if (!verdict.ok) {
        a.decision_reason = verdict.failure;
        return std::nullopt;
    }
    if (verdict.binary_sha256 != a.binary_hash) {
        a.decision_reason = "the claimed binary hash is not the one the IMA log records";
        return std::nullopt;
    }

    binding.platform_class       = admission_platform_name(a.platform_class);
    binding.ak_pubkey            = verdict.ak_spki_b64;
    binding.expected_measurement = verdict.measurement_hex;
    binding.approved_binary_hash = verdict.binary_sha256;
    return binding;
}

std::optional<AdmissionRecord> ServerAdmissionService::status(
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
    if (it->second.state != AdmissionState::Approved) return false;
    it->second.state = AdmissionState::Completed;
    persist();
    return true;
}

std::vector<AdmissionRecord> ServerAdmissionService::pending() const {
    std::lock_guard lock(mu_);
    std::vector<AdmissionRecord> out;
    for (const auto& [rid, a] : admissions_)
        if (a.state == AdmissionState::Pending) out.push_back(a);
    return out;
}

ServerAdmissionService::Result ServerAdmissionService::approve(
        const std::string& request_id, const std::string& pubkey_or_fingerprint, bool supersede) {
    std::lock_guard lock(mu_);
    auto it = admissions_.find(request_id);
    if (it == admissions_.end()) return {false, 404, "no such admission", request_id};
    auto& a = it->second;
    if (a.state != AdmissionState::Pending)
        return {false, 409, "admission is not pending", request_id};

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
    if (a.state != AdmissionState::Pending)
        return {false, 409, "admission is not pending", request_id};

    a.state = AdmissionState::Denied;
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
        if (a.state == AdmissionState::Pending && a.expires_at < now) {
            a.state = AdmissionState::Expired;
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
    AdmissionStoreDocument document;
    document.ever_approved = ever_approved_;
    document.denied_until.insert(denied_until_.begin(), denied_until_.end());
    document.admissions.reserve(admissions_.size());
    for (const auto& entry : admissions_) {
        document.admissions.push_back(entry.second);
    }
    storage::SignedEnvelope env;
    env.type = "admissions";
    env.data = document.toJson().dump();
    env.timestamp = now_unix();
    (void)storage_.write_file("onboarding", "admissions.json", env);
}

void ServerAdmissionService::load() {
    auto env = storage_.read_file("onboarding", "admissions.json");
    if (!env) return;
    try {
        const auto json = nlohmann::json::parse(env->data);
        auto decoded = admission_store_from_json(json);
        if (!decoded) throw std::runtime_error(decoded.error);
        ever_approved_ = decoded.value->ever_approved;
        for (auto& admission : decoded.value->admissions) {
            admissions_[admission.request_id] = std::move(admission);
        }
        const auto now = now_unix();
        for (const auto& [pubkey, until] : decoded.value->denied_until) {
            if (until > now) denied_until_[pubkey] = until;
        }
    } catch (const std::exception& e) {
        spdlog::warn("[ServerAdmissionService] failed to load admissions.json: {}", e.what());
    }
}

} // namespace nexus::core
