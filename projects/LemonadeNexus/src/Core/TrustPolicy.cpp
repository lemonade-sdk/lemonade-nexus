#include <LemonadeNexus/Core/TrustPolicy.hpp>

#include <spdlog/spdlog.h>

#include <chrono>
#include <cstring>

namespace nexus::core {

namespace chrono = std::chrono;

static uint64_t now_sec() {
    return static_cast<uint64_t>(
        chrono::duration_cast<chrono::seconds>(
            chrono::system_clock::now().time_since_epoch()).count());
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

TrustPolicyService::TrustPolicyService(
    TeeAttestationService& tee,
    BinaryAttestationService& binary_attestation,
    crypto::SodiumCryptoService& crypto)
    : tee_(tee)
    , binary_attestation_(binary_attestation)
    , crypto_(crypto)
{
}

// ---------------------------------------------------------------------------
// IService lifecycle
// ---------------------------------------------------------------------------

void TrustPolicyService::on_start() {
    spdlog::info("[{}] started (our TEE platform: {}, our tier: {})",
                  name(),
                  tee_platform_name(tee_.detected_platform()),
                  our_tier() == TrustTier::Tier1 ? "Tier1" : "Tier2");
}

void TrustPolicyService::on_stop() {
    spdlog::info("[{}] stopped ({} tracked peers)", name(), peers_.size());
}

// ---------------------------------------------------------------------------
// Zero-trust authorization
// ---------------------------------------------------------------------------

bool TrustPolicyService::authorize(const std::string& pubkey, TrustOperation op) const {
    std::lock_guard lock(mutex_);

    auto it = peers_.find(pubkey);
    if (it == peers_.end()) {
        // Unknown peer — only allow if operation needs Untrusted (none do)
        spdlog::debug("[{}] authorize: unknown peer {}, denied for {}",
                       name(), pubkey.substr(0, 12) + "...",
                       static_cast<uint8_t>(op));
        return false;
    }

    const auto& state = it->second;

    // Zero-trust freshness check: if Tier 1, ensure last verification isn't stale
    if (state.tier == TrustTier::Tier1) {
        auto now = now_sec();
        if (state.last_verified + kTrustExpirationSec < now) {
            spdlog::warn("[{}] peer {} Tier1 status expired (last verified {}s ago)",
                          name(), pubkey.substr(0, 12) + "...",
                          now - state.last_verified);
            // Treat as Tier2 for this check (actual demotion happens in expire_stale_peers)
            return is_operation_allowed(TrustTier::Tier2, op);
        }
    }

    bool allowed = is_operation_allowed(state.tier, op);
    if (!allowed) {
        spdlog::debug("[{}] authorize: peer {} (tier={}) denied for operation {}",
                       name(), pubkey.substr(0, 12) + "...",
                       static_cast<uint8_t>(state.tier),
                       static_cast<uint8_t>(op));
    }
    return allowed;
}

TrustTier TrustPolicyService::verify_and_update(
    const std::string& pubkey,
    const AttestationToken& token) {

    std::lock_guard lock(mutex_);

    auto& state = get_or_create(pubkey);

    // Verify the token through TeeAttestationService
    bool valid = tee_.verify_token(token);

    if (valid) {
        // Promotion to Tier 1
        if (state.tier != TrustTier::Tier1) {
            spdlog::info("[{}] peer {} promoted to Tier1 (platform: {})",
                          name(), pubkey.substr(0, 12) + "...",
                          tee_platform_name(token.platform));
        }
        state.tier = TrustTier::Tier1;
        state.platform = token.platform;
        state.last_verified = now_sec();
        state.last_token_timestamp = token.timestamp;
        state.attestation_hash = token.attestation_hash;
        state.binary_hash = token.binary_hash;
        state.failed_verifications = 0;
    } else {
        // Verification failed
        state.failed_verifications++;
        spdlog::warn("[{}] peer {} token verification failed ({} consecutive)",
                      name(), pubkey.substr(0, 12) + "...",
                      state.failed_verifications);

        if (state.failed_verifications >= kMaxFailedVerifications) {
            // Demote to Untrusted after repeated failures
            if (state.tier != TrustTier::Untrusted) {
                spdlog::warn("[{}] peer {} demoted to Untrusted after {} failures",
                              name(), pubkey.substr(0, 12) + "...",
                              state.failed_verifications);
            }
            state.tier = TrustTier::Untrusted;
        } else if (state.tier == TrustTier::Tier1) {
            // Single failure demotes from Tier1 to Tier2 (zero-trust)
            spdlog::warn("[{}] peer {} demoted from Tier1 to Tier2", name(),
                          pubkey.substr(0, 12) + "...");
            state.tier = TrustTier::Tier2;
        }
    }

    return state.tier;
}

// ---------------------------------------------------------------------------
// TEE challenge-response
// ---------------------------------------------------------------------------

std::array<uint8_t, 32> TrustPolicyService::challenge_peer(const std::string& pubkey) {
    std::lock_guard lock(mutex_);

    std::array<uint8_t, 32> nonce{};
    crypto_.random_bytes(nonce);
    pending_challenges_[pubkey] = nonce;

    spdlog::debug("[{}] issued TEE challenge to {}", name(), pubkey.substr(0, 12) + "...");
    return nonce;
}

bool TrustPolicyService::handle_challenge_response(
    const std::string& pubkey,
    const TeeAttestationReport& report) {

    std::lock_guard lock(mutex_);

    // Find the pending challenge
    auto ch_it = pending_challenges_.find(pubkey);
    if (ch_it == pending_challenges_.end()) {
        spdlog::warn("[{}] received challenge response from {} with no pending challenge",
                      name(), pubkey.substr(0, 12) + "...");
        return false;
    }

    auto expected_nonce = ch_it->second;
    pending_challenges_.erase(ch_it);

    // Verify the TEE report against our challenge nonce
    bool valid = tee_.verify_report(report, expected_nonce);

    auto& state = get_or_create(pubkey);

    if (valid) {
        // Also verify binary hash is approved
        bool binary_ok = true;
        if (binary_attestation_.has_signing_pubkey() && !report.binary_hash.empty()) {
            binary_ok = binary_attestation_.is_approved_binary(report.binary_hash);
        }

        if (binary_ok) {
            state.tier = TrustTier::Tier1;
            state.platform = report.platform;
            state.last_verified = now_sec();
            state.attestation_hash = "";  // Will be set on next token verification
            state.binary_hash = report.binary_hash;
            state.failed_verifications = 0;

            spdlog::info("[{}] peer {} passed TEE challenge — promoted to Tier1 (platform: {})",
                          name(), pubkey.substr(0, 12) + "...",
                          tee_platform_name(report.platform));
            return true;
        } else {
            spdlog::warn("[{}] peer {} TEE report valid but binary hash not approved",
                          name(), pubkey.substr(0, 12) + "...");
        }
    } else {
        spdlog::warn("[{}] peer {} TEE challenge response verification failed",
                      name(), pubkey.substr(0, 12) + "...");
    }

    state.failed_verifications++;
    if (state.failed_verifications >= kMaxFailedVerifications) {
        state.tier = TrustTier::Untrusted;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Trust state queries
// ---------------------------------------------------------------------------

TrustTier TrustPolicyService::peer_tier(const std::string& pubkey) const {
    std::lock_guard lock(mutex_);

    auto it = peers_.find(pubkey);
    if (it == peers_.end()) return TrustTier::Untrusted;

    // Apply freshness check for Tier 1
    if (it->second.tier == TrustTier::Tier1) {
        if (it->second.last_verified + kTrustExpirationSec < now_sec()) {
            return TrustTier::Tier2;  // Stale — report as Tier2
        }
    }

    return it->second.tier;
}

PeerTrustState TrustPolicyService::peer_state(const std::string& pubkey) const {
    std::lock_guard lock(mutex_);

    auto it = peers_.find(pubkey);
    if (it == peers_.end()) {
        PeerTrustState empty;
        empty.pubkey = pubkey;
        return empty;
    }
    return it->second;
}

TrustTier TrustPolicyService::our_tier() const {
    return tee_.platform_available() ? TrustTier::Tier1 : TrustTier::Tier2;
}

AttestationToken TrustPolicyService::generate_attestation_token(
    const crypto::Ed25519Keypair& keypair) {
    return tee_.generate_token(keypair);
}

std::vector<PeerTrustState> TrustPolicyService::all_peer_states() const {
    std::lock_guard lock(mutex_);

    std::vector<PeerTrustState> result;
    result.reserve(peers_.size());
    for (const auto& [_, state] : peers_) {
        result.push_back(state);
    }
    return result;
}

void TrustPolicyService::set_peer_tier2(const std::string& pubkey) {
    std::lock_guard lock(mutex_);

    auto& state = get_or_create(pubkey);
    state.tier = TrustTier::Tier2;
    state.last_verified = now_sec();
    spdlog::debug("[{}] peer {} set to Tier2 (certificate-only)", name(),
                   pubkey.substr(0, 12) + "...");
}

void TrustPolicyService::remove_peer(const std::string& pubkey) {
    std::lock_guard lock(mutex_);

    auto removed = peers_.erase(pubkey);
    if (removed > 0) {
        pending_challenges_.erase(pubkey);
        spdlog::debug("[{}] removed peer {} from trust state", name(),
                       pubkey.substr(0, 12) + "...");
    }
}

void TrustPolicyService::expire_stale_peers(uint64_t max_age_sec) {
    std::lock_guard lock(mutex_);

    auto now = now_sec();
    for (auto& [pubkey, state] : peers_) {
        if (state.tier == TrustTier::Tier1 &&
            state.last_verified + max_age_sec < now) {
            spdlog::warn("[{}] peer {} Tier1 expired (last verified {}s ago) — demoting to Tier2",
                          name(), pubkey.substr(0, 12) + "...",
                          now - state.last_verified);
            state.tier = TrustTier::Tier2;
        }
    }

    // Clean up stale pending challenges (older than 60 seconds)
    // Challenges have timestamps embedded in the nonce creation time,
    // but we'll just clear all of them periodically since they're short-lived
    if (pending_challenges_.size() > 100) {
        pending_challenges_.clear();
        spdlog::debug("[{}] cleared stale pending challenges", name());
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

PeerTrustState& TrustPolicyService::get_or_create(const std::string& pubkey) {
    auto it = peers_.find(pubkey);
    if (it == peers_.end()) {
        PeerTrustState state;
        state.pubkey = pubkey;
        state.tier = TrustTier::Untrusted;
        auto [new_it, _] = peers_.emplace(pubkey, std::move(state));
        return new_it->second;
    }
    return it->second;
}

} // namespace nexus::core
