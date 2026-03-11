#include <LemonadeNexus/Core/RootKeyChain.hpp>
#include <LemonadeNexus/Crypto/ShamirSecretSharing.hpp>

#include <spdlog/spdlog.h>
#include <sodium.h>

#include <chrono>
#include <cmath>
#include <cstring>

namespace nexus::core {

// ---------------------------------------------------------------------------
// JSON serialization — RootKeyEntry
// ---------------------------------------------------------------------------

void to_json(nlohmann::json& j, const RootKeyEntry& e) {
    j = nlohmann::json{
        {"activated_at",     e.activated_at},
        {"endorsement_sig",  e.endorsement_sig},
        {"expires_at",       e.expires_at},
        {"generation",       e.generation},
        {"pubkey_hex",       e.pubkey_hex},
        {"signed_by_hex",    e.signed_by_hex},
    };
}

void from_json(const nlohmann::json& j, RootKeyEntry& e) {
    j.at("activated_at").get_to(e.activated_at);
    j.at("pubkey_hex").get_to(e.pubkey_hex);
    j.at("generation").get_to(e.generation);
    if (j.contains("expires_at"))       j.at("expires_at").get_to(e.expires_at);
    if (j.contains("signed_by_hex"))    j.at("signed_by_hex").get_to(e.signed_by_hex);
    if (j.contains("endorsement_sig"))  j.at("endorsement_sig").get_to(e.endorsement_sig);
}

std::string canonical_root_key_json(const RootKeyEntry& e) {
    nlohmann::json j = {
        {"activated_at",  e.activated_at},
        {"expires_at",    e.expires_at},
        {"generation",    e.generation},
        {"pubkey_hex",    e.pubkey_hex},
        {"signed_by_hex", e.signed_by_hex},
    };
    return j.dump(); // nlohmann sorts keys alphabetically
}

// ---------------------------------------------------------------------------
// JSON serialization — PeerHealthRecord
// ---------------------------------------------------------------------------

void to_json(nlohmann::json& j, const PeerHealthRecord& h) {
    j = nlohmann::json{
        {"first_seen",         h.first_seen},
        {"last_check",         h.last_check},
        {"pubkey",             h.pubkey},
        {"successful_checks",  h.successful_checks},
        {"total_checks",       h.total_checks},
        {"uptime_ratio",       h.uptime_ratio},
    };
}

void from_json(const nlohmann::json& j, PeerHealthRecord& h) {
    j.at("pubkey").get_to(h.pubkey);
    if (j.contains("first_seen"))         j.at("first_seen").get_to(h.first_seen);
    if (j.contains("last_check"))         j.at("last_check").get_to(h.last_check);
    if (j.contains("total_checks"))       j.at("total_checks").get_to(h.total_checks);
    if (j.contains("successful_checks"))  j.at("successful_checks").get_to(h.successful_checks);
    if (j.contains("uptime_ratio"))       j.at("uptime_ratio").get_to(h.uptime_ratio);
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

RootKeyChainService::RootKeyChainService(crypto::SodiumCryptoService& crypto,
                                           storage::FileStorageService& storage)
    : crypto_(crypto), storage_(storage) {}

void RootKeyChainService::set_io_context(asio::io_context& io) {
    io_ = &io;
}

bool RootKeyChainService::apply_governance_params(uint32_t rotation_interval_sec,
                                                     float quorum_ratio,
                                                     float min_uptime) {
    bool changed = false;
    if (rotation_interval_sec >= 86400 && rotation_interval_sec != rotation_interval_sec_) {
        spdlog::info("RootKeyChain: governance updated rotation_interval: {}s -> {}s",
                      rotation_interval_sec_, rotation_interval_sec);
        rotation_interval_sec_ = rotation_interval_sec;
        changed = true;
    }
    if (quorum_ratio > 0.0f && quorum_ratio <= 1.0f && quorum_ratio != quorum_ratio_) {
        spdlog::info("RootKeyChain: governance updated quorum_ratio: {:.2f} -> {:.2f}",
                      quorum_ratio_, quorum_ratio);
        quorum_ratio_ = quorum_ratio;
        changed = true;
    }
    if (min_uptime > 0.0f && min_uptime <= 1.0f && min_uptime != min_uptime_) {
        spdlog::info("RootKeyChain: governance updated min_uptime: {:.2f} -> {:.2f}",
                      min_uptime_, min_uptime);
        min_uptime_ = min_uptime;
        changed = true;
    }
    if (changed) {
        // Restart the rotation timer with new interval
        start_rotation_timer();
    }
    return changed;
}

// ---------------------------------------------------------------------------
// IService lifecycle
// ---------------------------------------------------------------------------

void RootKeyChainService::on_start() {
    load_chain();
    load_peer_health();

    if (!chain_.empty()) {
        spdlog::info("RootKeyChain: loaded chain with {} entries, current root: {}",
                     chain_.size(), chain_.back().pubkey_hex.substr(0, 16) + "...");
    }

    start_rotation_timer();
}

void RootKeyChainService::on_stop() {
    rotation_timer_running_ = false;
    if (rotation_timer_) {
        rotation_timer_->cancel();
    }
    save_peer_health();
}

// ---------------------------------------------------------------------------
// Genesis initialization
// ---------------------------------------------------------------------------

void RootKeyChainService::initialize_genesis(const crypto::Ed25519Keypair& root_keypair) {
    std::lock_guard lock(mutex_);

    if (!chain_.empty()) {
        spdlog::debug("RootKeyChain: chain already exists, skipping genesis");
        return;
    }

    auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    RootKeyEntry genesis;
    genesis.pubkey_hex = crypto::to_hex(root_keypair.public_key);
    genesis.activated_at = now;
    genesis.expires_at = 0; // genesis never expires
    genesis.generation = 0;

    chain_.push_back(genesis);
    current_root_keypair_ = root_keypair;

    save_chain();
    spdlog::info("RootKeyChain: genesis root key initialized: {}",
                 genesis.pubkey_hex.substr(0, 16) + "...");
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

bool RootKeyChainService::is_valid_root_key(const std::string& pubkey_hex) const {
    std::lock_guard lock(mutex_);

    auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    for (const auto& entry : chain_) {
        if (entry.pubkey_hex == pubkey_hex) {
            if (entry.expires_at > 0 && now > entry.expires_at) {
                return false;
            }
            return true;
        }
    }
    return false;
}

bool RootKeyChainService::verify_with_any_root(
    std::span<const uint8_t> message,
    const crypto::Ed25519Signature& signature) const {

    std::lock_guard lock(mutex_);

    auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    for (const auto& entry : chain_) {
        if (entry.expires_at > 0 && now > entry.expires_at) {
            continue;
        }

        auto pk_bytes = crypto::from_hex(entry.pubkey_hex);
        if (pk_bytes.size() != crypto::kEd25519PublicKeySize) continue;

        crypto::Ed25519PublicKey pk{};
        std::memcpy(pk.data(), pk_bytes.data(), pk_bytes.size());

        if (crypto_.ed25519_verify(pk, message, signature)) {
            return true;
        }
    }
    return false;
}

std::string RootKeyChainService::current_root_pubkey_hex() const {
    std::lock_guard lock(mutex_);
    if (chain_.empty()) return {};
    return chain_.back().pubkey_hex;
}

std::vector<RootKeyEntry> RootKeyChainService::chain() const {
    std::lock_guard lock(mutex_);
    return chain_;
}

// ---------------------------------------------------------------------------
// Key Rotation
// ---------------------------------------------------------------------------

std::string RootKeyChainService::rotate() {
    std::lock_guard lock(mutex_);

    if (chain_.empty() || !current_root_keypair_) {
        spdlog::error("RootKeyChain: cannot rotate — no current root keypair");
        return {};
    }

    auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    auto new_keypair = crypto_.ed25519_keygen();
    auto new_pubkey_hex = crypto::to_hex(new_keypair.public_key);
    auto old_pubkey_hex = chain_.back().pubkey_hex;

    RootKeyEntry new_entry;
    new_entry.pubkey_hex = new_pubkey_hex;
    new_entry.activated_at = now;
    new_entry.expires_at = 0;
    new_entry.generation = chain_.back().generation + 1;
    new_entry.signed_by_hex = old_pubkey_hex;

    auto canonical = canonical_root_key_json(new_entry);
    auto canonical_bytes = std::vector<uint8_t>(canonical.begin(), canonical.end());
    auto sig = crypto_.ed25519_sign(current_root_keypair_->private_key, canonical_bytes);
    new_entry.endorsement_sig = crypto::to_base64(sig);

    // Mark old key as expiring (2x rotation interval grace period)
    chain_.back().expires_at = now + (rotation_interval_sec_ * 2);

    chain_.push_back(new_entry);
    current_root_keypair_ = new_keypair;

    save_chain();

    spdlog::info("RootKeyChain: rotated root key. gen {} -> {}. new: {}",
                 new_entry.generation - 1, new_entry.generation,
                 new_pubkey_hex.substr(0, 16) + "...");

    return new_pubkey_hex;
}

bool RootKeyChainService::accept_rotation(const RootKeyEntry& entry) {
    std::lock_guard lock(mutex_);

    if (chain_.empty()) {
        spdlog::warn("RootKeyChain: cannot accept rotation — no chain");
        return false;
    }

    // Check if we already have this generation
    for (const auto& existing : chain_) {
        if (existing.generation == entry.generation) {
            if (existing.pubkey_hex == entry.pubkey_hex) {
                return true; // already have it
            }
            spdlog::warn("RootKeyChain: conflicting entry for generation {}", entry.generation);
            return false;
        }
    }

    // Must be the next generation
    if (entry.generation != chain_.back().generation + 1) {
        spdlog::warn("RootKeyChain: expected generation {}, got {}",
                     chain_.back().generation + 1, entry.generation);
        return false;
    }

    if (entry.signed_by_hex != chain_.back().pubkey_hex) {
        spdlog::warn("RootKeyChain: entry not signed by current root");
        return false;
    }

    if (!verify_endorsement(entry)) {
        spdlog::warn("RootKeyChain: invalid endorsement signature for generation {}", entry.generation);
        return false;
    }

    auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    chain_.back().expires_at = now + (rotation_interval_sec_ * 2);
    chain_.push_back(entry);

    save_chain();

    spdlog::info("RootKeyChain: accepted rotation to generation {}: {}",
                 entry.generation, entry.pubkey_hex.substr(0, 16) + "...");
    return true;
}

bool RootKeyChainService::verify_endorsement(const RootKeyEntry& entry) const {
    if (entry.signed_by_hex.empty() || entry.endorsement_sig.empty()) {
        return false;
    }

    for (const auto& existing : chain_) {
        if (existing.pubkey_hex == entry.signed_by_hex) {
            auto pk_bytes = crypto::from_hex(existing.pubkey_hex);
            if (pk_bytes.size() != crypto::kEd25519PublicKeySize) return false;

            crypto::Ed25519PublicKey pk{};
            std::memcpy(pk.data(), pk_bytes.data(), pk_bytes.size());

            auto sig_bytes = crypto::from_base64(entry.endorsement_sig);
            if (sig_bytes.size() != crypto::kEd25519SignatureSize) return false;

            crypto::Ed25519Signature sig{};
            std::memcpy(sig.data(), sig_bytes.data(), sig_bytes.size());

            auto canonical = canonical_root_key_json(entry);
            auto canonical_vec = std::vector<uint8_t>(canonical.begin(), canonical.end());

            return crypto_.ed25519_verify(pk, canonical_vec, sig);
        }
    }
    return false;
}

// ---------------------------------------------------------------------------
// Dynamic Shamir's Secret Sharing
// ---------------------------------------------------------------------------

uint8_t RootKeyChainService::compute_threshold(uint8_t eligible_count) const {
    if (eligible_count < 2) return 2; // absolute minimum
    auto k = static_cast<uint8_t>(std::ceil(static_cast<float>(eligible_count) * quorum_ratio_));
    if (k < 2) k = 2;
    return k;
}

std::vector<std::string> RootKeyChainService::generate_shamir_shares(uint8_t eligible_peer_count) const {
    std::lock_guard lock(mutex_);

    if (!current_root_keypair_) {
        spdlog::error("RootKeyChain: no root private key to split");
        return {};
    }

    if (eligible_peer_count < 2) {
        spdlog::warn("RootKeyChain: need at least 2 eligible Tier1 peers for Shamir split, have {}",
                     eligible_peer_count);
        return {};
    }

    uint8_t threshold = compute_threshold(eligible_peer_count);

    // Split the Ed25519 private key (64 bytes)
    std::vector<uint8_t> secret(current_root_keypair_->private_key.begin(),
                                 current_root_keypair_->private_key.end());

    auto shares = crypto::ShamirSecretSharing::split(secret, threshold, eligible_peer_count);

    sodium_memzero(secret.data(), secret.size());

    if (shares.empty()) {
        spdlog::error("RootKeyChain: Shamir split failed (K={}, N={})",
                     threshold, eligible_peer_count);
        return {};
    }

    std::vector<std::string> result;
    result.reserve(shares.size());
    for (const auto& share : shares) {
        result.push_back(crypto::ShamirSecretSharing::share_to_string(share));
    }

    spdlog::info("RootKeyChain: generated {} Shamir shares (threshold {}, 25%% fault tolerance)",
                 eligible_peer_count, threshold);
    return result;
}

bool RootKeyChainService::reconstruct_from_shares(const std::vector<std::string>& share_strings,
                                                    uint8_t expected_threshold) {
    std::lock_guard lock(mutex_);

    if (chain_.empty()) {
        spdlog::error("RootKeyChain: no chain — cannot reconstruct");
        return false;
    }

    if (share_strings.size() < expected_threshold) {
        spdlog::error("RootKeyChain: need {} shares, only have {}",
                     expected_threshold, share_strings.size());
        return false;
    }

    std::vector<crypto::ShamirShare> shares;
    for (const auto& s : share_strings) {
        auto share = crypto::ShamirSecretSharing::share_from_string(s);
        if (!share) {
            spdlog::error("RootKeyChain: invalid share string");
            return false;
        }
        shares.push_back(*share);
    }

    auto secret = crypto::ShamirSecretSharing::reconstruct(shares, expected_threshold);
    if (!secret || secret->size() != crypto::kEd25519PrivateKeySize) {
        spdlog::error("RootKeyChain: Shamir reconstruction failed");
        return false;
    }

    crypto::Ed25519Keypair kp;
    std::memcpy(kp.private_key.data(), secret->data(), crypto::kEd25519PrivateKeySize);
    std::memcpy(kp.public_key.data(),
                secret->data() + crypto::kEd25519SeedSize,
                crypto::kEd25519PublicKeySize);

    sodium_memzero(secret->data(), secret->size());

    auto reconstructed_hex = crypto::to_hex(kp.public_key);
    auto expected_hex = chain_.back().pubkey_hex;

    if (reconstructed_hex != expected_hex) {
        spdlog::error("RootKeyChain: reconstructed key doesn't match current root. "
                     "Got: {}, expected: {}",
                     reconstructed_hex.substr(0, 16), expected_hex.substr(0, 16));
        sodium_memzero(kp.private_key.data(), kp.private_key.size());
        return false;
    }

    current_root_keypair_ = kp;
    spdlog::info("RootKeyChain: root private key reconstructed from {} shares (threshold {})",
                 share_strings.size(), expected_threshold);
    return true;
}

void RootKeyChainService::store_received_share(const std::string& share_string, uint32_t generation) {
    std::lock_guard lock(mutex_);
    received_shares_[generation] = share_string;
    spdlog::debug("RootKeyChain: stored Shamir share for generation {}", generation);
}

std::optional<std::string> RootKeyChainService::get_stored_share(uint32_t generation) const {
    std::lock_guard lock(mutex_);
    auto it = received_shares_.find(generation);
    if (it != received_shares_.end()) {
        return it->second;
    }
    return std::nullopt;
}

bool RootKeyChainService::has_root_private_key() const {
    std::lock_guard lock(mutex_);
    return current_root_keypair_.has_value();
}

std::optional<crypto::Ed25519Keypair> RootKeyChainService::root_keypair() const {
    std::lock_guard lock(mutex_);
    return current_root_keypair_;
}

// ---------------------------------------------------------------------------
// Peer Health Tracking
// ---------------------------------------------------------------------------

void RootKeyChainService::record_peer_check(const std::string& pubkey, bool responded) {
    std::lock_guard lock(health_mutex_);

    auto now = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    auto& record = peer_health_[pubkey];
    if (record.pubkey.empty()) {
        record.pubkey = pubkey;
        record.first_seen = now;
    }

    record.total_checks++;
    if (responded) {
        record.successful_checks++;
    }
    record.last_check = now;

    // Recompute uptime ratio
    if (record.total_checks > 0) {
        record.uptime_ratio = static_cast<float>(record.successful_checks) /
                              static_cast<float>(record.total_checks);
    }
}

PeerHealthRecord RootKeyChainService::peer_health(const std::string& pubkey) const {
    std::lock_guard lock(health_mutex_);
    auto it = peer_health_.find(pubkey);
    if (it != peer_health_.end()) {
        return it->second;
    }
    return PeerHealthRecord{};
}

std::vector<PeerHealthRecord> RootKeyChainService::all_peer_health() const {
    std::lock_guard lock(health_mutex_);
    std::vector<PeerHealthRecord> result;
    result.reserve(peer_health_.size());
    for (const auto& [_, record] : peer_health_) {
        result.push_back(record);
    }
    return result;
}

std::vector<std::string> RootKeyChainService::eligible_tier1_peers() const {
    std::lock_guard lock(health_mutex_);
    std::vector<std::string> result;
    for (const auto& [pubkey, record] : peer_health_) {
        if (record.total_checks >= 100 && record.uptime_ratio >= min_uptime_) {
            result.push_back(pubkey);
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

void RootKeyChainService::load_chain() {
    auto envelope = storage_.read_file("identity", "root_chain.json");
    if (!envelope || envelope->data.empty()) return;

    try {
        auto j = nlohmann::json::parse(envelope->data);
        if (j.contains("chain") && j["chain"].is_array()) {
            chain_ = j["chain"].get<std::vector<RootKeyEntry>>();
        }
    } catch (const std::exception& e) {
        spdlog::error("RootKeyChain: failed to parse root_chain.json: {}", e.what());
    }
}

void RootKeyChainService::save_chain() {
    nlohmann::json j = {
        {"type", "root_key_chain"},
        {"chain", chain_},
    };

    storage::SignedEnvelope env;
    env.type = "root_key_chain";
    env.data = j.dump(2);
    env.timestamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    (void)storage_.write_file("identity", "root_chain.json", env);
}

void RootKeyChainService::load_peer_health() {
    auto envelope = storage_.read_file("identity", "peer_health.json");
    if (!envelope || envelope->data.empty()) return;

    try {
        auto j = nlohmann::json::parse(envelope->data);
        if (j.contains("peers") && j["peers"].is_array()) {
            for (const auto& entry : j["peers"]) {
                PeerHealthRecord record = entry.get<PeerHealthRecord>();
                peer_health_[record.pubkey] = record;
            }
        }
    } catch (const std::exception& e) {
        spdlog::error("RootKeyChain: failed to parse peer_health.json: {}", e.what());
    }
}

void RootKeyChainService::save_peer_health() {
    std::lock_guard lock(health_mutex_);

    nlohmann::json peers = nlohmann::json::array();
    for (const auto& [_, record] : peer_health_) {
        peers.push_back(record);
    }

    nlohmann::json j = {
        {"type", "peer_health"},
        {"peers", peers},
    };

    storage::SignedEnvelope env;
    env.type = "peer_health";
    env.data = j.dump(2);
    env.timestamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());

    (void)storage_.write_file("identity", "peer_health.json", env);
}

// ---------------------------------------------------------------------------
// Rotation timer
// ---------------------------------------------------------------------------

void RootKeyChainService::start_rotation_timer() {
    if (!io_ || rotation_interval_sec_ == 0) return;

    rotation_timer_ = std::make_unique<asio::steady_timer>(*io_);
    rotation_timer_running_ = true;
    on_rotation_tick();
}

void RootKeyChainService::on_rotation_tick() {
    if (!rotation_timer_running_) return;

    rotation_timer_->expires_after(std::chrono::seconds(rotation_interval_sec_));
    rotation_timer_->async_wait([this](const asio::error_code& ec) {
        if (ec || !rotation_timer_running_) return;

        // Only rotate if we hold the root private key
        if (has_root_private_key()) {
            spdlog::info("RootKeyChain: automatic rotation triggered");
            auto new_key = rotate();
            if (!new_key.empty()) {
                spdlog::info("RootKeyChain: rotation complete, new root: {}",
                             new_key.substr(0, 16) + "...");
                // After rotation, shares should be redistributed via gossip
                // (handled by GossipService which observes the generation change)
            }
        }

        on_rotation_tick();
    });
}

} // namespace nexus::core
