#pragma once

#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <asio.hpp>
#include <nlohmann/json.hpp>

#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

namespace nexus::core {

/// A single entry in the root key chain.
/// Each entry is signed by the previous root key, establishing a chain of trust.
struct RootKeyEntry {
    std::string pubkey_hex;        // Ed25519 public key (hex)
    uint64_t    activated_at{0};   // Unix timestamp when this key became active
    uint64_t    expires_at{0};     // Unix timestamp when this key expires (0 = no expiry)
    uint32_t    generation{0};     // Monotonic generation counter (genesis = 0)
    std::string signed_by_hex;     // Pubkey (hex) of the key that endorsed this one ("" for genesis)
    std::string endorsement_sig;   // Base64 Ed25519 signature of canonical JSON by signed_by
};

void to_json(nlohmann::json& j, const RootKeyEntry& e);
void from_json(const nlohmann::json& j, RootKeyEntry& e);

/// Canonical JSON of a RootKeyEntry for signing (excludes endorsement_sig).
[[nodiscard]] std::string canonical_root_key_json(const RootKeyEntry& e);

/// Peer uptime health record used for Tier1 eligibility gating.
/// Only peers with >= 90% uptime qualify to hold root key shares
/// and participate as Tier1 authority servers.
struct PeerHealthRecord {
    std::string pubkey;             // peer's Ed25519 public key (hex or base64)
    uint64_t    first_seen{0};      // Unix timestamp of first observation
    uint64_t    total_checks{0};    // total gossip tick checks
    uint64_t    successful_checks{0}; // ticks where peer responded
    float       uptime_ratio{0.0f}; // successful / total (0.0 - 1.0)
    uint64_t    last_check{0};      // last check timestamp

    /// Minimum uptime ratio required for Tier1 authority status.
    static constexpr float kMinTier1Uptime = 0.90f;

    [[nodiscard]] bool qualifies_for_tier1() const {
        // Need at least 100 checks for meaningful data (avoids new-peer bias)
        return total_checks >= 100 && uptime_ratio >= kMinTier1Uptime;
    }
};

void to_json(nlohmann::json& j, const PeerHealthRecord& h);
void from_json(const nlohmann::json& j, PeerHealthRecord& h);

/// Root Key Chain Service.
///
/// Manages a chain of root Ed25519 keys where each new key is endorsed by the
/// previous one. This enables:
///
///   1. **Key rotation** — automatic weekly rotation generates a new root keypair,
///      the old key signs an endorsement, and the chain propagates via gossip.
///
///   2. **Root survivability** — the current root private key is split using
///      Shamir's Secret Sharing and distributed to ALL eligible Tier1 peers.
///      Threshold K = ceil(75% of N), meaning 25% of Tier1 peers can be offline
///      and the network can still reconstruct the key. If the original root server
///      dies, the remaining Tier1 peers reconstruct the key autonomously.
///
///   3. **Certificate verification** — a server certificate is valid if signed by
///      ANY non-expired key in the chain, providing backward compatibility during
///      rotation transitions.
///
///   4. **Uptime gating** — only peers with >= 90% uptime qualify for Tier1 authority
///      and receive Shamir shares. This prevents unreliable peers from holding
///      critical key material.
///
/// Shamir distribution model:
///   - N = number of eligible Tier1 peers (uptime >= 90%)
///   - K = ceil(N * 0.75), minimum 2
///   - Shares sent encrypted to each Tier1 peer via gossip (ShamirShareDistribute)
///   - On root loss, any K peers submit their shares to reconstruct
///
/// The chain is persisted to `data/identity/root_chain.json` and propagated
/// via gossip (RootKeyRotation message type).
class RootKeyChainService : public IService<RootKeyChainService> {
    friend class IService<RootKeyChainService>;

public:
    RootKeyChainService(crypto::SodiumCryptoService& crypto,
                         storage::FileStorageService& storage);

    // --- Protocol Constants (hardcoded, changeable only via Tier1 governance) ---
    static constexpr uint32_t kDefaultRotationIntervalSec = 604800;  // 7 days
    static constexpr float    kDefaultQuorumRatio         = 0.75f;   // 25% fault tolerance
    static constexpr float    kDefaultMinUptime           = 0.90f;   // 90% uptime for Tier1

    /// Set io_context for the rotation timer. Must be called before start().
    void set_io_context(asio::io_context& io);

    /// Apply governance-approved parameter changes (called by GovernanceService only).
    /// @return true if parameters were updated.
    bool apply_governance_params(uint32_t rotation_interval_sec,
                                  float quorum_ratio,
                                  float min_uptime);

    /// Get current active parameters (may differ from defaults if governance changed them).
    [[nodiscard]] uint32_t rotation_interval_sec() const { return rotation_interval_sec_; }
    [[nodiscard]] float quorum_ratio() const { return quorum_ratio_; }
    [[nodiscard]] float min_uptime() const { return min_uptime_; }

    /// Initialize the chain with a genesis root key (first-time setup).
    /// If a chain already exists, this is a no-op.
    /// @param root_keypair The initial root Ed25519 keypair.
    void initialize_genesis(const crypto::Ed25519Keypair& root_keypair);

    /// Check if a pubkey (hex) is a valid (non-expired) root key in the chain.
    [[nodiscard]] bool is_valid_root_key(const std::string& pubkey_hex) const;

    /// Check if a certificate signature was made by any valid root key.
    /// @param message The signed data.
    /// @param signature The Ed25519 signature.
    /// @return true if signed by any non-expired key in the chain.
    [[nodiscard]] bool verify_with_any_root(
        std::span<const uint8_t> message,
        const crypto::Ed25519Signature& signature) const;

    /// Get the current (latest) root public key.
    [[nodiscard]] std::string current_root_pubkey_hex() const;

    /// Get the full chain.
    [[nodiscard]] std::vector<RootKeyEntry> chain() const;

    /// Rotate the root key: generate new keypair, endorse with current key, append to chain.
    /// @return The new root public key (hex), or empty on failure.
    [[nodiscard]] std::string rotate();

    /// Accept a new root key entry from gossip (verified against chain).
    /// @return true if the entry was accepted and appended.
    bool accept_rotation(const RootKeyEntry& entry);

    /// Generate Shamir shares for dynamic distribution to Tier1 peers.
    /// N = eligible_peer_count, K = ceil(N * quorum_ratio), minimum K=2.
    /// @param eligible_peer_count Number of Tier1 peers with qualifying uptime.
    /// @return Vector of share strings ("x:base64(y)"), one per eligible peer.
    [[nodiscard]] std::vector<std::string> generate_shamir_shares(uint8_t eligible_peer_count) const;

    /// Reconstruct the root private key from Shamir shares and set it as current.
    /// @param share_strings  The K shares submitted by peers.
    /// @param expected_threshold  K value (must match what was used during split).
    /// @return true if reconstruction succeeded and key matches current root pubkey.
    bool reconstruct_from_shares(const std::vector<std::string>& share_strings,
                                  uint8_t expected_threshold);

    /// Store a Shamir share we received from the root holder.
    void store_received_share(const std::string& share_string, uint32_t generation);

    /// Get our stored share for a given generation (if any).
    [[nodiscard]] std::optional<std::string> get_stored_share(uint32_t generation) const;

    /// Check if we hold the current root private key (can sign enrollments).
    [[nodiscard]] bool has_root_private_key() const;

    /// Get the current root keypair (for enrollment signing). Only valid if has_root_private_key().
    [[nodiscard]] std::optional<crypto::Ed25519Keypair> root_keypair() const;

    // --- Peer Health Tracking ---

    /// Record a peer health check result (called every gossip tick).
    void record_peer_check(const std::string& pubkey, bool responded);

    /// Get a peer's health record.
    [[nodiscard]] PeerHealthRecord peer_health(const std::string& pubkey) const;

    /// Get all peer health records.
    [[nodiscard]] std::vector<PeerHealthRecord> all_peer_health() const;

    /// Get list of Tier1-eligible peers (uptime >= min_uptime, enough checks).
    [[nodiscard]] std::vector<std::string> eligible_tier1_peers() const;

    /// Compute the Shamir threshold for current eligible peer count.
    /// K = ceil(N * quorum_ratio), minimum 2, capped at 255.
    [[nodiscard]] uint8_t compute_threshold(uint8_t eligible_count) const;

    // IService
    [[nodiscard]] static constexpr std::string_view name() { return "RootKeyChainService"; }

private:
    void on_start();
    void on_stop();

    /// Load chain from data/identity/root_chain.json.
    void load_chain();

    /// Persist chain to data/identity/root_chain.json.
    void save_chain();

    /// Load peer health records from data/identity/peer_health.json.
    void load_peer_health();

    /// Persist peer health records.
    void save_peer_health();

    /// Verify an endorsement signature on a chain entry.
    [[nodiscard]] bool verify_endorsement(const RootKeyEntry& entry) const;

    /// Start the periodic rotation timer.
    void start_rotation_timer();
    void on_rotation_tick();

    crypto::SodiumCryptoService& crypto_;
    storage::FileStorageService& storage_;

    mutable std::mutex mutex_;
    std::vector<RootKeyEntry> chain_;

    // Current root private key (only held by the node that performed the rotation)
    std::optional<crypto::Ed25519Keypair> current_root_keypair_;

    // Shamir shares we've received from the root holder (generation -> share string)
    std::unordered_map<uint32_t, std::string> received_shares_;

    // Peer health tracking
    mutable std::mutex health_mutex_;
    std::unordered_map<std::string, PeerHealthRecord> peer_health_;

    // Rotation timer
    asio::io_context* io_{nullptr};
    std::unique_ptr<asio::steady_timer> rotation_timer_;
    uint32_t rotation_interval_sec_{604800}; // default: 7 days
    std::atomic<bool> rotation_timer_running_{false};

    // Dynamic Shamir parameters
    float quorum_ratio_{0.75f};    // K = ceil(N * this), meaning 25% can be offline
    float min_uptime_{0.90f};      // minimum uptime for Tier1 eligibility
};

} // namespace nexus::core
