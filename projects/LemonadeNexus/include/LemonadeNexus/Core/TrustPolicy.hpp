#pragma once

#include <LemonadeNexus/Core/BinaryAttestation.hpp>
#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Core/TeeAttestation.hpp>
#include <LemonadeNexus/Core/TrustTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>

#include <mutex>
#include <string>
#include <unordered_map>

namespace nexus::core {

/// Per-peer trust state tracked by the TrustPolicyService.
struct PeerTrustState {
    std::string pubkey;                          ///< base64 Ed25519 pubkey
    TrustTier tier{TrustTier::Untrusted};        ///< current trust level
    TeePlatform platform{TeePlatform::None};      ///< their reported TEE platform
    uint64_t last_verified{0};                   ///< unix timestamp of last successful verification
    uint64_t last_token_timestamp{0};            ///< timestamp from the last valid token
    std::string attestation_hash;                ///< hash of their last verified TEE report
    std::string binary_hash;                     ///< binary hash from their last token
    uint32_t failed_verifications{0};            ///< consecutive failures (demotion trigger)
};

/// Central zero-trust enforcement service.
///
/// Every operation on the mesh is gated through this service:
///   - `authorize(pubkey, operation)` — checks if a peer's trust tier allows the operation
///   - `verify_and_update(pubkey, token)` — verifies an AttestationToken, updates trust state
///   - `challenge_peer(pubkey)` — generates a TEE challenge nonce for mutual verification
///   - `handle_challenge_response(pubkey, report)` — validates a TEE report in response to challenge
///
/// Trust state is never cached indefinitely. Tier 1 status requires a fresh, valid
/// AttestationToken on every sensitive transaction (zero-trust). If a peer's token
/// expires or verification fails, they are immediately demoted to Tier 2.
///
/// Docker compatibility:
///   Trust policy doesn't care about the container runtime — it only checks
///   attestation tokens and TEE reports. If the TEE hardware is passed through
///   to Docker (--device=/dev/sgx_enclave, etc.), attestation works normally.
class TrustPolicyService : public IService<TrustPolicyService> {
    friend class IService<TrustPolicyService>;

public:
    TrustPolicyService(TeeAttestationService& tee,
                        BinaryAttestationService& binary_attestation,
                        crypto::SodiumCryptoService& crypto);

    // -----------------------------------------------------------------------
    // Zero-trust authorization — call this BEFORE processing any message
    // -----------------------------------------------------------------------

    /// Check if a peer is authorized for a specific operation.
    /// This is the main gate — called on every incoming gossip message.
    [[nodiscard]] bool authorize(const std::string& pubkey, TrustOperation op) const;

    /// Verify an AttestationToken and update the peer's trust tier.
    /// Returns the peer's trust tier AFTER verification.
    /// On failure, the peer is demoted to Tier 2 (or Untrusted).
    [[nodiscard]] TrustTier verify_and_update(const std::string& pubkey,
                                               const AttestationToken& token);

    // -----------------------------------------------------------------------
    // TEE challenge-response for mutual verification
    // -----------------------------------------------------------------------

    /// Generate a challenge nonce for a peer. The peer must respond with a
    /// signed TEE attestation report bound to this nonce.
    [[nodiscard]] std::array<uint8_t, 32> challenge_peer(const std::string& pubkey);

    /// Handle a TEE report sent in response to our challenge.
    /// Returns true if the report is valid and the peer is promoted to Tier 1.
    [[nodiscard]] bool handle_challenge_response(
        const std::string& pubkey,
        const TeeAttestationReport& report);

    // -----------------------------------------------------------------------
    // Trust state queries
    // -----------------------------------------------------------------------

    /// Get the current trust tier of a peer.
    [[nodiscard]] TrustTier peer_tier(const std::string& pubkey) const;

    /// Get the full trust state for a peer (for diagnostics / API).
    [[nodiscard]] PeerTrustState peer_state(const std::string& pubkey) const;

    /// Get our own trust tier (based on local TEE availability).
    [[nodiscard]] TrustTier our_tier() const;

    /// Generate an attestation token signed with the given keypair.
    /// Used by GossipService to attach tokens to outgoing messages.
    [[nodiscard]] AttestationToken generate_attestation_token(
        const crypto::Ed25519Keypair& keypair);

    /// Access the underlying TEE attestation service (for challenge-response).
    [[nodiscard]] TeeAttestationService& tee_attestation_service() { return tee_; }

    /// Get all tracked peers and their trust states.
    [[nodiscard]] std::vector<PeerTrustState> all_peer_states() const;

    /// Explicitly set a peer to Tier 2 (certificate-only, e.g., after adding via certificate).
    void set_peer_tier2(const std::string& pubkey);

    /// Remove a peer from the trust state map entirely.
    void remove_peer(const std::string& pubkey);

    /// Demote all peers whose last verification is older than max_age_sec.
    /// Called periodically (e.g., from gossip timer) to enforce freshness.
    void expire_stale_peers(uint64_t max_age_sec);

    /// Maximum consecutive verification failures before demotion to Untrusted.
    static constexpr uint32_t kMaxFailedVerifications = 3;

    /// Maximum age (seconds) of last successful verification before auto-demotion.
    static constexpr uint64_t kTrustExpirationSec = 600;  // 10 minutes

private:
    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "TrustPolicyService"; }

    /// Internal: find or create a peer trust state entry.
    PeerTrustState& get_or_create(const std::string& pubkey);

    TeeAttestationService& tee_;
    BinaryAttestationService& binary_attestation_;
    crypto::SodiumCryptoService& crypto_;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, PeerTrustState> peers_;

    // Outstanding challenges: pubkey → nonce
    std::unordered_map<std::string, std::array<uint8_t, 32>> pending_challenges_;
};

} // namespace nexus::core
