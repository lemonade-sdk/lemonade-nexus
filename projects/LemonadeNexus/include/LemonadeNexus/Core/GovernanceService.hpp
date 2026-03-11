#pragma once

#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Core/RootKeyChain.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Gossip/GossipTypes.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <nlohmann/json.hpp>

#include <functional>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace nexus::core {

/// Democratic governance service for protocol parameter changes.
///
/// Only Tier1 peers can propose or vote on changes. Proposals require a simple
/// majority (>50%) of known Tier1 peers to pass. The governable parameters are:
///
///   - rotation_interval_sec  (root key rotation period, default 7 days)
///   - shamir_quorum_ratio    (Shamir threshold K = ceil(N * ratio), default 0.75)
///   - min_tier1_uptime       (minimum uptime for Tier1 authority, default 0.90)
///
/// These are hardcoded protocol constants that cannot be changed via CLI or
/// environment variables — only through this democratic governance protocol.
///
/// Flow:
///   1. A Tier1 peer creates a proposal (GovernanceProposal gossip message)
///   2. All Tier1 peers receive the proposal and cast votes (GovernanceVote)
///   3. When >50% of Tier1 peers approve, the change is applied
///   4. Applied changes propagate to RootKeyChainService
///   5. Proposals expire after 24 hours if quorum is not met
///
/// Persistence: proposals and votes are stored in data/governance/
class GovernanceService : public IService<GovernanceService> {
    friend class IService<GovernanceService>;

public:
    /// Governance quorum: simple majority of Tier1 peers.
    static constexpr float kGovernanceQuorum = 0.51f;

    /// Proposal vote window: 24 hours.
    static constexpr uint32_t kProposalTimeoutSec = 86400;

    /// Callback type for broadcasting governance messages via gossip.
    using BroadcastFn = std::function<void(gossip::GossipMsgType, const std::vector<uint8_t>&)>;

    GovernanceService(crypto::SodiumCryptoService& crypto,
                       storage::FileStorageService& storage,
                       RootKeyChainService& root_key_chain);

    /// Set the broadcast function (wired from GossipService).
    void set_broadcast_fn(BroadcastFn fn);

    /// Set our own keypair (for signing proposals/votes).
    void set_keypair(const crypto::Ed25519Keypair& kp);

    // --- Proposal creation ---

    /// Create a governance proposal. Only valid from Tier1 peers.
    /// @param parameter   Which parameter to change.
    /// @param new_value   The proposed new value (string-serialized).
    /// @param rationale   Human-readable reason for the change.
    /// @return proposal_id on success, empty string on failure.
    [[nodiscard]] std::string create_proposal(gossip::GovernableParam parameter,
                                               const std::string& new_value,
                                               const std::string& rationale);

    // --- Incoming gossip handlers ---

    /// Handle an incoming governance proposal from gossip.
    /// @return true if the proposal was accepted (new, valid, not duplicate).
    bool handle_proposal(const gossip::GovernanceProposalData& proposal);

    /// Handle an incoming governance vote from gossip.
    /// @return true if the vote was accepted.
    bool handle_vote(const gossip::GovernanceVoteData& vote);

    /// Expire timed-out proposals (called periodically from gossip tick).
    void expire_proposals();

    // --- Query ---

    /// Get all active (Collecting) proposals.
    [[nodiscard]] std::vector<gossip::GovernanceBallot> active_proposals() const;

    /// Get all proposals (including completed).
    [[nodiscard]] std::vector<gossip::GovernanceBallot> all_proposals() const;

    /// Get the current parameter values as JSON.
    [[nodiscard]] nlohmann::json current_params() const;

    // --- Tier1 peer count (set externally) ---

    /// Update the known Tier1 peer count (called from GossipService on each tick).
    void set_tier1_peer_count(uint32_t count);

    // IService
    [[nodiscard]] static constexpr std::string_view name() { return "GovernanceService"; }

private:
    void on_start();
    void on_stop();

    /// Verify a proposal's Ed25519 signature.
    [[nodiscard]] bool verify_proposal_signature(const gossip::GovernanceProposalData& p) const;

    /// Verify a vote's Ed25519 signature.
    [[nodiscard]] bool verify_vote_signature(const gossip::GovernanceVoteData& v) const;

    /// Canonical JSON for proposal signing (excludes signature field).
    [[nodiscard]] static std::string canonical_proposal_json(const gossip::GovernanceProposalData& p);

    /// Canonical JSON for vote signing (excludes signature field).
    [[nodiscard]] static std::string canonical_vote_json(const gossip::GovernanceVoteData& v);

    /// Check if quorum is met for a proposal and apply if approved.
    void check_governance_quorum(const std::string& proposal_id);

    /// Apply an approved governance change to the RootKeyChainService.
    void apply_proposal(const gossip::GovernanceProposalData& proposal);

    /// Validate a proposed parameter value (range checks, sanity).
    [[nodiscard]] bool validate_param_value(gossip::GovernableParam param,
                                             const std::string& value) const;

    /// Get the current value of a governable parameter as a string.
    [[nodiscard]] std::string current_param_value(gossip::GovernableParam param) const;

    /// Load governance state from disk.
    void load_state();

    /// Persist governance state to disk.
    void save_state();

    crypto::SodiumCryptoService& crypto_;
    storage::FileStorageService& storage_;
    RootKeyChainService&         root_key_chain_;

    crypto::Ed25519Keypair keypair_{};
    BroadcastFn            broadcast_fn_;

    mutable std::mutex mutex_;
    std::unordered_map<std::string, gossip::GovernanceBallot> proposals_;
    uint32_t tier1_peer_count_{0};
};

} // namespace nexus::core
