#pragma once

// The atomic epoch handoff (architecture 8.5).
//
// The manager answers one question: what security state is Nexus in now. It
// drives the transition phases — select, final-attest, vote keys, DKG, ready,
// authorize, activate — and it never activates a partial transition. The old
// epoch stays authoritative until activation; every abort leaves it in place.
//
// The manager does not verify SNP evidence, does not run HotStuff, and does
// not compute FROST math. It records the outcomes those services produce.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>
#include <LemonadeNexus/Security/Epoch/EpochState.hpp>
#include <LemonadeNexus/Security/Epoch/EpochTransition.hpp>
#include <LemonadeNexus/Security/Epoch/Tier1Set.hpp>

#include <map>
#include <optional>
#include <set>
#include <vector>

namespace nexus::security {

class EpochManager {
public:
    EpochManager(EpochState initial,
                 std::map<NodeId, crypto::Ed25519PublicKey> current_vote_keys);

    /// Freezes the eligible set and selects the next Tier 1 members by hash
    /// rank. Refuses when a transition is already in progress, or when the
    /// reachable active target falls below the compiled minimum.
    [[nodiscard]] bool prepare_next_epoch(const Tier1Set& frozen_eligible,
                                          std::size_t admitted_server_count);

    /// Records one final-attestation verdict for a selected member. A failing
    /// verdict removes the member and pulls the next hash-ranked candidate;
    /// when no candidate remains, the set shrinks while it stays at or above
    /// the compiled minimum, otherwise the transition aborts.
    [[nodiscard]] bool record_final_attestation(const AttestationVerdict& verdict);

    /// Removes a selected member that went silent (handoff timeout) and pulls
    /// the next hash-ranked candidate. Collected state for the removed member
    /// is dropped and the DKG restarts.
    [[nodiscard]] bool replace_participant(const NodeId& node, EpochTransitionFailure reason);

    /// Records the epoch BFT vote key a selected member registered. One key
    /// per member; a changed key mid-handoff is refused.
    [[nodiscard]] bool record_vote_key(const NodeId& node, const crypto::Ed25519PublicKey& key);

    /// Records the fresh DKG outcome for the next epoch group.
    [[nodiscard]] bool record_dkg_result(const crypto::Ed25519PublicKey& group_public_key,
                                         const Digest& dkg_transcript_digest);

    /// Records that the current epoch finalized the handoff in consensus.
    [[nodiscard]] bool record_handoff_authorization(const Digest& consensus_certificate_digest);

    /// Activates the next epoch. Requires a Ready transition plus the recorded
    /// handoff authorization; returns the new current state.
    [[nodiscard]] std::optional<EpochState> activate_next_epoch();

    void abort_transition(EpochTransitionFailure reason);

    [[nodiscard]] const EpochState& current() const { return current_; }
    [[nodiscard]] const EpochTransition* transition() const {
        return transition_.has_value() ? &*transition_ : nullptr;
    }
    [[nodiscard]] const std::map<NodeId, crypto::Ed25519PublicKey>& current_vote_keys() const {
        return current_vote_keys_;
    }
    [[nodiscard]] const std::map<NodeId, crypto::Ed25519PublicKey>& next_vote_keys() const {
        return next_vote_keys_;
    }
    [[nodiscard]] bool target_shortfall() const { return target_shortfall_; }
    [[nodiscard]] bool reserve_shortfall() const { return reserve_shortfall_; }

private:
    [[nodiscard]] bool transition_active() const;
    [[nodiscard]] bool pull_replacement();
    void drop_participant_state(const NodeId& node);
    void recompute_phase();
    [[nodiscard]] Digest computed_attestation_root() const;

    EpochState current_;
    std::map<NodeId, crypto::Ed25519PublicKey> current_vote_keys_;

    std::optional<EpochTransition> transition_;
    std::vector<NodeId> rank_;
    std::set<NodeId> removed_candidates_;
    std::map<NodeId, AttestationVerdict> final_verdicts_;
    std::map<NodeId, crypto::Ed25519PublicKey> next_vote_keys_;
    bool authorized_ = false;
    Digest authorization_certificate_digest_{};
    bool target_shortfall_ = false;
    bool reserve_shortfall_ = false;
};

}  // namespace nexus::security
