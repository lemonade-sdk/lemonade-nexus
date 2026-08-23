#include <LemonadeNexus/Security/Epoch/EpochManager.hpp>

#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Security/Epoch/Tier1Selector.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Policy/Tier1TargetPolicy.hpp>

#include <algorithm>

namespace nexus::security {

EpochManager::EpochManager(EpochState initial,
                           std::map<NodeId, crypto::Ed25519PublicKey> current_vote_keys)
    : current_(std::move(initial)), current_vote_keys_(std::move(current_vote_keys)) {}

bool EpochManager::transition_active() const {
    return transition_.has_value() && transition_->phase != EpochTransitionPhase::Aborted;
}

bool EpochManager::prepare_next_epoch(const Tier1Set& frozen_eligible,
                                      std::size_t admitted_server_count) {
    if (transition_active()) {
        return false;
    }

    const auto outcome = tier1_target_outcome(admitted_server_count, frozen_eligible.size());
    if (outcome.active_target < constants::kMinActiveTier1) {
        return false;
    }
    target_shortfall_ = outcome.target_shortfall;
    reserve_shortfall_ = outcome.reserve_shortfall;

    // The eligible set is frozen before ranking, so a candidate cannot re-time
    // its entry to shop for a better score.
    rank_ = Tier1Selector::rank(frozen_eligible, current_.authority_public_key,
                                current_.id + 1);

    EpochTransition transition;
    transition.from_epoch = current_.id;
    transition.to_epoch = current_.id + 1;
    transition.phase = EpochTransitionPhase::Attesting;
    transition.selected_members.assign(rank_.begin(),
                                       rank_.begin() + static_cast<std::ptrdiff_t>(
                                                           outcome.active_target));

    auto selected_set = Tier1Set::from_nodes(transition.selected_members);
    transition.participant_set_digest = selected_set->digest();
    transition.next_consensus_quorum =
        constants::consensus_quorum(transition.selected_members.size());
    transition.next_authority_threshold =
        constants::authority_threshold(transition.selected_members.size());

    transition_ = std::move(transition);
    removed_candidates_.clear();
    final_verdicts_.clear();
    next_vote_keys_.clear();
    authorized_ = false;
    authorization_certificate_digest_ = Digest{};
    return true;
}

void EpochManager::drop_participant_state(const NodeId& node) {
    final_verdicts_.erase(node);
    next_vote_keys_.erase(node);
    // Any DKG outcome belongs to the old participant set; it restarts.
    transition_->dkg_transcript_digest = Digest{};
    transition_->next_authority_key = crypto::Ed25519PublicKey{};
    authorized_ = false;
}

bool EpochManager::pull_replacement() {
    auto& selected = transition_->selected_members;
    for (const auto& candidate : rank_) {
        const bool already_selected =
            std::find(selected.begin(), selected.end(), candidate) != selected.end();
        if (already_selected || removed_candidates_.contains(candidate)) {
            continue;
        }
        selected.push_back(candidate);
        return true;
    }
    return false;
}

void EpochManager::recompute_phase() {
    auto& transition = *transition_;
    const auto& selected = transition.selected_members;

    const auto selected_set = Tier1Set::from_nodes(selected);
    transition.participant_set_digest = selected_set->digest();
    transition.next_consensus_quorum = constants::consensus_quorum(selected.size());
    transition.next_authority_threshold = constants::authority_threshold(selected.size());

    const bool all_attested = std::all_of(selected.begin(), selected.end(),
                                          [this](const NodeId& node) {
                                              const auto it = final_verdicts_.find(node);
                                              return it != final_verdicts_.end() &&
                                                     it->second.passed;
                                          });
    if (!all_attested) {
        transition.phase = EpochTransitionPhase::Attesting;
        transition.attestation_root = Digest{};
        return;
    }
    transition.attestation_root = computed_attestation_root();

    const bool all_keys = std::all_of(selected.begin(), selected.end(),
                                      [this](const NodeId& node) {
                                          return next_vote_keys_.contains(node);
                                      });
    if (!all_keys) {
        transition.phase = EpochTransitionPhase::GeneratingVoteKeys;
        return;
    }

    constexpr crypto::Ed25519PublicKey kZeroKey{};
    if (transition.next_authority_key == kZeroKey) {
        transition.phase = EpochTransitionPhase::GeneratingAuthorityKey;
        return;
    }
    transition.phase = EpochTransitionPhase::Ready;
}

Digest EpochManager::computed_attestation_root() const {
    // Sorted by node identity so every verifier derives the same root.
    CanonicalEncoder encoder("lemonade-nexus/attestation-root:v1");
    encoder.add_u64(transition_->selected_members.size());
    std::vector<NodeId> sorted = transition_->selected_members;
    std::sort(sorted.begin(), sorted.end());
    for (const auto& node : sorted) {
        encoder.add_bytes(node.bytes);
        encoder.add_bytes(final_verdicts_.at(node).evidence_digest);
    }
    return encoder.digest();
}

bool EpochManager::record_final_attestation(const AttestationVerdict& verdict) {
    if (!transition_active()) {
        return false;
    }
    if (transition_->phase != EpochTransitionPhase::Attesting &&
        transition_->phase != EpochTransitionPhase::GeneratingVoteKeys &&
        transition_->phase != EpochTransitionPhase::GeneratingAuthorityKey) {
        return false;
    }
    // The current epoch issues the final challenges; a verdict from another
    // epoch context proves nothing about this handoff.
    if (verdict.epoch != current_.id) {
        return false;
    }
    auto& selected = transition_->selected_members;
    if (std::find(selected.begin(), selected.end(), verdict.node_id) == selected.end()) {
        return false;
    }

    if (verdict.passed) {
        final_verdicts_[verdict.node_id] = verdict;
        recompute_phase();
        return true;
    }

    // A failed prerequisite is final for this handoff: the member leaves and
    // the next hash-ranked candidate takes its place (architecture 8.5).
    removed_candidates_.insert(verdict.node_id);
    selected.erase(std::remove(selected.begin(), selected.end(), verdict.node_id),
                   selected.end());
    drop_participant_state(verdict.node_id);

    if (!pull_replacement() && selected.size() < constants::kMinActiveTier1) {
        abort_transition(EpochTransitionFailure::EligiblePoolBelowMinimum);
        return true;
    }
    target_shortfall_ = target_shortfall_ || selected.size() < rank_.size();
    recompute_phase();
    return true;
}

bool EpochManager::replace_participant(const NodeId& node, EpochTransitionFailure reason) {
    if (!transition_active()) {
        return false;
    }
    auto& selected = transition_->selected_members;
    const auto it = std::find(selected.begin(), selected.end(), node);
    if (it == selected.end()) {
        return false;
    }
    removed_candidates_.insert(node);
    selected.erase(it);
    drop_participant_state(node);

    if (!pull_replacement() && selected.size() < constants::kMinActiveTier1) {
        abort_transition(reason);
        return true;
    }
    recompute_phase();
    return true;
}

bool EpochManager::record_vote_key(const NodeId& node, const crypto::Ed25519PublicKey& key) {
    if (!transition_active() || transition_->phase == EpochTransitionPhase::Ready) {
        return false;
    }
    constexpr crypto::Ed25519PublicKey kZeroKey{};
    if (key == kZeroKey) {
        return false;
    }
    const auto& selected = transition_->selected_members;
    if (std::find(selected.begin(), selected.end(), node) == selected.end()) {
        return false;
    }
    const auto existing = next_vote_keys_.find(node);
    if (existing != next_vote_keys_.end()) {
        // Idempotent for the same key; a changed key mid-handoff is refused.
        return existing->second == key;
    }
    next_vote_keys_[node] = key;
    recompute_phase();
    return true;
}

bool EpochManager::record_dkg_result(const crypto::Ed25519PublicKey& group_public_key,
                                     const Digest& dkg_transcript_digest) {
    if (!transition_active() ||
        transition_->phase != EpochTransitionPhase::GeneratingAuthorityKey) {
        return false;
    }
    constexpr crypto::Ed25519PublicKey kZeroKey{};
    constexpr Digest kZeroDigest{};
    if (group_public_key == kZeroKey || dkg_transcript_digest == kZeroDigest) {
        return false;
    }
    transition_->next_authority_key = group_public_key;
    transition_->dkg_transcript_digest = dkg_transcript_digest;
    recompute_phase();
    return true;
}

bool EpochManager::record_handoff_authorization(const Digest& consensus_certificate_digest) {
    if (!transition_active() || transition_->phase != EpochTransitionPhase::Ready) {
        return false;
    }
    constexpr Digest kZeroDigest{};
    if (consensus_certificate_digest == kZeroDigest) {
        return false;
    }
    authorized_ = true;
    authorization_certificate_digest_ = consensus_certificate_digest;
    return true;
}

std::optional<EpochState> EpochManager::activate_next_epoch() {
    if (!transition_.has_value() || !ready_for_activation(*transition_) || !authorized_) {
        return std::nullopt;
    }

    auto selected_set = Tier1Set::from_nodes(transition_->selected_members);
    EpochState next = make_epoch_state(transition_->to_epoch, current_.network_id,
                                       std::move(*selected_set),
                                       transition_->next_authority_key,
                                       transition_->attestation_root);

    current_ = std::move(next);
    current_vote_keys_ = std::move(next_vote_keys_);
    next_vote_keys_.clear();
    transition_.reset();
    rank_.clear();
    removed_candidates_.clear();
    final_verdicts_.clear();
    authorized_ = false;
    return current_;
}

void EpochManager::abort_transition(EpochTransitionFailure reason) {
    if (!transition_.has_value()) {
        return;
    }
    // The old epoch stays authoritative; the aborted record remains visible
    // until the next prepare replaces it.
    transition_->phase = EpochTransitionPhase::Aborted;
    transition_->failure = reason;
    authorized_ = false;
}

}  // namespace nexus::security
