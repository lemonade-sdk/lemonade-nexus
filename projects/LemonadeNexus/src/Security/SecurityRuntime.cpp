#include <LemonadeNexus/Security/SecurityRuntime.hpp>

#include <LemonadeNexus/Security/Consensus/LeaderSelection.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <algorithm>

namespace nexus::security {

SecurityRuntime::SecurityRuntime(SecurityRuntimeConfig config)
    : config_(std::move(config)),
      attestation_(config_.profile, config_.amd_revocation),
      authority_(config_.self, commitments_),
      consensus_store_(config_.consensus_directory) {}

AuthorityEpochContext SecurityRuntime::authority_context() const {
    const EpochState& current = epochs_->current();
    AuthorityEpochContext context;
    context.network_id = current.network_id;
    context.epoch = current.id;
    context.consensus_quorum = current.consensus_quorum;
    context.authority_threshold = current.authority_threshold;
    context.members = current.tier1_members;
    context.vote_keys = epochs_->current_vote_keys();
    return context;
}

bool SecurityRuntime::start_consensus(EpochVoteKey own_vote_key, const Digest& previous_checkpoint) {
    const EpochState& current = epochs_->current();
    if (!current.tier1_members.contains(config_.self)) {
        return false;
    }
    HotStuffConfig config;
    config.security_ruleset = current.security_ruleset;
    config.consensus_ruleset = current.consensus_ruleset;
    config.network_id = current.network_id;
    config.epoch = current.id;
    // The epoch chains from the checkpoint that authorized it; the same value
    // seeds the deterministic leader order.
    config.genesis_digest = previous_checkpoint;
    config.leader_order = LeaderSelection::order(current.tier1_members.members(),
                                                 previous_checkpoint, current.id);
    config.vote_keys = epochs_->current_vote_keys();
    config.quorum = current.consensus_quorum;
    config.self = config_.self;
    config.transition_validator = config_.transition_validator;

    consensus_ = std::make_unique<HotStuffService>(std::move(config), std::move(own_vote_key),
                                                   consensus_store_);
    return consensus_->usable();
}

bool SecurityRuntime::adopt_epoch_one(const BootstrapCertificate& certificate,
                                      const crypto::Ed25519PublicKey& genesis_public_key,
                                      Tier1Set founders,
                                      std::map<NodeId, crypto::Ed25519PublicKey> vote_keys,
                                      std::optional<DkgResult> own_dkg,
                                      std::optional<EpochVoteKey> own_vote_key) {
    if (epochs_.has_value()) {
        return false;
    }
    if (!verify_bootstrap_certificate(certificate, genesis_public_key)) {
        return false;
    }
    if (certificate.epoch != 1 ||
        certificate.security_ruleset != constants::kSecurityRulesetVersion ||
        certificate.consensus_ruleset != constants::kConsensusRulesetVersion) {
        return false;
    }
    // The certificate names the founders and the compiled threshold; the
    // adopted state must be exactly what Genesis signed.
    if (certificate.tier1_set_digest != founders.digest() ||
        certificate.authority_threshold != constants::authority_threshold(founders.size()) ||
        founders.size() < constants::kMinActiveTier1) {
        return false;
    }
    for (const auto& member : founders.members()) {
        if (!vote_keys.contains(member)) {
            return false;
        }
    }

    const bool member = founders.contains(config_.self);
    if (member && (!own_dkg.has_value() || !own_vote_key.has_value())) {
        return false;
    }
    if (own_dkg.has_value() &&
        (own_dkg->group_public_key != certificate.authority_public_key ||
         own_dkg->transcript_digest != certificate.dkg_transcript_digest ||
         own_dkg->participant_set_digest != certificate.tier1_set_digest)) {
        return false;
    }

    EpochState epoch_one = make_epoch_state(1, certificate.network_id, std::move(founders),
                                            certificate.authority_public_key,
                                            certificate.attestation_root);
    epochs_.emplace(std::move(epoch_one), std::move(vote_keys));

    if (!member) {
        return true;
    }
    if (!authority_.install_epoch(authority_context(), std::move(*own_dkg))) {
        epochs_.reset();
        return false;
    }
    return start_consensus(std::move(*own_vote_key),
                           bootstrap_certificate_signing_digest(certificate));
}

bool SecurityRuntime::restore_epoch(StoredEpoch stored,
                                    std::optional<EpochVoteKey> own_vote_key) {
    if (epochs_.has_value()) {
        return false;
    }
    const bool member = stored.state.tier1_members.contains(config_.self);
    const Digest checkpoint = stored.checkpoint;
    epochs_.emplace(std::move(stored.state), std::move(stored.vote_keys));
    if (!member || !own_vote_key.has_value()) {
        return true;
    }
    return start_consensus(std::move(*own_vote_key), checkpoint);
}

bool SecurityRuntime::activate_next_epoch(std::optional<DkgResult> own_dkg,
                                          std::optional<EpochVoteKey> own_vote_key,
                                          const Digest& previous_checkpoint) {
    if (!epochs_.has_value()) {
        return false;
    }
    const EpochTransition* transition = epochs_->transition();
    if (transition == nullptr || !ready_for_activation(*transition)) {
        return false;
    }
    const bool member = std::find(transition->selected_members.begin(),
                                  transition->selected_members.end(),
                                  config_.self) != transition->selected_members.end();
    if (member && (!own_dkg.has_value() || !own_vote_key.has_value())) {
        return false;
    }
    if (own_dkg.has_value() &&
        (own_dkg->group_public_key != transition->next_authority_key ||
         own_dkg->transcript_digest != transition->dkg_transcript_digest ||
         own_dkg->participant_set_digest != transition->participant_set_digest)) {
        return false;
    }

    if (!epochs_->activate_next_epoch().has_value()) {
        return false;
    }

    // The old epoch's consensus and share end here, before anything new
    // starts: no window exists where both epochs can act.
    consensus_.reset();
    if (!member) {
        authority_.clear_epoch();
        return true;
    }
    if (!authority_.install_epoch(authority_context(), std::move(*own_dkg))) {
        return false;
    }
    return start_consensus(std::move(*own_vote_key), previous_checkpoint);
}

}  // namespace nexus::security
