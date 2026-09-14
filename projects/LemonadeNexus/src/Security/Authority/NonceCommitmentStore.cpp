#include <LemonadeNexus/Security/Authority/NonceCommitmentStore.hpp>

namespace nexus::security {

bool NonceCommitmentStore::register_session(EpochId epoch, SigningSessionId session_id) {
    return sessions_[epoch].insert(session_id).second;
}

bool NonceCommitmentStore::insert(const NonceCommitment& commitment) {
    if (commitment.commitment.empty()) {
        return false;
    }
    if (!session_registered(commitment.epoch, commitment.session_id)) {
        return false;
    }
    if (!session_participants_
             .insert({commitment.epoch, commitment.session_id, commitment.participant})
             .second) {
        return false;
    }
    const GroupKey group{commitment.epoch, commitment.key_generation};
    return seen_commitments_[group].insert(commitment.commitment).second;
}

bool NonceCommitmentStore::commitment_exists(EpochId epoch, KeyGeneration key_generation,
                                             std::span<const uint8_t> commitment) const {
    const auto group_it = seen_commitments_.find(GroupKey{epoch, key_generation});
    if (group_it == seen_commitments_.end()) {
        return false;
    }
    return group_it->second.contains(
        std::vector<uint8_t>(commitment.begin(), commitment.end()));
}

bool NonceCommitmentStore::session_registered(EpochId epoch, SigningSessionId session_id) const {
    const auto it = sessions_.find(epoch);
    return it != sessions_.end() && it->second.contains(session_id);
}

}  // namespace nexus::security
