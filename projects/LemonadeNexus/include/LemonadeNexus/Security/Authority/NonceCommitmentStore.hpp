#pragma once

// The mesh memory of spent FROST nonce commitments.
//
// A restored snapshot can forget that its signer already used a commitment.
// The mesh record lives outside that signer, so a repeated commitment or a
// repeated signing session is rejected even when the local signer forgot it.
// The store holds public commitments only — never a secret nonce.

#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstdint>
#include <map>
#include <set>
#include <span>
#include <vector>

namespace nexus::security {

struct NonceCommitment {
    EpochId epoch = 0;
    KeyGeneration key_generation = 0;

    SigningSessionId session_id = 0;
    NodeId participant;

    std::vector<uint8_t> commitment;
};

class NonceCommitmentStore {
public:
    /// Registers a signing session identifier. Returns false when the
    /// identifier was already used — a repeated session is a replay.
    [[nodiscard]] bool register_session(EpochId epoch, SigningSessionId session_id);

    /// Records one participant commitment. Returns false when the commitment
    /// bytes were already seen for this epoch group key, or when this
    /// participant already committed in this session, or when the session was
    /// never registered.
    [[nodiscard]] bool insert(const NonceCommitment& commitment);

    [[nodiscard]] bool commitment_exists(EpochId epoch, KeyGeneration key_generation,
                                         std::span<const uint8_t> commitment) const;

    [[nodiscard]] bool session_registered(EpochId epoch, SigningSessionId session_id) const;

private:
    using GroupKey = std::pair<EpochId, KeyGeneration>;

    std::map<GroupKey, std::set<std::vector<uint8_t>>> seen_commitments_;
    std::map<EpochId, std::set<SigningSessionId>> sessions_;
    std::set<std::tuple<EpochId, SigningSessionId, NodeId>> session_participants_;
};

}  // namespace nexus::security
