#pragma once

// One explicit epoch transition object (architecture 22).
//
// The old epoch stays authoritative until the transition is complete. A
// partial transition must never activate: ready_for_activation is the one
// gate, and it demands positive evidence for every field, so a
// default-constructed or half-filled transition always fails it.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstddef>
#include <cstdint>
#include <vector>

namespace nexus::security {

enum class EpochTransitionPhase {
    Selecting,
    Attesting,
    GeneratingVoteKeys,
    GeneratingAuthorityKey,
    Ready,
    Finalizing,
    Aborted,
};

enum class EpochTransitionFailure : uint16_t {
    None,
    EligiblePoolBelowMinimum,
    FinalAttestationFailed,
    VoteKeyMissing,
    DkgFailed,
    ThresholdUnreachable,
    HandoffTimeout,
    AuthorizationMissing,
};

struct EpochTransition {
    EpochId from_epoch{};
    EpochId to_epoch{};

    EpochTransitionPhase phase{EpochTransitionPhase::Selecting};

    std::vector<NodeId> selected_members;

    Digest participant_set_digest{};
    Digest attestation_root{};
    Digest dkg_transcript_digest{};

    crypto::Ed25519PublicKey next_authority_key{};

    std::size_t next_consensus_quorum{};
    std::size_t next_authority_threshold{};

    EpochTransitionFailure failure{EpochTransitionFailure::None};
};

[[nodiscard]] inline bool ready_for_activation(const EpochTransition& transition) {
    constexpr crypto::Ed25519PublicKey kZeroKey{};
    constexpr Digest kZeroDigest{};
    return transition.phase == EpochTransitionPhase::Ready
        && transition.failure == EpochTransitionFailure::None
        && transition.selected_members.size() >= constants::kMinActiveTier1
        && transition.next_authority_key != kZeroKey
        && transition.dkg_transcript_digest != kZeroDigest
        && transition.participant_set_digest != kZeroDigest;
}

}  // namespace nexus::security
