#pragma once

// One FROST signing attempt over one finalized authority object.
//
// A session identifier is used once. An aborted session never resumes: the
// retry is a new session with a new identifier and a fresh nonce, because a
// restored snapshot that replays an old session must find it already spent.

#include <LemonadeNexus/Security/Authority/AuthorityObject.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <vector>

namespace nexus::security {

enum class SigningPhase : uint16_t {
    Created,
    CollectingCommitments,
    CollectingShares,
    Complete,
    Aborted,
};

struct SigningSession {
    SigningSessionId id = 0;

    EpochId epoch = 0;
    KeyGeneration key_generation = 0;

    AuthorityObject object;

    std::vector<NodeId> signer_set;

    SigningPhase phase = SigningPhase::Created;
};

}  // namespace nexus::security
