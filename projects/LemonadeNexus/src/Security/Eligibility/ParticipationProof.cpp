#include <LemonadeNexus/Security/Eligibility/ParticipationProof.hpp>

#include <LemonadeNexus/Security/CanonicalEncoding.hpp>

#include <sodium.h>

namespace nexus::security {

namespace {

inline constexpr std::string_view kChallengeDomain =
    "LEMONADE-NEXUS-T1-PARTICIPATION-CHALLENGE-V1";
inline constexpr std::string_view kResponseDomain =
    "LEMONADE-NEXUS-T1-PARTICIPATION-RESPONSE-V1";

}  // namespace

Digest participation_challenge_digest(const ParticipationChallenge& challenge) {
    CanonicalEncoder encoder(kChallengeDomain);
    encoder.add_bytes(challenge.network_id);
    encoder.add_u64(challenge.epoch);
    encoder.add_u16(challenge.security_ruleset);
    encoder.add_u16(challenge.consensus_ruleset);
    encoder.add_bytes(challenge.node_id.bytes);
    encoder.add_u64(challenge.incarnation);
    encoder.add_bytes(challenge.nonce);
    encoder.add_u64(challenge.anchor_height);
    encoder.add_bytes(challenge.anchor_state);
    encoder.add_bytes(challenge.observer.bytes);
    return encoder.digest();
}

Digest participation_response_signing_digest(const ParticipationResponse& response) {
    // The challenge digest carries the nonce and the observer, so the signature
    // covers the whole context transitively. The fields repeat here so a
    // mismatch is diagnosed rather than surfacing as a broken signature.
    CanonicalEncoder encoder(kResponseDomain);
    encoder.add_bytes(response.challenge_digest);
    encoder.add_bytes(response.network_id);
    encoder.add_u64(response.epoch);
    encoder.add_u16(response.security_ruleset);
    encoder.add_u16(response.consensus_ruleset);
    encoder.add_bytes(response.node_id.bytes);
    encoder.add_u64(response.incarnation);
    encoder.add_u64(response.anchor_height);
    encoder.add_bytes(response.anchor_state);
    return encoder.digest();
}

ParticipationResponse answer_participation_challenge(const ParticipationChallenge& challenge,
                                                     const crypto::Ed25519Keypair& identity) {
    ParticipationResponse response;
    response.challenge_digest = participation_challenge_digest(challenge);
    response.network_id = challenge.network_id;
    response.epoch = challenge.epoch;
    response.security_ruleset = challenge.security_ruleset;
    response.consensus_ruleset = challenge.consensus_ruleset;
    response.node_id.bytes = identity.public_key;
    response.incarnation = challenge.incarnation;
    response.anchor_height = challenge.anchor_height;
    response.anchor_state = challenge.anchor_state;

    const Digest digest = participation_response_signing_digest(response);
    crypto_sign_detached(response.identity_signature.data(), nullptr, digest.data(), digest.size(),
                         identity.private_key.data());
    return response;
}

std::string_view participation_failure_name(ParticipationFailure failure) {
    switch (failure) {
        case ParticipationFailure::None:                return "none";
        case ParticipationFailure::ChallengeMismatch:   return "no matching challenge";
        case ParticipationFailure::NetworkMismatch:     return "wrong network";
        case ParticipationFailure::EpochMismatch:       return "wrong epoch";
        case ParticipationFailure::RulesetMismatch:     return "wrong ruleset";
        case ParticipationFailure::IdentityMismatch:    return "wrong node identity";
        case ParticipationFailure::IncarnationMismatch: return "wrong incarnation";
        case ParticipationFailure::AnchorMismatch:      return "wrong anchor";
        case ParticipationFailure::SignatureInvalid:    return "signature invalid";
    }
    return "unknown failure";
}

ParticipationFailure verify_participation_response(const ParticipationResponse& response,
                                                    const ParticipationChallenge& challenge) {
    if (response.challenge_digest != participation_challenge_digest(challenge)) {
        return ParticipationFailure::ChallengeMismatch;
    }
    if (response.network_id != challenge.network_id) {
        return ParticipationFailure::NetworkMismatch;
    }
    if (response.epoch != challenge.epoch) {
        return ParticipationFailure::EpochMismatch;
    }
    if (response.security_ruleset != challenge.security_ruleset ||
        response.consensus_ruleset != challenge.consensus_ruleset) {
        return ParticipationFailure::RulesetMismatch;
    }
    if (response.node_id != challenge.node_id) {
        return ParticipationFailure::IdentityMismatch;
    }
    if (response.incarnation != challenge.incarnation) {
        return ParticipationFailure::IncarnationMismatch;
    }
    if (response.anchor_height != challenge.anchor_height ||
        response.anchor_state != challenge.anchor_state) {
        return ParticipationFailure::AnchorMismatch;
    }
    // Last, because it is the expensive one, and because a mismatch above is a
    // better diagnosis than a broken signature.
    const Digest digest = participation_response_signing_digest(response);
    if (crypto_sign_verify_detached(response.identity_signature.data(), digest.data(),
                                    digest.size(), response.node_id.bytes.data()) != 0) {
        return ParticipationFailure::SignatureInvalid;
    }
    return ParticipationFailure::None;
}

}  // namespace nexus::security
