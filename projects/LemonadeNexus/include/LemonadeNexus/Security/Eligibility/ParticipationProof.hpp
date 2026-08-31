#pragma once

// The participation exchange for a candidate that holds no epoch vote key.
//
// An accepted HotStuff vote is the strongest participation proof there is, but
// only a current Tier 1 member can produce one. A Tier 2 candidate has to be
// able to prove the same fact — an authenticated current participant, anchored
// to finalized mesh state — before it is selected, or Tier 1 membership could
// only ever be renewed and never entered.
//
// No existing exchange proves enough. Attestation evidence binds identity,
// incarnation, epoch and ruleset but nothing about finalized state, and it is
// already what continuity counts, so reusing it would collapse the two facts
// into one. A sync request is unsigned. Gossip and WireGuard authenticate a
// transport, which is not an authorization result. So this is the smallest
// dedicated challenge-response that binds everything required, and nothing
// else: it is not a health protocol and carries no load, latency or score.
//
// The observer chooses the finalized state reference, so it knows it
// independently, and the candidate's signature binds its identity to that point
// in finalized history. A response harvested elsewhere answers no challenge
// this observer issued.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstdint>
#include <string_view>

namespace nexus::security {

/// Issued by a current Tier 1 member to any authenticated candidate.
struct ParticipationChallenge {
    NetworkId network_id{};
    EpochId epoch{};
    SecurityRulesetVersion security_ruleset{};
    ConsensusRulesetVersion consensus_ruleset{};

    /// Who must answer. A node answers only a challenge naming itself.
    NodeId node_id{};
    IncarnationId incarnation{};

    Nonce nonce{};

    /// The finalized state the observer holds: its own quorum-certified height
    /// and the committed state root there. The candidate binds its answer to
    /// this, so the observation cannot be replayed against another point in
    /// history or another mesh.
    Height finalized_height{};
    Digest finalized_state{};

    NodeId observer{};
};

[[nodiscard]] Digest participation_challenge_digest(const ParticipationChallenge& challenge);

/// The candidate's signed answer. It proves possession of the node identity
/// key and nothing about hardware; platform facts travel through attestation.
struct ParticipationResponse {
    Digest challenge_digest{};

    NetworkId network_id{};
    EpochId epoch{};
    SecurityRulesetVersion security_ruleset{};
    ConsensusRulesetVersion consensus_ruleset{};

    NodeId node_id{};
    IncarnationId incarnation{};

    Height finalized_height{};
    Digest finalized_state{};

    crypto::Ed25519Signature identity_signature{};
};

[[nodiscard]] Digest participation_response_signing_digest(const ParticipationResponse& response);

/// Builds the answer to a challenge and signs it under the node identity key.
/// A node identity IS its Ed25519 public key, so there is no separate key to
/// look up and no way to answer as another node.
[[nodiscard]] ParticipationResponse answer_participation_challenge(
    const ParticipationChallenge& challenge, const crypto::Ed25519Keypair& identity);

/// Why a response proved nothing. Every value is a refusal.
enum class ParticipationFailure : uint16_t {
    None,
    /// No outstanding challenge matches this answer. Checked before the
    /// challenge is consumed, so a replayed answer cannot deny a live one.
    ChallengeMismatch,
    NetworkMismatch,
    EpochMismatch,
    RulesetMismatch,
    IdentityMismatch,
    IncarnationMismatch,
    /// The answer names finalized state other than the one the challenge did.
    StateMismatch,
    SignatureInvalid,
};

[[nodiscard]] std::string_view participation_failure_name(ParticipationFailure failure);

/// Verifies one answer against the challenge that provoked it.
[[nodiscard]] ParticipationFailure verify_participation_response(
    const ParticipationResponse& response, const ParticipationChallenge& challenge);

}  // namespace nexus::security
