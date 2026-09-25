#pragma once

// One Tier 1 member's signed statement about one candidate.
//
// Mesh facts are not self-reported. A candidate cannot say how long it has been
// up or how well it participates; the members that watched it say so, each
// signs its own statement, and a quorum of them is what makes a fact.
//
// Nothing here carries a wall-clock time. A peer-supplied timestamp is a value
// an adversary chooses, so continuity is measured in protocol state instead:
// the epoch the observation belongs to, and the quorum-certified height the
// observer held when it made the statement.
//
// Architecture reference: Security Architecture Final Draft 1.1, section 13.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Attestation/VerifiedPlatformClaims.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstdint>

namespace nexus::security {

enum class ObservationKind : uint16_t {
    /// The observer verified a fresh attestation from the subject itself.
    Attestation,
    /// The observer accepted authenticated security-plane traffic from the
    /// subject at or above finalized state the observer holds.
    Participation,
};

/// A deterministic protocol fault, proved rather than judged. Any unresolved
/// fault denies mesh health; none of these is an opinion about a peer.
enum class ObjectiveFault : uint16_t {
    DuplicateIncarnation,
    Equivocation,
    InvalidConsensusBehavior,
};

struct EligibilityObservation {
    NetworkId network_id{};
    /// The epoch this statement belongs to. Observations expire by epoch, so a
    /// replayed old statement cannot extend anything.
    EpochId epoch{};

    NodeId subject{};
    IncarnationId subject_incarnation{};
    ObservationKind kind{};

    /// Which attestation the observer verified. Every challenge carries a fresh
    /// nonce, so two observations with distinct digests are two separate
    /// rounds — that is what makes continuity countable without a clock.
    /// Empty for a Participation observation.
    Digest attestation_digest{};

    /// What the observer's verifier proved about the subject's platform.
    ///
    /// Platform facts travel here for the same reason mesh facts do: a node
    /// never attests itself, so every correct node has to learn them from the
    /// observers. A quorum agreeing on one claim set is what makes the platform
    /// half of eligibility deterministic. Default for a Participation
    /// observation — a vote proves nothing about hardware.
    VerifiedPlatformClaims claims;

    /// The observer's own quorum-certified height, and the finalized state it
    /// held there. Height is monotonic and certified by a quorum, so an
    /// observer cannot wind it forward alone.
    Height height{};
    Digest state_reference{};

    NodeId observer{};
    crypto::Ed25519Signature signature{};
};

[[nodiscard]] Digest observation_signing_digest(const EligibilityObservation& observation);

/// Verifies the signature under the observer's identity key. A node identity IS
/// its Ed25519 identity public key, so there is no separate key to look up and
/// no way to sign as another observer.
[[nodiscard]] bool observation_signature_valid(const EligibilityObservation& observation);

[[nodiscard]] EligibilityObservation sign_observation(EligibilityObservation observation,
                                                       const crypto::Ed25519Keypair& identity);

[[nodiscard]] std::string_view observation_kind_name(ObservationKind kind);
[[nodiscard]] std::string_view objective_fault_name(ObjectiveFault fault);

}  // namespace nexus::security
