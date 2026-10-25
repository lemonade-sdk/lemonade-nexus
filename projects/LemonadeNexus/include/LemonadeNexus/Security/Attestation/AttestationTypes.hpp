#pragma once

// Typed objects for the Tier 1 remote attestation protocol.
//
// These types carry evidence and results between the candidate and the
// verifiers. They prove facts; they never grant authority. The verdict feeds
// Tier1EligibilityPolicy, which decides eligibility elsewhere.
//
// Architecture reference: Security Architecture Final Draft 1.1, sections 5.2,
// 9, 25 and 31.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationProfileId.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationState.hpp>
#include <LemonadeNexus/Security/Attestation/VerifiedPlatformClaims.hpp>
#include <LemonadeNexus/Security/Attestation/PlatformEvidence.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstdint>
#include <span>
#include <vector>

namespace nexus::security {

/// What one attestation is FOR. The purpose and its context digest are inside
/// the challenge digest, the evidence signing digest and (transitively) the
/// TPM quote, so evidence produced for one purpose can never satisfy another.
enum class AttestationPurpose : uint16_t {
    /// Ordinary mesh eligibility: the rolling re-attestation cadence. The
    /// context binds network, epoch, node and incarnation.
    Eligibility = 1,
    /// The fresh final attestation for one finalized next-epoch plan. The
    /// context binds the plan digest, the attempt and the selected set, so a
    /// replacement attempt needs a new attestation by construction.
    FinalEpochReadiness = 2,
    /// Profile-specific platform enrollment.  It proves the SVSM service EK
    /// and proposed AK so an authorized observer can issue MakeCredential.
    /// It grants no eligibility and is never accepted as a Tier-1 verdict.
    PlatformEnrollment = 3,
    /// The attestation a storage-key holder requires before it answers one
    /// unlock request (design B7). The context binds the network, the epoch,
    /// the holder plan, and the request digest (which carries the request
    /// nonce), so the evidence answers exactly one request. A holder outside
    /// Tier 1 may challenge for this purpose only. It grants no eligibility
    /// and is never accepted as a Tier 1 verdict.
    StorageUnlock = 4,
    /// A witness's check that a server runs one release, attested and healthy,
    /// during an upgrade turn (Design-Auto-Update Phase 5). The context binds
    /// the network, the release number, the subject, and the upgrade chain
    /// head, so the evidence answers one chain position only. It grants no
    /// eligibility and is never accepted as a Tier 1 verdict.
    UpgradeHealth = 5,
};

/// The canonical context for an ordinary eligibility attestation.
[[nodiscard]] Digest eligibility_attestation_context(const NetworkId& network_id, EpochId epoch,
                                                     const NodeId& node,
                                                     IncarnationId incarnation);

/// The canonical context for one plan's final attestation. `selected_set_digest`
/// is the Tier1Set digest of the plan's selected members.
[[nodiscard]] Digest final_readiness_attestation_context(
    const NetworkId& network_id, EpochId next_epoch, const Digest& plan_digest, uint32_t attempt,
    const Digest& selected_set_digest, const NodeId& node, IncarnationId incarnation);

/// The canonical context for one storage unlock request. `request_digest` is
/// storage_unlock_request_digest() of the request, which binds the requester,
/// the ephemeral point, and the request nonce.
[[nodiscard]] Digest storage_unlock_attestation_context(const NetworkId& network_id,
                                                        EpochId epoch,
                                                        const Digest& plan_digest,
                                                        const Digest& request_digest);

/// The canonical context for one upgrade-health observation. `chain_head` is
/// the digest of the newest finalized upgrade record the witness holds.
[[nodiscard]] Digest upgrade_health_attestation_context(const NetworkId& network_id,
                                                        uint64_t release_number,
                                                        const NodeId& subject,
                                                        const Digest& chain_head);

/// The challenge the current Tier 1 set issues for one attestation attempt.
struct AttestationChallenge {
    /// Which mesh is asking. Transport authenticates the envelope, but transport
    /// authentication is not trust: without this inside the signed context, a
    /// node enrolled in one Nexus network could answer another network's
    /// challenge with the same identity and the same platform.
    NetworkId network_id{};

    Nonce nonce{};
    NodeId node_id{};
    crypto::Ed25519PublicKey node_key{};
    IncarnationId incarnation{};
    EpochId epoch{};
    SecurityRulesetVersion security_ruleset{};
    ConsensusRulesetVersion consensus_ruleset{};

    /// Which provider must answer, and under which version of its rules. The
    /// candidate cannot choose: a challenge names one profile, and evidence
    /// built for any other profile answers nothing (1.1 section 31).
    AttestationProfileId profile_id{AttestationProfileId::Unknown};
    AttestationProfileRuleset profile_ruleset{};

    Digest policy_digest{};

    /// What this attestation is for, and the exact context it answers. Both are
    /// inside challenge_digest(), so the quote commits to them.
    AttestationPurpose purpose{AttestationPurpose::Eligibility};
    Digest context_digest{};

    ImaEvidenceMode ima_mode{ImaEvidenceMode::Full};
    /// Zero for Full.  For Resume these identify the exact verifier-owned
    /// checkpoint and redundantly state its replay position.  All four fields
    /// enter challenge_digest(), and therefore the TPM quote.
    Digest ima_checkpoint_digest{};
    uint64_t ima_prior_event_count{};
    Digest ima_prior_pcr10{};
    /// Verifier-owned required-path state at the named checkpoint.  The
    /// checkpoint digest commits to it; the producer uses it only to refuse a
    /// stale/inconsistent Resume, never as an authorization input.
    std::vector<ImaCheckpointPath> ima_checkpoint_paths;
};

/// The challenge value C from architecture 9. The prover uses this digest as
/// the nonce input of evidence_binding(), so one TPM quote transitively binds
/// the node identity, the incarnation, the epoch and the attestation policy.
[[nodiscard]] Digest challenge_digest(const AttestationChallenge& challenge);

/// The bundle a candidate returns. It contains evidence only; it never
/// contains a trusted eligibility result.
struct AttestationEvidence {
    /// The network this bundle was built for. Stated rather than inferred, so a
    /// cross-network answer is diagnosed as such instead of surfacing as a
    /// digest mismatch.
    NetworkId network_id{};

    Digest challenge_digest{};
    NodeId node_id{};
    IncarnationId incarnation{};
    /// The epoch this evidence answers. Stated explicitly so a cross-epoch
    /// answer is diagnosed as such instead of surfacing as a digest mismatch.
    EpochId epoch{};
    SecurityRulesetVersion security_ruleset{};
    ConsensusRulesetVersion consensus_ruleset{};

    /// Which profile this bundle was built for. Stated by the prover and signed
    /// with the rest, so evidence encoded for provider A cannot be replayed as
    /// provider B, and a candidate cannot request a weaker profile than the one
    /// its challenge names.
    AttestationProfileId profile_id{AttestationProfileId::Unknown};
    AttestationProfileRuleset profile_ruleset{};

    /// Echoed from the challenge and signed with the rest, so a bundle built
    /// for one purpose or context cannot be relabelled as another.
    AttestationPurpose purpose{AttestationPurpose::Eligibility};
    Digest context_digest{};

    /// Explicit transfer commitment.  The identity signature covers the mode,
    /// exact raw IMA length and SHA-256 digest in addition to the canonical
    /// platform bundle.  Chunk signatures are neither needed nor accepted.
    ImaEvidenceMode ima_mode{ImaEvidenceMode::Full};
    uint64_t ima_bytes{};
    Digest ima_digest{};

    crypto::Ed25519PublicKey epoch_vote_key{};
    PlatformEvidence platform;
    crypto::Ed25519Signature identity_signature{};
};

/// Start of one bounded SVSM evidence transfer.  `evidence.platform` carries
/// all fixed platform fields with an empty ima_binary_log; its signature is the
/// candidate's signature over the COMPLETE evidence reconstructed at End.
struct AttestationEvidenceStart {
    Digest challenge_digest{};
    Digest transfer_id{};
    ImaEvidenceMode mode{ImaEvidenceMode::Full};
    uint64_t total_transfer_bytes{};
    uint64_t ima_bytes{};
    uint32_t total_chunks{};
    Digest ima_digest{};
    Digest platform_digest{};
    AttestationEvidence evidence;
};

struct AttestationEvidenceChunk {
    Digest challenge_digest{};
    Digest transfer_id{};
    uint32_t chunk_index{};
    std::vector<uint8_t> bytes;
};

struct AttestationEvidenceEnd {
    Digest challenge_digest{};
    Digest transfer_id{};
    uint64_t total_transfer_bytes{};
    uint64_t ima_bytes{};
    uint32_t total_chunks{};
    Digest ima_digest{};
    Digest platform_digest{};
};

[[nodiscard]] Digest evidence_transfer_id(const AttestationEvidenceStart& start);
[[nodiscard]] Digest platform_evidence_digest(const PlatformEvidence& platform);
[[nodiscard]] Digest raw_ima_digest(std::span<const uint8_t> bytes);

/// Preimage of the identity signature. The chain from architecture 18: the
/// quote binds the platform to the node identity, and this signature binds the
/// epoch vote key to that identity. The platform bundle enters as one digest —
/// a CanonicalEncoder digest over the tagged platform envelope.  The evidence
/// type and its exact canonical profile-specific bytes are both signed.
[[nodiscard]] Digest evidence_signing_digest(const AttestationEvidence& evidence);

/// One deterministic failure model for the whole protocol. The typed result
/// controls behavior; log text only explains it.
enum class AttestationFailure : uint16_t {
    None,
    ChallengeMismatch,
    IdentityMismatch,
    IdentitySignatureInvalid,
    RulesetMismatch,
    SnpInvalid,
    TcbTooOld,
    VtpmBindingInvalid,
    TpmQuoteInvalid,
    BootMeasurementInvalid,
    ImaMeasurementInvalid,
    BinaryMeasurementInvalid,
    RuntimeProfileInvalid,
    IncarnationStale,
    EpochMismatch,
    EvidenceOversized,
    /// The compiled profile leaves a prerequisite unpinned, so it cannot tell a
    /// good platform from a bad one. Appended last: the values above are stable.
    ProfileIncomplete,

    /// No compiled provider claims this profile ID.
    ProviderUnknown,
    /// A compiled provider claims the ID but cannot verify evidence yet, so it
    /// proves nothing rather than guessing at a format.
    ProviderUnsupported,
    /// The bundle answers with a different profile than the challenge named.
    ProfileIdMismatch,
    /// Same profile, different rules. Old evidence cannot answer new rules.
    ProfileRulesetMismatch,
    /// The hardware endorsement is revoked, or revocation data is missing or
    /// expired so the question cannot be answered. Both fail closed.
    EndorsementRevoked,
    /// The bundle answers for a different Nexus network.
    NetworkMismatch,
    /// The bundle answers for a different purpose than the challenge named.
    PurposeMismatch,
    /// Same purpose, different bound context: another plan, attempt, or
    /// selected set. Old evidence cannot answer a new context.
    ContextMismatch,
    /// A final-readiness or storage-unlock challenge with no context bound.
    /// Never issued; a hostile one proves nothing.
    ContextUnbound,
    ActivationRequired,
    CheckpointRequired,
    CheckpointInvalid,
    TransferInvalid,
};

/// The bounded result of one verification. It states facts about one candidate
/// under one policy; it does not decide eligibility or selection.
struct AttestationVerdict {
    NodeId node_id{};
    EpochId epoch{};
    IncarnationId incarnation{};
    /// The purpose and context the answered challenge bound. Consumers match
    /// these against what they expect: an eligibility verdict confers no
    /// final readiness, and the reverse.
    AttestationPurpose purpose{AttestationPurpose::Eligibility};
    Digest context_digest{};
    Digest policy_digest{};
    Digest evidence_digest{};
    /// True when no step failed. It is a summary, never an input: Tier 1 reads
    /// `claims`, so a verdict that somehow passed without proving anything
    /// still confers nothing.
    bool passed{false};
    AttestationFailure failure{AttestationFailure::None};

    /// What a provider actually proved. A step that never ran leaves its claim
    /// false, which is what makes an unproven prerequisite fail closed.
    VerifiedPlatformClaims claims;

    /// The measured hash of every approved path, from the replayed IMA log.
    /// Filled only on a passing verdict; empty otherwise. A witness reads it to
    /// tell which release the subject runs. Local only, never on the wire.
    std::vector<ImaCheckpointPath> measured_paths;
};

}  // namespace nexus::security
