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
#include <LemonadeNexus/Security/Attestation/VerifiedPlatformClaims.hpp>
#include <LemonadeNexus/Security/EvidenceSnpVtpm.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstdint>

namespace nexus::security {

/// The challenge the current Tier 1 set issues for one attestation attempt.
struct AttestationChallenge {
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
};

/// The challenge value C from architecture 9. The prover uses this digest as
/// the nonce input of evidence_binding(), so one TPM quote transitively binds
/// the node identity, the incarnation, the epoch and the attestation policy.
[[nodiscard]] Digest challenge_digest(const AttestationChallenge& challenge);

/// The bundle a candidate returns. It contains evidence only; it never
/// contains a trusted eligibility result.
struct AttestationEvidence {
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

    crypto::Ed25519PublicKey epoch_vote_key{};
    SnpVtpmEvidence platform;
    crypto::Ed25519Signature identity_signature{};
};

/// Preimage of the identity signature. The chain from architecture 18: the
/// quote binds the platform to the node identity, and this signature binds the
/// epoch vote key to that identity. The platform bundle enters as one digest —
/// a CanonicalEncoder digest over the canonical wire form from
/// encode_snp_vtpm_evidence() — so the signature covers the exact transported
/// bytes.
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
};

/// The bounded result of one verification. It states facts about one candidate
/// under one policy; it does not decide eligibility or selection.
struct AttestationVerdict {
    NodeId node_id{};
    EpochId epoch{};
    IncarnationId incarnation{};
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
};

}  // namespace nexus::security
