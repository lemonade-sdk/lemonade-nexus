#pragma once

// Typed objects for the Tier 1 remote attestation protocol.
//
// These types carry evidence and results between the candidate and the
// verifiers. They prove facts; they never grant authority. The verdict feeds
// Tier1EligibilityPolicy, which decides eligibility elsewhere.
//
// Architecture reference: Security Architecture Final Draft 1.0, sections 5.5,
// 7.2, 7.3, 7.5 and 11.2.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
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
    Digest policy_digest{};
};

/// The challenge value C from architecture 5.5. The prover uses this digest as
/// the nonce input of evidence_binding(), so one TPM quote transitively binds
/// the node identity, the incarnation, the epoch and the attestation policy.
[[nodiscard]] Digest challenge_digest(const AttestationChallenge& challenge);

/// The bundle a candidate returns. It contains evidence only; it never
/// contains a trusted eligibility result.
struct AttestationEvidence {
    Digest challenge_digest{};
    NodeId node_id{};
    IncarnationId incarnation{};
    SecurityRulesetVersion security_ruleset{};
    ConsensusRulesetVersion consensus_ruleset{};
    crypto::Ed25519PublicKey epoch_vote_key{};
    SnpVtpmEvidence platform;
    crypto::Ed25519Signature identity_signature{};
};

/// Preimage of the identity signature. The chain from architecture 11.2: the
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
};

/// The bounded result of one verification. It states facts about one candidate
/// under one policy; it does not decide eligibility or selection.
struct AttestationVerdict {
    NodeId node_id{};
    EpochId epoch{};
    IncarnationId incarnation{};
    Digest policy_digest{};
    Digest evidence_digest{};
    bool passed{false};
    AttestationFailure failure{AttestationFailure::None};
};

}  // namespace nexus::security
