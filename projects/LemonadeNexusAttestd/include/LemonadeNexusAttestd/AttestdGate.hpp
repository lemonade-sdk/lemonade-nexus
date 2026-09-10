#pragma once

// The only decision nexus-attestd makes: is this challenge answerable, and what
// exactly does the answer commit to?
//
// The daemon exists so the main Nexus server never needs TPM or IMA access. That
// separation only buys something if the daemon is NARROW: it turns one
// fully-formed AttestationChallenge into one hardware-backed AttestationEvidence
// and does nothing else. It does not decide Tier 1 eligibility, does not quote
// caller-chosen PCRs, does not sign caller-chosen bytes, and holds no mesh
// authority. A caller that owns the socket gains exactly one ability — make this
// node attest ITSELF against a challenge — which is the ability any mesh peer
// already has by issuing a challenge over the wire.
//
// Everything in this header is pure: no clock, no filesystem, no TPM. The
// refusals are therefore exercisable on a laptop, which is the whole reason the
// gate lives apart from the socket and the prover.
//
// Architecture reference: Security Architecture Final Draft 1.1, sections 9, 18,
// 25 and 31.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>
#include <LemonadeNexus/Security/EvidenceBinding.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string_view>

namespace nexus::attestd {

/// Why the daemon did not answer. One typed value per reason: "this host has no
/// TPM" and "you asked for the wrong network" are different operator problems,
/// and a caller must never have to parse log text to tell them apart.
enum class Refusal : uint16_t {
    None = 0,

    /// The request bytes are not a well-formed challenge. Covers an oversized
    /// frame, malformed JSON, a missing field, a bad width, and — deliberately —
    /// any field this daemon does not know: see decode_challenge.
    MalformedRequest,

    /// The challenge names a profile this daemon does not produce. Only
    /// AzureSnpVtpm has a prover here; anything else goes unanswered rather than
    /// being answered with the wrong evidence shape.
    ProfileNotSupported,

    /// Same profile, different rules. Old evidence cannot answer new rules, so a
    /// ruleset this binary does not implement is refused instead of guessed at.
    ProfileRulesetMismatch,

    /// The challenge names a security or consensus ruleset this binary does not
    /// implement.
    RulesetMismatch,

    /// All-zero network_id. A default-constructed challenge would otherwise get
    /// evidence bound to "network zero", which every mesh would then have to
    /// remember to reject.
    NetworkUnbound,

    /// All-zero node_key (or node_id). Evidence bound to the zero key proves
    /// nothing about any identity.
    NodeUnbound,

    /// A final-readiness challenge with no context bound. Never legitimately
    /// issued; a hostile one proves nothing (AttestationFailure::ContextUnbound).
    ContextUnbound,

    /// This build or this host has no platform prover: not Linux, no TPM FAPI,
    /// no vTPM. Reported distinctly from EvidenceUnavailable so an operator can
    /// tell "wrong binary/host" from "the TPM path failed".
    PlatformUnavailable,

    /// The platform prover ran and produced nothing. The reason is a diagnostic
    /// string, never a second typed value: the caller's action is the same.
    EvidenceUnavailable,

    /// The bundle exceeds what one local operation may stream
    /// (kMaxLocalFrameBytes x kMaxLocalChunks). A LOCAL resource bound, not the
    /// mesh's kMaxPlatformEvidenceWireBytes — see AttestdFraming.hpp.
    EvidenceOversized,
};

[[nodiscard]] std::string_view refusal_name(Refusal r);

/// Human-readable explanation. Log text and wire diagnostics only — the typed
/// value above is what controls behavior.
[[nodiscard]] std::string_view refusal_reason(Refusal r);

/// True when every byte is zero. An unbound identity or network is a
/// default-constructed struct that reached us, and it must fail closed.
[[nodiscard]] bool all_zero(std::span<const uint8_t> bytes);

/// Every refusal decidable from the challenge alone, in a fixed order, before
/// any TPM work happens.
///
/// There is deliberately no check that the challenge addresses "this" node: the
/// daemon holds no identity, and platform evidence bound to a node_key whose
/// secret the caller cannot use is harmless — the caller simply fails to produce
/// the identity signature the verifier demands. The verifier stays authoritative.
///
/// Never returns an eligibility opinion: Tier 1 is decided by
/// Tier1EligibilityPolicy on a verifier, never here.
[[nodiscard]] Refusal check_challenge(const security::AttestationChallenge& challenge);

/// What the daemon returns: the platform's own evidence, and the digest it was
/// bound to. Assembling an AttestationEvidence around this — echoing the
/// challenge fields, binding the epoch vote key, and signing with the node
/// identity — belongs to Nexus, which owns that key.
struct PlatformEvidenceBundle {
    security::Digest          challenge_digest{};
    security::SnpVtpmEvidence platform;
};

/// The value the vTPM will sign as qualifyingData, derived and never supplied.
///
/// This is the whole reason the request type is a challenge instead of a byte
/// string: the caller hands over a structured challenge, the daemon hashes it
/// with challenge_digest(), and only that digest reaches evidence_binding(). A
/// caller therefore cannot steer the quote onto bytes of its own choosing, which
/// is what "no arbitrary TPM quoting" means in practice.
///
/// `binary_measurement` is the raw IMA hash of the running binary — the prover
/// reads it from the kernel; it is never a caller input. Empty when IMA gave the
/// prover nothing, which is exactly how produce_snp_vtpm_evidence behaves.
[[nodiscard]] std::array<uint8_t, security::kEvidenceBindingSize> derive_quote_binding(
    const security::AttestationChallenge& challenge, std::span<const uint8_t> binary_measurement);

}  // namespace nexus::attestd
