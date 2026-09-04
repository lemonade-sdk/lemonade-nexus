#include <LemonadeNexusAttestd/AttestdGate.hpp>

#include <LemonadeNexus/Security/Attestation/AttestationProfileId.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <algorithm>

namespace nexus::attestd {

namespace constants = nexus::security::constants;

std::string_view refusal_name(Refusal r) {
    switch (r) {
        case Refusal::None:                   return "none";
        case Refusal::MalformedRequest:       return "malformed_request";
        case Refusal::ProfileNotSupported:    return "profile_not_supported";
        case Refusal::ProfileRulesetMismatch: return "profile_ruleset_mismatch";
        case Refusal::RulesetMismatch:        return "ruleset_mismatch";
        case Refusal::NetworkUnbound:         return "network_unbound";
        case Refusal::NodeUnbound:            return "node_unbound";
        case Refusal::ContextUnbound:         return "context_unbound";
        case Refusal::PlatformUnavailable:    return "platform_unavailable";
        case Refusal::EvidenceUnavailable:    return "evidence_unavailable";
        case Refusal::EvidenceOversized:      return "evidence_oversized";
    }
    return "unknown";
}

std::string_view refusal_reason(Refusal r) {
    switch (r) {
        case Refusal::None:
            return "answered";
        case Refusal::MalformedRequest:
            return "the request is not a well-formed attestation challenge";
        case Refusal::ProfileNotSupported:
            return "this daemon produces snp-vtpm evidence only";
        case Refusal::ProfileRulesetMismatch:
            return "the challenge names a profile ruleset this binary does not implement";
        case Refusal::RulesetMismatch:
            return "the challenge names a security or consensus ruleset this binary does not "
                   "implement";
        case Refusal::NetworkUnbound:
            return "the challenge binds no network";
        case Refusal::NodeUnbound:
            return "the challenge binds no node identity";
        case Refusal::ContextUnbound:
            return "a final-readiness challenge must bind a context";
        case Refusal::PlatformUnavailable:
            return "this build or host has no snp-vtpm prover";
        case Refusal::EvidenceUnavailable:
            return "the platform produced no evidence";
        case Refusal::EvidenceOversized:
            return "the produced evidence exceeds what one local operation may stream";
    }
    return "unknown";
}

bool all_zero(std::span<const uint8_t> bytes) {
    return std::all_of(bytes.begin(), bytes.end(), [](uint8_t b) { return b == 0; });
}

Refusal check_challenge(const security::AttestationChallenge& challenge) {
    // Ordered cheapest and most structural first, so a garbage challenge is
    // diagnosed as garbage rather than as an identity problem.

    // One evidence format, decided by the compiled binary. A challenge naming
    // any other profile is answered with nothing, never with the wrong shape.
    if (challenge.profile_id != security::kTier1AttestationProfileId) {
        return Refusal::ProfileNotSupported;
    }
    if (challenge.profile_ruleset != security::kAttestationProfileRulesetVersion) {
        return Refusal::ProfileRulesetMismatch;
    }
    if (challenge.security_ruleset != constants::kSecurityRulesetVersion ||
        challenge.consensus_ruleset != constants::kConsensusRulesetVersion) {
        return Refusal::RulesetMismatch;
    }

    // A default-constructed challenge must not reach the TPM. Without these the
    // daemon would happily bind a quote to "network zero, identity zero", and
    // every verifier in the mesh would have to remember to reject it.
    if (all_zero(challenge.network_id)) {
        return Refusal::NetworkUnbound;
    }
    if (all_zero(challenge.node_key) || all_zero(challenge.node_id.bytes)) {
        return Refusal::NodeUnbound;
    }

    // NodeId IS the raw Ed25519 identity key (SecurityTypes.hpp), so the two
    // fields must agree. Which identity it is does not matter here: the daemon
    // holds no key, and evidence bound to a node_key the caller cannot sign for
    // is unusable rather than dangerous.
    if (challenge.node_id.bytes != challenge.node_key) {
        return Refusal::NodeUnbound;
    }

    // A final-readiness attestation whose context is empty binds no plan, no
    // attempt and no selected set — it is a replayable blank cheque.
    if (challenge.purpose == security::AttestationPurpose::FinalEpochReadiness &&
        all_zero(challenge.context_digest)) {
        return Refusal::ContextUnbound;
    }

    return Refusal::None;
}


std::array<uint8_t, security::kEvidenceBindingSize> derive_quote_binding(
    const security::AttestationChallenge& challenge, std::span<const uint8_t> binary_measurement) {
    // Exactly what produce_snp_vtpm_evidence computes internally from the nonce
    // it is handed. Restated here so the binding is assertable without a TPM.
    const security::Digest nonce = security::challenge_digest(challenge);
    return security::evidence_binding(nonce, challenge.node_key, binary_measurement);
}

}  // namespace nexus::attestd
