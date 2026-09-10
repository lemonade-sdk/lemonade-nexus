#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>

#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <string>

namespace nexus::security {

namespace {
inline constexpr std::string_view kAttestationContextDomain =
    "lemonade-nexus/attestation-context:v1";
}

Digest eligibility_attestation_context(const NetworkId& network_id, EpochId epoch,
                                       const NodeId& node, IncarnationId incarnation) {
    CanonicalEncoder encoder(kAttestationContextDomain);
    encoder.add_u16(static_cast<uint16_t>(AttestationPurpose::Eligibility));
    encoder.add_bytes(network_id);
    encoder.add_u64(epoch);
    encoder.add_bytes(node.bytes);
    encoder.add_u64(incarnation);
    return encoder.digest();
}

Digest final_readiness_attestation_context(const NetworkId& network_id, EpochId next_epoch,
                                           const Digest& plan_digest, uint32_t attempt,
                                           const Digest& selected_set_digest, const NodeId& node,
                                           IncarnationId incarnation) {
    CanonicalEncoder encoder(kAttestationContextDomain);
    encoder.add_u16(static_cast<uint16_t>(AttestationPurpose::FinalEpochReadiness));
    encoder.add_bytes(network_id);
    encoder.add_u64(next_epoch);
    encoder.add_bytes(plan_digest);
    encoder.add_u32(attempt);
    encoder.add_bytes(selected_set_digest);
    encoder.add_bytes(node.bytes);
    encoder.add_u64(incarnation);
    return encoder.digest();
}

Digest challenge_digest(const AttestationChallenge& challenge) {
    CanonicalEncoder encoder(constants::kTier1AttestDomain);
    encoder.add_string("challenge");
    encoder.add_bytes(challenge.network_id);
    encoder.add_bytes(challenge.nonce);
    encoder.add_bytes(challenge.node_id.bytes);
    encoder.add_bytes(challenge.node_key);
    encoder.add_u64(challenge.incarnation);
    encoder.add_u64(challenge.epoch);
    encoder.add_u16(challenge.security_ruleset);
    encoder.add_u16(challenge.consensus_ruleset);
    // The profile identity is inside the challenge digest, so the TPM quote
    // that commits to that digest commits to the profile too. Evidence built
    // under a different profile cannot produce this value.
    encoder.add_u16(static_cast<uint16_t>(challenge.profile_id));
    encoder.add_u16(challenge.profile_ruleset);
    encoder.add_bytes(challenge.policy_digest);
    // The purpose and its context are inside this digest, so the TPM quote
    // that commits to it commits to what the attestation is FOR. Evidence for
    // plan A cannot produce the value plan B's challenge names.
    encoder.add_u16(static_cast<uint16_t>(challenge.purpose));
    encoder.add_bytes(challenge.context_digest);
    return encoder.digest();
}

namespace {

// The platform bundle is hashed as its canonical wire form, so the signature
// covers the exact bytes a verifier receives — not a second encoding of them.
Digest platform_bundle_digest(const SnpVtpmEvidence& platform) {
    const std::string encoded = encode_snp_vtpm_evidence(platform);
    CanonicalEncoder encoder(constants::kTier1AttestDomain);
    encoder.add_string("platform-bundle");
    encoder.add_string(encoded);
    return encoder.digest();
}

}  // namespace

Digest evidence_signing_digest(const AttestationEvidence& evidence) {
    CanonicalEncoder encoder(constants::kTier1AttestDomain);
    encoder.add_string("evidence");
    encoder.add_bytes(evidence.network_id);
    encoder.add_bytes(evidence.challenge_digest);
    encoder.add_bytes(evidence.node_id.bytes);
    encoder.add_u64(evidence.incarnation);
    encoder.add_u64(evidence.epoch);
    encoder.add_u16(evidence.security_ruleset);
    encoder.add_u16(evidence.consensus_ruleset);
    encoder.add_u16(static_cast<uint16_t>(evidence.profile_id));
    encoder.add_u16(evidence.profile_ruleset);
    encoder.add_u16(static_cast<uint16_t>(evidence.purpose));
    encoder.add_bytes(evidence.context_digest);
    encoder.add_bytes(evidence.epoch_vote_key);
    encoder.add_bytes(platform_bundle_digest(evidence.platform));
    return encoder.digest();
}

}  // namespace nexus::security
