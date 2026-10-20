#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>

#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <string>

#include <sodium.h>

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
    encoder.add_u64(epoch.underlying());
    encoder.add_bytes(node.bytes);
    encoder.add_u64(incarnation.underlying());
    return encoder.digest();
}

Digest final_readiness_attestation_context(const NetworkId& network_id, EpochId next_epoch,
                                           const Digest& plan_digest, uint32_t attempt,
                                           const Digest& selected_set_digest, const NodeId& node,
                                           IncarnationId incarnation) {
    CanonicalEncoder encoder(kAttestationContextDomain);
    encoder.add_u16(static_cast<uint16_t>(AttestationPurpose::FinalEpochReadiness));
    encoder.add_bytes(network_id);
    encoder.add_u64(next_epoch.underlying());
    encoder.add_bytes(plan_digest);
    encoder.add_u32(attempt);
    encoder.add_bytes(selected_set_digest);
    encoder.add_bytes(node.bytes);
    encoder.add_u64(incarnation.underlying());
    return encoder.digest();
}

Digest challenge_digest(const AttestationChallenge& challenge) {
    CanonicalEncoder encoder(constants::kTier1AttestDomain);
    encoder.add_string("challenge");
    encoder.add_bytes(challenge.network_id);
    encoder.add_bytes(challenge.nonce);
    encoder.add_bytes(challenge.node_id.bytes);
    encoder.add_bytes(challenge.node_key);
    encoder.add_u64(challenge.incarnation.underlying());
    encoder.add_u64(challenge.epoch.underlying());
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
    encoder.add_u16(static_cast<uint16_t>(challenge.ima_mode));
    encoder.add_bytes(challenge.ima_checkpoint_digest);
    encoder.add_u64(challenge.ima_prior_event_count);
    encoder.add_bytes(challenge.ima_prior_pcr10);
    encoder.add_u64(challenge.ima_checkpoint_paths.size());
    for (const auto& path : challenge.ima_checkpoint_paths) {
        encoder.add_string(path.path);
        encoder.add_string(path.sha256);
    }
    return encoder.digest();
}

namespace {

// The platform bundle is hashed as its canonical wire form, so the signature
// covers the exact bytes a verifier receives — not a second encoding of them.
Digest platform_bundle_digest(const PlatformEvidence& platform) {
    const std::string encoded = encode_platform_evidence(platform);
    CanonicalEncoder encoder(constants::kTier1AttestDomain);
    encoder.add_string("platform-bundle:v1");
    encoder.add_u16(static_cast<uint16_t>(platform_evidence_type(platform)));
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
    encoder.add_u64(evidence.incarnation.underlying());
    encoder.add_u64(evidence.epoch.underlying());
    encoder.add_u16(evidence.security_ruleset);
    encoder.add_u16(evidence.consensus_ruleset);
    encoder.add_u16(static_cast<uint16_t>(evidence.profile_id));
    encoder.add_u16(evidence.profile_ruleset);
    encoder.add_u16(static_cast<uint16_t>(evidence.purpose));
    encoder.add_bytes(evidence.context_digest);
    encoder.add_u16(static_cast<uint16_t>(evidence.ima_mode));
    encoder.add_u64(evidence.ima_bytes);
    encoder.add_bytes(evidence.ima_digest);
    encoder.add_bytes(evidence.epoch_vote_key);
    encoder.add_bytes(platform_bundle_digest(evidence.platform));
    return encoder.digest();
}

Digest platform_evidence_digest(const PlatformEvidence& platform) {
    return platform_bundle_digest(platform);
}

Digest raw_ima_digest(std::span<const uint8_t> bytes) {
    Digest digest{};
    crypto_hash_sha256(digest.data(), bytes.data(), bytes.size());
    return digest;
}

Digest evidence_transfer_id(const AttestationEvidenceStart& start) {
    CanonicalEncoder encoder("LEMONADE-NEXUS-ATTESTATION-TRANSFER-V1");
    encoder.add_bytes(start.challenge_digest);
    encoder.add_bytes(start.evidence.node_id.bytes);
    encoder.add_u64(start.evidence.incarnation.underlying());
    encoder.add_u16(static_cast<uint16_t>(start.evidence.profile_id));
    encoder.add_u16(start.evidence.profile_ruleset);
    encoder.add_u16(static_cast<uint16_t>(start.mode));
    encoder.add_u64(start.total_transfer_bytes);
    encoder.add_u64(start.ima_bytes);
    encoder.add_u32(start.total_chunks);
    encoder.add_bytes(start.ima_digest);
    encoder.add_bytes(start.platform_digest);
    return encoder.digest();
}

}  // namespace nexus::security
