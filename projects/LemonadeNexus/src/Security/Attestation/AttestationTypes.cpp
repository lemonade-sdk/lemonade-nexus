#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>

#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <string>

namespace nexus::security {

Digest challenge_digest(const AttestationChallenge& challenge) {
    CanonicalEncoder encoder(constants::kTier1AttestDomain);
    encoder.add_string("challenge");
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
    encoder.add_bytes(evidence.challenge_digest);
    encoder.add_bytes(evidence.node_id.bytes);
    encoder.add_u64(evidence.incarnation);
    encoder.add_u64(evidence.epoch);
    encoder.add_u16(evidence.security_ruleset);
    encoder.add_u16(evidence.consensus_ruleset);
    encoder.add_u16(static_cast<uint16_t>(evidence.profile_id));
    encoder.add_u16(evidence.profile_ruleset);
    encoder.add_bytes(evidence.epoch_vote_key);
    encoder.add_bytes(platform_bundle_digest(evidence.platform));
    return encoder.digest();
}

}  // namespace nexus::security
