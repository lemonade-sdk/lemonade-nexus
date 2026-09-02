#include <LemonadeNexus/Security/Authority/MeshCredential.hpp>

#include <sodium.h>

namespace nexus::security {

Digest mesh_credential_digest(const MeshCredentialGrant& grant) {
    CanonicalEncoder encoder(kMeshCredentialDomain);
    encoder.add_bytes(grant.network_id);
    encoder.add_u64(grant.epoch);
    encoder.add_u64(grant.key_generation);
    encoder.add_u16(static_cast<uint16_t>(grant.operation));
    encoder.add_string(grant.subject_pubkey);
    encoder.add_string(grant.subject_server_id);
    encoder.add_string(grant.subject_wg_pubkey);
    encoder.add_string(grant.platform_class);
    encoder.add_string(grant.expected_measurement);
    encoder.add_string(grant.approved_binary_hash);
    encoder.add_u64(grant.issued_at);
    encoder.add_u64(grant.expires_at);
    encoder.add_bytes(grant.previous_grant_digest);
    return encoder.digest();
}

MeshCredentialFailure verify_mesh_credential(const MeshCredential& credential,
                                             const VerifiedEpochAuthority& issuing_authority,
                                             uint64_t now) {
    const MeshCredentialGrant& grant = credential.grant;
    if (grant.network_id != issuing_authority.network_id) {
        return MeshCredentialFailure::WrongNetwork;
    }
    // The caller must have supplied the authority for the grant's own epoch —
    // the one whose key signed it. A mismatch means the verifier has not
    // walked the chain to that epoch, so it cannot verify this credential yet.
    if (grant.epoch != issuing_authority.epoch) {
        return MeshCredentialFailure::EpochUnavailable;
    }
    if (grant.key_generation != grant.epoch) {
        return MeshCredentialFailure::KeyGenerationInvalid;
    }
    // The one cryptographic check: the epoch authority group key signed this
    // exact grant. A FROST group signature verifies as a standard Ed25519
    // signature, so this holds for the aggregated production signature and for
    // any single-key stand-in equally.
    const Digest digest = mesh_credential_digest(grant);
    if (crypto_sign_verify_detached(credential.authority_signature.data(), digest.data(),
                                    digest.size(),
                                    issuing_authority.group_public_key.data()) != 0) {
        return MeshCredentialFailure::SignatureInvalid;
    }
    if (now != 0 && grant.expires_at != 0 && now > grant.expires_at) {
        return MeshCredentialFailure::Expired;
    }
    return MeshCredentialFailure::None;
}

}  // namespace nexus::security
