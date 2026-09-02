#pragma once

// The post-Genesis server credential, authorized by finalized mesh authority.
//
// A ServerCertificate today is signed by the persistent root/Genesis private
// key — a standing human governance key. This type replaces that authority:
// a credential is a typed grant signed by the EPOCH FROST authority key, the
// same key the mesh derives fresh every epoch through consensus and DKG. It
// verifies under the group public key carried by a VerifiedEpochAuthority, so
// anyone who walked the handoff chain can verify a credential without trusting
// the root key for anything beyond the Genesis bootstrap.
//
// There is no arbitrary signing here: a grant is produced only after the
// current epoch finalizes the admission (or revocation) decision in consensus
// and authorizes one AuthorityObject signing session over the grant digest.
// Genesis keeps only its bootstrap role; it signs no server credentials.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Security/Epoch/AuthorityChain.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstdint>
#include <string>

namespace nexus::security {

/// What a credential grant does. The set is protocol-controlled: a new kind is
/// a deterministic security-rule change and needs a new security ruleset.
enum class CredentialOperation : uint16_t {
    /// Admit a server: bind its identity, mesh static, and platform policy.
    Issue = 1,
    /// Revoke a previously issued credential for a subject identity.
    Revoke = 2,
};

/// One typed, mesh-authorized server credential. Every field is signed under
/// the issuing epoch's authority key; nothing here is chosen by the subject.
struct MeshCredentialGrant {
    NetworkId network_id{};
    /// The epoch whose authority key signs this grant. The verifier resolves
    /// that epoch's group key through the verified handoff chain.
    EpochId epoch{};
    KeyGeneration key_generation{};

    CredentialOperation operation{CredentialOperation::Issue};

    /// The subject server's gossip identity (base64 Ed25519), and the DNS/IPAM
    /// label it owns. For Revoke, only the identity is meaningful.
    std::string subject_pubkey;
    std::string subject_server_id;

    /// The mesh static the subject is bound to. Empty for a Tier 2 credential
    /// with no advertised static, or for Revoke.
    std::string subject_wg_pubkey;

    /// Platform policy the subject must satisfy for Tier 1. Empty class = a
    /// plain Tier 2 credential, which claims no platform facts (the mesh does
    /// not require confidential computing to enroll).
    std::string platform_class;
    std::string expected_measurement;
    std::string approved_binary_hash;

    uint64_t issued_at{0};
    uint64_t expires_at{0};  // 0 = no expiry

    /// The prior grant this one supersedes, or zero. Chains a subject's
    /// credential history so a rebind is ordered, not last-writer-wins.
    Digest previous_grant_digest{};
};

inline constexpr std::string_view kMeshCredentialDomain =
    "lemonade-nexus/mesh-credential:v1";

/// Every field, in declaration order. This is what the epoch authority signs.
[[nodiscard]] Digest mesh_credential_digest(const MeshCredentialGrant& grant);

/// The signed credential as it travels and is stored: the grant plus the epoch
/// authority's signature over its digest. In production the signature is the
/// aggregated FROST AuthoritySignature (Ed25519-verifiable under the group
/// key); the type is signature-scheme agnostic here.
struct MeshCredential {
    MeshCredentialGrant grant;
    crypto::Ed25519Signature authority_signature{};
};

enum class MeshCredentialFailure : uint16_t {
    None,
    /// The grant names another network than the verifier's.
    WrongNetwork,
    /// The verifier does not hold the issuing epoch's authority — it must walk
    /// the chain to that epoch before it can verify a credential from it.
    EpochUnavailable,
    /// key_generation must equal the issuing epoch (the main authority key).
    KeyGenerationInvalid,
    /// The signature does not verify under the epoch authority group key.
    SignatureInvalid,
    /// The credential is past its expiry against the supplied clock.
    Expired,
};

/// Verifies a credential under a locally verified epoch authority. The caller
/// supplies the VerifiedEpochAuthority for the grant's epoch — obtained by
/// walking the handoff chain — so trust flows Genesis -> chain -> credential,
/// never through the root key. `now` is the verifier's clock for expiry; pass
/// zero to skip the expiry check (e.g. verifying a historical grant).
[[nodiscard]] MeshCredentialFailure verify_mesh_credential(
    const MeshCredential& credential, const VerifiedEpochAuthority& issuing_authority,
    uint64_t now);

}  // namespace nexus::security
