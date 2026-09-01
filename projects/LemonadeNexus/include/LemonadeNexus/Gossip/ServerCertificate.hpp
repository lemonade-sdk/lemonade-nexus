#pragma once

#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>

namespace nexus::gossip {

/// Signed certificate proving a server is authorized to participate in gossip.
/// Issued by the root management key holder (admin).
struct ServerCertificate {
    /// The Nexus network this certificate belongs to, as the hex of the derived
    /// 32-byte network id. Root-signed with everything else: a certificate from
    /// another network fails validation even under the same root key, and there
    /// is no acceptance path for a certificate without one.
    std::string network_id;
    std::string server_pubkey;   // base64 Ed25519 public key of the server
    std::string wg_pubkey;       // base64 X25519 mesh public key (derived from Ed25519)
    std::string server_id;       // human-readable identifier (e.g. "us-east-1")
    std::string endpoint_hint;   // initial "host:port" (may change)
    uint64_t    issued_at{0};    // Unix timestamp
    uint64_t    expires_at{0};   // Unix timestamp (0 = no expiry)
    std::string issuer_pubkey;   // base64 Ed25519 public key of signer (root key)
    // The platform binding key validated at enrollment: a TPM AK under "tpm2", or
    // the AMD-vouched HCLAkPub under "snp-vtpm". Runtime quote verification checks
    // the hardware signature against THIS key — making identity ↔ key ↔ cert one
    // signed unit. The field name is historical; under snp-vtpm there is no TPM the
    // operator owns.
    std::string tpm_ak_pubkey;   // base64 DER SubjectPublicKeyInfo of the pinned key ("" = none)
    std::string tpm_ek_cert;     // optional PEM EK certificate (audit / future model-B re-validation)

    // What kind of evidence this server must present, and what it must say. Root
    // signed, so it is policy the server cannot choose for itself.
    std::string platform_class;       // "" (Tier 2), "tpm2", or "snp-vtpm"
    std::string expected_measurement; // hex SHA-384 SNP launch measurement (snp-vtpm)
    std::string approved_binary_hash; // hex SHA-256 of the binary approved at enrollment

    std::string signature;       // base64 Ed25519 signature by issuer
};

/// Canonical JSON for signing (excludes signature field).
[[nodiscard]] std::string canonical_cert_json(const ServerCertificate& cert);

/// Server IDs become DNS labels, IPAM keys, and filenames.
[[nodiscard]] bool valid_server_id_label(const std::string& s);

struct CertIssueParams {
    std::string network_id;         // hex of the derived network id (required)
    std::string server_pubkey_b64;  // candidate gossip Ed25519 pubkey (base64)
    std::string server_id;          // unique DNS label
    std::string tpm_ak_pubkey;      // optional base64 DER SPKI (platform binding key)
    std::string tpm_ek_cert;        // optional PEM
    std::string platform_class;     // "", "tpm2", "snp-vtpm"
    std::string expected_measurement;
    std::string approved_binary_hash;
    uint64_t    expires_at{0};      // 0 = no expiry
};

/// Build and root-sign a ServerCertificate. The issuer must be the mesh root
/// keypair — peers verify issuer_pubkey against their configured --root-pubkey.
[[nodiscard]] ServerCertificate issue_server_certificate(
    const CertIssueParams& params,
    crypto::SodiumCryptoService& crypto,
    const crypto::Ed25519PrivateKey& root_privkey,
    const crypto::Ed25519PublicKey& root_pubkey);

void to_json(nlohmann::json& j, const ServerCertificate& c);
void from_json(const nlohmann::json& j, ServerCertificate& c);

} // namespace nexus::gossip
