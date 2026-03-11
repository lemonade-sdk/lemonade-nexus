#pragma once

#include <nlohmann/json.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace nexus::core {

// ---------------------------------------------------------------------------
// Trust Tier — determines what operations a server is allowed to perform
// ---------------------------------------------------------------------------

/// Two-tier trust model:
///   Tier1 = TEE hardware-attested, full mesh participant
///   Tier2 = Certificate-only, hole punching only (no data propagation)
enum class TrustTier : uint8_t {
    Untrusted = 0,  ///< No valid certificate (rejected entirely)
    Tier2     = 1,  ///< Certificate-only: hole punch only, no data/keys/DNS
    Tier1     = 2,  ///< TEE-attested: full mesh participant
};

/// Operations that can be gated by trust tier.
enum class TrustOperation : uint8_t {
    HolePunch         = 0,  ///< UDP hole punching (Tier 2+)
    ServerDiscovery   = 1,  ///< /api/servers, relay list (Tier 2+)
    HealthCheck       = 2,  ///< /api/health (Tier 2+)
    GossipDigest      = 3,  ///< Gossip digest/delta sync (Tier 1 only)
    GossipPeerExchange = 4, ///< Gossip peer exchange (Tier 1 only)
    TreeRead          = 5,  ///< Read tree nodes (Tier 1 only)
    TreeWrite         = 6,  ///< Submit tree deltas (Tier 1 only)
    DnsResolve        = 7,  ///< DNS resolution (Tier 1 only)
    CredentialRequest = 8,  ///< Request DDNS credentials (Tier 1 only)
    KeyAccess         = 9,  ///< Read/modify keys (Tier 1 only)
    IpamAllocate      = 10, ///< IP allocation (Tier 1 only)
};

/// Check if a trust tier allows a specific operation.
[[nodiscard]] inline bool is_operation_allowed(TrustTier tier, TrustOperation op) {
    switch (op) {
        // Tier 2+ operations (basic connectivity)
        case TrustOperation::HolePunch:
        case TrustOperation::ServerDiscovery:
        case TrustOperation::HealthCheck:
            return tier >= TrustTier::Tier2;

        // Tier 1 only operations (data, keys, DNS)
        case TrustOperation::GossipDigest:
        case TrustOperation::GossipPeerExchange:
        case TrustOperation::TreeRead:
        case TrustOperation::TreeWrite:
        case TrustOperation::DnsResolve:
        case TrustOperation::CredentialRequest:
        case TrustOperation::KeyAccess:
        case TrustOperation::IpamAllocate:
            return tier >= TrustTier::Tier1;
    }
    return false;
}

// ---------------------------------------------------------------------------
// TEE Platform identification
// ---------------------------------------------------------------------------

enum class TeePlatform : uint8_t {
    None              = 0,  ///< No TEE hardware detected
    IntelSgx          = 1,  ///< Intel SGX (process-level enclave)
    IntelTdx          = 2,  ///< Intel TDX (VM-level trust domain)
    AmdSevSnp         = 3,  ///< AMD SEV-SNP (VM-level encrypted)
    AppleSecureEnclave = 4, ///< Apple Secure Enclave (macOS bare-metal)
};

[[nodiscard]] inline std::string_view tee_platform_name(TeePlatform p) {
    switch (p) {
        case TeePlatform::None:              return "none";
        case TeePlatform::IntelSgx:          return "sgx";
        case TeePlatform::IntelTdx:          return "tdx";
        case TeePlatform::AmdSevSnp:         return "sev-snp";
        case TeePlatform::AppleSecureEnclave: return "secure-enclave";
    }
    return "unknown";
}

[[nodiscard]] inline TeePlatform tee_platform_from_string(std::string_view s) {
    if (s == "sgx")             return TeePlatform::IntelSgx;
    if (s == "tdx")             return TeePlatform::IntelTdx;
    if (s == "sev-snp")         return TeePlatform::AmdSevSnp;
    if (s == "secure-enclave")  return TeePlatform::AppleSecureEnclave;
    return TeePlatform::None;
}

// ---------------------------------------------------------------------------
// TEE Attestation Report — platform-agnostic container for TEE proof
// ---------------------------------------------------------------------------

/// A TEE attestation report that can be attached to gossip messages.
/// In zero-trust mode, every sensitive gossip message includes a fresh
/// attestation token that the receiver must verify before processing.
struct TeeAttestationReport {
    TeePlatform platform{TeePlatform::None};
    std::vector<uint8_t> quote;         ///< Platform-specific attestation quote/report bytes
    std::array<uint8_t, 32> nonce{};    ///< Challenge nonce this report is bound to
    uint64_t timestamp{0};              ///< Unix timestamp of report generation
    std::string server_pubkey;          ///< base64 Ed25519 pubkey of the attesting server
    std::string binary_hash;            ///< hex SHA-256 of the running binary
    std::string signature;              ///< base64 Ed25519 signature over canonical JSON
};

/// Canonical JSON for signing (excludes signature field).
[[nodiscard]] std::string canonical_attestation_json(const TeeAttestationReport& r);

void to_json(nlohmann::json& j, const TeeAttestationReport& r);
void from_json(const nlohmann::json& j, TeeAttestationReport& r);

// ---------------------------------------------------------------------------
// Attestation Token — lightweight proof attached to each gossip message
// ---------------------------------------------------------------------------

/// A compact, signed token that proves Tier 1 status.
/// Included in every sensitive gossip message for zero-trust verification.
/// The token contains the full attestation report hash (not the full quote)
/// to keep message sizes manageable.
///
/// Zero-trust flow:
///   1. Server A sends gossip digest to Server B
///   2. Message includes AttestationToken signed by A
///   3. B verifies: token signature valid, token not expired, A has valid TEE
///   4. B only processes the message if verification passes
///   5. B's response also includes B's own AttestationToken (mutual verification)
struct AttestationToken {
    std::string server_pubkey;               ///< base64 Ed25519 pubkey
    TeePlatform platform{TeePlatform::None}; ///< what TEE platform
    std::string attestation_hash;            ///< hex SHA-256 of the full TeeAttestationReport
    std::string binary_hash;                 ///< hex SHA-256 of running binary
    uint64_t timestamp{0};                   ///< when this token was generated
    uint64_t attestation_timestamp{0};       ///< when the underlying TEE report was generated
    std::string signature;                   ///< base64 Ed25519 over canonical token JSON
};

/// Canonical JSON for signing (excludes signature field).
[[nodiscard]] std::string canonical_token_json(const AttestationToken& t);

void to_json(nlohmann::json& j, const AttestationToken& t);
void from_json(const nlohmann::json& j, AttestationToken& t);

/// Maximum age of an attestation token before it's considered stale (seconds).
/// Zero-trust: tokens are refreshed frequently.
inline constexpr uint64_t kAttestationTokenMaxAgeSec = 300;  // 5 minutes

/// Maximum age of the underlying TEE attestation report (seconds).
/// The full TEE report is expensive to generate, so it's cached longer.
inline constexpr uint64_t kTeeReportMaxAgeSec = 3600;  // 1 hour

} // namespace nexus::core
