#pragma once

// Verification of an AMD SEV-SNP attestation report: the AMD signature chain, then
// the guest policy. Pure OpenSSL, builds on every platform — a node that can never
// produce evidence must still be able to check a peer's.
//
// This is what separates "a blob that claims to be from AMD" from proof.

#include <LemonadeNexus/Security/SnpReport.hpp>

#include <span>
#include <string>
#include <vector>

namespace nexus::security {

/// Policy a verifier demands of the attesting platform. The defaults are the
/// Tier-1 bar: memory encryption that actually survives a hypervisor with a
/// debugger, and a report the guest could not have requested for itself.
struct SnpPolicyRequirements {
    /// DEBUG=1 lets the hypervisor read guest state — it defeats the entire
    /// "pause the VM and dump memory" property. Never optional.
    bool require_debug_disabled{true};

    /// A migration agent can move the guest out of its encryption boundary.
    bool require_no_migration_agent{true};

    /// Under a paravisor the report is requested at VMPL0 by the paravisor itself;
    /// a guest that could request its own would be at VMPL0 too. Either way the
    /// recorded level must be 0.
    bool require_vmpl0{true};

    /// Minimum security-patch levels. A report below the floor means the platform
    /// is running firmware with known issues.
    TcbVersion min_tcb{};

    /// Hex SHA-384 launch measurement to pin. Empty = accept any (used by the
    /// startup probe, which reports the value so it can be pinned at enrollment).
    std::string expected_measurement_hex;
};

struct SnpVerifyResult {
    bool        ok{false};
    std::string failure;   // human-readable, safe to log

    explicit operator bool() const { return ok; }
};

/// Verify the AMD signature chain over `report`:
///   1. ECDSA P-384 / SHA-384 over the report's first 0x2A0 bytes, under the VCEK.
///   2. VCEK -> ASK -> ARK, with the ARK checked against the compiled-in AMD root.
/// `vcek_der` is the leaf from AMD KDS (per chip and TCB, so it cannot be pinned).
/// `chain_pem` carries ASK and ARK; leave it EMPTY to use the compiled-in pair,
/// which is the normal case — both are fixed per product.
[[nodiscard]] SnpVerifyResult verify_snp_signature(const SnpReport& report,
                                                    std::span<const uint8_t> vcek_der,
                                                    std::string_view chain_pem);

/// AMD revocation state, as cached from the KDS CRL endpoint for one product.
///
/// The verifier does no network I/O: the caller supplies what it fetched, and
/// the validity window inside the CRL decides whether it may still be used.
struct AmdRevocationState {
    /// The KDS CRL, PEM or DER. Empty means nothing is cached.
    std::string crl;
    /// Wall-clock seconds since the epoch. Zero means the caller has no trusted
    /// clock, which fails closed: a CRL cannot be checked for expiry without
    /// one, and an expired CRL is what an attacker would want replayed.
    int64_t now_unix{0};
};

/// Check the VCEK and the ASK that issued it against AMD's CRL.
///
/// Fails closed on absent, unparsable, wrongly signed or expired revocation
/// data. That gates NEW attestation only: an epoch's membership is frozen once
/// selected, so a KDS outage cannot shrink a live quorum (architecture 1.1
/// section 11).
///
/// `chain_pem` follows verify_snp_signature: empty uses the compiled-in pair
/// whose ASK issued this VCEK.
[[nodiscard]] SnpVerifyResult verify_snp_revocation(std::span<const uint8_t> vcek_der,
                                                     std::string_view chain_pem,
                                                     const AmdRevocationState& state);

/// The CRL for one product. Fetched and cached by the operator's tooling; the
/// verifier never reaches the network itself.
[[nodiscard]] std::string amd_crl_kds_url(std::string_view product);

/// Check guest policy, VMPL, TCB floor and measurement. Independent of the
/// signature check so failures are separable in logs.
[[nodiscard]] SnpVerifyResult verify_snp_policy(const SnpReport& report,
                                                 const SnpPolicyRequirements& req);

/// The VCEK is per-chip and per-TCB, so its KDS URL is derived from the report.
/// `product` is the silicon generation ("Milan", "Genoa", ...).
[[nodiscard]] std::string vcek_kds_url(const SnpReport& report, std::string_view product);

/// Every silicon generation this binary carries root material for.
[[nodiscard]] std::span<const std::string_view> pinned_amd_products();

/// Compiled-in AMD root keys, by product. Never fetched at runtime.
[[nodiscard]] std::string_view pinned_amd_root(std::string_view product);

/// Compiled-in ASK + ARK for a product, in the order verify_snp_signature wants.
/// Empty for a product we have no pinned material for.
[[nodiscard]] std::string pinned_amd_chain(std::string_view product);

}  // namespace nexus::security
