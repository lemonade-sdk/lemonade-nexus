#pragma once

// Verification of an AMD SEV-SNP attestation report: the AMD signature chain, then
// the guest policy. Pure OpenSSL, builds on every platform — a node that can never
// produce evidence must still be able to check a peer's.
//
// This is what separates "a blob that claims to be from AMD" from proof.

#include <LemonadeNexus/Security/SnpReport.hpp>

#include <functional>
#include <span>
#include <string>
#include <vector>

namespace nexus::security {

/// What VMPL must have requested an SNP report.
///
/// VMPL is a privilege level, not a quality score: lower is more privileged.
/// Which level is correct depends on WHO requests the report in a given
/// platform shape, so this is a provider decision and never a global rule.
enum class VmplPolicy : uint16_t {
    /// Any level. Correct only for a startup self-probe; it proves nothing
    /// about who asked, so a Tier 1 profile must not leave it here.
    Unconstrained,

    /// The report must be recorded at VMPL0. Right when the component that
    /// requests it is the most privileged one in the guest: a paravisor that
    /// owns the boundary, or a native guest requesting its own report.
    RequireVmpl0,

    /// The report must be recorded ABOVE VMPL0, which proves something more
    /// privileged exists below the requester. This is the SVSM shape: the SVSM
    /// holds VMPL0 and Linux runs higher, so a guest-requested report recorded
    /// at VMPL0 would mean no SVSM was there.
    RequireAboveVmpl0,
};

/// Policy a verifier demands of the attesting platform. The defaults are the
/// Tier-1 bar for the properties that are the same everywhere: memory
/// encryption that survives a hypervisor with a debugger, and no migration
/// agent. VMPL is deliberately NOT among them — see VmplPolicy.
struct SnpPolicyRequirements {
    /// DEBUG=1 lets the hypervisor read guest state — it defeats the entire
    /// "pause the VM and dump memory" property. Never optional.
    bool require_debug_disabled{true};

    /// A migration agent can move the guest out of its encryption boundary.
    bool require_no_migration_agent{true};

    /// Which privilege level must have requested the report.
    ///
    /// There is no single right answer, so there is no default that is right
    /// everywhere. Under a paravisor the paravisor requests the report at VMPL0.
    /// A native guest that requests its own report is itself at VMPL0. But under
    /// an SVSM the SVSM holds VMPL0 and the Linux guest runs at a numerically
    /// HIGHER VMPL, so demanding 0 of a guest-requested report there would
    /// reject exactly the shape Tier 1 wants. The provider decides.
    VmplPolicy vmpl_policy{VmplPolicy::Unconstrained};

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
    /// Every KDS CRL this node holds, PEM or DER, one per AMD product. A mesh
    /// spans silicon generations, so the verifier is handed all of them and
    /// uses the one that verifies under the chain that issued the VCEK in
    /// hand. A list for another product cannot verify there, so offering it is
    /// not a way to widen anything. Empty means nothing is cached.
    std::vector<std::string> crls;
    /// Wall-clock seconds since the epoch. Zero means the caller has no trusted
    /// clock, which fails closed: a CRL cannot be checked for expiry without
    /// one, and an expired CRL is what an attacker would want replayed.
    int64_t now_unix{0};
};

/// Where the cached AMD CRL and the current time come from.
///
/// The verifier reaches no network and reads no clock of its own, so the same
/// evidence and the same revocation state always give the same verdict. Unset
/// means no revocation data: under a profile that requires the check, every
/// candidate whose AMD signature verifies is then refused.
using AmdRevocationSource = std::function<AmdRevocationState()>;

/// Check the VCEK and the ASK that issued it against AMD's CRL.
///
/// Fails closed when no supplied list verifies under this VCEK's chain, and
/// when the one that does is unparsable or expired. That gates NEW attestation only: an epoch's membership is frozen once
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
