#pragma once

// Startup platform self-verification.
//
// Detection used to mean "does a device node exist", which proves nothing: a file
// in /dev is not evidence, and on the platform we actually run (an Azure SNP CVM
// behind a paravisor) the SEV device node does not exist at all. This replaces it
// with a dry run — produce real evidence, then verify it through exactly the path a
// remote peer would use. If that round trip does not close, we are Tier 2.

#include <LemonadeNexus/Security/HclReport.hpp>
#include <LemonadeNexus/Security/SnpVerify.hpp>
#include <LemonadeNexus/Security/TpmQuote.hpp>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace nexus::security {

enum class EvidenceProfile {
    None,
    SnpVtpm,    // Azure-style paravisor CVM: report via vTPM NV, AK bound in REPORT_DATA
    SnpDirect,  // bare metal / direct-launch guest: /dev/sev-guest ioctl
};

[[nodiscard]] std::string_view evidence_profile_name(EvidenceProfile p);

/// Guest-kernel self-reports. Corroboration for a human reading logs — never an
/// input to a trust decision, because a guest can lie about every one of them.
struct PlatformDiagnostics {
    bool tpm_device_present{false};
    bool sev_guest_device_present{false};
    bool ima_measurements_present{false};
};

struct PlatformProbeResult {
    bool            tier1_capable{false};
    EvidenceProfile profile{EvidenceProfile::None};
    std::string     failure;      // why we are not Tier-1 capable
    PlatformDiagnostics diagnostics;

    /// True when this host produced a FRESH quote under the AMD-vouched key and
    /// self-verified it. False means we only checked a blob — which is all an
    /// offline `--verify-platform <file>` can do, and is never Tier-1 capable.
    bool quote_verified{false};
    /// True when the IMA log replayed to the quoted PCR 10 and named our binary.
    bool binary_measured{false};
    /// The IMA log could only be replayed in the SHA-1 bank. See EvidenceVerdict.
    bool ima_sha1_bank{false};
    /// Encoded size of the evidence bundle. It grows with the IMA log, and a
    /// gossip datagram cannot carry an unbounded one — this is the number an
    /// operator watches.
    std::size_t evidence_bytes{0};

    // Populated on success — these are what an operator pins at enrollment.
    std::string measurement_hex;   // SNP launch measurement
    std::string ak_pub_b64;        // platform binding key (DER SPKI, base64)
    std::string binary_sha256;     // IMA-measured hash of the running binary
    std::string chip_id_hex;
    std::string tcb;
    std::string policy_summary;
};

struct PlatformProbeConfig {
    std::filesystem::path cache_dir;             // where a fetched VCEK is cached
    std::string           product{"Milan"};      // AMD silicon generation
    SnpPolicyRequirements policy;
    bool                  allow_network{true};   // may we reach AMD KDS for a VCEK
    /// Raw Ed25519 identity to bind the self-test quote to. Empty is fine — the
    /// probe still proves the platform can produce a fresh, AMD-anchored quote;
    /// the identity binding is what every live challenge exercises.
    std::vector<uint8_t>  identity_pubkey;
    /// Require the IMA log to replay to the quoted PCR 10 and name our binary.
    /// This is the "secure binary" half; a host without IMA is not Tier-1 capable.
    bool                  require_ima{true};
    /// Read the HCL blob from a file instead of the vTPM. For offline verification
    /// of a blob captured elsewhere; never a way to bypass a check.
    std::filesystem::path hcl_blob_override;
};

/// Run the full chain. Safe to call on any platform: on a host with no evidence
/// source it returns tier1_capable = false with a reason, and never throws.
[[nodiscard]] PlatformProbeResult probe_platform(const PlatformProbeConfig& cfg);

/// Multi-line human-readable form — what --verify-platform prints and what the
/// server logs at startup.
[[nodiscard]] std::string format_probe_report(const PlatformProbeResult& r);

// ---------------------------------------------------------------------------
// Platform I/O, shared with the evidence backends
// ---------------------------------------------------------------------------

/// Read the paravisor's attestation blob out of vTPM NV. Unauthenticated by
/// design on Azure — anything in the guest that can open the TPM can read it,
/// which is exactly why the blob alone proves nothing. Empty off-platform.
[[nodiscard]] std::vector<uint8_t> read_hcl_nv_blob();

/// The VCEK for this chip and TCB, from the cache or AMD KDS. Not trusted on
/// arrival: the verifier independently requires the chain root to be the
/// compiled-in ARK, so a spoofed KDS buys nothing.
[[nodiscard]] std::vector<uint8_t> fetch_vcek(const std::filesystem::path& cache_dir,
                                               const SnpReport& report,
                                               const std::string& product, bool allow_network);

/// ASK + ARK, from the cache or AMD KDS. Same caveat as above.
[[nodiscard]] std::string fetch_amd_chain(const std::filesystem::path& cache_dir,
                                           const std::string& product, bool allow_network);

}  // namespace nexus::security
