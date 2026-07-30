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

#include <filesystem>
#include <optional>
#include <string>

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

    // Populated on success — these are what an operator pins at enrollment.
    std::string measurement_hex;  // SNP launch measurement
    std::string ak_pub_b64;       // platform binding key (DER SPKI, base64)
    std::string chip_id_hex;
    std::string tcb;
    std::string policy_summary;
};

struct PlatformProbeConfig {
    std::filesystem::path cache_dir;             // where a fetched VCEK is cached
    std::string           product{"Milan"};      // AMD silicon generation
    SnpPolicyRequirements policy;
    bool                  allow_network{true};   // may we reach AMD KDS for a VCEK
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

}  // namespace nexus::security
