#pragma once

// Azure paravisor ("HCL") attestation blob, published at vTPM NV index 0x01400001.
//
// Azure DCasv5/ECasv5 confidential VMs run a paravisor at VMPL0 that owns the SNP
// guest-message channel, so the guest never gets /dev/sev-guest and cannot request a
// report itself. Instead the paravisor fetches one at boot and parks it in vTPM NV.
// The blob is: a 32-byte HCL header, the AMD-signed SNP report, then a runtime-data
// region whose SHA-256 is exactly what the hardware signed into REPORT_DATA. That
// runtime region carries the paravisor vTPM's AK public key — so AMD is vouching for
// which vTPM identity belongs to this measured launch.
//
// Two consequences that shape everything downstream:
//   * The report is frozen at boot (REPORT_DATA[32:64] is zero — no room for a
//     verifier nonce), and the NV read needs no authorization. Possession of this
//     blob therefore proves NOTHING on its own. Freshness must come from a vTPM
//     quote signed by the AK bound below.
//   * The launch MEASUREMENT covers the paravisor, UEFI and vTPM firmware — NOT the
//     guest OS. Guest binary integrity has to ride the vTPM PCRs instead.

#include <LemonadeNexus/Security/SnpReport.hpp>

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace nexus::security {

inline constexpr uint32_t    kHclNvIndex    = 0x01400001;
inline constexpr std::size_t kHclHeaderSize = 32;
inline constexpr char        kHclMagic[4]   = {'H', 'C', 'L', 'A'};

/// The paravisor vTPM's attestation key, as carried in the runtime-data JWK set.
struct HclAkPub {
    std::string          kid;       // "HCLAkPub"
    std::vector<uint8_t> modulus;   // raw big-endian RSA modulus
    std::vector<uint8_t> exponent;
    [[nodiscard]] bool empty() const { return modulus.empty() || exponent.empty(); }
};

struct HclReport {
    SnpReport   snp;
    std::string runtime_json;  // the exact bytes hashed into REPORT_DATA
    HclAkPub    ak;

    /// sha256(runtime_json) == report_data[0:32]. False means the blob is internally
    /// inconsistent and the AK below is not the one AMD signed over.
    bool report_data_binds_runtime{false};
};

/// Parse and internally cross-check an HCL blob. Returns nullopt on any structural
/// failure — there is no partial success.
[[nodiscard]] std::optional<HclReport> parse_hcl_blob(std::span<const uint8_t> blob);

}  // namespace nexus::security
