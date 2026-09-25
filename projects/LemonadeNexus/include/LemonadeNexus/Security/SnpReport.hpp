#pragma once

// AMD SEV-SNP ATTESTATION_REPORT parsing. Pure structure decode — no verification.
// Everything here builds on every platform: a Tier-2 or Windows node must be able to
// verify a Tier-1 peer's evidence even though it can never produce any.

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace nexus::security {

inline constexpr std::size_t kSnpReportSize = 1184;   // 0x4A0
inline constexpr std::size_t kSnpSignedLen  = 0x2A0;  // signature covers [0, 0x2A0)
inline constexpr std::size_t kSnpSigOffset  = 0x2A0;
inline constexpr std::size_t kSnpSigCompLen = 72;     // r, then s — little-endian

// Field offsets. Stable across ABI versions 2..5 (v5 observed on Azure DCasv5).
namespace snp_off {
inline constexpr std::size_t kVersion      = 0x000;
inline constexpr std::size_t kGuestSvn     = 0x004;
inline constexpr std::size_t kPolicy       = 0x008;
inline constexpr std::size_t kVmpl         = 0x030;
inline constexpr std::size_t kSigAlgo      = 0x034;
inline constexpr std::size_t kReportData   = 0x050;
inline constexpr std::size_t kMeasurement  = 0x090;
inline constexpr std::size_t kHostData     = 0x0C0;
inline constexpr std::size_t kIdKeyDigest  = 0x0E0;
inline constexpr std::size_t kReportedTcb  = 0x180;
inline constexpr std::size_t kChipId       = 0x1A0;
}  // namespace snp_off

/// TCB_VERSION — four security-patch levels, one byte each.
struct TcbVersion {
    uint8_t bootloader{};
    uint8_t tee{};
    uint8_t snp{};
    uint8_t microcode{};

    /// Every component must meet the floor; a newer bootloader cannot offset an
    /// out-of-date microcode.
    [[nodiscard]] bool at_least(const TcbVersion& floor) const {
        return bootloader >= floor.bootloader && tee >= floor.tee &&
               snp >= floor.snp && microcode >= floor.microcode;
    }
    [[nodiscard]] std::string to_string() const;
};

/// GUEST_POLICY. `debug` is the field that decides whether "pause the VM and dump
/// memory" recovers anything: with DEBUG=1 the hypervisor may read guest state.
struct SnpGuestPolicy {
    uint8_t  abi_minor{};
    uint8_t  abi_major{};
    bool     smt{};            // bit 16
    bool     migrate_ma{};     // bit 18 — a migration agent may move the guest out
    bool     debug{};          // bit 19
    bool     single_socket{};  // bit 20
    uint64_t raw{};
};

struct SnpReport {
    uint32_t version{};
    uint32_t guest_svn{};
    uint32_t vmpl{};            // privilege level that REQUESTED the report
    uint32_t signature_algo{};  // 1 = ECDSA P-384 with SHA-384
    SnpGuestPolicy policy{};
    TcbVersion reported_tcb{};
    std::array<uint8_t, 64> report_data{};
    std::array<uint8_t, 48> measurement{};
    std::array<uint8_t, 32> host_data{};
    std::array<uint8_t, 48> id_key_digest{};
    std::array<uint8_t, 64> chip_id{};
    std::vector<uint8_t> raw;   // all 1184 bytes — the signature is over a prefix

    [[nodiscard]] std::string measurement_hex() const;
    [[nodiscard]] std::string chip_id_hex() const;
};

[[nodiscard]] std::optional<SnpReport> parse_snp_report(std::span<const uint8_t> bytes);

/// One-line log form: version, vmpl, policy bits, TCB, measurement prefix.
[[nodiscard]] std::string snp_report_summary(const SnpReport& r);

[[nodiscard]] std::string hex_of(std::span<const uint8_t> bytes);

}  // namespace nexus::security
