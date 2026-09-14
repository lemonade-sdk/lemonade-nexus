#pragma once

// What a piece of attestation evidence is bound to, and how.
//
// Every evidence backend has some fixed-size field the hardware signs over and
// the verifier gets to choose the contents of: a TPM quote's extraData, SNP's
// REPORT_DATA. That field is the only thing standing between "this platform is
// genuine" and "this platform is genuine AND is answering MY challenge RIGHT NOW
// as THIS identity running THIS build".
//
// The two fields are different widths, so a padding rule is unavoidable. It lives
// here and nowhere else — two implementations of "pad the hash" is exactly how you
// ship a system where prover and verifier disagree by 32 zero bytes and everything
// silently rejects.
//
// Measured on the live Azure vTPM: TPM2_Quote accepts a 32-byte qualifyingData and
// rejects a 64-byte one with TPM2_RC_SIZE. So the binding is 32 bytes, and the
// 64-byte REPORT_DATA form is that value zero-extended — the same rule the Azure
// paravisor already uses for its own runtime-data digest, whose REPORT_DATA[32:64]
// is all zeros on the real blob.

#include <array>
#include <cstdint>
#include <span>

namespace nexus::security {

/// Sized for a TPM quote's extraData, which is the tighter of the two consumers.
inline constexpr std::size_t kEvidenceBindingSize = 32;

/// SNP REPORT_DATA is 64 bytes.
inline constexpr std::size_t kEvidenceReportDataSize = 64;

/// SHA-256 over a domain-separated, length-prefixed encoding of:
///   * the verifier's nonce   — freshness (the SNP report itself is frozen at boot)
///   * our Ed25519 identity   — this evidence is about THIS node
///   * the binary measurement — and about THIS build
///
/// Length-prefixed so no two different tuples can encode to the same bytes.
[[nodiscard]] std::array<uint8_t, kEvidenceBindingSize>
evidence_binding(std::span<const uint8_t> nonce,
                 std::span<const uint8_t> identity_pubkey,
                 std::span<const uint8_t> binary_measurement);

/// The same binding in SNP REPORT_DATA form: zero-extended to 64 bytes. For a
/// direct-launch guest that requests its own report (snp-direct, not yet built);
/// under a paravisor REPORT_DATA belongs to the paravisor and freshness comes from
/// the quote instead.
[[nodiscard]] std::array<uint8_t, kEvidenceReportDataSize>
evidence_report_data(std::span<const uint8_t> nonce,
                     std::span<const uint8_t> identity_pubkey,
                     std::span<const uint8_t> binary_measurement);

}  // namespace nexus::security
