#pragma once

// Linux IMA measurement log — where a binary measurement stops being self-asserted.
//
// BinaryAttestationService::self_hash() reads /proc/self/exe off disk and SHA-256s
// it. That is the measured party choosing its own measurement: a modified binary
// reports whatever it likes. IMA is different — the kernel hashes each executable
// at exec() time and extends PCR 10 with the result, so the log can be replayed
// against a PCR value the guest cannot rewind or forge, and that PCR is inside a
// hardware-signed quote.
//
// The honest limit: this proves a modified binary cannot ATTEST, not that it
// cannot RUN. "Cannot run" needs dm-verity, and on an Azure CVM that has to ride
// the boot PCRs too, because the SNP launch MEASUREMENT does not cover the guest.

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::security {

/// One line of /sys/kernel/security/ima/ascii_runtime_measurements.
struct ImaEntry {
    uint32_t             pcr{10};
    std::vector<uint8_t> template_hash;   ///< what PCR 10 was extended with
    std::string          template_name;   ///< "ima-ng", "ima-sig", "ima", ...
    std::string          file_hash_algo;  ///< "sha256", "sha1", ... ("" for the "ima" template)
    std::string          file_hash_hex;
    std::string          path;
};

struct ImaLog {
    std::vector<ImaEntry> entries;
    /// Digest width seen in the log: 20 for SHA-1 template hashes, 32 for SHA-256.
    [[nodiscard]] std::size_t template_hash_size() const;
};

/// Parse the ASCII log. Returns nullopt only if the text is not an IMA log at all;
/// an empty log (no lines) parses to an empty entry list.
[[nodiscard]] std::optional<ImaLog> parse_ima_ascii(std::string_view text);

/// Replay the log into a PCR: start at zero, extend with each entry's template
/// hash in order. `bank_hash_alg` is a TPM algorithm id (see TpmQuote.hpp).
[[nodiscard]] std::vector<uint8_t> replay_ima_pcr(const ImaLog& log, uint32_t pcr_index,
                                                   uint16_t bank_hash_alg);

/// The PCR bank this log can actually be replayed against.
///
/// The ASCII log exposes exactly one template digest per entry, the one computed
/// with `ima_template_hash_algo` (default SHA-1). Since Linux ~4.20 the kernel
/// computes a SEPARATE template digest per PCR bank, so a SHA-1 log does not
/// replay into the SHA-256 bank at all — measured on the live box: the SHA-1 bank
/// matched exactly, the SHA-256 bank did not, and no zero-extension rule bridges
/// them because the SHA-256 bank holds a genuinely different digest.
///
/// So the bank is chosen by the log's own width rather than fixed. Booting with
/// `ima_template_hash_algo=sha256` upgrades this to SHA-256 with no code change;
/// until then log integrity rests on SHA-1 collision resistance, which callers are
/// expected to surface rather than hide.
[[nodiscard]] uint16_t ima_replay_bank(const ImaLog& log);

/// The kernel's measurement of `path`. The LAST entry wins: a file re-measured
/// after modification appears again, and the newest line is what is running.
[[nodiscard]] std::optional<ImaEntry> ima_entry_for_path(const ImaLog& log,
                                                          std::string_view path);

/// Read /sys/kernel/security/ima/ascii_runtime_measurements. Empty when IMA is
/// not enabled, the securityfs is not mounted, or we are not on Linux.
[[nodiscard]] std::string read_ima_ascii_log();

/// Absolute path of the running executable, as IMA would have recorded it.
[[nodiscard]] std::string running_executable_path();

}  // namespace nexus::security
