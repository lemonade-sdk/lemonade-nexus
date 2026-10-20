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
//
// The kernel sources of truth for the ABI parsed here:
//   * IMA ABI reference (ascii_runtime_measurements line format, template names,
//     template digests): https://docs.kernel.org/security/IMA-ABI.html
//     (source: Documentation/security/IMA-ABI.rst)
//   * the securityfs ascii_runtime_measurements interface specifically:
//     https://docs.kernel.org/security/IMA-ABI.html#ascii-runtime-measurements
//   * the template definitions ("ima", "ima-ng", "ima-sig", ...) and the
//     per-bank template digest widths (20 = SHA-1, 32 = SHA-256, ...):
//     https://docs.kernel.org/security/IMA-ABI.html#template-digest-format

#include <array>
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
    /// Widths follow the kernel's template digest format:
    /// https://docs.kernel.org/security/IMA-ABI.html#template-digest-format
    [[nodiscard]] std::size_t template_hash_size() const;
};

/// One entry from binary_runtime_measurements.  template_data is retained so
/// the SHA-256 bank digest can be recomputed exactly rather than trusting the
/// legacy SHA-1 template digest stored in the entry header.
struct ImaBinaryEntry {
    uint32_t pcr{10};
    std::array<uint8_t, 20> header_template_sha1{};
    std::string template_name;
    std::vector<uint8_t> template_data;
    std::string file_hash_algo;
    std::string file_hash_hex;
    std::string path;
    bool violation{false};
    /// Byte offset immediately after this entry in the exact source stream.
    /// Used only to cut a suffix after a verifier checkpoint; it is never a
    /// trusted input and is produced by the strict parser itself.
    std::size_t wire_end{};
};

struct ImaBinaryLog {
    std::vector<ImaBinaryEntry> entries;
};

struct ImaBinaryPathState {
    std::string path;
    std::string sha256;

    auto operator<=>(const ImaBinaryPathState&) const = default;
};

struct ImaBinaryReplayState {
    uint64_t event_count{};
    std::vector<uint8_t> pcr10;
    std::vector<ImaBinaryPathState> paths;
};

/// Strict native-little-endian Linux IMA binary ABI parser.  Tier 1 accepts
/// only ima-ng and ima-sig.  Every length is bounded by the supplied byte span,
/// every NUL terminator is checked, the legacy header SHA-1 is recomputed, and
/// trailing/truncated data is rejected.
[[nodiscard]] std::optional<ImaBinaryLog> parse_ima_binary(
    std::span<const uint8_t> bytes);

/// Replay SHA-256 PCR `pcr_index` by hashing each entry's exact template_data
/// with SHA-256 and extending SHA256(old || event_digest).  An IMA violation
/// marker or unsupported bank returns an empty vector.
[[nodiscard]] std::vector<uint8_t> replay_ima_binary_pcr(
    const ImaBinaryLog& log, uint32_t pcr_index, uint16_t bank_hash_alg);

/// Replay a parsed suffix from a verifier-owned state.  `event_count` counts
/// every binary-log record (not only PCR10 records), preserving the exact
/// sequence position.  Last-path state begins with `prior_paths` and is
/// updated by the suffix.  Any violation or malformed initial PCR fails.
[[nodiscard]] std::optional<ImaBinaryReplayState> replay_ima_binary_from(
    const ImaBinaryLog& suffix, uint64_t prior_event_count,
    std::span<const uint8_t> prior_pcr10,
    std::span<const ImaBinaryPathState> prior_paths = {});

/// One replay, both uses: the state after a log prefix plus the wire cut point,
/// so a caller derives the suffix and the next checkpoint without a second pass.
struct ImaBinaryPrefixReplay {
    ImaBinaryReplayState state;
    /// Source-stream byte offset immediately after the replayed entries.
    std::size_t wire_end{};
};

/// Replay the first `entry_count` entries from a prior state, with
/// replay_ima_binary_from semantics (any violation fails).  `entry_count`
/// beyond the log fails; entries after the prefix are not examined.
[[nodiscard]] std::optional<ImaBinaryPrefixReplay> replay_ima_binary_prefix(
    const ImaBinaryLog& log, uint64_t entry_count, uint64_t prior_event_count,
    std::span<const uint8_t> prior_pcr10,
    std::span<const ImaBinaryPathState> prior_paths = {});

/// Locate exactly `prior_event_count` entries in a current strict binary log,
/// replay that prefix from zero, require `prior_pcr10`, and return only the raw
/// bytes after it.  This is the producer-side stale-checkpoint/reboot gate.
[[nodiscard]] std::optional<std::vector<uint8_t>> ima_binary_suffix_after_checkpoint(
    std::span<const uint8_t> bytes, uint64_t prior_event_count,
    std::span<const uint8_t> prior_pcr10);

/// Cut the binary log at the unique entry whose replay reaches `target`.
/// None or more than one matching prefix fails closed.
[[nodiscard]] std::optional<std::vector<uint8_t>> ima_binary_truncate_to_pcr(
    std::span<const uint8_t> bytes, uint32_t pcr_index, uint16_t bank_hash_alg,
    std::span<const uint8_t> target);

[[nodiscard]] std::optional<ImaBinaryEntry> ima_binary_entry_for_path(
    const ImaBinaryLog& log, std::string_view path);

/// Read binary_runtime_measurements to EOF. Empty means unavailable.
[[nodiscard]] std::vector<uint8_t> read_ima_binary_log();

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
/// Kernel reference for the per-bank template digests, the
/// ascii_runtime_measurements line format, and the width-to-bank mapping:
/// https://docs.kernel.org/security/IMA-ABI.html#ascii-runtime-measurements and
/// https://docs.kernel.org/security/IMA-ABI.html#template-digest-format
///
/// So the bank is chosen by the log's own width rather than fixed — mapping the
/// width (20/32/48/64) to the PCR bank hash algorithm — and with an ASCII log
/// that width is always SHA-1. No boot parameter changes this: the
/// SHA-256 template digests are not in the ASCII format at all. Measured on the
/// live Azure box, the kernel's SHA-256 bank replays correctly from
/// binary_runtime_measurements — so reaching it is a format change here, not a
/// host configuration change. Until then log integrity rests on SHA-1 collision
/// resistance, which callers are expected to surface rather than hide.
[[nodiscard]] uint16_t ima_replay_bank(const ImaLog& log);

/// The kernel's measurement of `path`. The LAST entry wins: a file re-measured
/// after modification appears again, and the newest line is what is running.
[[nodiscard]] std::optional<ImaEntry> ima_entry_for_path(const ImaLog& log,
                                                          std::string_view path);

/// Cut `text` at the entry where its replay into `pcr_index` reaches `target`.
///
/// A quote and a log read are two operations, so on a busy host the log grows
/// between them and replays PAST the quoted PCR. The quoted value names its own
/// endpoint: fold entries one at a time and stop when the running value equals
/// it. Extension chains each value into the next, so that position is unique
/// under collision resistance and everything after it is the next attestation's.
///
/// Returns the prefix including the matching line's newline. nullopt when no
/// prefix reaches `target` — the log did not produce this quote. An all-zero
/// `target` yields an empty string. One pass, no retry, no quiet host needed.
[[nodiscard]] std::optional<std::string> ima_truncate_to_pcr(std::string_view text,
                                                              uint32_t pcr_index,
                                                              uint16_t bank_hash_alg,
                                                              std::span<const uint8_t> target);

/// Read /sys/kernel/security/ima/ascii_runtime_measurements. Empty when IMA is
/// not enabled, the securityfs is not mounted, or we are not on Linux.
[[nodiscard]] std::string read_ima_ascii_log();

/// Absolute path of the running executable, as IMA would have recorded it.
[[nodiscard]] std::string running_executable_path();

}  // namespace nexus::security
