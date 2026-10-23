#pragma once

// Files encrypted under this server's data key (DEK), design B9, B10, and the
// monthly DEK rotation of B5a. Phase 7, behind ServerConfig::storage_files_enabled.
//
// Format. A covered file is replaced in place by one encrypted object:
//
//   "LNXVAULT" (8) | format 0x01 (1) | key id (16) | nonce (24) | ciphertext+tag
//
// The cipher is the project AEAD (EncryptedBlob version 1, XChaCha20-Poly1305)
// under a file key derived from the DEK. The associated data is
// aead_aad("storage-file-at-rest", {domain, relative path, key id}), so a file
// moved to another path or domain, or a file under another DEK, does not
// decrypt. The key id is a one-way derivation of the DEK; it names the key
// without revealing it.
//
// Migration (B10), tracked in <state directory>/vault-state.json:
//
//   1. plaintext   Files are plaintext. A server that cannot unlock its DEK
//                  through t holders stays here and keeps its files.
//   2. migrating   Each file is encrypted to "<file>.vault-new" beside it, in
//                  batches. Then the vault asks the data key service for a new
//                  unlock round trip through the holders and, after it passes,
//                  decrypts every staged file with the DEK that round trip
//                  reproduced and compares it with the plaintext.
//   3. encrypted   Recorded only after step 2 passed for every file. Each
//                  plaintext is then overwritten (best effort) and replaced by
//                  its staged ciphertext.
//
// The plaintext stays authoritative until step 3 is durable, so a crash at any
// point loses nothing: the vault restarts staging, or finishes the
// replacements. After step 3 the vault never reads plaintext again (fail
// closed): a covered file without the header, under another key, or with a bad
// tag is refused, and nothing is written while the DEK is locked.
//
// Rotation (B5a): monthly on the local wall clock, or on request. The data key
// service creates and wraps a new DEK to the current S beside the old one
// (data-key.next.json) and proves through the holders that it unwraps. The
// vault re-encrypts every file to "<file>.vault-new" under the new DEK,
// verifies each, and then the data key service commits the new wrapped key.
// That commit is the switch point: before it the old files and key stand and
// an interrupted rotation is discarded and restarted; after it the staged
// files replace the old ciphertext. A reader always takes the candidate whose
// key id matches the DEK in memory, so either side of the switch reads the
// same content.
//
// Not covered (boot set, B6): the gossip identity and the storage share, both
// sealed. Rollback of a whole file to an older ciphertext under the same DEK is
// not detected.
//
// Thread safety: every public member is thread-safe. tick() and attach() run on
// the security io thread. The vault calls the DataKeySource under its own
// lock, and the source never calls back into the vault.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SecureBuffer.hpp>

#include <array>
#include <cstdint>
#include <filesystem>
#include <mutex>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::crypto { class SodiumCryptoService; }

namespace nexus::security {

/// The DEK operations the vault needs. DataKeyService implements it; tests
/// may inject a fake. io thread, except data_key() (any thread).
class DataKeySource {
public:
    virtual ~DataKeySource() = default;

    /// The DEK in guarded memory, or nullopt while locked. Thread-safe.
    [[nodiscard]] virtual std::optional<crypto::SecureBuffer> data_key() const = 0;
    /// True once an unlock round trip through the holders reproduced the DEK
    /// in memory, and no new round trip was requested since.
    [[nodiscard]] virtual bool unlock_verified() const = 0;
    /// Clears unlock_verified() and starts a new round trip through the
    /// holders.
    virtual void request_verification() = 0;

    /// Creates a replacement DEK, wraps it to the current S, stores it beside
    /// the current wrapped key, and starts a round trip that proves it
    /// unwraps. False when the DEK is locked or no verified plan exists.
    virtual bool begin_replacement() = 0;
    /// The replacement DEK, or nullopt when none is pending in this run.
    [[nodiscard]] virtual std::optional<crypto::SecureBuffer> replacement_key() const = 0;
    /// True once the replacement's round trip through the holders passed.
    [[nodiscard]] virtual bool replacement_verified() const = 0;
    /// Makes the replacement the current wrapped key (durable), then the DEK
    /// in memory. False unless replacement_verified().
    virtual bool commit_replacement() = 0;
    /// Discards the replacement and its stored wrapped key.
    virtual void abort_replacement() = 0;
};

/// One group of covered files: `directory` (relative to the data root, "/"
/// separated) and either one exact `name` or every name ending in `suffix`.
struct VaultCoverage {
    std::string domain;
    std::string directory;
    std::string name;
    std::string suffix;
};

enum class VaultMode : uint8_t { Plaintext, Migrating, Encrypted };

enum class VaultPhase : uint8_t {
    Idle,
    Staging,
    Verifying,
    Promoting,
    RotateStaging,
    RotateVerifying,
};

enum class VaultReadStatus : uint8_t {
    Ok,
    /// No file at the path.
    Missing,
    /// The files are encrypted and the DEK is not in memory. Retry after unlock.
    Locked,
    /// The file is not a valid object for this path, domain, and DEK, or it is
    /// plaintext after migration. Never retried as plaintext.
    Rejected,
};

struct VaultRead {
    VaultReadStatus status = VaultReadStatus::Missing;
    std::string bytes;
};

struct StorageVaultOptions {
    /// Files staged per tick.
    std::size_t batch = 64;
    /// Local DEK rotation interval. Per server; not a consensus rule.
    uint64_t rotation_interval_ms = 30ULL * 24 * 3600 * 1000;
};

[[nodiscard]] std::string_view vault_mode_name(VaultMode mode);
[[nodiscard]] std::string_view vault_phase_name(VaultPhase phase);

/// The suffix of a staged file.
inline constexpr std::string_view kVaultStagedSuffix = ".vault-new";

class StorageVault {
public:
    /// `data_root` is the server data directory; covered paths are relative to
    /// it. `state_directory` holds vault-state.json. Not owning: `crypto` must
    /// outlive the vault.
    StorageVault(std::filesystem::path data_root, std::filesystem::path state_directory,
                 crypto::SodiumCryptoService& crypto,
                 std::vector<VaultCoverage> coverage = default_coverage(),
                 StorageVaultOptions options = {});

    /// The mode recorded in <state_directory>/vault-state.json without a vault:
    /// nullopt when no state file exists, Encrypted when it is damaged.
    [[nodiscard]] static std::optional<VaultMode> recorded_mode(
        const std::filesystem::path& state_directory);

    /// The B9 file set this phase covers.
    [[nodiscard]] static std::vector<VaultCoverage> default_coverage();

    /// The covered files now on disk, or an empty list when the scan failed.
    /// The scan walks each coverage directory recursively and refuses to stop
    /// at an unreadable or symlinking entry: a partial list must never be
    /// reported as a complete one, so every caller treats an empty result with
    /// a file expected as "retry later", not "nothing to do".
    /// Test-only; io thread.
    [[nodiscard]] std::vector<std::string> test_enumerate_relative() const;

    /// Reads the state file and finishes interrupted replacements that need no
    /// key. A missing state file while a covered file holds the header, or a
    /// damaged state file, loads as Encrypted (fail closed). Call once before
    /// any read or write.
    void load();

    /// Not owning; `source` must outlive the vault or be detached with nullptr.
    void attach(DataKeySource* source);

    [[nodiscard]] VaultMode mode() const;
    [[nodiscard]] VaultPhase phase() const;
    /// False only when the files are encrypted and the DEK is not in memory.
    /// Services that read covered files start after this turns true.
    [[nodiscard]] bool files_ready() const;
    /// Unix ms of the last completed migration or rotation; 0 when none.
    [[nodiscard]] uint64_t last_rotation_ms() const;
    [[nodiscard]] bool rotation_requested() const;

    /// True when `path` is a covered file.
    [[nodiscard]] bool covers(const std::filesystem::path& path) const;

    [[nodiscard]] VaultRead read(const std::filesystem::path& path) const;
    /// Writes durably, mode 0600. False when the DEK is needed and locked, or
    /// the write fails; the previous content then stands.
    [[nodiscard]] bool write(const std::filesystem::path& path, std::string_view bytes);
    /// Removes the file and any staged copy. True when nothing remains.
    bool remove(const std::filesystem::path& path);

    /// Requests a DEK rotation on the next tick that can run it. Durable.
    /// False before migration completed.
    bool request_rotation();

    /// Migration and rotation work. io thread. `wall_ms` is Unix ms.
    void tick(uint64_t wall_ms);

    /// The encrypted object for `plaintext` (tests and the format contract).
    [[nodiscard]] std::optional<std::string> seal_for(const std::filesystem::path& path,
                                                      std::span<const uint8_t> dek,
                                                      std::string_view plaintext) const;

private:
    struct Covered {
        std::filesystem::path path;
        std::string relative;
        const VaultCoverage* coverage = nullptr;
    };
    using KeyId = std::array<uint8_t, 16>;

    [[nodiscard]] std::optional<Covered> classify(const std::filesystem::path& path) const;
    [[nodiscard]] std::vector<Covered> enumerate() const;
    [[nodiscard]] static std::filesystem::path staged_path(const std::filesystem::path& path);

    [[nodiscard]] KeyId key_id(std::span<const uint8_t> dek) const;
    [[nodiscard]] std::optional<std::string> seal(const Covered& file, std::span<const uint8_t> dek,
                                                  std::string_view plaintext) const;
    [[nodiscard]] std::optional<std::string> open(const Covered& file,
                                                  std::span<const uint8_t> dek,
                                                  std::string_view object) const;
    [[nodiscard]] static std::optional<KeyId> header_key_id(std::string_view object);
    [[nodiscard]] static bool has_header(std::string_view bytes);

    [[nodiscard]] VaultRead read_locked(const Covered& file) const;
    [[nodiscard]] bool write_locked(const Covered& file, std::string_view bytes);
    [[nodiscard]] bool stage_one(const Covered& file, std::span<const uint8_t> source_key,
                                 std::span<const uint8_t> target_key);
    [[nodiscard]] bool verify_scan_complete(const std::set<std::string>& original_files) const;
    [[nodiscard]] bool verify_all(std::span<const uint8_t> source_key,
                                  std::span<const uint8_t> target_key);
    void promote_all(const KeyId& target);
    void discard_staged();
    [[nodiscard]] bool save_state();

    void tick_migration(uint64_t wall_ms);
    void tick_rotation(uint64_t wall_ms);
    void start_rotation();
    void abort_rotation();
    void finish(uint64_t wall_ms);

    std::filesystem::path data_root_;
    std::filesystem::path state_path_;
    crypto::SodiumCryptoService& crypto_;
    std::vector<VaultCoverage> coverage_;
    StorageVaultOptions options_;

    mutable std::mutex mutex_;
    DataKeySource* source_ = nullptr;
    VaultMode mode_ = VaultMode::Plaintext;
    VaultPhase phase_ = VaultPhase::Idle;
    KeyId target_key_id_{};
    uint64_t last_rotation_ms_ = 0;
    bool rotation_requested_ = false;
    std::vector<Covered> pending_;
    bool pending_loaded_ = false;
    std::set<std::string> staged_originals_;
    mutable bool last_scan_ok_ = true;
};

}  // namespace nexus::security
