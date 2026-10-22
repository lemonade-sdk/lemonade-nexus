#pragma once

// Server-side store for sealed blobs. The boot set (B6) lives here: the gossip
// identity key today, the server's storage share once Phase 5 creates it.
//
// The store never sees a TPM. A SealBackend reaches nexus-attestd; production
// wires attestd_seal_backend() from LemonadeNexusAttestd/AttestdClient.hpp,
// and nothing else. Tests inject their own backend.
//
// Files, under one directory (0700), each 0600, written crash-atomically:
//
//   <name>.sealed       bound to the PCR 8/9 values of the running boot chain
//   <name>.next.sealed  bound to the PCR 8/9 values a verified release approval
//                       expects for the next boot chain (upgrade staging)
//
// Upgrade path. set_next_boot_chain() takes the expected PCRs from the
// installed, verified release approval. When they differ from the binding of
// the current blob, every successful unseal() and seal() also writes the next
// slot. After a reboot into the new chain the current blob reports
// PolicyMismatch, the next blob unseals, and the store re-seals the secret to
// the running PCRs as the new current blob, then deletes the next slot. The
// current blob is replaced only after the new one is durable, so a reboot back
// into the old chain still unseals until the promotion happens.
//
// Not thread-safe: one owner calls it during startup and from one strand later.

#include <LemonadeNexus/Crypto/SecureBuffer.hpp>
#include <LemonadeNexus/Security/Sealing/SealedBlob.hpp>

#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace nexus::security {

/// Outcome of one seal or unseal, as the server acts on it.
enum class SealStatus : uint8_t {
    Ok = 0,
    /// No blob under that name (store only; a backend never reports it).
    Missing,
    /// Sealing does not exist on this host: a build or host without a TPM, or a
    /// daemon too old to know the operation. Retrying does not help.
    Unavailable,
    /// The sealing daemon could not be reached. Retrying may help (the daemon
    /// may still be starting).
    Unreachable,
    /// PCR 8/9 differ from the values the blob is bound to.
    PolicyMismatch,
    /// The blob does not parse, does not load into this TPM, or does not
    /// authenticate.
    Corrupt,
    /// The TPM or the daemon failed in another way.
    Failed,
};

[[nodiscard]] std::string_view seal_status_name(SealStatus status);

struct SealReply {
    SealStatus  status{SealStatus::Failed};
    /// Encoded SealedBlob when status is Ok.
    std::string blob;
    /// Diagnostic only. Never contains secret material.
    std::string detail;
};

struct UnsealReply {
    SealStatus           status{SealStatus::Failed};
    /// The secret when status is Ok; empty otherwise.
    crypto::SecureBuffer plaintext;
    std::string          detail;
};

/// Seal `plaintext` for `domain`. `target` nullopt binds the running PCRs.
using SealFunction = std::function<SealReply(std::string_view domain,
                                             std::span<const uint8_t> plaintext,
                                             const std::optional<BootPcrValues>& target)>;
/// Unseal an encoded blob for `domain`.
using UnsealFunction = std::function<UnsealReply(std::string_view domain, std::string_view blob)>;

/// How the store reaches a TPM. Both functions are set, or neither: an empty
/// backend means sealing is unavailable on this build.
struct SealBackend {
    SealFunction   seal;
    UnsealFunction unseal;

    [[nodiscard]] bool available() const { return seal && unseal; }
};

class SealedBlobStore {
public:
    /// `directory` is created (0700) on first write. The store takes no lock;
    /// one process owns the directory.
    SealedBlobStore(std::filesystem::path directory, SealBackend backend);

    /// The PCR 8/9 values the next boot chain is expected to have, from a
    /// verified release approval. nullopt (pending or absent approval) stages
    /// nothing and leaves an existing next blob in place.
    void set_next_boot_chain(std::optional<BootPcrValues> values);

    [[nodiscard]] bool sealing_available() const { return backend_.available(); }

    /// Seal `plaintext` under `name` (a valid sealing domain) to the running
    /// PCRs and replace the current blob. Writes the next slot too when a
    /// different next boot chain is staged; otherwise removes a stale next
    /// blob bound to the running PCRs. Status Ok means the current blob is
    /// durable on disk.
    [[nodiscard]] SealReply seal(std::string_view name, std::span<const uint8_t> plaintext);

    /// Unseal `name`: the current blob first, then the next blob. A secret
    /// recovered from the next blob is re-sealed to the running PCRs before it
    /// is returned (promotion). Missing when neither file exists. On failure the
    /// status of the current blob is reported, and no file is changed.
    [[nodiscard]] UnsealReply unseal(std::string_view name);

    /// True when a current or next blob exists for `name`.
    [[nodiscard]] bool contains(std::string_view name) const;

    /// Remove both slots for `name`. True when nothing remains.
    bool remove(std::string_view name);

    [[nodiscard]] std::filesystem::path current_path(std::string_view name) const;
    [[nodiscard]] std::filesystem::path next_path(std::string_view name) const;

private:
    [[nodiscard]] bool write_blob(const std::filesystem::path& path, std::string_view blob,
                                  std::string& why) const;
    [[nodiscard]] std::optional<std::string> read_blob(const std::filesystem::path& path) const;
    /// Bring the next slot in line with next_boot_chain_ for a secret the
    /// caller holds. Failures are logged and do not fail the caller.
    void stage_next(std::string_view name, std::span<const uint8_t> plaintext,
                    const Digest& current_binding);

    std::filesystem::path        directory_;
    SealBackend                  backend_;
    std::optional<BootPcrValues> next_boot_chain_;
};

}  // namespace nexus::security
