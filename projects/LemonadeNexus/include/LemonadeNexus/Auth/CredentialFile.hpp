#pragma once

// File access for credentials/<user_id>.json and credentials/revoked.json,
// shared by Ed25519AuthProvider and PasskeyAuthProvider.
//
// The files go through the storage vault when it covers them (Phase 7,
// StorageVault "user-credentials"), and through durable plain-file I/O
// otherwise. A read has three results, and callers must keep them apart:
//
//   Absent      No file: a new user, or no revocation yet.
//   Unreadable  The file exists but is not usable: the vault is locked or
//               refuses the file, the read failed, or the content is not JSON.
//               A caller refuses the operation and never writes over the file.
//   Present     The file parsed as JSON.

#include <nlohmann/json.hpp>

#include <filesystem>
#include <string>
#include <vector>

namespace nexus::storage { class FileStorageService; }

namespace nexus::auth {

enum class CredentialFileState { Absent, Unreadable, Present };

struct CredentialFile {
    CredentialFileState state = CredentialFileState::Absent;
    /// The parsed content when `state` is Present; null otherwise.
    nlohmann::json data;
};

/// The directory that holds the credential files.
[[nodiscard]] std::filesystem::path credential_directory(
    const storage::FileStorageService& storage);

/// credentials/<user_id>.json. The caller validates `user_id`.
[[nodiscard]] std::filesystem::path credential_path(const storage::FileStorageService& storage,
                                                    const std::string& user_id);

/// credentials/revoked.json, the Ed25519 revocation list.
[[nodiscard]] std::filesystem::path revocation_path(const storage::FileStorageService& storage);

/// Reads `path`. Thread-safe as far as the storage vault is.
[[nodiscard]] CredentialFile read_credential_file(const storage::FileStorageService& storage,
                                                  const std::filesystem::path& path);

/// Writes `data` to `path` durably (mode 0600): through the vault when it
/// covers the path, otherwise with a temporary file and an atomic rename. On
/// failure the previous file stands. Callers serialize writes to one path.
[[nodiscard]] bool write_credential_file(const storage::FileStorageService& storage,
                                         const std::filesystem::path& path,
                                         const nlohmann::json& data);

struct CredentialListing {
    /// The *.json files in the directory, sorted. Staged and temporary files
    /// are not listed.
    std::vector<std::filesystem::path> files;
    /// False when the directory scan failed: the list is then incomplete and
    /// the caller must not treat a missing entry as an absent file.
    bool complete = true;
};

/// Lists the credential files without reading them. A missing directory is a
/// complete, empty listing.
[[nodiscard]] CredentialListing list_credential_files(const storage::FileStorageService& storage);

}  // namespace nexus::auth
