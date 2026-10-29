#pragma once

// Verification of a downloaded release before anything is staged.
//
// Trust comes from two signatures by the release key that Genesis delegates:
//   - release-approval.json: the approval the server attests against. It is
//     verified with the server's own verify_release_approval_bundle(), so the
//     updater and the server apply the same rules.
//   - manifest.json.sig: an Ed25519 signature over
//     kManifestSignatureDomain || manifest.json. It covers what the approval
//     cannot: which asset installs where, the OS package lock, and the
//     release number. The domain prefix keeps the two signature uses apart;
//     the approval preimage is canonical JSON and never starts with it.
//
// The release number is derived from the approval's release_id (the tag), so
// it is under the approval signature as well. It must be greater than the
// highest number this host has installed: no downgrade, no replay.

#include <LemonadeNexusUpdater/ReleaseTag.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Attestation/ReleaseApproval.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::updater {

inline constexpr std::string_view kManifestSignatureDomain =
    "lemonade-nexus/release-manifest/v1\n";
inline constexpr uint32_t kManifestFormatVersion = 1;
inline constexpr std::size_t kMaxManifestBytes = 256 * 1024;

/// The server files the updater replaces in the swap. Both are required
/// approved paths; the approval itself installs at
/// security::kReleaseApprovalPath.
inline constexpr std::string_view kSwappablePaths[] = {
    "/usr/bin/lemonade-nexus",
    "/usr/bin/nexus-attestd",
};

/// Where the updater installs its own binary. The updater is not attested, so
/// its hash is not in the approval: the manifest signature and the Sigstore
/// provenance cover it, and the swap happens only after the health gate.
inline constexpr std::string_view kUpdaterPath = "/usr/bin/nexus-updater";

struct ManifestFile {
    std::string asset;
    /// Absolute install path.
    std::string path;
    std::string sha256;
};

struct ManifestArtifact {
    std::string name;
    std::string sha256;
};

struct ReleaseManifest {
    uint32_t format_version{0};
    std::string repository;
    std::string tag;
    std::string version;
    uint64_t release_number{0};
    std::string source_commit;

    std::string approval_asset;
    std::string approval_sha256;
    /// release_approval_digest_hex() of the approval.
    std::string approval_digest;

    std::vector<ManifestFile> server_files;

    /// The release's updater binary, installed at kUpdaterPath after the
    /// health gate. An empty asset: the release carries none and the
    /// installed updater stays.
    ManifestFile updater;

    std::string os_lock_asset;
    std::string os_lock_sha256;
    bool boot_chain_changed{false};

    /// Every release asset, for the record. Informational for the updater.
    std::vector<ManifestArtifact> artifacts;
};

/// Strict parse of manifest.json. nullopt with a reason on any missing or
/// mistyped field, an invalid hash, or an asset name with a path separator.
[[nodiscard]] std::optional<ReleaseManifest> parse_release_manifest(std::string_view text,
                                                                    std::string& error);

/// The anchors a host pins. All of them come from root-owned configuration
/// or the compiled policy, never from the release being verified.
struct ReleaseTrust {
    crypto::Ed25519PublicKey genesis_public_key{};
    security::NetworkId network_id{};
    /// "owner/name" the manifest must name.
    std::string repository;
};

struct VerifiedRelease {
    security::ReleaseApprovalBundleV1 approval;
    ReleaseManifest manifest;
    ReleaseTag tag;
    std::string approval_json;
};

/// Verify the approval, the release number, the manifest signature, and the
/// manifest's agreement with the approval. Fail-closed; `error` names the
/// first failed check.
[[nodiscard]] std::optional<VerifiedRelease> verify_release_metadata(
    const ReleaseTrust& trust, std::string_view manifest_bytes,
    std::string_view manifest_signature_b64, std::string_view approval_bytes,
    uint64_t installed_release_number, std::string& error);

/// Check a downloaded asset against the verified manifest. A server file must
/// also match the newest hash the approval lists for its path (the first
/// entry; nexus-release-bundle writes the new hash first).
[[nodiscard]] bool verify_asset_hash(const VerifiedRelease& release, std::string_view asset,
                                     std::string_view sha256_hex, std::string& error);

/// Hex SHA-256 of a file, or nullopt when it cannot be read.
[[nodiscard]] std::optional<std::string> sha256_file_hex(const std::string& path);

/// Hex SHA-256 of bytes.
[[nodiscard]] std::string sha256_hex(std::string_view bytes);

}  // namespace nexus::updater
