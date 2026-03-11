#pragma once

#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <asio.hpp>
#include <nlohmann/json.hpp>

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::core {

/// A signed release manifest produced by the CI/CD pipeline.
/// Contains the SHA-256 of an official binary and is signed with the release signing key.
struct ReleaseManifest {
    std::string version;           // semantic version, e.g. "1.0.0"
    std::string commit_sha;        // git commit hash
    std::string platform;          // "linux-x86_64", "darwin-arm64", "darwin-x86_64", "windows-x86_64"
    std::string binary_sha256;     // hex-encoded SHA-256 of the compiled binary
    uint64_t    timestamp{0};      // Unix timestamp of build
    std::string signer_pubkey;     // base64 Ed25519 public key of the release signer
    std::string signature;         // base64 Ed25519 signature over canonical JSON
};

/// Canonical JSON for signing (excludes signature field).
[[nodiscard]] std::string canonical_manifest_json(const ReleaseManifest& m);

void to_json(nlohmann::json& j, const ReleaseManifest& m);
void from_json(const nlohmann::json& j, ReleaseManifest& m);

/// Minimal semantic version for release gating.
struct SemVer {
    uint32_t major{0};
    uint32_t minor{0};
    uint32_t patch{0};

    /// Parse "1.2.3" or "v1.2.3". Returns nullopt on failure.
    [[nodiscard]] static std::optional<SemVer> parse(std::string_view s);

    auto operator<=>(const SemVer&) const = default;
};

/// Binary attestation service: computes the SHA-256 hash of the running binary
/// and verifies it against signed release manifests from the CI/CD pipeline.
///
/// This prevents custom-compiled or tampered binaries from receiving operational
/// secrets (such as DDNS credentials) via the credential distribution protocol.
///
/// Supports fetching release manifests from GitHub releases to allow older
/// (but legitimately signed) binary versions to participate in the mesh.
class BinaryAttestationService : public IService<BinaryAttestationService> {
    friend class IService<BinaryAttestationService>;

public:
    BinaryAttestationService(crypto::SodiumCryptoService& crypto,
                              storage::FileStorageService& storage);

    /// Get the SHA-256 hash of our own binary (computed at startup).
    [[nodiscard]] const std::string& self_hash() const { return self_hash_; }

    /// Check if a binary hash matches any signed release manifest.
    /// Respects minimum_version — manifests below the floor are rejected.
    [[nodiscard]] bool is_approved_binary(const std::string& sha256_hex) const;

    /// Verify a release manifest's Ed25519 signature against the release signing pubkey.
    [[nodiscard]] bool verify_manifest(const ReleaseManifest& manifest) const;

    /// Add a verified manifest (persisted to data/releases/).
    bool add_manifest(const ReleaseManifest& manifest);

    /// Get all loaded manifests.
    [[nodiscard]] std::vector<ReleaseManifest> get_manifests() const;

    /// Set or override the release signing public key (base64 Ed25519).
    void set_release_signing_pubkey(const std::string& pubkey_b64);

    /// Check if we have a configured release signing pubkey.
    [[nodiscard]] bool has_signing_pubkey() const;

    // --- GitHub manifest fetching ---

    /// Set io_context for the periodic fetch timer. Must be called before start().
    void set_io_context(asio::io_context& io);

    /// Configure GitHub releases URL and manifest fetching parameters.
    void set_github_config(const std::string& releases_url,
                           uint32_t fetch_interval_sec,
                           const std::string& minimum_version);

    /// Fetch release manifests from GitHub releases API.
    /// Downloads manifest assets, verifies signatures, caches locally.
    /// @return number of newly discovered manifests
    [[nodiscard]] uint32_t fetch_github_manifests();

    /// Check if a version meets the minimum version requirement.
    [[nodiscard]] bool is_version_allowed(const std::string& version) const;

    /// Get configured minimum version (empty if none).
    [[nodiscard]] const std::string& minimum_version() const { return minimum_version_; }

    /// Get configured GitHub releases URL.
    [[nodiscard]] const std::string& github_releases_url() const { return github_releases_url_; }

private:
    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "BinaryAttestationService"; }

    /// Compute SHA-256 of our own executable binary.
    [[nodiscard]] std::string compute_self_hash();

    /// Load all manifests from data/releases/*.json
    void load_manifests();

    /// Persist a manifest to data/releases/
    bool persist_manifest(const ReleaseManifest& manifest);

    /// Parse the GitHub releases API JSON response and extract manifest download URLs.
    [[nodiscard]] std::vector<std::pair<std::string, std::string>>
    parse_github_releases(const std::string& json_body);

    /// Download a manifest JSON from a GitHub release asset URL.
    [[nodiscard]] std::optional<std::string> download_github_asset(
        const std::string& host, const std::string& path);

    /// Periodic fetch timer management.
    void start_fetch_timer();
    void on_fetch_tick();

    crypto::SodiumCryptoService& crypto_;
    storage::FileStorageService& storage_;

    std::string self_hash_;
    std::string release_signing_pubkey_b64_;  // base64 Ed25519
    std::vector<ReleaseManifest> manifests_;
    mutable std::mutex mutex_;

    // GitHub manifest fetching
    asio::io_context* io_{nullptr};
    std::unique_ptr<asio::steady_timer> fetch_timer_;
    std::string github_releases_url_;
    uint32_t manifest_fetch_interval_sec_{3600};
    std::string minimum_version_;
    bool fetch_timer_running_{false};
};

} // namespace nexus::core
