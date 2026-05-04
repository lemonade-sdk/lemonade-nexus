#include <LemonadeNexus/Core/BinaryAttestation.hpp>

#include <httplib.h>
#include <spdlog/spdlog.h>

#include <charconv>
#include <cstring>
#include <filesystem>
#include <fstream>

#if defined(__APPLE__)
#include <mach-o/dyld.h>
#elif defined(_WIN32)
#include <windows.h>
#elif defined(__linux__)
// Uses /proc/self/exe
#endif

namespace nexus::core {

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// ReleaseManifest serialization
// ---------------------------------------------------------------------------

std::string canonical_manifest_json(const ReleaseManifest& m) {
    json j;
    j["version"]        = m.version;
    j["commit_sha"]     = m.commit_sha;
    j["platform"]       = m.platform;
    j["binary_sha256"]  = m.binary_sha256;
    j["timestamp"]      = m.timestamp;
    j["signer_pubkey"]  = m.signer_pubkey;
    return j.dump();  // nlohmann::json sorts keys alphabetically by default
}

void to_json(json& j, const ReleaseManifest& m) {
    j = json{
        {"version",        m.version},
        {"commit_sha",     m.commit_sha},
        {"platform",       m.platform},
        {"binary_sha256",  m.binary_sha256},
        {"timestamp",      m.timestamp},
        {"signer_pubkey",  m.signer_pubkey},
        {"signature",      m.signature},
    };
}

void from_json(const json& j, ReleaseManifest& m) {
    if (j.contains("version"))        j.at("version").get_to(m.version);
    if (j.contains("commit_sha"))     j.at("commit_sha").get_to(m.commit_sha);
    if (j.contains("platform"))       j.at("platform").get_to(m.platform);
    if (j.contains("binary_sha256"))  j.at("binary_sha256").get_to(m.binary_sha256);
    if (j.contains("timestamp"))      j.at("timestamp").get_to(m.timestamp);
    if (j.contains("signer_pubkey"))  j.at("signer_pubkey").get_to(m.signer_pubkey);
    if (j.contains("signature"))      j.at("signature").get_to(m.signature);
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

BinaryAttestationService::BinaryAttestationService(
    crypto::SodiumCryptoService& crypto,
    storage::FileStorageService& storage)
    : crypto_(crypto)
    , storage_(storage)
{
}

// ---------------------------------------------------------------------------
// IService lifecycle
// ---------------------------------------------------------------------------

void BinaryAttestationService::on_start() {
    // Compute our binary hash
    self_hash_ = compute_self_hash();
    if (self_hash_.empty()) {
        //Throw error that there is no binary hash because even again if we are testing,
        // or are hacked we dont allow it to not exist even without TEE it means this is unnoficial.
        spdlog::warn("[{}] could not compute self binary hash", name());
    } else {
        spdlog::info("[{}] binary SHA-256: {}", name(), self_hash_);
    }

    // Load approved manifests from disk
    load_manifests();

    // Check if our own binary is in the approved list
    if (!self_hash_.empty() && !manifests_.empty()) {
        if (is_approved_binary(self_hash_)) {
            spdlog::info("[{}] our binary matches an approved release manifest", name());
        } else {
            spdlog::warn("[{}] our binary does NOT match any approved release manifest "
                          "(this may be a development build)", name());
            // we need access to a api client to log the attempt of loading a binary that is not approved.
            //basically we get to log they're IP, MAC, HOST, and any other information we deem "needed" in order to obtain a good blacklist.
        }
    }

    // Fetch manifests from GitHub on startup if configured
    if (!github_releases_url_.empty()) {
        auto fetched = fetch_github_manifests();
        if (fetched > 0) {
            spdlog::info("[{}] fetched {} manifests from GitHub on startup", name(), fetched);
        }
        start_fetch_timer();
    }

    spdlog::info("[{}] started ({} manifests loaded)", name(), manifests_.size());
}

void BinaryAttestationService::on_stop() {
    fetch_timer_running_ = false;
    if (fetch_timer_) {
        fetch_timer_->cancel();
    }
    spdlog::info("[{}] stopped", name());
}

// ---------------------------------------------------------------------------
// Self-hash computation (cross-platform)
// ---------------------------------------------------------------------------

std::string BinaryAttestationService::compute_self_hash() {
    std::filesystem::path exe_path;

#if defined(__linux__)
    // Linux: read /proc/self/exe symlink
    std::error_code ec;
    exe_path = std::filesystem::read_symlink("/proc/self/exe", ec);
    if (ec) {
        spdlog::warn("[{}] failed to read /proc/self/exe: {}", name(), ec.message());
        return {};
    }

#elif defined(__APPLE__)
    // macOS: use _NSGetExecutablePath
    char path_buf[4096];
    uint32_t buf_size = sizeof(path_buf);
    if (_NSGetExecutablePath(path_buf, &buf_size) != 0) {
        spdlog::warn("[{}] _NSGetExecutablePath failed (buffer too small: {})", name(), buf_size);
        return {};
    }
    exe_path = std::filesystem::canonical(path_buf);

#elif defined(_WIN32)
    // Windows: use GetModuleFileName
    char path_buf[MAX_PATH];
    auto len = GetModuleFileNameA(nullptr, path_buf, MAX_PATH);
    if (len == 0 || len >= MAX_PATH) {
        spdlog::warn("[{}] GetModuleFileName failed", name());
        return {};
    }
    exe_path = path_buf;

#else
    spdlog::warn("[{}] unsupported platform for binary self-hash", name());
    return {};
#endif

    // Read the binary and compute SHA-256
    std::ifstream file(exe_path, std::ios::binary);
    if (!file) {
        spdlog::warn("[{}] cannot open executable: {}", name(), exe_path.string());
        return {};
    }

    // Read in 64KB chunks for large binaries
    constexpr std::size_t kChunkSize = 65536;
    std::vector<uint8_t> full_contents;
    std::vector<uint8_t> chunk(kChunkSize);

    while (file) {
        file.read(reinterpret_cast<char*>(chunk.data()),
                  static_cast<std::streamsize>(kChunkSize));
        auto bytes_read = static_cast<std::size_t>(file.gcount());
        if (bytes_read > 0) {
            full_contents.insert(full_contents.end(),
                                 chunk.begin(), chunk.begin() + bytes_read);
        }
    }

    if (full_contents.empty()) {
        spdlog::warn("[{}] executable is empty: {}", name(), exe_path.string());
        return {};
    }

    auto hash = crypto_.sha256(std::span<const uint8_t>(full_contents));
    auto hex = crypto::to_hex(hash);

    spdlog::debug("[{}] executable: {} ({} bytes)", name(), exe_path.string(), full_contents.size());
    return hex;
}

// ---------------------------------------------------------------------------
// Manifest management
// ---------------------------------------------------------------------------

void BinaryAttestationService::load_manifests() {
    std::lock_guard lock(mutex_);
    manifests_.clear();

    const auto releases_dir = storage_.data_root() / "releases";
    if (!std::filesystem::exists(releases_dir)) {
        spdlog::debug("[{}] no releases directory at {}", name(), releases_dir.string());
        //I would prefer to throw here as well or perhaps soft throw and then hard throw after, so we can report
        //  the IP to the blacklist and host informarion for attempting to load up a binary incorrectly.
        // there should not be a way to load this software in a way it is not correct that is the job of the publisher/packager.
        return;
    }

    for (const auto& entry : std::filesystem::directory_iterator(releases_dir)) {
        if (!entry.is_regular_file() || entry.path().extension() != ".json") {
            continue;
        }

        try {
            std::ifstream f(entry.path());
            auto j = json::parse(f);
            auto manifest = j.get<ReleaseManifest>();

            if (verify_manifest(manifest)) {
                manifests_.push_back(std::move(manifest));
            } else {
                spdlog::warn("[{}] manifest at {} has invalid signature, skipping",
                              name(), entry.path().string());
            }
        } catch (const std::exception& e) {
            spdlog::warn("[{}] failed to parse manifest {}: {}",
                          name(), entry.path().string(), e.what());
        }
    }

    spdlog::info("[{}] loaded {} verified release manifests", name(), manifests_.size());
}

bool BinaryAttestationService::persist_manifest(const ReleaseManifest& manifest) {
    const auto releases_dir = storage_.data_root() / "releases";
    std::error_code ec;
    std::filesystem::create_directories(releases_dir, ec);
    if (ec) {
        spdlog::error("[{}] cannot create releases directory: {}", name(), ec.message());
        return false;
    }

    // Filename: version-platform.json
    const auto filename = manifest.version + "-" + manifest.platform + ".json";
    const auto path = releases_dir / filename;

    try {
        json j = manifest;
        std::ofstream f(path);
        f << j.dump(2);
        spdlog::info("[{}] saved manifest to {}", name(), path.string());
        return true;
    } catch (const std::exception& e) {
        spdlog::error("[{}] failed to save manifest: {}", name(), e.what());
        return false;
    }
}

bool BinaryAttestationService::add_manifest(const ReleaseManifest& manifest) {
    if (!verify_manifest(manifest)) {
        spdlog::warn("[{}] refusing to add manifest with invalid signature", name());
        return false;
    }

    {
        std::lock_guard lock(mutex_);

        // Check for duplicate
        for (const auto& m : manifests_) {
            if (m.binary_sha256 == manifest.binary_sha256 && m.platform == manifest.platform) {
                spdlog::debug("[{}] manifest for {} {} already exists",
                               name(), manifest.version, manifest.platform);
                return true; // already have it
            }
        }

        manifests_.push_back(manifest);
    }

    return persist_manifest(manifest);
}

bool BinaryAttestationService::is_approved_binary(const std::string& sha256_hex) const {
    std::lock_guard lock(mutex_);
    for (const auto& m : manifests_) {
        if (m.binary_sha256 == sha256_hex) {
            // Check minimum version if configured
            if (!minimum_version_.empty()) {
                auto min_ver = SemVer::parse(minimum_version_);
                auto manifest_ver = SemVer::parse(m.version);
                if (min_ver && manifest_ver && *manifest_ver < *min_ver) {
                    spdlog::warn("[{}] binary matches v{} but below minimum version {}",
                                  name(), m.version, minimum_version_);
                    return false;
                }
            }
            return true;
        }
    }
    return false;
}

bool BinaryAttestationService::verify_manifest(const ReleaseManifest& manifest) const {
    if (release_signing_pubkey_b64_.empty()) {
        // No signing key configured — accept all manifests (development mode)
        spdlog::debug("[{}] no release signing pubkey configured, accepting manifest", name());
        return true;
    }

    // Verify signer matches our expected release signing key
    if (manifest.signer_pubkey != release_signing_pubkey_b64_) {
        spdlog::warn("[{}] manifest signer '{}' does not match expected '{}'",
                      name(), manifest.signer_pubkey, release_signing_pubkey_b64_);
        return false;
    }

    // Verify Ed25519 signature
    auto pubkey_bytes = crypto::from_base64(manifest.signer_pubkey);
    if (pubkey_bytes.size() != crypto::kEd25519PublicKeySize) {
        spdlog::warn("[{}] manifest signer pubkey has invalid size", name());
        return false;
    }

    crypto::Ed25519PublicKey pubkey{};
    std::memcpy(pubkey.data(), pubkey_bytes.data(), crypto::kEd25519PublicKeySize);

    auto canonical = canonical_manifest_json(manifest);
    auto canonical_bytes = std::vector<uint8_t>(canonical.begin(), canonical.end());

    auto sig_bytes = crypto::from_base64(manifest.signature);
    if (sig_bytes.size() != crypto::kEd25519SignatureSize) {
        spdlog::warn("[{}] manifest signature has invalid size", name());
        return false;
    }

    crypto::Ed25519Signature sig{};
    std::memcpy(sig.data(), sig_bytes.data(), crypto::kEd25519SignatureSize);

    if (!crypto_.ed25519_verify(pubkey, canonical_bytes, sig)) {
        spdlog::warn("[{}] manifest signature verification failed for v{} {}",
                      name(), manifest.version, manifest.platform);
        return false;
    }

    return true;
}

std::vector<ReleaseManifest> BinaryAttestationService::get_manifests() const {
    std::lock_guard lock(mutex_);
    return manifests_;
}

void BinaryAttestationService::set_release_signing_pubkey(const std::string& pubkey_b64) {
    release_signing_pubkey_b64_ = pubkey_b64;
    spdlog::info("[{}] release signing pubkey set: {}",
                  name(), pubkey_b64.substr(0, 12) + "...");
}

bool BinaryAttestationService::has_signing_pubkey() const {
    return !release_signing_pubkey_b64_.empty();
}

// ---------------------------------------------------------------------------
// SemVer
// ---------------------------------------------------------------------------

std::optional<SemVer> SemVer::parse(std::string_view s) {
    if (s.empty()) return std::nullopt;
    // Strip leading 'v' or 'V'
    if (s.front() == 'v' || s.front() == 'V') s.remove_prefix(1);
    if (s.empty()) return std::nullopt;

    SemVer ver;
    auto parse_uint = [](std::string_view part, uint32_t& out) -> bool {
        auto [ptr, ec] = std::from_chars(part.data(), part.data() + part.size(), out);
        return ec == std::errc{} && ptr == part.data() + part.size();
    };

    // Find major.minor.patch
    auto dot1 = s.find('.');
    if (dot1 == std::string_view::npos) {
        if (!parse_uint(s, ver.major)) return std::nullopt;
        return ver;
    }
    if (!parse_uint(s.substr(0, dot1), ver.major)) return std::nullopt;

    auto rest = s.substr(dot1 + 1);
    auto dot2 = rest.find('.');
    if (dot2 == std::string_view::npos) {
        if (!parse_uint(rest, ver.minor)) return std::nullopt;
        return ver;
    }
    if (!parse_uint(rest.substr(0, dot2), ver.minor)) return std::nullopt;

    // Patch might have pre-release suffix (e.g. "3-beta"), take only digits
    auto patch_str = rest.substr(dot2 + 1);
    auto dash = patch_str.find('-');
    if (dash != std::string_view::npos) {
        patch_str = patch_str.substr(0, dash);
    }
    if (!parse_uint(patch_str, ver.patch)) return std::nullopt;

    return ver;
}

// ---------------------------------------------------------------------------
// GitHub manifest fetching
// ---------------------------------------------------------------------------

void BinaryAttestationService::set_io_context(asio::io_context& io) {
    io_ = &io;
}

void BinaryAttestationService::set_github_config(
    const std::string& releases_url,
    uint32_t fetch_interval_sec,
    const std::string& minimum_version)
{
    github_releases_url_ = releases_url;
    manifest_fetch_interval_sec_ = fetch_interval_sec > 0 ? fetch_interval_sec : 3600;
    minimum_version_ = minimum_version;

    if (!releases_url.empty()) {
        spdlog::info("[{}] GitHub manifest fetching configured: url={}, interval={}s, min_version={}",
                      name(), releases_url, manifest_fetch_interval_sec_,
                      minimum_version.empty() ? "(none)" : minimum_version);
    }
}

bool BinaryAttestationService::is_version_allowed(const std::string& version) const {
    if (minimum_version_.empty()) return true;

    auto min_ver = SemVer::parse(minimum_version_);
    auto ver = SemVer::parse(version);
    if (!min_ver || !ver) return true;  // unparseable = lenient

    return *ver >= *min_ver;
}

std::vector<std::pair<std::string, std::string>>
BinaryAttestationService::parse_github_releases(const std::string& json_body) {
    std::vector<std::pair<std::string, std::string>> asset_urls;  // {host, path}

    try {
        auto releases = json::parse(json_body);
        if (!releases.is_array()) return asset_urls;

        for (const auto& release : releases) {
            if (!release.contains("assets") || release.value("draft", false)) continue;

            for (const auto& asset : release["assets"]) {
                auto asset_name = asset.value("name", "");
                // Look for manifest JSON files (e.g., manifest-linux-x86_64.json)
                if (asset_name.find("manifest") != std::string::npos &&
                    asset_name.ends_with(".json")) {

                    auto download_url = asset.value("browser_download_url", "");
                    if (download_url.empty()) continue;

                    // Parse URL into host + path
                    // URL format: https://github.com/owner/repo/releases/download/tag/file
                    if (download_url.starts_with("https://")) {
                        auto url_rest = download_url.substr(8); // after "https://"
                        auto slash_pos = url_rest.find('/');
                        if (slash_pos != std::string::npos) {
                            auto host = url_rest.substr(0, slash_pos);
                            auto path = url_rest.substr(slash_pos);
                            asset_urls.emplace_back(host, path);
                        }
                    }
                }
            }
        }
    } catch (const std::exception& e) {
        spdlog::warn("[{}] failed to parse GitHub releases JSON: {}", name(), e.what());
    }

    return asset_urls;
}

std::optional<std::string> BinaryAttestationService::download_github_asset(
    const std::string& host, const std::string& path)
{
    try {
        httplib::SSLClient client(host, 443);
        client.set_connection_timeout(10);
        client.set_read_timeout(30);
        client.set_follow_location(true);

        httplib::Headers headers = {
            {"User-Agent", "LemonadeNexus/1.0"},
            {"Accept", "application/octet-stream"},
        };

        auto res = client.Get(path, headers);
        if (!res) {
            spdlog::warn("[{}] GitHub asset download failed for {}{}: connection error",
                          name(), host, path);
            return std::nullopt;
        }

        if (res->status != 200) {
            spdlog::warn("[{}] GitHub asset download failed: HTTP {}",
                          name(), res->status);
            return std::nullopt;
        }

        return res->body;
    } catch (const std::exception& e) {
        spdlog::warn("[{}] GitHub asset download exception: {}", name(), e.what());
        return std::nullopt;
    }
}

uint32_t BinaryAttestationService::fetch_github_manifests() {
    if (github_releases_url_.empty()) return 0;

    spdlog::debug("[{}] fetching manifests from GitHub...", name());

    // Parse the configured URL into host + path
    std::string api_host;
    std::string api_path;

    if (github_releases_url_.starts_with("https://")) {
        auto url_rest = github_releases_url_.substr(8);
        auto slash_pos = url_rest.find('/');
        if (slash_pos != std::string::npos) {
            api_host = url_rest.substr(0, slash_pos);
            api_path = url_rest.substr(slash_pos);
        }
    }

    if (api_host.empty() || api_path.empty()) {
        spdlog::warn("[{}] invalid GitHub releases URL: {}", name(), github_releases_url_);
        return 0;
    }

    // Fetch the releases list
    std::string releases_json;
    try {
        httplib::SSLClient client(api_host, 443);
        client.set_connection_timeout(10);
        client.set_read_timeout(30);

        httplib::Headers headers = {
            {"User-Agent", "LemonadeNexus/1.0"},
            {"Accept", "application/vnd.github+json"},
        };

        // Support optional auth token for private repos / higher rate limits
        if (const char* token = std::getenv("SP_GITHUB_TOKEN")) {
            headers.emplace("Authorization", std::string("Bearer ") + token);
        }

        auto res = client.Get(api_path, headers);
        if (!res) {
            spdlog::warn("[{}] GitHub API request failed: connection error", name());
            return 0;
        }

        if (res->status != 200) {
            spdlog::warn("[{}] GitHub API returned HTTP {}", name(), res->status);
            return 0;
        }

        // Check rate limit
        auto remaining = res->get_header_value("X-RateLimit-Remaining");
        if (!remaining.empty()) {
            int rem = std::atoi(remaining.c_str());
            if (rem < 10) {
                spdlog::warn("[{}] GitHub API rate limit low: {} remaining", name(), rem);
            }
        }

        releases_json = res->body;
    } catch (const std::exception& e) {
        spdlog::warn("[{}] GitHub API exception: {}", name(), e.what());
        return 0;
    }

    // Parse the response and find manifest asset URLs
    auto asset_urls = parse_github_releases(releases_json);
    if (asset_urls.empty()) {
        spdlog::debug("[{}] no manifest assets found in GitHub releases", name());
        return 0;
    }

    // Download and process each manifest
    uint32_t new_count = 0;
    for (const auto& [host, path] : asset_urls) {
        auto body = download_github_asset(host, path);
        if (!body) continue;

        try {
            auto j = json::parse(*body);
            auto manifest = j.get<ReleaseManifest>();

            // Verify signature — this is the security boundary
            if (!verify_manifest(manifest)) {
                spdlog::warn("[{}] GitHub manifest has invalid signature, skipping: v{} {}",
                              name(), manifest.version, manifest.platform);
                continue;
            }

            // Check minimum version
            if (!is_version_allowed(manifest.version)) {
                spdlog::debug("[{}] GitHub manifest v{} below minimum {}, skipping",
                               name(), manifest.version, minimum_version_);
                continue;
            }

            // add_manifest handles dedup and persistence
            if (add_manifest(manifest)) {
                spdlog::info("[{}] fetched manifest from GitHub: v{} {} (hash: {})",
                              name(), manifest.version, manifest.platform,
                              manifest.binary_sha256.substr(0, 16) + "...");
                ++new_count;
            }
        } catch (const std::exception& e) {
            spdlog::warn("[{}] failed to parse GitHub manifest: {}", name(), e.what());
        }
    }

    if (new_count > 0) {
        spdlog::info("[{}] fetched {} new manifests from GitHub ({} total)",
                      name(), new_count, manifests_.size());
    }

    return new_count;
}

void BinaryAttestationService::start_fetch_timer() {
    if (!io_ || github_releases_url_.empty()) return;

    if (!fetch_timer_) {
        fetch_timer_ = std::make_unique<asio::steady_timer>(*io_);
    }

    fetch_timer_running_ = true;
    fetch_timer_->expires_after(std::chrono::seconds(manifest_fetch_interval_sec_));
    fetch_timer_->async_wait([this](const asio::error_code& ec) {
        if (!ec && fetch_timer_running_) {
            on_fetch_tick();
            start_fetch_timer();
        }
    });
}

void BinaryAttestationService::on_fetch_tick() {
    auto new_count = fetch_github_manifests();
    if (new_count > 0) {
        // Re-check our own binary against newly fetched manifests
        if (!self_hash_.empty() && is_approved_binary(self_hash_)) {
            spdlog::info("[{}] our binary now matches an approved manifest after GitHub fetch", name());
        }
    }
}

} // namespace nexus::core
