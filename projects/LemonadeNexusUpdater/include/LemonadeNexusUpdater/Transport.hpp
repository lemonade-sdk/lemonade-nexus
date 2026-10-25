#pragma once

// The updater's outside world, as seams: HTTPS reads of GitHub, local
// commands, and the GitHub release document. Production binds the real
// implementations; tests bind fakes.

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::updater {

/// GET `url` and return the body of the final 200 response, at most
/// `max_bytes`. nullopt with a reason on any failure.
using HttpGet = std::function<std::optional<std::string>(const std::string& url,
                                                         std::size_t max_bytes,
                                                         std::string& error)>;

struct CommandResult {
    /// Exit status; -1 when the command could not run or was killed.
    int exit_code{-1};
    /// stdout and stderr, truncated at kMaxCommandOutputBytes.
    std::string output;
};

inline constexpr std::size_t kMaxCommandOutputBytes = 1024 * 1024;

/// Run argv[0] from PATH with the remaining arguments. No shell.
using CommandRunner = std::function<CommandResult(const std::vector<std::string>& argv)>;

/// The hosts the production client may contact. GitHub serves release assets
/// through redirects to its own content hosts.
[[nodiscard]] bool allowed_github_host(std::string_view host);

/// Production HTTPS GET: TLS with certificate verification against the system
/// trust store, redirects followed only to allowed GitHub hosts (at most 5).
[[nodiscard]] std::optional<std::string> https_get(const std::string& url, std::size_t max_bytes,
                                                   std::string& error);

/// Production command runner: fork and exec with a fixed PATH, LC_ALL=C, and
/// DEBIAN_FRONTEND=noninteractive. stdout and stderr are captured together.
[[nodiscard]] CommandResult run_command(const std::vector<std::string>& argv);

struct ReleaseAsset {
    std::string name;
    std::string download_url;
    uint64_t size{0};
};

struct GitHubRelease {
    std::string tag;
    bool draft{false};
    bool prerelease{false};
    std::vector<ReleaseAsset> assets;
};

/// "https://api.github.com/repos/<repo>/releases/latest".
[[nodiscard]] std::string latest_release_url(std::string_view repository);

/// Parse a GitHub release document. Assets whose download URL is not
/// "https://github.com/<repo>/releases/download/<tag>/<name>" are dropped:
/// the updater fetches nothing the release does not name under its own tag.
[[nodiscard]] std::optional<GitHubRelease> parse_github_release(std::string_view json_text,
                                                                std::string_view repository,
                                                                std::string& error);

}  // namespace nexus::updater
