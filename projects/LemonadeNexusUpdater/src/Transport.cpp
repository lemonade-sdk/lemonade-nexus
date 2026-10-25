#include <LemonadeNexusUpdater/Transport.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include <cerrno>
#include <cstring>
#include <filesystem>

#ifndef _WIN32
#  include <fcntl.h>
#  include <poll.h>
#  include <signal.h>
#  include <sys/wait.h>
#  include <unistd.h>
#endif

namespace nexus::updater {

namespace {

struct ParsedUrl {
    std::string host;
    std::string path;
};

std::optional<ParsedUrl> parse_https_url(std::string_view url) {
    constexpr std::string_view kScheme = "https://";
    if (url.substr(0, kScheme.size()) != kScheme) return std::nullopt;
    url.remove_prefix(kScheme.size());
    const auto slash = url.find('/');
    ParsedUrl out;
    out.host = std::string(url.substr(0, slash));
    out.path = slash == std::string_view::npos ? "/" : std::string(url.substr(slash));
    // No userinfo, no explicit port, no IP literal tricks: a plain host name.
    if (out.host.empty() || out.host.find_first_of("@:[]") != std::string::npos) {
        return std::nullopt;
    }
    return out;
}

}  // namespace

bool allowed_github_host(std::string_view host) {
    constexpr std::string_view kContentSuffix = ".githubusercontent.com";
    if (host == "api.github.com" || host == "github.com") return true;
    return host.size() > kContentSuffix.size() &&
           host.substr(host.size() - kContentSuffix.size()) == kContentSuffix;
}

std::optional<std::string> https_get(const std::string& url, std::size_t max_bytes,
                                     std::string& error) {
    std::string current = url;
    for (int hop = 0; hop < 6; ++hop) {
        const auto parsed = parse_https_url(current);
        if (!parsed || !allowed_github_host(parsed->host)) {
            error = "refusing to fetch " + current;
            return std::nullopt;
        }
        httplib::SSLClient client(parsed->host, 443);
        client.enable_server_certificate_verification(true);
        for (const char* bundle : {"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt"}) {
            if (std::filesystem::exists(bundle)) {
                client.set_ca_cert_path(bundle);
                break;
            }
        }
        client.set_follow_location(false);
        client.set_connection_timeout(30);
        client.set_read_timeout(120);
        const httplib::Headers headers = {
            {"User-Agent", "nexus-updater"},
            {"Accept", parsed->host == "api.github.com" ? "application/vnd.github+json"
                                                         : "application/octet-stream"},
        };
        std::string body;
        bool too_large = false;
        int status = 0;
        auto result = client.Get(
            parsed->path, headers,
            [&](const httplib::Response& response) {
                status = response.status;
                return true;
            },
            [&](const char* data, std::size_t length) {
                if (status != 200) return true;  // a redirect body is discarded
                if (body.size() + length > max_bytes) {
                    too_large = true;
                    return false;
                }
                body.append(data, length);
                return true;
            });
        if (too_large) {
            error = current + " is larger than " + std::to_string(max_bytes) + " bytes";
            return std::nullopt;
        }
        if (!result) {
            error = "request to " + parsed->host + " failed: " + httplib::to_string(result.error());
            return std::nullopt;
        }
        if (result->status == 200) return body;
        if (result->status == 301 || result->status == 302 || result->status == 303 ||
            result->status == 307 || result->status == 308) {
            current = result->get_header_value("Location");
            continue;
        }
        error = current + " returned HTTP " + std::to_string(result->status);
        return std::nullopt;
    }
    error = "too many redirects for " + url;
    return std::nullopt;
}

CommandResult run_command(const std::vector<std::string>& argv) {
    CommandResult out;
#ifndef _WIN32
    if (argv.empty()) return out;
    int pipe_fds[2];
    if (::pipe(pipe_fds) != 0) return out;
    std::vector<char*> args;
    for (const auto& a : argv) args.push_back(const_cast<char*>(a.c_str()));
    args.push_back(nullptr);
    // Built before fork: the child only calls async-signal-safe functions.
    std::vector<std::string> candidates;
    for (const char* dir : {"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/"}) {
        candidates.push_back(dir + argv[0]);
    }
    const pid_t pid = ::fork();
    if (pid < 0) {
        ::close(pipe_fds[0]);
        ::close(pipe_fds[1]);
        return out;
    }
    if (pid == 0) {
        ::dup2(pipe_fds[1], STDOUT_FILENO);
        ::dup2(pipe_fds[1], STDERR_FILENO);
        ::close(pipe_fds[0]);
        ::close(pipe_fds[1]);
        const int devnull = ::open("/dev/null", O_RDONLY);
        if (devnull >= 0) ::dup2(devnull, STDIN_FILENO);
        static char path[] = "PATH=/usr/sbin:/usr/bin:/sbin:/bin";
        static char lang[] = "LC_ALL=C";
        static char frontend[] = "DEBIAN_FRONTEND=noninteractive";
        char* envp[] = {path, lang, frontend, nullptr};
        for (const auto& candidate : candidates) ::execve(candidate.c_str(), args.data(), envp);
        ::_exit(127);
    }
    ::close(pipe_fds[1]);
    char buf[8192];
    while (true) {
        const ssize_t n = ::read(pipe_fds[0], buf, sizeof(buf));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        if (out.output.size() < kMaxCommandOutputBytes) {
            out.output.append(buf, static_cast<std::size_t>(n));
        }
    }
    ::close(pipe_fds[0]);
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
    }
    out.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
#else
    (void)argv;
#endif
    return out;
}

std::string latest_release_url(std::string_view repository) {
    return "https://api.github.com/repos/" + std::string(repository) + "/releases/latest";
}

std::optional<GitHubRelease> parse_github_release(std::string_view json_text,
                                                  std::string_view repository,
                                                  std::string& error) {
    const auto j = nlohmann::json::parse(json_text, nullptr, false);
    if (j.is_discarded() || !j.is_object()) {
        error = "the release document is not JSON";
        return std::nullopt;
    }
    GitHubRelease r;
    try {
        r.tag = j.at("tag_name").get<std::string>();
        r.draft = j.value("draft", false);
        r.prerelease = j.value("prerelease", false);
        const std::string prefix = "https://github.com/" + std::string(repository) +
                                   "/releases/download/" + r.tag + "/";
        for (const auto& a : j.at("assets")) {
            ReleaseAsset asset;
            asset.name = a.at("name").get<std::string>();
            asset.download_url = a.at("browser_download_url").get<std::string>();
            asset.size = a.value("size", uint64_t{0});
            if (asset.download_url != prefix + asset.name) continue;
            r.assets.push_back(std::move(asset));
        }
    } catch (const std::exception& e) {
        error = std::string("the release document is incomplete: ") + e.what();
        return std::nullopt;
    }
    return r;
}

}  // namespace nexus::updater
