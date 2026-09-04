// nexus-attestd — the evidence-producing daemon.
//
// One job: a production AttestationChallenge in, a hardware-backed
// AttestationEvidence out. It exists so that TPM access and the root-only IMA
// measurement log are held by ONE small binary instead of by the whole Nexus
// server. Everything the daemon deliberately cannot do is spelled out in
// AttestdGate.hpp and AttestdSocket.hpp; the short version is that it decides no
// eligibility, quotes nothing a caller chooses, signs nothing a caller supplies,
// and carries no mesh authority.

#include <LemonadeNexusAttestd/AttestdService.hpp>
#include <LemonadeNexusAttestd/AttestdSocket.hpp>

#include <sodium.h>
#include <spdlog/spdlog.h>

#include <atomic>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <string>

#ifndef NEXUS_VERSION
#  define NEXUS_VERSION "0.0.0-dev"
#endif
#ifndef NEXUS_GIT_COMMIT
#  define NEXUS_GIT_COMMIT "unknown"
#endif

namespace {

std::atomic<bool> g_stop{false};

extern "C" void handle_signal(int) { g_stop.store(true); }

struct Options {
    nexus::attestd::AttestdSocketConfig socket;
    std::filesystem::path cache_dir{"/var/lib/nexus-attestd/cache"};
    bool allow_network{true};
    std::string log_level{"info"};
};

void print_usage() {
    std::fputs(
        "nexus-attestd " NEXUS_VERSION " (" NEXUS_GIT_COMMIT ")\n"
        "\n"
        "Answers attestation challenges with hardware-backed evidence.\n"
        "\n"
        "  --socket <path>     unix socket to listen on\n"
        "                      (default /run/nexus-attestd/nexus-attestd.sock)\n"
        "  --group <name>      group allowed to use the socket (default nexus)\n"
        "  --cache-dir <path>  VCEK / AMD chain cache (default /var/lib/nexus-attestd/cache)\n"
        "  --no-network        never reach AMD KDS; the cache must be pre-seeded\n"
        "  --log-level <lvl>   trace|debug|info|warn|error (default info)\n"
        "  --version           print version and exit\n",
        stdout);
}

Options parse_args(int argc, char* argv[], bool& want_exit) {
    Options opts;
    for (int i = 1; i < argc; ++i) {
        auto next = [&](const char* flag) -> const char* {
            return (std::strcmp(argv[i], flag) == 0 && i + 1 < argc) ? argv[++i] : nullptr;
        };
        if (std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0) {
            print_usage();
            want_exit = true;
            return opts;
        }
        if (std::strcmp(argv[i], "--version") == 0) {
            std::fputs("nexus-attestd " NEXUS_VERSION " (" NEXUS_GIT_COMMIT ")\n", stdout);
            want_exit = true;
            return opts;
        }
        if (const char* v = next("--socket")) {
            opts.socket.path = v;
        } else if (const char* v2 = next("--group")) {
            opts.socket.group = v2;
        } else if (const char* v4 = next("--cache-dir")) {
            opts.cache_dir = v4;
        } else if (std::strcmp(argv[i], "--no-network") == 0) {
            opts.allow_network = false;
        } else if (const char* v5 = next("--log-level")) {
            opts.log_level = v5;
        } else {
            spdlog::warn("unrecognised argument '{}'", argv[i]);
        }
    }
    return opts;
}

}  // namespace

int main(int argc, char* argv[]) {
    bool want_exit = false;
    const Options opts = parse_args(argc, argv, want_exit);
    if (want_exit) return 0;

    spdlog::set_level(spdlog::level::from_str(opts.log_level));
    spdlog::info("nexus-attestd {} ({})", NEXUS_VERSION, NEXUS_GIT_COMMIT);

    if (sodium_init() < 0) {
        spdlog::error("libsodium failed to initialise");
        return 1;
    }

    std::string why;
    std::error_code ec;
    std::filesystem::create_directories(opts.cache_dir, ec);
    if (ec) {
        spdlog::warn("cache directory {}: {}", opts.cache_dir.string(), ec.message());
    }

    // Stated once at startup rather than discovered per request, so an operator
    // who deployed the wrong build finds out immediately.
    if (!nexus::attestd::AttestdService::platform_available()) {
        spdlog::warn(
            "this build has no snp-vtpm prover (needs Linux and LEMONADE_HAVE_TPM_FAPI); every "
            "challenge will be refused with platform_unavailable");
    }

    nexus::attestd::AttestdConfig config;
    config.cache_dir = opts.cache_dir;
    config.allow_network = opts.allow_network;
    nexus::attestd::AttestdService service{std::move(config)};

    nexus::attestd::UnixRequestSocket socket;
    if (!socket.open(opts.socket, &why)) {
        spdlog::error("socket: {}", why);
        return 1;
    }

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);
#ifndef _WIN32
    // A peer that hangs up mid-response must not kill the daemon.
    std::signal(SIGPIPE, SIG_IGN);
#endif

    socket.serve(
        [&service](std::string_view request, const nexus::attestd::ResponseWriter& write) {
            service.handle_request(request, write);
        },
        g_stop);

    spdlog::info("nexus-attestd stopping");
    return 0;
}
