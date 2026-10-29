// nexus-updater: one update cycle per run. nexus-updater.path starts it when
// the server touches the wake marker (a rollout started, or this server's
// turn opened); nexus-updater.timer runs it after boot and every five minutes
// after the last cycle. See Updater.hpp for the cycle.
//
//   nexus-updater [--config <server-config.json>] [--trusted-root <file>]
//
// The release identity (repository, workflow, ref) is compiled in. The
// options only name files; none of them changes what is trusted.

#include <LemonadeNexusUpdater/SigstoreVerifier.hpp>
#include <LemonadeNexusUpdater/Updater.hpp>

#include <LemonadeNexus/Core/GenesisAnchor.hpp>
#include <LemonadeNexus/Core/UpgradeControl.hpp>

#include <nlohmann/json.hpp>
#include <sodium.h>
#include <spdlog/spdlog.h>

#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <thread>

#ifndef _WIN32
#  include <sys/utsname.h>
#endif

namespace {

constexpr const char* kRepository = "lemonade-sdk/lemonade-nexus";
constexpr const char* kWorkflowPath = ".github/workflows/release.yml";
constexpr const char* kRef = "refs/heads/main";

std::optional<std::string> read_text(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    return std::string{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

int usage() {
    std::fprintf(stderr,
                 "usage: nexus-updater [--config <server-config.json>] [--trusted-root <file>]\n");
    return 2;
}

}  // namespace

int main(int argc, char** argv) {
    std::string config_path = "/var/lib/lemonade-nexus/lemonade-nexus.json";
    std::string trusted_root_path = "/usr/lib/lemonade-nexus/updater/sigstore-trusted-root.json";
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        } else if (std::strcmp(argv[i], "--trusted-root") == 0 && i + 1 < argc) {
            trusted_root_path = argv[++i];
        } else {
            return usage();
        }
    }
    if (sodium_init() < 0) {
        spdlog::error("[updater] libsodium did not initialize");
        return 1;
    }
    // systemd 252 and later name the activating unit: the path unit (with
    // the changed path) or the timer.
    if (const char* trigger = std::getenv("TRIGGER_UNIT")) {
        const char* path = std::getenv("TRIGGER_PATH");
        spdlog::info("[updater] started by {}{}{}", trigger, path != nullptr ? " on " : "",
                     path != nullptr ? path : "");
    }

    // The Genesis anchor comes from the server's root-owned configuration.
    const auto config_text = read_text(config_path);
    const auto config = config_text ? nlohmann::json::parse(*config_text, nullptr, false)
                                    : nlohmann::json();
    if (!config.is_object() || !config.contains("genesis_pubkey") ||
        !config["genesis_pubkey"].is_string()) {
        spdlog::error("[updater] {} has no genesis_pubkey; refusing to run", config_path);
        return 1;
    }
    const auto anchor = nexus::core::load_genesis_anchor(config["genesis_pubkey"].get<std::string>());
    if (!anchor) {
        spdlog::error("[updater] genesis_pubkey is not an Ed25519 public key");
        return 1;
    }

    const auto root_text = read_text(trusted_root_path);
    std::string error;
    const auto sigstore =
        root_text ? nexus::updater::parse_sigstore_trusted_root(*root_text, error) : std::nullopt;
    if (!sigstore) {
        spdlog::error("[updater] cannot load the Sigstore trusted root {}: {}", trusted_root_path,
                      error);
        return 1;
    }

    nexus::updater::UpdaterConfig cfg;
    cfg.trust.genesis_public_key = anchor->genesis_public_key;
    cfg.trust.network_id = anchor->network_id;
    cfg.trust.repository = kRepository;

    const nexus::updater::ProvenancePolicy policy{kRepository, kWorkflowPath, kRef};
    nexus::updater::UpdaterEnv env;
    env.http = nexus::updater::https_get;
    env.control = [](std::string_view request) {
        return nexus::updater::control_exchange(
            std::string(nexus::core::kUpgradeControlSocketPath), request,
            nexus::updater::kControlDeadlineSeconds);
    };
    env.run = nexus::updater::run_command;
    env.provenance = [root = *sigstore, policy](std::string_view bundle, std::string_view sha256,
                                                std::string& why) {
        return nexus::updater::verify_provenance_bundle(root, bundle, sha256, policy, why);
    };
    env.sleep = [](std::chrono::seconds s) { std::this_thread::sleep_for(s); };
    env.now = [] { return std::chrono::steady_clock::now(); };
    env.kernel_release = [] {
#ifndef _WIN32
        utsname u{};
        if (::uname(&u) == 0) return std::string(u.release);
#endif
        return std::string();
    };

    nexus::updater::Updater updater(std::move(cfg), std::move(env));
    const auto result = updater.run_once();
    switch (result.outcome) {
        case nexus::updater::CycleOutcome::Failed:
        case nexus::updater::CycleOutcome::Refused:
            return 1;
        default:
            return 0;
    }
}
