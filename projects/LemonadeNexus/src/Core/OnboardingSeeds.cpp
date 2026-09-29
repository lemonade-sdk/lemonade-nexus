#include "OnboardingSeeds.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <asio/ip/address.hpp>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <utility>

namespace nexus::core::onboarding_seeds {

namespace {
using json = nlohmann::json;
}

bool is_ip_host(const std::string& host) {
    try {
        asio::ip::make_address(host);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

void plan_onboarded_seeds(const std::string& config_path,
                          const std::string& mesh_genesis_b64,
                          const std::vector<std::string>& server_seeds,
                          const std::string& proven_host,
                          int proven_port,
                          std::vector<std::string>& new_seeds,
                          bool& genesis_mismatch,
                          std::string& proven_skip_note) {
    std::vector<std::string> existing;
    genesis_mismatch = false;
    proven_skip_note.clear();
    if (!std::filesystem::exists(config_path)) {
        spdlog::warn("Onboard: config {} not found; treating seed_peers as empty",
                     config_path);
    } else {
        std::ifstream f(config_path);
        if (!f) {
            spdlog::warn("Onboard: cannot read config {}; treating seed_peers as empty",
                         config_path);
        } else {
            auto parsed = json::parse(f, nullptr, false);
            if (parsed.is_discarded() || !parsed.is_object()) {
                spdlog::warn("Onboard: config {} does not parse as a JSON object; "
                             "treating seed_peers as empty", config_path);
            } else {
                if (parsed.contains("seed_peers")) {
                    if (parsed["seed_peers"].is_array())
                        existing = parsed["seed_peers"].get<std::vector<std::string>>();
                    else
                        spdlog::warn("Onboard: config {} has a non-array seed_peers; "
                                     "treating as empty", config_path);
                }
                if (parsed.contains("genesis_pubkey") && parsed["genesis_pubkey"].is_string()) {
                    const auto config_genesis = parsed["genesis_pubkey"].get<std::string>();
                    if (config_genesis != mesh_genesis_b64) genesis_mismatch = true;
                }
            }
        }
    }
    // The server-reported seeds use its self-detected public IP, which can be
    // wrong (multihomed/NAT). The address we just onboarded through is proven
    // reachable — recommend it first. Gossip peers are IP-only, so a
    // hostname target is never added; the operator adds the server's public
    // IP from the anchors instead.
    std::vector<std::string> seeds;
    if (!proven_host.empty()) {
        if (is_ip_host(proven_host)) {
            seeds.push_back(proven_host + ":" + std::to_string(proven_port));
        } else {
            proven_skip_note = "proven seed skipped: " + proven_host +
                               " is a hostname; gossip peers are IP-only — use "
                               "the server's public IP (see anchors above) for seed_peers";
        }
    }
    for (const auto& s : server_seeds)
        if (std::find(seeds.begin(), seeds.end(), s) == seeds.end())
            seeds.push_back(s);

    std::vector<std::string> merged = existing;
    for (const auto& s : seeds)
        if (std::find(merged.begin(), merged.end(), s) == merged.end()) {
            merged.push_back(s);
            new_seeds.push_back(s);
        }
}

}  // namespace nexus::core::onboarding_seeds
