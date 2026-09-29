#pragma once

// Internal seed planning for onboarding. Not the public include tree and not
// the ln_* SDK surface; test_onboarding gets a narrow PRIVATE path to it
// (see tests/CMakeLists.txt).

#include <string>
#include <vector>

namespace nexus::core::onboarding_seeds {

// True if `host` (the part of a "host:port" target before the port) is a
// literal IPv4/IPv6 address. Gossip peers are IP-only (GossipService
// endpoint parsing never does DNS), so a hostname target cannot become a
// seed even though the HTTP onboarding to it succeeded.
[[nodiscard]] bool is_ip_host(const std::string& host);

// Read the candidate's config READ-ONLY and merge the seed peers into the
// existing list (existing seeds first, then the proven onboarding target,
// then any server-reported peers not already present). The config file is
// root-protected: onboarding never modifies it, it only reports what the
// operator should apply. A missing, unreadable, or malformed config (or a
// non-array seed_peers) warns once and treats the existing seeds as empty —
// a config-file condition never fails the run, by which point the
// certificate is already installed.
//
// `proven_host`/`proven_port` is the "host:port" the onboarding ran
// through: proven reachable, so it is the first recommended seed. Gossip
// peers are IP-only, so a hostname target is NOT added; in that case
// `proven_skip_note` carries the operator note explaining the skip, and
// stays empty when the proven seed was added (or no target was given).
// `new_seeds` receives the merged peers absent from the config (the ones to
// recommend); `genesis_mismatch` is set when the config carries a
// genesis_pubkey that differs from `mesh_genesis_b64`.
void plan_onboarded_seeds(const std::string& config_path,
                          const std::string& mesh_genesis_b64,
                          const std::vector<std::string>& server_seeds,
                          const std::string& proven_host,
                          int proven_port,
                          std::vector<std::string>& new_seeds,
                          bool& genesis_mismatch,
                          std::string& proven_skip_note);

}  // namespace nexus::core::onboarding_seeds
