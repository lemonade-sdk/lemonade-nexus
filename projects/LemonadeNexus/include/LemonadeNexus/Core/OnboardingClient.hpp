#pragma once

#include <string>

namespace nexus::core {

struct ServerConfig;

/// Run the candidate-side onboarding flow (`--onboard-server`): discover a mesh
/// server, prove possession of our gossip key, request admission, wait for the
/// decision, install the issued certificate + seed peers, and exit. Requires a
/// preconfigured root pubkey (--root-pubkey); the response may confirm it but
/// never establishes it. Returns a process exit code.
[[nodiscard]] int run_onboard_server(ServerConfig& config);

/// "" when `pinned_hex` is a usable root anchor (32-byte hex), else an
/// actionable error. Onboarding must not run without a pinned root.
[[nodiscard]] std::string validate_pinned_root(const std::string& pinned_hex);

/// "" when the server-delivered root key confirms the pinned one (byte
/// comparison; empty `delivered_hex` is fine — confirm-only), else an error.
[[nodiscard]] std::string check_root_confirmation(const std::string& pinned_hex,
                                                  const std::string& delivered_hex);

} // namespace nexus::core
