#pragma once

namespace nexus::core {

struct ServerConfig;

/// Run the candidate-side onboarding flow (`--onboard-server`): discover a mesh
/// server, prove possession of our gossip key, request admission, wait for the
/// decision, install the issued certificate + root anchor + seed peers, and
/// exit. Returns a process exit code.
[[nodiscard]] int run_onboard_server(ServerConfig& config);

} // namespace nexus::core
