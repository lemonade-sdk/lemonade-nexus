#pragma once

#include <LemonadeNexus/Core/ServerConfig.hpp>

#include <optional>
#include <string>

namespace nexus::core {

/// Result of ensuring a data directory holds both server keypairs.
struct InitResult {
    std::string identity_pubkey_hex;  // mesh root pubkey when this box is genesis
    std::string gossip_pubkey_b64;    // what server certificates bind to
    bool identity_created{false};
    bool gossip_created{false};
};

/// Create the data dir + identity/gossip keypairs if missing. Never regenerates
/// existing keys. Returns nullopt on I/O failure.
[[nodiscard]] std::optional<InitResult> ensure_initialized(const ServerConfig& config);

/// Run any CLI-mode flag (--print-tpm-ak, --first-run, --enroll-server,
/// --revoke-server, --add-manifest, --onboard-server) and the uninitialized-
/// data-dir gate. Returns the process exit code when the invocation was a CLI
/// mode (or the gate failed); nullopt when the normal server should start.
[[nodiscard]] std::optional<int> run_cli_mode(ServerConfig& config, const char* argv0);

} // namespace nexus::core
