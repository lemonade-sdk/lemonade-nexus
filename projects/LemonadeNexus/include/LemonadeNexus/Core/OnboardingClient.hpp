#pragma once

#include <string>
#include <vector>

namespace nexus::core {

struct ServerConfig;

/// Run the candidate-side onboarding flow (`--onboard-server`): discover a mesh
/// server, prove possession of our gossip key, request admission, wait for the
/// decision, install the issued certificate into the data directory, and exit.
/// The config file is never modified (the trust anchors stay root-protected);
/// instead the approved anchors and the recommended seed peers are printed for
/// the operator to apply. Requires a preconfigured root pubkey (--root-pubkey);
/// the response may confirm it but never establishes it. Returns a process exit
/// code.
[[nodiscard]] int run_onboard_server(ServerConfig& config);

/// "" when `pinned_hex` is a usable root anchor (32-byte hex), else an
/// actionable error. Onboarding must not run without a pinned root.
[[nodiscard]] std::string validate_pinned_root(const std::string& pinned_hex);

/// "" when the server-delivered root key confirms the pinned one (byte
/// comparison; empty `delivered_hex` is fine — confirm-only), else an error.
[[nodiscard]] std::string check_root_confirmation(const std::string& pinned_hex,
                                                  const std::string& delivered_hex);

/// Extract the member FQDNs listed by tier discovery TXT record(s) of the
/// form "v=sp1 host=<id>.<region>.seip.<base> [host=... ...]". The input is
/// untrusted DNS data: fields are whitespace-delimited, only "host=" fields
/// are collected, and empty values are skipped. Empty when no members.
/// Exposed for unit testing.
[[nodiscard]] std::vector<std::string> parse_discovery_txt_hosts(
    const std::vector<std::string>& txt_strings);

/// Build the onboarding discovery candidate list ("fqdn:port" per entry):
/// per tier (1, then 2), the tier's member FQDNs in record order, followed by
/// the tier wildcard FQDN itself as a fallback (deployments whose certificate
/// covers the tier name). Exposed for unit testing.
[[nodiscard]] std::vector<std::string> build_discovery_targets(
    const std::vector<std::string>& tier1_members,
    const std::vector<std::string>& tier2_members,
    const std::string& region,
    const std::string& dns_base_domain,
    int http_port);

} // namespace nexus::core
