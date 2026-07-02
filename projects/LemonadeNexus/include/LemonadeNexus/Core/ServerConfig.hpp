#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace nexus::core {

struct ServerConfig {
    // Network
    uint16_t    http_port{9100};
    uint16_t    udp_port{51940};  // mesh + hole-punch (shared UDP port)
    uint16_t    gossip_port{9102};
    uint16_t    stun_port{3478};
    uint16_t    relay_port{9103};
    uint16_t    dns_port{5335};          // internal DNS listen port (behind NAT)
    uint16_t    public_dns_port{53};     // DNS port advertised to clients (NAT-mapped to dns_port)
    std::string bind_address{"0.0.0.0"};
    std::string public_ip;              // public-facing IP for DNS glue records (auto-detected if empty)
    std::string region;                 // cloud region code (e.g. "us-east", auto-detected if empty)
    std::string wg_interface{"nexus0"}; // boringtun interface name. MUST NOT be "wg0" or any
                                        // interface you are connected through -- the server flushes
                                        // and re-keys this device on startup, which would drop that tunnel.

    // Storage
    std::string data_root{"data"};

    // Auth
    std::string rp_id{"lemonade-nexus.local"};
    std::string jwt_secret; // empty = auto-generate & persist

    // Server identity
    std::string root_pubkey; // hex Ed25519 pubkey of the root management key

    // Gossip
    std::vector<std::string> seed_peers; // ["host:port", ...]
    uint32_t gossip_interval_sec{5};

    // Rate limiting
    uint32_t rate_limit_rpm{120};
    uint32_t rate_limit_burst{20};

    // Logging
    std::string log_level{"info"};

    // TLS (optional)
    std::string tls_cert_path;
    std::string tls_key_path;

    // ACME certificate provider
    std::string acme_provider{"letsencrypt"}; // "letsencrypt", "letsencrypt_staging", "zerossl"
    std::string acme_eab_kid;                // ZeroSSL External Account Binding Key ID
    std::string acme_eab_hmac_key;           // ZeroSSL EAB HMAC key (base64url)
    std::string dns_provider{"local"};       // "local" = self-hosted authoritative DNS, "cloudflare" = API fallback

    // Server hostname (used for ACME TLS cert: <hostname>.srv.<dns_base_domain>)
    std::string server_hostname;             // e.g. "central" -> "central.srv.lemonade-nexus.io"
    bool        auto_tls{true};              // automatically request TLS cert via ACME on startup

    // DNS resolution
    std::string dns_base_domain{"lemonade-nexus.io"};
    std::string dns_ns_hostname;            // this server's NS hostname (e.g. "ns1.lemonade-nexus.io")
    bool        dns_seed_discovery{true};   // auto-discover seed peers from tier/region DNS records on startup

    // Binary attestation
    std::string release_signing_pubkey;       // base64 Ed25519 pubkey for release manifest verification
    bool require_binary_attestation{false};   // require matching manifest for credential distribution

    // GitHub release manifest fetching (auto-fetch signed manifests for older versions)
    std::string github_releases_url;              // e.g. "https://api.github.com/repos/owner/repo/releases"
    uint32_t    manifest_fetch_interval_sec{3600}; // how often to check GitHub (default 1 hour)
    std::string minimum_version;                   // optional semver floor, e.g. "1.2.0"

    // Dynamic DNS (Namecheap)
    std::string ddns_domain;                  // base domain, e.g. "example.com"
    std::string ddns_password;                // Namecheap DDNS password (root server only)
    uint32_t    ddns_update_interval_sec{300};
    bool        ddns_enabled{false};

    // First-run CLI mode: initialize the data directory (identity + gossip
    // keypairs), print onboarding info (pubkeys, node ID, next steps), and exit.
    bool        first_run{false};

    // Enrollment CLI mode (non-empty = run enrollment and exit)
    std::string enroll_server_pubkey;
    std::string enroll_server_id;
    std::string enroll_tpm_ak_pubkey;  // base64 DER SPKI AK to pin in the cert (Model A)
    std::string enroll_tpm_ek_cert_path; // optional path to the joining TPM's EK cert (PEM)
    std::string revoke_server_pubkey;
    bool        print_tpm_ak{false};   // print this host's TPM AK pubkey (base64 DER SPKI) and exit

    // Manifest CLI mode
    std::string add_manifest_path;  // path to a release manifest JSON to import

    // Runtime-only: path the config was loaded from (not persisted to JSON).
    std::string config_path{"lemonade-nexus.json"};

    // Onboarding — candidate side (--onboard-server [host:port])
    bool        onboard_server{false};       // run the onboarding client and exit
    std::string onboard_target;              // optional "host:port" of a mesh server (else DNS discovery)
    std::string onboard_server_id;           // requested DNS label (auto-derived if empty)
    uint32_t    onboard_timeout_sec{900};    // give up waiting for admission after this

    // Onboarding — mesh side
    bool        onboard_enabled{true};             // accept onboarding requests when we hold the root key
    bool        onboard_auto_approve_bootstrap{true}; // auto-approve until the first admission is approved
    float       admission_quorum_ratio{0.75f};     // Tier1 vote fraction for admission ballots
    uint32_t    onboard_min_tier1_for_vote{6};     // switch from sole-discretion to voting at this many Tier1s
    uint32_t    onboard_request_ttl_sec{3600};     // pending admission lifetime
    uint32_t    onboard_max_pending{8};            // cap on concurrent pending admissions

    // Private API (dual-server mode — auto-enabled once tunnel IP is allocated)
    uint16_t    private_http_port{9101};     // Private API port (VPN-only)

    // Quorum-based enrollment
    bool     require_peer_confirmation{false};    // require Tier1 peer votes before full admission
    float    enrollment_quorum_ratio{0.5f};       // fraction of Tier1 peers needed (default 50%)
    uint32_t enrollment_vote_timeout_sec{60};     // vote collection window (seconds)
    uint32_t enrollment_max_retries{3};           // retries before permanent rejection

    // TEE Attestation / Trust
    bool require_tee_attestation{false};      // require Tier 1 TEE for full mesh participation
    uint32_t tee_attestation_validity_sec{3600};  // how long a TEE report is valid (default 1h)
    std::string tee_platform_override;        // force TEE platform detection ("sgx", "tdx", "sev-snp", "secure-enclave")
};

/// Load config: CLI args > env vars > config file > defaults.
[[nodiscard]] ServerConfig load_config(int argc, char* argv[]);

/// Validate and log errors. Returns false if config is fatally invalid.
[[nodiscard]] bool validate_config(const ServerConfig& config);

/// Print usage/help text.
void print_usage(const char* prog);

void to_json(nlohmann::json& j, const ServerConfig& c);
void from_json(const nlohmann::json& j, ServerConfig& c);

} // namespace nexus::core
