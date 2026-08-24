#include <LemonadeNexus/Core/ServerConfig.hpp>

#include <spdlog/spdlog.h>

#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <set>

namespace nexus::core {

using json = nlohmann::json;

// ---------------------------------------------------------------------------
// JSON serialization
// ---------------------------------------------------------------------------

void from_json(const json& j, ServerConfig& c) {
    if (j.contains("http_port"))           j.at("http_port").get_to(c.http_port);
    if (j.contains("udp_port"))            j.at("udp_port").get_to(c.udp_port);
    if (j.contains("gossip_port"))         j.at("gossip_port").get_to(c.gossip_port);
    if (j.contains("stun_port"))           j.at("stun_port").get_to(c.stun_port);
    if (j.contains("relay_port"))          j.at("relay_port").get_to(c.relay_port);
    if (j.contains("dns_port"))            j.at("dns_port").get_to(c.dns_port);
    if (j.contains("public_dns_port"))     j.at("public_dns_port").get_to(c.public_dns_port);
    if (j.contains("bind_address"))        j.at("bind_address").get_to(c.bind_address);
    if (j.contains("wg_interface"))        j.at("wg_interface").get_to(c.wg_interface);
    if (j.contains("data_root"))           j.at("data_root").get_to(c.data_root);
    if (j.contains("rp_id"))               j.at("rp_id").get_to(c.rp_id);
    if (j.contains("jwt_secret"))          j.at("jwt_secret").get_to(c.jwt_secret);
    if (j.contains("root_pubkey"))         j.at("root_pubkey").get_to(c.root_pubkey);
    if (j.contains("genesis_pubkey"))      j.at("genesis_pubkey").get_to(c.genesis_pubkey);
    if (j.contains("seed_peers"))          j.at("seed_peers").get_to(c.seed_peers);
    if (j.contains("rate_limit_rpm"))      j.at("rate_limit_rpm").get_to(c.rate_limit_rpm);
    if (j.contains("rate_limit_burst"))    j.at("rate_limit_burst").get_to(c.rate_limit_burst);
    if (j.contains("log_level"))           j.at("log_level").get_to(c.log_level);
    if (j.contains("acme_provider"))       j.at("acme_provider").get_to(c.acme_provider);
    if (j.contains("acme_eab_kid"))        j.at("acme_eab_kid").get_to(c.acme_eab_kid);
    if (j.contains("acme_eab_hmac_key"))   j.at("acme_eab_hmac_key").get_to(c.acme_eab_hmac_key);
    if (j.contains("dns_provider"))        j.at("dns_provider").get_to(c.dns_provider);
    if (j.contains("public_ip"))           j.at("public_ip").get_to(c.public_ip);
    if (j.contains("region"))              j.at("region").get_to(c.region);
    if (j.contains("server_hostname"))     j.at("server_hostname").get_to(c.server_hostname);
    if (j.contains("dns_base_domain"))     j.at("dns_base_domain").get_to(c.dns_base_domain);
    if (j.contains("dns_seed_discovery"))  j.at("dns_seed_discovery").get_to(c.dns_seed_discovery);
    if (j.contains("dns_ns_hostname"))     j.at("dns_ns_hostname").get_to(c.dns_ns_hostname);
    if (j.contains("release_signing_pubkey"))     j.at("release_signing_pubkey").get_to(c.release_signing_pubkey);
    if (j.contains("github_releases_url"))        j.at("github_releases_url").get_to(c.github_releases_url);
    if (j.contains("manifest_fetch_interval_sec")) j.at("manifest_fetch_interval_sec").get_to(c.manifest_fetch_interval_sec);
    if (j.contains("minimum_version"))            j.at("minimum_version").get_to(c.minimum_version);
    if (j.contains("ddns_domain"))                j.at("ddns_domain").get_to(c.ddns_domain);
    if (j.contains("ddns_password"))              j.at("ddns_password").get_to(c.ddns_password);
    if (j.contains("ddns_update_interval_sec"))   j.at("ddns_update_interval_sec").get_to(c.ddns_update_interval_sec);
    if (j.contains("ddns_enabled"))               j.at("ddns_enabled").get_to(c.ddns_enabled);
    if (j.contains("open_registration"))          j.at("open_registration").get_to(c.open_registration);
    if (j.contains("private_http_port"))          j.at("private_http_port").get_to(c.private_http_port);
    if (j.contains("onboard_enabled"))           j.at("onboard_enabled").get_to(c.onboard_enabled);
    if (j.contains("onboard_request_ttl_sec"))   j.at("onboard_request_ttl_sec").get_to(c.onboard_request_ttl_sec);
    if (j.contains("onboard_max_pending"))       j.at("onboard_max_pending").get_to(c.onboard_max_pending);
}

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------

void print_usage(const char* prog) {
    spdlog::info("Usage: {} [OPTIONS]", prog);
    spdlog::info("");
    spdlog::info("Options:");
    spdlog::info("  --config <path>            JSON config file (default: lemonade-nexus.json)");
    spdlog::info("  --http-port <N>            HTTP port (default: 9100)");
    spdlog::info("  --udp-port <N>             mesh + hole-punch UDP port (default: 51940)");
    spdlog::info("  --gossip-port <N>          Gossip protocol UDP port (default: 9102)");
    spdlog::info("  --stun-port <N>            STUN UDP port (default: 3478)");
    spdlog::info("  --relay-port <N>           Relay UDP port (default: 9103)");
    spdlog::info("  --bind-address <addr>      Bind address for all services (default: 0.0.0.0)");
    spdlog::info("  --public-ip <addr>         Public IP to advertise in DNS (default: auto-detect)");
    spdlog::info("  --wg-interface <name>      boringtun interface (default: nexus0). NEVER use 'wg0' or anything in use.");
    spdlog::info("  --data-root <path>         Data directory (default: data)");
    spdlog::info("  --log-level <level>        Log level: trace/debug/info/warn/error");
    spdlog::info("  --seed-peer <host:port>    Add a gossip seed peer (repeatable)");
    spdlog::info("  --root-pubkey <hex>        Root management Ed25519 public key (hex)");
    spdlog::info("  --genesis-pubkey <b64>     Pinned Genesis bootstrap anchor (base64 Ed25519); its authority ends at Epoch 1 activation");
    spdlog::info("  --rp-id <domain>           Relying party ID for WebAuthn (default: lemonade-nexus.local)");
    spdlog::info("  --first-run                Initialize the data directory (identity + gossip keys), print onboarding info, exit");
    spdlog::info("  --onboard-server [fqdn:port] Join an existing mesh: request admission over its public API (verified HTTPS by FQDN), then exit (requires --root-pubkey)");
    spdlog::info("  --onboard-addr <ip>        Pin the connect IP while still verifying --onboard-server's cert FQDN (e.g. local dev where the FQDN maps to 127.0.0.1)");
    spdlog::info("  --onboard-id <label>       Requested server ID for onboarding (default: auto-derived)");
    spdlog::info("  --onboard-token <tok>      Single-use enrollment token for immediate admission (or SP_ONBOARD_TOKEN)");
    spdlog::info("  --mint-admission-token     Mint a server-admission enrollment token and exit (root holder only)");
    spdlog::info("  --token-candidate <b64>    Required with --mint-admission-token: joining server's gossip pubkey (base64) the token is bound to");
    spdlog::info("  --token-ttl <sec>          Minted-token lifetime, 60-3600s (default: 600)");
    spdlog::info("  --no-onboard               Refuse to accept onboarding requests from new servers");
    spdlog::info("  --enroll-server <b64> <id> Enroll a server: sign cert for its base64 gossip pubkey; <id> is a unique DNS label");
    spdlog::info("  --enroll-tpm-ak <b64>      Pin the server's platform binding key (base64 DER SPKI) in the cert");
    spdlog::info("  --enroll-tpm-ek-cert <path> Attach the server's TPM EK cert (PEM) for audit/validation");
    spdlog::info("  --verify-platform [blob]   Verify this host's platform evidence (AMD signature chain,");
    spdlog::info("                             guest policy, memory-encryption guarantees) and exit.");
    spdlog::info("                             Optionally verify a captured HCL blob file instead.");
    spdlog::info("  --revoke-server <b64>      Revoke a server by its base64 gossip pubkey");
    spdlog::info("  --add-manifest <path>      Import a signed release manifest JSON");
    spdlog::info("  --ddns-domain <domain>     Base domain for DDNS (e.g. example.com)");
    spdlog::info("  --ddns-password <pass>     Namecheap DDNS password");
    spdlog::info("  --ddns-enabled             Enable dynamic DNS updates");
    spdlog::info("  --release-signing-pubkey <b64>  Release signing pubkey (base64 Ed25519)");
    spdlog::info("  --github-releases-url <url>  GitHub API URL for fetching release manifests");
    spdlog::info("  --manifest-fetch-interval <sec>  How often to fetch manifests (default 3600)");
    spdlog::info("  --minimum-version <semver>   Minimum binary version allowed (e.g. 1.2.0)");
    spdlog::info("  --private-http-port <N>      Private API port (default: 9101)");
    spdlog::info("  --require-peer-confirmation  Require peer quorum before full enrollment");
    spdlog::info("  --dns-port <N>             Internal DNS listen port (default: 5335, NAT-mapped from public)");
    spdlog::info("  --public-dns-port <N>      DNS port advertised to clients (default: 53)");
    spdlog::info("  --dns-base-domain <dom>    DNS zone suffix (default: lemonade-nexus.io)");
    spdlog::info("  --no-dns-seed-discovery    Disable auto-discovery of seed peers from tier/region DNS");
    spdlog::info("  --dns-provider <name>      DNS provider: 'local' (default) or 'cloudflare'");
    spdlog::info("  --dns-ns-hostname <fqdn>   This server's NS hostname (e.g. ns1.example.com)");
    spdlog::info("  --server-hostname <name>   Server hostname for TLS cert (auto-generated from region if omitted)");
    spdlog::info("  --acme-provider <name>     ACME CA provider: letsencrypt (default), letsencrypt_staging, zerossl");
    spdlog::info("  --acme-eab-kid <kid>       ZeroSSL EAB Key ID");
    spdlog::info("  --acme-eab-hmac-key <key>  ZeroSSL EAB HMAC key (base64url)");
    spdlog::info("  --closed-registration      New identities must present a device link token to join");
    spdlog::info("  --region <code>            Cloud region (e.g. us-east, eu-west; auto-detected if omitted)");
    spdlog::info("  --help, -h                 Show this help");
}

// ---------------------------------------------------------------------------
// Load config
// ---------------------------------------------------------------------------

ServerConfig load_config(int argc, char* argv[]) {
    ServerConfig config;
    std::string config_path = "lemonade-nexus.json";

    // --- Pass 1: find --config path ---
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            config_path = argv[++i];
        }
    }

    // --- Load JSON config file ---
    if (std::filesystem::exists(config_path)) {
        try {
            std::ifstream f(config_path);
            auto j = json::parse(f);
            config = j.get<ServerConfig>();
            spdlog::info("Loaded config from {}", config_path);
        } catch (const std::exception& e) {
            spdlog::warn("Failed to parse config {}: {}", config_path, e.what());
        }
    }
    config.config_path = config_path;  // remembered for onboarding write-back

    // --- Pass 2: CLI overrides ---
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0) {
            print_usage(argv[0]);
            std::exit(0);
        } else if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
            ++i; // already handled
        } else if (std::strcmp(argv[i], "--http-port") == 0 && i + 1 < argc) {
            config.http_port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--udp-port") == 0 && i + 1 < argc) {
            config.udp_port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--gossip-port") == 0 && i + 1 < argc) {
            config.gossip_port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--stun-port") == 0 && i + 1 < argc) {
            config.stun_port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--relay-port") == 0 && i + 1 < argc) {
            config.relay_port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--bind-address") == 0 && i + 1 < argc) {
            config.bind_address = argv[++i];
        } else if (std::strcmp(argv[i], "--public-ip") == 0 && i + 1 < argc) {
            config.public_ip = argv[++i];
        } else if (std::strcmp(argv[i], "--wg-interface") == 0 && i + 1 < argc) {
            config.wg_interface = argv[++i];
        } else if (std::strcmp(argv[i], "--data-root") == 0 && i + 1 < argc) {
            config.data_root = argv[++i];
        } else if (std::strcmp(argv[i], "--log-level") == 0 && i + 1 < argc) {
            config.log_level = argv[++i];
        } else if (std::strcmp(argv[i], "--seed-peer") == 0 && i + 1 < argc) {
            config.seed_peers.push_back(argv[++i]);
        } else if (std::strcmp(argv[i], "--root-pubkey") == 0 && i + 1 < argc) {
            config.root_pubkey = argv[++i];
        } else if (std::strcmp(argv[i], "--genesis-pubkey") == 0 && i + 1 < argc) {
            config.genesis_pubkey = argv[++i];
        } else if (std::strcmp(argv[i], "--rp-id") == 0 && i + 1 < argc) {
            config.rp_id = argv[++i];
        } else if (std::strcmp(argv[i], "--enroll-server") == 0 && i + 2 < argc) {
            config.enroll_server_pubkey = argv[++i];
            config.enroll_server_id     = argv[++i];
        } else if (std::strcmp(argv[i], "--enroll-tpm-ak") == 0 && i + 1 < argc) {
            config.enroll_tpm_ak_pubkey = argv[++i];
        } else if (std::strcmp(argv[i], "--enroll-tpm-ek-cert") == 0 && i + 1 < argc) {
            config.enroll_tpm_ek_cert_path = argv[++i];
        } else if (std::strcmp(argv[i], "--first-run") == 0) {
            config.first_run = true;
        } else if (std::strcmp(argv[i], "--verify-platform") == 0) {
            config.verify_platform = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') config.verify_platform_blob = argv[++i];
        } else if (std::strcmp(argv[i], "--revoke-server") == 0 && i + 1 < argc) {
            config.revoke_server_pubkey = argv[++i];
        } else if (std::strcmp(argv[i], "--add-manifest") == 0 && i + 1 < argc) {
            config.add_manifest_path = argv[++i];
        } else if (std::strcmp(argv[i], "--ddns-domain") == 0 && i + 1 < argc) {
            config.ddns_domain = argv[++i];
        } else if (std::strcmp(argv[i], "--ddns-password") == 0 && i + 1 < argc) {
            config.ddns_password = argv[++i];
        } else if (std::strcmp(argv[i], "--ddns-enabled") == 0) {
            config.ddns_enabled = true;
        } else if (std::strcmp(argv[i], "--release-signing-pubkey") == 0 && i + 1 < argc) {
            config.release_signing_pubkey = argv[++i];
        } else if (std::strcmp(argv[i], "--github-releases-url") == 0 && i + 1 < argc) {
            config.github_releases_url = argv[++i];
        } else if (std::strcmp(argv[i], "--manifest-fetch-interval") == 0 && i + 1 < argc) {
            config.manifest_fetch_interval_sec = static_cast<uint32_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--minimum-version") == 0 && i + 1 < argc) {
            config.minimum_version = argv[++i];
        } else if (std::strcmp(argv[i], "--private-http-port") == 0 && i + 1 < argc) {
            config.private_http_port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--onboard-server") == 0) {
            config.onboard_server = true;
            // Optional positional target ("<fqdn>[:port]"); anything starting with '-' is a flag.
            if (i + 1 < argc && argv[i + 1][0] != '-') config.onboard_target = argv[++i];
        } else if (std::strcmp(argv[i], "--onboard-addr") == 0 && i + 1 < argc) {
            config.onboard_addr = argv[++i];
        } else if (std::strcmp(argv[i], "--onboard-id") == 0 && i + 1 < argc) {
            config.onboard_server_id = argv[++i];
        } else if (std::strcmp(argv[i], "--onboard-timeout") == 0 && i + 1 < argc) {
            config.onboard_timeout_sec = static_cast<uint32_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--onboard-token") == 0 && i + 1 < argc) {
            config.onboard_token = argv[++i];
        } else if (std::strcmp(argv[i], "--mint-admission-token") == 0) {
            config.mint_admission_token = true;
        } else if (std::strcmp(argv[i], "--token-candidate") == 0 && i + 1 < argc) {
            config.mint_token_candidate = argv[++i];
        } else if (std::strcmp(argv[i], "--token-ttl") == 0 && i + 1 < argc) {
            config.mint_token_ttl_sec = static_cast<uint32_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--no-onboard") == 0) {
            config.onboard_enabled = false;
        } else if (std::strcmp(argv[i], "--dns-port") == 0 && i + 1 < argc) {
            config.dns_port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--public-dns-port") == 0 && i + 1 < argc) {
            config.public_dns_port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--dns-base-domain") == 0 && i + 1 < argc) {
            config.dns_base_domain = argv[++i];
        } else if (std::strcmp(argv[i], "--no-dns-seed-discovery") == 0) {
            config.dns_seed_discovery = false;
        } else if (std::strcmp(argv[i], "--dns-provider") == 0 && i + 1 < argc) {
            config.dns_provider = argv[++i];
        } else if (std::strcmp(argv[i], "--dns-ns-hostname") == 0 && i + 1 < argc) {
            config.dns_ns_hostname = argv[++i];
        } else if (std::strcmp(argv[i], "--server-hostname") == 0 && i + 1 < argc) {
            config.server_hostname = argv[++i];
        } else if (std::strcmp(argv[i], "--acme-provider") == 0 && i + 1 < argc) {
            config.acme_provider = argv[++i];
        } else if (std::strcmp(argv[i], "--acme-eab-kid") == 0 && i + 1 < argc) {
            config.acme_eab_kid = argv[++i];
        } else if (std::strcmp(argv[i], "--acme-eab-hmac-key") == 0 && i + 1 < argc) {
            config.acme_eab_hmac_key = argv[++i];
        } else if (std::strcmp(argv[i], "--closed-registration") == 0) {
            config.open_registration = false;
        } else if (std::strcmp(argv[i], "--region") == 0 && i + 1 < argc) {
            config.region = argv[++i];
        }
    }

    // --- Pass 3: environment variable overrides ---
    if (const char* v = std::getenv("SP_LOG_LEVEL"))   config.log_level   = v;
    if (const char* v = std::getenv("SP_HTTP_PORT"))    config.http_port   = static_cast<uint16_t>(std::atoi(v));
    if (const char* v = std::getenv("SP_UDP_PORT"))     config.udp_port    = static_cast<uint16_t>(std::atoi(v));
    if (const char* v = std::getenv("SP_GOSSIP_PORT"))  config.gossip_port = static_cast<uint16_t>(std::atoi(v));
    if (const char* v = std::getenv("SP_STUN_PORT"))    config.stun_port   = static_cast<uint16_t>(std::atoi(v));
    if (const char* v = std::getenv("SP_RELAY_PORT"))   config.relay_port  = static_cast<uint16_t>(std::atoi(v));
    if (const char* v = std::getenv("SP_BIND_ADDRESS")) config.bind_address = v;
    if (const char* v = std::getenv("SP_WG_INTERFACE")) config.wg_interface = v;
    if (const char* v = std::getenv("SP_PUBLIC_IP"))    config.public_ip    = v;
    if (const char* v = std::getenv("SP_DATA_ROOT"))    config.data_root   = v;
    if (const char* v = std::getenv("SP_ROOT_PUBKEY"))  config.root_pubkey = v;
    if (const char* v = std::getenv("SP_GENESIS_PUBKEY")) config.genesis_pubkey = v;
    if (const char* v = std::getenv("SP_ONBOARD_TOKEN")) config.onboard_token = v;
    if (const char* v = std::getenv("SP_JWT_SECRET"))   config.jwt_secret  = v;
    if (const char* v = std::getenv("SP_RP_ID"))          config.rp_id       = v;
    if (const char* v = std::getenv("SP_ACME_PROVIDER"))    config.acme_provider   = v;
    if (const char* v = std::getenv("SP_DNS_PROVIDER"))     config.dns_provider    = v;
    if (const char* v = std::getenv("SP_DNS_PORT"))         config.dns_port        = static_cast<uint16_t>(std::atoi(v));
    if (const char* v = std::getenv("SP_PUBLIC_DNS_PORT"))  config.public_dns_port = static_cast<uint16_t>(std::atoi(v));
    if (const char* v = std::getenv("SP_DNS_BASE_DOMAIN"))  config.dns_base_domain = v;
    if (const char* v = std::getenv("SP_DNS_SEED_DISCOVERY")) {
        std::string s = v;
        config.dns_seed_discovery = !(s == "0" || s == "false" || s == "no");
    }
    if (const char* v = std::getenv("SP_DNS_NS_HOSTNAME")) config.dns_ns_hostname = v;
    if (const char* v = std::getenv("SP_RELEASE_SIGNING_PUBKEY")) config.release_signing_pubkey = v;
    if (const char* v = std::getenv("SP_DDNS_DOMAIN"))    config.ddns_domain   = v;
    if (const char* v = std::getenv("SP_DDNS_PASSWORD"))  config.ddns_password = v;
    if (std::getenv("SP_DDNS_ENABLED"))                   config.ddns_enabled  = true;
    if (const char* v = std::getenv("SP_GITHUB_RELEASES_URL"))  config.github_releases_url       = v;
    if (const char* v = std::getenv("SP_MANIFEST_FETCH_INTERVAL")) config.manifest_fetch_interval_sec = static_cast<uint32_t>(std::atoi(v));
    if (const char* v = std::getenv("SP_MINIMUM_VERSION"))      config.minimum_version           = v;
    if (const char* v = std::getenv("SP_PRIVATE_HTTP_PORT")) config.private_http_port = static_cast<uint16_t>(std::atoi(v));
    if (const char* v = std::getenv("SP_REGION"))        config.region                    = v;
    if (const char* v = std::getenv("SP_SERVER_HOSTNAME"))    config.server_hostname       = v;
    if (const char* v = std::getenv("SP_ACME_EAB_KID"))       config.acme_eab_kid          = v;
    if (const char* v = std::getenv("SP_ACME_EAB_HMAC_KEY"))  config.acme_eab_hmac_key     = v;
    if (std::getenv("SP_CLOSED_REGISTRATION"))           config.open_registration     = false;

    if (const char* v = std::getenv("SP_SEED_PEERS")) {
        // Comma-separated list
        std::string peers_str = v;
        std::string::size_type start = 0;
        while (start < peers_str.size()) {
            auto end = peers_str.find(',', start);
            if (end == std::string::npos) end = peers_str.size();
            auto peer = peers_str.substr(start, end - start);
            if (!peer.empty()) config.seed_peers.push_back(peer);
            start = end + 1;
        }
    }

    return config;
}

// ---------------------------------------------------------------------------
// Validate
// ---------------------------------------------------------------------------

bool validate_config(const ServerConfig& config) {
    bool valid = true;

    // Check ports are non-zero
    auto check_port = [&](uint16_t port, const char* name) {
        if (port == 0) {
            spdlog::error("Config: {} cannot be 0", name);
            valid = false;
        }
    };
    check_port(config.http_port, "http_port");
    check_port(config.udp_port, "udp_port");
    check_port(config.gossip_port, "gossip_port");
    check_port(config.stun_port, "stun_port");
    check_port(config.relay_port, "relay_port");
    check_port(config.dns_port, "dns_port");
    // public_dns_port is the externally-advertised (NAT-mapped) DNS port, not a local
    // listener — validate it's non-zero but exclude it from the internal-uniqueness set.
    check_port(config.public_dns_port, "public_dns_port");

    // Check ports are unique
    std::set<uint16_t> ports = {
        config.http_port, config.udp_port, config.gossip_port,
        config.stun_port, config.relay_port, config.dns_port
    };
    if (ports.size() < 6) {
        spdlog::error("Config: port conflict — all 6 ports must be unique");
        valid = false;
    }

    // Validate private API port (used automatically once tunnel IP is allocated)
    check_port(config.private_http_port, "private_http_port");
    if (ports.contains(config.private_http_port)) {
        spdlog::error("Config: private_http_port {} conflicts with another port", config.private_http_port);
        valid = false;
    }

    // Check data root (created by --first-run, not here — a plain start against
    // a missing data dir must be able to fail cleanly without side effects)
    if (config.data_root.empty()) {
        spdlog::error("Config: data_root cannot be empty");
        valid = false;
    }


    // Trust anchors are mandatory for a normal server start. Both used to be
    // warnings, and both are now load-bearing: without root_pubkey no certificate
    // can be verified (verify_server_certificate fails closed), and without
    // release_signing_pubkey no release manifest can be authenticated, so no binary
    // can ever be approved. A server missing either can never reach Tier 1 — say so
    // at startup instead of running in a permanently degraded state.
    //
    // CLI modes are exempt: --first-run generates the identity these anchor to, and
    // the enroll/onboard/manifest modes exit before any of it is used.
    const bool cli_mode = config.first_run || config.verify_platform ||
                          config.onboard_server ||
                          config.mint_admission_token || !config.enroll_server_pubkey.empty() ||
                          !config.revoke_server_pubkey.empty() || !config.add_manifest_path.empty();

    if (!cli_mode) {
        if (config.root_pubkey.empty()) {
            spdlog::error("Config: root_pubkey is required — without it no server certificate "
                           "can be verified and no peer can be trusted");
            valid = false;
        }
        if (config.release_signing_pubkey.empty()) {
            spdlog::error("Config: release_signing_pubkey is required — without it no release "
                           "manifest can be authenticated, so no binary can be approved and "
                           "this server can never reach Tier 1");
            valid = false;
        }
    }

    if (config.seed_peers.empty()) {
        spdlog::warn("Config: no seed_peers — this server won't gossip until peers are added");
    }

    if (config.rp_id.empty()) {
        spdlog::warn("Config: rp_id is empty — WebAuthn passkeys will not validate");
    }

    spdlog::info("Config: HTTP:{} UDP/WG:{} Gossip:{} STUN:{} Relay:{} DNS:{} data={}",
                  config.http_port, config.udp_port, config.gossip_port,
                  config.stun_port, config.relay_port, config.dns_port,
                  config.data_root);

    return valid;
}

} // namespace nexus::core
