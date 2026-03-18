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

void to_json(json& j, const ServerConfig& c) {
    j = json{
        {"http_port",           c.http_port},
        {"udp_port",            c.udp_port},
        {"wg_port",             c.wg_port},
        {"gossip_port",         c.gossip_port},
        {"stun_port",           c.stun_port},
        {"relay_port",          c.relay_port},
        {"dns_port",            c.dns_port},
        {"bind_address",        c.bind_address},
        {"data_root",           c.data_root},
        {"rp_id",               c.rp_id},
        {"jwt_secret",          c.jwt_secret},
        {"root_pubkey",         c.root_pubkey},
        {"seed_peers",          c.seed_peers},
        {"gossip_interval_sec", c.gossip_interval_sec},
        {"rate_limit_rpm",      c.rate_limit_rpm},
        {"rate_limit_burst",    c.rate_limit_burst},
        {"log_level",           c.log_level},
        {"tls_cert_path",       c.tls_cert_path},
        {"tls_key_path",        c.tls_key_path},
        {"acme_provider",       c.acme_provider},
        {"acme_eab_kid",        c.acme_eab_kid},
        {"acme_eab_hmac_key",   c.acme_eab_hmac_key},
        {"dns_provider",        c.dns_provider},
        {"public_ip",           c.public_ip},
        {"server_hostname",     c.server_hostname},
        {"auto_tls",            c.auto_tls},
        {"dns_base_domain",     c.dns_base_domain},
        {"dns_ns_hostname",     c.dns_ns_hostname},
        {"release_signing_pubkey",     c.release_signing_pubkey},
        {"require_binary_attestation", c.require_binary_attestation},
        {"github_releases_url",        c.github_releases_url},
        {"manifest_fetch_interval_sec", c.manifest_fetch_interval_sec},
        {"minimum_version",            c.minimum_version},
        {"ddns_domain",                c.ddns_domain},
        {"ddns_password",              c.ddns_password},
        {"ddns_update_interval_sec",   c.ddns_update_interval_sec},
        {"ddns_enabled",               c.ddns_enabled},
        {"private_http_port",          c.private_http_port},
        {"require_peer_confirmation",  c.require_peer_confirmation},
        {"enrollment_quorum_ratio",    c.enrollment_quorum_ratio},
        {"enrollment_vote_timeout_sec", c.enrollment_vote_timeout_sec},
        {"enrollment_max_retries",     c.enrollment_max_retries},
        {"require_tee_attestation",    c.require_tee_attestation},
        {"tee_attestation_validity_sec", c.tee_attestation_validity_sec},
        {"tee_platform_override",      c.tee_platform_override},
    };
}

void from_json(const json& j, ServerConfig& c) {
    if (j.contains("http_port"))           j.at("http_port").get_to(c.http_port);
    if (j.contains("udp_port"))            j.at("udp_port").get_to(c.udp_port);
    if (j.contains("wg_port"))             j.at("wg_port").get_to(c.wg_port);
    if (j.contains("gossip_port"))         j.at("gossip_port").get_to(c.gossip_port);
    if (j.contains("stun_port"))           j.at("stun_port").get_to(c.stun_port);
    if (j.contains("relay_port"))          j.at("relay_port").get_to(c.relay_port);
    if (j.contains("dns_port"))            j.at("dns_port").get_to(c.dns_port);
    if (j.contains("bind_address"))        j.at("bind_address").get_to(c.bind_address);
    if (j.contains("data_root"))           j.at("data_root").get_to(c.data_root);
    if (j.contains("rp_id"))               j.at("rp_id").get_to(c.rp_id);
    if (j.contains("jwt_secret"))          j.at("jwt_secret").get_to(c.jwt_secret);
    if (j.contains("root_pubkey"))         j.at("root_pubkey").get_to(c.root_pubkey);
    if (j.contains("seed_peers"))          j.at("seed_peers").get_to(c.seed_peers);
    if (j.contains("gossip_interval_sec")) j.at("gossip_interval_sec").get_to(c.gossip_interval_sec);
    if (j.contains("rate_limit_rpm"))      j.at("rate_limit_rpm").get_to(c.rate_limit_rpm);
    if (j.contains("rate_limit_burst"))    j.at("rate_limit_burst").get_to(c.rate_limit_burst);
    if (j.contains("log_level"))           j.at("log_level").get_to(c.log_level);
    if (j.contains("tls_cert_path"))       j.at("tls_cert_path").get_to(c.tls_cert_path);
    if (j.contains("tls_key_path"))        j.at("tls_key_path").get_to(c.tls_key_path);
    if (j.contains("acme_provider"))       j.at("acme_provider").get_to(c.acme_provider);
    if (j.contains("acme_eab_kid"))        j.at("acme_eab_kid").get_to(c.acme_eab_kid);
    if (j.contains("acme_eab_hmac_key"))   j.at("acme_eab_hmac_key").get_to(c.acme_eab_hmac_key);
    if (j.contains("dns_provider"))        j.at("dns_provider").get_to(c.dns_provider);
    if (j.contains("public_ip"))           j.at("public_ip").get_to(c.public_ip);
    if (j.contains("server_hostname"))     j.at("server_hostname").get_to(c.server_hostname);
    if (j.contains("auto_tls"))            j.at("auto_tls").get_to(c.auto_tls);
    if (j.contains("dns_base_domain"))     j.at("dns_base_domain").get_to(c.dns_base_domain);
    if (j.contains("dns_ns_hostname"))     j.at("dns_ns_hostname").get_to(c.dns_ns_hostname);
    if (j.contains("release_signing_pubkey"))     j.at("release_signing_pubkey").get_to(c.release_signing_pubkey);
    if (j.contains("require_binary_attestation")) j.at("require_binary_attestation").get_to(c.require_binary_attestation);
    if (j.contains("github_releases_url"))        j.at("github_releases_url").get_to(c.github_releases_url);
    if (j.contains("manifest_fetch_interval_sec")) j.at("manifest_fetch_interval_sec").get_to(c.manifest_fetch_interval_sec);
    if (j.contains("minimum_version"))            j.at("minimum_version").get_to(c.minimum_version);
    if (j.contains("ddns_domain"))                j.at("ddns_domain").get_to(c.ddns_domain);
    if (j.contains("ddns_password"))              j.at("ddns_password").get_to(c.ddns_password);
    if (j.contains("ddns_update_interval_sec"))   j.at("ddns_update_interval_sec").get_to(c.ddns_update_interval_sec);
    if (j.contains("ddns_enabled"))               j.at("ddns_enabled").get_to(c.ddns_enabled);
    if (j.contains("private_http_port"))          j.at("private_http_port").get_to(c.private_http_port);
    if (j.contains("require_peer_confirmation"))  j.at("require_peer_confirmation").get_to(c.require_peer_confirmation);
    if (j.contains("enrollment_quorum_ratio"))  j.at("enrollment_quorum_ratio").get_to(c.enrollment_quorum_ratio);
    if (j.contains("enrollment_vote_timeout_sec")) j.at("enrollment_vote_timeout_sec").get_to(c.enrollment_vote_timeout_sec);
    if (j.contains("enrollment_max_retries"))   j.at("enrollment_max_retries").get_to(c.enrollment_max_retries);
    if (j.contains("require_tee_attestation"))   j.at("require_tee_attestation").get_to(c.require_tee_attestation);
    if (j.contains("tee_attestation_validity_sec")) j.at("tee_attestation_validity_sec").get_to(c.tee_attestation_validity_sec);
    if (j.contains("tee_platform_override"))     j.at("tee_platform_override").get_to(c.tee_platform_override);
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
    spdlog::info("  --udp-port <N>             UDP hole-punch port (default: 51940)");
    spdlog::info("  --wg-port <N>              WireGuard listen port (default: 51820)");
    spdlog::info("  --gossip-port <N>          Gossip protocol UDP port (default: 9102)");
    spdlog::info("  --stun-port <N>            STUN UDP port (default: 3478)");
    spdlog::info("  --relay-port <N>           Relay UDP port (default: 9103)");
    spdlog::info("  --bind-address <addr>      Bind address for all services (default: 0.0.0.0)");
    spdlog::info("  --data-root <path>         Data directory (default: data)");
    spdlog::info("  --log-level <level>        Log level: trace/debug/info/warn/error");
    spdlog::info("  --seed-peer <host:port>    Add a gossip seed peer (repeatable)");
    spdlog::info("  --root-pubkey <hex>        Root management Ed25519 public key (hex)");
    spdlog::info("  --rp-id <domain>           Relying party ID for WebAuthn (default: lemonade-nexus.local)");
    spdlog::info("  --enroll-server <hex> <id> Enroll a server: sign cert for pubkey with given ID");
    spdlog::info("  --revoke-server <hex>      Revoke a server by its pubkey");
    spdlog::info("  --add-manifest <path>      Import a signed release manifest JSON");
    spdlog::info("  --ddns-domain <domain>     Base domain for DDNS (e.g. example.com)");
    spdlog::info("  --ddns-password <pass>     Namecheap DDNS password");
    spdlog::info("  --ddns-enabled             Enable dynamic DNS updates");
    spdlog::info("  --release-signing-pubkey <b64>  Release signing pubkey (base64 Ed25519)");
    spdlog::info("  --require-attestation      Require binary attestation for credential distribution");
    spdlog::info("  --github-releases-url <url>  GitHub API URL for fetching release manifests");
    spdlog::info("  --manifest-fetch-interval <sec>  How often to fetch manifests (default 3600)");
    spdlog::info("  --minimum-version <semver>   Minimum binary version allowed (e.g. 1.2.0)");
    spdlog::info("  --private-http-port <N>      Private API port (default: 9101)");
    spdlog::info("  --require-peer-confirmation  Require peer quorum before full enrollment");
    spdlog::info("  --enrollment-quorum <ratio>  Fraction of Tier1 peers needed (default 0.5)");
    spdlog::info("  --dns-port <N>             Authoritative DNS port (default: 53)");
    spdlog::info("  --dns-base-domain <dom>    DNS zone suffix (default: lemonade-nexus.io)");
    spdlog::info("  --dns-provider <name>      DNS provider: 'local' (default) or 'cloudflare'");
    spdlog::info("  --dns-ns-hostname <fqdn>   This server's NS hostname (e.g. ns1.example.com)");
    spdlog::info("  --server-hostname <name>   Server hostname for TLS cert (auto-generated from region if omitted)");
    spdlog::info("  --acme-provider <name>     ACME CA provider: letsencrypt (default), letsencrypt_staging, zerossl");
    spdlog::info("  --acme-eab-kid <kid>       ZeroSSL EAB Key ID");
    spdlog::info("  --acme-eab-hmac-key <key>  ZeroSSL EAB HMAC key (base64url)");
    spdlog::info("  --tls-cert-path <path>     Path to TLS certificate PEM (manual override)");
    spdlog::info("  --tls-key-path <path>      Path to TLS private key PEM (manual override)");
    spdlog::info("  --no-auto-tls              Disable automatic TLS certificate via ACME");
    spdlog::info("  --require-tee              Require TEE hardware attestation for Tier 1");
    spdlog::info("  --tee-platform <name>      Override TEE platform detection (sgx/tdx/sev-snp/secure-enclave)");
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
        } else if (std::strcmp(argv[i], "--wg-port") == 0 && i + 1 < argc) {
            config.wg_port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--gossip-port") == 0 && i + 1 < argc) {
            config.gossip_port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--stun-port") == 0 && i + 1 < argc) {
            config.stun_port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--relay-port") == 0 && i + 1 < argc) {
            config.relay_port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--bind-address") == 0 && i + 1 < argc) {
            config.bind_address = argv[++i];
        } else if (std::strcmp(argv[i], "--data-root") == 0 && i + 1 < argc) {
            config.data_root = argv[++i];
        } else if (std::strcmp(argv[i], "--log-level") == 0 && i + 1 < argc) {
            config.log_level = argv[++i];
        } else if (std::strcmp(argv[i], "--seed-peer") == 0 && i + 1 < argc) {
            config.seed_peers.push_back(argv[++i]);
        } else if (std::strcmp(argv[i], "--root-pubkey") == 0 && i + 1 < argc) {
            config.root_pubkey = argv[++i];
        } else if (std::strcmp(argv[i], "--rp-id") == 0 && i + 1 < argc) {
            config.rp_id = argv[++i];
        } else if (std::strcmp(argv[i], "--enroll-server") == 0 && i + 2 < argc) {
            config.enroll_server_pubkey = argv[++i];
            config.enroll_server_id     = argv[++i];
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
        } else if (std::strcmp(argv[i], "--require-attestation") == 0) {
            config.require_binary_attestation = true;
        } else if (std::strcmp(argv[i], "--github-releases-url") == 0 && i + 1 < argc) {
            config.github_releases_url = argv[++i];
        } else if (std::strcmp(argv[i], "--manifest-fetch-interval") == 0 && i + 1 < argc) {
            config.manifest_fetch_interval_sec = static_cast<uint32_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--minimum-version") == 0 && i + 1 < argc) {
            config.minimum_version = argv[++i];
        } else if (std::strcmp(argv[i], "--private-http-port") == 0 && i + 1 < argc) {
            config.private_http_port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--require-peer-confirmation") == 0) {
            config.require_peer_confirmation = true;
        } else if (std::strcmp(argv[i], "--enrollment-quorum") == 0 && i + 1 < argc) {
            config.enrollment_quorum_ratio = std::atof(argv[++i]);
        } else if (std::strcmp(argv[i], "--dns-port") == 0 && i + 1 < argc) {
            config.dns_port = static_cast<uint16_t>(std::atoi(argv[++i]));
        } else if (std::strcmp(argv[i], "--dns-base-domain") == 0 && i + 1 < argc) {
            config.dns_base_domain = argv[++i];
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
        } else if (std::strcmp(argv[i], "--no-auto-tls") == 0) {
            config.auto_tls = false;
        } else if (std::strcmp(argv[i], "--tls-cert-path") == 0 && i + 1 < argc) {
            config.tls_cert_path = argv[++i];
        } else if (std::strcmp(argv[i], "--tls-key-path") == 0 && i + 1 < argc) {
            config.tls_key_path = argv[++i];
        } else if (std::strcmp(argv[i], "--require-tee") == 0) {
            config.require_tee_attestation = true;
        } else if (std::strcmp(argv[i], "--tee-platform") == 0 && i + 1 < argc) {
            config.tee_platform_override = argv[++i];
        }
    }

    // --- Pass 3: environment variable overrides ---
    if (const char* v = std::getenv("SP_LOG_LEVEL"))   config.log_level   = v;
    if (const char* v = std::getenv("SP_HTTP_PORT"))    config.http_port   = static_cast<uint16_t>(std::atoi(v));
    if (const char* v = std::getenv("SP_UDP_PORT"))     config.udp_port    = static_cast<uint16_t>(std::atoi(v));
    if (const char* v = std::getenv("SP_WG_PORT"))      config.wg_port     = static_cast<uint16_t>(std::atoi(v));
    if (const char* v = std::getenv("SP_GOSSIP_PORT"))  config.gossip_port = static_cast<uint16_t>(std::atoi(v));
    if (const char* v = std::getenv("SP_STUN_PORT"))    config.stun_port   = static_cast<uint16_t>(std::atoi(v));
    if (const char* v = std::getenv("SP_RELAY_PORT"))   config.relay_port  = static_cast<uint16_t>(std::atoi(v));
    if (const char* v = std::getenv("SP_BIND_ADDRESS")) config.bind_address = v;
    if (const char* v = std::getenv("SP_PUBLIC_IP"))    config.public_ip    = v;
    if (const char* v = std::getenv("SP_DATA_ROOT"))    config.data_root   = v;
    if (const char* v = std::getenv("SP_ROOT_PUBKEY"))  config.root_pubkey = v;
    if (const char* v = std::getenv("SP_JWT_SECRET"))   config.jwt_secret  = v;
    if (const char* v = std::getenv("SP_RP_ID"))          config.rp_id       = v;
    if (const char* v = std::getenv("SP_ACME_PROVIDER"))    config.acme_provider   = v;
    if (const char* v = std::getenv("SP_DNS_PROVIDER"))     config.dns_provider    = v;
    if (const char* v = std::getenv("SP_DNS_PORT"))         config.dns_port        = static_cast<uint16_t>(std::atoi(v));
    if (const char* v = std::getenv("SP_DNS_BASE_DOMAIN"))  config.dns_base_domain = v;
    if (const char* v = std::getenv("SP_DNS_NS_HOSTNAME")) config.dns_ns_hostname = v;
    if (const char* v = std::getenv("SP_RELEASE_SIGNING_PUBKEY")) config.release_signing_pubkey = v;
    if (const char* v = std::getenv("SP_DDNS_DOMAIN"))    config.ddns_domain   = v;
    if (const char* v = std::getenv("SP_DDNS_PASSWORD"))  config.ddns_password = v;
    if (std::getenv("SP_DDNS_ENABLED"))                   config.ddns_enabled  = true;
    if (std::getenv("SP_REQUIRE_ATTESTATION"))            config.require_binary_attestation = true;
    if (const char* v = std::getenv("SP_GITHUB_RELEASES_URL"))  config.github_releases_url       = v;
    if (const char* v = std::getenv("SP_MANIFEST_FETCH_INTERVAL")) config.manifest_fetch_interval_sec = static_cast<uint32_t>(std::atoi(v));
    if (const char* v = std::getenv("SP_MINIMUM_VERSION"))      config.minimum_version           = v;
    if (const char* v = std::getenv("SP_PRIVATE_HTTP_PORT")) config.private_http_port = static_cast<uint16_t>(std::atoi(v));
    if (std::getenv("SP_REQUIRE_PEER_CONFIRMATION"))      config.require_peer_confirmation = true;
    if (const char* v = std::getenv("SP_ENROLLMENT_QUORUM")) config.enrollment_quorum_ratio = std::atof(v);
    if (std::getenv("SP_REQUIRE_TEE"))                   config.require_tee_attestation   = true;
    if (const char* v = std::getenv("SP_TEE_PLATFORM"))  config.tee_platform_override     = v;
    if (const char* v = std::getenv("SP_SERVER_HOSTNAME"))    config.server_hostname       = v;
    if (const char* v = std::getenv("SP_ACME_EAB_KID"))       config.acme_eab_kid          = v;
    if (const char* v = std::getenv("SP_ACME_EAB_HMAC_KEY"))  config.acme_eab_hmac_key     = v;
    if (std::getenv("SP_NO_AUTO_TLS"))                   config.auto_tls              = false;
    if (const char* v = std::getenv("SP_TLS_CERT_PATH")) config.tls_cert_path         = v;
    if (const char* v = std::getenv("SP_TLS_KEY_PATH"))  config.tls_key_path          = v;

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
    check_port(config.wg_port, "wg_port");
    check_port(config.gossip_port, "gossip_port");
    check_port(config.stun_port, "stun_port");
    check_port(config.relay_port, "relay_port");
    check_port(config.dns_port, "dns_port");

    // Check ports are unique
    std::set<uint16_t> ports = {
        config.http_port, config.udp_port, config.wg_port, config.gossip_port,
        config.stun_port, config.relay_port, config.dns_port
    };
    if (ports.size() < 7) {
        spdlog::error("Config: port conflict — all 7 ports must be unique");
        valid = false;
    }

    // Validate private API port (used automatically once tunnel IP is allocated)
    check_port(config.private_http_port, "private_http_port");
    if (ports.contains(config.private_http_port)) {
        spdlog::error("Config: private_http_port {} conflicts with another port", config.private_http_port);
        valid = false;
    }

    // Check data root
    if (config.data_root.empty()) {
        spdlog::error("Config: data_root cannot be empty");
        valid = false;
    } else {
        std::error_code ec;
        std::filesystem::create_directories(config.data_root, ec);
        if (ec) {
            spdlog::error("Config: cannot create data_root '{}': {}", config.data_root, ec.message());
            valid = false;
        }
    }

    // Warnings (non-fatal)
    if (config.root_pubkey.empty()) {
        spdlog::warn("Config: root_pubkey not set — server enrollment will not be available");
    }

    if (config.seed_peers.empty()) {
        spdlog::warn("Config: no seed_peers — this server won't gossip until peers are added");
    }

    if (config.rp_id.empty()) {
        spdlog::warn("Config: rp_id is empty — WebAuthn passkeys will not validate");
    }

    spdlog::info("Config: HTTP:{} UDP:{} WG:{} Gossip:{} STUN:{} Relay:{} DNS:{} data={}",
                  config.http_port, config.udp_port, config.wg_port, config.gossip_port,
                  config.stun_port, config.relay_port, config.dns_port,
                  config.data_root);

    return valid;
}

} // namespace nexus::core
