#include <LemonadeNexus/Core/Coordinator.hpp>
#include <LemonadeNexus/Core/HostnameGenerator.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/ACL/ACLService.hpp>
#include <LemonadeNexus/Network/HttpServer.hpp>
#include <LemonadeNexus/Network/RateLimiter.hpp>
#include <LemonadeNexus/Network/UdpHolePunch.hpp>

// Lemonade-Nexus services
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Gossip/ServerCertificate.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <LemonadeNexus/Network/StunService.hpp>
#include <LemonadeNexus/Relay/RelayService.hpp>
#include <LemonadeNexus/Relay/RelayDiscoveryService.hpp>
#include <LemonadeNexus/Acme/AcmeService.hpp>
#include <LemonadeNexus/Network/DnsService.hpp>
#include <LemonadeNexus/Relay/GeoRegion.hpp>
#include <LemonadeNexus/Core/BinaryAttestation.hpp>
#include <LemonadeNexus/Core/GovernanceService.hpp>
#include <LemonadeNexus/Core/RootKeyChain.hpp>
#include <LemonadeNexus/Core/TeeAttestation.hpp>
#include <LemonadeNexus/Core/TrustPolicy.hpp>
#include <LemonadeNexus/Network/ApiTypes.hpp>
#include <LemonadeNexus/Network/DdnsService.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <thread>

int main(int argc, char* argv[]) {
    // --- Load configuration: CLI args > env vars > config file > defaults ---
    auto config = nexus::core::load_config(argc, argv);
    spdlog::set_level(spdlog::level::from_str(config.log_level));
    spdlog::info("Lemonade-Nexus starting...");

    if (!nexus::core::validate_config(config)) {
        spdlog::error("Invalid configuration, exiting");
        return 1;
    }

    // --- Handle enrollment/revocation CLI commands (exit after) ---
    if (!config.enroll_server_pubkey.empty()) {
        nexus::crypto::SodiumCryptoService enroll_crypto;
        enroll_crypto.start();
        nexus::storage::FileStorageService enroll_storage{std::filesystem::path(config.data_root)};
        enroll_storage.start();
        nexus::crypto::KeyWrappingService enroll_kw{enroll_crypto, enroll_storage};
        enroll_kw.start();

        auto privkey = enroll_kw.unlock_identity({});
        auto pubkey = enroll_kw.load_identity_pubkey();
        if (!privkey || !pubkey) {
            spdlog::error("Cannot enroll: root identity not available. Run server once first to generate identity.");
            return 1;
        }

        nexus::gossip::ServerCertificate cert;
        cert.server_pubkey  = config.enroll_server_pubkey;
        cert.server_id      = config.enroll_server_id;
        cert.issued_at      = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        cert.expires_at     = 0; // no expiry
        cert.issuer_pubkey  = nexus::crypto::to_base64(*pubkey);

        auto canonical = nexus::gossip::canonical_cert_json(cert);
        auto canonical_bytes = std::vector<uint8_t>(canonical.begin(), canonical.end());
        auto sig = enroll_crypto.ed25519_sign(*privkey, canonical_bytes);
        cert.signature = nexus::crypto::to_base64(sig);

        nlohmann::json cert_json = cert;
        nexus::storage::SignedEnvelope env;
        env.type = "server_certificate";
        env.data = cert_json.dump();
        env.timestamp = cert.issued_at;
        (void)enroll_storage.write_file("identity", "server_cert.json", env);

        spdlog::info("Enrolled server '{}' (pubkey: {})", cert.server_id, cert.server_pubkey);
        spdlog::info("Certificate written to {}/identity/server_cert.json", config.data_root);
        return 0;
    }

    if (!config.revoke_server_pubkey.empty()) {
        // Load existing revoked list, append, save
        nexus::storage::FileStorageService rev_storage{std::filesystem::path(config.data_root)};
        rev_storage.start();

        nlohmann::json revoked = nlohmann::json::array();
        auto env = rev_storage.read_file("identity", "revoked_servers.json");
        if (env) {
            try { revoked = nlohmann::json::parse(env->data); } catch (...) {}
        }
        revoked.push_back(config.revoke_server_pubkey);

        nexus::storage::SignedEnvelope rev_env;
        rev_env.type = "revocation_list";
        rev_env.data = revoked.dump();
        rev_env.timestamp = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        (void)rev_storage.write_file("identity", "revoked_servers.json", rev_env);

        spdlog::info("Revoked server pubkey: {}", config.revoke_server_pubkey);
        rev_storage.stop();
        return 0;
    }

    // --- Handle --add-manifest CLI command ---
    if (!config.add_manifest_path.empty()) {
        nexus::crypto::SodiumCryptoService manifest_crypto;
        manifest_crypto.start();
        nexus::storage::FileStorageService manifest_storage{std::filesystem::path(config.data_root)};
        manifest_storage.start();

        nexus::core::BinaryAttestationService manifest_attestation{manifest_crypto, manifest_storage};
        if (!config.release_signing_pubkey.empty()) {
            manifest_attestation.set_release_signing_pubkey(config.release_signing_pubkey);
        }

        try {
            std::ifstream f(config.add_manifest_path);
            auto j = nlohmann::json::parse(f);
            auto manifest = j.get<nexus::core::ReleaseManifest>();

            if (manifest_attestation.add_manifest(manifest)) {
                spdlog::info("Added release manifest: v{} {} (hash: {})",
                              manifest.version, manifest.platform, manifest.binary_sha256);
            } else {
                spdlog::error("Failed to add manifest (invalid signature?)");
                return 1;
            }
        } catch (const std::exception& e) {
            spdlog::error("Failed to parse manifest file '{}': {}", config.add_manifest_path, e.what());
            return 1;
        }

        manifest_storage.stop();
        manifest_crypto.stop();
        return 0;
    }

    const auto http_port   = config.http_port;
    const auto udp_port    = config.udp_port;
    const auto gossip_port = config.gossip_port;
    const auto stun_port   = config.stun_port;
    const auto relay_port  = config.relay_port;
    const auto dns_port    = config.dns_port;

    // --- Data directory ---
    const std::filesystem::path data_root = config.data_root;

    // --- Coordinator (owns ASIO io_context + signal handling) ---
    nexus::core::Coordinator coordinator{http_port, udp_port};

    // ========================================================================
    // Phase 1: Crypto
    // ========================================================================
    nexus::crypto::SodiumCryptoService crypto;
    crypto.start();

    // ========================================================================
    // Phase 2: File storage
    // ========================================================================
    nexus::storage::FileStorageService storage{data_root};
    storage.start();

    // ========================================================================
    // Phase 9: Key wrapping (depends on crypto + storage)
    // ========================================================================
    nexus::crypto::KeyWrappingService key_wrapping{crypto, storage};
    key_wrapping.start();

    // ========================================================================
    // Binary Attestation (depends on crypto + storage)
    // ========================================================================
    nexus::core::BinaryAttestationService attestation{crypto, storage};
    if (!config.release_signing_pubkey.empty()) {
        attestation.set_release_signing_pubkey(config.release_signing_pubkey);
    }
    if (!config.github_releases_url.empty()) {
        attestation.set_io_context(coordinator.io_context());
        attestation.set_github_config(config.github_releases_url,
                                       config.manifest_fetch_interval_sec,
                                       config.minimum_version);
    }
    attestation.start();

    // ========================================================================
    // TEE Attestation (depends on crypto + storage + binary attestation)
    // ========================================================================
    nexus::core::TeeAttestationService tee{crypto, storage, attestation};
    if (!config.tee_platform_override.empty()) {
        tee.set_platform_override(config.tee_platform_override);
    }
    tee.start();

    // ========================================================================
    // Trust Policy — zero-trust enforcement (depends on TEE + binary attestation + crypto)
    // ========================================================================
    nexus::core::TrustPolicyService trust_policy{tee, attestation, crypto};
    trust_policy.start();

    // ========================================================================
    // Phase 3: Permission tree (depends on storage + crypto)
    // ========================================================================
    nexus::tree::PermissionTreeService tree{storage, crypto};
    tree.start();

    // ========================================================================
    // Phase 5: IPAM (depends on storage)
    // ========================================================================
    nexus::ipam::IPAMService ipam{storage};
    ipam.start();

    // ========================================================================
    // Root Key Chain (always on — protocol constants, not configurable)
    // Rotation: weekly | Shamir quorum: 75% | Min Tier1 uptime: 90%
    // Parameters can only be changed via Tier1 democratic governance.
    // ========================================================================
    nexus::core::RootKeyChainService root_key_chain{crypto, storage};
    root_key_chain.set_io_context(coordinator.io_context());
    root_key_chain.start();

    // If root identity exists, initialize the chain with it
    auto root_privkey = key_wrapping.unlock_identity({});
    auto root_pubkey = key_wrapping.load_identity_pubkey();
    if (root_privkey && root_pubkey) {
        nexus::crypto::Ed25519Keypair root_kp;
        root_kp.private_key = *root_privkey;
        root_kp.public_key = *root_pubkey;
        root_key_chain.initialize_genesis(root_kp);
    }

    // ========================================================================
    // Democratic Governance (depends on crypto + storage + root key chain)
    // Tier1 peers can propose and vote on protocol parameter changes.
    // ========================================================================
    nexus::core::GovernanceService governance{crypto, storage, root_key_chain};
    governance.start();

    // ========================================================================
    // Phase 4: Gossip (depends on storage + crypto, uses io_context)
    // ========================================================================
    nexus::gossip::GossipService gossip{coordinator.io_context(), gossip_port, storage, crypto};
    if (!config.root_pubkey.empty()) {
        auto root_pk_bytes = nexus::crypto::from_hex(config.root_pubkey);
        if (root_pk_bytes.size() == nexus::crypto::kEd25519PublicKeySize) {
            nexus::crypto::Ed25519PublicKey root_pk{};
            std::memcpy(root_pk.data(), root_pk_bytes.data(), root_pk_bytes.size());
            gossip.set_root_pubkey(root_pk);
        }
    }
    // Wire zero-trust enforcement into gossip
    if (config.require_tee_attestation) {
        gossip.set_trust_policy(&trust_policy);
    }
    // Wire root key chain into gossip (always active)
    gossip.set_root_key_chain(&root_key_chain);
    // Wire democratic governance into gossip
    gossip.set_governance(&governance);
    // Wire quorum-based enrollment config
    gossip.set_enrollment_config(config.require_peer_confirmation,
                                  config.enrollment_quorum_ratio,
                                  config.enrollment_vote_timeout_sec,
                                  config.enrollment_max_retries);
    // Wire IPAM so gossip can allocate tunnel IPs during ServerHello
    gossip.set_ipam(&ipam);
    // Add seed peers before starting gossip
    for (const auto& peer_endpoint : config.seed_peers) {
        gossip.add_peer(peer_endpoint, "");  // pubkey discovered via ServerHello
    }
    gossip.start();

    // ========================================================================
    // Dynamic DNS (depends on crypto + storage + attestation + gossip)
    // ========================================================================
    nexus::network::DdnsService ddns{coordinator.io_context(), crypto, storage, attestation, gossip};
    if (config.ddns_enabled) {
        nexus::network::DdnsConfig ddns_config;
        ddns_config.domain              = config.ddns_domain;
        ddns_config.ddns_password       = config.ddns_password;
        ddns_config.update_interval_sec = config.ddns_update_interval_sec;
        ddns_config.enabled             = config.ddns_enabled;
        ddns.set_credentials(ddns_config);
    }
    // Set hostname from server certificate if available
    {
        auto cert_env = storage.read_file("identity", "server_cert.json");
        if (cert_env) {
            try {
                auto cert_j = nlohmann::json::parse(cert_env->data);
                auto server_id = cert_j.value("server_id", "");
                if (!server_id.empty()) {
                    ddns.set_hostname(server_id);
                }
            } catch (...) {}
        }
    }
    if (config.require_tee_attestation) {
        ddns.set_trust_policy(&trust_policy);
    }
    ddns.start();

    // ========================================================================
    // Phase 6: STUN (depends on crypto, uses io_context)
    // ========================================================================
    nexus::network::StunService stun{coordinator.io_context(), stun_port, crypto, "lemonade-nexus-central"};
    stun.start();

    // ========================================================================
    // Phase 7: Relay (depends on crypto, uses io_context)
    // ========================================================================
    nexus::crypto::Ed25519PublicKey central_pubkey{};
    if (auto pk = key_wrapping.load_identity_pubkey()) {
        central_pubkey = *pk;
    }

    nexus::relay::RelayService relay{coordinator.io_context(), relay_port, crypto, central_pubkey};
    relay.start();

    nexus::relay::RelayDiscoveryService relay_discovery{storage};
    relay_discovery.start();

    // ========================================================================
    // Phase 10: ACME (depends on storage)
    // ========================================================================
    nexus::acme::AcmeProviderConfig acme_config;
    if (config.acme_provider == "zerossl") {
        acme_config = nexus::acme::AcmeProviderConfig::zerossl(
            config.acme_eab_kid, config.acme_eab_hmac_key);
    } else if (config.acme_provider == "letsencrypt_staging") {
        acme_config = nexus::acme::AcmeProviderConfig::letsencrypt_staging();
    } else {
        acme_config = nexus::acme::AcmeProviderConfig::letsencrypt();
    }
    nexus::acme::AcmeService acme{storage, std::move(acme_config), config.dns_provider};
    acme.start();

    // ========================================================================
    // Phase 11: DNS resolution (depends on tree + io_context)
    // ========================================================================
    nexus::network::DnsService dns{coordinator.io_context(), dns_port, tree, config.dns_base_domain};
    {
        nexus::network::DnsService::PortConfig dns_ports;
        dns_ports.http_port   = http_port;
        dns_ports.udp_port    = udp_port;
        dns_ports.gossip_port = gossip_port;
        dns_ports.stun_port   = stun_port;
        dns_ports.relay_port  = relay_port;
        dns_ports.dns_port    = dns_port;
        dns_ports.private_http_port = config.private_http_port;
        dns.set_port_config(dns_ports);
    }
    // Wire DNS ↔ Gossip: local record mutations broadcast via gossip,
    // incoming deltas apply locally. This enables distributed authoritative DNS
    // where all Tier 1 peers serve the same zone.
    gossip.set_dns(&dns);
    dns.set_record_callback([&gossip](const std::string& delta_id,
                                       const std::string& operation,
                                       const nexus::network::DnsZoneRecord& record) {
        nexus::gossip::DnsRecordDelta delta;
        delta.delta_id    = delta_id;
        delta.operation   = operation;
        delta.fqdn        = record.fqdn;
        delta.record_type = record.record_type;
        delta.value       = record.value;
        delta.ttl         = record.ttl;
        delta.timestamp   = record.timestamp;
        gossip.broadcast_dns_record_delta(delta);
    });

    // ========================================================================
    // Server Hostname Resolution
    // ========================================================================
    // Priority: --server-hostname / SP_SERVER_HOSTNAME > persisted > auto-generate
    if (config.server_hostname.empty()) {
        auto persisted = nexus::core::HostnameGenerator::load_persisted_hostname(data_root);
        if (persisted) {
            config.server_hostname = *persisted;
            spdlog::info("Loaded server hostname from disk: {}", config.server_hostname);
        } else {
            auto region = nexus::core::HostnameGenerator::detect_region();
            std::string region_code = region.value_or("unknown");

            // Gather existing hostnames for collision avoidance
            std::unordered_set<std::string> existing_hostnames;
            // Check gossip peers
            for (const auto& peer : gossip.get_peers()) {
                // Try to extract server_id from peer certificate
                if (!peer.certificate_json.empty()) {
                    try {
                        auto cert_j = nlohmann::json::parse(peer.certificate_json);
                        auto sid = cert_j.value("server_id", "");
                        if (!sid.empty()) existing_hostnames.insert(sid);
                    } catch (...) {}
                }
            }

            config.server_hostname = nexus::core::HostnameGenerator::generate_unique_hostname(
                region_code, existing_hostnames);

            nexus::core::HostnameGenerator::persist_hostname(data_root, config.server_hostname);
            spdlog::info("Auto-generated server hostname: {} (region: {})", config.server_hostname, region_code);
        }
    }

    // Resolve NS hostname: explicit --dns-ns-hostname > derived from --server-hostname
    // NS hostname uses base domain (for Namecheap glue); server FQDN uses .srv. subdomain (for ACME cert)
    std::string ns_hostname = config.dns_ns_hostname;
    if (ns_hostname.empty() && !config.server_hostname.empty()) {
        ns_hostname = config.server_hostname + "." + config.dns_base_domain;
        spdlog::info("DNS: auto-derived NS hostname: {}", ns_hostname);
    }

    // Resolve public IP for DNS glue A records:
    //   SP_PUBLIC_IP > non-wildcard bind address > auto-detect via external service
    std::string server_public_ip = config.public_ip;
    if (server_public_ip.empty() && config.bind_address != "0.0.0.0" && !config.bind_address.empty()) {
        server_public_ip = config.bind_address;
    }
    if (server_public_ip.empty()) {
        try {
            httplib::Client ip_cli("http://api.ipify.org");
            ip_cli.set_connection_timeout(3, 0);
            ip_cli.set_read_timeout(3, 0);
            auto ip_res = ip_cli.Get("/");
            if (ip_res && ip_res->status == 200 && !ip_res->body.empty()) {
                server_public_ip = ip_res->body;
                // Trim whitespace
                while (!server_public_ip.empty() && (server_public_ip.back() == '\n' || server_public_ip.back() == '\r'))
                    server_public_ip.pop_back();
                spdlog::info("DNS: auto-detected public IP: {}", server_public_ip);
            }
        } catch (...) {
            spdlog::warn("DNS: failed to auto-detect public IP");
        }
    }

    // Configure this server's NS identity for SOA/NS responses
    if (!ns_hostname.empty() && !server_public_ip.empty()) {
        dns.set_our_nameserver(ns_hostname, server_public_ip);
        dns.add_nameserver(ns_hostname, server_public_ip);
        spdlog::info("DNS: registered as nameserver {} -> {}", ns_hostname, server_public_ip);
    } else if (!ns_hostname.empty()) {
        spdlog::warn("DNS: NS hostname '{}' configured but no public IP available — skipping NS registration", ns_hostname);
    }

    // Wire ACME → local DNS for DNS-01 challenges
    acme.set_dns_service(&dns);

    // Publish this server's _config TXT record (gossip-synced to all peers)
    {
        std::string config_id;
        // Try server_cert.json first (enrolled servers)
        auto cert_env = storage.read_file("identity", "server_cert.json");
        if (cert_env) {
            try {
                auto cert_j = nlohmann::json::parse(cert_env->data);
                config_id = cert_j.value("server_id", "");
            } catch (...) {}
        }
        // Fall back to server_hostname (unenrolled servers)
        if (config_id.empty() && !config.server_hostname.empty()) {
            config_id = config.server_hostname;
        }
        if (!config_id.empty()) {
            // Include the .srv. FQDN in _config TXT so clients know the cert hostname
            std::string config_fqdn;
            if (!config.server_hostname.empty() && !config.dns_base_domain.empty()) {
                config_fqdn = config.server_hostname + ".srv." + config.dns_base_domain;
            }
            dns.publish_port_config(config_id, config_fqdn);
            spdlog::info("DNS: published _config TXT for {} (host={})", config_id, config_fqdn);
        }
    }

    dns.start();

    // ========================================================================
    // Original services: Auth + ACL
    // ========================================================================
    // JWT secret: config > persisted file > auto-generate and persist
    std::string jwt_secret_hex = config.jwt_secret;
    if (jwt_secret_hex.empty()) {
        const auto jwt_path = data_root / "identity" / "jwt_secret.hex";
        if (std::filesystem::exists(jwt_path)) {
            std::ifstream f(jwt_path);
            std::getline(f, jwt_secret_hex);
            spdlog::info("Loaded JWT secret from {}", jwt_path.string());
        } else {
            std::array<uint8_t, 32> jwt_secret_bytes{};
            crypto.random_bytes(std::span<uint8_t>(jwt_secret_bytes));
            jwt_secret_hex = nexus::crypto::to_hex(
                std::span<const uint8_t>(jwt_secret_bytes));
            std::filesystem::create_directories(jwt_path.parent_path());
            std::ofstream f(jwt_path);
            f << jwt_secret_hex;
            spdlog::info("Generated and persisted JWT secret to {}", jwt_path.string());
        }
    }

    nexus::auth::AuthService auth_service{storage, crypto,
                                           config.rp_id, jwt_secret_hex};
    auth_service.start();

    auto acl_db_path = std::filesystem::path{config.data_root} / "acl.db";
    nexus::acl::ACLService acl_service{acl_db_path, crypto};
    acl_service.set_signing_keypair(gossip.keypair());

    // Wire ACL ↔ Gossip: local mutations broadcast via gossip, incoming deltas apply locally
    gossip.set_acl(&acl_service);
    acl_service.set_delta_callback([&gossip](const nexus::acl::AclDelta& delta) {
        gossip.broadcast_acl_delta(delta);
    });

    acl_service.start();

    // ========================================================================
    // Auto-allocate server tunnel IP
    // ========================================================================
    // Flow:
    //   1. If manual override (--tunnel-bind-ip), use that
    //   2. If existing IPAM allocation, reuse it
    //   3. If joining a network (has peers), gossip ServerHello requests an IP from a peer
    //   4. Genesis server (no peers): self-allocates the first IP
    std::string server_node_id;
    {
        auto cert_env = storage.read_file("identity", "server_cert.json");
        if (cert_env) {
            try {
                auto cert_j = nlohmann::json::parse(cert_env->data);
                server_node_id = cert_j.value("server_id", "");
            } catch (...) {}
        }
    }

    std::string tunnel_bind_ip;

    if (!server_node_id.empty()) {
        // Check for existing IPAM allocation
        auto existing = ipam.get_allocation(server_node_id);
        if (existing && existing->tunnel) {
            tunnel_bind_ip = existing->tunnel->base_network;
        } else if (!config.seed_peers.empty()) {
            // Joining server: wait for gossip to assign us a tunnel IP via ServerHello
            spdlog::info("Waiting for tunnel IP assignment from network peers...");
            for (int i = 0; i < 15 && gossip.our_tunnel_ip().empty(); ++i) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            tunnel_bind_ip = gossip.our_tunnel_ip();
            if (tunnel_bind_ip.empty()) {
                spdlog::warn("No tunnel IP received from peers — self-allocating");
                auto alloc = ipam.allocate_tunnel_ip(server_node_id);
                tunnel_bind_ip = alloc.base_network;
            }
        } else {
            // Genesis server (no peers): self-allocate the first tunnel IP
            auto alloc = ipam.allocate_tunnel_ip(server_node_id);
            if (!alloc.base_network.empty()) {
                tunnel_bind_ip = alloc.base_network;
                spdlog::info("Genesis server — allocated tunnel IP: {}", tunnel_bind_ip);
            }
        }
        // Strip CIDR suffix (e.g. "10.64.0.1/32" -> "10.64.0.1")
        if (auto slash = tunnel_bind_ip.find('/'); slash != std::string::npos) {
            tunnel_bind_ip = tunnel_bind_ip.substr(0, slash);
        }
    }

    // ========================================================================
    // TLS Certificate Resolution
    // ========================================================================
    //
    // Priority:
    //   1. Manual override: --tls-cert-path / --tls-key-path
    //   2. Auto-TLS via ACME: request cert for <hostname>.srv.<dns_base_domain>
    //   3. Fallback: plain HTTP (first boot before ACME completes)
    // ========================================================================

    std::string tls_cert_path = config.tls_cert_path;
    std::string tls_key_path  = config.tls_key_path;

    // Resolve server hostname: --server-hostname > server_id from cert > empty
    std::string server_hostname = config.server_hostname;
    if (server_hostname.empty() && !server_node_id.empty()) {
        server_hostname = server_node_id;
    }

    // Build the server FQDN: <hostname>.srv.<dns_base_domain>
    std::string server_fqdn;
    if (!server_hostname.empty()) {
        server_fqdn = server_hostname + ".srv." + config.dns_base_domain;

        // Register an A record for the server FQDN so it resolves via our DNS
        if (!server_public_ip.empty()) {
            dns.set_record(server_fqdn, "A", server_public_ip, 300);
            spdlog::info("DNS: registered server FQDN {} -> {}", server_fqdn, server_public_ip);
        }

        // Also register the NS hostname A record (ns1.lemonade-nexus.io)
        // so both NS glue and server FQDN resolve
        std::string ns_fqdn = server_hostname + "." + config.dns_base_domain;
        if (ns_fqdn != server_fqdn && !server_public_ip.empty()) {
            dns.set_record(ns_fqdn, "A", server_public_ip, 300);
            spdlog::info("DNS: registered NS hostname {} -> {}", ns_fqdn, server_public_ip);
        }
    }

    // Auto-TLS: if no manual cert paths, check for existing ACME cert on disk
    bool needs_acme_background = false;
    if (tls_cert_path.empty() && tls_key_path.empty() && config.auto_tls && !server_fqdn.empty()) {
        const auto acme_cert_dir = data_root / "certs" / server_fqdn;
        const auto acme_cert_file = acme_cert_dir / "fullchain.pem";
        const auto acme_key_file  = acme_cert_dir / "privkey.pem";

        if (std::filesystem::exists(acme_cert_file) && std::filesystem::exists(acme_key_file)) {
            tls_cert_path = acme_cert_file.string();
            tls_key_path  = acme_key_file.string();
            spdlog::info("Auto-TLS: using existing ACME cert for {}", server_fqdn);
        } else {
            needs_acme_background = true;
            spdlog::info("Auto-TLS: no cert on disk for {} — will request in background", server_fqdn);
        }
    }

    // Populate config fields for other services to reference
    if (!tls_cert_path.empty() && !tls_key_path.empty()) {
        config.tls_cert_path = tls_cert_path;
        config.tls_key_path  = tls_key_path;
    }

    // ========================================================================
    // HTTP Control Plane — Dual-server architecture
    // ========================================================================
    //
    // Public server:  binds to 0.0.0.0:<http_port>   — pre-VPN bootstrap endpoints
    // Private server: binds to <tunnel_ip>:<private_http_port> — post-VPN sensitive ops
    //
    // When TLS cert is available, public server runs HTTPS; otherwise plain HTTP.
    // Private API always runs plain HTTP (VPN-only network, trusted).
    // Private API activates automatically once the server has a tunnel IP.
    // ========================================================================

    nexus::network::HttpServer http_server{http_port, "0.0.0.0",
                                            tls_cert_path, tls_key_path};

    // Private server — created automatically when a tunnel IP is available
    // Private server runs plain HTTP (only reachable over the VPN tunnel)
    std::unique_ptr<nexus::network::HttpServer> private_http_server;
    if (!tunnel_bind_ip.empty()) {
        private_http_server = std::make_unique<nexus::network::HttpServer>(
            config.private_http_port, tunnel_bind_ip);
        spdlog::info("Private API will bind to {}:{}", tunnel_bind_ip, config.private_http_port);
    }

    // Helper: returns the server that should handle "private" (VPN-only) routes.
    // When dual-server mode is off, everything goes on the public server.
    auto& private_srv = private_http_server
        ? private_http_server->server()
        : http_server.server();

    // --- Rate limiter (applied to both servers) ---
    nexus::network::RateLimiter rate_limiter{{config.rate_limit_rpm, config.rate_limit_burst}};
    auto rate_limit_handler = [&rate_limiter](const httplib::Request& req, httplib::Response& res) -> httplib::Server::HandlerResponse {
        if (!rate_limiter.allow(req.remote_addr)) {
            res.status = 429;
            nlohmann::json rl_j = nexus::network::ErrorResponse{.error = "rate limited"};
            res.set_content(rl_j.dump(), "application/json");
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
    };
    http_server.server().set_pre_routing_handler(rate_limit_handler);
    if (private_http_server) {
        private_http_server->server().set_pre_routing_handler(rate_limit_handler);
    }

    // --- Health ---
    http_server.server().Get("/api/health", [&config](const httplib::Request&, httplib::Response& res) {
        nexus::network::HealthResponse resp;
        resp.rp_id = config.rp_id;
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    });

    // --- TLS status (public) ---
    http_server.server().Get("/api/tls/status", [&](const httplib::Request&, httplib::Response& res) {
        nlohmann::json resp = {
            {"tls_enabled", http_server.is_tls()},
            {"cert_path",   http_server.tls_cert_path()},
            {"key_path",    http_server.tls_key_path()},
            {"server_fqdn", server_fqdn},
            {"auto_tls",    config.auto_tls},
        };
        res.set_content(resp.dump(), "application/json");
    });

    // --- Auth ---
    http_server.server().Post("/api/auth", [&](const httplib::Request& req, httplib::Response& res) {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            nlohmann::json j = nexus::network::ErrorResponse{.error = "invalid json"};
            res.set_content(j.dump(), "application/json");
            return;
        }
        auto result = auth_service.authenticate(body);

        // After successful Ed25519 auth, grant add_child on root so the
        // newly registered key can create child nodes.
        if (result.authenticated && body.value("method", "") == "ed25519") {
            auto pubkey = body.value("pubkey", std::string{});
            if (!pubkey.empty()) {
                tree.grant_assignment("root", {
                    .management_pubkey = pubkey,
                    .permissions = {"read", "add_child"},
                });
            }
        }

        nexus::network::AuthResponse resp{
            .authenticated = result.authenticated,
            .user_id       = result.user_id,
            .session_token = result.session_token,
            .error         = result.error_message,
        };
        res.status = result.authenticated ? 200 : 401;
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    });

    // --- Auth: passkey registration ---
    http_server.server().Post("/api/auth/register", [&](const httplib::Request& req, httplib::Response& res) {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            nlohmann::json j = nexus::network::ErrorResponse{.error = "invalid json"};
            res.set_content(j.dump(), "application/json");
            return;
        }
        auto result = auth_service.register_passkey(body);
        nexus::network::AuthResponse resp{
            .authenticated = result.authenticated,
            .user_id       = result.user_id,
            .session_token = result.session_token,
            .error         = result.error_message,
        };
        res.status = result.authenticated ? 200 : 400;
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    });

    // --- Auth: Ed25519 challenge issuance ---
    http_server.server().Post("/api/auth/challenge", [&](const httplib::Request& req, httplib::Response& res) {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            nlohmann::json j = nexus::network::ErrorResponse{.error = "invalid json"};
            res.set_content(j.dump(), "application/json");
            return;
        }
        auto pubkey = body.value("pubkey", std::string{});
        if (pubkey.empty()) {
            res.status = 400;
            nlohmann::json j = nexus::network::ErrorResponse{.error = "pubkey required"};
            res.set_content(j.dump(), "application/json");
            return;
        }
        auto challenge = auth_service.issue_ed25519_challenge(pubkey);
        res.set_content(challenge.dump(), "application/json");
    });

    // --- Auth: Ed25519 pubkey registration ---
    http_server.server().Post("/api/auth/register/ed25519", [&](const httplib::Request& req, httplib::Response& res) {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            nlohmann::json j = nexus::network::ErrorResponse{.error = "invalid json"};
            res.set_content(j.dump(), "application/json");
            return;
        }
        auto result = auth_service.register_ed25519(body);

        // Grant add_child on root for newly registered Ed25519 keys
        if (result.authenticated) {
            auto pubkey = body.value("pubkey", std::string{});
            if (!pubkey.empty()) {
                tree.grant_assignment("root", {
                    .management_pubkey = pubkey,
                    .permissions = {"read", "add_child"},
                });
            }
        }

        nexus::network::AuthResponse resp{
            .authenticated = result.authenticated,
            .user_id       = result.user_id,
            .session_token = result.session_token,
            .error         = result.error_message,
        };
        res.status = result.authenticated ? 200 : 400;
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    });

    // --- Server discovery (public — needed for bootstrap) ---
    http_server.server().Get("/api/servers", [&](const httplib::Request&, httplib::Response& res) {
        auto peers = gossip.get_peers();
        std::vector<nexus::network::ServerEntry> entries;

        // Include ourselves — use public IP, not bind address
        std::string our_endpoint = (!server_public_ip.empty() ? server_public_ip : config.bind_address)
                                   + ":" + std::to_string(config.http_port);
        entries.push_back({
            .endpoint  = our_endpoint,
            .http_port = config.http_port,
            .healthy   = true,
        });

        // Include known gossip peers
        for (const auto& p : peers) {
            entries.push_back({
                .endpoint  = p.endpoint,
                .pubkey    = p.pubkey,
                .http_port = p.http_port,
                .last_seen = p.last_seen,
                .healthy   = true,
            });
        }
        nlohmann::json j = entries;
        res.set_content(j.dump(), "application/json");
    });

    // --- Stats (public) ---
    http_server.server().Get("/api/stats", [&](const httplib::Request&, httplib::Response& res) {
        auto peers = gossip.get_peers();
        nlohmann::json resp = {
            {"service", "lemonade-nexus"},
            {"peer_count", peers.size()},
            {"private_api_enabled", !tunnel_bind_ip.empty()},
        };
        res.set_content(resp.dump(), "application/json");
    });

    // --- POST /api/join — composite bootstrap endpoint (public) ---
    // Authenticates, creates a node, allocates a tunnel IP, returns WireGuard config
    http_server.server().Post("/api/join", [&](const httplib::Request& req, httplib::Response& res) {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            nlohmann::json j = nexus::network::ErrorResponse{.error = "invalid json"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        // Step 1: Authenticate
        auto auth_result = auth_service.authenticate(body);
        if (!auth_result.authenticated) {
            res.status = 401;
            nlohmann::json j = nexus::network::ErrorResponse{
                .error  = "authentication failed",
                .detail = auth_result.error_message,
            };
            res.set_content(j.dump(), "application/json");
            return;
        }

        // Step 2: Extract the client's public key
        auto client_pubkey = body.value("public_key", "");
        if (client_pubkey.empty()) {
            res.status = 400;
            nlohmann::json j = nexus::network::ErrorResponse{.error = "public_key required"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        // Step 3: Create a node in the permission tree
        auto node_id = auth_result.user_id;
        if (node_id.empty()) {
            node_id = "node-" + client_pubkey.substr(0, 16);
        }

        // Bootstrap: if no root node exists, the first joiner becomes root
        auto existing_root = tree.get_node("root");
        if (!existing_root) {
            nexus::tree::TreeNode root_node;
            root_node.id        = "root";
            root_node.parent_id = "";
            root_node.type      = nexus::tree::NodeType::Root;
            root_node.hostname  = config.server_hostname.empty()
                                    ? "root" : config.server_hostname;
            root_node.mgmt_pubkey = client_pubkey;
            root_node.assignments = {{
                .management_pubkey = client_pubkey,
                .permissions = {"read", "write", "add_child", "delete_node",
                                "edit_node", "admin"},
            }};
            tree.bootstrap_root(root_node);
            node_id = "root";  // first user IS root
        } else if (node_id != "root") {
            // Root exists — create an endpoint node under it
            nexus::tree::TreeNode endpoint_node;
            endpoint_node.id        = node_id;
            endpoint_node.parent_id = "root";
            endpoint_node.type      = nexus::tree::NodeType::Endpoint;
            endpoint_node.hostname  = body.value("hostname",
                                        "endpoint-" + node_id.substr(0, 8));
            endpoint_node.mgmt_pubkey = client_pubkey;
            tree.insert_join_node(endpoint_node);
        }

        // Step 4: Allocate a tunnel IP
        auto alloc = ipam.allocate_tunnel_ip(node_id);
        if (alloc.base_network.empty()) {
            res.status = 409;
            nlohmann::json j = nexus::network::ErrorResponse{.error = "IP allocation failed"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        // Step 5: Get server's WireGuard public key
        std::string wg_server_pubkey;
        if (auto pk = key_wrapping.load_identity_pubkey()) {
            wg_server_pubkey = nexus::crypto::to_base64(*pk);
        }

        // Step 6: Build response with everything the client needs for WireGuard setup
        std::string server_tunnel = tunnel_bind_ip.empty() ? "10.100.0.1" : tunnel_bind_ip;
        nlohmann::json resp = {
            {"token", auth_result.session_token},
            {"node_id", node_id},
            {"tunnel_ip", alloc.base_network},
            {"server_tunnel_ip", server_tunnel},
            {"private_api_port", !tunnel_bind_ip.empty() ? config.private_http_port : config.http_port},
            {"wg_server_pubkey", wg_server_pubkey},
            {"wg_endpoint", config.bind_address + ":" + std::to_string(config.relay_port)},
            {"dns_servers", nlohmann::json::array({server_tunnel})},
        };
        spdlog::info("[Join] node={} tunnel_ip={}", node_id, alloc.base_network);
        res.set_content(resp.dump(), "application/json");
    });

    // ====================================================================
    // PRIVATE ENDPOINTS (on private server when dual-mode, else public)
    // All wrapped with require_auth() to enforce Bearer token auth.
    // ====================================================================

    using nexus::auth::require_auth;
    using nexus::auth::SessionClaims;

    // --- Tree: get node ---
    private_srv.Get(R"(/api/tree/node/(.+))", require_auth(auth_service,
        [&](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        auto node_id = req.matches[1].str();
        auto node = tree.get_node(node_id);
        if (!node) {
            res.status = 404;
            nlohmann::json j = nexus::network::ErrorResponse{.error = "node not found"};
            res.set_content(j.dump(), "application/json");
            return;
        }
        nlohmann::json j = *node;
        res.set_content(j.dump(), "application/json");
    }));

    // --- Tree: submit delta ---
    private_srv.Post("/api/tree/delta", require_auth(auth_service,
        [&](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            nlohmann::json j = nexus::network::ErrorResponse{.error = "invalid json"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        nexus::tree::TreeDelta delta;
        try {
            delta = body.get<nexus::tree::TreeDelta>();
        } catch (...) {
            // Fallback: partial parse for backwards compatibility
            delta.operation = body.value("operation", "");
            delta.target_node_id = body.value("target_node_id", "");
            if (body.contains("node_data")) {
                auto& nd = body["node_data"];
                delta.node_data.id = nd.value("id", "");
                delta.node_data.parent_id = nd.value("parent_id", "");
            }
            delta.signer_pubkey = body.value("signer_pubkey", "");
            delta.signature = body.value("signature", "");
        }

        bool ok = tree.apply_delta(delta);
        nexus::network::DeltaResponse resp{.success = ok};
        if (!ok) {
            res.status = 403;
            resp.error = "delta rejected";
        }
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // --- Tree: get children ---
    private_srv.Get(R"(/api/tree/children/(.+))", require_auth(auth_service,
        [&](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        auto parent_id = req.matches[1].str();
        auto children = tree.get_children(parent_id);
        nlohmann::json j = children;  // uses existing TreeNode to_json
        res.set_content(j.dump(), "application/json");
    }));

    // --- IPAM: allocate ---
    private_srv.Post("/api/ipam/allocate", require_auth(auth_service,
        [&](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            nlohmann::json j = nexus::network::ErrorResponse{.error = "invalid json"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        auto ipam_req = body.get<nexus::network::IpamAllocateRequest>();

        nexus::ipam::Allocation alloc;
        if (ipam_req.block_type == "tunnel") {
            alloc = ipam.allocate_tunnel_ip(ipam_req.node_id);
        } else if (ipam_req.block_type == "private") {
            alloc = ipam.allocate_private_subnet(ipam_req.node_id, ipam_req.prefix_len);
        } else if (ipam_req.block_type == "shared") {
            alloc = ipam.allocate_shared_block(ipam_req.node_id, ipam_req.prefix_len);
        } else {
            res.status = 400;
            nlohmann::json j = nexus::network::ErrorResponse{.error = "invalid block_type"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        bool ok = !alloc.base_network.empty();
        nexus::network::IpamAllocateResponse resp{
            .success = ok,
            .network = alloc.base_network,
            .node_id = alloc.customer_node_id,
        };
        res.status = ok ? 200 : 409;
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // --- Relay: list ---
    private_srv.Get("/api/relay/list", require_auth(auth_service,
        [&](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        nexus::relay::RelaySelectionCriteria criteria;
        criteria.max_results = 50;
        auto relays = relay_discovery.discover_relays(criteria);

        std::vector<nexus::network::RelayInfoEntry> entries;
        entries.reserve(relays.size());
        for (const auto& r : relays) {
            entries.push_back({
                .relay_id         = r.relay_id,
                .endpoint         = r.endpoint,
                .region           = r.region,
                .reputation_score = r.reputation_score,
                .supports_stun    = r.supports_stun,
                .supports_relay   = r.supports_relay,
            });
        }
        nlohmann::json j = entries;
        res.set_content(j.dump(), "application/json");
    }));

    // --- Relay: find nearest ---
    // GET /api/relay/nearest?region=us-ca&max=5
    // or  /api/relay/nearest?lat=37.7&lon=-122.4&max=5
    private_srv.Get("/api/relay/nearest", require_auth(auth_service,
        [&](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        auto max_str = req.get_param_value("max");
        uint32_t max_results = max_str.empty() ? 5 : static_cast<uint32_t>(std::atoi(max_str.c_str()));
        if (max_results == 0) max_results = 5;
        if (max_results > 50) max_results = 50;

        // Determine the client's region
        std::string client_region = req.get_param_value("region");
        auto lat_str = req.get_param_value("lat");
        auto lon_str = req.get_param_value("lon");

        // If lat/lon provided, find the nearest region code
        if (client_region.empty() && !lat_str.empty() && !lon_str.empty()) {
            nexus::relay::GeoCoord coord{std::atof(lat_str.c_str()), std::atof(lon_str.c_str())};
            auto nearest = nexus::relay::GeoRegion::find_closest_region(coord);
            if (nearest) {
                client_region = nearest->code;
            }
        }

        if (client_region.empty()) {
            res.status = 400;
            nlohmann::json j = nexus::network::ErrorResponse{.error = "region or lat/lon required"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        if (!nexus::relay::GeoRegion::is_valid_region(client_region)) {
            res.status = 400;
            nlohmann::json j = nexus::network::ErrorResponse{.error = "unknown region", .region = client_region};
            res.set_content(j.dump(), "application/json");
            return;
        }

        // Get all relays
        nexus::relay::RelaySelectionCriteria criteria;
        criteria.max_results = 200; // get all, we'll sort ourselves
        auto relays = relay_discovery.discover_relays(criteria);

        // Collect unique relay regions
        std::vector<std::string> relay_regions;
        for (const auto& r : relays) {
            if (!r.region.empty()) {
                relay_regions.push_back(r.region);
            }
        }

        // Sort regions by distance from client
        auto sorted_regions = nexus::relay::GeoRegion::sort_by_distance(client_region, relay_regions);

        // Build region priority map
        std::unordered_map<std::string, int> region_priority;
        for (int i = 0; i < static_cast<int>(sorted_regions.size()); ++i) {
            if (!region_priority.contains(sorted_regions[i])) {
                region_priority[sorted_regions[i]] = i;
            }
        }

        // Sort relays: by region distance, then reputation
        std::sort(relays.begin(), relays.end(),
            [&](const nexus::relay::RelayNodeInfo& a, const nexus::relay::RelayNodeInfo& b) {
                int pa = region_priority.contains(a.region) ? region_priority[a.region] : 999;
                int pb = region_priority.contains(b.region) ? region_priority[b.region] : 999;
                if (pa != pb) return pa < pb;
                return a.reputation_score > b.reputation_score;
            });

        if (relays.size() > max_results) relays.resize(max_results);

        // Build response entries with distance
        nexus::network::RelayNearestResponse resp;
        resp.client_region = client_region;
        resp.relays.reserve(relays.size());
        for (const auto& r : relays) {
            nexus::network::RelayInfoEntry entry{
                .relay_id         = r.relay_id,
                .endpoint         = r.endpoint,
                .region           = r.region,
                .reputation_score = r.reputation_score,
                .supports_stun    = r.supports_stun,
                .supports_relay   = r.supports_relay,
            };
            auto dist = nexus::relay::GeoRegion::distance_between_regions(client_region, r.region);
            if (dist) entry.distance_km = static_cast<int>(*dist);
            resp.relays.push_back(std::move(entry));
        }

        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // --- Relay: ticket ---
    private_srv.Post("/api/relay/ticket", require_auth(auth_service,
        [&](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            nlohmann::json j = nexus::network::ErrorResponse{.error = "invalid json"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        auto ticket_req = body.get<nexus::network::RelayTicketRequest>();

        if (ticket_req.peer_id.empty() || ticket_req.relay_id.empty()) {
            res.status = 400;
            nlohmann::json j = nexus::network::ErrorResponse{.error = "peer_id and relay_id required"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        // Build ticket
        nexus::relay::RelayTicket ticket;
        ticket.peer_id = ticket_req.peer_id;
        ticket.relay_id = ticket_req.relay_id;
        crypto.random_bytes(std::span<uint8_t>(ticket.session_nonce));

        auto now = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());
        ticket.issued_at = now;
        ticket.expires_at = now + 300; // 5 minutes

        // Sign with central key if available
        auto privkey = key_wrapping.unlock_identity({});
        if (privkey) {
            std::vector<uint8_t> canonical;
            canonical.insert(canonical.end(), ticket.peer_id.begin(), ticket.peer_id.end());
            canonical.insert(canonical.end(), ticket.relay_id.begin(), ticket.relay_id.end());
            canonical.insert(canonical.end(), ticket.session_nonce.begin(), ticket.session_nonce.end());
            auto push_u64 = [&](uint64_t v) {
                for (int i = 0; i < 8; ++i) {
                    canonical.push_back(static_cast<uint8_t>(v & 0xFF));
                    v >>= 8;
                }
            };
            push_u64(ticket.issued_at);
            push_u64(ticket.expires_at);

            auto sig = crypto.ed25519_sign(*privkey, std::span<const uint8_t>(canonical));
            std::memcpy(ticket.signature.data(), sig.data(), sig.size());
        }

        nexus::network::RelayTicketResponse resp{
            .peer_id       = ticket.peer_id,
            .relay_id      = ticket.relay_id,
            .session_nonce = nexus::crypto::to_base64(
                std::span<const uint8_t>(ticket.session_nonce)),
            .issued_at     = ticket.issued_at,
            .expires_at    = ticket.expires_at,
            .signature     = nexus::crypto::to_base64(
                std::span<const uint8_t>(ticket.signature)),
        };
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // --- Relay: register ---
    private_srv.Post("/api/relay/register", require_auth(auth_service,
        [&](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            nlohmann::json j = nexus::network::ErrorResponse{.error = "invalid json"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        auto reg_req = body.get<nexus::network::RelayRegisterRequest>();

        if (reg_req.relay_id.empty() || reg_req.endpoint.empty()) {
            res.status = 400;
            nlohmann::json j = nexus::network::ErrorResponse{.error = "relay_id and endpoint required"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        // Validate region code if provided
        if (!reg_req.region.empty() && !nexus::relay::GeoRegion::is_valid_region(reg_req.region)) {
            res.status = 400;
            nlohmann::json j = nexus::network::ErrorResponse{
                .error  = "invalid region code",
                .region = reg_req.region,
                .hint   = "Use format: us-ca, eu-de, ap-jp, etc.",
            };
            res.set_content(j.dump(), "application/json");
            return;
        }

        nexus::storage::SignedEnvelope envelope;
        envelope.type = "relay_node";
        envelope.data = body.dump();
        envelope.timestamp = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());

        (void)storage.write_file("relay", reg_req.relay_id, envelope);
        relay_discovery.refresh_relay_list();

        // Build DNS names this relay is reachable at
        nexus::network::RelayRegisterResponse resp{
            .success  = true,
            .relay_id = reg_req.relay_id,
            .region   = reg_req.region,
        };
        if (!reg_req.hostname.empty()) {
            resp.dns_names.push_back(reg_req.hostname + ".relays." + config.dns_base_domain);
            if (!reg_req.region.empty()) {
                resp.dns_names.push_back(reg_req.hostname + "." + reg_req.region + ".relays." + config.dns_base_domain);
            }
            resp.dns_names.push_back(reg_req.hostname + ".relay." + config.dns_base_domain);
        }

        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // --- TLS: hot-reload certificates ---
    private_srv.Post("/api/tls/reload", require_auth(auth_service,
        [&](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        // Optionally accept new cert/key paths in the request body
        std::string reload_cert = http_server.tls_cert_path();
        std::string reload_key  = http_server.tls_key_path();

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (!body.is_discarded()) {
            if (body.contains("cert_path")) reload_cert = body["cert_path"].get<std::string>();
            if (body.contains("key_path"))  reload_key  = body["key_path"].get<std::string>();
        }

        if (!http_server.is_tls()) {
            // Try to upgrade from HTTP to HTTPS
            if (reload_cert.empty() || reload_key.empty()) {
                res.status = 400;
                nlohmann::json j = nexus::network::ErrorResponse{
                    .error = "not running TLS and no cert/key paths provided"};
                res.set_content(j.dump(), "application/json");
                return;
            }
            res.status = 400;
            nlohmann::json j = nexus::network::ErrorResponse{
                .error = "server is running plain HTTP — restart with TLS cert to enable HTTPS"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        bool ok = http_server.reload_tls_certs(reload_cert, reload_key);
        nlohmann::json resp = {
            {"success",   ok},
            {"cert_path", reload_cert},
            {"key_path",  reload_key},
        };
        res.status = ok ? 200 : 500;
        res.set_content(resp.dump(), "application/json");
    }));

    // --- TLS: request new ACME cert and reload ---
    private_srv.Post("/api/tls/renew", require_auth(auth_service,
        [&](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        if (server_fqdn.empty()) {
            res.status = 400;
            nlohmann::json j = nexus::network::ErrorResponse{
                .error = "no server FQDN configured — set --server-hostname"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        auto result = acme.renew_certificate(server_fqdn);
        if (!result.success) {
            res.status = 502;
            nlohmann::json j = nexus::network::ErrorResponse{
                .error  = "ACME renewal failed",
                .detail = result.error_message,
            };
            res.set_content(j.dump(), "application/json");
            return;
        }

        // Hot-reload the new cert
        bool reloaded = false;
        if (http_server.is_tls() && !result.cert_path.empty() && !result.key_path.empty()) {
            reloaded = http_server.reload_tls_certs(result.cert_path, result.key_path);
        }

        nlohmann::json resp = {
            {"success",      true},
            {"domain",       server_fqdn},
            {"cert_path",    result.cert_path},
            {"key_path",     result.key_path},
            {"hot_reloaded", reloaded},
        };
        res.set_content(resp.dump(), "application/json");
    }));

    // --- ACME: get certificate ---
    private_srv.Get(R"(/api/certs/(.+))", require_auth(auth_service,
        [&](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        auto domain = req.matches[1].str();
        auto bundle = acme.get_certificate(domain);
        if (!bundle) {
            res.status = 404;
            nlohmann::json j = nexus::network::ErrorResponse{.error = "certificate not found"};
            res.set_content(j.dump(), "application/json");
            return;
        }
        nexus::network::CertStatusResponse resp{
            .domain     = domain,
            .has_cert   = true,
            .expires_at = bundle->expires_at,
        };
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // --- Certificate issuance for clients (borrowed license) ---
    private_srv.Post("/api/certs/issue", require_auth(auth_service,
        [&](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            nlohmann::json j = nexus::network::ErrorResponse{.error = "invalid json"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        auto cert_req = body.get<nexus::network::CertIssueRequest>();

        if (cert_req.hostname.empty() || cert_req.client_pubkey.empty()) {
            res.status = 400;
            nlohmann::json j = nexus::network::ErrorResponse{.error = "hostname and client_pubkey required"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        // Validate hostname contains only safe characters
        for (char c : cert_req.hostname) {
            if (!std::isalnum(static_cast<unsigned char>(c)) && c != '-' && c != '_') {
                res.status = 400;
                nlohmann::json j = nexus::network::ErrorResponse{.error = "invalid hostname characters"};
                res.set_content(j.dump(), "application/json");
                return;
            }
        }

        // Build the FQDN: <hostname>.capi.<base_domain>
        std::string fqdn = cert_req.hostname + ".capi." + config.dns_base_domain;

        // Check if we already have a valid cert for this domain
        auto existing = acme.get_certificate(fqdn);
        if (!existing) {
            // Request a new certificate via ACME
            spdlog::info("[CertIssue] requesting ACME cert for {}", fqdn);
            auto result = acme.request_certificate(fqdn);
            if (!result.success) {
                res.status = 502;
                nlohmann::json j = nexus::network::ErrorResponse{
                    .error  = "ACME certificate request failed",
                    .detail = result.error_message,
                };
                res.set_content(j.dump(), "application/json");
                return;
            }
            existing = acme.get_certificate(fqdn);
            if (!existing) {
                res.status = 500;
                nlohmann::json j = nexus::network::ErrorResponse{.error = "certificate issued but not found in storage"};
                res.set_content(j.dump(), "application/json");
                return;
            }
        }

        // Encrypt the private key for the requesting client
        // 1. Decode client's Ed25519 public key
        std::string pk_data = cert_req.client_pubkey;
        // Strip "ed25519:" prefix if present
        if (pk_data.starts_with("ed25519:")) {
            pk_data = pk_data.substr(8);
        }
        auto pk_bytes = nexus::crypto::from_base64(pk_data);
        if (pk_bytes.size() != nexus::crypto::kEd25519PublicKeySize) {
            res.status = 400;
            nlohmann::json j = nexus::network::ErrorResponse{.error = "invalid client_pubkey size"};
            res.set_content(j.dump(), "application/json");
            return;
        }
        nexus::crypto::Ed25519PublicKey client_ed_pk{};
        std::memcpy(client_ed_pk.data(), pk_bytes.data(), pk_bytes.size());

        // 2. Convert to X25519 and generate ephemeral keypair for forward secrecy
        auto client_x_pk = nexus::crypto::SodiumCryptoService::ed25519_pk_to_x25519(client_ed_pk);
        auto ephemeral = crypto.x25519_keygen();

        // 3. DH(ephemeral_sk, client_x_pk) -> shared secret
        auto shared_secret = crypto.x25519_dh(ephemeral.private_key, client_x_pk);

        // 4. HKDF -> AES-256-GCM key
        const std::string info_str = "lemonade-nexus-cert-issue";
        auto enc_key = crypto.hkdf_sha256(shared_secret, {},
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(info_str.data()), info_str.size()), 32);
        nexus::crypto::AesGcmKey aes_key{};
        std::memcpy(aes_key.data(), enc_key.data(), std::min(enc_key.size(), aes_key.size()));

        // 5. Encrypt the private key PEM
        auto privkey_bytes = std::vector<uint8_t>(
            existing->privkey_pem.begin(), existing->privkey_pem.end());
        auto encrypted = crypto.aes_gcm_encrypt(aes_key, privkey_bytes, {});

        // 6. Return the bundle
        nexus::network::CertIssueResponse resp{
            .domain            = fqdn,
            .fullchain_pem     = existing->fullchain_pem,
            .encrypted_privkey = nexus::crypto::to_base64(encrypted.ciphertext),
            .nonce             = nexus::crypto::to_base64(encrypted.nonce),
            .ephemeral_pubkey  = nexus::crypto::to_base64(ephemeral.public_key),
            .expires_at        = existing->expires_at,
        };
        spdlog::info("[CertIssue] issued cert for {} to client {}", fqdn, cert_req.client_pubkey.substr(0, 16));
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // --- Credential distribution (root server distributes DDNS creds to verified servers) ---
    private_srv.Post("/api/credentials/request", require_auth(auth_service,
        [&](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            res.status = 400;
            nlohmann::json j = nexus::network::ErrorResponse{.error = "invalid json"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        // Need root private key to sign the DH exchange
        auto root_privkey = key_wrapping.unlock_identity({});
        auto root_pubkey = key_wrapping.load_identity_pubkey();
        if (!root_privkey || !root_pubkey) {
            res.status = 503;
            nlohmann::json j = nexus::network::ErrorResponse{.error = "root identity not available"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        auto response = ddns.handle_credential_request(body, *root_privkey, *root_pubkey);
        if (!response) {
            res.status = 403;
            nlohmann::json j = nexus::network::CredentialErrorResponse{.success = false, .error = "verification failed"};
            res.set_content(j.dump(), "application/json");
            return;
        }

        res.set_content(*response, "application/json");
    }));

    // --- DDNS status ---
    private_srv.Get("/api/ddns/status", require_auth(auth_service,
        [&](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        nexus::network::DdnsStatusResponse resp{
            .has_credentials = ddns.has_credentials(),
            .last_ip         = ddns.last_ip(),
            .binary_hash     = attestation.self_hash(),
            .binary_approved = attestation.is_approved_binary(attestation.self_hash()),
        };
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // --- DDNS force update ---
    private_srv.Post("/api/ddns/update", require_auth(auth_service,
        [&](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        bool ok = ddns.update_now();
        nexus::network::DdnsUpdateResponse resp{
            .success = ok,
            .ip      = ddns.last_ip(),
        };
        res.status = ok ? 200 : 500;
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // --- Binary attestation: list manifests ---
    private_srv.Get("/api/attestation/manifests", require_auth(auth_service,
        [&](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        auto manifests = attestation.get_manifests();
        nexus::network::AttestationManifestsResponse resp{
            .self_hash                   = attestation.self_hash(),
            .self_approved               = attestation.is_approved_binary(attestation.self_hash()),
            .github_url                  = config.github_releases_url,
            .minimum_version             = config.minimum_version,
            .manifest_fetch_interval_sec = config.manifest_fetch_interval_sec,
        };
        resp.manifests.reserve(manifests.size());
        for (const auto& m : manifests) {
            resp.manifests.push_back({
                .version       = m.version,
                .platform      = m.platform,
                .binary_sha256 = m.binary_sha256,
                .timestamp     = m.timestamp,
            });
        }
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // --- Binary attestation: trigger GitHub fetch ---
    private_srv.Post("/api/attestation/fetch", require_auth(auth_service,
        [&](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        auto count = attestation.fetch_github_manifests();
        nexus::network::AttestationFetchResponse resp{
            .success         = true,
            .new_manifests   = count,
            .total_manifests = attestation.get_manifests().size(),
        };
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // Helper: trust tier to string
    auto tier_name = [](nexus::core::TrustTier t) -> std::string {
        switch (t) {
            case nexus::core::TrustTier::Tier1: return "Tier1";
            case nexus::core::TrustTier::Tier2: return "Tier2";
            default: return "Untrusted";
        }
    };

    // --- Trust status ---
    private_srv.Get("/api/trust/status", require_auth(auth_service,
        [&](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        auto our_tier = trust_policy.our_tier();
        auto peer_states = trust_policy.all_peer_states();

        nexus::network::TrustStatusResponse resp{
            .our_tier     = tier_name(our_tier),
            .our_platform = std::string(nexus::core::tee_platform_name(tee.detected_platform())),
            .require_tee  = config.require_tee_attestation,
            .binary_hash  = attestation.self_hash(),
            .peer_count   = peer_states.size(),
        };
        resp.peers.reserve(peer_states.size());
        for (const auto& ps : peer_states) {
            resp.peers.push_back({
                .pubkey                = ps.pubkey,
                .tier                  = static_cast<uint8_t>(ps.tier),
                .tier_name             = tier_name(ps.tier),
                .platform              = std::string(nexus::core::tee_platform_name(ps.platform)),
                .last_verified         = ps.last_verified,
                .binary_hash           = ps.binary_hash,
                .failed_verifications  = ps.failed_verifications,
            });
        }
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // --- Trust: peer detail ---
    private_srv.Get(R"(/api/trust/peer/(.+))", require_auth(auth_service,
        [&](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        auto pubkey = req.matches[1].str();
        auto state = trust_policy.peer_state(pubkey);

        nexus::network::TrustPeerDetailResponse resp{
            .pubkey                = state.pubkey,
            .tier                  = static_cast<uint8_t>(state.tier),
            .tier_name             = tier_name(state.tier),
            .platform              = std::string(nexus::core::tee_platform_name(state.platform)),
            .last_verified         = state.last_verified,
            .attestation_hash      = state.attestation_hash,
            .binary_hash           = state.binary_hash,
            .failed_verifications  = state.failed_verifications,
        };
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // Helper: enrollment state to string
    auto enrollment_state_name = [](nexus::gossip::EnrollmentBallot::State s) -> std::string {
        switch (s) {
            case nexus::gossip::EnrollmentBallot::State::Collecting: return "Collecting";
            case nexus::gossip::EnrollmentBallot::State::Approved:   return "Approved";
            case nexus::gossip::EnrollmentBallot::State::Rejected:   return "Rejected";
            case nexus::gossip::EnrollmentBallot::State::TimedOut:   return "TimedOut";
            default: return "Unknown";
        }
    };

    // Helper: convert an EnrollmentBallot to an EnrollmentEntry
    auto ballot_to_entry = [&](const nexus::gossip::EnrollmentBallot& b, bool include_detail) {
        nexus::network::EnrollmentEntry entry{
            .request_id          = b.request_id,
            .candidate_pubkey    = b.candidate_pubkey,
            .candidate_server_id = b.candidate_server_id,
            .sponsor_pubkey      = b.sponsor_pubkey,
            .state               = static_cast<uint8_t>(b.state),
            .state_name          = enrollment_state_name(b.state),
            .created_at          = b.created_at,
            .timeout_at          = b.timeout_at,
            .retries             = b.retries,
            .vote_count          = b.votes.size(),
        };
        if (include_detail) {
            entry.certificate_json = b.certificate_json;
        }
        entry.votes.reserve(b.votes.size());
        for (const auto& v : b.votes) {
            nexus::network::EnrollmentVoteEntry ve{
                .voter_pubkey = v.voter_pubkey,
                .approve      = v.approve,
                .reason       = v.reason,
                .timestamp    = v.timestamp,
            };
            if (include_detail) ve.signature = v.signature;
            entry.votes.push_back(std::move(ve));
        }
        return entry;
    };

    // --- Enrollment quorum: list pending enrollments ---
    private_srv.Get("/api/enrollment/status", require_auth(auth_service,
        [&](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        auto ballots = gossip.pending_enrollments();
        nexus::network::EnrollmentStatusResponse resp{
            .enabled          = config.require_peer_confirmation,
            .quorum_ratio     = config.enrollment_quorum_ratio,
            .vote_timeout_sec = config.enrollment_vote_timeout_sec,
            .pending_count    = ballots.size(),
        };
        resp.enrollments.reserve(ballots.size());
        for (const auto& b : ballots) {
            resp.enrollments.push_back(ballot_to_entry(b, false));
        }
        nlohmann::json j = resp;
        res.set_content(j.dump(), "application/json");
    }));

    // --- Enrollment quorum: get specific enrollment ---
    private_srv.Get(R"(/api/enrollment/(.+))", require_auth(auth_service,
        [&](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        auto request_id = req.matches[1].str();
        auto ballots = gossip.pending_enrollments();

        for (const auto& b : ballots) {
            if (b.request_id == request_id) {
                auto entry = ballot_to_entry(b, true);
                nlohmann::json j = entry;
                res.set_content(j.dump(), "application/json");
                return;
            }
        }

        res.status = 404;
        nlohmann::json j = nexus::network::ErrorResponse{.error = "enrollment not found"};
        res.set_content(j.dump(), "application/json");
    }));

    // --- Governance: current parameters ---
    private_srv.Get("/api/governance/params", require_auth(auth_service,
        [&](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        res.set_content(governance.current_params().dump(), "application/json");
    }));

    // Helper: governance ballot state to string
    auto governance_state_name = [](nexus::gossip::GovernanceBallot::State s) -> std::string {
        switch (s) {
            case nexus::gossip::GovernanceBallot::State::Collecting: return "Collecting";
            case nexus::gossip::GovernanceBallot::State::Approved:   return "Approved";
            case nexus::gossip::GovernanceBallot::State::Rejected:   return "Rejected";
            case nexus::gossip::GovernanceBallot::State::TimedOut:   return "TimedOut";
            default: return "Unknown";
        }
    };

    // --- Governance: list proposals ---
    private_srv.Get("/api/governance/proposals", require_auth(auth_service,
        [&](const httplib::Request&, httplib::Response& res, const SessionClaims&) {
        auto proposals = governance.all_proposals();
        std::vector<nexus::network::GovernanceProposalEntry> entries;
        entries.reserve(proposals.size());
        for (const auto& b : proposals) {
            nexus::network::GovernanceProposalEntry entry{
                .proposal_id     = b.proposal.proposal_id,
                .proposer_pubkey = b.proposal.proposer_pubkey,
                .parameter       = static_cast<uint8_t>(b.proposal.parameter),
                .new_value       = b.proposal.new_value,
                .old_value       = b.proposal.old_value,
                .rationale       = b.proposal.rationale,
                .created_at      = b.proposal.created_at,
                .expires_at      = b.proposal.expires_at,
                .state           = static_cast<uint8_t>(b.state),
                .state_name      = governance_state_name(b.state),
            };
            entry.votes.reserve(b.votes.size());
            for (const auto& v : b.votes) {
                entry.votes.push_back({
                    .voter_pubkey = v.voter_pubkey,
                    .approve      = v.approve,
                    .reason       = v.reason,
                    .timestamp    = v.timestamp,
                });
            }
            entries.push_back(std::move(entry));
        }
        nlohmann::json j = entries;
        res.set_content(j.dump(), "application/json");
    }));

    // --- Governance: create proposal ---
    private_srv.Post("/api/governance/propose", require_auth(auth_service,
        [&](const httplib::Request& req, httplib::Response& res, const SessionClaims&) {
        try {
            auto body = nlohmann::json::parse(req.body);
            auto propose_req = body.get<nexus::network::GovernanceProposeRequest>();

            if (propose_req.new_value.empty()) {
                res.status = 400;
                nlohmann::json j = nexus::network::ErrorResponse{.error = "new_value required"};
                res.set_content(j.dump(), "application/json");
                return;
            }

            auto param = static_cast<nexus::gossip::GovernableParam>(propose_req.parameter);
            auto proposal_id = governance.create_proposal(param, propose_req.new_value, propose_req.rationale);
            if (proposal_id.empty()) {
                res.status = 400;
                nlohmann::json j = nexus::network::ErrorResponse{.error = "invalid proposal (check parameter and value)"};
                res.set_content(j.dump(), "application/json");
                return;
            }

            nexus::network::GovernanceProposeResponse resp{
                .proposal_id = proposal_id,
                .status      = "created",
            };
            nlohmann::json j = resp;
            res.set_content(j.dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 400;
            nlohmann::json j = nexus::network::ErrorResponse{.error = e.what()};
            res.set_content(j.dump(), "application/json");
        }
    }));

    // ====================================================================
    // Start HTTP servers
    // ====================================================================
    http_server.start();
    if (private_http_server) {
        private_http_server->start();
    }

    // ========================================================================
    // UDP Hole Punch (original)
    // ========================================================================
    nexus::network::HolePunchService hole_punch{coordinator.io_context(), udp_port};
    hole_punch.start();

    // ========================================================================
    // Run — blocks until SIGINT/SIGTERM
    // ========================================================================
    const auto http_proto = http_server.is_tls() ? "HTTPS" : "HTTP";
    if (private_http_server) {
        spdlog::info("All services started. Listening on {}:{}, PrivateHTTP:{}:{}, UDP:{}, Gossip:{}, STUN:{}, Relay:{}, DNS:{}",
                     http_proto, http_port, tunnel_bind_ip, config.private_http_port,
                     udp_port, gossip_port, stun_port, relay_port, dns_port);
    } else {
        spdlog::info("All services started. Listening on {}:{}, UDP:{}, Gossip:{}, STUN:{}, Relay:{}, DNS:{}",
                     http_proto, http_port, udp_port, gossip_port, stun_port, relay_port, dns_port);
    }
    if (http_server.is_tls() && !server_fqdn.empty()) {
        spdlog::info("TLS enabled for {} (cert={})", server_fqdn, http_server.tls_cert_path());
    }

    // ========================================================================
    // Background ACME retry — if no cert yet, retry every 5 minutes
    // ========================================================================
    std::atomic<bool> acme_retry_stop{false};
    std::thread acme_retry_thread;
    if (needs_acme_background) {
        acme_retry_thread = std::thread([&]() {
            constexpr auto initial_delay  = std::chrono::seconds(30);
            constexpr auto base_interval  = std::chrono::minutes(5);
            constexpr auto max_interval   = std::chrono::hours(1);
            auto current_interval = base_interval;

            spdlog::info("Auto-TLS: background retry starting in 30s for {}", server_fqdn);
            for (auto elapsed = std::chrono::seconds(0);
                 elapsed < initial_delay && !acme_retry_stop.load();
                 elapsed += std::chrono::seconds(1)) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }

            while (!acme_retry_stop.load()) {
                spdlog::info("Auto-TLS: attempting ACME certificate for {}", server_fqdn);
                auto result = acme.request_certificate(server_fqdn);
                if (result.success) {
                    spdlog::info("Auto-TLS: ACME certificate issued for {} (cert={}, key={})",
                                  server_fqdn, result.cert_path, result.key_path);
                    spdlog::info("Auto-TLS: restarting server to activate HTTPS...");
                    coordinator.shutdown();
                    break;
                }

                // Detect rate limiting — back off to 1 hour
                bool rate_limited = result.error_message.find("rateLimited") != std::string::npos
                                 || result.error_message.find("429") != std::string::npos
                                 || result.error_message.find("too many") != std::string::npos;

                if (rate_limited) {
                    current_interval = max_interval;
                    spdlog::warn("Auto-TLS: rate limited by ACME provider — backing off to {} minutes",
                                  std::chrono::duration_cast<std::chrono::minutes>(current_interval).count());
                } else {
                    // Exponential backoff: 5m, 10m, 20m, 40m, capped at 60m
                    auto mins = std::chrono::duration_cast<std::chrono::minutes>(current_interval).count();
                    spdlog::warn("Auto-TLS: ACME retry failed — retrying in {} minutes", mins);
                    auto doubled = current_interval * 2;
                    current_interval = doubled > max_interval ? max_interval : doubled;
                }

                for (auto elapsed = std::chrono::seconds(0);
                     elapsed < current_interval && !acme_retry_stop.load();
                     elapsed += std::chrono::seconds(1)) {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }

                // Reset backoff after a successful wait through rate limit window
                if (rate_limited) {
                    current_interval = base_interval;
                }
            }
        });
    }

    // ========================================================================
    // Background ACME renewal — check daily, renew when cert expires within 30 days
    // ========================================================================
    std::atomic<bool> acme_renewal_stop{false};
    std::thread acme_renewal_thread;
    if (!server_fqdn.empty() && config.auto_tls && !needs_acme_background) {
        acme_renewal_thread = std::thread([&]() {
            // First check after 1 hour, then every 24 hours
            constexpr auto initial_delay = std::chrono::hours(1);
            constexpr auto check_interval = std::chrono::hours(24);

            spdlog::info("Auto-TLS: certificate renewal monitor started for {} (checking daily)", server_fqdn);

            // Wait for initial delay
            for (auto elapsed = std::chrono::seconds(0);
                 elapsed < initial_delay && !acme_renewal_stop.load();
                 elapsed += std::chrono::seconds(1)) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }

            while (!acme_renewal_stop.load()) {
                auto result = acme.renew_certificate(server_fqdn);
                if (result.success && !result.cert_path.empty()) {
                    // Check if the cert was actually renewed (not just "still valid")
                    // by comparing paths — renew_certificate returns the existing path when skipping
                    spdlog::info("Auto-TLS: renewal check complete for {} (cert={})",
                                  server_fqdn, result.cert_path);
                }
                if (!result.success) {
                    spdlog::warn("Auto-TLS: renewal failed for {}: {}",
                                  server_fqdn, result.error_message);
                }

                // Wait for next check
                for (auto elapsed = std::chrono::seconds(0);
                     elapsed < check_interval && !acme_renewal_stop.load();
                     elapsed += std::chrono::seconds(1)) {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }
            }
        });
    }

    coordinator.run();

    // ========================================================================
    // Shutdown (reverse order)
    // ========================================================================
    acme_retry_stop.store(true);
    if (acme_retry_thread.joinable()) {
        acme_retry_thread.join();
    }
    acme_renewal_stop.store(true);
    if (acme_renewal_thread.joinable()) {
        acme_renewal_thread.join();
    }
    hole_punch.stop();
    if (private_http_server) {
        private_http_server->stop();
    }
    http_server.stop();
    ddns.stop();
    dns.stop();
    acme.stop();
    relay_discovery.stop();
    relay.stop();
    stun.stop();
    gossip.stop();
    governance.stop();
    root_key_chain.stop();
    ipam.stop();
    tree.stop();
    trust_policy.stop();
    tee.stop();
    attestation.stop();
    key_wrapping.stop();
    acl_service.stop();
    auth_service.stop();
    storage.stop();
    crypto.stop();

    spdlog::info("Lemonade-Nexus shut down cleanly.");
    return 0;
}
