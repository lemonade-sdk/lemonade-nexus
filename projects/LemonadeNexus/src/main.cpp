#include <LemonadeNexus/Core/Coordinator.hpp>
#include <LemonadeNexus/Core/HostnameGenerator.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Core/ServerIdentity.hpp>
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
#include <LemonadeNexus/Core/BinaryAttestation.hpp>
#include <LemonadeNexus/Core/GovernanceService.hpp>
#include <LemonadeNexus/Core/RootKeyChain.hpp>
#include <LemonadeNexus/Core/TeeAttestation.hpp>
#include <LemonadeNexus/Core/TrustPolicy.hpp>
#include <LemonadeNexus/Network/ApiTypes.hpp>
#include <LemonadeNexus/Network/DdnsService.hpp>
#include <LemonadeNexus/WireGuard/WireGuardService.hpp>

// CRTP request handlers
#include <LemonadeNexus/Api/PublicApiHandler.hpp>
#include <LemonadeNexus/Api/AuthApiHandler.hpp>
#include <LemonadeNexus/Api/TreeApiHandler.hpp>
#include <LemonadeNexus/Api/RelayApiHandler.hpp>
#include <LemonadeNexus/Api/CertApiHandler.hpp>
#include <LemonadeNexus/Api/AdminApiHandler.hpp>
#include <LemonadeNexus/Api/MeshApiHandler.hpp>

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
    // Create services (dependency order)
    // ========================================================================
    nexus::crypto::SodiumCryptoService crypto;
    crypto.start();

    nexus::storage::FileStorageService storage{data_root};
    storage.start();

    nexus::crypto::KeyWrappingService key_wrapping{crypto, storage};
    key_wrapping.start();

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

    nexus::core::TeeAttestationService tee{crypto, storage, attestation};
    if (!config.tee_platform_override.empty()) {
        tee.set_platform_override(config.tee_platform_override);
    }
    tee.start();

    nexus::core::TrustPolicyService trust_policy{tee, attestation, crypto};
    trust_policy.start();

    nexus::tree::PermissionTreeService tree{storage, crypto};
    tree.start();

    nexus::ipam::IPAMService ipam{storage};
    ipam.start();

    nexus::core::RootKeyChainService root_key_chain{crypto, storage};
    root_key_chain.set_io_context(coordinator.io_context());
    root_key_chain.start();

    // Load or auto-generate server identity keypair
    auto root_privkey = key_wrapping.unlock_identity({});
    auto root_pubkey = key_wrapping.load_identity_pubkey();
    if (!root_privkey || !root_pubkey) {
        spdlog::info("No identity keypair found — generating one for this server");
        auto generated = key_wrapping.generate_and_store_identity({});
        root_privkey = generated.private_key;
        root_pubkey  = generated.public_key;
    }
    if (root_privkey && root_pubkey) {
        nexus::crypto::Ed25519Keypair root_kp;
        root_kp.private_key = *root_privkey;
        root_kp.public_key = *root_pubkey;
        root_key_chain.initialize_genesis(root_kp);

        // If the tree has a root node with a different pubkey (e.g. identity was
        // regenerated after keypair files were lost), update it automatically.
        auto identity_pk = "ed25519:" + nexus::crypto::to_base64(
            std::span<const uint8_t>(root_pubkey->data(), root_pubkey->size()));
        auto root_node = tree.get_node("root");
        if (root_node && root_node->mgmt_pubkey != identity_pk) {
            spdlog::warn("Root node pubkey mismatch — updating to match new server identity");
            spdlog::info("  old: {}", root_node->mgmt_pubkey);
            spdlog::info("  new: {}", identity_pk);
            auto updated = *root_node;
            updated.mgmt_pubkey = identity_pk;
            for (auto& a : updated.assignments) {
                a.management_pubkey = identity_pk;
            }
            tree.update_node_direct("root", updated);
        }
    }

    nexus::core::GovernanceService governance{crypto, storage, root_key_chain};
    governance.start();

    // ========================================================================
    // Gossip (depends on storage + crypto, uses io_context)
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
    if (config.require_tee_attestation) {
        gossip.set_trust_policy(&trust_policy);
    }
    gossip.set_root_key_chain(&root_key_chain);
    gossip.set_governance(&governance);
    gossip.set_enrollment_config(config.require_peer_confirmation,
                                  config.enrollment_quorum_ratio,
                                  config.enrollment_vote_timeout_sec,
                                  config.enrollment_max_retries);
    gossip.set_ipam(&ipam);
    for (const auto& peer_endpoint : config.seed_peers) {
        gossip.add_peer(peer_endpoint, "");
    }
    gossip.start();

    // ========================================================================
    // Dynamic DNS
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
    // STUN + Relay
    // ========================================================================
    nexus::network::StunService stun{coordinator.io_context(), stun_port, crypto, "lemonade-nexus-central"};
    stun.start();

    nexus::crypto::Ed25519PublicKey central_pubkey{};
    if (auto pk = key_wrapping.load_identity_pubkey()) {
        central_pubkey = *pk;
    }
    nexus::relay::RelayService relay{coordinator.io_context(), relay_port, crypto, central_pubkey};
    relay.start();

    nexus::relay::RelayDiscoveryService relay_discovery{storage};
    relay_discovery.start();

    // ========================================================================
    // ACME
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
    // DNS
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
    // Server identity resolution (uses ServerIdentity helpers)
    // ========================================================================
    nexus::core::resolve_server_hostname(config, data_root, gossip);
    nexus::core::resolve_server_region(config, data_root);

    // NS hostname: explicit > derived from server_hostname
    std::string ns_hostname = config.dns_ns_hostname;
    if (ns_hostname.empty() && !config.server_hostname.empty()) {
        ns_hostname = config.server_hostname + "." + config.dns_base_domain;
        spdlog::info("DNS: auto-derived NS hostname: {}", ns_hostname);
    }

    std::string server_public_ip = nexus::core::resolve_public_ip(config);

    // Configure NS identity for SOA/NS responses
    if (!ns_hostname.empty() && !server_public_ip.empty()) {
        dns.set_our_nameserver(ns_hostname, server_public_ip);
        dns.add_nameserver(ns_hostname, server_public_ip);
        spdlog::info("DNS: registered as nameserver {} -> {}", ns_hostname, server_public_ip);
    } else if (!ns_hostname.empty()) {
        spdlog::warn("DNS: NS hostname '{}' configured but no public IP available -- skipping NS registration", ns_hostname);
    }

    acme.set_dns_service(&dns);

    // Publish _config TXT records (gossip-synced)
    // The NS hostname (e.g. "ns1") is what clients use for DNS discovery.
    // Also publish under the server node ID for gossip-based discovery.
    {
        std::string config_fqdn = nexus::core::build_server_fqdn(
            config.server_hostname, config.dns_base_domain);

        // Determine the NS hostname prefix (e.g. "ns1" from "ns1.lemonade-nexus.io")
        std::string ns_prefix;
        std::string ns_fqdn = config.dns_ns_hostname;
        if (ns_fqdn.empty() && !config.server_hostname.empty()) {
            ns_prefix = config.server_hostname;
        } else if (!ns_fqdn.empty()) {
            auto dot = ns_fqdn.find('.');
            ns_prefix = (dot != std::string::npos) ? ns_fqdn.substr(0, dot) : ns_fqdn;
        }

        // Publish under NS hostname prefix (for client DNS discovery: _config.ns1.domain)
        if (!ns_prefix.empty()) {
            dns.publish_port_config(ns_prefix, config_fqdn);
            spdlog::info("DNS: published _config TXT for {} (host={})", ns_prefix, config_fqdn);
        }

        // Also publish under server node ID (for gossip-based server discovery)
        std::string node_id = nexus::core::resolve_server_node_id(storage);
        if (!node_id.empty() && node_id != ns_prefix) {
            dns.publish_port_config(node_id, config_fqdn);
            spdlog::info("DNS: published _config TXT for {} (host={})", node_id, config_fqdn);
        }
    }

    // Publish SEIP records: <id>.<region>.seip.<domain> for geo-aware discovery
    dns.set_server_region(config.region);
    std::string server_seip_fqdn;
    std::string server_private_fqdn;
    {
        auto seip_id = nexus::core::resolve_server_node_id(storage);
        if (!seip_id.empty() && !config.region.empty() && !server_public_ip.empty()) {
            server_seip_fqdn = seip_id + "." + config.region + ".seip." + config.dns_base_domain;
            server_private_fqdn = "private." + server_seip_fqdn;

            dns.publish_seip_records(seip_id, config.region, server_public_ip);
            spdlog::info("SEIP: published {} -> {}", server_seip_fqdn, server_public_ip);

            // Request ACME cert for the SEIP hostname (public API)
            if (config.auto_tls) {
                auto seip_tls = nexus::core::resolve_tls_cert(config, data_root, server_seip_fqdn);
                if (!seip_tls.cert_path.empty() && !seip_tls.key_path.empty()) {
                    // Use SEIP cert as the primary public API cert
                    config.tls_cert_path = seip_tls.cert_path;
                    config.tls_key_path  = seip_tls.key_path;
                    spdlog::info("SEIP: using TLS cert for {}", server_seip_fqdn);
                } else if (seip_tls.needs_acme_background) {
                    spdlog::info("SEIP: requesting ACME cert for {} in background", server_seip_fqdn);
                    std::thread([&acme, fqdn = server_seip_fqdn]() {
                        std::this_thread::sleep_for(std::chrono::seconds(5));
                        (void)acme.request_certificate(fqdn);
                    }).detach();
                }
            }
        }
    }

    dns.start();

    // NS slot claiming: first 9 servers claim ns1-ns9 for DNS bootstrap
    gossip.set_our_region(config.region);
    gossip.set_dns_base_domain(config.dns_base_domain);
    if (!server_public_ip.empty()) {
        gossip.try_claim_ns_slot(server_public_ip);
        if (auto slot = gossip.our_ns_slot()) {
            spdlog::info("SEIP: claimed NS slot ns{} for {}", *slot, server_public_ip);
        }
    }

    // ========================================================================
    // Auth + ACL
    // ========================================================================
    auto jwt_secret_hex = nexus::core::resolve_jwt_secret(config, data_root, crypto);

    nexus::auth::AuthService auth_service{storage, crypto,
                                           config.rp_id, jwt_secret_hex};
    auth_service.start();

    auto acl_db_path = std::filesystem::path{config.data_root} / "acl.db";
    nexus::acl::ACLService acl_service{acl_db_path, crypto};
    acl_service.set_signing_keypair(gossip.keypair());

    gossip.set_acl(&acl_service);
    acl_service.set_delta_callback([&gossip](const nexus::acl::AclDelta& delta) {
        gossip.broadcast_acl_delta(delta);
    });
    acl_service.start();

    // ========================================================================
    // Tunnel IP + TLS resolution
    // ========================================================================
    auto server_node_id = nexus::core::resolve_server_node_id(storage);
    std::string tunnel_bind_ip = nexus::core::resolve_tunnel_ip(
        server_node_id, config, ipam, gossip);

    // Resolve server FQDN and register DNS records
    std::string server_hostname = config.server_hostname;
    if (server_hostname.empty() && !server_node_id.empty()) {
        server_hostname = server_node_id;
    }

    std::string server_fqdn = nexus::core::build_server_fqdn(
        server_hostname, config.dns_base_domain);

    if (!server_fqdn.empty()) {
        if (!server_public_ip.empty()) {
            dns.set_record(server_fqdn, "A", server_public_ip, 300);
            spdlog::info("DNS: registered server FQDN {} -> {}", server_fqdn, server_public_ip);
        }
        std::string ns_fqdn = server_hostname + "." + config.dns_base_domain;
        if (ns_fqdn != server_fqdn && !server_public_ip.empty()) {
            dns.set_record(ns_fqdn, "A", server_public_ip, 300);
            spdlog::info("DNS: registered NS hostname {} -> {}", ns_fqdn, server_public_ip);
        }
    }

    auto tls = nexus::core::resolve_tls_cert(config, data_root, server_fqdn);
    if (!tls.cert_path.empty() && !tls.key_path.empty()) {
        config.tls_cert_path = tls.cert_path;
        config.tls_key_path  = tls.key_path;
    }

    // ========================================================================
    // WireGuard interface — server-side tunnel endpoint
    // ========================================================================
    nexus::wireguard::WireGuardService wireguard_service{
        "wg0", std::filesystem::path{config.data_root} / "wireguard"};
    wireguard_service.start();

    // Derive Curve25519 keypair from Ed25519 identity for WireGuard
    std::string wg_server_privkey_b64;
    if (root_privkey) {
        auto x_sk = nexus::crypto::SodiumCryptoService::ed25519_sk_to_x25519(*root_privkey);
        wg_server_privkey_b64 = nexus::crypto::to_base64(
            std::span<const uint8_t>(x_sk.data(), x_sk.size()));
    }

    // Set up the WireGuard interface with the server's tunnel IP
    if (!wg_server_privkey_b64.empty() && !tunnel_bind_ip.empty()) {
        nexus::wireguard::WgInterfaceConfig wg_iface;
        wg_iface.private_key = wg_server_privkey_b64;
        wg_iface.address     = tunnel_bind_ip + "/10";  // 10.64.0.0/10 mesh subnet
        wg_iface.listen_port = config.udp_port;

        if (wireguard_service.setup_interface(wg_iface, {})) {
            spdlog::info("WireGuard: wg0 up on :{} with tunnel IP {}/10",
                          config.udp_port, tunnel_bind_ip);
        } else {
            spdlog::warn("WireGuard: failed to set up wg0 — clients will not be able to connect. "
                          "Ensure wireguard-tools and kernel module are installed.");
        }
    } else {
        spdlog::warn("WireGuard: skipping wg0 setup (no identity key or tunnel IP)");
    }

    // ========================================================================
    // Backbone: server-to-server WireGuard mesh (172.16.0.0/22)
    // ========================================================================
    std::string backbone_ip;
    std::string wg_server_pubkey_b64;
    if (root_pubkey) {
        auto x_pk = nexus::crypto::SodiumCryptoService::ed25519_pk_to_x25519(*root_pubkey);
        wg_server_pubkey_b64 = nexus::crypto::to_base64(
            std::span<const uint8_t>(x_pk.data(), x_pk.size()));
    }

    if (!server_node_id.empty() && !wg_server_pubkey_b64.empty()) {
        auto ed25519_pubkey_b64 = nexus::crypto::to_base64(
            std::span<const uint8_t>(root_pubkey->data(), root_pubkey->size()));

        auto bb_alloc = ipam.allocate_backbone_ip(server_node_id, ed25519_pubkey_b64);
        backbone_ip = bb_alloc.base_network;
        // Strip CIDR for display
        auto slash = backbone_ip.find('/');
        auto backbone_ip_bare = (slash != std::string::npos) ? backbone_ip.substr(0, slash) : backbone_ip;

        // Add backbone address to wg0 (does NOT flush the existing client address)
        if (wireguard_service.add_address(backbone_ip_bare + "/22")) {
            spdlog::info("Backbone: added {}/22 to wg0", backbone_ip_bare);
        }

        // Wire gossip with WG service and backbone info
        gossip.set_wireguard(&wireguard_service);
        gossip.set_our_backbone_ip(backbone_ip_bare);
        gossip.set_our_wg_pubkey(wg_server_pubkey_b64);

        // Set up IPAM callback to broadcast backbone allocations via gossip
        ipam.set_backbone_callback(
            [&gossip](const nexus::ipam::BackboneAllocationDelta& delta) {
                gossip.broadcast_backbone_ipam_delta(delta);
            });

        spdlog::info("Backbone: server mesh on 172.16.0.0/22, our IP: {}, WG pubkey: {}",
                      backbone_ip_bare, wg_server_pubkey_b64.substr(0, 12) + "...");
    } else {
        spdlog::warn("Backbone: skipping (no server node ID or WG key)");
    }

    // ========================================================================
    // Private DNS records: private/backend FQDNs → tunnel/backbone IPs
    // ========================================================================
    {
        auto seip_id = nexus::core::resolve_server_node_id(storage);
        if (!seip_id.empty() && !config.region.empty()) {
            // private.<id>.<region>.seip.<domain> → server tunnel IP (for client HTTPS)
            if (!tunnel_bind_ip.empty()) {
                server_private_fqdn = "private." + seip_id + "." + config.region +
                                      ".seip." + config.dns_base_domain;
                dns.set_record(server_private_fqdn, "A", tunnel_bind_ip, 300);
                spdlog::info("DNS: private {} -> {}", server_private_fqdn, tunnel_bind_ip);
            }

            // backend.<id>.<region>.seip.<domain> → server backbone IP (for server-to-server)
            auto slash = backbone_ip.find('/');
            auto bb_bare = (slash != std::string::npos) ? backbone_ip.substr(0, slash) : backbone_ip;
            if (!bb_bare.empty()) {
                auto backend_fqdn = "backend." + seip_id + "." + config.region +
                                    ".seip." + config.dns_base_domain;
                dns.set_record(backend_fqdn, "A", bb_bare, 300);
                spdlog::info("DNS: backend {} -> {}", backend_fqdn, bb_bare);
            }
        }
    }

    // ========================================================================
    // HTTP Control Plane -- Dual-server architecture
    // ========================================================================
    nexus::network::HttpServer http_server{http_port, "0.0.0.0",
                                            tls.cert_path, tls.key_path};

    std::unique_ptr<nexus::network::HttpServer> private_http_server;
    if (!tunnel_bind_ip.empty()) {
        // Try to get/request ACME cert for the private FQDN
        std::string priv_cert_path, priv_key_path;
        if (!server_private_fqdn.empty() && config.auto_tls) {
            auto priv_tls = nexus::core::resolve_tls_cert(config, data_root, server_private_fqdn);
            if (!priv_tls.cert_path.empty() && !priv_tls.key_path.empty()) {
                priv_cert_path = priv_tls.cert_path;
                priv_key_path  = priv_tls.key_path;
                spdlog::info("Private API: using TLS cert for {}", server_private_fqdn);
            } else if (priv_tls.needs_acme_background) {
                spdlog::info("Private API: no cert for {} -- requesting in background", server_private_fqdn);
                // Request cert asynchronously — private API starts as HTTP initially,
                // will need restart to pick up the cert once ACME completes
                std::thread([&acme, fqdn = server_private_fqdn]() {
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                    (void)acme.request_certificate(fqdn);
                }).detach();
            }
        }

        if (!priv_cert_path.empty()) {
            private_http_server = std::make_unique<nexus::network::HttpServer>(
                config.private_http_port, tunnel_bind_ip, priv_cert_path, priv_key_path);
        } else {
            private_http_server = std::make_unique<nexus::network::HttpServer>(
                config.private_http_port, tunnel_bind_ip);
        }
        spdlog::info("Private API will bind to {}:{} ({})", tunnel_bind_ip,
                      config.private_http_port, priv_cert_path.empty() ? "HTTP" : "HTTPS");
    }

    auto& private_srv = private_http_server
        ? private_http_server->server()
        : http_server.server();
    if (!private_http_server) {
        spdlog::warn("SECURITY: No tunnel_bind_ip configured — private API routes "
                     "are exposed on the public HTTP server. Set a tunnel IP to "
                     "isolate authenticated endpoints to the WireGuard interface.");
    }

    // Rate limiter
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

    // ========================================================================
    // Register CRTP request handlers
    // ========================================================================
    nexus::api::ApiContext ctx{
        .config           = config,
        .auth             = auth_service,
        .tree             = tree,
        .ipam             = ipam,
        .gossip           = gossip,
        .crypto           = crypto,
        .key_wrapping     = key_wrapping,
        .storage          = storage,
        .acme             = acme,
        .http_server      = http_server,
        .ddns             = ddns,
        .relay            = relay,
        .relay_discovery  = relay_discovery,
        .attestation      = attestation,
        .tee              = tee,
        .trust_policy     = trust_policy,
        .governance       = governance,
        .wireguard        = &wireguard_service,
        .dns              = &dns,
        .server_fqdn      = server_fqdn,
        .server_seip_fqdn = server_seip_fqdn,
        .server_private_fqdn = server_private_fqdn,
        .server_public_ip = server_public_ip,
        .tunnel_bind_ip   = tunnel_bind_ip,
    };

    nexus::api::PublicApiHandler public_api{ctx};
    nexus::api::AuthApiHandler   auth_api{ctx};
    nexus::api::TreeApiHandler   tree_api{ctx};
    nexus::api::RelayApiHandler  relay_api{ctx};
    nexus::api::CertApiHandler   cert_api{ctx};
    nexus::api::AdminApiHandler  admin_api{ctx};
    nexus::api::MeshApiHandler   mesh_api{ctx};

    public_api.register_routes(http_server.server(), private_srv);
    auth_api.register_routes(http_server.server(), private_srv);
    tree_api.register_routes(http_server.server(), private_srv);
    relay_api.register_routes(http_server.server(), private_srv);
    cert_api.register_routes(http_server.server(), private_srv);
    admin_api.register_routes(http_server.server(), private_srv);
    mesh_api.register_routes(http_server.server(), private_srv);

    // ========================================================================
    // Start HTTP servers
    // ========================================================================
    http_server.start();
    if (private_http_server) {
        private_http_server->start();
    }

    // ========================================================================
    // UDP Hole Punch (separate port from WireGuard)
    // ========================================================================
    const uint16_t hole_punch_port = 51941;
    nexus::network::HolePunchService hole_punch{coordinator.io_context(), hole_punch_port};
    hole_punch.start();

    // ========================================================================
    // Run -- blocks until SIGINT/SIGTERM
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
    // Background ACME retry -- if no cert yet, retry every 5 minutes
    // ========================================================================
    std::atomic<bool> acme_retry_stop{false};
    std::thread acme_retry_thread;
    if (tls.needs_acme_background) {
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

                bool rate_limited = result.error_message.find("rateLimited") != std::string::npos
                                 || result.error_message.find("429") != std::string::npos
                                 || result.error_message.find("too many") != std::string::npos;

                if (rate_limited) {
                    current_interval = max_interval;
                    spdlog::warn("Auto-TLS: rate limited by ACME provider -- backing off to {} minutes",
                                  std::chrono::duration_cast<std::chrono::minutes>(current_interval).count());
                } else {
                    auto mins = std::chrono::duration_cast<std::chrono::minutes>(current_interval).count();
                    spdlog::warn("Auto-TLS: ACME retry failed -- retrying in {} minutes", mins);
                    auto doubled = current_interval * 2;
                    current_interval = doubled > max_interval ? max_interval : doubled;
                }

                for (auto elapsed = std::chrono::seconds(0);
                     elapsed < current_interval && !acme_retry_stop.load();
                     elapsed += std::chrono::seconds(1)) {
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                }

                if (rate_limited) {
                    current_interval = base_interval;
                }
            }
        });
    }

    // ========================================================================
    // Background ACME renewal -- check daily, renew when cert expires within 30 days
    // ========================================================================
    std::atomic<bool> acme_renewal_stop{false};
    std::thread acme_renewal_thread;
    if (!server_fqdn.empty() && config.auto_tls && !tls.needs_acme_background) {
        acme_renewal_thread = std::thread([&]() {
            constexpr auto initial_delay = std::chrono::hours(1);
            constexpr auto check_interval = std::chrono::hours(24);

            spdlog::info("Auto-TLS: certificate renewal monitor started for {} (checking daily)", server_fqdn);

            for (auto elapsed = std::chrono::seconds(0);
                 elapsed < initial_delay && !acme_renewal_stop.load();
                 elapsed += std::chrono::seconds(1)) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }

            while (!acme_renewal_stop.load()) {
                auto result = acme.renew_certificate(server_fqdn);
                if (result.success && !result.cert_path.empty()) {
                    spdlog::info("Auto-TLS: renewal check complete for {} (cert={})",
                                  server_fqdn, result.cert_path);
                }
                if (!result.success) {
                    spdlog::warn("Auto-TLS: renewal failed for {}: {}",
                                  server_fqdn, result.error_message);
                }

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
    wireguard_service.stop();
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
