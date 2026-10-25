#include <LemonadeNexus/Core/BootSet.hpp>
#include <LemonadeNexus/Core/CliModes.hpp>
#include <LemonadeNexus/Core/GenesisAnchor.hpp>
#include <LemonadeNexus/Core/Coordinator.hpp>
#include <LemonadeNexus/Core/HostnameGenerator.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Core/ServerIdentity.hpp>
#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/ACL/ACLService.hpp>
#include <LemonadeNexus/Network/HttpServer.hpp>
#include <LemonadeNexus/Network/RateLimiter.hpp>

// Lemonade-Nexus services
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Security/Storage/StorageVault.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeConsensus.hpp>
#include <LemonadeNexus/Tree/TreeOpSubmitter.hpp>
#include <LemonadeNexus/Tree/TreeRole.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Gossip/ServerCertificate.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <LemonadeNexus/Network/StunService.hpp>
#include <LemonadeNexus/Relay/RelayService.hpp>
#include <LemonadeNexus/Relay/RelayDiscoveryService.hpp>
#include <LemonadeNexus/Acme/AcmeService.hpp>
#include <LemonadeNexus/Network/DnsService.hpp>
#include <LemonadeNexus/Network/SeipNaming.hpp>
#include <LemonadeNexus/Core/BinaryAttestation.hpp>
#include <LemonadeNexus/Core/ServerAdmissionService.hpp>
#include <LemonadeNexus/Core/ApplicationRoot.hpp>
#include <LemonadeNexus/Core/SecurityMeshStartup.hpp>
#include <LemonadeNexus/Core/UpgradeControl.hpp>
#include <LemonadeNexus/Security/Attestation/LinuxAttestationProfile.hpp>
#include <LemonadeNexus/Security/Lifecycle/SecurityMeshService.hpp>
#include <LemonadeNexus/Security/PlatformProbe.hpp>
#include <LemonadeNexus/Security/Transport/AuthorityChainCodec.hpp>
#include <LemonadeNexus/Security/Sealing/SealedBlob.hpp>
#include <LemonadeNexus/Network/ApiTypes.hpp>
#include <LemonadeNexus/Network/DdnsService.hpp>
#include <LemonadeNexus/Boringtun/BoringtunService.hpp>
#include <LemonadeNexus/Boringtun/ForwardAuthorizer.hpp>
#include <LemonadeNexus/Network/VirtualNetService.hpp>

// CRTP request handlers
#include <LemonadeNexus/Api/PublicApiHandler.hpp>
#include <LemonadeNexus/Api/AuthApiHandler.hpp>
#include <LemonadeNexus/Api/Tier1ApiHandler.hpp>
#include <LemonadeNexus/Api/TreeApiHandler.hpp>
#include <LemonadeNexus/Api/TreeRouteGate.hpp>
#include <LemonadeNexus/Api/RelayApiHandler.hpp>
#include <LemonadeNexus/Api/CertApiHandler.hpp>
#include <LemonadeNexus/Api/AdminApiHandler.hpp>
#include <LemonadeNexus/Api/MeshApiHandler.hpp>
#include <LemonadeNexus/Api/OnboardApiHandler.hpp>
#include <LemonadeNexus/Api/AccountDataApiHandler.hpp>
#include <LemonadeNexus/Api/RoutingApiHandler.hpp>
#include <LemonadeNexus/Routing/RoutingCoordinationService.hpp>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#ifdef LEMONADE_HAVE_ATTESTD_CLIENT
#  include <LemonadeNexusAttestd/AttestdClient.hpp>
#endif

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <future>
#include <fstream>
#include <iterator>
#include <memory>
#include <mutex>
#include <optional>
#include <thread>
#include <unordered_set>

int main(int argc, char* argv[]) {
    // --- Load configuration: CLI args > env vars > config file > defaults ---
    auto config = nexus::core::load_config(argc, argv);
    spdlog::set_level(spdlog::level::from_str(config.log_level));
    spdlog::info("Lemonade-Nexus starting...");

    if (!nexus::core::validate_config(config)) {
        spdlog::error("Invalid configuration, exiting");
        return 1;
    }

    // The boot set (gossip identity) is sealed through nexus-attestd. Builds
    // without the attestd client have no sealing and keep identity/keypair.json.
    nexus::security::SealBackend seal_backend;
#ifdef LEMONADE_HAVE_ATTESTD_CLIENT
    seal_backend = nexus::attestd::attestd_seal_backend(nexus::attestd::AttestdClientConfig{});
#endif

    // --- CLI modes (--first-run, --enroll-server, ...) and the
    // uninitialized-data-dir gate live in Core/CliModes.cpp.
    if (auto rc = nexus::core::run_cli_mode(config, argv[0], seal_backend)) {
        return *rc;
    }

    const auto http_port   = config.http_port;
    const auto udp_port    = config.udp_port;
    const auto gossip_port = config.gossip_port;
    const auto stun_port   = config.stun_port;
    const auto relay_port  = config.relay_port;
    const auto dns_port    = config.dns_port;
    const auto public_dns_port = config.public_dns_port;

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
    if (!config.github_releases_url.empty()) {
        attestation.set_io_context(coordinator.io_context());
        attestation.set_github_config(config.github_releases_url,
                                       config.manifest_fetch_interval_sec,
                                       config.minimum_version);
    }

    // The old TEE/trust services are gone: attestation, eligibility, and
    // Tier 1 authority live in the mesh security system.

    // Phase 7: files under the data key. The vault always exists; its state
    // decides whether the services that read those files wait for the unlock
    // (below). A vault that cannot unlock serves no storage-dependent reads
    // or writes — never plaintext as a substitute.
    const auto vault_state_directory = data_root / "security" / "storage";
    std::unique_ptr<nexus::security::StorageVault> storage_vault =
        std::make_unique<nexus::security::StorageVault>(data_root, vault_state_directory, crypto);
    storage_vault->load();
    storage.set_vault(storage_vault.get());
    // Services that read files under the data key start only once it is in
    // memory. Gossip, attestation, and holder duties start without it (B8).
    const bool defer_file_services = !storage_vault->files_ready();

    // Only a current Tier 1 member holds the tree (TreeRole below). Until the
    // role says so the tree is closed: nothing is loaded and nothing written.
    nexus::tree::PermissionTreeService tree{storage, crypto};
    tree.close();

    nexus::ipam::IPAMService ipam{storage};
    ipam.start();

    // Load or auto-generate server identity keypair. Under the data key, a
    // file that exists but does not open stops startup instead of being
    // replaced.
    std::optional<nexus::crypto::Ed25519PrivateKey> root_privkey;
    std::optional<nexus::crypto::Ed25519PublicKey> root_pubkey;
    const auto load_node_identity = [&]() -> bool {
        root_privkey = key_wrapping.unlock_identity({});
        root_pubkey = key_wrapping.load_identity_pubkey();
        if (!root_privkey || !root_pubkey) {
            if (key_wrapping.identity_present()) {
                spdlog::error("identity/keypair.enc exists and does not open under the data "
                              "key; refusing to replace it");
                return false;
            }
            spdlog::info("No identity keypair found — generating one for this server");
            auto generated = key_wrapping.generate_and_store_identity({});
            root_privkey = generated.private_key;
            root_pubkey  = generated.public_key;
        }
        return true;
    };
    if (!defer_file_services && !load_node_identity()) {
        return 1;
    }


    // ========================================================================
    // Gossip (depends on storage + crypto, uses io_context)
    // ========================================================================
    // The gossip identity comes from the boot set: unsealed through
    // nexus-attestd when sealed, otherwise identity/keypair.json, which is
    // sealed here when this host can. A sealed identity that does not unseal
    // stops startup; a new identity is never created in its place.
    nexus::core::BootSetConfig boot_set;
    boot_set.data_root = data_root;
    boot_set.backend = seal_backend;
    if (const auto anchor = nexus::core::load_genesis_anchor(config.genesis_pubkey);
        anchor && anchor->release) {
        // Expected PCR 8/9 of the installed, verified approval: staged so a
        // boot-chain upgrade still unseals after its reboot.
        boot_set.next_boot_chain =
            nexus::security::boot_pcrs_from_approval(anchor->release->approval);
    }
    std::string boot_set_error;
    const auto gossip_identity =
        nexus::core::load_gossip_identity(storage, boot_set, boot_set_error);
    if (!gossip_identity) {
        spdlog::error("Boot set: {}", boot_set_error);
        return 1;
    }
    spdlog::info("Gossip identity protection: {}",
                 nexus::core::gossip_identity_protection_name(gossip_identity->protection));

    nexus::gossip::GossipService gossip{coordinator.io_context(), gossip_port, storage, crypto};
    gossip.set_identity(gossip_identity->keypair);
    if (!config.root_pubkey.empty()) {
        auto root_pk_bytes = nexus::crypto::from_hex(config.root_pubkey);
        if (root_pk_bytes.size() == nexus::crypto::kEd25519PublicKeySize) {
            nexus::crypto::Ed25519PublicKey root_pk{};
            std::memcpy(root_pk.data(), root_pk_bytes.data(), root_pk_bytes.size());
            gossip.set_root_pubkey(root_pk);
        }
    }
    gossip.set_ipam(&ipam);

    // Tree record transfer: the tree retains applied signed statements
    // through gossip's bounded pool (transfer only, never re-applies them),
    // and gossip evaluates received records against the tree's existing
    // operation-derived permissions.
    // In ops mode the committed tree log replaces this transfer.
    if (!config.tree_ops_enabled) {
        tree.set_delta_retention_sink(
            [&gossip](const nexus::storage::FileStorageService::RetainedDelta& rec) {
                return gossip.retain_local_delta(rec);
            });
    }
    gossip.set_tree(&tree);
    // No tree role before finalized membership says so: the record transfer
    // pool is not read, and tree log entries are neither taken nor served.
    gossip.set_tree_role(false);

    for (const auto& peer_endpoint : config.seed_peers) {
        gossip.add_peer(peer_endpoint, "");
    }

    // Resolve our region + public IP early (reused later for NS/SEIP setup).
    nexus::core::resolve_server_region(config, data_root);
    std::string server_public_ip = nexus::core::resolve_public_ip(config);
    if (!server_public_ip.empty()) {
        gossip.set_our_advertised_endpoint(
            server_public_ip + ":" + std::to_string(gossip_port));
    }
    // Region must be set before start: the first ServerHellos carry it (there is
    // no periodic re-hello), and a peer learned from a region-less hello never
    // gets a SEIP FQDN, so clients can't reach or fail over to it.
    gossip.set_our_region(config.region);

    gossip.start();

    // DNS seed discovery uses BLOCKING system DNS lookups for names this server may
    // itself be authoritative for, so it must NOT run on the startup path — it would
    // hang until our own DNS service is up. Run it detached; discovered peers are
    // added once they resolve and get a ServerHello on the next gossip tick. Self
    // entries are dropped by the gossip identity guard.
    if (config.dns_seed_discovery) {
        std::thread([&gossip,
                     base   = config.dns_base_domain,
                     region = config.region,
                     ip     = server_public_ip,
                     port   = config.gossip_port,
                     seeds  = config.seed_peers]() {
            auto found = nexus::core::discover_seed_endpoints(base, region, ip, port);
            std::unordered_set<std::string> existing(seeds.begin(), seeds.end());
            std::size_t added = 0;
            for (const auto& ep : found) {
                if (existing.insert(ep).second) { gossip.add_peer(ep, ""); ++added; }
            }
            spdlog::info("DNS discovery: seeded {} peer(s) from tier/region DNS (region '{}')",
                          added, region);
        }).detach();
    }


    // ========================================================================
    // Security mesh — unconditional in normal operation; start_security_mesh
    // is the only wiring. Constructed after gossip.start() because the gossip
    // identity keypair exists only then; declared after gossip so it is
    // destroyed first.
    // ========================================================================
    nexus::security::PlatformEvidenceSource platform_source;
    nexus::security::PlatformActivationSource activation_source;
#ifdef LEMONADE_HAVE_ATTESTD_CLIENT
    // Platform evidence and SVSM AK activation come from nexus-attestd over
    // its unix socket, so this process needs neither TPM access nor the
    // root-only IMA log. No in-process fallback: an absent or refusing daemon
    // fails closed at the verifier.
    {
        nexus::attestd::AttestdClientConfig attestd;
        platform_source = nexus::attestd::attestd_platform_source(attestd);
        activation_source = nexus::attestd::attestd_activation_source(attestd);
        std::error_code sock_ec;
        if (!std::filesystem::exists(attestd.path, sock_ec)) {
            spdlog::warn("nexus-attestd socket {} is absent; platform evidence will be "
                         "empty, SVSM AK activation will be refused, and every attestation "
                         "will fail until the daemon runs",
                         attestd.path.string());
        } else {
            spdlog::info("platform evidence source: nexus-attestd at {}",
                         attestd.path.string());
        }
    }
#endif
    std::string mesh_error;
    // The application root is created on Tier 1 entry (TreeRole below), not
    // when this node first holds epoch authority: the Genesis node issues the
    // bootstrap certificate without becoming a Tier 1 member, and a Tier 2
    // server holds no tree.
    auto security_mesh = nexus::core::start_security_mesh(
        coordinator.io_context(), config, gossip, key_wrapping,
        std::move(platform_source), std::move(activation_source), mesh_error, {},
        nexus::core::SecurityMeshStorageInputs{.seal_backend = seal_backend,
                                               .vault = storage_vault.get()});
    if (!security_mesh) {
        spdlog::error("Config: {}", mesh_error);
        return 1;
    }
    // The tree log, once it starts, for the updater's health report. The
    // control socket reads it on the security io thread; the guard after
    // tree_consensus clears it before the log is destroyed.
    struct TreeStatusSource {
        std::mutex mutex;
        const nexus::tree::TreeConsensus* tree = nullptr;
    } tree_status_source;
#if defined(LEMONADE_HAVE_UPGRADE_CONTROL)
    // The turn gate, health report, and boot-chain staging for nexus-updater:
    // root peers only. It starts before the data-key wait so the updater can
    // watch an unlock. Without the socket the updater waits.
    nexus::core::UpgradeControlConfig upgrade_control_config;
    upgrade_control_config.hooks.tree_status =
        [&tree_status_source]() -> std::optional<nexus::core::UpgradeTreeStatus> {
        std::lock_guard lock(tree_status_source.mutex);
        if (tree_status_source.tree == nullptr) return std::nullopt;
        const auto t = tree_status_source.tree->status_summary();
        return nexus::core::UpgradeTreeStatus{t.healthy, t.height, t.applied_height, t.behind,
                                              static_cast<uint64_t>(t.held)};
    };
    upgrade_control_config.hooks.stage_boot_chain =
        [staging = nexus::core::BootChainStagingInputs{
             std::filesystem::path(data_root) / std::string(nexus::core::kSealedDirectory),
             seal_backend}](const nexus::security::ReleaseApprovalBundleV1& accepted) {
            return nexus::core::stage_boot_chain_for_approval(staging, accepted);
        };
    auto upgrade_control = std::make_unique<nexus::core::UpgradeControlServer>(
        coordinator.io_context(), std::move(upgrade_control_config),
        [mesh = security_mesh->service.get()](std::function<void()> work) {
            mesh->post(std::move(work));
        },
        *security_mesh->service->upgrade());
    if (std::string control_error; !upgrade_control->start(control_error)) {
        spdlog::warn("Upgrade control socket unavailable ({}); nexus-updater cannot read "
                     "this server's turn or health",
                     control_error);
    }
#endif
    if (defer_file_services) {
        // Fail closed: the files are encrypted, so nothing that reads them
        // starts before t holders return the data key. There is no plaintext
        // fallback.
        spdlog::info("Waiting for the data key: files are encrypted and the services that "
                     "read them start after the unlock");
        std::atomic<bool> stop_requested{false};
        asio::signal_set unlock_signals{coordinator.io_context(), SIGINT, SIGTERM};
        unlock_signals.async_wait(
            [&stop_requested](const asio::error_code& ec, int) {
                if (!ec) stop_requested = true;
            });
        // The storage key can also find, after startup, that its records
        // belong to another epoch chain; then the files can never unlock.
        auto* storage_key = security_mesh->service->storage_key();
        const auto storage_halted = [storage_key] {
            return storage_key != nullptr && !storage_key->halt_reason().empty();
        };
        const bool unlocked = nexus::core::wait_for_storage_unlock(
            coordinator.io_context(), *storage_vault,
            [&] { return stop_requested.load() || storage_halted(); });
        unlock_signals.cancel();
        if (!unlocked) {
            if (storage_halted()) {
                spdlog::error("Storage: {}", storage_key->halt_reason());
                return 1;
            }
            spdlog::info("Stopped before the data key unlocked");
            return 0;
        }
        spdlog::info("Data key unlocked; starting the services that read encrypted files");
        if (!load_node_identity()) {
            return 1;
        }
    }
    // Legacy manifest consumers reuse the Genesis-delegated release authority;
    // config and environment never select this key.
    if (!security_mesh->release_signing_pubkey_b64.empty()) {
        attestation.set_release_signing_pubkey(
            security_mesh->release_signing_pubkey_b64);
    }
    attestation.start();

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
    // The mesh security system answers Tier 1 membership; an unset gate
    // denies inside DdnsService.
    ddns.set_tier1_gate([&security_mesh](std::string_view server_pk_b64) {
        if (!security_mesh) return false;
        const auto bytes = nexus::crypto::from_base64(
            nexus::crypto::canonical_key_b64(server_pk_b64));
        if (bytes.size() != nexus::crypto::kEd25519PublicKeySize) return false;
        nexus::security::NodeId node;
        std::memcpy(node.bytes.data(), bytes.data(), bytes.size());
        return security_mesh->service->is_current_member(node);
    });
    ddns.start();

    // Tier1-labelled DNS records assert finalized membership; the same source
    // that gates DDNS credentials gates them, and unset denies.
    gossip.set_tier1_membership_source([&security_mesh](const std::string& pk_b64) {
        if (!security_mesh) return false;
        const auto bytes = nexus::crypto::from_base64(pk_b64);
        if (bytes.size() != nexus::crypto::kEd25519PublicKeySize) return false;
        nexus::security::NodeId node;
        std::memcpy(node.bytes.data(), bytes.data(), bytes.size());
        return security_mesh->service->is_current_member(node);
    });

    // ========================================================================
    // STUN + Relay
    // ========================================================================
    nexus::network::StunService stun{coordinator.io_context(), stun_port, crypto, "lemonade-nexus-central"};
    stun.start();

    // Every server relays, Tier 1 and Tier 2 alike. A ticket is valid when a
    // current Tier 1 member signed it, by the membership the security mesh
    // verified from the authority chain; the relay needs no tree. The ticket
    // must also name this relay, by its base64 node identity key.
    nexus::relay::RelayService relay{coordinator.io_context(), relay_port, crypto};
    relay.set_relay_id(nexus::crypto::to_base64(
        std::span<const uint8_t>(gossip.keypair().public_key)));
    relay.set_ticket_authority(
        [mesh = security_mesh->service.get()]() -> std::optional<nexus::relay::RelayTicketAuthority> {
            const auto snapshot = mesh->membership();
            if (!snapshot.known) return std::nullopt;
            return nexus::relay::RelayTicketAuthority{mesh->network_id(), snapshot.epoch,
                                                      snapshot.members};
        });
    relay.start();

    nexus::relay::RelayDiscoveryService relay_discovery{storage};
    relay_discovery.start();

    // Routing-layer coordination control plane (fails closed without a root key).
    nexus::routing::RoutingCoordinationService routing{crypto, gossip};
    routing.start();

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
    // Phase 7: route the ACME account key and issued cert keys through the
    // storage vault (DEK-encrypted at rest). When files were locked at startup,
    // the unlock gate above already returned before reaching here, so the data
    // key is in memory and ACME may start and read/write keys through the vault.
    acme.set_vault(storage_vault.get());
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
        dns_ports.public_dns_port = public_dns_port;
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
    // (region already resolved before gossip.start() for DNS seed discovery)

    // NS hostname: explicit > derived from server_hostname. The special value
    // "none" (case-insensitive) opts this server out of NS slot claiming: it
    // claims no slot and releases any slot it still holds.
    bool ns_opt_out = false;
    {
        std::string probe = config.dns_ns_hostname;
        for (auto& c : probe) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        ns_opt_out = (probe == "none");
    }
    std::string ns_hostname = ns_opt_out ? "" : config.dns_ns_hostname;
    if (!ns_opt_out && ns_hostname.empty() && !config.server_hostname.empty()) {
        ns_hostname = config.server_hostname + "." + config.dns_base_domain;
        spdlog::info("DNS: auto-derived NS hostname: {}", ns_hostname);
    }

    // (server_public_ip already resolved before gossip.start() for DNS seed discovery)

    // Every server answers the zone apex with its own public address, even
    // one that holds no NS slot.
    if (!server_public_ip.empty()) dns.set_apex_address(server_public_ip);

    // Configure NS identity for SOA/NS responses
    if (!ns_hostname.empty() && !server_public_ip.empty()) {
        dns.set_our_nameserver(ns_hostname, server_public_ip);
        dns.add_nameserver(ns_hostname, server_public_ip);
        spdlog::info("DNS: registered as nameserver {} -> {}", ns_hostname, server_public_ip);
    } else if (!ns_hostname.empty()) {
        spdlog::warn("DNS: NS hostname '{}' configured but no public IP available -- skipping NS registration", ns_hostname);
    }

    acme.set_dns_service(&dns);

    // Publish SEIP records: <id>.<region>.seip.<domain> for geo-aware discovery
    dns.set_server_region(config.region);
    std::string server_seip_fqdn;
    std::string server_private_fqdn;
    {
        auto seip_id = nexus::core::resolve_server_node_id(storage);
        if (!seip_id.empty() && !config.region.empty() && !server_public_ip.empty()) {
            // No lowercasing here: main.cpp keeps the raw id/region case.
            server_seip_fqdn =
                nexus::seip::seipFqdn(seip_id, config.region, config.dns_base_domain);
            server_private_fqdn =
                nexus::seip::privateFqdn(seip_id, config.region, config.dns_base_domain);

            dns.publish_seip_records(seip_id, config.region, server_public_ip);
            spdlog::info("SEIP: published {} -> {}", server_seip_fqdn, server_public_ip);

            // Tier 1 = current epoch membership in the mesh security system.
            // Every enrolled server is at least Tier 2 transport.
            const int tier_num =
                (security_mesh &&
                 security_mesh->service->is_current_member(
                     nexus::security::NodeId{gossip.keypair().public_key}))
                    ? 1 : 2;
            dns.publish_tier_record(seip_id, config.region, tier_num, server_public_ip);

            // The public API cert (for the SEIP FQDN) is resolved below via
            // public_cert_fqdn — no per-FQDN handling needed here.
        }
    }

    // Publish _config TXT records (gossip-synced). After the SEIP block: host=
    // is the TLS certificate FQDN (docs/DNS-Discovery.md) that clients connect
    // to over verified HTTPS, so it must be the SEIP FQDN the cert is issued
    // for — the srv FQDN is only a cert target when SEIP isn't available (no
    // public IP), mirroring public_cert_fqdn below.
    {
        std::string config_fqdn = !server_seip_fqdn.empty()
            ? server_seip_fqdn
            : nexus::core::build_server_fqdn(config.server_hostname, config.dns_base_domain);

        // Determine the NS hostname prefix (e.g. "ns1" from "ns1.lemonade-nexus.io").
        // An opt-out node has no NS identity, so no ns-prefixed _config record.
        std::string ns_prefix;
        std::string ns_fqdn = ns_opt_out ? "" : config.dns_ns_hostname;
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

    dns.start();

    // NS slot claiming: first 9 servers claim ns1-ns9 for DNS bootstrap.
    // An explicit ns<N> identity pins the slot: the registrar's glue points
    // that exact name at this IP, so claiming any other slot would publish a
    // nameserver record the registry contradicts. "none" opts out: no slot
    // is claimed, and any slot this node still holds is released.
    gossip.set_dns_base_domain(config.dns_base_domain);
    if (ns_opt_out) {
        gossip.set_ns_opt_out(true);
        spdlog::info("NS slot: opt-out (dns_ns_hostname=none) — not claiming a slot");
        if (auto slot = gossip.our_ns_slot()) {
            gossip.release_ns_slot(*slot);
        }
    } else {
        if (!ns_hostname.empty()) {
            auto dot = ns_hostname.find('.');
            auto label = ns_hostname.substr(0, dot == std::string::npos ? ns_hostname.size() : dot);
            if (label.size() == 3 && label.starts_with("ns") &&
                label[2] >= '1' && label[2] <= '9') {
                gossip.set_preferred_ns_slot(static_cast<uint8_t>(label[2] - '0'));
            }
        }
        if (!server_public_ip.empty()) {
            gossip.try_claim_ns_slot(server_public_ip);
            if (auto slot = gossip.our_ns_slot()) {
                spdlog::info("SEIP: claimed NS slot ns{} for {}", *slot, server_public_ip);
            }
        }
    }

    // ========================================================================
    // Auth + ACL
    // ========================================================================
    auto jwt_secret_hex =
        nexus::core::resolve_jwt_secret(config, data_root, crypto, storage_vault.get());
    if (jwt_secret_hex.empty()) {
        spdlog::error("The JWT secret is not available; refusing to replace it");
        return 1;
    }

    nexus::auth::AuthService auth_service{storage, crypto,
                                           config.rp_id, jwt_secret_hex};
    auth_service.start();

    // Link tokens (invites) replicate between Tier 1 servers over the
    // backbone, so any Tier 1 server redeems them. Events are signed with the
    // gossip identity under their own domain and name a token only by its
    // hash; no server stores or sends the token. Without tree operations a
    // redemption waits for a concurrent redemption on another server to
    // arrive before it is used; with them, consensus orders the redemption.
    auth_service.set_link_token_replication(
        [&gossip](nexus::auth::LinkTokenEvent& e) { return gossip.sign_link_token_event(e); },
        [&gossip](const nexus::auth::LinkTokenEvent& e) {
            return gossip.broadcast_link_token_event(e);
        },
        config.tree_ops_enabled ? std::chrono::milliseconds{0}
                                : nexus::auth::TokenLinkAuthProvider::kDefaultSettleWindow);
    gossip.set_link_token_sink([&auth_service](const nexus::auth::LinkTokenEvent& e) {
        return auth_service.apply_replicated_link_token(e);
    });

    auto acl_db_path = std::filesystem::path{config.data_root} / "acl.db";
    nexus::acl::AclStore acl_store{acl_db_path};
    nexus::acl::ACLService acl_service{acl_store, crypto};
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

    // Clients reach the public API at the SEIP FQDN, so its certificate must
    // cover that name (fall back to the srv FQDN only when SEIP isn't set, e.g.
    // no public IP). The background ACME thread and renewal use the same target.
    const std::string public_cert_fqdn =
        !server_seip_fqdn.empty() ? server_seip_fqdn : server_fqdn;
    auto tls = nexus::core::resolve_tls_cert(data_root, public_cert_fqdn, storage_vault.get());

    // ========================================================================
    // boringtun interface — server-side tunnel endpoint
    // ========================================================================
    nexus::boringtun::BoringtunService boringtun_service{
        config.mesh_interface, std::filesystem::path{config.data_root} / "mesh"};
    boringtun_service.start();

    // In-process traffic termination: the userspace netstack answers on our
    // virtual IPs and bridges to the (unchanged) httplib private API. Wire the
    // dataplane <-> netstack seam before the dataplane starts taking packets.
    nexus::network::VirtualNetService vnet{};
    vnet.start();
    boringtun_service.dataplane().set_inbound_handler(
        [&vnet](std::span<const uint8_t> pkt) { vnet.deliver_inbound_ip_packet(pkt); });
    vnet.set_outbound_sink([&boringtun_service](std::span<const uint8_t> pkt) {
        boringtun_service.dataplane().send_outbound_ip_packet(pkt);
    });

    // Derive Curve25519 keypair from Ed25519 identity for the mesh
    std::string mesh_server_private_key_b64;
    if (root_privkey) {
        auto x_sk = nexus::crypto::SodiumCryptoService::ed25519_sk_to_x25519(*root_privkey);
        mesh_server_private_key_b64 = nexus::crypto::to_base64(
            std::span<const uint8_t>(x_sk.data(), x_sk.size()));
    }

    // Forwarding between two client endpoints follows the permission tree: a
    // client's server peer covers the whole plane, so without this policy any
    // joined endpoint could reach any other through the server. The deny
    // policy goes in before the dataplane takes peers and stays while this
    // server holds no tree: a Tier 2 server forwards no packet between
    // dataplane peers. It carries endpoint traffic only as the relay service
    // (ciphertext between ticket holders), never as endpoint forwarding.
    // TreeRole starts the authorizer on Tier 1 entry and restores the deny
    // policy when the server leaves Tier 1. Without a known plane the policy
    // cannot be built, so forwarding stays denied.
    boringtun_service.dataplane().set_forward_policy(nexus::boringtun::deny_forward_policy());
    std::optional<nexus::boringtun::ForwardAuthorizer> forward_authorizer;
    if (!tunnel_bind_ip.empty()) {
        if (auto plane = nexus::boringtun::Cidr::parse(tunnel_bind_ip + "/10")) {
            forward_authorizer.emplace(tree, boringtun_service.dataplane(), *plane);
        }
    }
    if (!forward_authorizer) {
        spdlog::error("boringtun: tunnel IP '{}' is {}; the dataplane forwards no packets "
                      "between peers",
                      tunnel_bind_ip, tunnel_bind_ip.empty() ? "not set" : "not an IPv4 address");
    }

    // Set up the boringtun interface with the server's tunnel IP
    if (!mesh_server_private_key_b64.empty() && !tunnel_bind_ip.empty()) {
        nexus::boringtun::BoringtunInterfaceConfig mesh_interface_config;
        mesh_interface_config.private_key = mesh_server_private_key_b64;
        mesh_interface_config.address     = tunnel_bind_ip + "/10";  // 10.64.0.0/10 mesh subnet
        mesh_interface_config.listen_port = config.udp_port;

        if (boringtun_service.setup_interface(mesh_interface_config, {})) {
            // The netstack answers on our tunnel IP across the whole client plane.
            vnet.add_local_ip(tunnel_bind_ip + "/10");
            spdlog::info("boringtun: userspace dataplane up on :{} with tunnel IP {}/10",
                          config.udp_port, tunnel_bind_ip);
        } else {
            spdlog::warn("boringtun: failed to start userspace dataplane on :{} — "
                          "clients will not be able to connect.", config.udp_port);
        }
    } else {
        spdlog::warn("boringtun: skipping {} setup (no identity key or tunnel IP)",
                     config.mesh_interface);
    }

    // ========================================================================
    // Backbone: server-to-server boringtun mesh (172.16.0.0/22)
    // ========================================================================
    std::string backbone_ip;
    std::string mesh_server_public_key_b64;
    if (root_pubkey) {
        auto x_pk = nexus::crypto::SodiumCryptoService::ed25519_pk_to_x25519(*root_pubkey);
        mesh_server_public_key_b64 = nexus::crypto::to_base64(
            std::span<const uint8_t>(x_pk.data(), x_pk.size()));
    }

    if (!server_node_id.empty() && !mesh_server_public_key_b64.empty()) {
        // Keyed on the gossip identity: it signs and is named in the backbone
        // claim peers verify. An existing allocation is returned unchanged.
        auto gossip_pubkey_b64 = nexus::crypto::to_base64(gossip.keypair().public_key);

        auto bb_alloc = ipam.allocate_backbone_ip(server_node_id, gossip_pubkey_b64);
        backbone_ip = bb_alloc.base_network;
        // Strip CIDR for display
        auto slash = backbone_ip.find('/');
        auto backbone_ip_bare = (slash != std::string::npos) ? backbone_ip.substr(0, slash) : backbone_ip;

        // Register the backbone address as a second virtual local IP (both the
        // dataplane router and the netstack must answer for it).
        if (boringtun_service.add_address(backbone_ip_bare + "/22")) {
            vnet.add_local_ip(backbone_ip_bare + "/22");
            spdlog::info("Backbone: registered virtual {}/22", backbone_ip_bare);
        }

        // Give gossip the mesh dataplane, the backbone identity it announces
        // to peers, and the virtual netstack that carries catch-up sync over
        // the backbone.
        gossip.set_boringtun(&boringtun_service);
        gossip.set_our_mesh_pubkey(mesh_server_public_key_b64);
        gossip.set_our_backbone_claim(server_node_id, backbone_ip_bare);
        gossip.set_virtual_net(&vnet);

        // Set up IPAM callback to broadcast backbone allocations via gossip
        ipam.set_backbone_callback(
            [&gossip](const nexus::ipam::BackboneAllocationDelta& delta) {
                gossip.broadcast_backbone_ipam_delta(delta);
            });

        spdlog::info("Backbone: server mesh on 172.16.0.0/22, our IP: {}, mesh public key: {}",
                      backbone_ip_bare, mesh_server_public_key_b64.substr(0, 12) + "...");
    } else {
        spdlog::warn("Backbone: skipping (no server node ID or mesh key)");
    }

    // ========================================================================
    // Private DNS records: private/backend FQDNs → tunnel/backbone IPs
    // ========================================================================
    {
        auto seip_id = nexus::core::resolve_server_node_id(storage);
        if (!seip_id.empty() && !config.region.empty()) {
            // private.<id>.<region>.seip.<domain> → server tunnel IP (for client HTTPS)
            if (!tunnel_bind_ip.empty()) {
                server_private_fqdn =
                    nexus::seip::privateFqdn(seip_id, config.region,
                                             config.dns_base_domain);
                dns.set_record(server_private_fqdn, "A", tunnel_bind_ip, 300);
                spdlog::info("DNS: private {} -> {}", server_private_fqdn, tunnel_bind_ip);
            }

            // backend.<id>.<region>.seip.<domain> → server backbone IP (for server-to-server)
            auto slash = backbone_ip.find('/');
            auto bb_bare = (slash != std::string::npos) ? backbone_ip.substr(0, slash) : backbone_ip;
            if (!bb_bare.empty()) {
                auto backend_fqdn =
                    nexus::seip::backendFqdn(seip_id, config.region,
                                             config.dns_base_domain);
                dns.set_record(backend_fqdn, "A", bb_bare, 300);
                spdlog::info("DNS: backend {} -> {}", backend_fqdn, bb_bare);
            }
        }
    }

    // ========================================================================
    // HTTP Control Plane -- Dual-server architecture
    // ========================================================================
    // When the TLS key is vault-covered (Phase 7) the key arrives in memory; the
    // cert is still opened by path. Fail closed: while the DEK is locked the key
    // cannot be read, tls.valid stays false, and the HTTPS listener is withheld
    // (no plaintext interim) until the background ACME/upgrade path brings it up.
    nexus::network::HttpServer http_server{http_port, "0.0.0.0"};
    if (tls.cert_path.empty()) {
        // No cert on disk yet — ACME background path will issue it and upgrade.
    } else if (!tls.key_bytes.empty()) {
        // Key is vault-covered and decrypted: enable HTTPS from the in-memory key.
        if (!http_server.enable_tls_inmemory_key(tls.cert_path, tls.key_bytes, tls.key_path)) {
            spdlog::warn("Public API: HTTPS withheld — in-memory TLS key could not be enabled");
        }
    } else {
        // Plaintext key on disk (pre-key state).
        if (!http_server.enable_tls_from_paths(tls.cert_path, tls.key_path)) {
            spdlog::warn("Public API: HTTPS withheld — TLS cert/key could not be enabled");
        }
    }

    std::unique_ptr<nexus::network::HttpServer> private_http_server;
    bool private_needs_acme = false;   // request + upgrade the private cert in the background
    if (!tunnel_bind_ip.empty()) {
        // Resolve the PRIVATE cert independently of the public one — its ACME
        // cert is the one issued for server_private_fqdn (never the public SEIP
        // cert).
        std::string priv_cert_path, priv_key_path;
        std::string priv_key_bytes;   // in-memory key when vault-covered
        if (!server_private_fqdn.empty()) {
            auto priv_tls = nexus::core::resolve_tls_cert(data_root, server_private_fqdn, storage_vault.get());
            if (!priv_tls.cert_path.empty() && !priv_tls.key_path.empty()) {
                priv_cert_path = priv_tls.cert_path;
                priv_key_path  = priv_tls.key_path;
                priv_key_bytes = priv_tls.key_bytes;
                spdlog::info("Private API: using TLS cert for {}", server_private_fqdn);
            } else if (priv_tls.needs_acme_background) {
                // The private API is withheld until its cert issues; the unified
                // background ACME thread below requests it and upgrades the
                // listener in place (no restart, no plaintext interim).
                spdlog::info("Private API: no cert for {} -- requesting + upgrading in background",
                             server_private_fqdn);
                private_needs_acme = true;
            }
        }

        auto priv_srv = std::make_unique<nexus::network::HttpServer>(
            config.private_http_port, tunnel_bind_ip);
        if (!priv_cert_path.empty()) {
            if (!priv_key_bytes.empty()) {
                if (!priv_srv->enable_tls_inmemory_key(priv_cert_path, priv_key_bytes, priv_key_path)) {
                    spdlog::warn("Private API: HTTPS withheld — in-memory TLS key could not be enabled");
                }
            } else {
                if (!priv_srv->enable_tls_from_paths(priv_cert_path, priv_key_path)) {
                    spdlog::warn("Private API: HTTPS withheld — TLS cert/key could not be enabled");
                }
            }
        }
        private_http_server = std::move(priv_srv);

        // The private API has no kernel tunnel address to bind anymore. Bind it
        // to loopback and let the in-process netstack pipe virtual TCP from the
        // tunnel/backbone IPs to it. Reaching loopback:private_http_port is no
        // more exposed than the old kernel bind to the (local) tunnel IP was,
        // and every private route is JWT-gated.
        private_http_server->set_bind_address("127.0.0.1");
        std::string bridge_target =
            "tcp:127.0.0.1:" + std::to_string(config.private_http_port);

        // Answer for the private API on both the client-tunnel IP and the
        // server backbone IP (the latter fixes the previously-unserved
        // backend.<id> record). Backbone IP is registered after allocation.
        vnet.add_tcp_forward(tunnel_bind_ip, config.private_http_port, bridge_target);
        {
            auto slash = backbone_ip.find('/');
            auto bb_bare = (slash != std::string::npos) ? backbone_ip.substr(0, slash) : backbone_ip;
            if (!bb_bare.empty())
                vnet.add_tcp_forward(bb_bare, config.private_http_port, bridge_target);
        }

        spdlog::info("Private API on virtual {}:{} ({}) via {}", tunnel_bind_ip,
                      config.private_http_port, priv_cert_path.empty() ? "HTTP" : "HTTPS",
                      bridge_target);
    }

    if (!private_http_server) {
        spdlog::warn("SECURITY: No tunnel_bind_ip configured — private API routes "
                     "are exposed on the public HTTP server. Set a tunnel IP to "
                     "isolate authenticated endpoints to the mesh interface.");
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

    // ========================================================================
    // Server onboarding (admission of new servers over the public API)
    // ========================================================================
    nexus::core::ServerAdmissionService admission{
        config, crypto, key_wrapping, storage, gossip};
    admission.set_network_id(security_mesh->network_id_hex);
    admission.start();

    // ========================================================================
    // Experimental tree operations (Phases 2 and 3), off by default:
    //   --tree-log  read-only log: build and replicate it, writes stay direct
    //   --tree-ops  ops: Tier 1 consensus orders writes, every Tier 1 member
    //               applies the committed (or replicated) log
    // The objects live for the process; the tree log runs only while this
    // server holds the tree (TreeRole below starts and stops it).
    // ========================================================================
    std::unique_ptr<nexus::tree::TreeConsensus> tree_consensus;
    // Destroyed before tree_consensus on every exit path: the control socket
    // reads the tree log status.
    struct ClearTreeStatus {
        TreeStatusSource& source;
        ~ClearTreeStatus() {
            std::lock_guard lock(source.mutex);
            source.tree = nullptr;
        }
    } clear_tree_status{tree_status_source};
    std::unique_ptr<nexus::tree::TreeOpSubmitter> tree_ops;
    std::function<std::optional<nexus::tree::TreeOpOutcome>(const std::string&)> tree_op_status;
    std::function<nlohmann::json()> tree_log_status;
    std::function<void()> sync_ipam;
    auto* mesh = security_mesh->service.get();
    if (config.tree_ops_enabled || config.tree_log_enabled) {
        const bool ops_mode = config.tree_ops_enabled;
        const auto network_bytes = nexus::crypto::from_hex(security_mesh->network_id_hex);
        nexus::security::NetworkId network_id{};
        if (network_bytes.size() != network_id.size()) {
            spdlog::error("Config: tree operations need the Genesis network id");
            return 1;
        }
        std::copy(network_bytes.begin(), network_bytes.end(), network_id.begin());
        nexus::security::NodeId self{};
        self.bytes = gossip.keypair().public_key;
        const std::string root_key =
            nexus::core::root_principal_from_hex(config.root_pubkey).value_or("");

        nexus::tree::TreeConsensusConfig tree_config;
        tree_config.self = self;
        tree_config.network_id = network_id;
        tree_config.root_key = root_key;
        tree_config.mode = ops_mode ? nexus::tree::TreeLogMode::Ops
                                    : nexus::tree::TreeLogMode::ReadOnly;
        tree_config.vault = storage_vault.get();
        tree_config.wall_clock_ms = [] {
            return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                             std::chrono::system_clock::now().time_since_epoch())
                                             .count());
        };
        // Not started here: until TreeRole starts it on Tier 1 entry the
        // handler is halted and refuses every block, op, and entry.
        tree_consensus = std::make_unique<nexus::tree::TreeConsensus>(
            std::move(tree_config), tree, crypto,
            std::filesystem::path(data_root) / "tree" / "log");
        auto* consensus = tree_consensus.get();

        // Replication (design A7) between Tier 1 members. Entries are
        // verified against the driver's verified authority chain and the
        // configured root key, on the security io thread; the sync stream
        // only carries bytes.
        consensus->set_authority_source([mesh](nexus::security::EpochId epoch) {
            return mesh->authority_for_epoch(epoch);
        });
        consensus->set_epoch_hint(
            [mesh](nexus::security::EpochId epoch) { mesh->note_epoch_hint(epoch); });
        consensus->set_appended_hook([&gossip](uint64_t height) { gossip.offer_tree_height(height); });
        gossip.enable_tree_stream(
            [consensus](uint64_t height) { return consensus->encoded_entry(height); },
            [consensus, mesh](std::vector<uint8_t> bytes) {
                mesh->post([consensus, bytes = std::move(bytes)] {
                    const auto entry = nexus::tree::decode_replicated_entry(bytes);
                    if (!entry) {
                        spdlog::warn("[tree] dropped a malformed replicated tree log entry");
                        return;
                    }
                    (void)consensus->receive_replicated(*entry);
                });
            });
        tree_log_status = [consensus, &gossip] {
            const auto s = consensus->status_summary();
            nlohmann::json out = gossip.tree_sync_status();
            out["mode"] = s.mode == nexus::tree::TreeLogMode::Ops ? "ops" : "read-only";
            out["healthy"] = s.healthy;
            out["halt_reason"] = s.halt_reason;
            out["height"] = s.height;
            out["applied_height"] = s.applied_height;
            out["state_root"] = nexus::crypto::to_base64(s.root);
            out["behind"] = s.behind;
            out["held_entries"] = s.held;
            out["last_refusal"] = s.last_refusal;
            return out;
        };

        if (ops_mode) {
            // The committed log carries tree changes between Tier 1 members,
            // so the record transfer pool for tree records is retired.
            gossip.retire_tree_transfer();
            // Tree-derived tunnel addresses are recorded in the IPAM file.
            sync_ipam = [&tree, &ipam] {
                std::map<std::string, std::string> assigned;
                for (const auto& [id, node] : tree.nodes_snapshot()) {
                    if (!node.tunnel_ip.empty()) assigned.emplace(id, node.tunnel_ip);
                }
                (void)ipam.sync_tree_tunnel_addresses(assigned);
            };
            consensus->set_applied_hook(sync_ipam);

            // Ops are signed with this server's gossip identity under their own
            // domain tag; the key never leaves GossipService.
            tree_ops = std::make_unique<nexus::tree::TreeOpSubmitter>(
                tree, crypto, network_id, gossip.keypair(),
                [consensus](nexus::tree::TreeOp op) { return consensus->submit(std::move(op)); },
                std::chrono::milliseconds(nexus::tree::kTreeOpCommitWaitMs));
            tree_ops->set_root_key(root_key);
            consensus->set_broadcast([mesh](nexus::security::TreeOpSubmitMsg message) {
                mesh->broadcast_tree_op(std::move(message));
            });
            consensus->set_root_request([submitter = tree_ops.get(), root_key] {
                nexus::tree::TreeOp op;
                op.kind = nexus::tree::TreeOpKind::EstablishRoot;
                op.target = "root";
                op.principal = root_key;
                op.body.source = nexus::tree::TreeOpSource::Session;
                const auto admission = submitter->submit_async(std::move(op));
                if (!admission.verdict.ok()) {
                    spdlog::warn("[tree] root operation not submitted: {}",
                                 admission.verdict.reason);
                }
            });
            mesh->register_payload_handler(*consensus);
            mesh->set_tree_op_sink([consensus](const nexus::security::TreeOpSubmitMsg& message,
                                               const nexus::security::NodeId& from) {
                consensus->receive_forwarded(message, from);
            });
            tree_op_status = [consensus](const std::string& op_id) {
                return consensus->status(op_id);
            };
            spdlog::warn("EXPERIMENTAL: tree operations enabled (ops mode). Tier 1 orders tree "
                         "writes through consensus and every Tier 1 member applies the "
                         "committed log; a member that joins or lags catches up by replication "
                         "from Tier 1. A Tier 2 server holds no tree.");
        } else {
            spdlog::warn("EXPERIMENTAL: tree log enabled (read-only mode). Tier 1 members build "
                         "and replicate the tree log; tree writes keep the direct paths.");
        }
    }

    // ========================================================================
    // Tree role: only a current Tier 1 member, by finalized epoch membership,
    // holds the tree. Entering Tier 1 loads the tree and starts the tree
    // services; leaving stops them and deletes the tree files. A server whose
    // membership is not known yet (before Epoch 1 activates) holds no tree and
    // deletes nothing.
    // ========================================================================
    const nexus::security::NodeId self_node{gossip.keypair().public_key};
    nexus::tree::TreeRole tree_role{nexus::tree::TreeRole::Hooks{
        .enter =
            [&] {
                storage.ensure_tree_directories();
                tree.start();
                // With tree operations on, the root is an EstablishRoot op that
                // Tier 1 commits (TreeConsensus::set_root_request); a direct
                // write would bypass consensus.
                if (!config.tree_ops_enabled) {
                    nexus::core::ensure_application_root(tree, config.root_pubkey);
                }
                gossip.set_tree_role(true);
                if (tree_consensus) {
                    if (!tree_consensus->start()) {
                        // Fail closed: the server serves its last committed
                        // tree but applies, votes for, and accepts no tree
                        // operation. The updater's health report shows the
                        // halt.
                        spdlog::error("EXPERIMENTAL tree operations halted at Tier 1 entry: {}",
                                      tree_consensus->halt_reason());
                    }
                    // Only a server that holds the tree reports a tree log to
                    // the updater; a Tier 2 server reports its own status only.
                    {
                        std::lock_guard lock(tree_status_source.mutex);
                        tree_status_source.tree = tree_consensus.get();
                    }
                    for (uint64_t height = 1;
                         height <= tree_consensus->status_summary().height; ++height) {
                        gossip.offer_tree_height(height);
                    }
                }
                if (sync_ipam) sync_ipam();
                if (forward_authorizer) forward_authorizer->start();
                return true;
            },
        .leave =
            [&] {
                if (forward_authorizer) forward_authorizer->stop();
                boringtun_service.dataplane().set_forward_policy(
                    nexus::boringtun::deny_forward_policy());
                gossip.set_tree_role(false);
                {
                    std::lock_guard lock(tree_status_source.mutex);
                    tree_status_source.tree = nullptr;
                }
                if (tree_consensus) tree_consensus->deactivate("this server is not in Tier 1");
                tree.close();
                // Tree-range tunnel records are a copy of tree data.
                if (sync_ipam) (void)ipam.sync_tree_tunnel_addresses({});
            },
        .purge =
            [&] {
                (void)storage.purge_tree_files();
                // Invites are tree state: a server outside Tier 1 keeps none.
                auth_service.purge_link_tokens();
                gossip.purge_link_tokens();
            },
    }};
    const auto update_tree_role = [&tree_role, mesh, self_node, vault = storage_vault.get()] {
        const auto snapshot = mesh->membership();
        auto view = nexus::tree::MembershipView::Unknown;
        if (snapshot.known) {
            view = std::find(snapshot.members.begin(), snapshot.members.end(), self_node) !=
                           snapshot.members.end()
                       ? nexus::tree::MembershipView::Member
                       : nexus::tree::MembershipView::NonMember;
        }
        tree_role.update(view, vault == nullptr || vault->files_ready());
        return snapshot;
    };
    // The io thread is not running yet, so this first update runs here: a
    // Tier 1 member serves the tree as soon as its listeners start, and a
    // Tier 2 server deletes a tree an older release left before it serves.
    (void)update_tree_role();
    mesh->set_tick_hook([update_tree_role, &tree_role, consensus = tree_consensus.get()] {
        const auto snapshot = update_tree_role();
        if (consensus && tree_role.holds_tree()) {
            consensus->set_members(snapshot.members);
            consensus->maintain();
        }
    });

    spdlog::warn("Storage key (Phase 5) and files under the data key (Phase 7) run on every "
                 "server: Tier 1 finalizes storage holder plans and key rotations, this server "
                 "keeps a data key wrapped to the storage key, and its identity, JWT secret, "
                 "DDNS credentials, account replica, and tree files are encrypted after an unlock "
                 "round trip through the holders. Mode: {}.",
                 storage_vault->mode() == nexus::security::VaultMode::Encrypted
                     ? "encrypted"
                     : "plaintext, pre-key or migrating");

    // The rollout proof for the release workflow's guard. It is built on the
    // security io thread; the HTTP thread waits a bounded time and reuses a
    // proof for a few seconds so an unauthenticated caller cannot keep that
    // thread busy.
    struct RolloutProofCache {
        std::mutex mutex;
        std::chrono::steady_clock::time_point built{};
        std::optional<std::string> proof;
    };
    auto rollout_proof_cache = std::make_shared<RolloutProofCache>();
    std::function<std::optional<std::string>()> rollout_proof =
        [cache = rollout_proof_cache,
         mesh = security_mesh->service.get()]() -> std::optional<std::string> {
        std::lock_guard lock(cache->mutex);
        const auto now = std::chrono::steady_clock::now();
        if (cache->built != std::chrono::steady_clock::time_point{} &&
            now - cache->built < std::chrono::seconds(10)) {
            return cache->proof;
        }
        auto promise = std::make_shared<std::promise<std::optional<std::string>>>();
        auto future = promise->get_future();
        mesh->post([promise, mesh] { promise->set_value(mesh->rollout_proof_json()); });
        if (future.wait_for(std::chrono::seconds(5)) != std::future_status::ready) {
            return std::nullopt;
        }
        cache->proof = future.get();
        cache->built = now;
        return cache->proof;
    };

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
        .routing          = routing,
        .attestation      = attestation,
        .admission        = admission,
        .boringtun        = &boringtun_service,
        .dns              = &dns,
        .server_fqdn      = server_fqdn,
        .server_seip_fqdn = server_seip_fqdn,
        .server_private_fqdn = server_private_fqdn,
        .server_public_ip = server_public_ip,
        .tunnel_bind_ip   = tunnel_bind_ip,
        .tree_ops         = tree_ops.get(),
        .tree_op_status   = tree_op_status,
        .tree_log_status  = tree_log_status,
        .storage_vault    = storage_vault.get(),
        // Any server serves the chain: it is candidate data the client
        // verifies against its pinned Genesis key.
        .authority_chain_page =
            [mesh](uint64_t have_epoch) -> std::vector<uint8_t> {
                const auto page = mesh->authority_chain_page(nexus::security::EpochId{have_epoch},
                                                             std::chrono::seconds(2));
                return page ? nexus::security::encode_authority_chain_page(*page)
                            : std::vector<uint8_t>{};
            },
        // A member proves its endpoint only while it holds and serves the tree.
        .tier1_identity =
            [mesh, self_node, &tree_role]() -> std::optional<nexus::api::Tier1Identity> {
                if (!tree_role.holds_tree()) return std::nullopt;
                const auto snapshot = mesh->membership();
                if (!snapshot.known ||
                    std::find(snapshot.members.begin(), snapshot.members.end(), self_node) ==
                        snapshot.members.end()) {
                    return std::nullopt;
                }
                nexus::api::Tier1Identity identity;
                const auto network = mesh->network_id();
                std::copy(network.begin(), network.end(), identity.network_id.begin());
                identity.epoch = snapshot.epoch.underlying();
                return identity;
            },
        .rollout_proof    = rollout_proof,
    };

    nexus::api::PublicApiHandler public_api{ctx};
    nexus::api::AuthApiHandler   auth_api{ctx};
    nexus::api::TreeApiHandler   tree_api{ctx};
    nexus::api::RelayApiHandler  relay_api{ctx};
    nexus::api::CertApiHandler   cert_api{ctx};
    nexus::api::AdminApiHandler  admin_api{ctx};
    nexus::api::MeshApiHandler   mesh_api{ctx};
    nexus::api::RoutingApiHandler routing_api{ctx};
    nexus::api::OnboardApiHandler onboard_api{ctx};
    nexus::api::AccountDataApiHandler account_data_api{ctx};
    nexus::api::Tier1ApiHandler  tier1_api{ctx};

    // Rate limit first, then the tree gate: on a server that does not hold
    // the tree every tree route answers a plain 421 (TreeRouteGate.hpp).
    const std::function<bool()> holds_tree = [&tree_role] { return tree_role.holds_tree(); };
    auto pre_routing_handler = [&rate_limit_handler, &holds_tree](
                                   const httplib::Request& req,
                                   httplib::Response& res) -> httplib::Server::HandlerResponse {
        if (rate_limit_handler(req, res) == httplib::Server::HandlerResponse::Handled) {
            return httplib::Server::HandlerResponse::Handled;
        }
        if (nexus::api::gate_tree_route(req, res, holds_tree)) {
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
    };

    // Route registration is factored into a lambda so it can be re-run if the
    // underlying server object is replaced (e.g. plain HTTP -> HTTPS upgrade after
    // a background ACME cert is issued).
    // Register every handler's public routes on `pub` and private routes on `priv`.
    auto register_on = [&](httplib::Server& pub, httplib::Server& priv) {
        pub.set_pre_routing_handler(pre_routing_handler);
        priv.set_pre_routing_handler(pre_routing_handler);
        public_api.register_routes(pub, priv);
        auth_api.register_routes(pub, priv);
        tree_api.register_routes(pub, priv);
        relay_api.register_routes(pub, priv);
        cert_api.register_routes(pub, priv);
        admin_api.register_routes(pub, priv);
        mesh_api.register_routes(pub, priv);
        routing_api.register_routes(pub, priv);
        onboard_api.register_routes(pub, priv);
        account_data_api.register_routes(pub, priv);
        tier1_api.register_routes(pub, priv);
    };
    // Re-runnable if the underlying server object is replaced (plain->HTTPS
    // upgrade after a background ACME cert). Resolves the private server on every
    // call since upgrade_to_tls swaps the object.
    auto register_public_routes = [&]() {
        auto& private_srv = private_http_server ? private_http_server->server()
                                                : http_server.server();
        register_on(http_server.server(), private_srv);
    };
    // Re-register ONLY the private routes on the (upgraded) private server object,
    // without touching the live public server: the handlers' public routes land
    // on a throwaway server that is discarded immediately.
    auto register_private_routes = [&]() {
        if (!private_http_server) return;
        httplib::Server discard;
        register_on(discard, private_http_server->server());
    };
    // Re-register ONLY the public routes on the (upgraded) public server object,
    // without touching the live private server: the handlers' private routes land
    // on a throwaway server that is discarded immediately.
    auto reregister_public_routes = [&]() {
        httplib::Server discard;
        register_on(http_server.server(), discard);
    };
    register_public_routes();

    // ========================================================================
    // Start HTTP servers
    // ========================================================================
    // Refuse-without-cert: the control-plane APIs serve HTTPS or nothing. A
    // server with no valid cert is withheld (no plaintext fallback). The public
    // API is brought up in place by the background ACME thread below once a cert
    // is issued; the private API picks its cert up on the next restart.
    if (http_server.is_tls()) {
        http_server.start();
    } else if (tls.needs_acme_background) {
        // Name the FQDN the cert is actually requested for (SEIP, srv fallback).
        spdlog::warn("Public API withheld: no TLS certificate yet for {} — it will "
                     "start once ACME issues one (no plaintext fallback)", public_cert_fqdn);
    } else {
        spdlog::error("Public API withheld: no TLS certificate for '{}' and no FQDN to "
                      "request one for via ACME (needs a public IP / SEIP FQDN; "
                      "no plaintext fallback).", public_cert_fqdn);
    }
    if (private_http_server) {
        if (private_http_server->is_tls()) {
            private_http_server->start();
        } else {
            spdlog::warn("Private API withheld: no TLS certificate yet for {} — it will "
                         "start once ACME issues one (no plaintext fallback)",
                         server_private_fqdn);
        }
    }

    // ========================================================================
    // Run -- blocks until SIGINT/SIGTERM
    // ========================================================================
    const std::string public_api_status =
        http_server.is_tls() ? ("HTTPS:" + std::to_string(http_port))
                             : ("HTTPS:" + std::to_string(http_port) + " (withheld, not listening)");
    const std::string private_api_status =
        (private_http_server && private_http_server->is_tls())
            ? ("PrivateHTTPS:" + tunnel_bind_ip + ":" + std::to_string(config.private_http_port))
            : ("PrivateHTTPS:" + tunnel_bind_ip + ":" + std::to_string(config.private_http_port) +
               " (withheld, not listening)");
    const auto dns_transport = dns.tcp_listening() ? "UDP+TCP" : "UDP";
    if (private_http_server) {
        spdlog::info("All services started. {}, {}, UDP:{}, Gossip/UDP:{}, STUN/UDP:{}, "
                     "Relay/UDP:{}, DNS/{}:{}",
                     public_api_status, private_api_status, udp_port, gossip_port, stun_port, relay_port,
                     dns_transport, dns_port);
    } else {
        spdlog::info("All services started. {}, UDP:{}, Gossip/UDP:{}, STUN/UDP:{}, "
                     "Relay/UDP:{}, DNS/{}:{}",
                     public_api_status, udp_port, gossip_port, stun_port, relay_port, dns_transport, dns_port);
    }
    if (http_server.is_tls() && !server_fqdn.empty()) {
        spdlog::info("TLS enabled for {} (cert={})", server_fqdn, http_server.tls_cert_path());
    }

    // Public-IP self-check: auto-detection measures the egress path, which on
    // multihomed/VPN'd hosts is not the ingress peers must reach. Probe our own
    // public endpoint once the listeners are up and warn if it refuses.
    if (!server_public_ip.empty()) {
        std::thread([ip = server_public_ip, port = http_port,
                     configured = !config.public_ip.empty()]() {
            std::this_thread::sleep_for(std::chrono::seconds(5));
            if (nexus::core::tcp_connect_check(ip, port, 4)) {
                spdlog::info("Public IP self-check: {}:{} accepts connections from this host",
                             ip, port);
            } else if (configured) {
                spdlog::warn("Public IP self-check: configured public_ip {}:{} did not accept "
                             "a connection from this host. This can be a NAT that doesn't "
                             "hairpin, but verify that peers can actually reach it.", ip, port);
            } else {
                spdlog::warn("Public IP self-check: auto-detected public IP {}:{} did not "
                             "accept a connection. Detection measures the egress path and is "
                             "often wrong on multihomed/VPN'd hosts — set public_ip explicitly "
                             "if peers cannot reach this server.", ip, port);
            }
        }).detach();
    }

    // ========================================================================
    // Background ACME retry -- if no cert yet, retry every 5 minutes
    // ========================================================================
    std::atomic<bool> acme_retry_stop{false};

    // Load the key of an issued certificate through AcmeService, which reads
    // it through the storage vault (the key file on disk may be DEK
    // ciphertext). Empty when the key is not readable yet.
    auto issued_key_pem = [&](const std::string& fqdn) -> std::string {
        auto bundle = acme.get_certificate(fqdn);
        return bundle ? std::move(bundle->privkey_pem) : std::string{};
    };

    // Obtain a cert for `fqdn` and bring `srv` up over HTTPS in place (hot-reload
    // if already TLS, else swap the listener to an SSLServer and re-register its
    // routes). Loops with backoff until issuance or shutdown; never serves
    // plaintext. `is_private` selects which routes to re-register on upgrade.
    auto activate_tls = [&](nexus::network::HttpServer& srv, const std::string& fqdn,
                            const char* label, bool is_private) {
        constexpr auto initial_delay = std::chrono::seconds(30);
        constexpr auto base_interval = std::chrono::minutes(5);
        constexpr auto max_interval  = std::chrono::hours(1);
        auto current_interval = base_interval;

        spdlog::info("Auto-TLS: background retry starting in 30s for {} ({})", fqdn, label);
        for (auto e = std::chrono::seconds(0); e < initial_delay && !acme_retry_stop.load();
             e += std::chrono::seconds(1))
            std::this_thread::sleep_for(std::chrono::seconds(1));

        while (!acme_retry_stop.load()) {
            spdlog::info("Auto-TLS: attempting ACME certificate for {} ({})", fqdn, label);
            auto result = acme.request_certificate(fqdn);
            if (result.success) {
                spdlog::info("Auto-TLS: ACME certificate issued for {} (cert={}, key={})",
                              fqdn, result.cert_path, result.key_path);
                const auto key_pem = issued_key_pem(fqdn);
                if (srv.is_tls()) {
                    if (srv.reload_tls_certs_inmemory_key(result.cert_path, key_pem,
                                                          result.key_path))
                        spdlog::info("Auto-TLS: reloaded TLS cert for {} (no restart)", fqdn);
                    else
                        spdlog::warn("Auto-TLS: failed to hot-reload TLS cert for {}", fqdn);
                    return;
                }
                spdlog::info("Auto-TLS: activating HTTPS for {} ({}) in place...", fqdn, label);
                srv.stop();
                if (srv.enable_tls_inmemory_key(result.cert_path, key_pem, result.key_path)) {
                    if (is_private) register_private_routes(); else reregister_public_routes();
                    srv.start();
                    spdlog::info("Auto-TLS: HTTPS active for {} ({}) — other services unaffected",
                                  fqdn, label);
                    return;
                }
                spdlog::error("Auto-TLS: TLS upgrade failed for {} ({}); stays withheld "
                              "(no plaintext fallback) — will retry", fqdn, label);
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
                spdlog::warn("Auto-TLS: ACME retry failed for {} -- retrying in {} minutes", fqdn, mins);
                auto doubled = current_interval * 2;
                current_interval = doubled > max_interval ? max_interval : doubled;
            }

            for (auto e = std::chrono::seconds(0);
                 e < current_interval && !acme_retry_stop.load();
                 e += std::chrono::seconds(1))
                std::this_thread::sleep_for(std::chrono::seconds(1));

            if (rate_limited) current_interval = base_interval;
        }
    };

    // Bring the public API up first, then the private API — one thread so the
    // ACME calls stay serialized (shared account/order state), and neither
    // listener serves plaintext while it waits for its cert.
    std::thread acme_retry_thread;
    if (tls.needs_acme_background || private_needs_acme) {
        acme_retry_thread = std::thread([&]() {
            if (tls.needs_acme_background)
                activate_tls(http_server, public_cert_fqdn, "public API", false);
            if (private_needs_acme && private_http_server)
                activate_tls(*private_http_server, server_private_fqdn, "private API", true);
        });
    }

    // ========================================================================
    // Background ACME renewal -- check daily. The server's own certs renew
    // when they expire within 30 days; the device and group loopback certs
    // this server issued renew when less than one third of their lifetime
    // remains (nexus::api::device_certificates_due).
    // ========================================================================
    std::atomic<bool> acme_renewal_stop{false};
    std::thread acme_renewal_thread;
    const bool have_private_fqdn = private_http_server && !server_private_fqdn.empty();
    if (!public_cert_fqdn.empty() || have_private_fqdn || !config.dns_base_domain.empty()) {
        acme_renewal_thread = std::thread([&]() {
            constexpr auto initial_delay = std::chrono::hours(1);
            constexpr auto check_interval = std::chrono::hours(24);

            spdlog::info("Auto-TLS: certificate renewal monitor started (public + private + "
                         "device, checking daily)");

            for (auto elapsed = std::chrono::seconds(0);
                 elapsed < initial_delay && !acme_renewal_stop.load();
                 elapsed += std::chrono::seconds(1)) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }

            // Renew + hot-reload one listener, but only once it is actually serving
            // TLS — so certs first obtained by the background issuance path are
            // covered too (they become is_tls() after the upgrade above).
            auto renew_one = [&](nexus::network::HttpServer& srv, const std::string& fqdn) {
                if (fqdn.empty() || !srv.is_tls()) return;
                auto r = acme.renew_certificate(fqdn);
                if (r.success && !r.cert_path.empty()) {
                    spdlog::info("Auto-TLS: renewal check complete for {} (cert={})",
                                  fqdn, r.cert_path);
                    (void)srv.reload_tls_certs_inmemory_key(r.cert_path, issued_key_pem(fqdn),
                                                            r.key_path);
                } else if (!r.success) {
                    spdlog::warn("Auto-TLS: renewal failed for {}: {}", fqdn, r.error_message);
                }
            };

            while (!acme_renewal_stop.load()) {
                renew_one(http_server, public_cert_fqdn);
                if (private_http_server) renew_one(*private_http_server, server_private_fqdn);

                // Devices receive a renewed certificate through their next
                // /api/certs/issue call (the SDK checks expiry and asks).
                for (const auto& domain : nexus::api::device_certificates_due(
                         acme, tree, config.dns_base_domain, nexus::api::epoch_seconds())) {
                    if (acme_renewal_stop.load()) break;
                    auto r = acme.request_certificate(domain);
                    if (r.success) {
                        spdlog::info("Auto-TLS: renewed device certificate {}", domain);
                    } else {
                        spdlog::warn("Auto-TLS: device certificate renewal failed for {}: {}",
                                     domain, r.error_message);
                    }
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
    if (forward_authorizer) forward_authorizer->stop();
    boringtun_service.stop();   // stops the dataplane: no more inbound packets
    vnet.stop();                // tears down the netstack + bridges
    if (private_http_server) {
        private_http_server->stop();
    }
    http_server.stop();
    admission.stop();
    ddns.stop();
    dns.stop();
    acme.stop();
    routing.stop();
    relay_discovery.stop();
    relay.stop();
    stun.stop();
#if defined(LEMONADE_HAVE_UPGRADE_CONTROL)
    upgrade_control->stop();
#endif
    if (security_mesh) {
        security_mesh->service->stop();  // uses gossip as transport: stop it first
    }
    gossip.stop();
    ipam.stop();
    tree.stop();
    attestation.stop();
    key_wrapping.stop();
    acl_service.stop();
    auth_service.stop();
    storage.stop();
    crypto.stop();

    spdlog::info("Lemonade-Nexus shut down cleanly.");
    return 0;
}
