#include <LemonadeNexus/Core/ServerIdentity.hpp>
#include <LemonadeNexus/Core/HostnameGenerator.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <array>
#include <chrono>
#include <fstream>
#include <thread>
#include <unordered_set>

namespace nexus::core {

std::string resolve_jwt_secret(
    const ServerConfig& config,
    const std::filesystem::path& data_root,
    crypto::SodiumCryptoService& crypto)
{
    std::string jwt_secret_hex = config.jwt_secret;
    if (!jwt_secret_hex.empty()) return jwt_secret_hex;

    const auto jwt_path = data_root / "identity" / "jwt_secret.hex";
    if (std::filesystem::exists(jwt_path)) {
        std::ifstream f(jwt_path);
        std::getline(f, jwt_secret_hex);
        spdlog::info("Loaded JWT secret from {}", jwt_path.string());
    } else {
        std::array<uint8_t, 32> jwt_secret_bytes{};
        crypto.random_bytes(std::span<uint8_t>(jwt_secret_bytes));
        jwt_secret_hex = crypto::to_hex(
            std::span<const uint8_t>(jwt_secret_bytes));
        std::filesystem::create_directories(jwt_path.parent_path());
        std::ofstream f(jwt_path);
        f << jwt_secret_hex;
        spdlog::info("Generated and persisted JWT secret to {}", jwt_path.string());
    }
    return jwt_secret_hex;
}

std::string resolve_server_node_id(storage::FileStorageService& storage) {
    // Prefer server certificate (from --enroll-server)
    auto cert_env = storage.read_file("identity", "server_cert.json");
    if (cert_env) {
        try {
            auto cert_j = nlohmann::json::parse(cert_env->data);
            auto id = cert_j.value("server_id", "");
            if (!id.empty()) return id;
        } catch (...) {}
    }

    // Fall back to identity pubkey — every server has one after first boot.
    // Derive a stable node ID so IPAM allocations persist across restarts.
    auto pk_env = storage.read_file("identity", "keypair.pub");
    if (pk_env && !pk_env->data.empty()) {
        // Use first 16 hex chars of the pubkey as a stable server node ID
        auto pubkey = pk_env->data;
        if (pubkey.size() > 16) pubkey = pubkey.substr(0, 16);
        auto node_id = "server-" + pubkey;
        spdlog::info("Derived server node ID from identity pubkey: {}", node_id);
        return node_id;
    }

    return {};
}

void resolve_server_hostname(
    ServerConfig& config,
    const std::filesystem::path& data_root,
    gossip::GossipService& gossip)
{
    if (!config.server_hostname.empty()) return;

    auto persisted = HostnameGenerator::load_persisted_hostname(data_root);
    if (persisted) {
        config.server_hostname = *persisted;
        spdlog::info("Loaded server hostname from disk: {}", config.server_hostname);
        return;
    }

    auto region = HostnameGenerator::detect_region();
    std::string region_code = region.value_or("unknown");

    // Gather existing hostnames for collision avoidance
    std::unordered_set<std::string> existing_hostnames;
    for (const auto& peer : gossip.get_peers()) {
        if (!peer.certificate_json.empty()) {
            try {
                auto cert_j = nlohmann::json::parse(peer.certificate_json);
                auto sid = cert_j.value("server_id", "");
                if (!sid.empty()) existing_hostnames.insert(sid);
            } catch (...) {}
        }
    }

    config.server_hostname = HostnameGenerator::generate_unique_hostname(
        region_code, existing_hostnames);

    HostnameGenerator::persist_hostname(data_root, config.server_hostname);
    spdlog::info("Auto-generated server hostname: {} (region: {})",
                  config.server_hostname, region_code);
}

std::string resolve_public_ip(const ServerConfig& config) {
    std::string ip = config.public_ip;
    if (ip.empty() && config.bind_address != "0.0.0.0" && !config.bind_address.empty()) {
        ip = config.bind_address;
    }
    if (ip.empty()) {
        try {
            httplib::Client ip_cli("http://api.ipify.org");
            ip_cli.set_connection_timeout(3, 0);
            ip_cli.set_read_timeout(3, 0);
            auto ip_res = ip_cli.Get("/");
            if (ip_res && ip_res->status == 200 && !ip_res->body.empty()) {
                ip = ip_res->body;
                while (!ip.empty() && (ip.back() == '\n' || ip.back() == '\r'))
                    ip.pop_back();
                spdlog::info("DNS: auto-detected public IP: {}", ip);
            }
        } catch (...) {
            spdlog::warn("DNS: failed to auto-detect public IP");
        }
    }
    return ip;
}

std::string build_server_fqdn(
    const std::string& server_hostname,
    const std::string& dns_base_domain)
{
    if (server_hostname.empty()) return {};
    return server_hostname + ".srv." + dns_base_domain;
}

std::string resolve_tunnel_ip(
    const std::string& server_node_id,
    const ServerConfig& config,
    ipam::IPAMService& ipam,
    gossip::GossipService& gossip)
{
    if (server_node_id.empty()) return {};

    std::string tunnel_bind_ip;

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
            spdlog::warn("No tunnel IP received from peers -- self-allocating");
            auto alloc = ipam.allocate_tunnel_ip(server_node_id);
            tunnel_bind_ip = alloc.base_network;
        }
    } else {
        // Genesis/root server: always use .1 as the gateway address.
        // Record an allocation so IPAM tracks this node, but override to .1.
        auto server_alloc = ipam.allocate_tunnel_ip(server_node_id);
        (void)server_alloc;
        tunnel_bind_ip = "10.64.0.1";
        spdlog::info("Genesis server -- gateway tunnel IP: {}", tunnel_bind_ip);
    }

    // Strip CIDR suffix (e.g. "10.64.0.1/32" -> "10.64.0.1")
    if (auto slash = tunnel_bind_ip.find('/'); slash != std::string::npos) {
        tunnel_bind_ip = tunnel_bind_ip.substr(0, slash);
    }
    return tunnel_bind_ip;
}

TlsResolution resolve_tls_cert(
    const ServerConfig& config,
    const std::filesystem::path& data_root,
    const std::string& server_fqdn)
{
    TlsResolution result;
    result.cert_path = config.tls_cert_path;
    result.key_path  = config.tls_key_path;

    // Auto-TLS: if no manual cert paths, check for existing ACME cert on disk
    if (result.cert_path.empty() && result.key_path.empty()
        && config.auto_tls && !server_fqdn.empty())
    {
        const auto acme_cert_dir  = data_root / "certs" / server_fqdn;
        const auto acme_cert_file = acme_cert_dir / "fullchain.pem";
        const auto acme_key_file  = acme_cert_dir / "privkey.pem";

        if (std::filesystem::exists(acme_cert_file) && std::filesystem::exists(acme_key_file)) {
            result.cert_path = acme_cert_file.string();
            result.key_path  = acme_key_file.string();
            spdlog::info("Auto-TLS: using existing ACME cert for {}", server_fqdn);
        } else {
            result.needs_acme_background = true;
            spdlog::info("Auto-TLS: no cert on disk for {} -- will request in background",
                          server_fqdn);
        }
    }
    return result;
}

} // namespace nexus::core
