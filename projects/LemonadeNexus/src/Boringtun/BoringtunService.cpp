#include <LemonadeNexus/Boringtun/BoringtunService.hpp>
#include <LemonadeNexus/Boringtun/IpRouter.hpp>

#include <sodium.h>
#include <spdlog/spdlog.h>

#include <array>
#include <fstream>
#include <optional>
#include <regex>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

namespace nexus::boringtun {

namespace {

/// Parse the host address of a CIDR (or bare IP) into host byte order.
std::optional<uint32_t> parse_host_ip(const std::string& cidr) {
    std::string ip = cidr;
    if (auto slash = cidr.find('/'); slash != std::string::npos)
        ip = cidr.substr(0, slash);
    auto parsed = Cidr::parse(ip);  // bare IP => /32, network == host address
    if (!parsed || parsed->prefix_len != 32) return std::nullopt;
    return parsed->network;
}

} // namespace

BoringtunService::BoringtunService(std::string interface_name,
                                   std::filesystem::path config_dir)
    : interface_name_(std::move(interface_name)),
      config_dir_(std::move(config_dir)) {}

BoringtunService::~BoringtunService() = default;

void BoringtunService::on_start() {
    spdlog::info("[{}] userspace dataplane facade ready (no kernel interface)", name());
}

void BoringtunService::on_stop() {
    std::lock_guard lock(mutex_);
    dataplane_.stop();
}

// ---------------------------------------------------------------------------
// Input validation
// ---------------------------------------------------------------------------

bool BoringtunService::is_valid_pubkey(const std::string& key) {
    if (key.size() != 44) return false;
    static const std::regex base64_re(R"(^[A-Za-z0-9+/]{43}=$)");
    return std::regex_match(key, base64_re);
}

bool BoringtunService::is_valid_endpoint(const std::string& ep) {
    if (ep.empty()) return true;  // peer without endpoint (NATed client)
    static const std::regex ipv4_ep_re(R"(^(\d{1,3}\.){3}\d{1,3}:\d{1,5}$)");
    static const std::regex ipv6_ep_re(R"(^\[[0-9a-fA-F:]+\]:\d{1,5}$)");
    static const std::regex host_ep_re(
        R"(^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*:\d{1,5}$)");
    return std::regex_match(ep, ipv4_ep_re) ||
           std::regex_match(ep, ipv6_ep_re) ||
           std::regex_match(ep, host_ep_re);
}

bool BoringtunService::is_valid_cidr(const std::string& cidr) {
    if (cidr.empty()) return false;
    static const std::regex ipv4_cidr_re(R"(^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$)");
    static const std::regex ipv6_cidr_re(R"(^[0-9a-fA-F:]+/\d{1,3}$)");
    return std::regex_match(cidr, ipv4_cidr_re) ||
           std::regex_match(cidr, ipv6_cidr_re);
}

bool BoringtunService::is_valid_allowed_ips(const std::string& allowed_ips) {
    if (allowed_ips.empty()) return false;
    std::istringstream stream(allowed_ips);
    std::string token;
    while (std::getline(stream, token, ',')) {
        auto start = token.find_first_not_of(" \t");
        auto end   = token.find_last_not_of(" \t");
        if (start == std::string::npos) return false;
        if (!is_valid_cidr(token.substr(start, end - start + 1))) return false;
    }
    return true;
}

bool BoringtunService::is_valid_interface_name(const std::string& iface) {
    if (iface.empty() || iface.size() > 15) return false;
    static const std::regex iface_re(R"(^[a-zA-Z0-9_-]+$)");
    return std::regex_match(iface, iface_re);
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

std::string BoringtunService::derive_public_key(const std::string& private_key_b64) {
    std::array<uint8_t, crypto_box_SECRETKEYBYTES> sk{};
    size_t len = 0;
    if (sodium_base642bin(sk.data(), sk.size(), private_key_b64.c_str(),
                          private_key_b64.size(), nullptr, &len, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0 || len != sk.size())
        return {};
    std::array<uint8_t, crypto_box_PUBLICKEYBYTES> pk{};
    if (crypto_scalarmult_base(pk.data(), sk.data()) != 0) return {};
    char b64[sodium_base64_ENCODED_LEN(crypto_box_PUBLICKEYBYTES,
                                       sodium_base64_VARIANT_ORIGINAL)];
    sodium_bin2base64(b64, sizeof(b64), pk.data(), pk.size(),
                      sodium_base64_VARIANT_ORIGINAL);
    return b64;
}

BoringtunKeypair BoringtunService::do_generate_keypair() {
    std::lock_guard lock(mutex_);
    unsigned char pk[crypto_box_PUBLICKEYBYTES];
    unsigned char sk[crypto_box_SECRETKEYBYTES];
    crypto_box_keypair(pk, sk);

    char pk_b64[sodium_base64_ENCODED_LEN(crypto_box_PUBLICKEYBYTES,
                                          sodium_base64_VARIANT_ORIGINAL)];
    char sk_b64[sodium_base64_ENCODED_LEN(crypto_box_SECRETKEYBYTES,
                                          sodium_base64_VARIANT_ORIGINAL)];
    sodium_bin2base64(pk_b64, sizeof(pk_b64), pk, crypto_box_PUBLICKEYBYTES,
                      sodium_base64_VARIANT_ORIGINAL);
    sodium_bin2base64(sk_b64, sizeof(sk_b64), sk, crypto_box_SECRETKEYBYTES,
                      sodium_base64_VARIANT_ORIGINAL);
    return BoringtunKeypair{.public_key = pk_b64, .private_key = sk_b64};
}

// ---------------------------------------------------------------------------
// Interface lifecycle (now purely virtual — registers addresses with the router)
// ---------------------------------------------------------------------------

bool BoringtunService::do_set_interface(const BoringtunInterfaceConfig& config) {
    std::lock_guard lock(mutex_);
    private_key_b64_ = config.private_key;
    listen_port_     = config.listen_port;
    return true;
}

bool BoringtunService::do_setup_interface(const BoringtunInterfaceConfig& config,
                                          const std::vector<BoringtunPeer>& peers) {
    if (!config.address.empty() && !is_valid_cidr(config.address)) {
        spdlog::error("[{}] setup_interface rejected: invalid address '{}'",
                       name(), config.address);
        return false;
    }
    if (config.private_key.empty()) {
        spdlog::error("[{}] setup_interface rejected: missing private key", name());
        return false;
    }

    std::lock_guard lock(mutex_);
    private_key_b64_ = config.private_key;
    public_key_b64_  = derive_public_key(config.private_key);
    listen_port_     = config.listen_port;
    if (public_key_b64_.empty()) {
        spdlog::error("[{}] setup_interface rejected: bad private key", name());
        return false;
    }

    UserspaceDataplane::Config dp_cfg;
    dp_cfg.private_key_b64 = private_key_b64_;
    dp_cfg.public_key_b64  = public_key_b64_;
    dp_cfg.listen_port     = listen_port_;
    if (!dataplane_.start(dp_cfg)) {
        spdlog::error("[{}] setup_interface: dataplane failed to bind UDP :{}",
                       name(), listen_port_);
        return false;
    }

    if (!config.address.empty()) {
        if (auto ip = parse_host_ip(config.address))
            dataplane_.add_local_ip(*ip);
    }

    for (const auto& peer : peers) {
        if (!is_valid_pubkey(peer.public_key)) continue;
        (void)dataplane_.add_peer(peer.public_key, peer.allowed_ips, peer.endpoint,
                                  peer.persistent_keepalive);
    }

    spdlog::info("[{}] userspace dataplane up on UDP :{} (virtual address {})",
                  name(), dataplane_.bound_port(), config.address);
    return true;
}

bool BoringtunService::do_teardown_interface() {
    std::lock_guard lock(mutex_);
    dataplane_.stop();
    return true;
}

bool BoringtunService::do_add_address(const std::string& address_cidr) {
    if (!is_valid_cidr(address_cidr)) {
        spdlog::error("[{}] invalid CIDR for add_address: '{}'", name(), address_cidr);
        return false;
    }
    std::lock_guard lock(mutex_);
    if (!add_local_address(address_cidr)) return false;
    spdlog::info("[{}] registered virtual address {}", name(), address_cidr);
    return true;
}

bool BoringtunService::add_local_address(const std::string& address_cidr) {
    auto ip = parse_host_ip(address_cidr);
    if (!ip) return false;
    dataplane_.add_local_ip(*ip);
    return true;
}

// ---------------------------------------------------------------------------
// Peer management (delegated to the dataplane)
// ---------------------------------------------------------------------------

bool BoringtunService::do_add_peer(const std::string& pubkey,
                                   const std::string& allowed_ips,
                                   const std::string& endpoint) {
    if (!is_valid_pubkey(pubkey)) {
        spdlog::error("[{}] add_peer rejected: invalid pubkey", name());
        return false;
    }
    if (!is_valid_allowed_ips(allowed_ips)) {
        spdlog::error("[{}] add_peer rejected: invalid allowed_ips '{}'", name(), allowed_ips);
        return false;
    }
    if (!is_valid_endpoint(endpoint)) {
        spdlog::error("[{}] add_peer rejected: invalid endpoint '{}'", name(), endpoint);
        return false;
    }
    std::lock_guard lock(mutex_);
    return dataplane_.add_peer(pubkey, allowed_ips, endpoint);
}

bool BoringtunService::do_remove_peer(const std::string& pubkey) {
    if (!is_valid_pubkey(pubkey)) return false;
    std::lock_guard lock(mutex_);
    return dataplane_.remove_peer(pubkey);
}

bool BoringtunService::do_update_endpoint(const std::string& pubkey,
                                          const std::string& new_endpoint) {
    if (!is_valid_pubkey(pubkey) || !is_valid_endpoint(new_endpoint)) return false;
    std::lock_guard lock(mutex_);
    return dataplane_.update_endpoint(pubkey, new_endpoint);
}

std::vector<BoringtunPeer> BoringtunService::do_get_peers() {
    std::lock_guard lock(mutex_);
    return dataplane_.snapshot_peers();
}

// ---------------------------------------------------------------------------
// Peer sync from tree (composes the verbs above)
// ---------------------------------------------------------------------------

int BoringtunService::do_sync_peers_from_tree(const std::vector<TreeNodePeer>& desired_peers) {
    for (const auto& dp : desired_peers) {
        if (!is_valid_pubkey(dp.public_key)) {
            spdlog::error("[{}] sync: invalid pubkey '{}'", name(), dp.public_key);
            return -1;
        }
        if (!dp.tunnel_ip.empty() && !is_valid_cidr(dp.tunnel_ip)) {
            spdlog::error("[{}] sync: invalid tunnel_ip '{}'", name(), dp.tunnel_ip);
            return -1;
        }
        if (!dp.private_subnet.empty() && !is_valid_cidr(dp.private_subnet)) {
            spdlog::error("[{}] sync: invalid private_subnet '{}'", name(), dp.private_subnet);
            return -1;
        }
        if (!is_valid_endpoint(dp.endpoint)) {
            spdlog::error("[{}] sync: invalid endpoint '{}'", name(), dp.endpoint);
            return -1;
        }
    }

    auto current_peers = do_get_peers();
    std::unordered_map<std::string, const BoringtunPeer*> current_map;
    for (const auto& cp : current_peers) current_map[cp.public_key] = &cp;

    std::unordered_set<std::string> desired_keys;
    for (const auto& dp : desired_peers) desired_keys.insert(dp.public_key);

    int changes = 0;
    for (const auto& dp : desired_peers) {
        std::string allowed_ips = dp.tunnel_ip;
        if (!dp.private_subnet.empty()) {
            if (!allowed_ips.empty()) allowed_ips += ", ";
            allowed_ips += dp.private_subnet;
        }

        auto it = current_map.find(dp.public_key);
        if (it == current_map.end()) {
            if (do_add_peer(dp.public_key, allowed_ips, dp.endpoint)) ++changes;
        } else if (!dp.endpoint.empty() && it->second->endpoint != dp.endpoint) {
            if (do_update_endpoint(dp.public_key, dp.endpoint)) ++changes;
        }
    }

    for (const auto& cp : current_peers) {
        if (!desired_keys.count(cp.public_key)) {
            if (do_remove_peer(cp.public_key)) ++changes;
        }
    }

    spdlog::info("[{}] sync_peers_from_tree: {} changes ({} desired, {} current)",
                  name(), changes, desired_peers.size(), current_peers.size());
    return changes;
}

// ---------------------------------------------------------------------------
// Config file generation / persistence (unchanged semantics)
// ---------------------------------------------------------------------------

std::string BoringtunService::do_generate_config(const BoringtunInterfaceConfig& config,
                                                 const std::vector<BoringtunPeer>& peers) {
    std::ostringstream out;
    out << "[Interface]\n";
    out << "PrivateKey = " << config.private_key << "\n";
    out << "ListenPort = " << config.listen_port << "\n";
    if (!config.address.empty()) out << "Address = " << config.address << "\n";
    if (!config.dns.empty())     out << "DNS = " << config.dns << "\n";
    for (const auto& peer : peers) {
        out << "\n[Peer]\n";
        out << "PublicKey = " << peer.public_key << "\n";
        if (!peer.allowed_ips.empty()) out << "AllowedIPs = " << peer.allowed_ips << "\n";
        if (!peer.endpoint.empty())    out << "Endpoint = " << peer.endpoint << "\n";
        if (peer.persistent_keepalive > 0)
            out << "PersistentKeepalive = " << peer.persistent_keepalive << "\n";
    }
    return out.str();
}

std::filesystem::path BoringtunService::config_file_path() const {
    return config_dir_ / (interface_name_ + ".conf");
}

bool BoringtunService::do_save_config(const std::string& config_contents) {
    std::lock_guard lock(mutex_);
    auto path = config_file_path();

    std::error_code ec;
    std::filesystem::create_directories(path.parent_path(), ec);
    if (ec) {
        spdlog::error("[{}] failed to create config dir '{}': {}",
                       name(), path.parent_path().string(), ec.message());
        return false;
    }

    std::ofstream ofs(path, std::ios::out | std::ios::trunc);
    if (!ofs.is_open()) {
        spdlog::error("[{}] failed to open config for writing: {}", name(), path.string());
        return false;
    }
    ofs << config_contents;
    ofs.close();
    if (ofs.fail()) {
        spdlog::error("[{}] failed to write config: {}", name(), path.string());
        return false;
    }

    std::filesystem::permissions(path,
        std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
        std::filesystem::perm_options::replace, ec);
    if (ec)
        spdlog::warn("[{}] failed to set permissions on '{}': {}",
                      name(), path.string(), ec.message());

    spdlog::info("[{}] saved config to '{}'", name(), path.string());
    return true;
}

std::string BoringtunService::do_load_config() {
    std::lock_guard lock(mutex_);
    auto path = config_file_path();
    if (!std::filesystem::exists(path)) return {};

    std::ifstream ifs(path);
    if (!ifs.is_open()) {
        spdlog::error("[{}] failed to open config for reading: {}", name(), path.string());
        return {};
    }
    std::ostringstream buf;
    buf << ifs.rdbuf();
    return buf.str();
}

} // namespace nexus::boringtun
