/// ln_pump_* — a host-owned, socket-level tunnel with no kernel TUN device and
/// no system VPN. Joins the userspace BoringTun dataplane
/// (nexus::wireguard::UserspaceDataplane) to the in-process virtual netstack
/// (crates/virtual-netstack, smoltcp), and exposes mesh connectivity as ordinary
/// loopback sockets:
///   - egress: a 127.0.0.1 listener bridged to a virtual TCP connect across the
///     mesh (connect a normal socket to reach a mesh endpoint);
///   - ingress: a virtual vip:vport bridged to a local service.
/// Decrypted inbound IP goes dataplane -> netstack; the netstack's outbound IP
/// goes netstack -> dataplane (encrypt -> UDP).

#include <LemonadeNexusSDK/lemonade_nexus.h>

#include <LemonadeNexus/WireGuard/IpRouter.hpp>
#include <LemonadeNexus/WireGuard/UserspaceDataplane.hpp>

#include <virtual_netstack.h>
#include <nlohmann/json.hpp>

#include <cstdlib>
#include <cstring>
#include <optional>
#include <span>
#include <string>
#include <unordered_set>

using json = nlohmann::json;
using nexus::wireguard::Cidr;
using nexus::wireguard::UserspaceDataplane;
using nexus::wireguard::WgPeer;

struct ln_pump_s {
    UserspaceDataplane dp;
    NsHandle*          ns{nullptr};
    std::string        server_pubkey;  // never removed by sync_peers
    std::string        tunnel_addr;    // our virtual IP (no prefix), egress source
};

namespace {

std::string json_str(const json& j, const char* key) {
    auto it = j.find(key);
    return it != j.end() && it->is_string() ? it->get<std::string>() : std::string{};
}

std::string addr_part(const std::string& cidr) {
    auto slash = cidr.find('/');
    return slash == std::string::npos ? cidr : cidr.substr(0, slash);
}

int prefix_part(const std::string& cidr, int fallback) {
    auto slash = cidr.find('/');
    if (slash == std::string::npos) return fallback;
    try {
        return std::stoi(cidr.substr(slash + 1));
    } catch (...) {
        return fallback;
    }
}

std::string allowed_for(const std::string& tunnel_ip, const std::string& private_subnet) {
    std::string out = tunnel_ip;
    if (!private_subnet.empty()) out += out.empty() ? private_subnet : ("," + private_subnet);
    return out;
}

uint16_t keepalive_of(const json& j) {
    auto it = j.find("keepalive");
    return it != j.end() && it->is_number() ? static_cast<uint16_t>(it->get<int>()) : 25;
}

char* dup_cstr(const std::string& s) {
    char* p = static_cast<char*>(std::malloc(s.size() + 1));
    if (p) std::memcpy(p, s.c_str(), s.size() + 1);
    return p;
}

// The netstack hands every outbound IP packet here; re-inject into the dataplane.
void output_trampoline(void* ctx, const uint8_t* pkt, size_t len) {
    if (!ctx || !pkt || len == 0) return;
    static_cast<ln_pump_s*>(ctx)->dp.send_outbound_ip_packet({pkt, len});
}

}  // namespace

ln_pump_t* ln_pump_create(const char* config_json) {
    if (!config_json) return nullptr;
    json cfg;
    try {
        cfg = json::parse(config_json);
    } catch (...) {
        return nullptr;
    }
    if (!cfg.is_object()) return nullptr;

    UserspaceDataplane::Config dpcfg;
    dpcfg.private_key_b64 = json_str(cfg, "private_key");
    dpcfg.public_key_b64  = json_str(cfg, "public_key");
    if (auto it = cfg.find("listen_port"); it != cfg.end() && it->is_number())
        dpcfg.listen_port = static_cast<uint16_t>(it->get<int>());
    else
        dpcfg.listen_port = 0;
    if (dpcfg.private_key_b64.empty() || dpcfg.public_key_b64.empty()) return nullptr;

    auto* pump = new ln_pump_s{};

    pump->ns = ns_create(dpcfg.mtu, &output_trampoline, pump);
    if (!pump->ns) {
        delete pump;
        return nullptr;
    }

    // Decrypted inbound IP -> netstack.
    pump->dp.set_inbound_handler([pump](std::span<const uint8_t> pkt) {
        if (!pkt.empty()) ns_feed_inbound(pump->ns, pkt.data(), pkt.size());
    });

    if (!pump->dp.start(dpcfg)) {
        ns_destroy(pump->ns);
        delete pump;
        return nullptr;
    }

    // Register our virtual address; widen the prefix to the mesh plane (from the
    // first allowed-IPs entry) so mesh peers are on-link for egress.
    std::string tunnel_cidr = json_str(cfg, "tunnel_ip");
    pump->tunnel_addr = addr_part(tunnel_cidr);
    if (!pump->tunnel_addr.empty()) {
        // Register in the dataplane's cryptokey router so decrypted packets to
        // our tunnel IP are delivered locally (to the netstack) rather than dropped.
        if (auto c = Cidr::parse(pump->tunnel_addr); c && c->prefix_len == 32) {
            pump->dp.add_local_ip(c->network);
        }
        int prefix = 10;
        std::string allowed_join;
        if (auto it = cfg.find("allowed_ips"); it != cfg.end() && it->is_array() && !it->empty()) {
            if ((*it)[0].is_string()) prefix = prefix_part((*it)[0].get<std::string>(), 10);
            for (const auto& a : *it) {
                if (!a.is_string()) continue;
                if (!allowed_join.empty()) allowed_join += ",";
                allowed_join += a.get<std::string>();
            }
        }
        ns_add_local_ip(pump->ns, (pump->tunnel_addr + "/" + std::to_string(prefix)).c_str());
    }

    // Add the server as the initial peer.
    pump->server_pubkey = json_str(cfg, "server_public_key");
    if (!pump->server_pubkey.empty()) {
        std::string allowed;
        if (auto it = cfg.find("allowed_ips"); it != cfg.end() && it->is_array()) {
            for (const auto& a : *it) {
                if (!a.is_string()) continue;
                if (!allowed.empty()) allowed += ",";
                allowed += a.get<std::string>();
            }
        }
        if (allowed.empty()) allowed = "0.0.0.0/0";
        (void)pump->dp.add_peer(pump->server_pubkey, allowed,
                                json_str(cfg, "server_endpoint"), keepalive_of(cfg));
    }

    return reinterpret_cast<ln_pump_t*>(pump);
}

void ln_pump_destroy(ln_pump_t* pump) {
    if (!pump) return;
    auto* p = reinterpret_cast<ln_pump_s*>(pump);
    p->dp.stop();          // stop feeding the netstack before tearing it down
    if (p->ns) ns_destroy(p->ns);
    delete p;
}

uint16_t ln_pump_tcp_egress(ln_pump_t* pump, const char* dst_ip, uint16_t dst_port) {
    if (!pump || !dst_ip) return 0;
    auto* p = reinterpret_cast<ln_pump_s*>(pump);
    if (!p->ns || p->tunnel_addr.empty()) return 0;
    return ns_add_tcp_egress(p->ns, dst_ip, dst_port, p->tunnel_addr.c_str());
}

ln_error_t ln_pump_tcp_forward(ln_pump_t* pump, const char* vip, uint16_t vport,
                               const char* target) {
    if (!pump || !vip || !target) return LN_ERR_NULL_ARG;
    auto* p = reinterpret_cast<ln_pump_s*>(pump);
    if (!p->ns) return LN_ERR_INTERNAL;
    return ns_add_tcp_forward(p->ns, vip, vport, target) == 0 ? LN_OK : LN_ERR_REJECTED;
}

ln_error_t ln_pump_sync_peers(ln_pump_t* pump, const char* peers_json) {
    if (!pump || !peers_json) return LN_ERR_NULL_ARG;
    auto* p = reinterpret_cast<ln_pump_s*>(pump);
    json arr;
    try {
        arr = json::parse(peers_json);
    } catch (...) {
        return LN_ERR_INTERNAL;
    }
    if (!arr.is_array()) return LN_ERR_NULL_ARG;

    std::unordered_set<std::string> desired;
    for (const auto& peer : arr) {
        if (!peer.is_object()) continue;
        std::string pub = json_str(peer, "wg_pubkey");
        if (pub.empty()) continue;
        std::string endpoint = json_str(peer, "endpoint");
        if (endpoint.empty()) endpoint = json_str(peer, "relay_endpoint");
        std::string allowed =
            allowed_for(json_str(peer, "tunnel_ip"), json_str(peer, "private_subnet"));
        if (allowed.empty()) continue;
        desired.insert(pub);
        (void)p->dp.add_peer(pub, allowed, endpoint, keepalive_of(peer));
    }

    for (const auto& wg : p->dp.snapshot_peers()) {
        if (wg.public_key == p->server_pubkey) continue;
        if (!desired.count(wg.public_key)) (void)p->dp.remove_peer(wg.public_key);
    }
    return LN_OK;
}

ln_error_t ln_pump_status(ln_pump_t* pump, char** out_json) {
    if (!pump || !out_json) return LN_ERR_NULL_ARG;
    auto* p = reinterpret_cast<ln_pump_s*>(pump);
    json arr = json::array();
    for (const auto& wg : p->dp.snapshot_peers()) {
        arr.push_back({
            {"wg_pubkey", wg.public_key},
            {"allowed_ips", wg.allowed_ips},
            {"endpoint", wg.endpoint},
            {"last_handshake", wg.last_handshake},
            {"rx_bytes", wg.rx_bytes},
            {"tx_bytes", wg.tx_bytes},
            {"keepalive", wg.persistent_keepalive},
        });
    }
    *out_json = dup_cstr(arr.dump());
    return *out_json ? LN_OK : LN_ERR_INTERNAL;
}
