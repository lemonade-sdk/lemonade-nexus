/// ln_pump_* — a host-owned WireGuard dataplane for platforms where the OS owns
/// the virtual interface (macOS/iOS NetworkExtension, Android VpnService). Wraps
/// nexus::wireguard::UserspaceDataplane: the host bridges plaintext IP packets
/// in/out, the pump owns the UDP socket, Noise sessions, routing, and timers.

#include <LemonadeNexusSDK/lemonade_nexus.h>

#include <LemonadeNexus/WireGuard/IpRouter.hpp>
#include <LemonadeNexus/WireGuard/UserspaceDataplane.hpp>

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
    UserspaceDataplane   dp;
    ln_pump_tun_write_cb cb{nullptr};
    void*                ctx{nullptr};
    std::string          server_pubkey;  // never removed by sync_peers
};

namespace {

std::string json_str(const json& j, const char* key) {
    auto it = j.find(key);
    return it != j.end() && it->is_string() ? it->get<std::string>() : std::string{};
}

/// Host-order address from "a.b.c.d" or "a.b.c.d/NN" (the address, not network).
std::optional<uint32_t> address_of(const std::string& cidr) {
    if (cidr.empty()) return std::nullopt;
    auto slash = cidr.find('/');
    auto c = Cidr::parse(slash == std::string::npos ? cidr : cidr.substr(0, slash));
    if (!c || c->prefix_len != 32) return std::nullopt;
    return c->network;
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

}  // namespace

ln_pump_t* ln_pump_create(const char* config_json,
                          ln_pump_tun_write_cb on_tun_write, void* ctx) {
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
    pump->cb  = on_tun_write;
    pump->ctx = ctx;
    pump->dp.set_inbound_handler([pump](std::span<const uint8_t> pkt) {
        if (pump->cb) pump->cb(pump->ctx, pkt.data(), pkt.size());
    });

    if (!pump->dp.start(dpcfg)) {
        delete pump;
        return nullptr;
    }

    if (auto ip = address_of(json_str(cfg, "tunnel_ip"))) pump->dp.add_local_ip(*ip);

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
    delete reinterpret_cast<ln_pump_s*>(pump);  // dtor stops the dataplane
}

ln_error_t ln_pump_outbound_ip(ln_pump_t* pump, const uint8_t* ip_packet, size_t len) {
    if (!pump || !ip_packet) return LN_ERR_NULL_ARG;
    auto* p = reinterpret_cast<ln_pump_s*>(pump);
    return p->dp.send_outbound_ip_packet({ip_packet, len}) ? LN_OK : LN_ERR_REJECTED;
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
