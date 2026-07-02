#include <LemonadeNexus/Core/OnboardingClient.hpp>

#include <LemonadeNexus/Core/CliModes.hpp>
#include <LemonadeNexus/Core/HostnameGenerator.hpp>
#include <LemonadeNexus/Core/ServerAdmissionService.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Core/ServerIdentity.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Gossip/ServerCertificate.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <httplib.h>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <span>
#include <thread>

namespace nexus::core {

using json = nlohmann::json;

namespace {

uint64_t now_unix() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

struct HttpResult { bool connected{false}; int status{0}; std::string body; };

/// POST/GET to "host:port", trying HTTPS (no cert verification — trust is
/// anchored in Ed25519 signatures) then plain HTTP.
HttpResult http_call(const std::string& host, int port, const std::string& method,
                     const std::string& path, const std::string& body) {
    auto run = [&](auto& cli) -> HttpResult {
        cli.set_connection_timeout(3);
        cli.set_read_timeout(5);
        httplib::Result r = (method == "GET")
            ? cli.Get(path.c_str())
            : cli.Post(path.c_str(), body, "application/json");
        if (!r) return {false, 0, ""};
        return {true, r->status, r->body};
    };
    {
        httplib::SSLClient tls(host, port);
        tls.enable_server_certificate_verification(false);
        auto res = run(tls);
        if (res.connected) return res;
    }
    httplib::Client plain(host, port);
    return run(plain);
}

std::vector<uint8_t> lp_join(const std::vector<std::string>& parts) {
    std::vector<uint8_t> buf;
    for (const auto& s : parts) {
        uint32_t n = static_cast<uint32_t>(s.size());
        for (int i = 0; i < 4; ++i) buf.push_back((n >> (i * 8)) & 0xFF);
        buf.insert(buf.end(), s.begin(), s.end());
    }
    return buf;
}

/// host:port -> {host, port(default 9100)}.
std::pair<std::string, int> split_hostport(const std::string& hp, int default_port) {
    auto colon = hp.rfind(':');
    if (colon == std::string::npos) return {hp, default_port};
    return {hp.substr(0, colon), std::atoi(hp.substr(colon + 1).c_str())};
}

struct GossipKeys {
    std::string pub_b64;
    crypto::Ed25519PrivateKey priv{};
    bool ok{false};
};

GossipKeys load_gossip_keys(const std::string& data_root) {
    GossipKeys k;
    std::ifstream f(std::filesystem::path(data_root) / "identity" / "keypair.json");
    if (!f) return k;
    try {
        auto env = json::parse(f);
        auto data = env.contains("data") && env["data"].is_object()
            ? env["data"] : json::parse(env.value("data", std::string{"{}"}));
        k.pub_b64 = data.value("public_key", "");
        auto priv = crypto::from_base64(data.value("private_key", ""));
        if (priv.size() != crypto::kEd25519PrivateKeySize || k.pub_b64.empty()) return k;
        std::memcpy(k.priv.data(), priv.data(), priv.size());
        k.ok = true;
    } catch (...) {}
    return k;
}

std::string sign_b64(crypto::SodiumCryptoService& crypto,
                     const crypto::Ed25519PrivateKey& sk,
                     const std::vector<uint8_t>& msg) {
    auto sig = crypto.ed25519_sign(sk, std::span<const uint8_t>(msg));
    return crypto::to_base64(std::span<const uint8_t>(sig.data(), sig.size()));
}

/// Verify the issued cert is bound to our pubkey and signed by the root anchor.
bool verify_issued_cert(crypto::SodiumCryptoService& crypto, const json& cert_j,
                        const std::string& our_pubkey_b64, const std::string& root_hex,
                        std::string& err) {
    gossip::ServerCertificate cert = cert_j.get<gossip::ServerCertificate>();
    if (cert.server_pubkey != our_pubkey_b64) {
        err = "certificate is bound to a different pubkey"; return false;
    }
    auto root_bytes = crypto::from_hex(root_hex);
    if (root_bytes.size() != crypto::kEd25519PublicKeySize) {
        err = "root pubkey is not 32 bytes"; return false;
    }
    auto issuer = crypto::from_base64(cert.issuer_pubkey);
    if (issuer.size() != crypto::kEd25519PublicKeySize ||
        std::memcmp(issuer.data(), root_bytes.data(), issuer.size()) != 0) {
        err = "certificate issuer does not match the mesh root pubkey"; return false;
    }
    crypto::Ed25519PublicKey root_pk{};
    std::memcpy(root_pk.data(), root_bytes.data(), root_bytes.size());
    auto canonical = gossip::canonical_cert_json(cert);
    auto canonical_bytes = std::vector<uint8_t>(canonical.begin(), canonical.end());
    auto sig = crypto::from_base64(cert.signature);
    if (sig.size() != crypto::kEd25519SignatureSize) { err = "bad signature size"; return false; }
    crypto::Ed25519Signature sigv{};
    std::memcpy(sigv.data(), sig.data(), sig.size());
    if (!crypto.ed25519_verify(root_pk, std::span<const uint8_t>(canonical_bytes), sigv)) {
        err = "certificate signature does not verify against the root pubkey"; return false;
    }
    return true;
}

/// Key-merge root_pubkey + seed_peers into the JSON config, preserving unknown keys.
void merge_config(const std::string& config_path, const std::string& root_hex,
                  const std::vector<std::string>& seeds) {
    json j = json::object();
    if (std::filesystem::exists(config_path)) {
        std::ifstream f(config_path);
        try { j = json::parse(f); } catch (...) { j = json::object(); }
        if (!j.is_object()) j = json::object();
    }
    j["root_pubkey"] = root_hex;
    std::vector<std::string> merged;
    if (j.contains("seed_peers") && j["seed_peers"].is_array())
        merged = j["seed_peers"].get<std::vector<std::string>>();
    for (const auto& s : seeds)
        if (std::find(merged.begin(), merged.end(), s) == merged.end()) merged.push_back(s);
    j["seed_peers"] = merged;
    std::ofstream out(config_path);
    out << j.dump(2) << "\n";
}

/// Probe candidate targets; return the first "host:port" that accepts onboarding.
std::string pick_target(const std::vector<std::string>& targets) {
    for (const auto& t : targets) {
        auto [host, port] = split_hostport(t, 9100);
        auto r = http_call(host, port, "GET", "/api/onboard/info", "");
        if (!r.connected || r.status != 200) continue;
        try {
            if (json::parse(r.body).value("accepts_onboarding", false)) return t;
        } catch (...) {}
    }
    return {};
}

} // namespace

int run_onboard_server(ServerConfig& config) {
    auto init = ensure_initialized(config);
    if (!init) return 1;

    auto keys = load_gossip_keys(config.data_root);
    if (!keys.ok) {
        spdlog::error("Onboard: could not load gossip keypair from {}/identity/keypair.json",
                      config.data_root);
        return 1;
    }

    crypto::SodiumCryptoService crypto;
    crypto.start();

    // Region + requested server_id.
    resolve_server_region(config, std::filesystem::path(config.data_root));
    std::string region = config.region;
    std::string server_id = config.onboard_server_id;
    if (server_id.empty()) {
        server_id = HostnameGenerator::generate_unique_hostname(
            region.empty() ? "unknown" : region, {});
    }
    if (!gossip::valid_server_id_label(server_id)) {
        spdlog::error("Onboard: server ID '{}' is not a valid DNS label", server_id);
        return 1;
    }

    // Target selection: explicit --onboard-server host:port, else DNS discovery.
    std::vector<std::string> targets;
    if (!config.onboard_target.empty()) {
        targets.push_back(config.onboard_target);
    } else if (!config.dns_base_domain.empty() && !region.empty()) {
        for (int tier : {1, 2}) {
            auto host = "tier" + std::to_string(tier) + "." + region + ".seip." +
                        config.dns_base_domain;
            for (const auto& ip : resolve_a_records(host))
                targets.push_back(ip + ":" + std::to_string(config.http_port));
        }
    }
    if (targets.empty()) {
        spdlog::error("Onboard: no target. Pass '--onboard-server <host:port>' or configure "
                      "DNS discovery (region + dns_base_domain).");
        return 1;
    }

    auto target = pick_target(targets);
    if (target.empty()) {
        spdlog::error("Onboard: no reachable server is accepting onboarding "
                      "(tried {} target(s)).", targets.size());
        return 1;
    }
    auto [host, port] = split_hostport(target, 9100);
    spdlog::info("Onboard: requesting admission from {} as '{}'", target, server_id);

    // Optional Tier1 evidence.
    std::string tpm_ak;
    // (AK export is a follow-up hookup; Tier2 cert by default.)

    // 1. Challenge.
    auto ch = http_call(host, port, "POST", "/api/onboard/challenge",
                        json{{"candidate_pubkey", keys.pub_b64}}.dump());
    if (!ch.connected || ch.status != 200) {
        spdlog::error("Onboard: challenge failed ({})", ch.body); return 1;
    }
    std::string nonce = json::parse(ch.body).value("nonce", "");

    // 2. Signed request.
    uint64_t ts = now_unix();
    auto req_sig = sign_b64(crypto, keys.priv,
        lp_join({"ln-onboard:v1", nonce, keys.pub_b64, server_id, region, tpm_ak,
                 std::to_string(ts)}));
    json reqbody{{"candidate_pubkey", keys.pub_b64}, {"server_id", server_id},
                 {"region", region}, {"tpm_ak_pubkey", tpm_ak}, {"nonce", nonce},
                 {"timestamp", ts}, {"signature", req_sig}};
    auto rq = http_call(host, port, "POST", "/api/onboard/request", reqbody.dump());
    if (!rq.connected || rq.status != 200) {
        spdlog::error("Onboard: admission request rejected ({})", rq.body); return 1;
    }
    std::string request_id = json::parse(rq.body).value("request_id", "");

    // Print our fingerprint for the admin's out-of-band comparison.
    std::printf("\nOnboarding request submitted.\n");
    std::printf("  server ID:   %s\n", server_id.c_str());
    std::printf("  fingerprint: %s\n", keys.pub_b64.substr(0, 16).c_str());
    std::printf("  Approve on the genesis:\n");
    std::printf("    curl -H 'Authorization: Bearer <admin-jwt>' -X POST \\\n");
    std::printf("      http://<genesis>:9101/api/onboard/approve/%s \\\n", request_id.c_str());
    std::printf("      -d '{\"fingerprint\":\"%s\"}'\n\n", keys.pub_b64.substr(0, 16).c_str());

    // 3. Poll until decided or timeout.
    const uint64_t deadline = now_unix() + config.onboard_timeout_sec;
    json approved;
    while (now_unix() < deadline) {
        uint64_t pts = now_unix();
        auto psig = sign_b64(crypto, keys.priv,
            lp_join({"ln-onboard-poll:v1", request_id, std::to_string(pts)}));
        auto pl = http_call(host, port, "POST", "/api/onboard/poll",
            json{{"request_id", request_id}, {"candidate_pubkey", keys.pub_b64},
                 {"timestamp", pts}, {"signature", psig}}.dump());
        if (pl.connected && pl.status == 200) {
            auto pj = json::parse(pl.body);
            auto state = pj.value("state", "");
            if (state == "approved") { approved = pj; break; }
            if (state == "denied" || state == "expired") {
                spdlog::error("Onboard: admission {} ({})", state, pj.value("reason", ""));
                return 1;
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    if (approved.is_null()) {
        spdlog::error("Onboard: timed out waiting for admission after {}s",
                      config.onboard_timeout_sec);
        return 1;
    }

    // 4. Verify + install the certificate.
    std::string root_hex = approved.value("root_pubkey", "");
    if (!config.root_pubkey.empty() && !root_hex.empty() && config.root_pubkey != root_hex) {
        spdlog::error("Onboard: delivered root pubkey does not match the configured --root-pubkey");
        return 1;
    }
    if (root_hex.empty()) root_hex = config.root_pubkey;
    std::string err;
    if (!verify_issued_cert(crypto, approved["certificate"], keys.pub_b64, root_hex, err)) {
        spdlog::error("Onboard: refusing certificate — {}", err);
        return 1;
    }

    storage::FileStorageService storage{std::filesystem::path(config.data_root)};
    storage.start();
    storage::SignedEnvelope env;
    env.type = "server_certificate";
    env.data = approved["certificate"].dump();
    env.timestamp = now_unix();
    if (!storage.write_file("identity", "server_cert.json", env)) {
        spdlog::error("Onboard: failed to write server_cert.json"); return 1;
    }

    std::vector<std::string> seeds;
    if (approved.contains("seed_peers"))
        seeds = approved["seed_peers"].get<std::vector<std::string>>();
    merge_config(config.config_path, root_hex, seeds);

    // 5. Acknowledge (releases the server-side pending record).
    uint64_t ats = now_unix();
    auto asig = sign_b64(crypto, keys.priv,
        lp_join({"ln-onboard-ack:v1", request_id, std::to_string(ats)}));
    (void)http_call(host, port, "POST", "/api/onboard/ack",
        json{{"request_id", request_id}, {"candidate_pubkey", keys.pub_b64},
             {"timestamp", ats}, {"signature", asig}}.dump());

    std::printf("\n====================================================================\n");
    std::printf("  Onboarded as '%s'\n", server_id.c_str());
    std::printf("====================================================================\n");
    std::printf("Certificate installed: %s/identity/server_cert.json\n", config.data_root.c_str());
    std::printf("Config updated:        %s (root_pubkey + %zu seed peer(s))\n",
                config.config_path.c_str(), seeds.size());
    std::printf("\nStart the server normally:\n");
    std::printf("  ./lemonade-nexus --data-root %s\n\n", config.data_root.c_str());

    storage.stop();
    crypto.stop();
    return 0;
}

} // namespace nexus::core
