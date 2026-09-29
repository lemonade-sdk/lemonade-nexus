#include <LemonadeNexus/Core/OnboardingClient.hpp>

#include <LemonadeNexus/Core/CliModes.hpp>
#include <LemonadeNexus/Core/HostnameGenerator.hpp>
#include <LemonadeNexus/Core/NetUtil.hpp>
#include <LemonadeNexus/Core/OnboardingTypes.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Core/ServerIdentity.hpp>
#include <LemonadeNexus/Network/SeipNaming.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Gossip/ServerCertificate.hpp>
#include <LemonadeNexus/Security/EvidenceSnpVtpm.hpp>
#include <LemonadeNexus/Security/HclReport.hpp>
#include <LemonadeNexus/Security/TpmQuote.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include "OnboardingSeeds.hpp"
#include "OnboardingValidation.hpp"

#include <httplib.h>
#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <functional>
#include <optional>
#include <span>
#include <string_view>
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

/// GET/POST to an onboarding server over verified HTTPS. `host` MUST be the
/// server's certificate FQDN — the cert is verified against the system trust
/// store and the hostname. `connect_ip`, when set, lands the socket on that
/// address (httplib hostname->addr map) while still verifying `host`, for an
/// operator pinning a specific IP. No plaintext, no verification-disabled path.
HttpResult http_call(const std::string& host, int port, const std::string& method,
                     const std::string& path, const std::string& body,
                     const std::string& connect_ip = "") {
    httplib::SSLClient tls(host, port);
    if (!connect_ip.empty())
        tls.set_hostname_addr_map({{host, connect_ip}});
    tls.set_connection_timeout(3);
    tls.set_read_timeout(5);
    httplib::Result r = (method == "GET")
        ? tls.Get(path.c_str())
        : tls.Post(path.c_str(), body, "application/json");
    if (!r) return {false, 0, ""};
    return {true, r->status, r->body};
}

enum class HttpJsonFailure { none, not_connected, bad_status, invalid_json, invalid_fields };

template <typename T>
struct HttpJsonResult {
    HttpJsonFailure failure{HttpJsonFailure::none};
    int status{0};
    std::string body;
    std::string decode_error;
    std::optional<T> value;
};

/// POST `body` and decode a 200 response through `from_json`. Connection
/// failure and non-200 responses are reported (not_connected / bad_status)
/// without parsing, preserving the raw `body`; a 200 whose body is not JSON
/// is invalid_json with decode_error "/: invalid json"; a 200 that parses but
/// fails `from_json` is invalid_fields with the decode error in decode_error.
template <typename T>
HttpJsonResult<T> post_json(const std::string& host, int port, const std::string& path,
                            const std::string& body, const std::string& connect_ip,
                            const std::function<std::optional<T>(const json&, std::string&)>&
                                from_json) {
    HttpJsonResult<T> result;
    const auto r = http_call(host, port, "POST", path, body, connect_ip);
    result.status = r.status;
    result.body = std::move(r.body);
    if (!r.connected) {
        result.failure = HttpJsonFailure::not_connected;
        return result;
    }
    if (r.status != 200) {
        result.failure = HttpJsonFailure::bad_status;
        return result;
    }
    const auto parsed = json::parse(result.body, nullptr, false);
    if (parsed.is_discarded()) {
        result.failure = HttpJsonFailure::invalid_json;
        result.decode_error = "/: invalid json";
        return result;
    }
    if (auto value = from_json(parsed, result.decode_error))
        result.value = std::move(*value);
    else
        result.failure = HttpJsonFailure::invalid_fields;
    return result;
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
bool verify_issued_cert(crypto::SodiumCryptoService& crypto,
                        const gossip::ServerCertificate& cert,
                        const std::string& our_pubkey_b64, const std::string& root_hex,
                        std::string& err) {
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

/// Produce platform evidence bound to the admission challenge nonce, so the bundle
/// the root server verifies cannot be one captured from another node's join.
std::optional<security::SnpVtpmEvidence> collect_onboarding_evidence(
        const ServerConfig& config, const std::string& our_pubkey_b64,
        const std::string& nonce_b64) {
    security::EvidenceProduceConfig cfg;
    cfg.cache_dir = std::filesystem::path(config.data_root) / "attestation";
    try {
        cfg.identity_pubkey = crypto::from_base64(our_pubkey_b64);
    } catch (...) {
        return std::nullopt;
    }
    std::vector<uint8_t> nonce;
    try {
        nonce = crypto::from_base64(nonce_b64);
    } catch (...) {
        return std::nullopt;
    }

    std::string why;
    auto ev = security::produce_snp_vtpm_evidence(cfg, nonce, &why);
    if (!ev) spdlog::debug("Onboard: no platform evidence ({})", why);
    return ev;
}

/// Probe candidate targets; return the first "host:port" that accepts onboarding.
/// Logs why each candidate failed so an operator can see why discovery dead-ended
/// (connection/TLS failure, non-200, bad JSON, or the server refusing onboarding).
std::string pick_target(const std::vector<std::string>& targets,
                        const std::string& connect_ip) {
    for (const auto& t : targets) {
        const auto hp = nexus::net::splitHostPort(t, 9100);
        if (!hp) {
            spdlog::warn("Onboard: probe of {} failed: invalid host:port", t);
            continue;
        }
        auto [host, port] = *hp;
        auto r = http_call(host, port, "GET", "/api/onboard/info", "", connect_ip);
        if (!r.connected) {
            spdlog::warn("Onboard: probe of {} failed: not connected "
                         "(no TCP/TLS handshake; hostname verification may have "
                         "failed)", t);
            continue;
        }
        if (r.status != 200) {
            spdlog::warn("Onboard: probe of {} failed: HTTP {}", t, r.status);
            continue;
        }
        auto body = json::parse(r.body, nullptr, false);
        if (body.is_discarded()) {
            spdlog::warn("Onboard: probe of {} failed: /api/onboard/info is not "
                         "valid JSON", t);
            continue;
        }
        auto info = OnboardingInfoResponse::fromJson(body);
        if (info && info.value->accepts_onboarding) return t;
        spdlog::warn("Onboard: probe of {} failed: server is not accepting "
                     "onboarding", t);
    }
    return {};
}

} // namespace

std::vector<std::string> parse_discovery_txt_hosts(
    const std::vector<std::string>& txt_strings) {
    std::vector<std::string> hosts;
    static constexpr std::string_view kHostKey = "host=";
    for (const auto& record : txt_strings) {
        std::size_t pos = 0;
        while (pos < record.size()) {
            const auto space = record.find(' ', pos);
            const std::string field = record.substr(
                pos, space == std::string::npos ? std::string::npos : space - pos);
            pos = (space == std::string::npos) ? record.size() : space + 1;
            if (field.size() > kHostKey.size() &&
                field.compare(0, kHostKey.size(), kHostKey) == 0) {
                hosts.push_back(field.substr(kHostKey.size()));
            }
        }
    }
    return hosts;
}

std::vector<std::string> build_discovery_targets(
    const std::vector<std::string>& tier1_members,
    const std::vector<std::string>& tier2_members,
    const std::string& region,
    const std::string& dns_base_domain,
    int http_port) {
    std::vector<std::string> targets;
    const std::string port_suffix = ":" + std::to_string(http_port);
    for (int tier : {1, 2}) {
        const auto& members = (tier == 1) ? tier1_members : tier2_members;
        for (const auto& member : members)
            if (!member.empty()) targets.push_back(member + port_suffix);
        targets.push_back(nexus::seip::tierFqdn(tier, region, dns_base_domain) + port_suffix);
    }
    return targets;
}

std::string validate_pinned_root(const std::string& pinned_hex) {
    if (pinned_hex.empty())
        return "onboarding requires a pinned mesh root key: pass --root-pubkey <hex> "
               "(obtain it out of band — the genesis server prints it at --first-run)";
    try {   // from_hex throws on malformed input
        if (crypto::from_hex(pinned_hex).size() == crypto::kEd25519PublicKeySize)
            return {};
    } catch (...) {}
    return "--root-pubkey is not a 32-byte hex Ed25519 public key";
}

std::string check_root_confirmation(const std::string& pinned_hex,
                                    const std::string& delivered_hex) {
    if (delivered_hex.empty()) return {};   // confirm-only: absent is fine
    try {   // malformed delivered hex is a mismatch, not a crash
        if (crypto::from_hex(pinned_hex) == crypto::from_hex(delivered_hex))
            return {};
    } catch (...) {}
    return "server delivered a root pubkey that does not match the pinned "
           "--root-pubkey; refusing (possible MITM or wrong mesh)";
}

int run_onboard_server(ServerConfig& config) {
    // Trust must be pre-anchored: the response may confirm the root key,
    // never establish it.
    if (auto err = validate_pinned_root(config.root_pubkey); !err.empty()) {
        spdlog::error("Onboard: {}", err);
        return 1;
    }

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

    // Target selection: explicit --onboard-server <fqdn>[:port] (verified by its
    // certificate FQDN; --onboard-addr optionally pins the connect IP), else DNS
    // discovery of the region's tier SEIP FQDNs. We connect BY the FQDN — the
    // cert can't be verified against a bare IP.
    std::vector<std::string> targets;
    const std::string connect_ip = config.onboard_addr;
    if (!config.onboard_target.empty()) {
        targets.push_back(config.onboard_target);
    } else if (!config.dns_base_domain.empty() && !region.empty()) {
        // The server's ACME certificate covers the member FQDN
        // (<id>.<region>.seip.<base>) — never the tier name — so a probe of the
        // tier FQDN fails hostname verification. Fetch each tier's member list
        // from the aggregated tier TXT record and probe the member FQDNs (their
        // certificates verify and their own A records supply the IP); the tier
        // FQDN itself stays as a fallback candidate for deployments whose
        // certificate does cover tier names.
        std::vector<std::string> tier1_members;
        std::vector<std::string> tier2_members;
        for (int tier : {1, 2}) {
            const std::string tier_fqdn =
                nexus::seip::tierFqdn(tier, region, config.dns_base_domain);
            std::vector<std::string>& members =
                (tier == 1) ? tier1_members : tier2_members;
            const auto txt_strings = resolve_txt_records(tier_fqdn);
            if (txt_strings.empty()) {
                spdlog::warn("Onboard: tier TXT query for {} returned no records "
                             "(tier membership unavailable)", tier_fqdn);
                continue;
            }
            members = parse_discovery_txt_hosts(txt_strings);
            if (members.empty()) {
                spdlog::warn("Onboard: tier TXT record for {} lists no host= "
                             "members", tier_fqdn);
                continue;
            }
            spdlog::info("Onboard: tier{} member FQDNs: {}", tier, members.size());
        }
        targets = build_discovery_targets(tier1_members, tier2_members, region,
                                          config.dns_base_domain, config.http_port);
    }
    if (targets.empty()) {
        spdlog::error("Onboard: no target. Pass '--onboard-server <fqdn[:port]>' or configure "
                      "DNS discovery (region + dns_base_domain).");
        return 1;
    }

    auto target = pick_target(targets, connect_ip);
    if (target.empty()) {
        spdlog::error("Onboard: no reachable server is accepting onboarding "
                      "(tried {} target(s)).", targets.size());
        return 1;
    }
    const auto host_port = nexus::net::splitHostPort(target, 9100);
    if (!host_port) {
        spdlog::error("Onboard: invalid host:port in target '{}'", target);
        return 1;
    }
    auto [host, port] = *host_port;
    spdlog::info("Onboard: requesting admission from {} as '{}'", target, server_id);

    // 1. Challenge.
    ChallengeRequest challenge_request;
    challenge_request.candidate_pubkey = keys.pub_b64;
    auto ch = post_json<ChallengeResponse>(
        host, port, "/api/onboard/challenge", challenge_request.toJson().dump(),
        connect_ip,
        [](const json& j, std::string& error) -> std::optional<ChallengeResponse> {
            auto r = ChallengeResponse::fromJson(j);
            if (!r) { error = r.error; return std::nullopt; }
            return r.value;
        });
    if (ch.failure == HttpJsonFailure::not_connected ||
        ch.failure == HttpJsonFailure::bad_status) {
        spdlog::error("Onboard: challenge failed ({})", ch.body); return 1;
    }
    if (!ch.value) {
        spdlog::error("Onboard: invalid challenge response ({})", ch.decode_error);
        return 1;
    }
    const std::string& nonce = ch.value->nonce;

    // 2. Platform evidence, bound to the challenge nonce so this bundle admits only
    //    this join. Absent evidence is a Tier-2 certificate, not a failure.
    AdmissionRequest in;
    in.candidate_pubkey = keys.pub_b64;
    in.server_id        = server_id;
    in.region           = region;
    in.nonce            = nonce;
    in.timestamp        = now_unix();

    if (auto ev = collect_onboarding_evidence(config, keys.pub_b64, nonce)) {
        in.platform_class  = AdmissionPlatform::SnpVtpm;
        in.evidence        = security::encode_snp_vtpm_evidence(*ev);
        in.binary_hash     = ev->binary_sha256;
        in.evidence_sha256 = crypto::to_hex(crypto.sha256(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(in.evidence.data()), in.evidence.size())));
        if (auto blob = security::parse_hcl_blob(ev->hcl_blob)) {
            in.measurement   = blob->snp.measurement_hex();
            in.tpm_ak_pubkey = security::rsa_spki_b64(blob->ak.modulus, blob->ak.exponent);
        }
        spdlog::info("Onboard: attaching snp-vtpm evidence (measurement {}...)",
                     in.measurement.substr(0, 16));
    } else {
        spdlog::warn("Onboard: no platform evidence on this host — requesting a Tier-2 "
                     "certificate");
    }

    // 3. Signed request.
    in.signature = sign_b64(crypto, keys.priv, canonical_admission_request(in));
    if (!config.onboard_token.empty())
        in.enrollment_token = config.onboard_token;
    auto rq = post_json<AdmissionResponse>(
        host, port, "/api/onboard/request", in.toJson().dump(), connect_ip,
        [](const json& j, std::string& error) -> std::optional<AdmissionResponse> {
            auto r = AdmissionResponse::fromJson(j);
            if (!r) { error = r.error; return std::nullopt; }
            return r.value;
        });
    if (rq.failure == HttpJsonFailure::not_connected ||
        rq.failure == HttpJsonFailure::bad_status) {
        spdlog::error("Onboard: admission request rejected ({})", rq.body); return 1;
    }
    if (!rq.value) {
        spdlog::error("Onboard: invalid admission response ({})", rq.decode_error);
        return 1;
    }
    const std::string request_id = rq.value->request_id;

    // Print our fingerprint for the admin's out-of-band comparison.
    std::printf("\nOnboarding request submitted.\n");
    std::printf("  server ID:   %s\n", server_id.c_str());
    std::printf("  fingerprint: %s\n", keys.pub_b64.substr(0, 16).c_str());
    if (config.onboard_token.empty()) {
        std::printf("  Approve on the genesis:\n");
        std::printf("    curl -H 'Authorization: Bearer <admin-jwt>' -X POST \\\n");
        std::printf("      https://private.<genesis-fqdn>:9101/api/onboard/approve/%s \\\n", request_id.c_str());
        std::printf("      -d '{\"fingerprint\":\"%s\"}'\n", keys.pub_b64.substr(0, 16).c_str());
        std::printf("  (or skip the wait next time: mint a token on the root server with\n");
        std::printf("   --mint-admission-token and pass it via --onboard-token)\n\n");
    }

    // 3. Poll until decided or timeout.
    const uint64_t deadline = now_unix() + config.onboard_timeout_sec;
    std::optional<ApprovedOnboardingBundle> approved;
    while (now_unix() < deadline) {
        uint64_t pts = now_unix();
        PollRequest poll;
        poll.request_id = request_id;
        poll.candidate_pubkey = keys.pub_b64;
        poll.timestamp = pts;
        poll.signature = sign_b64(crypto, keys.priv,
            canonical_onboarding_status(kOnboardPollTag, request_id, pts));
        auto pl = post_json<PollResponse>(
            host, port, "/api/onboard/poll", poll.toJson().dump(), connect_ip,
            [](const json& j, std::string& error) -> std::optional<PollResponse> {
                auto r = poll_response_from_json(j);
                if (!r) { error = r.error; return std::nullopt; }
                return r.value;
            });
        if (pl.failure == HttpJsonFailure::invalid_json ||
            pl.failure == HttpJsonFailure::invalid_fields) {
            spdlog::error("Onboard: invalid poll response ({})", pl.decode_error);
            return 1;
        }
        if (pl.failure == HttpJsonFailure::none) {
            if (auto* bundle = std::get_if<ApprovedOnboardingBundle>(&*pl.value)) {
                approved = std::move(*bundle);
                break;
            }
            const auto& status = std::get<AdmissionStatusResponse>(*pl.value);
            if (status.state == AdmissionState::Denied ||
                status.state == AdmissionState::Expired) {
                spdlog::error("Onboard: admission {} ({})",
                              admission_state_name(status.state), status.reason);
                return 1;
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(5));
    }
    if (!approved) {
        spdlog::error("Onboard: timed out waiting for admission after {}s",
                      config.onboard_timeout_sec);
        return 1;
    }

    // 4. Verify + install the certificate — strictly against the pinned root.
    if (auto err = check_root_confirmation(config.root_pubkey, approved->root_pubkey);
        !err.empty()) {
        spdlog::error("Onboard: {}", err);
        return 1;
    }
    std::string err;
    if (!verify_issued_cert(crypto, approved->certificate, keys.pub_b64,
                            config.root_pubkey, err)) {
        spdlog::error("Onboard: refusing certificate — {}", err);
        return 1;
    }
    // Verify the Genesis binding before persisting any onboarding state.
    if (auto binding_err = onboarding_validation::check_bundle_genesis_binding(crypto,
                                                                              *approved);
        !binding_err.empty()) {
        spdlog::error("Onboard: refusing bundle — {}", binding_err);
        return 1;
    }

    storage::FileStorageService storage{std::filesystem::path(config.data_root)};
    storage.start();
    storage::SignedEnvelope env;
    env.type = "server_certificate";
    env.data = nlohmann::json(approved->certificate).dump();
    env.timestamp = now_unix();
    if (!storage.write_file("identity", "server_cert.json", env)) {
        spdlog::error("Onboard: failed to write server_cert.json"); return 1;
    }

    // The config file is root-protected: merge the seeds read-only and report
    // what the operator should apply instead of rewriting the file. A
    // config-file condition never blocks the run; the ack still goes out.
    // The onboarding target is the proven-reachable seed; a hostname target
    // is skipped (gossip peers are IP-only) with an operator note instead.
    std::vector<std::string> new_seeds;
    bool genesis_mismatch = false;
    std::string proven_skip_note;
    onboarding_seeds::plan_onboarded_seeds(config.config_path,
                                           approved->genesis_pubkey,
                                           approved->seed_peers,
                                           host, approved->gossip_port,
                                           new_seeds, genesis_mismatch,
                                           proven_skip_note);
    if (genesis_mismatch) {
        spdlog::warn("Onboard: the config at {} sets a genesis_pubkey that does not "
                     "match the admitted mesh; correct it before start — the daemon "
                     "will fail closed at startup against the wrong network",
                     config.config_path);
    }

    // Align our hostname with the admitted server_id so DNS/NS records carry
    // one name instead of an auto-generated <region>-N.
    if (HostnameGenerator::persist_hostname(std::filesystem::path(config.data_root), server_id)) {
        config.server_hostname = server_id;
    }

    // 5. Acknowledge (releases the server-side pending record).
    uint64_t ats = now_unix();
    AckRequest ack;
    ack.request_id = request_id;
    ack.candidate_pubkey = keys.pub_b64;
    ack.timestamp = ats;
    ack.signature = sign_b64(crypto, keys.priv,
        canonical_onboarding_status(kOnboardAckTag, request_id, ats));
    (void)http_call(host, port, "POST", "/api/onboard/ack",
                    ack.toJson().dump(), connect_ip);

    std::printf("\n====================================================================\n");
    std::printf("  Onboarded as '%s'\n", server_id.c_str());
    std::printf("====================================================================\n");
    std::printf("Certificate installed: %s/identity/server_cert.json\n", config.data_root.c_str());
    std::printf("Config file left untouched (root-protected trust anchors): %s\n",
                config.config_path.c_str());
    if (genesis_mismatch)
        std::printf("WARNING: the config's genesis_pubkey does not match the admitted\n"
                    "mesh. Correct it before start, or the daemon will fail closed at\n"
                    "startup against the wrong network.\n");
    std::printf("Approved anchors (verify they match your config):\n");
    std::printf("  root_pubkey:    %s\n",
                approved->root_pubkey.empty() ? config.root_pubkey.c_str()
                                              : approved->root_pubkey.c_str());
    std::printf("  genesis_pubkey: %s\n", approved->genesis_pubkey.c_str());
    if (new_seeds.empty()) {
        std::printf("No new seed peers to add.\n");
    } else {
        std::printf("Recommended seed_peers to add to %s (operator, as root):\n",
                    config.config_path.c_str());
        for (const auto& s : new_seeds)
            std::printf("  - %s\n", s.c_str());
    }
    if (!proven_skip_note.empty())
        std::printf("WARNING: %s\n", proven_skip_note.c_str());
    std::printf("\nStart the server normally:\n");
    std::printf("  ./lemonade-nexus --data-root %s\n\n", config.data_root.c_str());

    storage.stop();
    crypto.stop();
    return 0;
}

} // namespace nexus::core
