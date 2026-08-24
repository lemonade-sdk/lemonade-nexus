#include <LemonadeNexus/Core/CliModes.hpp>

#include <LemonadeNexus/Core/AdmissionTokenStore.hpp>
#include <LemonadeNexus/Core/BinaryAttestation.hpp>
#include <LemonadeNexus/Core/OnboardingClient.hpp>
#include <LemonadeNexus/Security/PlatformProbe.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Gossip/ServerCertificate.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <spdlog/spdlog.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <span>
#include <system_error>

namespace nexus::core {

namespace {

uint64_t now_unix() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

/// Is the pubkey being enrolled this host's own gossip key?
bool enrolling_self(storage::FileStorageService& storage, const std::string& pubkey_b64) {
    auto kp_env = storage.read_file("identity", "keypair.json");
    if (!kp_env) return false;
    try {
        return nlohmann::json::parse(kp_env->data).value("public_key", "") == pubkey_b64;
    } catch (...) {
        return false;
    }
}


int run_verify_platform(const ServerConfig& config) {
    security::PlatformProbeConfig cfg;
    cfg.cache_dir = std::filesystem::path(config.data_root) / "attestation";
    if (!config.verify_platform_blob.empty()) {
        cfg.hcl_blob_override = config.verify_platform_blob;
    }
    const auto result = security::probe_platform(cfg);
    std::printf("%s", security::format_probe_report(result).c_str());
    return result.tier1_capable ? 0 : 1;
}

int run_first_run(const ServerConfig& config) {
    auto init = ensure_initialized(config);
    if (!init) return 1;

    const auto node_id  = "server-" + init->identity_pubkey_hex.substr(0, 16);
    const auto data_abs =
        std::filesystem::absolute(config.data_root).lexically_normal().string();

    std::printf("\n");
    std::printf("====================================================================\n");
    std::printf("  Lemonade-Nexus — server initialized\n");
    std::printf("====================================================================\n");
    std::printf("Data directory:   %s\n", data_abs.c_str());
    std::printf("Identity pubkey:  %s%s\n",
                init->identity_pubkey_hex.c_str(), init->identity_created ? "" : "  (existing)");
    std::printf("Gossip pubkey:    %s%s\n",
                init->gossip_pubkey_b64.c_str(), init->gossip_created ? "" : "  (existing)");
    std::printf("Default node ID:  %s\n", node_id.c_str());
    std::printf("\n");
    std::printf("Next steps\n");
    std::printf("----------\n");
    std::printf("GENESIS (first server of a new mesh):\n");
    std::printf("  ./lemonade-nexus --root-pubkey %s\n", init->identity_pubkey_hex.c_str());
    std::printf("  The identity pubkey above IS the mesh root pubkey; every other\n");
    std::printf("  server must be started with that same --root-pubkey value.\n");
    std::printf("\n");
    std::printf("JOIN an existing mesh:\n");
    std::printf("  ./lemonade-nexus --onboard-server [host:port] --data-root %s\n",
                config.data_root.c_str());
    std::printf("  (requests admission over the mesh's public API; the mesh admin\n");
    std::printf("   approves it, no file copying needed)\n");
    std::printf("\n");

    return 0;
}

int run_enroll(const ServerConfig& config) {
    // The ID becomes the server's node ID: an IPAM allocation key and a
    // public DNS label (<id>.<region>.seip.<domain>, _config.<id>, ...),
    // and below it is embedded in the output filename.
    if (!gossip::valid_server_id_label(config.enroll_server_id)) {
        spdlog::error("Cannot enroll: server ID '{}' must be a DNS label — "
                      "1-63 chars of [a-z0-9-], no leading/trailing hyphen.",
                      config.enroll_server_id);
        return 1;
    }

    crypto::SodiumCryptoService enroll_crypto;
    enroll_crypto.start();

    // Peers match cert.server_pubkey against the base64 gossip pubkey a
    // server announces, so anything else (e.g. the hex root pubkey) would
    // produce a cert that never verifies against a live peer.
    if (crypto::from_base64(config.enroll_server_pubkey).size() !=
        crypto::kEd25519PublicKeySize) {
        spdlog::error("Cannot enroll: pubkey is not a base64 Ed25519 key. Pass the "
                      "gossip pubkey the joining server prints at startup: "
                      "'[GossipService] listening ... (pubkey: <base64>)'.");
        return 1;
    }
    storage::FileStorageService enroll_storage{std::filesystem::path(config.data_root)};
    enroll_storage.start();
    crypto::KeyWrappingService enroll_kw{enroll_crypto, enroll_storage};
    enroll_kw.start();

    auto privkey = enroll_kw.unlock_identity({});
    auto pubkey = enroll_kw.load_identity_pubkey();
    if (!privkey || !pubkey) {
        spdlog::error("Cannot enroll: root identity not available. "
                      "Run '--first-run' first to initialize this server's identity.");
        return 1;
    }

    // Only the root-key holder may issue certificates. A fresh genesis has an
    // empty root_pubkey (the operator sets it after --first-run), so enforce the
    // match only once an anchor is configured — otherwise genesis bootstrap breaks.
    if (!config.root_pubkey.empty()) {
        std::vector<uint8_t> have(pubkey->begin(), pubkey->end());
        std::vector<uint8_t> want;
        try { want = crypto::from_hex(config.root_pubkey); } catch (...) {}
        if (have != want) {
            spdlog::error("Cannot enroll: this server's identity is not the configured root "
                          "key (root_pubkey); only the root-key holder may issue certificates.");
            return 1;
        }
    }

    gossip::CertIssueParams params;
    params.server_pubkey_b64 = config.enroll_server_pubkey;
    params.server_id         = config.enroll_server_id;
    params.tpm_ak_pubkey     = config.enroll_tpm_ak_pubkey;
    params.expires_at        = 0;

    // Self-enrollment is the only manual path that can prove anything: we are the
    // host being enrolled, so run the probe and take the policy from what actually
    // verified. Nothing is typed in — an operator cannot pin a measurement this
    // host does not produce, and cannot forget to pin one it does.
    const bool self_enroll = enrolling_self(enroll_storage, config.enroll_server_pubkey);
    if (self_enroll) {
        security::PlatformProbeConfig probe_cfg;
        probe_cfg.cache_dir = std::filesystem::path(config.data_root) / "attestation";
        const auto probe = security::probe_platform(probe_cfg);
        if (probe.tier1_capable) {
            params.platform_class       = std::string(evidence_profile_name(probe.profile));
            params.tpm_ak_pubkey        = probe.ak_pub_b64;
            params.expected_measurement = probe.measurement_hex;
            params.approved_binary_hash = probe.binary_sha256;
            spdlog::info("Enroll: platform evidence verified — issuing a '{}' certificate",
                         params.platform_class);
        } else {
            spdlog::warn("Enroll: no verified platform evidence on this host ({}) — issuing a "
                         "Tier-2 certificate", probe.failure);
        }
    }

    if (!config.enroll_tpm_ek_cert_path.empty()) {
        std::ifstream ek_f(config.enroll_tpm_ek_cert_path);
        if (ek_f) {
            std::string ek_pem((std::istreambuf_iterator<char>(ek_f)),
                                std::istreambuf_iterator<char>());
            params.tpm_ek_cert = ek_pem;
            spdlog::info("Enroll: attached EK certificate from {} ({} bytes) — validate the "
                         "EK→AK chain to the TPM vendor CA before trusting this AK.",
                         config.enroll_tpm_ek_cert_path, ek_pem.size());
        } else {
            spdlog::warn("Enroll: could not read EK cert '{}' — continuing without it",
                         config.enroll_tpm_ek_cert_path);
        }
    }
    if (params.platform_class.empty()) {
        spdlog::warn("Enroll: '{}' gets a Tier-2 certificate. Only a host that proves its own "
                     "platform can hold a Tier-1 one — self-enroll there, or let it join "
                     "through --onboard-server, which verifies evidence at admission.",
                     config.enroll_server_id);
    }

    auto cert = gossip::issue_server_certificate(params, enroll_crypto, *privkey, *pubkey);

    nlohmann::json cert_json = cert;
    storage::SignedEnvelope env;
    env.type = "server_certificate";
    env.data = cert_json.dump();
    env.timestamp = cert.issued_at;

    // identity/server_cert.json is this server's OWN live certificate
    // (gossip, DDNS, and node-id resolution all read it), so only install
    // there when enrolling our own gossip pubkey. Certs issued for other
    // servers go to a sibling file the admin copies to the joining server.
    const std::string cert_file = self_enroll
        ? "server_cert.json"
        : "server_cert_" + config.enroll_server_id + ".json";

    if (!enroll_storage.write_file("identity", cert_file, env)) {
        spdlog::error("Failed to write certificate to {}/identity/{}",
                      config.data_root, cert_file);
        return 1;
    }

    spdlog::info("Enrolled server '{}' (pubkey: {})", cert.server_id, cert.server_pubkey);
    if (self_enroll) {
        spdlog::info("Enrolled our own gossip pubkey — installed as this server's "
                     "certificate: {}/identity/server_cert.json", config.data_root);
    } else {
        spdlog::info("Certificate written to {}/identity/{}", config.data_root, cert_file);
        spdlog::info("Copy it to the joining server as <data-root>/identity/server_cert.json, "
                     "then (re)start that server.");
    }
    return 0;
}

int run_mint_admission_token(const ServerConfig& config) {
    // A token pre-authorizes admission to the mesh anchored at root_pubkey, so
    // minting is stricter than --enroll-server: no anchor, no token.
    if (config.root_pubkey.empty()) {
        spdlog::error("Cannot mint: no --root-pubkey configured. The mesh root pubkey is "
                      "printed by --first-run on the genesis server.");
        return 1;
    }
    // Candidate binding is mandatory: the token is a bearer credential carried
    // over the unauthenticated onboarding transport, so it must be spendable
    // only by the joining server's own key.
    if (config.mint_token_candidate.empty()) {
        spdlog::error("Cannot mint: --token-candidate <b64> is required. Pass the joining "
                      "server's gossip pubkey (printed as 'Gossip pubkey' at its --first-run).");
        return 1;
    }

    crypto::SodiumCryptoService mint_crypto;
    mint_crypto.start();
    storage::FileStorageService mint_storage{std::filesystem::path(config.data_root)};
    mint_storage.start();
    crypto::KeyWrappingService mint_kw{mint_crypto, mint_storage};
    mint_kw.start();

    auto pubkey = mint_kw.load_identity_pubkey();
    if (!pubkey) {
        spdlog::error("Cannot mint: root identity not available. "
                      "Run '--first-run' first to initialize this server's identity.");
        return 1;
    }
    std::vector<uint8_t> have(pubkey->begin(), pubkey->end());
    std::vector<uint8_t> want;
    try { want = crypto::from_hex(config.root_pubkey); } catch (...) {}
    if (have != want) {
        spdlog::error("Cannot mint: this server's identity is not the configured root key "
                      "(root_pubkey); only the root-key holder may mint admission tokens.");
        return 1;
    }

    // The store is shared with a live daemon on the same data_root — no restart
    // needed; single-use is enforced by an atomic file remove at consumption.
    AdmissionTokenStore tokens{mint_storage, mint_crypto};
    auto minted = tokens.mint(config.mint_token_candidate,
                              std::chrono::seconds{config.mint_token_ttl_sec});
    if (!minted) return 1;

    std::printf("\nServer-admission enrollment token (single-use):\n");
    std::printf("  token:      %s\n", minted->first.c_str());
    std::printf("  expires_at: %llu (unix)\n",
                static_cast<unsigned long long>(minted->second.expires_at));
    std::printf("  bound to:   %s\n", minted->second.candidate_pubkey.c_str());
    std::printf("\nOn the joining server:\n");
    std::printf("  ./lemonade-nexus --onboard-server <host:port> \\\n");
    std::printf("      --root-pubkey %s \\\n", config.root_pubkey.c_str());
    std::printf("      --onboard-token %s\n\n", minted->first.c_str());
    return 0;
}

int run_revoke(const ServerConfig& config) {
    // Load existing revoked list, append, save
    storage::FileStorageService rev_storage{std::filesystem::path(config.data_root)};
    rev_storage.start();

    nlohmann::json revoked = nlohmann::json::array();
    auto env = rev_storage.read_file("identity", "revoked_servers.json");
    if (env) {
        try { revoked = nlohmann::json::parse(env->data); } catch (...) {}
    }
    revoked.push_back(config.revoke_server_pubkey);

    storage::SignedEnvelope rev_env;
    rev_env.type = "revocation_list";
    rev_env.data = revoked.dump();
    rev_env.timestamp = now_unix();
    (void)rev_storage.write_file("identity", "revoked_servers.json", rev_env);

    spdlog::info("Revoked server pubkey: {}", config.revoke_server_pubkey);
    rev_storage.stop();
    return 0;
}

int run_add_manifest(const ServerConfig& config) {
    crypto::SodiumCryptoService manifest_crypto;
    manifest_crypto.start();
    storage::FileStorageService manifest_storage{std::filesystem::path(config.data_root)};
    manifest_storage.start();

    BinaryAttestationService manifest_attestation{manifest_crypto, manifest_storage};
    // if release signing pubkey is empty we need to really throw, it should always
    //be there no matter what, even if our platform doesnt support TEE
    if (!config.release_signing_pubkey.empty()) {
        manifest_attestation.set_release_signing_pubkey(config.release_signing_pubkey);
    }

    try {
        std::ifstream f(config.add_manifest_path);
        auto j = nlohmann::json::parse(f);
        auto manifest = j.get<ReleaseManifest>();

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

} // namespace

std::optional<InitResult> ensure_initialized(const ServerConfig& config) {
    std::error_code ec;
    std::filesystem::create_directories(config.data_root, ec);
    if (ec) {
        spdlog::error("Cannot create data directory '{}': {}", config.data_root, ec.message());
        return std::nullopt;
    }

    crypto::SodiumCryptoService crypto;
    crypto.start();
    storage::FileStorageService storage{std::filesystem::path(config.data_root)};
    storage.start();
    crypto::KeyWrappingService kw{crypto, storage};
    kw.start();

    InitResult result;

    // Identity keypair (identity/keypair.pub + keypair.enc). On a genesis
    // server this pubkey doubles as the mesh root pubkey.
    auto identity_pub = kw.load_identity_pubkey();
    if (!identity_pub) {
        auto generated = kw.generate_and_store_identity({});
        identity_pub = generated.public_key;
        result.identity_created = true;
    }
    result.identity_pubkey_hex = crypto::to_hex(
        std::span<const uint8_t>(identity_pub->data(), identity_pub->size()));

    // Gossip keypair (identity/keypair.json) — same file and format
    // GossipService loads at startup. Its pubkey is what certificates bind
    // to, so creating it here lets a server be enrolled before it ever runs.
    if (auto kp_env = storage.read_file("identity", "keypair.json")) {
        try {
            auto kp_j = nlohmann::json::parse(kp_env->data);
            result.gossip_pubkey_b64 = kp_j.value("public_key", "");
        } catch (...) {}
    }
    if (result.gossip_pubkey_b64.empty()) {
        auto kp = crypto.ed25519_keygen();
        result.gossip_pubkey_b64 = crypto::to_base64(
            std::span<const uint8_t>(kp.public_key.data(), kp.public_key.size()));
        storage::SignedEnvelope kp_env;
        kp_env.type = "identity_keypair";
        nlohmann::json kp_json;
        kp_json["public_key"]  = result.gossip_pubkey_b64;
        kp_json["private_key"] = crypto::to_base64(
            std::span<const uint8_t>(kp.private_key.data(), kp.private_key.size()));
        kp_env.data = kp_json.dump();
        kp_env.signer_pubkey = "ed25519:" + result.gossip_pubkey_b64;
        kp_env.timestamp = now_unix();
        if (!storage.write_file("identity", "keypair.json", kp_env)) {
            spdlog::error("Failed to write {}/identity/keypair.json", config.data_root);
            return std::nullopt;
        }
        result.gossip_created = true;
    }

    kw.stop();
    storage.stop();
    crypto.stop();
    return result;
}

std::optional<int> run_cli_mode(ServerConfig& config, const char* argv0) {
    if (config.verify_platform)                   return run_verify_platform(config);
    if (config.first_run)                         return run_first_run(config);
    if (config.onboard_server)                    return run_onboard_server(config);
    if (config.mint_admission_token)              return run_mint_admission_token(config);
    if (!config.enroll_server_pubkey.empty())     return run_enroll(config);
    if (!config.revoke_server_pubkey.empty())     return run_revoke(config);
    if (!config.add_manifest_path.empty())        return run_add_manifest(config);

    // --- Refuse to start without an initialized data directory ---
    // A fresh box with no seed peers would otherwise silently bootstrap itself
    // as a brand-new one-node genesis mesh (own root chain, gateway tunnel IP,
    // ns1 claim) instead of joining anything.
    const std::filesystem::path dr{config.data_root};
    if (!std::filesystem::exists(dr)) {
        spdlog::error("Data directory '{}' not found.", config.data_root);
        spdlog::error("Initialize this server first:  {} --first-run", argv0);
        spdlog::error("(or pass --data-root <path> pointing at an initialized data directory)");
        return 1;
    }
    if (!std::filesystem::exists(dr / "identity" / "keypair.pub")) {
        spdlog::error("Data directory '{}' is not initialized (identity/keypair.pub missing).",
                      config.data_root);
        spdlog::error("Initialize this server first:  {} --first-run --data-root {}",
                      argv0, config.data_root);
        return 1;
    }

    return std::nullopt;
}

} // namespace nexus::core
