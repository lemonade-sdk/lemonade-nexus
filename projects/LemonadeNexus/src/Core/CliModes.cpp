#include <LemonadeNexus/Core/CliModes.hpp>

#include <LemonadeNexus/Core/BinaryAttestation.hpp>
#include <LemonadeNexus/Core/OnboardingClient.hpp>
#include <LemonadeNexus/Core/TeeAttestationTpm.hpp>
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

int run_print_tpm_ak() {
    auto ak = tpm::export_ak_pubkey_b64();
    if (!ak) {
        spdlog::error("No TPM available — cannot export an Attestation Key. "
                      "(Need /dev/tpmrm0 or a TCTI such as swtpm, on a Linux TPM build.)");
        return 1;
    }
    // Print the raw value to stdout so it can be piped into --enroll-tpm-ak.
    spdlog::info("TPM AK pubkey (base64 DER SPKI):");
    std::printf("%s\n", ak->c_str());
    return 0;
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

    gossip::CertIssueParams params;
    params.server_pubkey_b64 = config.enroll_server_pubkey;
    params.server_id         = config.enroll_server_id;
    params.tpm_ak_pubkey     = config.enroll_tpm_ak_pubkey;
    params.expires_at        = 0;

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
    if (params.tpm_ak_pubkey.empty()) {
        spdlog::warn("Enroll: no TPM AK pinned (--enroll-tpm-ak) — '{}' will be a Tier-2 "
                     "certificate and cannot reach Tier 1 under require_tee_attestation.",
                     config.enroll_server_id);
    } else {
        spdlog::info("Enroll: pinned TPM AK ({}...) for '{}'",
                     params.tpm_ak_pubkey.substr(0, 16), config.enroll_server_id);
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
    std::string cert_file = "server_cert_" + config.enroll_server_id + ".json";
    if (auto kp_env = enroll_storage.read_file("identity", "keypair.json")) {
        try {
            auto kp_j = nlohmann::json::parse(kp_env->data);
            if (kp_j.value("public_key", "") == config.enroll_server_pubkey) {
                cert_file = "server_cert.json";
            }
        } catch (...) {}
    }

    if (!enroll_storage.write_file("identity", cert_file, env)) {
        spdlog::error("Failed to write certificate to {}/identity/{}",
                      config.data_root, cert_file);
        return 1;
    }

    spdlog::info("Enrolled server '{}' (pubkey: {})", cert.server_id, cert.server_pubkey);
    if (cert_file == "server_cert.json") {
        spdlog::info("Enrolled our own gossip pubkey — installed as this server's "
                     "certificate: {}/identity/server_cert.json", config.data_root);
    } else {
        spdlog::info("Certificate written to {}/identity/{}", config.data_root, cert_file);
        spdlog::info("Copy it to the joining server as <data-root>/identity/server_cert.json, "
                     "then (re)start that server.");
    }
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
    if (config.print_tpm_ak)                      return run_print_tpm_ak();
    if (config.first_run)                         return run_first_run(config);
    if (config.onboard_server)                    return run_onboard_server(config);
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
