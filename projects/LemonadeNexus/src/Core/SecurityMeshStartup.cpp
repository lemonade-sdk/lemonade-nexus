#include <LemonadeNexus/Core/SecurityMeshStartup.hpp>

#include <LemonadeNexus/Core/BootSet.hpp>
#include <LemonadeNexus/Core/GenesisAnchor.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Security/Attestation/LinuxAttestationProfile.hpp>
#include <LemonadeNexus/Security/Attestation/ReleaseApproval.hpp>
#include <LemonadeNexus/Security/Lifecycle/SecurityMeshService.hpp>
#include <LemonadeNexus/Security/Storage/StorageVault.hpp>

#include <chrono>

#include <spdlog/spdlog.h>

namespace nexus::core {

std::optional<SecurityMeshStartup> start_security_mesh(
        asio::io_context& io, const ServerConfig& config,
        gossip::GossipService& gossip, crypto::KeyWrappingService& key_wrapping,
        security::PlatformEvidenceSource platform_source,
        security::PlatformActivationSource activation_source, std::string& error,
        std::function<void()> on_epoch_established, const SecurityMeshStorageInputs& storage) {
    const auto anchor = load_genesis_anchor(config.genesis_pubkey);
    if (!anchor) {
        error = "genesis_pubkey is not a base64 Ed25519 public key";
        return std::nullopt;
    }
    security::SecurityMeshConfig mesh_config;
    mesh_config.data_root = std::filesystem::path(config.data_root);
    mesh_config.genesis_public_key = anchor->genesis_public_key;
    // Certificates bind to this network id; the gossip gate fails closed without it.
    gossip.set_network_id(crypto::to_hex(anchor->network_id));
    mesh_config.identity = gossip.keypair();
    // Release-global policy comes only from the verified packaged approval. A
    // missing or unverified object leaves the compiled SVSM template
    // incomplete; there is no local or environment fallback.
    const auto& release = anchor->release;
    mesh_config.profile = release
        ? security::profile_from_release_approval(release->approval)
        : security::linux_attestation_profile_v3_svsm_release();
    if (release) {
        // The value the bootstrap certificate commits; founding and adoption
        // both compare against it.
        mesh_config.release_approval_digest =
            security::release_approval_digest(release->approval);
    } else {
        spdlog::warn("Tier-1 release approval unavailable: {}", anchor->release_error);
    }
    if (!security::profile_is_complete(mesh_config.profile)) {
        for (const auto gap : security::profile_gaps(mesh_config.profile)) {
            spdlog::warn("Attestation profile v{} is incomplete: {}",
                         mesh_config.profile.profile_version,
                         security::profile_gap_name(gap));
        }
        spdlog::warn("No node can reach Tier 1 until the profile pins these values.");
    }
    mesh_config.platform_source = std::move(platform_source);
    mesh_config.activation_source = std::move(activation_source);
    mesh_config.on_epoch_established = std::move(on_epoch_established);
    mesh_config.storage_key_enabled = config.storage_key_enabled;
    if (config.storage_key_enabled) {
        // The share is sealed beside the gossip identity, with the same
        // backend, directory, and upgrade staging (B7 step 1).
        mesh_config.seal_backend = storage.seal_backend;
        mesh_config.sealed_directory =
            std::filesystem::path(config.data_root) / kSealedDirectory;
        if (release) {
            mesh_config.next_boot_chain = security::boot_pcrs_from_approval(release->approval);
        }
        mesh_config.vault = storage.vault;
    }
    auto startup = std::make_optional<SecurityMeshStartup>();
    startup->service =
        std::make_unique<security::SecurityMeshService>(io, mesh_config, gossip,
                                                        &key_wrapping);
    startup->service->start();
    startup->network_id_hex = crypto::to_hex(anchor->network_id);
    if (release) {
        startup->release_signing_pubkey_b64 =
            release->authority.release_signing_pubkey_b64;
        startup->release_approval_digest_hex =
            security::release_approval_digest_hex(release->approval);
    }
    return startup;
}

bool wait_for_storage_unlock(asio::io_context& io, const security::StorageVault& vault,
                             const std::function<bool()>& stop) {
    // Pacing only; the unlock itself retries with its own backoff.
    constexpr auto kSlice = std::chrono::milliseconds(100);
    while (!vault.files_ready() && !(stop && stop())) {
        if (io.stopped()) io.restart();
        (void)io.run_for(kSlice);
    }
    if (io.stopped()) io.restart();
    return vault.files_ready();
}

}  // namespace nexus::core
