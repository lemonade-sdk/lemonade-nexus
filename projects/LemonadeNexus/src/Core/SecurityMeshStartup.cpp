#include <LemonadeNexus/Core/SecurityMeshStartup.hpp>

#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Security/Attestation/LinuxAttestationProfile.hpp>
#include <LemonadeNexus/Security/Genesis/BootstrapCertificate.hpp>
#include <LemonadeNexus/Security/Lifecycle/SecurityMeshService.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <spdlog/spdlog.h>

#include <cstring>

namespace nexus::core {

std::optional<SecurityMeshStartup> start_security_mesh(
        asio::io_context& io, const ServerConfig& config,
        gossip::GossipService& gossip, crypto::KeyWrappingService& key_wrapping,
        security::PlatformEvidenceSource platform_source, std::string& error) {
    const auto genesis_bytes = crypto::from_base64(
        crypto::canonical_key_b64(config.genesis_pubkey));
    if (genesis_bytes.size() != crypto::kEd25519PublicKeySize) {
        error = "genesis_pubkey is not a base64 Ed25519 public key";
        return std::nullopt;
    }
    security::SecurityMeshConfig mesh_config;
    mesh_config.data_root = std::filesystem::path(config.data_root);
    std::memcpy(mesh_config.genesis_public_key.data(), genesis_bytes.data(),
                genesis_bytes.size());
    // Certificates bind to this network id; the gossip gate fails closed without it.
    const auto network_id = security::derive_network_id(
        mesh_config.genesis_public_key,
        security::constants::kSecurityRulesetVersion,
        security::constants::kConsensusRulesetVersion);
    gossip.set_network_id(crypto::to_hex(network_id));
    mesh_config.identity = gossip.keypair();
    // The named profile, not a default-constructed one. It is currently
    // incomplete by design, so every attestation fails with
    // ProfileIncomplete until a qualifying host supplies the pinned values.
    mesh_config.profile = security::linux_attestation_profile_v1();
    if (!security::profile_is_complete(mesh_config.profile)) {
        for (const auto gap : security::profile_gaps(mesh_config.profile)) {
            spdlog::warn("Attestation profile v{} is incomplete: {}",
                         mesh_config.profile.profile_version,
                         security::profile_gap_name(gap));
        }
        spdlog::warn("No node can reach Tier 1 until the profile pins these values.");
    }
    mesh_config.platform_source = std::move(platform_source);
    auto startup = std::make_optional<SecurityMeshStartup>();
    startup->service =
        std::make_unique<security::SecurityMeshService>(io, mesh_config, gossip,
                                                        &key_wrapping);
    startup->service->start();
    startup->network_id_hex = crypto::to_hex(network_id);
    return startup;
}

}  // namespace nexus::core
