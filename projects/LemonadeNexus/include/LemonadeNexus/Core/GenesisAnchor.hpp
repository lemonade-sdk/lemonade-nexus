#pragma once

// The pinned Genesis anchor fixes the network id and which packaged release
// approval verifies. Daemon startup and CLI modes need the same triple; this
// is the one place that computes it.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Attestation/ReleaseApproval.hpp>
#include <LemonadeNexus/Security/Genesis/BootstrapCertificate.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <cstring>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>

namespace nexus::core {

struct GenesisAnchor {
    crypto::Ed25519PublicKey genesis_public_key{};
    security::NetworkId network_id{};
    /// Absent with `release_error` set when the packaged bundle is missing or
    /// unverified; callers decide whether that is fatal.
    std::optional<security::ReleaseApprovalBundleV1> release;
    std::string release_error;
};

/// Decode the anchor key, derive the network id it names, and load the
/// packaged release approval. nullopt only when `genesis_pubkey_b64` is not
/// a base64 Ed25519 public key.
[[nodiscard]] inline std::optional<GenesisAnchor> load_genesis_anchor(
        std::string_view genesis_pubkey_b64,
        const std::filesystem::path& release_approval_path =
            std::filesystem::path(security::kReleaseApprovalPath)) {
    const auto genesis_bytes =
        crypto::from_base64(crypto::canonical_key_b64(genesis_pubkey_b64));
    if (genesis_bytes.size() != crypto::kEd25519PublicKeySize) {
        return std::nullopt;
    }
    auto anchor = std::make_optional<GenesisAnchor>();
    std::memcpy(anchor->genesis_public_key.data(), genesis_bytes.data(),
                genesis_bytes.size());
    anchor->network_id = security::derive_network_id(
        anchor->genesis_public_key,
        security::constants::kSecurityRulesetVersion,
        security::constants::kConsensusRulesetVersion);
    anchor->release = security::load_release_approval_bundle(
        release_approval_path, anchor->genesis_public_key, anchor->network_id,
        anchor->release_error);
    return anchor;
}

}  // namespace nexus::core
