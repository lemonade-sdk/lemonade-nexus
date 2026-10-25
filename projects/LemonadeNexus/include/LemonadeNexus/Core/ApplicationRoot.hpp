#pragma once

// The configured root management key as a tree principal. The application
// root itself is an EstablishRoot tree operation that Tier 1 commits through
// consensus (TreeConsensus::set_root_request), or it arrives with the one-time
// tree merge commit (TreeMerge.hpp). No caller creates it directly.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <algorithm>
#include <cctype>
#include <optional>
#include <span>
#include <string>

namespace nexus::core {

/// The configured root management key as a tree principal
/// ("ed25519:<base64>"), or nullopt when `root_pubkey_hex` is not a 32-byte
/// Ed25519 key in hex. Never throws.
inline std::optional<std::string> root_principal_from_hex(const std::string& root_pubkey_hex) {
    // Validate before decoding: from_hex throws, and callers run on the io
    // thread.
    const bool well_formed =
        root_pubkey_hex.size() == 2 * crypto::kEd25519PublicKeySize &&
        std::all_of(root_pubkey_hex.begin(), root_pubkey_hex.end(),
                    [](unsigned char c) { return std::isxdigit(c) != 0; });
    if (!well_formed) return std::nullopt;
    const auto bytes = crypto::from_hex(root_pubkey_hex);
    return "ed25519:" + crypto::to_base64(std::span<const uint8_t>(bytes.data(), bytes.size()));
}

}  // namespace nexus::core
