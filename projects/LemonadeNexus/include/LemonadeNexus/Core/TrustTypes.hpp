#pragma once

// Evidence-side remnants of the old trust model. The mutable tiers, the
// rolling tokens, and the operation matrix are gone: Tier 1 authority lives
// in the mesh security system. What stays is pure evidence pinning.

#include <cstdint>
#include <cstddef>
#include <string>

namespace nexus::core {

inline constexpr std::size_t kMaxInlineEvidenceBytes = 16384;

struct PeerPlatformBinding {
    /// "" (nothing enrolled), "tpm2", or "snp-vtpm".
    std::string platform_class;
    /// The platform binding key: for tpm2 the AK, for snp-vtpm the HCLAkPub AMD
    /// vouched for. Base64 DER SubjectPublicKeyInfo.
    std::string ak_pubkey;
    /// Hex SHA-384 SNP launch measurement pinned at enrollment (snp-vtpm).
    std::string expected_measurement;
    /// Hex SHA-256 of the binary the operator approved at enrollment.
    std::string approved_binary_hash;

    [[nodiscard]] bool empty() const {
        return platform_class.empty() && ak_pubkey.empty() &&
               expected_measurement.empty() && approved_binary_hash.empty();
    }
};

}  // namespace nexus::core
