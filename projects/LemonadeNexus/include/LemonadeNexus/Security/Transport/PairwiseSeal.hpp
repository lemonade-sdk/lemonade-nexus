#pragma once

// Confidentiality for pairwise DKG packages.
//
// A round-2 package is a secret share for one recipient. The transport
// authenticates the sender through the packet signature; this sealer adds
// confidentiality to the recipient only, so the package stays private on any
// path the mesh routes it over. Sealed to the X25519 form of the recipient's
// Ed25519 node identity; only the holder of that identity key can open it.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SecureBuffer.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace nexus::security {

class PairwiseSealer {
public:
    explicit PairwiseSealer(const crypto::Ed25519PrivateKey& own_identity_key);

    [[nodiscard]] std::optional<std::vector<uint8_t>> seal_for(
        const NodeId& recipient, std::span<const uint8_t> plaintext) const;

    [[nodiscard]] std::optional<std::vector<uint8_t>> unseal(
        std::span<const uint8_t> ciphertext) const;

    /// Bytes the seal adds to a plaintext.
    [[nodiscard]] static std::size_t overhead();

private:
    crypto::X25519PublicKey public_key_{};
    crypto::SecureBuffer secret_key_;
};

}  // namespace nexus::security
