#pragma once

// Core protocol scalar types shared across the security subsystem.
//
// NodeId is a distinct struct, not an array alias: consensus code passes node
// identities and digests side by side, and an accidental swap must not compile.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>

#include <array>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <span>

namespace nexus::security {

using EpochId = uint64_t;
using View = uint64_t;
using Height = uint64_t;
using KeyGeneration = uint64_t;
using IncarnationId = uint64_t;
using OperationId = uint64_t;
using SigningSessionId = uint64_t;

using SecurityRulesetVersion = uint16_t;
using ConsensusRulesetVersion = uint16_t;

inline constexpr std::size_t kDigestSize = 32;
using Digest = std::array<uint8_t, kDigestSize>;

// The network identity is the digest of the bootstrap certificate; Genesis
// fixes it once and every later object binds to it.
using NetworkId = Digest;

inline constexpr std::size_t kNonceSize = 32;
using Nonce = std::array<uint8_t, kNonceSize>;

// A node's identity is its raw Ed25519 identity public key.
inline constexpr std::size_t kNodeIdSize = crypto::kEd25519PublicKeySize;

struct NodeId {
    std::array<uint8_t, kNodeIdSize> bytes{};

    auto operator<=>(const NodeId&) const = default;

    [[nodiscard]] std::span<const uint8_t> span() const { return bytes; }
};

}  // namespace nexus::security
