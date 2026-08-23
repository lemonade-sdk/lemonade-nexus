#pragma once

// Deterministic hash-ranked Tier 1 selection (architecture 8.3).
//
// The selector is pure: no network, no local randomness, no operator input,
// no mutable state. The seed comes from the current epoch authority key,
// which is fixed before the next eligible set is frozen — so no candidate
// can predict or steer its own score.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Epoch/Tier1Set.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstddef>
#include <vector>

namespace nexus::security {

class Tier1Selector {
public:
    /// Every eligible node, sorted ascending by (score, node_id). The full
    /// ranking exists so a failed selectee is replaced by the next
    /// hash-ranked candidate (architecture 8.5). The eligible set MUST be
    /// frozen before ranking, so a candidate cannot re-time its entry to
    /// shop for a better score.
    [[nodiscard]] static std::vector<NodeId> rank(
        const Tier1Set& frozen_eligible,
        const crypto::Ed25519PublicKey& current_epoch_group_key,
        EpochId next_epoch);

    /// The first min(count, pool size) nodes of rank().
    [[nodiscard]] static std::vector<NodeId> select(
        const Tier1Set& frozen_eligible,
        const crypto::Ed25519PublicKey& current_epoch_group_key,
        EpochId next_epoch,
        std::size_t count);
};

}  // namespace nexus::security
