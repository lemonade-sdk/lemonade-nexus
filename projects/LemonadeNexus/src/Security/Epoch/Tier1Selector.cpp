#include <LemonadeNexus/Security/Epoch/Tier1Selector.hpp>

#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <algorithm>
#include <tuple>

namespace nexus::security {

namespace {

[[nodiscard]] Digest selection_seed(const crypto::Ed25519PublicKey& group_key, EpochId next_epoch) {
    CanonicalEncoder encoder(constants::kTier1SelectDomain);
    encoder.add_string("seed");
    encoder.add_bytes(group_key);
    encoder.add_u64(next_epoch);
    return encoder.digest();
}

[[nodiscard]] Digest score(const Digest& seed, const NodeId& node) {
    CanonicalEncoder encoder(constants::kTier1SelectDomain);
    encoder.add_string("score");
    encoder.add_bytes(seed);
    encoder.add_bytes(node.bytes);
    return encoder.digest();
}

}  // namespace

std::vector<NodeId> Tier1Selector::rank(const Tier1Set& frozen_eligible,
                                        const crypto::Ed25519PublicKey& current_epoch_group_key,
                                        EpochId next_epoch) {
    const Digest seed = selection_seed(current_epoch_group_key, next_epoch);

    struct Scored {
        Digest score;
        NodeId node;
    };
    std::vector<Scored> scored;
    scored.reserve(frozen_eligible.size());
    for (const auto& node : frozen_eligible.members()) {
        scored.push_back({score(seed, node), node});
    }
    std::sort(scored.begin(), scored.end(), [](const Scored& a, const Scored& b) {
        return std::tie(a.score, a.node) < std::tie(b.score, b.node);
    });

    std::vector<NodeId> ranked;
    ranked.reserve(scored.size());
    for (const auto& entry : scored) {
        ranked.push_back(entry.node);
    }
    return ranked;
}

std::vector<NodeId> Tier1Selector::select(const Tier1Set& frozen_eligible,
                                          const crypto::Ed25519PublicKey& current_epoch_group_key,
                                          EpochId next_epoch,
                                          std::size_t count) {
    std::vector<NodeId> ranked = rank(frozen_eligible, current_epoch_group_key, next_epoch);
    if (count < ranked.size()) {
        ranked.resize(count);
    }
    return ranked;
}

}  // namespace nexus::security
