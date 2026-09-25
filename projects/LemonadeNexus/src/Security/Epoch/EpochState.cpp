#include <LemonadeNexus/Security/Epoch/EpochState.hpp>

#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <utility>

namespace nexus::security {

EpochState make_epoch_state(EpochId id,
                            const NetworkId& network_id,
                            Tier1Set tier1_members,
                            const crypto::Ed25519PublicKey& authority_public_key,
                            const Digest& attestation_root) {
    const std::size_t frozen_count = tier1_members.size();
    const Digest set_digest = tier1_members.digest();
    return EpochState{
        .id = id,
        .network_id = network_id,
        .tier1_members = std::move(tier1_members),
        .consensus_quorum = constants::consensus_quorum(frozen_count),
        .authority_threshold = constants::authority_threshold(frozen_count),
        .authority_public_key = authority_public_key,
        .attestation_root = attestation_root,
        .participant_set_digest = set_digest,
        .security_ruleset = constants::kSecurityRulesetVersion,
        .consensus_ruleset = constants::kConsensusRulesetVersion,
    };
}

}  // namespace nexus::security
