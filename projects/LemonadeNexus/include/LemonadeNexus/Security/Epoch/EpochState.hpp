#pragma once

// The activated security state for one epoch.
//
// The thresholds come from the frozen member count at activation. An offline
// or failed member reduces liveness, never these values (architecture 16).
// The struct is immutable after activation: there are no mutating helpers,
// and membership changes only through the next atomic epoch transition.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Epoch/Tier1Set.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstddef>

namespace nexus::security {

struct EpochState {
    EpochId id{};
    NetworkId network_id{};

    Tier1Set tier1_members;

    std::size_t consensus_quorum{};
    std::size_t authority_threshold{};

    crypto::Ed25519PublicKey authority_public_key{};

    Digest attestation_root{};
    Digest participant_set_digest{};

    SecurityRulesetVersion security_ruleset{};
    ConsensusRulesetVersion consensus_ruleset{};
};

/// Computes the thresholds from the frozen member count, binds the
/// participant-set digest, and stamps the compiled ruleset versions.
[[nodiscard]] EpochState make_epoch_state(EpochId id,
                                          const NetworkId& network_id,
                                          Tier1Set tier1_members,
                                          const crypto::Ed25519PublicKey& authority_public_key,
                                          const Digest& attestation_root);

}  // namespace nexus::security
