#pragma once

// The finalized epoch authority record (architecture 20).
//
// The previous epoch authorizes this record. After activation the group
// public key is authoritative only for its own epoch; historical keys stay
// valid for historical examination only.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstddef>
#include <string>
#include <string_view>

namespace nexus::security {

struct EpochAuthority {
    NetworkId network_id{};
    EpochId epoch{};

    // For the main authority key, key_generation == epoch.
    KeyGeneration key_generation{};

    SecurityRulesetVersion security_ruleset{};
    ConsensusRulesetVersion consensus_ruleset{};

    Digest tier1_set_digest{};

    std::size_t consensus_quorum{};
    std::size_t authority_threshold{};

    std::string frost_ciphersuite;
    crypto::Ed25519PublicKey group_public_key{};

    Digest dkg_transcript_digest{};
    Digest attestation_root{};
    Digest previous_checkpoint{};
};

inline constexpr std::string_view kEpochAuthorityDomain = "lemonade-nexus/epoch-authority:v1";

/// Every field, in declaration order. This digest is what the previous epoch
/// authority signs to authorize the handoff.
[[nodiscard]] inline Digest epoch_authority_digest(const EpochAuthority& authority) {
    CanonicalEncoder encoder(kEpochAuthorityDomain);
    encoder.add_bytes(authority.network_id);
    encoder.add_u64(authority.epoch);
    encoder.add_u64(authority.key_generation);
    encoder.add_u16(authority.security_ruleset);
    encoder.add_u16(authority.consensus_ruleset);
    encoder.add_bytes(authority.tier1_set_digest);
    encoder.add_u64(static_cast<uint64_t>(authority.consensus_quorum));
    encoder.add_u64(static_cast<uint64_t>(authority.authority_threshold));
    encoder.add_string(authority.frost_ciphersuite);
    encoder.add_bytes(authority.group_public_key);
    encoder.add_bytes(authority.dkg_transcript_digest);
    encoder.add_bytes(authority.attestation_root);
    encoder.add_bytes(authority.previous_checkpoint);
    return encoder.digest();
}

}  // namespace nexus::security
