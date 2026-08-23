#pragma once

// The one-time bridge from Genesis authority to Epoch 1.
//
// Genesis signs exactly one certificate, over the finalized Epoch 1 facts.
// Epoch 1 consumes it; later epochs chain from epoch authority records and
// never look at Genesis again. There is no post-genesis override.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstddef>

namespace nexus::security {

// Fixed before the certificate exists: every later object binds to this value,
// including the certificate itself.
[[nodiscard]] NetworkId derive_network_id(const crypto::Ed25519PublicKey& genesis_public_key,
                                          SecurityRulesetVersion security_ruleset,
                                          ConsensusRulesetVersion consensus_ruleset);

struct BootstrapCertificate {
    NetworkId network_id{};

    EpochId epoch = 1;

    Digest tier1_set_digest{};
    std::size_t authority_threshold = 0;

    crypto::Ed25519PublicKey authority_public_key{};

    Digest dkg_transcript_digest{};
    Digest attestation_root{};

    SecurityRulesetVersion security_ruleset = 0;
    ConsensusRulesetVersion consensus_ruleset = 0;

    crypto::Ed25519Signature genesis_signature{};
};

[[nodiscard]] Digest bootstrap_certificate_signing_digest(const BootstrapCertificate& certificate);

[[nodiscard]] bool verify_bootstrap_certificate(const BootstrapCertificate& certificate,
                                                const crypto::Ed25519PublicKey& genesis_public_key);

}  // namespace nexus::security
