#pragma once

// The production evidence producer.
//
// It answers a challenge addressed to this node with what the platform can
// prove, then signs the envelope with the node identity key. It never
// fabricates: a host without a platform path returns an empty platform
// bundle, which the verifier fails.
//
// Architecture reference: Security Architecture Final Draft 1.1, sections 9,
// 18 and 25.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Attestation/EvidenceProducer.hpp>

#include <filesystem>
#include <functional>
#include <optional>
#include <string>

namespace nexus::security {

struct EvidenceProducerSources {
    /// This node's identity. The NodeId is identity.public_key.
    crypto::Ed25519Keypair identity;
    /// The epoch vote public key to bind. nullopt means none exists yet.
    std::function<std::optional<crypto::Ed25519PublicKey>(EpochId)> vote_key_for_epoch;
    /// VCEK and AMD chain cache for the Linux prover.
    std::filesystem::path cache_directory;
    /// Path of the nexus binary for the IMA measurement lookup. The platform
    /// prover resolves the running executable itself today; this value is
    /// never written into a bundle, because a self-declared path is the
    /// self-attestation that architecture 5.1 forbids.
    std::string nexus_binary_path;
};

class PlatformEvidenceProducer final : public IEvidenceProducer {
public:
    explicit PlatformEvidenceProducer(EvidenceProducerSources sources);

    /// nullopt for a challenge addressed to another identity, or when no
    /// vote key exists for the challenge epoch. Otherwise a signed bundle
    /// whose platform part is whatever the host produced — possibly empty.
    [[nodiscard]] std::optional<AttestationEvidence> produce(
        const AttestationChallenge& challenge) override;

    /// True when this build has a platform path (Linux + TPM stack). False
    /// means every produced bundle is empty. A host on a capable build can
    /// still produce an empty bundle; only produce() can show that, because
    /// a device node proves nothing (see PlatformProbe).
    [[nodiscard]] bool platform_available() const;

private:
    [[nodiscard]] SnpVtpmEvidence platform_bundle(const Digest& nonce) const;

    EvidenceProducerSources sources_;
};

}  // namespace nexus::security
