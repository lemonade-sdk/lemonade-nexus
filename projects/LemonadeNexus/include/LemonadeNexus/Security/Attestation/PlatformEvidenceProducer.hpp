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

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>

namespace nexus::security {

/// Where the platform half of a bundle comes from. Unset means produce it here,
/// which needs TPM and IMA access in this process; set it to reach a privileged
/// helper (nexus-attestd) instead. Either way the identity key never leaves:
/// the source gets the challenge, which carries only the PUBLIC key.
///
/// It takes the whole challenge rather than a nonce so the helper cannot be
/// handed one — it derives the quote nonce itself, and the caller checks the
/// evidence came back bound to the digest it expected.
using PlatformEvidenceSource = std::function<PlatformEvidence(const AttestationChallenge&)>;

/// SVSM AK credential activation, run by the daemon that holds the node's TPM
/// access. All four fields travel as-is; returns the activated secret digest,
/// or nullopt with the daemon's typed reason in `failure`.
using PlatformActivationSource =
    std::function<std::optional<std::vector<uint8_t>>(
        std::span<const uint8_t> ek_public, std::span<const uint8_t> ak_public,
        std::span<const uint8_t> credential_blob, std::span<const uint8_t> encrypted_secret,
        std::string* failure)>;

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

    /// Optional out-of-process platform source; see PlatformEvidenceSource.
    /// Last so existing positional initialisation keeps working.
    PlatformEvidenceSource platform_source;

    /// Optional out-of-process activation source; see PlatformActivationSource.
    /// When unset, activate() refuses and the candidate cannot enroll.
    PlatformActivationSource activation_source;

    /// Optional time source for the enrollment-loop warn; unset means
    /// std::chrono::steady_clock::now(). Last so positional init keeps working.
    std::function<std::chrono::steady_clock::time_point()> clock;
};

class PlatformEvidenceProducer final : public IEvidenceProducer {
public:
    explicit PlatformEvidenceProducer(EvidenceProducerSources sources);

    /// nullopt for a challenge addressed to another identity, or when no
    /// vote key exists for the challenge epoch. Otherwise a signed bundle
    /// whose platform part is whatever the host produced — possibly empty.
    [[nodiscard]] std::optional<AttestationEvidence> produce(
        const AttestationChallenge& challenge) override;
    [[nodiscard]] std::optional<SvsmAkActivationResponseMessage> activate(
        const SvsmAkActivationOfferMessage& offer) override;

    /// True when this build has a platform path (Linux + TPM stack). False
    /// means every produced bundle is empty. A host on a capable build can
    /// still produce an empty bundle; only produce() can show that, because
    /// a device node proves nothing (see PlatformProbe).
    [[nodiscard]] bool platform_available() const;

    /// Enrollment-loop observability: consecutive enrollment-evidence
    /// productions since the last activation or non-enrollment produce, and
    /// warns emitted for the current streak.
    [[nodiscard]] std::size_t enrollment_streak() const { return enrollment_streak_; }
    [[nodiscard]] std::size_t enrollment_warnings() const { return enrollment_warnings_; }

private:
    [[nodiscard]] PlatformEvidence platform_bundle(const AttestationChallenge& challenge,
                                                    const Digest& nonce) const;
    /// Streak bookkeeping behind the enrollment-loop warn; called on every
    /// successful produce().
    void note_produced(const AttestationChallenge& challenge);

    EvidenceProducerSources sources_;

    // A candidate stuck re-answering enrollment challenges warns after ~2
    // minutes, then at that backoff. Reset by activation or any other produce.
    std::size_t enrollment_streak_ = 0;
    std::size_t enrollment_warnings_ = 0;
    std::chrono::steady_clock::time_point enrollment_first_{};
    std::chrono::steady_clock::time_point enrollment_warn_at_{};
};

}  // namespace nexus::security
