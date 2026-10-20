#pragma once

// The prover side of attestation.
//
// A producer answers a challenge addressed to this node with whatever the
// platform can show. It never fabricates: a host without a platform path
// produces an empty platform bundle, which the verifier fails, or nothing
// at all. The challenge digest is the quote nonce, and the node identity key
// signs the envelope that carries the epoch vote key.

#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>
#include <LemonadeNexus/Security/Attestation/SvsmAkEnrollment.hpp>

#include <optional>

namespace nexus::security {

class IEvidenceProducer {
public:
    virtual ~IEvidenceProducer() = default;
    [[nodiscard]] virtual std::optional<AttestationEvidence> produce(
        const AttestationChallenge& challenge) = 0;

    /// Candidate half of the profile-specific activation round.  Providers
    /// without a protected SVSM vTPM return nullopt.
    [[nodiscard]] virtual std::optional<SvsmAkActivationResponseMessage> activate(
        const SvsmAkActivationOfferMessage&) { return std::nullopt; }
};

}  // namespace nexus::security
