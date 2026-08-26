#include <LemonadeNexus/Security/Eligibility/EligibilityObservation.hpp>

#include <LemonadeNexus/Security/CanonicalEncoding.hpp>

#include <sodium.h>

#include <string>
#include <utility>

namespace nexus::security {

namespace {

inline constexpr std::string_view kObservationDomain =
    "LEMONADE-NEXUS-T1-OBSERVATION-V1";

}  // namespace

Digest observation_signing_digest(const EligibilityObservation& observation) {
    CanonicalEncoder encoder(kObservationDomain);
    encoder.add_bytes(observation.network_id);
    encoder.add_u64(observation.epoch);
    encoder.add_bytes(observation.subject.bytes);
    encoder.add_u64(observation.subject_incarnation);
    encoder.add_u16(static_cast<uint16_t>(observation.kind));
    encoder.add_bytes(observation.attestation_digest);
    encoder.add_u64(observation.height);
    encoder.add_bytes(observation.state_reference);
    encoder.add_bytes(observation.observer.bytes);
    return encoder.digest();
}

bool observation_signature_valid(const EligibilityObservation& observation) {
    const Digest digest = observation_signing_digest(observation);
    return crypto_sign_verify_detached(observation.signature.data(), digest.data(),
                                       digest.size(),
                                       observation.observer.bytes.data()) == 0;
}

EligibilityObservation sign_observation(EligibilityObservation observation,
                                         const crypto::Ed25519Keypair& identity) {
    observation.observer.bytes = identity.public_key;
    const Digest digest = observation_signing_digest(observation);
    crypto_sign_detached(observation.signature.data(), nullptr, digest.data(), digest.size(),
                         identity.private_key.data());
    return observation;
}

std::string_view observation_kind_name(ObservationKind kind) {
    switch (kind) {
        case ObservationKind::Attestation:   return "attestation";
        case ObservationKind::Participation: return "participation";
    }
    return "unknown observation";
}

std::string_view objective_fault_name(ObjectiveFault fault) {
    switch (fault) {
        case ObjectiveFault::DuplicateIncarnation:     return "duplicate incarnation";
        case ObjectiveFault::Equivocation:             return "equivocation";
        case ObjectiveFault::InvalidConsensusBehavior: return "invalid consensus behavior";
    }
    return "unknown fault";
}

}  // namespace nexus::security
