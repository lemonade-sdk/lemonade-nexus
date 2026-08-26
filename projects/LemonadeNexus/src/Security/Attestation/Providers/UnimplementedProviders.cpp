// The providers that are declared but cannot verify anything yet.
//
// Both refuse for a reason, and the reasons differ. SnpSvsmVtpmProvider waits
// on real evidence from an approved SVSM host, because inventing the service
// binding would pin a format the live protocol does not use.
// SnpDirectBootProvider waits on an approved runtime-integrity proof, which no
// TPM-less measured boot supplies today.
//
// Neither examine() can run: AttestationVerifier calls readiness() first and
// both refuse there. The bodies exist so that a future caller reaching them
// still gets no claims rather than an empty pass.

#include <LemonadeNexus/Security/Attestation/Providers/SnpDirectBootProvider.hpp>
#include <LemonadeNexus/Security/Attestation/Providers/SnpSvsmVtpmProvider.hpp>

namespace nexus::security {

PlatformVerification SnpSvsmVtpmProvider::examine(const AttestationChallenge&,
                                                   const AttestationEvidence&) const {
    PlatformVerification result;
    result.failure = AttestationFailure::ProviderUnsupported;
    return result;
}

PlatformVerification SnpDirectBootProvider::examine(const AttestationChallenge&,
                                                     const AttestationEvidence&) const {
    PlatformVerification result;
    result.failure = AttestationFailure::ProviderUnsupported;
    return result;
}

}  // namespace nexus::security
