// Providers that still cannot verify anything. SnpDirectBootProvider waits on
// an approved runtime-integrity proof, which no TPM-less measured boot supplies
// today. Its examine() body exists so a future caller reaching it still gets no
// claims rather than an empty pass.

#include <LemonadeNexus/Security/Attestation/Providers/SnpDirectBootProvider.hpp>

namespace nexus::security {

PlatformVerification SnpDirectBootProvider::examine(const AttestationChallenge&,
                                                     const AttestationEvidence&,
                                                     const PlatformVerificationState&) const {
    PlatformVerification result;
    result.failure = AttestationFailure::ProviderUnsupported;
    return result;
}

}  // namespace nexus::security
