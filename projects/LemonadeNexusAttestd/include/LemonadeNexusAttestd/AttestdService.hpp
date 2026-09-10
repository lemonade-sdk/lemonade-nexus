#pragma once

// The daemon's single operation, with the platform underneath it.
//
//   serialized AttestationChallenge  ->  serialized PlatformEvidenceBundle
//
// A platform evidence helper, not an identity service. It holds no node secret
// and signs nothing: assembling and signing an AttestationEvidence around this
// bundle belongs to Nexus, which owns the identity key. That split is why the
// privileged component can be small.
//
// Nothing else is exposed. There is no "quote these PCRs", no "sign these
// bytes", no "give me the SNP report", and no eligibility verdict: deciding
// Tier 1 from a prover's own output would be self-attestation.
//
// The prover half of the snp-vtpm chain needs Linux plus a TPM stack. On every
// other build the service still constructs, still refuses correctly, and answers
// Refusal::PlatformUnavailable — so the target compiles and the gate stays
// testable on a developer machine.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>
#include <LemonadeNexusAttestd/AttestdCodec.hpp>
#include <LemonadeNexusAttestd/AttestdGate.hpp>

#include <filesystem>
#include <string>
#include <string_view>

namespace nexus::attestd {

struct AttestdConfig {
    /// Where the VCEK and the AMD chain are cached. Writable state; the systemd
    /// unit grants exactly this one directory.
    std::filesystem::path cache_dir;

    /// May the prover reach AMD KDS for a VCEK it has not cached. Off in a
    /// network-isolated deployment, where the cache must be pre-seeded.
    bool allow_network{true};
};

class AttestdService {
public:
    explicit AttestdService(AttestdConfig config);
    ~AttestdService();

    AttestdService(const AttestdService&) = delete;
    AttestdService& operator=(const AttestdService&) = delete;

    /// True when this build has an snp-vtpm prover at all. False means every
    /// answer is Refusal::PlatformUnavailable. A true here still proves nothing
    /// about the host — only a produced bundle does.
    [[nodiscard]] static bool platform_available();

    /// The typed path: gate the challenge, then produce a platform bundle bound
    /// to the digest the daemon derived. `detail` receives the prover's reason
    /// when the answer is a refusal. Nothing here is signed.
    [[nodiscard]] Refusal answer(const security::AttestationChallenge& challenge,
                                 PlatformEvidenceBundle& out, std::string* detail);

    /// The wire path: bytes in, frames out. Always emits a response — a caller
    /// that sends garbage gets a typed refusal, never a closed socket with no
    /// explanation. Streams rather than returning a string, so the evidence is
    /// never held twice.
    void handle_request(std::string_view request, const FrameSink& sink);

private:
    AttestdConfig config_;
};

}  // namespace nexus::attestd
