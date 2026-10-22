#pragma once

// The daemon's operations, with the platform underneath them.
//
//   serialized AttestationChallenge   ->  serialized PlatformEvidenceBundle
//   serialized activation offer       ->  one Result frame (or a refusal)
//   seal request (domain, binding)    ->  one Result frame: sealed key object + key
//   unseal request (key object)       ->  one Result frame: the key
//
// A platform evidence helper, not an identity service. It holds no node secret
// and signs nothing: assembling and signing an AttestationEvidence around this
// bundle belongs to Nexus, which owns the identity key. That split is why the
// privileged component can be small.
//
// Activation, seal and unseal live here because this daemon is the only
// component the unit file gives TPM access to. Seal creates a random key bound
// to PCR 8 and 9 of this TPM under a dedicated seal parent
// (Security/Sealing/TpmSeal.hpp); unseal returns that key while the PCRs
// match. The server encrypts its secret under the key itself, so the daemon
// never receives the secret or its ciphertext. The key passes through this
// process only for one request; the daemon stores nothing, creates no
// persistent TPM state, and still never reads the server's data directory.
// None of these operations decides anything about eligibility.
//
// Nothing else is exposed. There is no "quote these PCRs", no "sign these
// bytes", no "give me the SNP report", no PCR selection a caller can choose,
// and no eligibility verdict: deciding Tier 1 from a prover's own output would
// be self-attestation.
//
// The prover half of the snp-vtpm chain needs Linux plus a TPM stack. On every
// other build the service still constructs, still refuses correctly, and answers
// Refusal::PlatformUnavailable — so the target compiles and the gate stays
// testable on a developer machine. Activation answers
// Refusal::ActivationUnavailable and sealing Refusal::SealUnavailable on those
// builds.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SecureBuffer.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>
#include <LemonadeNexus/Security/Sealing/TpmSeal.hpp>
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

    std::filesystem::path svsm_report_object{
        "/sys/kernel/config/tsm/report/nexus-attestd-svsm"};
    std::filesystem::path guest_report_object{
        "/sys/kernel/config/tsm/report/nexus-attestd-guest"};

    /// TCTI loader string for activation, seal and unseal. The unit's
    /// DeviceAllow grants /dev/tpmrm0 only; the TSS default device:/dev/tpm0
    /// would be refused. A test-only seam (a TPM simulator), deliberately not
    /// reachable from the command line, like hcl_blob_override in the prover.
    std::string tcti{"device:/dev/tpmrm0"};
};

/// #49: heal hint appended to the refusal log line when the prover's detail
/// names the dedicated TSM report objects — the setup unit was skipped or
/// failed. Empty for every other detail.
[[nodiscard]] std::string_view tsm_heal_hint(std::string_view detail);

/// #12/#48e: true when the prover's failure is AMD endorsement discovery — the
/// one failure that clearing the in-memory resolve and re-probing KDS can heal.
[[nodiscard]] bool endorsement_discovery_failed(std::string_view detail);

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
    /// never held twice. Dispatches on the request type: a challenge gets the
    /// evidence path, an activation offer gets the TPM path.
    void handle_request(std::string_view request, const FrameSink& sink);

private:
    /// The activation answer: run TPM2_ActivateCredential inside the protected
    /// vTPM and return the activated secret digest. Typed refusal when this
    /// build or host cannot run it, or the TPM refuses the keys.
    [[nodiscard]] Refusal answer_activation(const SvsmAkActivationRequest& request,
                                            std::vector<uint8_t>& activated_secret,
                                            std::string* detail);

    /// Create a key sealed to PCR 8 and 9 (the running values, or the
    /// request's target values).
    [[nodiscard]] Refusal answer_seal(const SealRequest& request, security::SealedKey& sealed,
                                      std::string* detail);

    /// Unseal the key a sealed key object holds; `key` receives it in guarded
    /// memory.
    [[nodiscard]] Refusal answer_unseal(const UnsealRequest& request, crypto::SecureBuffer& key,
                                        std::string* detail);

    AttestdConfig config_;

    /// #12/#48e: chip/TCB the last verified AMD endorsement covered. While it
    /// stands, evidence is produced with networking off — the disk cache already
    /// holds that VCEK — so KDS is not probed per request. Cleared, and the
    /// produce retried online once, when the offline resolve fails. Set only
    /// after a fully verified produce, so nothing unverified is ever cached.
    std::string endorsed_chip_tcb_;
};

}  // namespace nexus::attestd
