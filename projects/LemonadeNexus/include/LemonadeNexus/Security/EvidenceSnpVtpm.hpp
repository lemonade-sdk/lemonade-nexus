#pragma once

// The snp-vtpm evidence chain, end to end.
//
//   AMD ARK -> ASK -> VCEK  --signs-->  SNP report (DEBUG=0, MEASUREMENT, VMPL=0)
//                                             |
//                REPORT_DATA[0:32] == SHA-256(runtime JSON containing HCLAkPub)
//                                             v
//                                         HCLAkPub  --signs-->  vTPM quote
//                                                                   |
//                                 PCRs (measured boot + IMA 10) + evidence binding
//
// Four links, each independently checkable, and the last one is the whole point:
// the SNP report is frozen at boot and its NV index is world-readable, so holding
// the blob proves nothing. Freshness comes from the quote, and the quote is only
// worth anything because AMD signed over the key that produced it.
//
// The prover half needs a TPM stack (Linux + LEMONADE_HAVE_TPM_FAPI). The verifier
// half is pure OpenSSL and builds everywhere, so a Tier-2, Windows or macOS node
// can still check a peer.

#include <LemonadeNexus/Security/MeasurementIma.hpp>
#include <LemonadeNexus/Security/SnpVerify.hpp>
#include <LemonadeNexus/Security/TpmQuote.hpp>

#include <cstdint>
#include <filesystem>
#include <optional>
#include <span>
#include <string>
#include <utility>
#include <string_view>
#include <vector>

namespace nexus::security {

/// PCRs quoted for snp-vtpm evidence: the guest-visible boot chain plus IMA.
/// Deliberately small — Esys_PCR_Read returns at most 8 digests per call, and
/// every extra PCR is one more value that has to be stable across reboots.
inline constexpr uint32_t kEvidencePcrs[] = {0, 1, 4, 7, 10};
inline constexpr uint32_t kImaPcr = 10;

/// PCR 10 is quoted in the SHA-1 bank as well, because which bank the IMA log can
/// be replayed against is decided by the kernel's ima_template_hash_algo, not by
/// us. Quoting both means one prover works on either configuration; the verifier
/// then demands the bank the log actually matches. See ima_replay_bank.
inline constexpr uint16_t kEvidenceImaBanks[] = {kTpmAlgSha256, kTpmAlgSha1};

/// Everything a peer needs to check the chain above without asking us anything
/// else. Transported as JSON (see encode/decode) inside a challenge response.
struct SnpVtpmEvidence {
    std::vector<uint8_t> hcl_blob;       ///< paravisor blob from vTPM NV 0x01400001
    std::vector<uint8_t> vcek_der;       ///< AMD leaf for this chip + TCB
    std::string          amd_chain_pem;  ///< ASK + ARK (root is re-checked against the pinned ARK)
    std::vector<uint8_t> tpms_attest;    ///< the signed TPMS_ATTEST
    std::vector<uint8_t> tpm_signature;  ///< TPMT_SIGNATURE wire bytes, under HCLAkPub
    std::vector<uint8_t> pcr_values;     ///< concatenated quoted PCR values
    std::string          ima_log;        ///< IMA ASCII measurement log
    std::string          binary_path;    ///< which IMA entry describes the running binary
    std::string          binary_sha256;  ///< hex; bound into the quote, confirmed against the log
    /// Why the prover could not measure its own binary. Diagnostic only — a
    /// verifier rejects on the ABSENT measurement, never on this string.
    std::string          ima_unavailable;

    /// Hex SHA-256 of the IMA policy the kernel is enforcing. The kernel does not
    /// publish the active policy on every build, so an absent value fails the
    /// check rather than skipping it.
    std::string          ima_policy_sha256;

    /// Runtime state of the process that produced this bundle: "1" or "0" for
    /// no_new_privs, and the numeric seccomp mode.
    ///
    /// These are SELF-REPORTED. No TPM quote covers them, so they are worth
    /// exactly as much as the binary that reports them: the identity signature
    /// binds them, and the binary carrying that identity is IMA-measured and
    /// must appear on the approved release list. A modified binary could lie
    /// here, and a modified binary is already rejected. Do not read these as
    /// hardware-attested facts.
    std::string          runtime_no_new_privs;
    std::string          runtime_seccomp_mode;

    [[nodiscard]] bool empty() const { return hcl_blob.empty() || tpms_attest.empty(); }
};

[[nodiscard]] std::string encode_snp_vtpm_evidence(const SnpVtpmEvidence& ev);
[[nodiscard]] std::optional<SnpVtpmEvidence> decode_snp_vtpm_evidence(std::string_view json);

// ---------------------------------------------------------------------------
// Prover
// ---------------------------------------------------------------------------

struct EvidenceProduceConfig {
    std::filesystem::path cache_dir;              ///< where the VCEK + AMD chain are cached
    std::string           product{"Milan"};
    bool                  allow_network{true};    ///< may we reach AMD KDS
    std::vector<uint8_t>  identity_pubkey;        ///< raw Ed25519; bound into the quote
    std::filesystem::path hcl_blob_override;      ///< offline testing only, never a bypass
};

/// Produce a fresh evidence bundle bound to `nonce`. Returns nullopt with a reason
/// in `failure` on any platform that cannot produce one — which is every platform
/// except an Azure-style SNP CVM with a working vTPM.
[[nodiscard]] std::optional<SnpVtpmEvidence> produce_snp_vtpm_evidence(
    const EvidenceProduceConfig& cfg, std::span<const uint8_t> nonce, std::string* failure);

// ---------------------------------------------------------------------------
// Verifier
// ---------------------------------------------------------------------------

struct EvidenceRequirements {
    SnpPolicyRequirements policy;
    /// Hex SHA-384 launch measurement pinned at enrollment. Empty accepts any,
    /// which is only right for the startup self-probe and first enrollment.
    std::string expected_measurement_hex;
    /// Base64 DER SPKI of the AK pinned at enrollment. Empty accepts whichever AK
    /// AMD vouched for; non-empty demands it be the SAME vTPM as at enrollment.
    std::string expected_ak_spki_b64;
    /// An IMA log that replays to the quoted PCR 10 is what makes the binary
    /// measurement non-self-chosen. Off only for the platform-only probe.
    bool require_ima{true};

    /// Boot state. Each entry pins one quoted PCR to a hex value. The quote
    /// covers these PCRs, so unlike the runtime fields below they are hardware
    /// facts. Empty pins none, which is only right for a first enrollment.
    std::vector<std::pair<uint32_t, std::string>> expected_pcrs;

    /// Hex SHA-256 of the IMA policy the prover must be enforcing. Empty pins
    /// none.
    std::string expected_ima_policy_sha256;

    /// Runtime profile. See the caveat on the evidence fields: these are
    /// self-reported by an approved binary, not attested by hardware.
    bool require_no_new_privs{false};
    bool require_seccomp{false};
};

struct EvidenceVerdict {
    bool        ok{false};
    std::string failure;
    /// The AMD chain, the guest policy and a fresh quote under HCLAkPub all
    /// checked out — "secure memory" proven — regardless of whether the binary
    /// measurement did. Reported separately so the owner's two requirements are
    /// separately diagnosable; `ok` still needs both.
    bool        quote_verified{false};

    std::string measurement_hex;   ///< SNP launch measurement (pin this at enrollment)
    std::string ak_spki_b64;       ///< HCLAkPub as DER SPKI (pin this too)
    std::string binary_sha256;     ///< IMA-confirmed measurement of the running binary
    std::string chip_id_hex;
    std::string tcb;
    std::string report_summary;
    /// True when the IMA log could only be replayed in the SHA-1 bank, so log
    /// integrity rests on SHA-1 collision resistance. Fixed by booting the guest
    /// with ima_template_hash_algo=sha256.
    bool ima_replayed_in_sha1_bank{false};

    /// Per-link outcomes, so a caller can build a Tier 1 evidence state without
    /// re-deriving anything from `failure`. Each stays false until its link
    /// actually passes, so a bundle that stops early leaves every later link
    /// false and Tier 1 eligibility fails closed.
    bool snp_signature_valid{false};
    bool snp_policy_valid{false};
    /// The reported TCB is at or above the required floor. Evaluated on its own
    /// rather than borrowed from snp_policy_valid, which also covers guest
    /// policy and the launch measurement.
    bool tcb_valid{false};
    bool ak_bound_to_report{false};
    bool quote_bound_to_challenge{false};
    bool boot_state_valid{false};
    bool ima_anchored{false};
    bool binary_measured{false};
    bool runtime_profile_valid{false};

    explicit operator bool() const { return ok; }
};

/// Run every link. `identity_pubkey` is the raw Ed25519 key the evidence must be
/// bound to — the caller has already tied it to an enrolled certificate.
[[nodiscard]] EvidenceVerdict verify_snp_vtpm_evidence(const SnpVtpmEvidence& ev,
                                                        std::span<const uint8_t> nonce,
                                                        std::span<const uint8_t> identity_pubkey,
                                                        const EvidenceRequirements& req);

}  // namespace nexus::security
