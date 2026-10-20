#pragma once

// COCONUT-SVSM protected-vTPM evidence.
//
// This is deliberately not an HCL shape.  The SVSM service report binds a
// TPMT_PUBLIC EK manifest at VMPL0; enrollment proves an AK belongs to that
// EK with TPM2_MakeCredential/TPM2_ActivateCredential; a normal attestation
// then carries a fresh quote under the enrolled AK plus a guest-requested SNP
// report proving Linux runs above VMPL0.

#include <LemonadeNexus/Security/EvidenceSnpVtpm.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationState.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <array>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::security {

inline constexpr uint32_t kSvsmAttestationProtocolVersion = 1;
inline constexpr uint32_t kSvsmVtpmManifestVersion = 0;
inline constexpr std::string_view kSvsmVtpmServiceGuid =
    "c476f1eb-0123-45a5-9641-b4e7dde5bfe3";

inline constexpr uint32_t kSvsmEvidencePcrs[] = {0, 1, 4, 7, 8, 9, 10};
// Release-global boot pins: exactly the set a LIVE_BOOT_APPROVED release
// approval carries (verify_release_approval_bundle enforces PCR8+PCR9). The
// quote still covers kSvsmEvidencePcrs. PCR10 is absent because it advances
// with the IMA log (Full replay + verifier checkpoint instead). PCR0/1/4/7
// are absent because they are not release-pinnable: PCR1 is host-variant,
// and 0/4/7 are firmware-owned — they are recorded and replay-verified as
// qualification evidence, never pinned per release.
inline constexpr uint32_t kSvsmBootPcrs[] = {8, 9};

struct TpmRsaPublic {
    uint16_t type{};
    uint16_t name_alg{};
    uint32_t object_attributes{};
    std::vector<uint8_t> auth_policy;
    uint16_t symmetric_alg{};
    uint16_t symmetric_key_bits{};
    uint16_t symmetric_mode{};
    uint16_t scheme{};
    uint16_t scheme_hash{};
    uint16_t key_bits{};
    uint32_t exponent{};
    std::vector<uint8_t> modulus;
    std::vector<uint8_t> name;  ///< nameAlg || H(TPMT_PUBLIC)
    std::string spki_b64;
};

/// Strictly parse the raw TPMT_PUBLIC returned by SVSM vtpm_get_manifest().
/// Only RSA public areas usable as an EK or AK are accepted; trailing bytes,
/// unsupported parameter unions, and non-SHA256 Names fail closed.
[[nodiscard]] std::optional<TpmRsaPublic> parse_tpmt_public_rsa(
    std::span<const uint8_t> bytes);

/// Object-role checks used after the common wire parser.  The service manifest
/// must be a restricted decrypt EK (AES-128-CFB, NULL RSA scheme), while the
/// quote key must be a restricted signing AK (NULL symmetric, RSASSA/SHA-256).
/// Requiring the role attributes prevents a syntactically valid arbitrary RSA
/// object from being relabelled as either end of the activation relationship.
[[nodiscard]] bool is_svsm_vtpm_ek(const TpmRsaPublic& public_area);
[[nodiscard]] bool is_nexus_quote_ak(const TpmRsaPublic& public_area);

/// Enrollment receipt identity.  The verifier stores this only after a
/// MakeCredential secret for `ek_name` and `ak_name` was recovered through
/// ActivateCredential.  It is verifier-owned state, not a prover assertion.
[[nodiscard]] Digest ak_ek_binding_digest(std::span<const uint8_t> ek_name,
                                          std::span<const uint8_t> ak_name);

/// The exact 64-byte input used for both TSM requests.  It is SHA-512 over a
/// versioned domain and the canonical challenge digest (which already binds
/// network, node key, profile/ruleset, purpose and context).  No padding is
/// involved and callers cannot supply REPORT_DATA directly.
[[nodiscard]] std::array<uint8_t, 64> svsm_report_nonce(const Digest& challenge_digest);

/// Enrollment has its own typed context rather than reusing a mesh
/// AttestationChallenge.  The resulting digest binds the root-issued admission
/// nonce and candidate identity and is the sole input accepted by the SVSM
/// enrollment evidence operation.
[[nodiscard]] Digest svsm_enrollment_challenge_digest(
    std::span<const uint8_t> admission_nonce,
    std::span<const uint8_t> candidate_identity);

struct SnpSvsmVtpmEvidence {
    uint32_t protocol_version{kSvsmAttestationProtocolVersion};
    std::string service_provider{"svsm"};
    std::string service_guid{std::string(kSvsmVtpmServiceGuid)};
    uint32_t service_manifest_version{kSvsmVtpmManifestVersion};

    std::vector<uint8_t> svsm_report;    ///< VMPL0 report from the service request
    std::vector<uint8_t> guest_report;   ///< guest TSM report, required VMPL > 0
    std::vector<uint8_t> vcek_der;
    std::string amd_chain_pem;
    std::vector<uint8_t> ek_manifest;    ///< raw TPMT_PUBLIC, exactly as SVSM returned it
    std::vector<uint8_t> certificate_blob;

    std::vector<uint8_t> ak_public;      ///< raw TPMT_PUBLIC used to verify the quote
    std::vector<uint8_t> tpms_attest;
    std::vector<uint8_t> tpm_signature;
    std::vector<uint8_t> pcr_values;

    std::vector<uint8_t> ima_binary_log;
    std::string binary_path;
    std::string binary_sha256;
    std::string ima_unavailable;
    std::string runtime_no_new_privs;
    std::string runtime_seccomp_mode;

    [[nodiscard]] bool empty() const {
        return svsm_report.empty() || guest_report.empty() || ek_manifest.empty() ||
               ak_public.empty() || tpms_attest.empty();
    }
};

[[nodiscard]] std::string encode_snp_svsm_vtpm_evidence(const SnpSvsmVtpmEvidence& ev);
[[nodiscard]] std::optional<SnpSvsmVtpmEvidence> decode_snp_svsm_vtpm_evidence(
    std::string_view json);

struct SnpSvsmEvidenceProduceConfig {
    std::filesystem::path cache_dir;
    bool allow_network{true};
    std::vector<uint8_t> identity_pubkey;
    std::filesystem::path service_report_object{
        "/sys/kernel/config/tsm/report/nexus-attestd-svsm"};
    std::filesystem::path guest_report_object{
        "/sys/kernel/config/tsm/report/nexus-attestd-guest"};
};

/// Produce a fresh SVSM bundle.  Hardware inputs are derived only from the
/// typed challenge digest and the compiled PCR set; there is no raw report-data
/// or caller-selected PCR API.
[[nodiscard]] std::optional<SnpSvsmVtpmEvidence> produce_snp_svsm_vtpm_evidence(
    const SnpSvsmEvidenceProduceConfig& config, const Digest& challenge_digest,
    std::string* failure);

struct SvsmEvidenceRequirements {
    SnpPolicyRequirements policy;
    bool require_revocation_check{false};
    AmdRevocationState revocation;
    std::string expected_measurement_hex;
    std::string expected_ek_name_hex;
    std::string expected_ak_name_hex;
    std::string expected_ak_spki_b64;
    Digest expected_ak_ek_binding{};
    std::vector<std::string> approved_paths;
    std::string evidence_collector_path;
    std::vector<std::pair<uint32_t, std::string>> expected_pcrs;
    bool require_no_new_privs{false};
    bool require_seccomp{false};
    ImaEvidenceMode ima_mode{ImaEvidenceMode::Full};
    const AttestationCheckpoint* checkpoint{nullptr};
    /// Test/verification boundary for signed semantic fixtures. Production
    /// leaves this empty and always uses the pinned AMD chain verifier.
    std::function<SnpVerifyResult(const SnpReport&, std::span<const uint8_t>,
                                  std::string_view)> signature_verifier;
};

/// Exact first failing link for the SVSM chain.  Tests assert these values so
/// reordering cannot turn a semantic mutation into an uninformative generic
/// rejection.
enum class SvsmEvidenceFailure : uint16_t {
    None,
    Protocol,
    ServiceReportMalformed,
    GuestReportMalformed,
    ServiceSignatureInvalid,
    GuestSignatureInvalid,
    RevocationInvalid,
    ServiceVmplInvalid,
    ServiceReportDataInvalid,
    ServiceManifestInvalid,
    ServiceChipInvalid,
    ServiceMeasurementInvalid,
    ServiceDebugEnabled,
    ServiceMigrationEnabled,
    ServiceTcbTooOld,
    GuestVmplInvalid,
    GuestNonceInvalid,
    GuestChipInvalid,
    GuestMeasurementInvalid,
    GuestDebugEnabled,
    GuestMigrationEnabled,
    GuestTcbTooOld,
    PairChipMismatch,
    PairMeasurementMismatch,
    EkMismatch,
    AkMismatch,
    ActivationReceiptInvalid,
    QuoteMalformed,
    QuoteSignatureInvalid,
    QuoteNonceInvalid,
    QuotePcrDigestInvalid,
    BootPcrInvalid,
    ImaMalformed,
    ImaViolation,
    ImaPcr10Mismatch,
    ImaCheckpointInvalid,
    BinaryMeasurementInvalid,
    RuntimeProfileInvalid,
};

struct SvsmEvidenceVerdict : EvidenceVerdict {
    SvsmEvidenceFailure svsm_failure{SvsmEvidenceFailure::None};
    ImaBinaryReplayState ima_state;
};

struct SvsmAkEnrollmentRequirements {
    /// Carries the release measurement pin (policy.expected_measurement_hex).
    SnpPolicyRequirements policy;
    bool require_revocation_check{false};
    AmdRevocationState revocation;
};

struct SvsmAkEnrollmentIdentity {
    bool ok{false};
    std::string failure;
    std::string measurement_hex;
    std::string chip_id_hex;
    std::vector<uint8_t> ek_name;
    std::vector<uint8_t> ak_name;
    std::string ak_spki_b64;
};

/// Validate the first enrollment message before issuing MakeCredential.  This
/// intentionally stops at the attested EK and proposed AK: only a subsequent
/// successful ActivateCredential response may turn these values into pins.
[[nodiscard]] SvsmAkEnrollmentIdentity verify_svsm_ak_enrollment_identity(
    const SnpSvsmVtpmEvidence& ev,
    const Digest& enrollment_challenge_digest,
    const SvsmAkEnrollmentRequirements& req);

/// Verify the complete normal-attestation chain.  `expected_ak_ek_binding`
/// must have been committed only after successful credential activation.
[[nodiscard]] SvsmEvidenceVerdict verify_snp_svsm_vtpm_evidence(
    const SnpSvsmVtpmEvidence& ev, const Digest& challenge_digest,
    std::span<const uint8_t> identity_pubkey, const SvsmEvidenceRequirements& req);

}  // namespace nexus::security
