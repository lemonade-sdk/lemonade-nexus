#pragma once

// TPM 2.0 quote structures, on the wire.
//
// Parsing and signature verification only — no tss2 dependency, so this builds on
// macOS and Windows. A node that can never produce a quote must still be able to
// check a peer's, or "verify the evidence" degenerates into "trust whoever has
// the hardware".

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace nexus::security {

// TPM 2.0 constants (tss2_tpm2_types.h), repeated here so the verifier needs no
// headers from the TPM stack.
inline constexpr uint32_t kTpmGeneratedValue = 0xff544347u;  // TPM2_GENERATED_VALUE
inline constexpr uint16_t kTpmStAttestQuote  = 0x8018u;      // TPM2_ST_ATTEST_QUOTE
inline constexpr uint16_t kTpmAlgRsassa      = 0x0014u;
inline constexpr uint16_t kTpmAlgRsapss      = 0x0016u;
inline constexpr uint16_t kTpmAlgEcdsa       = 0x0018u;
inline constexpr uint16_t kTpmAlgSha1        = 0x0004u;
inline constexpr uint16_t kTpmAlgSha256      = 0x000Bu;
inline constexpr uint16_t kTpmAlgSha384      = 0x000Cu;
inline constexpr uint16_t kTpmAlgSha512      = 0x000Du;

/// Digest length of a TPM hash algorithm, or 0 if we do not handle it.
[[nodiscard]] std::size_t tpm_digest_size(uint16_t hash_alg);

struct TpmPcrSelection {
    uint16_t              hash_alg{};
    std::vector<uint32_t> pcrs;  // ascending, the order the TPM reports values in
};

/// The parts of TPMS_ATTEST a verifier acts on.
struct TpmQuote {
    std::vector<uint8_t>         qualified_signer;  // TPM2B_NAME of the signing key
    std::vector<uint8_t>         extra_data;        // our binding value
    std::vector<TpmPcrSelection> selections;
    std::vector<uint8_t>         pcr_digest;
};

/// Reject anything that is not a well-formed TPM2_ST_ATTEST_QUOTE.
[[nodiscard]] std::optional<TpmQuote> parse_tpm_quote(std::span<const uint8_t> tpms_attest);

/// pcrDigest inside the signed quote == H(concatenated PCR values). Without this
/// the PCR values travelling beside the quote are just a claim.
/// `hash_alg` is the signing scheme's hash — the algorithm TPM2_Quote used.
[[nodiscard]] bool quote_pcr_digest_matches(const TpmQuote& quote,
                                             std::span<const uint8_t> pcr_values,
                                             uint16_t hash_alg);

/// Pull one PCR out of the concatenated value blob, positioned by the quote's own
/// selection. Returns nullopt if that PCR was not quoted or the blob is short.
[[nodiscard]] std::optional<std::vector<uint8_t>> quote_pcr_value(
    const TpmQuote& quote, uint16_t bank_hash_alg, uint32_t pcr,
    std::span<const uint8_t> pcr_values);

/// Verify a TPMT_SIGNATURE (wire form: u16 sigAlg, u16 hashAlg, then the scheme's
/// parameters) over `tpms_attest`, under an RSA public key supplied as raw
/// big-endian modulus and exponent — the form the Azure HCL runtime JWK carries.
/// Handles RSASSA (PKCS#1 v1.5) and RSAPSS. `failure` is optional.
[[nodiscard]] bool verify_quote_signature_rsa(std::span<const uint8_t> tpms_attest,
                                               std::span<const uint8_t> tpmt_signature,
                                               std::span<const uint8_t> modulus,
                                               std::span<const uint8_t> exponent,
                                               std::string* failure = nullptr);

/// The signing scheme's hash algorithm, read off the TPMT_SIGNATURE header.
[[nodiscard]] std::optional<uint16_t> tpmt_signature_hash_alg(
    std::span<const uint8_t> tpmt_signature);

/// RSA(n, e) as base64 DER SubjectPublicKeyInfo — the shape a certificate pins.
[[nodiscard]] std::string rsa_spki_b64(std::span<const uint8_t> modulus,
                                        std::span<const uint8_t> exponent);

}  // namespace nexus::security
