#pragma once

// Sealed blobs: secrets bound to this host's vTPM and to its boot chain.
//
// One blob holds:
//
//   - a TPM keyed-hash object (TPM2B_PUBLIC + TPM2B_PRIVATE) under a dedicated
//     owner-hierarchy parent. Its sensitive data is a random 32-byte key, and
//     its authPolicy is TPM2_PolicyPCR over the SHA-256 bank of PCR 8 and 9
//     (kSvsmBootPcrs, the PCRs a qualified release approval pins);
//   - the secret, encrypted with XChaCha20-Poly1305 under that key. The
//     associated data binds the sealing domain, the PCR digest, and the TPM
//     public area, so a blob cannot move to another domain or binding.
//
// Split of work: nexus-attestd creates the key object and unseals the key
// (Sealing/TpmSeal.hpp). The server process encrypts and decrypts the secret
// with make_sealed_blob() and open_sealed_blob() and stores the blob. The
// secret and the ciphertext therefore never reach the daemon, which keeps the
// rule that a compromised helper does not inherit the server's data.
//
// The TPM object holds only a key because TPM2B_SENSITIVE_DATA is limited to
// 128 bytes. The TPM enforces the PCR policy on every unseal. The blob is not
// a secret: it is useless without this TPM in the bound boot state.
//
// Everything in this header is pure: no TPM, no clock, no file system.

#include <LemonadeNexus/Crypto/SecureBuffer.hpp>
#include <LemonadeNexus/Security/EvidenceSnpSvsmVtpm.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::security {

struct ReleaseApprovalV1;

inline constexpr uint32_t kSealedBlobFormatVersion = 1;
inline constexpr std::string_view kSealedBlobType = "lemonade-nexus-sealed-blob";

/// Largest secret one blob carries. The boot set is a few hundred bytes; the
/// bound keeps a local caller from making the daemon encrypt large inputs.
inline constexpr std::size_t kMaxSealPlaintextBytes = 8 * 1024;

/// Largest encoded blob, accepted by every parser before it decodes anything.
inline constexpr std::size_t kMaxSealedBlobBytes = 32 * 1024;

/// Longest sealing domain name. See valid_seal_domain().
inline constexpr std::size_t kMaxSealDomainBytes = 48;

/// Size of the random key the TPM object carries.
inline constexpr std::size_t kSealKeyBytes = 32;

/// Largest marshalled TPM2B_PUBLIC or TPM2B_PRIVATE accepted for a sealed key
/// object. A keyed-hash object is a few hundred bytes.
inline constexpr std::size_t kMaxTpmObjectBytes = 2048;

/// Number of PCRs the seal policy binds: kSvsmBootPcrs, in that order.
inline constexpr std::size_t kSealPcrCount = std::size(kSvsmBootPcrs);

/// One SHA-256 PCR value.
using PcrValue = std::array<uint8_t, 32>;

/// Values of PCR 8 and PCR 9 (SHA-256 bank), in kSvsmBootPcrs order.
using BootPcrValues = std::array<PcrValue, kSealPcrCount>;

/// The sealing domain names one secret role, for example "gossip-identity" or
/// "storage-share". Each role gets its own domain so a blob sealed for one role
/// never unseals as another. Valid: 1 to kMaxSealDomainBytes characters from
/// [a-z0-9-], starting with a letter.
[[nodiscard]] bool valid_seal_domain(std::string_view domain);

/// The TPM pcrDigest for the policy: SHA-256 over PCR 8 then PCR 9.
[[nodiscard]] Digest boot_pcr_digest(const BootPcrValues& values);

/// Marshalled TPML_PCR_SELECTION for SHA-256 PCR 8 and 9 (TPM wire form).
[[nodiscard]] std::vector<uint8_t> boot_pcr_selection_wire();

/// The authPolicy a seal carries: one TPM2_PolicyPCR from the zero digest,
///   SHA-256(0^32 || TPM_CC_PolicyPCR || boot_pcr_selection_wire() || pcr_digest).
/// Computed here, not with a TPM trial session, so a seal to a future boot
/// state (an approved release's expected PCR values) needs no TPM in that state.
[[nodiscard]] Digest boot_pcr_policy_digest(const Digest& pcr_digest);

/// The TPM half of a blob: the sealed key object and the binding it carries.
struct SealedKeyObject {
    /// boot_pcr_digest() of the values the policy binds.
    Digest pcr_digest{};
    /// TPM2B_PUBLIC of the sealed key object (outer size included).
    std::vector<uint8_t> tpm_public;
    /// TPM2B_PRIVATE of the sealed key object, encrypted to the seal parent.
    std::vector<uint8_t> tpm_private;
};

/// Parsed blob. Public metadata only; the key stays inside the TPM object.
struct SealedBlob {
    std::string domain;
    /// boot_pcr_digest() of the values the policy binds.
    Digest pcr_digest{};
    /// TPM2B_PUBLIC of the sealed key object (outer size included).
    std::vector<uint8_t> tpm_public;
    /// TPM2B_PRIVATE of the sealed key object, encrypted to the seal parent.
    std::vector<uint8_t> tpm_private;
    /// XChaCha20-Poly1305 nonce (crypto::kAeadNonceSize bytes).
    std::vector<uint8_t> nonce;
    /// Ciphertext with the appended tag.
    std::vector<uint8_t> ciphertext;
};

/// Canonical JSON form. Hex for the digest, base64 for byte strings.
[[nodiscard]] std::string encode_sealed_blob(const SealedBlob& blob);

/// Strict parse: exact key set, version, type, PCR selection, field widths,
/// and size bounds. Any deviation is nullopt. A parsed blob is still
/// unauthenticated until the TPM and the AEAD tag accept it.
[[nodiscard]] std::optional<SealedBlob> decode_sealed_blob(std::string_view text);

/// AEAD associated data for one blob (crypto::aead_aad with the sealed-blob
/// purpose tag over domain, PCR digest, and TPM public area).
[[nodiscard]] std::vector<uint8_t> sealed_blob_aad(std::string_view domain,
                                                   const Digest& pcr_digest,
                                                   std::span<const uint8_t> tpm_public);

/// Encrypt `plaintext` (1..kMaxSealPlaintextBytes) under `key` (kSealKeyBytes,
/// unsealed from `object`) for `domain`, and return the encoded blob.
/// nullopt on invalid input.
[[nodiscard]] std::optional<std::string> make_sealed_blob(std::string_view domain,
                                                          const SealedKeyObject& object,
                                                          std::span<const uint8_t> key,
                                                          std::span<const uint8_t> plaintext);

/// Authenticate and decrypt a blob with the key unsealed from its object.
/// nullopt when the tag fails: a damaged blob, another domain, or another key.
[[nodiscard]] std::optional<crypto::SecureBuffer> open_sealed_blob(const SealedBlob& blob,
                                                                   std::span<const uint8_t> key);

/// The PCR 8 and 9 values a release approval pins, in kSvsmBootPcrs order.
/// nullopt when the approval is pending or does not carry exactly those two
/// SHA-256 values. The caller must have verified the approval first.
[[nodiscard]] std::optional<BootPcrValues> boot_pcrs_from_approval(
    const ReleaseApprovalV1& approval);

}  // namespace nexus::security
