#pragma once

// The TPM half of sealing. Only nexus-attestd calls these: the server process
// has no TPM access (PrivateDevices=yes) and reaches them over the attestd
// socket instead.
//
// The TPM seals a random 32-byte key, never the server's secret. The server
// encrypts the secret under that key (SealedBlob.hpp), so the daemon handles a
// key whose ciphertext it never receives.
//
// Key separation: every seal uses a dedicated primary key in the owner
// hierarchy, created from a template whose unique field is the sealing tag
// (kSealParentUnique). It is a storage parent only. It is not the quote AK,
// not the EK, and not a key any other component creates. No persistent TPM
// handle and no NV index is created; the parent is recreated for each call.
// Sessions are salted to the parent, so the key is encrypted on its way into
// and out of the TPM.
//
// Both entry points need Linux and the tpm2-tss ESYS stack. On every other
// build they return TpmSealError::Unavailable.

#include <LemonadeNexus/Crypto/SecureBuffer.hpp>
#include <LemonadeNexus/Security/Sealing/SealedBlob.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace nexus::security {

/// Unique field of the seal parent template. Changing it orphans every blob.
inline constexpr std::string_view kSealParentUnique = "LEMONADE-NEXUS-SEAL-PARENT-V1";

enum class TpmSealError : uint8_t {
    None = 0,
    /// This build has no TPM stack, or no TPM answers at the TCTI.
    Unavailable,
    /// The current PCR 8/9 values differ from the values the object binds. The
    /// expected cause is a changed boot chain (kernel, initramfs, GRUB
    /// configuration, or kernel command line).
    PolicyMismatch,
    /// The object does not parse, does not carry the policy its PCR digest
    /// implies, or the TPM refuses to load it. Causes: a damaged file, an
    /// object from another TPM, or a TPM whose owner seed changed (a cleared
    /// or re-manufactured vTPM).
    Corrupt,
    /// Any other TPM failure. The detail names the step and the TPM rc.
    TpmFailure,
};

[[nodiscard]] std::string_view tpm_seal_error_name(TpmSealError error);

struct TpmSealStatus {
    TpmSealError error{TpmSealError::None};
    std::string  detail;
};

/// A new sealed key: the object to store, and the key it holds, for the
/// caller to encrypt with and then discard.
struct SealedKey {
    SealedKeyObject      object;
    crypto::SecureBuffer key;
};

/// Create a random kSealKeyBytes key sealed to PCR 8 and 9.
///
/// `target` nullopt binds the values the TPM holds now. A value binds those
/// PCR values instead; the release-upgrade path uses this with the expected
/// PCRs of a verified release approval, so the next boot chain can unseal.
/// Sealing to a target needs no trust in the caller: the caller only receives
/// a fresh key it could have generated itself, and the TPM enforces the binding
/// at unseal time. `tcti_config` is the TCTI loader string; nullptr uses the
/// stack default.
[[nodiscard]] std::optional<SealedKey> tpm_seal_key(const std::optional<BootPcrValues>& target,
                                                    TpmSealStatus& status,
                                                    const char* tcti_config = nullptr);

/// Unseal the key an object holds. The PCR values are read first so a changed
/// boot chain reports PolicyMismatch instead of a TPM error; the TPM still
/// enforces the policy itself. The key is returned in guarded memory.
[[nodiscard]] std::optional<crypto::SecureBuffer> tpm_unseal_key(const SealedKeyObject& object,
                                                                 TpmSealStatus& status,
                                                                 const char* tcti_config = nullptr);

}  // namespace nexus::security
