#pragma once

#include <optional>
#include <string>

namespace nexus::core::tpm {

/// Is a TPM 2.0 usable on this host right now (device present AND an ESYS context
/// can be opened)? Generation-only; always false on non-Linux / no-FAPI builds.
[[nodiscard]] bool tpm_available();

/// Provision the deterministic primary Attestation Key (ECC P-256 restricted
/// signing) if needed and return its public key as base64 DER SubjectPublicKeyInfo
/// — the exact form pinned in `ServerCertificate::tpm_ak_pubkey`.
///
/// Used by the joining server (`--print-tpm-ak`) so an admin can copy the AK into
/// the `--enroll-server` command (Model A). Returns std::nullopt if no TPM is
/// available or provisioning fails. Linux + LEMONADE_HAVE_TPM_FAPI only.
[[nodiscard]] std::optional<std::string> export_ak_pubkey_b64();

} // namespace nexus::core::tpm
