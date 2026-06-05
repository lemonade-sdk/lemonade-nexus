# TEE Attestation Hardening + TPM Root-of-Trust — Design & Plan

Status: **In progress** (Phase 1 landing)
Owner: server / core
Scope: `projects/LemonadeNexus/src/Core/TeeAttestation.cpp`, `TrustPolicy.cpp`,
`Gossip/GossipService.cpp`, `main.cpp`, `Core/TrustTypes.*`,
`Gossip/ServerCertificate.*`, new `Core/TeeAttestationTpm.cpp`.

---

## 1. Problem statement

The current TEE attestation flow does **not** provide the security property it
claims. A motivated attacker with no TEE hardware can be promoted to **Tier 1**
(full mesh participant: tree writes, key access, credential issuance, IPAM).
Root causes:

1. **No hardware root of trust.** Every `verify_*_report` only checks a 4-byte
   ASCII magic and that the nonce echoed inside the quote equals
   `report.nonce`. There is no DCAP/IAS, AMD KDS/VCEK, or Apple-CA verification,
   and the quote carries no real hardware measurement. The `generate_*` side
   simply writes `magic ‖ nonce ‖ binary_hash ‖ timestamp` after `open()`-ing
   the device — an attacker writes the same bytes by hand.
2. **`server_pubkey` is self-asserted.** Both `verify_token` and
   `do_verify_report` verify the Ed25519 signature against the pubkey carried
   *inside the same message*. That only proves "whoever holds this key signed
   this" — never that the key is an enrolled, root-CA-certified server. The
   gossip layer then keys trust directly on `token.server_pubkey`.
3. **Optional signature.** `do_verify_report` wraps the signature check in
   `if (!report.signature.empty() && !report.server_pubkey.empty())`. An empty
   signature skips verification entirely.
4. **Size-gated nonce check.** Structural verifiers guard the nonce `memcmp`
   with `if (quote.size() >= 36)` and then `return true`, so a 4-byte quote
   (`"SEV1"`) passes with no nonce binding. The Apple non-Apple branch returns
   `quote.size() >= 36` for any blob.
5. **`binary_hash` self-asserted + conditional.** `is_approved_binary()` only
   runs `if (has_signing_pubkey())`; the hash is a free-text field the attacker
   chooses (copy a known-approved hash).
6. **Replayable bearer tokens.** The token path has no verifier nonce/audience
   binding; an observed token can be replayed within its freshness window.
7. **`set_platform_override`** sets `detected_platform_` straight from config
   with no hardware check, flipping a non-TEE box to "Tier 1 capable".
8. **`std::cin.get()`** in `main.cpp` blocks startup on any headless deploy.
9. **Detour TODOs** propose in-process obfuscation — the wrong mitigation.

### Threat model & goal

A Tier-1 promotion must require **hardware-signed evidence**, bound to **(a)** a
fresh verifier challenge, **(b)** the server's enrolled identity key, and
**(c)** the running binary's measurement — anchored to a key the verifier
**already trusts** (the existing root-CA-signed `ServerCertificate`). No field
the attacker controls may sit outside a signature the verifier checks against a
trusted key.

---

## 2. Target architecture (TPM 2.0 via tss2-fapi)

`tss2::fapi` is already wired into the build
(`projects/LemonadeNexus/CMakeLists.txt`): it provides `<tss2/tss2_fapi.h>` and
defines `LEMONADE_HAVE_TPM_FAPI=1` on Linux, and is a no-op INTERFACE target on
macOS/Windows. We hang a TPM root-of-trust off the **existing** server
certificate.

### 2.1 Trust anchor — enrollment-pinned AK (model A, chosen)

At enrollment, the joining server presents its TPM **Attestation Key (AK)**
public key (and EK certificate). The root admin validates the EK→AK chain to the
TPM vendor CA **once**, then embeds the AK pubkey into the root-CA-signed
`ServerCertificate`. At runtime, peers verify a quote's signature against the AK
pinned in that already-trusted certificate. This reuses the existing root key
and `--enroll` flow and makes identity ↔ AK ↔ certificate a single signed unit
(closing issue 2 structurally).

> **Alternative (model B), deferred:** every verifier ships TPM vendor root CAs
> and performs runtime EK credential-activation per challenge. Strongest, but
> heavy and stateful. Layer it on top of model A later.

### 2.2 Prover / verifier split

- **Generation** needs a TPM → Linux + FAPI only (`#ifdef LEMONADE_HAVE_TPM_FAPI`).
- **Verification** is pure signature/structure checking → runs **anywhere** with
  OpenSSL (already built from source). A macOS/Windows/Tier-2 node with no TPM
  can still *verify* a Tier-1 peer. This is why the no-op FAPI target on
  non-Linux is correct: those nodes verify but cannot self-attest.

### 2.3 Quote binding

The value fed to `TPM2_Quote` (and re-checked on verify) is:

```
qualifyingData = SHA256( nonce ‖ server_pubkey_bytes ‖ binary_hash_bytes )
```

The AK's hardware signature therefore covers the challenge nonce, the identity
key, **and** the binary hash simultaneously. The binary hash is additionally
reflected in a TPM PCR (extended at startup) so it is measured, not merely
self-declared.

---

## 3. Data-model changes (Phase 2)

`TeeAttestationReport` (in `Core/TrustTypes.hpp`) gains real TPM evidence:

```cpp
struct TeeAttestationReport {
    TeePlatform platform{TeePlatform::None};   // + TeePlatform::Tpm2 = 5
    std::vector<uint8_t> tpms_attest;    // raw TPMS_ATTEST (the signed structure)
    std::vector<uint8_t> tpm_signature;  // raw TPMT_SIGNATURE
    std::string          ak_pubkey;      // base64 AK pub (hint; MUST match cert-pinned AK)
    std::vector<uint8_t> pcr_values;     // selected PCRs (to recompute the digest)
    std::array<uint8_t,32> nonce{};      // verifier challenge → qualifyingData
    uint64_t    timestamp{0};
    std::string server_pubkey;           // base64 Ed25519 identity key
    std::string binary_hash;             // hex SHA-256 of running binary (also PCR-extended)
    std::string signature;               // Ed25519 over canonical JSON — MANDATORY
};
```

`AttestationToken` gains `challenge_nonce` (base64) echoing the most recent
verifier challenge, so it is no longer a pure bearer credential.

`ServerCertificate` (in `Gossip/ServerCertificate.hpp`) gains:

```cpp
std::string tpm_ak_pubkey;   // base64 — the AK the root admin validated at enrollment
std::string tpm_ek_cert;     // optional PEM, retained for audit / model-B re-validation
```

`canonical_cert_json`, `canonical_attestation_json`, and `canonical_token_json`
must include the new fields so the relevant signatures cover them.

---

## 4. TPM FAPI backend (Phase 3, Linux only)

New TU `Core/TeeAttestationTpm.cpp`, guarded by `LEMONADE_HAVE_TPM_FAPI`, wired
in `src/CMakeLists.txt`. Detection probes `/dev/tpmrm0` / `/dev/tpm0` then
`Fapi_Initialize`.

**Provisioning (once, in `on_start`):** `Fapi_Initialize` → `Fapi_Provision` (if
needed) → create persistent restricted signing AK at `/HS/SRK/lemonadeAK` if
absent → export AK pub (pinned by the enrollment CLI).

**`generate_tpm_report(nonce)`:** extend app PCR 23 with the binary measurement
→ `Fapi_Quote(pcrList={0,1,7,23}, "/HS/SRK/lemonadeAK", qualifyingData, ...)` →
populate `tpms_attest` / `tpm_signature` / `pcr_values` → Ed25519-sign the
canonical report with the identity key (mandatory).

> Exact FAPI argument orders must be confirmed against the vendored
> `tss2/tss2_fapi.h` (4.1.3) at implementation time. If the FAPI-JSON `quoteInfo`
> proves awkward to re-verify cross-platform, use `Esys_Quote` to obtain raw
> `TPMS_ATTEST` bytes instead (decision tracked in §8 open questions).

**`verify_tpm_report(report, expected_nonce, trusted_ak_pubkey)` — OpenSSL only:**

1. Recompute `qualifyingData` from `expected_nonce ‖ server_pubkey ‖ binary_hash`.
2. Parse `tpms_attest`: check `magic == TPM_GENERATED_VALUE (0xff544347)`,
   `type == TPM_ST_ATTEST_QUOTE`, and that its `extraData` equals
   `qualifyingData`. **This is the anti-injection core** — the binding is checked
   against hardware-signed bytes, not against attacker-supplied sibling fields.
3. Verify `tpm_signature` over `tpms_attest` using **`trusted_ak_pubkey`** (the
   AK pinned in the peer's enrolled certificate — *not* `report.ak_pubkey`).
4. Recompute the PCR digest from `pcr_values`; check it matches the `pcrDigest`
   inside `tpms_attest`; enforce an expected-set policy for boot PCRs and that
   PCR 23 equals the approved binary measurement.
5. Consult `binary_attestation_.is_approved_binary()` — **unconditional**.

---

## 5. Phases

| Phase | Scope | Status |
|------|-------|--------|
| **1. Cheap hardening** (no TPM): mandatory signature, hard size checks, cert-pubkey binding in gossip, sponsor/token cross-check, remove `cin.get`, gate override, config enforcement | **landing** |
| **2. Data model**: new report/token/cert fields, canonical JSON, `Tpm2` enum, `trusted_pubkey` threaded through CRTP + callers | pending |
| **3. TPM backend**: FAPI generate + OpenSSL verify, PCR extend, detection | pending |
| **4. Enrollment binding**: AK pinning in `--enroll`, EK validation, config validation | pending |
| **5. Tests**: unit + negative + swtpm integration | pending |

### Phase 1 — concrete changes (this PR)

- **`TeeAttestation.cpp` `do_verify_report`** — signature is **mandatory**:
  reject when `signature` or `server_pubkey` is empty (issue 3).
- **`TeeAttestation.cpp` structural backends** (SGX/TDX/SEV/Apple) — hard-fail
  when `quote.size() < 36`; always enforce the nonce binding (issue 4). These
  remain structural-only and **insecure until Phase 3** — clearly commented.
- **`GossipService.cpp`** — new `peer_has_verified_certificate(pubkey)` helper;
  `verify_message_trust`, `handle_tee_response`, and
  `handle_enrollment_vote_request` now require the token/report `server_pubkey`
  to belong to an enrolled, certificate-verified, non-revoked peer, and the
  enrollment path cross-checks `token.server_pubkey == sponsor_pubkey` (issue 2).
- **`ServerConfig.cpp` `validate_config`** — when `require_tee_attestation` is
  set, require `release_signing_pubkey` (so the approved-binary check cannot be
  silently skipped; issue 5, config half).

### Tests (Phase 5) — negative cases that fail *today*

empty-signature report rejected; 4-byte `"SEV1"` quote rejected; self-asserted
pubkey not in any cert rejected; token replay (stale `challenge_nonce`)
rejected; tampered `extraData` rejected; AK mismatch vs cert rejected; plus an
`swtpm`-gated TPM integration test.

---

## 6. On the detour / obfuscation TODOs (issue 9)

In-process detours on the *prover* are irrelevant once the *verifier* checks a
hardware-signed quote against a cert-pinned AK — that is the actual mitigation.
The "function-call obscurity" idea is dropped; the TODO comments are replaced
with a pointer to this document.

---

## 7. Compatibility / rollout

- Phase 1 is pure hardening and needs no TPM; it tightens existing checks.
- During migration, the legacy structural backends stay compiled (hardened) so a
  mixed fleet keeps functioning; Phase 3 adds `Tpm2` as the only backend with a
  real root of trust, and Phase 4 makes it required when `require_tee_attestation`.
- The no-op FAPI target keeps non-Linux builds green; those nodes verify-only.

---

## 8. Open questions

1. **AK trust model** — model A (enrollment-pinned, chosen) vs model B (runtime
   EK-cert chain, deferred). Confirm A is acceptable for v1.
2. **Quote transport** — FAPI-JSON `quoteInfo` vs raw `TPMS_ATTEST` via
   `Esys_Quote`. Raw bytes verify trivially with OpenSSL on any platform; lean raw.
3. **PCR policy** — which PCRs define "approved boot" for the deployment
   (firmware/secure-boot 0–7 + app PCR 23)? Needs the container/host boot story.
