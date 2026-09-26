---
layout: default
title: Attestation
---

# Attestation

This page describes the implemented attestation behavior: which providers
verify, what the evidence path proves, what the shipped profile requires, and
how failures surface.

- [Provider Matrix](#provider-matrix)
- [Evidence Path](#evidence-path)
- [The Shipped Profile](#the-shipped-profile)
- [The Evidence Helper: nexus-attestd](#the-evidence-helper-nexus-attestd)
- [Runtime Requirements](#runtime-requirements)
- [Fail-Closed Diagnostics](#fail-closed-diagnostics)
- [Qualifying a Host](#qualifying-a-host)

## Provider Matrix

The compiled verifier dispatches on an attestation profile ID. Evidence built
for one profile cannot answer a challenge for another.

| Profile ID | Provider | State |
|---|---|---|
| `snp-hcl-vtpm` | `AzureSnpVtpmProvider` | **Implemented.** Verifies the AMD SEV-SNP chain (VCEK ← ASK ← compiled-in ARK), the SNP report signature, guest policy, launch measurement, TCB floor, the paravisor-bound vTPM (HCL report with `HCLAkPub`), the fresh TPM quote, and IMA runtime measurements. |
| `snp-svsm-vtpm` | `SnpSvsmVtpmProvider` | **Declared, refuses.** Returns `ProviderUnsupported`. The SVSM service-manifest format is not invented; it waits on real evidence from an approved SVSM host. |
| `snp-direct-boot` | `SnpDirectBootProvider` | **Declared, refuses, and not Tier 1 capable.** Returns `ProviderUnsupported`. A TPM-less measured boot has no protected runtime measurement accumulator, so implementing its evidence format will not make it Tier 1 capable. |
| `tdx` | (none) | Named so the enum stays stable. No provider. |

Intel SGX, Intel TDX, and Apple Secure Enclave are **not** implemented Tier 1
providers in this repository. Do not plan a deployment around them.

Four separate things are often conflated; keep them apart:

1. **Provider capability** — the design can produce the required claims.
2. **Implemented verifier** — code exists and verifies the evidence.
3. **Release-profile completeness** — the shipped profile is pinned (it is
   not, today).
4. **Successful deployment qualification** — a real host passed end to end
   (none has, today).

## Evidence Path

```text
challenge (fresh nonce, network, node, epoch, incarnation, profile)
    -> platform evidence (SNP report + HCL/vTPM bundle + IMA log)
    -> PlatformEvidenceProvider verifies -> VerifiedPlatformClaims
    -> Tier1EligibilityPolicy (fifteen prerequisites, conjunction, fail closed)
    -> signed mesh observations
    -> finalized eligibility -> selection -> readiness -> handoff
```

- The quote's `REPORT_DATA` equals `SHA-512(challenge)`, so the evidence binds
  to a fresh challenge. The bound context includes the network ID, profile
  ID and ruleset, node identity, incarnation, epoch, and policy digest.
- Platform claims travel inside **signed observations** from current Tier 1
  members. A node never supplies its own eligibility facts; a locally
  computed answer would be a self-report.
- The verifier checks profile completeness first. An incomplete profile
  fails every candidate with `ProfileIncomplete` before any other check.
- AMD revocation: the VCEK and its issuing ASK are checked against a cached
  KDS CRL under the same compiled-in root. This gates **new** attestation
  only; a frozen epoch's membership is not shrunk by a KDS outage.

## The Shipped Profile

`start_security_mesh()` installs the named compiled profile
`linux_attestation_profile_v1()`. It fixes the rules:

| Field | Pinned value |
|---|---|
| Debug disabled | required |
| Migration agent | denied |
| VMPL policy | `RequireVmpl0` (the HCL/paravisor shape) |
| IMA log | required, kernel-readback proof |
| `no_new_privs`, seccomp | required |
| Approved paths | `/usr/bin/lemonade-nexus`, `/usr/bin/nexus-attestd` |
| Evidence collector | `/usr/bin/nexus-attestd` (itself an approved path) |

Deliberately **unset** (these are release observations, never host
observations):

| Field | Gap name | Consequence while unset |
|---|---|---|
| `snp.expected_measurement_hex` | `NoPinnedLaunchMeasurement` | Any SNP guest image would pass |
| `snp.min_tcb` | `NoTcbFloor` | Firmware with known issues would pass |
| `ima_policy_digest` | `NoImaPolicyDigest` | The measuring policy is unproven |
| Approved path digests | `NoApprovedBinary` | No measured component can be looked up |

While those stay unset, `profile_is_complete()` is false, every attestation
fails with `ProfileIncomplete`, and **no node can reach Tier 1**. The server
logs each gap at startup. This is the intended behavior: pinning values
observed on an unqualified host would make the profile decide nothing.

## The Evidence Helper: nexus-attestd

`nexus-attestd` is a separate daemon (`/usr/bin/nexus-attestd`) that answers
one question over one local socket: produce this host's platform evidence for
a challenge.

The unit file draws the privilege boundary explicitly:

- **Dedicated identity** (`User=nexus-attestd`), not root and not the server's
  account. A server compromise does not inherit TPM access, and a helper
  compromise does not inherit the server's data.
- **The only device:** `/dev/tpmrm0` (read/write), via `DevicePolicy=closed`.
  The raw `/dev/tpm0` is not allowed.
- **The only capability:** `CAP_DAC_READ_SEARCH`, needed to read the IMA
  measurement log under the 0700-root securityfs. Everything else is
  dropped.
- **Filesystem isolation:** `ProtectSystem=strict`, and the sensitive trees
  are masked — including `/var/lib/lemonade-nexus` (which holds the node
  identity keypair and any persisted authority material), `/etc/shadow`, and
  the SSH keys. The mask is required *because* the capability bypasses DAC
  reads; a capability cannot reach what the mount namespace does not show.
- **No TCP port is ever bound.** Network egress exists only so an uncached
  VCEK can be fetched from AMD KDS (best-effort). A network-isolated
  deployment pre-seeds the cache and runs with `--no-network`.

The boundary means the helper is scoped, **not** entirely privilege-free: it
holds the one capability and the one device the evidence path needs, and
nothing else. It does **not** hold the Nexus identity key, the consensus vote
key, or the FROST share. The Nexus server has no TPM or IMA access at all.

## Runtime Requirements

For a server to produce evidence the implemented provider can verify:

- An AMD SEV-SNP guest with the vTPM **inside** the confidential boundary —
  the paravisor/SVSM shape that publishes `HCLAkPub` in the SNP report's
  runtime data. A host-side `swtpm` attached by QEMU sits outside the
  boundary and its quotes carry no attestation weight.
- The IMA measurement policy loaded **before** the Nexus binary first
  executes (the `nexus-ima-policy.service` unit ships with the IMA
  measurement component, which is not part of this repository yet).
- The Nexus binaries installed at the approved paths (`/usr/bin/lemonade-nexus`,
  `/usr/bin/nexus-attestd`) with their release digests pinned in a complete
  profile.
- The `nexus-attestd` service running; the server unit requests it with
  `Wants=`/`After=`. A missing helper costs Tier 1, it does not stop the mesh
  node.
- AMD revocation data: `scripts/nexus-refresh-amd-crl` fetches a product's KDS
  list and installs it atomically under
  `<data_root>/security/revocation`. A fetch failure keeps the existing
  entry; revocation data then expires on its own signed `nextUpdate`, after
  which new Tier 1 attestation fails closed.

## Fail-Closed Diagnostics

Expected log lines and what they mean:

| Log line | Meaning |
|---|---|
| `Attestation profile v1 is incomplete: <gap>` (repeated per gap) | The shipped profile is missing pinned values. Every candidate will fail `ProfileIncomplete`. Normal at this revision. |
| `No node can reach Tier 1 until the profile pins these values.` | Same, as a summary. |
| Verdict failures recording `ProfileIncomplete` | The completeness gate, working as designed. |
| `ProviderUnsupported` from the SVSM or direct-boot provider | A candidate presented (or was configured for) an unimplemented provider shape. It stays ineligible. |
| `Onboard: no platform evidence on this host` | The onboarding candidate could not produce evidence; it requests a Tier 2 certificate. Not a failure of the join. |
| Missing helper / socket refused | The server runs without evidence capability. Mesh services work; Tier 1 is unreachable. |

Missing, stale, invalid, unsupported, or incomplete evidence must never
become acceptance. If a diagnostic suggests otherwise, that is a defect to
report, not a setting to work around.

## Qualifying a Host

Two host shapes can satisfy the compiled profile:

1. **SVSM-vTPM (the HCL/paravisor shape).** Run an SVSM at VMPL0 with the
   guest at VMPL1 or above, so the vTPM lives inside the confidential
   boundary and the SNP report binds it. This is the shape the implemented
   `snp-hcl-vtpm` provider verifies.
2. **SNP measured direct boot** with the kernel, initrd, and command line in
   the launch measurement and a dm-verity root hash pinned on that command
   line. The corresponding provider is declared but not implemented, so this
   shape is not verifiable today.

The profile must not be relaxed to accept an unbound vTPM. Accepting one
would let any hypervisor mint a passing Tier 1 node.
