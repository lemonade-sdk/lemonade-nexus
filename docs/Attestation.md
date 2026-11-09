---
layout: default
title: Attestation
---

# Attestation

This page describes the implemented attestation behavior: which providers
verify, what the evidence path proves, what the profile requires, and
how failures surface.

- [Provider Matrix](#provider-matrix)
- [Evidence Path](#evidence-path)
- [The Profile](#the-profile)
- [The Evidence Helper: nexus-attestd](#the-evidence-helper-nexus-attestd)
- [Runtime Requirements](#runtime-requirements)
- [Fail-Closed Diagnostics](#fail-closed-diagnostics)
- [Qualifying a Host](#qualifying-a-host)

## Provider Matrix

The compiled verifier dispatches on an attestation profile ID. Evidence built
for one profile cannot answer a challenge for another.

| Profile ID | Provider | State |
|---|---|---|
| `snp-svsm-vtpm` | `SnpSvsmVtpmProvider` | **Implemented. The Tier 1 profile** (`kTier1AttestationProfileId`): the only profile under which this binary issues Tier 1 challenges. Verifies the AMD SEV-SNP chain (VCEK ← ASK ← compiled-in ARK), the COCONUT-SVSM service report that binds the vTPM endorsement key (EK) at VMPL0, the attestation key (AK) enrolled to that EK through TPM credential activation, a guest SNP report that proves Linux runs above VMPL0, the launch measurement, the TCB floor, a fresh quote under the AK, PCR 8 and 9, and IMA runtime measurements. |
| `snp-hcl-vtpm` | `AzureSnpVtpmProvider` | **Implemented, not the Tier 1 profile.** Verifies the paravisor shape: the SNP chain, the HCL report with `HCLAkPub`, the fresh TPM quote, and IMA runtime measurements. No challenge uses this profile while `kTier1AttestationProfileId` names the SVSM profile. |
| `snp-direct-boot` | `SnpDirectBootProvider` | **Declared, refuses, and not Tier 1 capable.** Returns `ProviderUnsupported`. A TPM-less measured boot has no protected runtime measurement accumulator, so implementing its evidence format will not make it Tier 1 capable. |
| `tdx` | (none) | Named so the enum stays stable. No provider. |

Intel SGX, Intel TDX, and Apple Secure Enclave are **not** implemented Tier 1
providers in this repository. Do not plan a deployment around them.

Four separate things are often conflated; keep them apart:

1. **Provider capability** — the design can produce the required claims.
2. **Implemented verifier** — code exists and verifies the evidence.
3. **Release-profile completeness** — a verified, signed release approval
   supplies the release values (see [The Profile](#the-profile)). Without one,
   the profile is incomplete.
4. **Successful deployment qualification** — a real host passed end to end.
   A release approval records its state in `qualification_state`; the
   current fleet profile (`release/fleet-profile.json`) is
   `LIVE_BOOT_APPROVED`, which requires exact PCR 8 and 9 values. This page
   does not record a qualification of any other host shape.

## Evidence Path

```text
challenge (fresh nonce, network, node, epoch, incarnation, profile)
    -> AK enrollment once per incarnation (credential activation via nexus-attestd)
    -> platform evidence (guest SNP report + SVSM service report + AK quote + IMA log)
    -> PlatformEvidenceProvider verifies -> VerifiedPlatformClaims
    -> Tier1EligibilityPolicy (fifteen prerequisites, conjunction, fail closed)
    -> signed mesh observations
    -> finalized eligibility -> selection -> readiness -> handoff
```

- The SNP `REPORT_DATA` is SHA-512 over a versioned domain and the canonical
  challenge digest, so the evidence binds to a fresh challenge. The bound context includes the network ID, profile
  ID and ruleset, node identity, incarnation, epoch, and policy digest.
- Platform claims travel inside **signed observations** from current Tier 1
  members. A node never supplies its own eligibility facts; a locally
  computed answer would be a self-report.
- The verifier checks profile completeness first. An incomplete profile
  fails every candidate with `ProfileIncomplete` before any other check.
- **IMA checkpoints.** After a passing SVSM attestation, the verifier stores
  a checkpoint (event count, PCR 10, required paths) bound to the network,
  node, incarnation, profile, policy digest, and enrolled AK. A later
  challenge can ask for `Resume` from that checkpoint. A checkpoint that does
  not match fails with `CheckpointRequired` or `CheckpointInvalid`.
- AMD revocation: the VCEK and its issuing ASK are checked against a cached
  KDS CRL under the same compiled-in root. This gates **new** attestation
  only; a frozen epoch's membership is not shrunk by a KDS outage.

## The Profile

`start_security_mesh()` builds the profile from the packaged release
approval (`/usr/lib/lemonade-nexus/release/release-approval.json`). The
approval must verify against the pinned Genesis key: Genesis signs the release
authority (network ID and release key), and the release key signs the
approval. Without a verified approval, the server keeps the compiled template
`linux_attestation_profile_v3_svsm_release()`. The template carries launch
measurements, an IMA policy, and a kernel identity, but no approved binary
digests and no PCR values, so it is incomplete. There is no local or
environment fallback.

The compiled template fixes the rules:

| Field | Pinned value |
|---|---|
| Debug disabled | required |
| Migration agent | denied |
| VMPL policy | `RequireAboveVmpl0` (Linux runs above the SVSM at VMPL0) |
| IMA log | required, SHA-256 replay bank, measured-kernel policy binding |
| `no_new_privs`, seccomp | required |
| Approved paths | `/usr/bin/lemonade-nexus`, `/usr/bin/nexus-attestd` |
| Evidence collector | `/usr/bin/nexus-attestd` (itself an approved path) |
| TCB floor | `kReleaseMinTcb` (AMD-SB-3030, AMD-SB-3034). An approval can raise it, never lower it. |

The signed approval supplies the release values. They are release
observations, never host observations:

| Field | Source in the approval | Gap name while unset |
|---|---|---|
| `snp.expected_measurements_hex` | `svsm_launch_measurements`, one per approved VM shape | `NoPinnedLaunchMeasurement` |
| `ima_policy_digest`, `ima_policy_id` | `ima_policy` (`id`, `sha256`) | `NoImaPolicyDigest` |
| Kernel identity | `kernel` (release, bzImage, vmlinux, module tree) | — |
| Approved path digests | `approved_paths`, plus `previous_release_paths` during a rollout | `NoApprovedBinary` |
| `expected_pcrs` | PCR 8 and 9 (`expected_pcrs`) | `NoExpectedPcrs` |

While any value is unset, `profile_is_complete()` is false, every attestation
fails with `ProfileIncomplete`, and **no node can reach Tier 1**. The server
logs each gap at startup. A package built locally without
`-DLEMONADE_RELEASE_APPROVAL_FILE` installs the unsigned example from
`packaging/release/`, so it stays in this state. An approval binds to one
network ID; it does not verify for another Genesis key.

## The Evidence Helper: nexus-attestd

`nexus-attestd` is a separate daemon (`/usr/bin/nexus-attestd`) that answers
over one local socket: produce this host's platform evidence for a challenge,
and run the TPM operations the Nexus server may not run itself. These are the
AK credential activation for SVSM enrollment, and the seal and unseal of a
32-byte key bound to PCR 8 and 9, which protects the server's boot set (see
[B6](Design-Tree-Consensus-and-Storage-Key#b6-sealing-the-boot-set)). The
activation request carries the verifier's credential material as-is and returns
the activated secret digest. Seal and unseal never receive the server's secret
or its ciphertext; the server encrypts with the key itself. The daemon never
decides eligibility, persists nothing, and creates no persistent TPM handle.

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

For a server to produce evidence the Tier 1 provider can verify:

- An AMD SEV-SNP guest that runs Linux above VMPL0, with a COCONUT-SVSM vTPM
  at VMPL0 **inside** the confidential boundary, and a launch measurement
  that the release approval lists. A host-side `swtpm` attached by QEMU sits
  outside the boundary and its quotes carry no attestation weight.
- The kernel TSM report interface (`/sys/kernel/config/tsm/report`).
  `nexus-attestd-tsm-setup.service` creates the two report objects that
  `nexus-attestd` uses.
- The boot chain whose PCR 8 and 9 the release approval pins.
- The IMA measurement policy loaded **before** the Nexus binary first
  executes (the `nexus-ima-policy.service` unit ships with the IMA
  measurement component, which is not part of this repository yet).
- The Nexus binaries installed at the approved paths (`/usr/bin/lemonade-nexus`,
  `/usr/bin/nexus-attestd`) with their release digests listed in the
  verified release approval.
- The `nexus-attestd` service running; the server unit requests it with
  `Wants=`/`After=`. A missing helper costs Tier 1, it does not stop the mesh
  node, except on a host whose gossip identity is fully sealed: that server
  waits about 30 s for the helper and then stops rather than create a new
  identity.
- AMD revocation data under `<data_root>/security/revocation`, one
  `<product>.crl` per compiled-in product. The server keeps it current itself
  (`AmdRevocationRefresher`, started by `SecurityMeshService`): at start and
  then once an hour it reads each cached list, and when no list is cached or
  the cached `nextUpdate` is within 7 days or past, it fetches
  `https://kdsintf.amd.com/vcek/v1/<product>/crl` off the io thread. The
  fetched bytes replace the cached file only when they parse as a CRL, verify
  under the compiled-in ARK/ASK for that product, and carry a `thisUpdate`
  not older than the cached one. Any other answer keeps the cached file, logs
  one warning that names the reason, and backs off (5 min doubling to 6 h).
  A list still expires on its own signed `nextUpdate`, after which new Tier 1
  attestation fails closed until a fetch succeeds; the refresh cannot make
  verification pass without a valid list. `scripts/nexus-refresh-amd-crl`
  seeds the same directory by hand for a host that must start without
  outbound access to KDS.

## Fail-Closed Diagnostics

Expected log lines and what they mean:

| Log line | Meaning |
|---|---|
| `Attestation profile v3 is incomplete: <gap>` (repeated per gap) | The profile is missing release values, usually because no verified release approval is installed. Every candidate will fail `ProfileIncomplete`. |
| `Tier-1 release approval unavailable: <reason>` | The packaged approval is missing, unsigned, for another network, or does not verify against the Genesis key. |
| `No node can reach Tier 1 until the profile pins these values.` | Same, as a summary. |
| Verdict failures recording `ProfileIncomplete` | The completeness gate, working as designed. |
| `ProviderUnsupported` from the direct-boot provider | A candidate presented (or was configured for) an unimplemented provider shape. It stays ineligible. |
| `ActivationRequired`, `CheckpointRequired`, `CheckpointInvalid` | The SVSM AK is not enrolled for this incarnation, or the IMA checkpoint does not match. The AK rotates on reboot, so a reboot re-runs enrollment. |
| `Onboard: no platform evidence on this host` | The onboarding candidate could not produce evidence; it requests a Tier 2 certificate. Not a failure of the join. |
| `[revocation] <product>: CRL refreshed from KDS; thisUpdate ..., nextUpdate ...` | A newer AMD-signed list replaced the cached one. |
| `[revocation] <product>: CRL refresh failed (<reason>): ...; the cached list is valid until ... / expired at ...; next attempt at ...` | KDS did not answer, or answered with something that is not AMD's current list for the product (`fetch_failed`, `unparsable`, `signature_invalid`, `older_than_cached`, `store_failed`). The cached file is unchanged. Once it expires, verdicts record `EndorsementRevoked` for every candidate until a fetch succeeds. |
| `[revocation] no KDS fetch configured` | The service was built without a fetch (tests). The assembled server always configures one. |
| Missing helper / socket refused | The server runs without evidence capability. Mesh services work; Tier 1 is unreachable. |

Missing, stale, invalid, unsupported, or incomplete evidence must never
become acceptance. If a diagnostic suggests otherwise, that is a defect to
report, not a setting to work around.

## Qualifying a Host

Two host shapes appear in the profile set:

1. **SVSM-vTPM (the Tier 1 profile).** Run a COCONUT-SVSM at VMPL0 with the
   guest at VMPL1 or above, so the vTPM lives inside the confidential
   boundary and the SVSM service report binds it. This is the shape the
   `snp-svsm-vtpm` provider verifies. The host also needs a launch
   measurement and a boot chain that the release approval lists; a new VM
   shape needs a reviewed change to `release/fleet-profile.json` (see
   [Releasing](Releasing#reviewed-release-inputs)).
2. **SNP measured direct boot** with the kernel, initrd, and command line in
   the launch measurement and a dm-verity root hash pinned on that command
   line. The corresponding provider is declared but not implemented, so this
   shape is not verifiable today.

The profile must not be relaxed to accept an unbound vTPM. Accepting one
would let any hypervisor mint a passing Tier 1 node.
