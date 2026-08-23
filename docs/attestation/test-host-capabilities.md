# Test Host Attestation Capabilities

**Host:** `uwb-nx0-mesh-root` (`nexus@10.10.12.40`)
**Collected:** 2026-08-23 with `scripts/nexus-attest-profile` 0.1.0
**Evidence archive:** `docs/attestation/evidence/uwb-nx0-mesh-root-2026-08-23.tgz` (`reference` and `evidence` runs)

## Host summary

| Item | Value |
|---|---|
| OS | Ubuntu 26.04 LTS |
| Kernel | 7.0.0-30-generic |
| Virtualization | KVM guest |
| CPU | AMD EPYC 9354 (host silicon supports SEV-SNP) |
| Secure Boot | Enabled |
| Kernel lockdown | `integrity` |
| IMA | Active, 52 measurements, `ima-ng` sha256 template |

## Present facilities

* securityfs with `ima`, `evm`, `integrity`, `lockdown`, `lsm`, `apparmor`.
* IMA ASCII and binary runtime measurement logs, readable as root.
* Secure Boot state through `mokutil` and EFI variables.
* Kernel config, kernel command line, and security sysctls.
* systemd service inspection tools (`systemctl`, `systemd-analyze`).
* Standard tooling: `openssl`, `curl`, `jq`, `python3`, `readelf`, `getcap`.

## Missing facilities

| Facility | State | Consequence |
|---|---|---|
| TPM device (`/dev/tpm*`) | Absent | No quotes, no PCR values, no AK. The IMA log cannot anchor to a quoted PCR 10. `boot_aggregate` is all zeros. |
| SEV-SNP guest report | Absent | The guest is plain KVM. No confidential-compute evidence exists. |
| tpm2-tools | Not installed | All `tpm:*` and `azure:*` collection steps report `missing`. |
| TPM boot event log (`/sys/kernel/security/tpm0/`) | Absent | Measured-boot replay is impossible. |
| Azure IMDS / THIM endpoints | Absent | No VCEK, no instance metadata. This host is not an Azure CVM. |
| Readable IMA policy | Read fails as root | The kernel does not expose the loaded policy (`CONFIG_IMA_READ_POLICY` likely off). The policy digest prerequisite cannot be collected here. |
| IMA SHA-256 template bank | Template digests are SHA-1 | The log replays only into the SHA-1 bank. A production profile requires `ima_template_hash_algo=sha256`. |
| Installed nexus binary and active `nexus.service` | Absent | Binary and runtime process evidence steps report `missing`. |

## Verifier consequence

This host can never pass the compiled Tier 1 profile. That is correct behavior. The
collector gathers what exists and records what does not. The Nexus verifier decides
trust, and this host fails the SEV-SNP, vTPM, quote, and PCR prerequisites.

The host remains useful for:

* Collector behavior tests (present-capability and missing-capability paths).
* IMA log format work against a real kernel 7.x log.
* Runtime hardening profile work (systemd sandboxing, seccomp, `no_new_privs`).

## Collector run results

* `reference` mode: completes, records 8 missing/error items, writes manifest and checksums.
* `evidence` mode with a 32-byte hex challenge: completes; `challenge_sha256` in the
  manifest matches the caller challenge bytes.
* Odd-length hex challenge: aborts before collection with exit 2 and no manifest.
* Missing `--challenge` in evidence mode: aborts with exit 2.
* Unknown mode: aborts with exit 2.

## Follow-up for a production profile host

1. Provision an Azure `DCasv5` (or equivalent SEV-SNP) host for the first supported profile.
2. Boot with a TPM-anchored IMA setup and `ima_template_hash_algo=sha256`.
3. Enable a readable IMA policy or a policy-digest collection path.
4. Install tpm2-tools on collection hosts.
