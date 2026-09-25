# Test Host Attestation Capabilities

**Host:** `uwb-nx0-mesh-root` (`nexus@10.10.12.40`)

This host has been collected twice. The second collection supersedes the first
as the current state. The first is kept as the record of the host before
SEV-SNP and vTPM were enabled, and its conclusions remain true of that
configuration.

| Collection | Archive | State |
|---|---|---|
| 2026-08-23 | `evidence/uwb-nx0-mesh-root-2026-08-23.tgz` | Historical. Plain KVM guest: no TPM, no SEV-SNP. |
| 2026-08-26 | `evidence/uwb-nx0-mesh-root-2026-08-26-snp.tgz` | **Current.** Native SEV-SNP guest with a vTPM. |

---

# Current collection — 2026-08-26

**Collected:** `2026-08-26T01:13:20Z` with `scripts/nexus-attest-profile` 0.1.0
**Modes:** `reference` and `evidence --challenge <32 fresh random bytes>`
**Challenge:** `9d5d8d12d48b8abd98775e3cefed2ab7f888ca4dbf7c40333f513b0af0f4e9bb`

## Host summary

| Item | Value |
|---|---|
| OS | Ubuntu 26.04 LTS |
| Kernel | 7.0.0-30-generic |
| Virtualization | QEMU/KVM, Q35 + ICH9, EDK II 2025.11-3ubuntu7 |
| CPU | AMD EPYC 9354 32-Core (family 25, model 17 — Genoa) |
| Confidential computing | `AMD SEV SEV-ES SEV-SNP` active; systemd reports `sev-snp` |
| Guest privilege level | **VMPL0** (`SEV: SNP running at VMPL0`) |
| vTPM | TPM 2.0, ACPI `MSFT0101`, driver `tpm_crb`, manufacturer `IBM` |
| Secure Boot | **Not enabled** (no `SecureBoot-*` EFI variable) |
| Kernel lockdown | `[none]` |
| IMA | Enabled, **no measuring policy** (log holds only `boot_aggregate`) |
| Root filesystem | LVM, no dm-verity |

## SEV-SNP — working and cryptographically verified

The guest reads its own attestation report through the kernel TSM configfs
interface (`/sys/kernel/config/tsm/report`, provider `sev_guest`). This is the
native path. It is not the Azure paravisor path.

| Field | Value |
|---|---|
| Report version | 3 (1184 bytes) |
| Signature algorithm | 1 — ECDSA P-384 with SHA-384 |
| Guest policy | `0x30000` — DEBUG denied, migration agent denied |
| VMPL | 0 |
| Launch measurement | `826de00d89da6a54ddc829c64aa871cc3409e50b19b7117aceccce9515e65050f689836a70777cd676f52f826394b8b5` |
| Chip ID | `aea3ce6f…8e4d6d4` (64 bytes) |
| Reported TCB | bootloader 9, TEE 0, SNP 23, microcode 72 |
| Firmware | 1.55 build 39 |
| `HOST_DATA` | all zero |

Three properties were verified off-host against the archived bytes:

1. **AMD chain.** VCEK ← ASK (`CN=SEV-Genoa`) ← ARK (`CN=ARK-Genoa`, self-signed).
   `openssl verify` returns OK. The VCEK was fetched from the AMD key server for
   this chip ID and TCB.
2. **Report signature.** ECDSA P-384 over SHA-384 of report bytes `0x000`–`0x2A0`,
   checked under the VCEK public key: **Verified OK**.
3. **Challenge binding.** `REPORT_DATA == SHA-512(challenge)`. The `reference`
   run carries a different `REPORT_DATA` and the identical launch measurement,
   which is exactly what a fresh challenge over a stable image produces.

The SEV-SNP evidence from this host is genuine and hardware-rooted.

The host serves no certificate chain of its own: the TSM `auxblob` is empty, so
a verifier must fetch the VCEK from AMD using the chip ID and TCB in the report.

## vTPM — present, exercisable, and outside the trust boundary

The vTPM works mechanically. All four PCR banks are live, PCRs 0–10 and 14 are
populated, the TPM event log holds 117 parsed events over 31359 bytes, an
attestation key can be created, and `tpm2_quote` signs a fresh challenge.

It nevertheless carries **no attestation weight on this host**:

| Observation | Consequence |
|---|---|
| Guest runs at **VMPL0** | No service module sits below the guest. A COCONUT-SVSM vTPM would occupy VMPL0 and force the guest to VMPL1 or higher. |
| `svsm` absent from kernel log; `/sys/firmware/qemu_fw_cfg` present | Direct QEMU guest. No paravisor. |
| ACPI TPM2 table OEM ID `BOCHS`, manufacturer `IBM`, driver `tpm_crb` | The vTPM is a host-side `swtpm` attached by QEMU. |
| No EK certificate in NV, no persistent AK | The vTPM has no chain to any manufacturer root. The AK the collector used was created on the spot and is uncertified. |
| SNP `HOST_DATA` is zero and `REPORT_DATA` is caller-chosen | Nothing in the hardware report vouches for the vTPM key. |

The vTPM therefore lives outside the SEV-SNP encryption and integrity boundary.
A hostile hypervisor can forge any quote it produces, including PCR contents.
Measured-boot and IMA evidence taken from this vTPM prove nothing against the
threat model SEV-SNP exists to address.

This is the structural difference from an Azure confidential VM, where the
paravisor holds the vTPM inside the guest boundary and publishes `HCLAkPub`
in the SNP report's runtime data — which is precisely the binding the compiled
verifier requires.

## What the SNP launch measurement does and does not cover

The guest boots through GRUB from an unmeasured LVM volume:

```
BOOT_IMAGE=/vmlinuz-7.0.0-30-generic root=/dev/mapper/ubuntu--vg-ubuntu--lv ro
```

There is no measured direct boot and no dm-verity. The launch measurement
therefore covers the initial firmware image only. The kernel, the initrd, the
root filesystem, and any Nexus binary on it are outside it.

## Regressions against the 2026-08-23 collection

Enabling SEV-SNP rebuilt the guest and lost two facilities the earlier
configuration had:

| Facility | 2026-08-23 | 2026-08-26 |
|---|---|---|
| Secure Boot | Enabled | **Not enabled** |
| IMA measurements | 52 entries | **1 entry** (`boot_aggregate` only) |

`CONFIG_IMA=y`, `CONFIG_IMA_APPRAISE=y` and `CONFIG_IMA_ARCH_POLICY=y` are set,
but `CONFIG_IMA_WRITE_POLICY` is **not** set and the kernel command line carries
no `ima_policy=`. No policy can be loaded at runtime, so nothing on this host is
measured and no binary can be IMA-anchored until the command line changes and the
host reboots.

## Verdict against the compiled Tier 1 profile

**This host does not satisfy the compiled Tier 1 profile.** It fails closed, and
that is the correct result. The reasons are ordered by how fundamental they are:

| # | Prerequisite | State | Fundamental? |
|---|---|---|---|
| 1 | vTPM inside the confidential boundary, bound to SNP hardware | Absent — host-side swtpm, VMPL0 guest | **Yes.** Needs host reconfiguration. |
| 2 | Evidence chain format the verifier parses (Azure HCL blob) | Absent — native TSM report only | Yes, for this code path. |
| 3 | IMA measuring policy anchoring the Nexus binary to PCR 10 | Absent — no policy loaded | No. Kernel command line plus reboot. |
| 4 | Secure Boot | Not enabled | No. Firmware setting. |
| 5 | Boot chain covered by a measurement | Absent — GRUB from unmeasured LVM | No. Measured direct boot or dm-verity. |
| 6 | Installed Nexus binary and running service | Absent | No. Deployment step. |
| 7 | Compiled profile carrying pinned values | Absent in the binary | No. See the status document. |

Item 1 is the one that cannot be fixed from inside the guest, and it is the one
that decides the question. Either of two host changes would resolve it:

* Run a **COCONUT-SVSM vTPM** at VMPL0 with the guest at VMPL1 or above, so the
  vTPM lives inside the confidential boundary and the SNP report can bind it; or
* Use **SNP measured direct boot** with the kernel, initrd and command line in
  the launch measurement and a dm-verity root hash pinned on that command line,
  so software integrity rests on the SNP measurement and needs no vTPM.

The profile must not be relaxed to accept an unbound vTPM. Accepting one would
let any hypervisor mint a passing Tier 1 node.

## Continuing usefulness

Until a host change lands, this host remains the right target for:

* Native SEV-SNP report collection and AMD chain verification against real bytes.
* Negative attestation testing and Tier 2 behavior.
* Ineligible-peer and transport testing across a real network.
* IMA and event-log format work against a real kernel 7.x host.

---

# Historical collection — 2026-08-23

**Archive:** `evidence/uwb-nx0-mesh-root-2026-08-23.tgz`

At that time the host was a plain KVM guest. The conclusions below describe that
configuration and are retained unchanged.

| Item | Value |
|---|---|
| Virtualization | KVM guest, no confidential computing |
| Secure Boot | Enabled |
| Kernel lockdown | `integrity` |
| IMA | Active, 52 measurements, `ima-ng` sha256 template |

Missing at that time: TPM device, SEV-SNP guest report, `tpm2-tools`, TPM boot
event log, Azure IMDS and THIM endpoints, readable IMA policy, a SHA-256 IMA
template bank, and an installed Nexus binary.

That host could never pass the compiled Tier 1 profile, and the collector
recording every missing facility was the correct result.
