---
title: "Wire and Storage Compatibility Between Releases"
---

# Wire and Storage Compatibility Between Releases

Status: **rule in force** for every release after the first auto-update
release (Design-Auto-Update Phase 3). The mixed-version gate checks it; see
[Checks](#checks).

Servers update one at a time (Design-Auto-Update Phase 5), so a mesh always
holds servers on release N and N+1 during a rollout. This page states what a
release may change and what it must keep.

## The rule

1. **Release N+1 accepts every message that release N sends.** It decodes
   every message kind, topic, attestation purpose, and block payload kind that
   N can produce, and it applies the same validity rules to them.
2. **Release N+1 does not require a message that release N cannot send**,
   until the whole mesh runs N+1. A feature that needs every server waits for
   a finalized fact that all servers run N+1. It never turns on from local
   configuration.
3. **Additions only.** A new message kind, topic, purpose, payload kind, or
   field is added. An existing value keeps its number and its layout. Values
   that another open change reserved stay reserved (for example, security
   message kind 37 is `StorageWrapClaim`).
4. **A release keeps these values unchanged:**
   - `kSecurityRulesetVersion` and `kConsensusRulesetVersion`. They feed
     `network_id`, so a change orphans every epoch record, storage record,
     and release approval. The test `ReleaseRulesetPin.*` fails when a release
     changes them. A ruleset change is a separate, consensus-finalized
     transition with its own migration plan.
   - `kSecurityWireVersion`. A release N verifier refuses an approval whose
     security wire version differs from its own.
   - `kAttestdWireVersion` and the attestation profile ruleset, for the same
     reason.

   The kernel, IMA policy, and SVSM launch identity are not on this list.
   Since Design-Auto-Update Phase 0.3 the signed approval carries them (from
   `release/fleet-profile.json`) and a release N verifier checks them against
   that approval only, so N+1 may change them.
5. **Storage formats change only with a reader for the previous format.** A
   release reads every durable record that release N writes: epoch state,
   consensus state, attestation state, storage records, the release chain
   record, and the upgrade records.
6. **Approvals overlap by one release.** The approval of N+1 lists the
   hashes of N in `previous_release_paths`, so N and N+1 attest each other.
   N-1 stops passing attestation once a server adopts N+1.

## Baseline

The rule starts with the bootstrap release, the first date-tagged release
(Design-Auto-Update Phase 6). Its baseline is the fleet's r21 line: the r21
release carries the release approval with an SVSM launch measurement set and
a bootstrap certificate that commits the approval digest. Both arrived after
security wire version 3 (commit `e9748c6`), so r21 runs version 3, like this
line. This is inferred from the r21 approval format; the r21 binary is not a
release asset and no mixed-version run against it is recorded.

The `vX.Y.Z-alpha` GitHub releases are not a baseline. `v0.9.7-alpha` sends
security wire version 1. A current server refuses every such envelope at the
version byte (`decode_security_message` returns `BadVersion`), and its
message layouts also differ (attestation challenge and evidence fields, the
bootstrap certificate). A mixed-version run against that release therefore
reports dropped messages from every old node. The router records these drops
as `WireVersionMismatch` (14), not `Malformed`, and the gate script reports
the old binary as an invalid baseline. The commit r21 started from
(`dd80e7f`) is also wire version 1; the r21 build added the version 3 work on
top of it, so that commit alone is not r21 either.

## A new block payload kind

A server that does not know a payload kind refuses the whole proposal that
carries it, so it cannot vote for that block. A new payload kind therefore
waits for proof that the committee knows it. `UpgradeProgress` (kind 4) uses
this gate: a leader proposes an upgrade record only when every current Tier 1
member sent a signed upgrade status in the liveness window, and a server
sends a status only when it runs a release that knows the kind.

## Checks

- `tests/security/lifecycle/upgrade_path.cpp` runs servers on N and N+1 in one
  memory mesh: an in-place restart onto N+1 that keeps the epoch chain and the
  Tier 1 role, approval adoption over the backbone, cross attestation by the
  profile hashes, and the upgrade turns.
- `tests/security/release/ruleset_pin.cpp` pins the ruleset versions and the
  `network_id` derivation.
- `scripts/mixed-version-mesh.sh` and the `Mixed-version gate` workflow run
  the previous release's server binary next to the new binary in one
  multi-process mesh. `release.yml` calls the workflow with the previous
  date-tagged release; for the bootstrap release the run uses an r21-line
  build as `OLD_BIN` by hand. On a host without SEV-SNP the run proves wire
  compatibility only: both binaries decode each other's traffic, and the mesh
  refuses to found on unproven hardware. Founding, epoch transition, storage
  unlock, and cross attestation across binaries need an SEV-SNP host; the
  script runs those checks when `NEXUS_MIXED_HARDWARE=snp` is set on such a
  host. A run without that hardware is not evidence for them.
