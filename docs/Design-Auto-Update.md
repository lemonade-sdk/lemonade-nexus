---
title: "Design: In-Place Auto-Update"
---

# Design: In-Place Auto-Update

Status: **draft plan; Phases 0.1, 0.3, 1 to 5 implemented, not
hardware-qualified, release workflow not run.** See
[Implementation status](#implementation-status).

## Goal

- An operator runs **one** GitHub Actions workflow. It builds every artifact,
  versions it by date, signs it, and publishes the release. No other step.
- Every server updates itself **in place**, **one at a time**. It keeps its
  epoch chain, Tier 1 membership, storage key share, data key, sealed boot set,
  tree log, and data. There is no re-found and no manual deploy.
- A server on the new release joins and works with servers on the previous
  release. Servers on the previous release attest the new release.

- The update covers the operating system too: the updater applies the
  release's OS packages (kernel, GRUB, pinned system libraries) and reboots the
  machine when the boot chain changed, under the same one-at-a-time rule.

## Non-goals

- Changing who holds authority. The release key that Genesis pins stays the
  root of trust for releases. GitHub is a transport and a second check.
- Distribution-driven updates. `unattended-upgrades` is disabled on the fleet;
  every OS change arrives through a release so its measurements are known.

## OS updates and reboot

1. The release pins an OS package set (`release/os-packages.lock`: exact
   kernel, GRUB, and library package versions).
2. The release workflow measures the expected PCR 8/9 for that set on a
   reference VM image built in CI, and writes them into the approval next to
   the current values. The approval lists both, so servers attest each other
   during the rollout.
3. Before a reboot the updater asks the server to stage the next boot chain:
   the server seals a second copy of its boot set to the new PCR 8/9 from the
   verified approval (storage design B6 and Phase 6 `SealedBlobStore` staging).
4. The updater installs the packages, then reboots inside its upgrade turn.
   The health gate (Phase 4 step 7) runs after the reboot. On failure the
   updater boots the previous GRUB entry and halts the rollout.
5. A release that does not change the boot chain restarts only the services,
   with no reboot.

## Versioning

- Release tag: `vYYYY.MM.DD`. A second release on the same day is
  `vYYYY.MM.DD.2`, then `.3`.
- Release number: a monotonic integer derived from the tag
  (`YYYYMMDD * 100 + N`). The approval carries it. Servers refuse any approval
  whose number is not greater than the highest number they have accepted
  (no downgrade, no replay).

## Phase 0: Gates (answer before code)

1. **In-place restart across an approval change (blocked today).** The
   storage review (2026-10-24) found two blockers:
   - A stored bootstrap certificate commits one release approval, and
     recovery refuses a different one (`SecurityDriver.cpp:228-234`).
   - A ruleset version change changes `network_id`
     (`SecurityMeshService.cpp:25-28`). Storage records under the old id are
     then refused (`StorageKeyService.cpp:538`), and the node cannot unlock.

   Required design: a newer approval, signed by the Genesis-pinned release key
   with a higher release number, supersedes the committed one without
   Genesis. The Genesis commitment then binds the release *signer* and the
   network, not one approval digest. Releases keep the ruleset versions that
   feed `network_id` unchanged; a ruleset change is a separate,
   consensus-finalized transition, never a side effect of an update. This is
   a trust-model change, so it needs explicit review and a migration test.
   Owner approval: 2026-10-24, on the condition that it stays secure (fail
   closed, signer pinned by Genesis, monotonic release number, no downgrade).

   Implemented as follows (`Security/Attestation/ReleaseChain.hpp`). The
   bootstrap certificate format is unchanged and still commits the founding
   approval digest. That approval names the release signer and the network,
   so the commitment binds both. Each server keeps one release chain record
   beside its epoch state: the pinned signer, the digest of the approval that
   pinned it, the bound founding digest, the highest accepted release number,
   and the newest accepted approval. At restart the driver accepts the stored
   certificate when the founding approval it names carries the pinned signer
   for this network; it no longer requires the loaded approval digest. A
   different Genesis-signed release key is refused (`WrongSigner`), so
   Genesis cannot install a new release authority after Epoch 1. A release
   key rotation would need its own consensus-finalized transition.
2. **Holder margin.** With 5 holders, `t = 4`. One server down is exactly
   survivable. Confirm that unlock and consensus continue while one Tier 1
   server restarts.
3. **Fleet profile.** The approval pins PCR 8/9, SVSM launch measurements, and
   system library hashes taken from the fleet (`ceremony/fleet-libs`). Move
   these inputs into a reviewed file in the repository
   (`release/fleet-profile.json`) so CI can build the approval without access to
   the VMs.

## Phase 1: Release workflow (`release.yml`)

Trigger: `workflow_dispatch` only, from `main`.

1. Compute the date version and release number. Fail if the tag exists.
2. Build all targets in a matrix: server, `nexus-attestd`, SDK, Flutter
   clients, and `.deb`/`.rpm` packages. Server binaries build in a pinned
   container that matches the fleet toolchain, so hashes are reproducible.
3. Generate the release approval with `nexus-release-bundle` from
   `release/fleet-profile.json` and the built hashes. The approval lists the
   new hashes **and** the previous release's hashes (overlap window of one
   release).
4. Sign the approval with the release key. The key is a secret in a GitHub
   environment `release` that only this workflow on `main` can read.
5. Attach Sigstore build provenance (`actions/attest-build-provenance`) for
   every artifact.
6. Create the tag and the GitHub release. Upload the artifacts, the signed
   approval, and a manifest (version, release number, hashes, wire versions).

Repository settings that this model depends on: branch protection on `main`
(reviewed merges only), and workflow dispatch limited to maintainers.

## Phase 2: Approval chain and adoption

1. **Verification.** A server accepts an approval only when its signature
   verifies against the Genesis-pinned release key, its network id matches,
   and its release number is greater than the highest accepted number.
2. **Runtime adoption.** A server that receives a newer valid approval over the
   backbone (from a peer or its own updater) stores it and uses it for
   attestation. This lets servers on release N attest a server on N+1.
3. **Overlap.** Attestation accepts a binary hash listed in the newest accepted
   approval. Because each approval lists the previous release's hashes too,
   N and N+1 attest each other during the rollout. N-1 stops passing once N+1
   is adopted.
4. **Persistence.** The highest accepted release number survives restart.
   It is stored with the security state, not in a config file.

## Phase 3: Mixed-version compatibility

1. **Wire rule.** Release N+1 must accept every message release N sends, and
   must not require a message N cannot send, until the whole mesh runs N+1.
   New message types and fields are additive; a feature that needs every
   server waits for a finalized "all servers on N+1" fact before it turns on.
2. **Storage rule.** On-disk formats change only with a reader for the previous
   format.
3. **CI gate.** A mixed-version test runs the previous release's server binary
   (downloaded from the last GitHub release) with the new binary in one mesh:
   founding, epoch transition, tree ops, storage unlock, and attestation in
   both directions. The release workflow refuses to publish if it fails.

## Phase 4: Updater

A separate small service, `nexus-updater` (systemd unit and timer, runs as
root). The server keeps no write access to `/usr/bin`. The updater holds no
server keys.

1. Poll the GitHub releases API (default: every 15 minutes).
2. Download the manifest, the approval, and the artifacts for this host.
3. Verify: the approval (Phase 2 rules), the artifact hashes against the
   approval, and the Sigstore provenance (repository, `release.yml`, `main`).
   Any failure stops the update and logs why.
4. Stage the files next to the installed ones. Hand the approval to the server
   for adoption (Phase 2).
5. Wait for this server's upgrade turn (Phase 5).
6. Stop the server, swap the binaries and the approval atomically, keep the
   previous files, and start the server.
7. **Health gate**, within a bounded time: the server reports the new version,
   passes attestation, resumes its epoch role, unlocks its data key, and
   catches up the tree log.
8. On success, report "upgraded". On failure, restore the previous files,
   restart, and report "failed". A failure halts the rollout for every server
   until a newer release appears.

## Phase 5: One at a time, through consensus

1. **Order.** For each release, the order is a deterministic ranking of
   admitted servers (hash of release number and node id). Tier 2 servers go
   first, then Tier 1, so a bad release fails on a non-voting server first.
2. **Turn.** A server may restart only when finalized state shows that every
   server ahead of it reported "upgraded" for this release and no server is
   currently down. Turn state is a new consensus payload kind
   (`UpgradeProgress`, on the Phase 2 `BlockPayload` extension point). A
   server's "upgraded" report counts only when a witness quorum observed the
   server attested and healthy on the new version.
3. **Safety rule.** Never more than one Tier 1 server or storage holder down.
   If any holder is unreachable, the rollout waits.
4. **Halt.** A "failed" report finalizes a halt for the release.

## Phase 6: Bootstrap (one time)

The servers run r21, which has no updater, no runtime approval adoption, and
plaintext files. The first auto-update release is installed once by the
procedure from the storage review: back up the security and sealed state,
install one server at a time, confirm migration and unlock before the next,
and never re-found. Every release after that uses Phases 1-5.

Release chain migration (one step per server, before its first start on the
new release):

1. Copy the installed r21 approval
   (`/usr/lib/lemonade-nexus/release/release-approval.json`) to
   `<data_root>/security/release/release-founding-approval.json`.
2. Install the new release. At its first start the server pins the release
   signer from the new (format 3) approval, then binds the stored
   certificate's commitment through the copied r21 approval. The server
   accepts the file only when its digest equals the commitment, its Genesis
   delegation and release signature verify for this network, and its signer
   is the pinned signer. Without the file, or with any other file, the driver
   fails closed and the epoch state stays untouched.
3. The first auto-update approval must be signed by the r21 release key and
   list the r21 hashes in `previous_release_paths`, so r21 and the new release
   attest each other during the bootstrap. The release key in the GitHub
   `release` environment must therefore be the existing r21 release key; a new
   key would need a new Genesis delegation, which this design does not allow.
   The release workflow reads the r21 approval from
   `release/r21-release-approval.json` and refuses to build the bootstrap
   release without it ([Releasing](Releasing)).
4. r21 servers cannot adopt a newer approval at runtime and do not know the
   upgrade-turn traffic. The new release proposes no upgrade record until
   every Tier 1 member sends an upgrade status, so mixed r21 and new servers
   keep running consensus without upgrade records.

## Implementation status

| Part | State | Where |
|---|---|---|
| 0.1 Approval supersession | Implemented | `ReleaseChain`, `SecurityDriver::start` (`release_commitment`), `ReleaseApproval` format 3 |
| 0.2 Holder margin | Open; see the restart defect below | |
| 0.3 Fleet profile | Implemented; seeded from r21 | `release/fleet-profile.json`, `ReleaseApproval.cpp` (boot line verified against the approval only) |
| 1 Release workflow | Implemented, not run | `.github/workflows/release.yml`, `scripts/nexus-release-tool`, `scripts/nexus-release-sign`, [Releasing](Releasing) |
| Release guards | Implemented, not run | Previous approval required; rollout proof (`Security/Upgrade/RolloutProof.hpp`, `nexus-rollout-check`, `GET /api/upgrade/rollout-proof`); mixed-version job |
| 2 Approval chain and adoption | Implemented | `ReleaseChain`, `UpgradeService` (ApprovalOffer, status-driven exchange), `AttestationService::replace_profile` |
| 3 Mixed-version gate | Memory-mesh test in CI; multi-process job (wire checks only without SEV-SNP) | `tests/security/lifecycle/upgrade_path.cpp`, `scripts/mixed-version-mesh.sh`, `.github/workflows/mixed-version.yml`, [Wire Compatibility](Wire-Compatibility) |
| 4 Updater | Implemented and unit tested | `projects/LemonadeNexusUpdater/`, `packaging/systemd/nexus-updater.*` |
| 5 Upgrade turns | Implemented | `BlockPayloadKind::UpgradeProgress`, `Security/Upgrade/`, [Upgrade Control](Upgrade-Control) |
| OS updates and reboot | Implemented and unit tested; the package lock lists no packages yet | `release/os-packages.lock`, `Core/BootChainStaging` |

Decisions made during implementation:

- **Signed manifest.** The approval cannot carry the file-to-path mapping or
  the OS package lock. The release key also signs `manifest.json`, with the
  domain prefix `lemonade-nexus/release-manifest/v1\n`.
- **Updater language.** A C++ project, so it uses the server's own approval
  verification (`verify_release_approval_bundle`) and canonical encoding
  instead of a second implementation.
- **Provenance.** Offline verification of the Sigstore bundle published next
  to each asset, against a trusted root pinned in the package. No Sigstore
  service is contacted. Only Rekor v1 entries with an inclusion promise are
  accepted.
- **One control interface.** The server's root-only `upgrade.sock`
  (`Core/UpgradeControl.hpp`) carries `status`, `health`, `offer_approval`,
  `stage`, `turn`, `report`, and `stage_boot_chain`. The updater offers the
  approval before it asks for a turn; `stage_boot_chain` acts only on the
  approval the release chain accepted.
- **Boot line in the approval (Phase 0.3).** The kernel, IMA policy, SVSM
  launch measurements, and source identity come from
  `release/fleet-profile.json` into the signed approval. Servers verify them
  against the approval only; the approval is already signer-pinned and
  number-monotonic. The compiled floors that stay are the TCB minimum
  (AMD-SB-3030, AMD-SB-3034) and the protocol identity (wire and ruleset
  versions, attestation profile, attestd wire version): the ruleset pin is a
  Phase 0.1 rule, and the others name what the binary itself implements.
- **Rollout guard.** The release workflow verifies a rollout proof from Tier 1
  finalized state (the authority chain from Genesis, then every upgrade record
  under its commit proof) and refuses to publish unless the previous release's
  rollout is complete and not halted. A status file published by each updater
  was rejected: it is a self-report and needs a publishing credential on every
  server. The bootstrap release, which has no rollout records, is recorded as
  complete by a reviewed commit (`release/bootstrap-complete`).
- **PCR measurement.** A GitHub-hosted runner cannot boot the fleet guest. The
  PCRs come from the reviewed profile; an optional job on a reference-VM
  runner compares them (`scripts/nexus-measure-boot-chain`).

Details that the phases above leave open:

- **Approval format 3** adds `release_number` and `previous_release_paths`.
  `approved_paths` lists only this release's hashes; attestation accepts the
  union of both lists. `nexus-release-bundle` takes `release_number` in the
  spec and `--previous-approval <bundle.json>`.
- **Persistence.** The highest accepted number is in
  `<data_root>/security/release/release-chain.json`, re-verified at every
  start. It is not rollback-protected against a party that can write that
  directory; see Known limits.
- **Adoption traffic.** One security message kind, `Upgrade` (38), carries
  approval offers (at most 32 KiB, one per peer per 10 s), signed statuses,
  witness observations, record proofs, and record requests. Kind 37 is left
  to `StorageWrapClaim`.
- **Turn participants.** Current Tier 1 members and every other server with a
  live status that reports a configured attestation collector. Voters derive
  the set themselves; a Start record finalizes only when a quorum derived the
  same set. A server outside the order restarts after every participant is
  upgraded.
- **Liveness is a vote-time fact.** A Turn record needs a fresh signed Ready
  status from the subject and a live status from every other participant in
  each voter's view (60 s window). A finalized Turn counts its subject as down
  until Upgraded or Halt, so at most one participant is down by the protocol.
- **Witness quorum** is the eligibility rule (`witness_threshold`): the
  consensus quorum for a Tier 2 subject, one fewer (at least f + 1) for a
  Tier 1 subject, never counting the subject. Each observation binds the
  upgrade chain head, so it cannot be replayed at another position.
- **Data key.** The health report shows the data key state but the turn
  rule ignores it; a server can stay locked until enough holders run the new
  release.

Known limits found during the implementation:

- **HotStuff restart catch-up (fixed).** A restarted Tier 1 member that came
  back one block behind refused every later proposal for a missing parent and
  never asked for it. PR #80 fixed this: the member requests the parent from
  the proposer and replays the held proposal.
  `DriverMesh.SequentialRestartsKeepEveryMemberCommitting` covers sequential
  restarts.
- **Release record rollback.** A party that can write the security directory
  can replace or delete the release record. The accepted number cannot fall
  below the running release (the packaged, measured approval is folded in at
  every start), and a peer with a higher accepted release pushes its approval
  within one offer window, so the exposure is the window between the running
  release and a newer adopted one. Storing the number in the storage vault
  does not help: the vault does not detect a whole-file rollback and is locked
  when the driver starts. Sealing does not help either: a sealed blob is bound
  to PCR 8/9, not to a counter. A real fix needs a TPM monotonic counter
  (nexus-attestd has no NV operation) or a start-time check against finalized
  state.
- **A halted rollout blocks the release workflow.** A fix for it would need
  the hashes of two earlier releases, and an approval lists one.
- **Bootstrap baseline.** The first gated release is the bootstrap release;
  its baseline is the r21 line, not a GitHub release. The `vX.Y.Z-alpha`
  releases use security wire version 1 and are not a baseline
  ([Wire Compatibility](Wire-Compatibility), Baseline).
- **A participant that never becomes Ready blocks the rollout** until a newer
  release replaces it. A participant that leaves the mesh does the same.

## Tier 2 and the tree

Tier 2 servers are pure proxies of data and connections that are already
encrypted end to end. They have no tree role: they do not read, write,
redirect, or forward tree requests, and they do not terminate or vouch for a
client session. Tier 2 servers do not store, replicate, or serve the tree at all; the Phase 3
replication to Tier 2 is removed. A server that leaves Tier 1 deletes its tree
copy after its last epoch ends. Clients send every
tree read and write directly to a Tier 1 server. The SDK selects Tier 1 servers
from the finalized epoch membership and verifies that list; it never asks a
Tier 2 server for tree data.

## Tests

- Approval: a forged signature, a wrong network, an equal or lower release
  number, a hash not in the approval, a replayed old approval after restart.
- Provenance: a wrong repository, a wrong workflow, a wrong ref, a missing
  attestation.
- Rollout: two servers trying to restart at once, a server down when a turn
  starts, a health-gate timeout and rollback, a halt after "failed", a restart
  of the updater mid-swap.
- Mixed version: the CI gate in Phase 3.
- In place: the epoch, membership, storage share, data key, and tree log are
  identical before and after an update.

## Risks

- **Release key in GitHub.** Anyone who can push to `main` or run the workflow
  can ship to the mesh. Branch protection and dispatch limits are the control.
- **Boot-chain updates.** A kernel or GRUB update changes PCR 8/9. That breaks
  attestation and the sealed boot set. Disable unattended kernel upgrades on
  the fleet; a boot-chain change needs its own staged approval (Phase 6 of the
  storage design covers re-seal).
- **System library updates.** The approval pins system library hashes. An OS
  package update that changes them fails attestation. Pin those packages or
  ship the libraries with the release.
- **Holder margin.** At 5 holders a crash during a rollout means two down and
  no unlock. More holders (7 at 10 admitted servers) is the real fix.
