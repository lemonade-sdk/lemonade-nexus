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
   is adopted. After a halted rollout of N+1, servers run N+1 or N, so the
   fix lists the hashes of both (release guard, below).
4. **Persistence.** The highest accepted release number survives restart.
   It is stored with the security state, not in a config file. Finalized
   consensus state anchors it against rollback (Known limits, Release record
   rollback).

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

Owner decision (2026-10-24): r21 is not a baseline. The first date-tagged
release is the bootstrap release. Every server installs it once by hand, and
the network is founded fresh on it. There is no storage state yet, so a fresh
founding is safe at this point, and only at this point. Every release after
that uses Phases 1-5 and installs in place.

1. The release workflow detects the bootstrap release: no earlier date tag or
   date-tagged release exists, and `release/bootstrap-complete` does not
   exist. There is no manual switch. The bootstrap approval has no
   `previous_release_paths`, the rollout guard and the mixed-version gate do
   not run, and no r21 input is read.
2. The founding uses the Genesis key behind `network_id` in
   `release/fleet-profile.json`, because the approval names that network. The
   founding certificate commits the bootstrap approval, and the release chain
   pins its signer at first start.
   The founding-approval migration file (`kFoundingApprovalFile`) is not part
   of this procedure.
3. After every server runs the bootstrap release, a reviewed commit names its
   tag in `release/bootstrap-complete`. The next release refuses to publish
   until it does, because the bootstrap release has no rollout records to
   prove.

The operator steps are in [Releasing](Releasing), Bootstrap procedure.

## Implementation status

| Part | State | Where |
|---|---|---|
| 0.1 Approval supersession | Implemented | `ReleaseChain`, `SecurityDriver::start` (`release_commitment`), `ReleaseApproval` format 3 |
| 0.2 Holder margin | Open; see the restart defect below | |
| 0.3 Fleet profile | Implemented; seeded from r21 | `release/fleet-profile.json`, `ReleaseApproval.cpp` (boot line verified against the approval only) |
| 1 Release workflow | Implemented, not run | `.github/workflows/release.yml`, `scripts/nexus-release-tool`, `scripts/nexus-release-sign`, [Releasing](Releasing) |
| Release guards | Implemented, not run | Previous approval required; rollout proof (`Security/Upgrade/RolloutProof.hpp`, `nexus-rollout-check`, `GET /api/upgrade/rollout-proof`); fix after a halt (`release_follows_rollout`, `nexus-release-bundle --previous-halted`); mixed-version job; bootstrap detection (`nexus-release-tool previous`) |
| Release floor | Implemented, memory-mesh tested | `ReleaseChain::raise_floor`, `UpgradeService` (finalized Start records) |
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
  under its commit proof). It publishes only when the previous release's
  rollout is complete, or halted with a fix that covers both releases: after
  a halt, the Upgraded records show which servers run the halted release, and
  every other server runs the release before it. The published previous
  approval must have the digest that the finalized Start record names, and
  `nexus-rollout-check --approval` (`release_follows_rollout`) refuses a new
  approval whose `previous_release_paths` are not exactly the required set:
  the previous release after completion, the halted release and the release
  before it after a halt. A status file published by each updater
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
  start. The finalized network floor protects it against rollback; see Known
  limits, Release record rollback.
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
  can replace or delete the release record. Finalized consensus state is the
  anchor (`ReleaseChain::raise_floor`). A rollout starts with a finalized
  Start record, and a Tier 1 quorum votes for it only when each voter accepted
  its exact approval, so the newest finalized Start release is a network
  floor. Every server raises its floor from the upgrade records it holds at
  start and from each finalized Start it learns: Tier 1 by commit, Tier 2 by
  verified record proofs from Tier 1. Below the floor, the release chain holds
  no usable approval: the server attests no peer and votes for no upgrade
  record until a peer hands it the newer approval. The floor has no file of
  its own; it is rebuilt from finalized state at every start. Remaining
  exposure: before a rollout starts, the floor lags the newest adopted
  approval, and the accepted number stays at or above the running release
  (the packaged approval is folded in at every start). A server whose upgrade
  records were deleted too learns the floor from Tier 1 within one record-sync
  interval. The storage vault and sealing were rejected as anchors: the vault
  does not detect a whole-file rollback and is locked when the driver starts,
  and a sealed blob is bound to PCR 8/9, not to a counter. nexus-attestd has
  no TPM NV counter operation.
- **A fix after a halt covers two releases.** Consecutive halts grow the
  overlap by one release each until a rollout completes. The approval holds
  one PCR 8/9 pair, so a halt of a release that changed the boot chain needs
  a reviewed decision about the boot chain of the fix.
- **Bootstrap baseline.** The bootstrap release has no baseline: every server
  installs it by hand on a fresh founding (Phase 6). The `vX.Y.Z-alpha`
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
  package update that changes them fails attestation. The server and
  `nexus-attestd` link OpenSSL (the snapshot-pinned Ubuntu static libraries,
  which need no zlib or zstd), libstdc++, and libgcc statically, so those
  fixes ship in a Nexus release. Only glibc stays
  shared; `release/os-packages.lock` pins `libc6`, and a `libc6` change ships
  with new `system_libraries` hashes ([Releasing](Releasing)).
- **Holder margin.** At 5 holders a crash during a rollout means two down and
  no unlock. More holders (7 at 10 admitted servers) is the real fix.
