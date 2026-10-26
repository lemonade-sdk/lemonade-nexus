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
   N-1 stops passing attestation once a server adopts N+1. After a halted
   rollout of N+1, servers run N+1 or N, so the fix lists the hashes of both.

## Baseline

The rule starts with the bootstrap release, the first date-tagged release
(Design-Auto-Update Phase 6). The bootstrap release itself has no baseline:
every server installs it by hand and the network is founded fresh on it, so
no earlier release runs beside it. The release after it is the first one
that must interoperate with a previous release.

The `vX.Y.Z-alpha` GitHub releases are not a baseline. `v0.9.7-alpha` sends
security wire version 1. A current server refuses every such envelope at the
version byte (`decode_security_message` returns `BadVersion`), and its
message layouts also differ (attestation challenge and evidence fields, the
bootstrap certificate). A mixed-version run against that release therefore
reports dropped messages from every old node. The router records these drops
as `WireVersionMismatch` (14), not `Malformed`, and the gate script reports
the old binary as an invalid baseline.

## Additions in this line

- **Sync paging.** `SyncRequest` has an optional trailing `after_height`
  (u64). A request without it keeps the earlier layout, so every release
  decodes a restart sync request. A release from before this field refuses a
  paged request as trailing bytes. A replica that is far behind then cannot
  page from that peer; it asks the next leader whose proposal it cannot link.
  Nothing else depends on paging.
- **Stored consensus blocks.** A Tier 1 server now writes
  `security/consensus/hotstuff-chain-<epoch>.json` before each vote: the
  headers and certificates of the uncommitted blocks below its high
  certificate. An earlier release stored the high certificate but not the
  block it names, so when every member restarted at once, no member held that
  block and no leader could propose again. The new file is outside the
  storage vault: consensus starts before the data key unlocks. It holds no
  block payload, so a batch in an uncommitted block is lost on every member
  alike in a full restart, and its ops must be submitted again.
  - N+1 loads the safety and commit files of N in place. N ignores the new
    file, so a rollback also loads.
  - A member that restarts on N+1 without the file takes the blocks from its
    running peers through restart sync and writes the file with its next
    vote.
  - Install order: update the Tier 1 members one at a time, and let each one
    rejoin and vote before the next one stops (the normal rollout order). Do
    not restart the whole committee together until every member ran N+1 and
    voted once. If all members restart together on state from N, no member
    holds the block. Consensus for that epoch then stays halted: no leader
    can propose, every member keeps its safety state, and no vote is unsafe.
    There is no override.
- **Link token replication.** Gossip type `LinkTokenSync` (0x1B) and the
  catch-up stream `link` are new. A release from before them drops a
  `LinkTokenSync` datagram on the backbone as an unknown type, and ignores a
  `link` digest page or catch-up request as an unknown stream, so it neither
  stores nor answers link token events. Nothing an earlier release sends
  changes. During a rollout a token minted on an earlier release is redeemed
  only on that server (as before), and a token minted on N+1 is redeemed on
  any N+1 Tier 1 server. N+1 still reads the plaintext per-token files
  (`link_tokens/<sha256>.json`) an earlier release wrote. The new files
  (`link_tokens/ledger.json`, `link_replica/replica.json`) are storage-vault
  files; an earlier release does not read them.
- **Tree op link extension.** A `Join` with a link token and an
  `AcceptInvite` from N+1 append a link extension to the canonical op
  encoding. An op without it encodes exactly as before, and N+1
  applies such an op with the earlier rules, so ops from N stay valid and give
  the same tree on N and N+1. A release from before the extension refuses an
  op that carries it (trailing bytes), so it cannot vote for a block with
  one. Upgrade every Tier 1 server before clients redeem invites.

## Tree operations always on

The release that removed `tree_ops_enabled` and `tree_log_enabled` runs tree
operations on every server. During its rolling update, old and new releases
run side by side:

- A new server that holds a tree from an earlier release awaits the one-time
  merge commit ([Tree Merge Ceremony](Tree-Merge-Ceremony)). It serves its
  tree for reads, answers tree writes with `503` and `Retry-After`, proposes
  no tree block, and votes for none. An old server keeps its direct writes
  until it is updated; those writes are in its tree when the merge collects
  the exports.
- No tree block can commit before the merge: it needs the votes of a quorum
  of Tier 1, and an awaiting server gives none. An old release registers no
  tree payload handler, so it withholds its vote from every block that
  carries a tree batch.
- The record transfer messages of the old release (`Digest`, `DeltaRequest`,
  `DeltaResponse`) are dropped by the new release, which never applies them.
- The merge runs only after every server runs the new release: an old server
  has no `POST /api/tree/merge/export` route, and the merge refuses to build
  without an export from every current Tier 1 member.

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
  date-tagged release; the bootstrap release has no previous release and
  skips the gate. On a host without SEV-SNP the run proves wire
  compatibility only: both binaries decode each other's traffic, and the mesh
  refuses to found on unproven hardware. Founding, epoch transition, storage
  unlock, and cross attestation across binaries need an SEV-SNP host; the
  script runs those checks when `NEXUS_MIXED_HARDWARE=snp` is set on such a
  host. A run without that hardware is not evidence for them.
