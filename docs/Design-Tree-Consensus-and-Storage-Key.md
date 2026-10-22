---
layout: default
title: "Design: Tree Consensus and Threshold Storage Key"
---

# Design: Tree Consensus and Threshold Storage Key

Status: **approved**. Phase 1 is implemented behind the experimental
`tree_ops_enabled` setting and applies tree operations locally only. See
[Configuration](Configuration#experimental-tree-operations) for its behavior
and limits. The design changes the trust model, so `AGENTS.md` requires review
of each later phase and its migration plan before code.

## Table of Contents
- [Summary](#summary)
- [Decisions Already Made](#decisions-already-made)
- [Current State](#current-state)
- [Part A: Tree Changes Through Consensus](#part-a-tree-changes-through-consensus)
- [Part B: Threshold Storage Key](#part-b-threshold-storage-key)
- [Part C: Key-Generation Race Fix](#part-c-key-generation-race-fix)
- [Phases](#phases)
- [Tests Required](#tests-required)
- [Open Decisions](#open-decisions)

## Summary

Two problems, one plan:

1. **Servers do not stay in sync.** Each server applies only the tree changes
   it receives directly. Two admins who edit through two servers produce two
   different trees. Part A sends every tree change through the Tier 1
   HotStuff consensus, so every server applies the same changes in the same
   order.
2. **A copied disk exposes the server's secrets.** Private keys, the session
   secret, TLS keys, and the whole tree are on disk in plaintext, or
   encrypted with a key stored beside them. Part B encrypts each server's
   files with a data key that only 65% of the attested servers together can
   unlock. The storage secret is never assembled in one place.

FROST, the epoch signing key, does not change.

## Decisions Already Made

| Decision | Value |
|---|---|
| Storage key threshold | 65% of holders, rounded up |
| Holders | Every server that passes SEV-SNP attestation, at most 50 |
| Re-share | Every epoch (share refresh), and right away when a holder is lost or added |
| Key rotation | Storage secret daily (rewraps data keys); each server's data key monthly and after a suspected compromise (re-encrypts files) |
| Recovery | No offline recovery key. Re-sharing restores full tolerance while at least the threshold stays online. |
| Tree versions | Nodes hold their versions. The existing sync library (`nexus::sync`) replicates committed changes; consensus orders them. |
| Saving a change | The API waits up to 10 s for the commit, then reports the change as pending |
| Re-share authority | Needs 65% of the current holders, not only a consensus quorum |
| FROST and consensus | Unchanged in role, threshold, and storage |
| Endpoint tiers | Tier 3 = inference node, Tier 4 = client (see [Security](Security#server-roles)) |

| Holders | Needed (65%) | Can be offline |
|---|---|---|
| 5 | 4 | 1 |
| 7 | 5 | 2 |
| 10 | 7 | 3 |
| 20 | 13 | 7 |
| 31 | 21 | 10 |
| 50 (cap) | 33 | 17 |

## Current State

Facts from the code at `37c359e` (r18):

- **Consensus carries no application data.** A `Proposal` holds only state
  roots, a 32-byte `transitions_digest`, and a time hint
  (`ConsensusTypes.hpp:21-44`). Replicas vote only when they derived the same
  digest themselves (`SecurityDriver.cpp:1691-1704`). Consensus orders only
  the four epoch-boundary stages.
- **No committed log.** `hotstuff-commit-<epoch>.json` keeps only the latest
  commit; blocks live in memory (`ConsensusStore.cpp:96-104`). A restarted
  replica fetches at most 8 uncommitted blocks (`kMaxSyncChainBlocks`).
  Activation resets consensus and drops uncommitted blocks
  (`SecurityRuntime.cpp:154`).
- **Tree changes apply locally only.** `TreeApiHandler` calls
  `apply_delta`, `insert_join_node`, `update_node_direct`, `grant_assignment`,
  `set_assignment`, and `delete_node_direct` directly. Gossip keeps received
  tree records in a transfer pool and never applies them
  (`GossipService.cpp:862-951`).
- **Tree validation is not deterministic.** `do_apply_delta` checks freshness
  against each server's wall clock (300 s past, 60 s future) and replay
  against a steady-clock cache (`PermissionTreeService.cpp:669-717`). Two
  servers can disagree on the same delta.
- **The key-generation code cannot make a storage key.** `DkgSession` emits
  only a FROST Ed25519 group whose share never leaves the FFI. It has no
  re-sharing, and its participant count is 5 to 31 with a threshold of about
  67% (`DkgSession.cpp:77,90`).
- **No vTPM sealing exists**, and the server process cannot reach the TPM
  (`PrivateDevices=yes`). Only `nexus-attestd` holds `/dev/tpmrm0`.
- **Secrets on disk:**

  | File | Protection today |
  |---|---|
  | `identity/keypair.json` (gossip identity; Genesis on the root) | Plaintext, mode 644 |
  | `identity/keypair.enc` (node identity; root management key on the root) | AEAD under `wrap_local.key` + `/etc/machine-id`, empty passphrase |
  | `identity/wrap_local.key` | Plaintext, 600 |
  | `security/vote-key-*.json` | AEAD, same machine binding |
  | `identity/jwt_secret.hex` | Plaintext, 600 |
  | `certs/*/privkey.pem`, `certs/account.key` | Plaintext, 600 |
  | ACL rows, DDNS credentials | AEAD under a key derived from `keypair.json` |
  | `tree/nodes`, `tree/deltas` | Plaintext |

## Part A: Tree Changes Through Consensus

### A1. Tree operation

Every change to the tree becomes one **tree operation**:

```text
TreeOp {
  version        1
  network_id     binds the op to this network
  op_id          SHA-256 of the canonical encoding without signatures
  kind           create_node | update_fields | set_assignment | delete_node | join
  target         node id
  base_version   the target node's version the author saw
  body           kind-specific fields
  author         Ed25519 key of the signer
  signature      over the canonical encoding
  submitted_by   server that received it (for routing only, unsigned)
}
```

- Every tree node gains a `version` counter. Each applied op increments it.
- `base_version` makes concurrent edits deterministic. An op whose
  `base_version` no longer matches is rejected; the client reloads and
  retries.
- `set_assignment` replaces one principal's entry. Two admins changing
  different principals on the same node conflict under this rule; a later
  revision can relax it to per-principal versions (see
  [Open Decisions](#open-decisions)).
- **Joins** are ops too. The device signs a join statement over the server's
  challenge. The receiving server wraps it in a `join` op signed by its own
  server key. Every replica verifies both signatures and re-derives the node
  id, tunnel address, and endpoint identifier deterministically. Address
  allocation therefore moves into the op's deterministic apply step.
- Every write path in `TreeApiHandler` produces an op. The local-only methods
  (`insert_join_node`, `update_node_direct`, `grant_assignment`,
  `delete_node_direct`) stop being called from request handlers.

### A2. Submission

1. The API server validates the op statically (format, signature, size) and
   sends it over the backbone to the Tier 1 servers. A Tier 2 server forwards
   to Tier 1 the same way.
2. Each Tier 1 server keeps a bounded pending pool, keyed by `op_id`, with
   per-author limits.
3. The API answers when the op commits or is refused, waiting up to 10 s.
   After that it returns `202` with the `op_id`, the app shows the change as
   pending, and polls until it commits.

### A3. Consensus payload

- A new `TreeBlock` carries an ordered batch of ops. `Proposal` gains
  `ops_digest`, the hash of the batch. The proposal message carries the batch
  itself.
- Size: the security envelope limit is 60,000 bytes. A batch is capped at
  48,000 bytes and `kMaxTransitionsPerBlock` (128) ops. Larger backlogs use
  more blocks. The unused 256 KiB constant is removed or aligned.
- The leader fills a block from its pending pool. Empty blocks stay empty, as
  today.
- Epoch-boundary stages keep priority. A block carries either a stage digest
  or a tree batch, never both, so the stage logic is unchanged.

### A4. Deterministic validation

A replica votes for a tree block only if every op validates against the tree
state of the block's parent (committed state plus the uncommitted ancestors).
The checks are the current rules with the non-deterministic inputs removed:

- signature, network binding, and size;
- operation permission and the content rules of `delta_content_refusal_locked`
  and `set_assignment` (admin anchor, joined identities, no self-change of an
  admin's anchor entry, identity fields unchanged);
- `base_version` matches;
- `op_id` not already committed (replay is checked against the committed log,
  not a clock);
- **freshness uses block time.** `Proposal.timestamp_hint` becomes binding: it
  must exceed the parent's and stay within 60 s of each replica's clock, or
  the replica withholds its vote. An op is fresh if its signed time is within
  300 s of the block time.

### A5. State root

`proposed_state_root` becomes a commitment to the tree, not only a hash
chain: `H(parent_root ‖ ops_digest ‖ tree_digest_after)`, where
`tree_digest_after` is a deterministic digest of every node's canonical
encoding and version. Replicas recompute it and vote only on a match.

### A6. Commit, apply, and the tree log

- `SecurityDriver::on_commits` passes committed tree blocks to a new
  `TreeLog`. It appends each block durably as `tree/log/<height>.json` with
  its commit QC, then applies the ops to `PermissionTreeService` in order.
- The tree log height is independent of consensus views and continues across
  epochs. Activation still resets consensus; ops pending at that moment are
  resubmitted to the new epoch's pool.
- Snapshots every 1,000 heights bound replay time. A snapshot is the tree's
  canonical encoding plus its digest, cross-checked against the state root.
- The gossip transfer pool for tree records is retired once all servers run
  the tree log.

### A7. Tier 2 and lagging servers

- Replication reuses the existing sync library (`nexus::sync`, already used
  for DNS and account envelopes): a new `"tree"` stream whose entries are
  committed log blocks keyed by height, with the same digest and catch-up
  exchange over the backbone. Consensus fixes the order; the sync library
  only carries it, so last-writer-wins never decides a permission change.
- A receiving server verifies each block's QC against the epoch's vote keys
  and follows the authority chain across epochs. It applies only verified
  entries, in height order.
- Tier 2 servers never vote. They apply the same verified log, so they serve
  the same tree.
- A server that cannot verify an entry stops applying and keeps serving the
  last verified state. It never applies unverified data.

### A8. Effect on clients

- Peer lists, permissions, and the tree become identical on every server.
- A later step can give clients proof: a server returns a node with the QC
  that committed it, so an app can reject a peer entry a compromised server
  invented. This closes the "lying server" case and is listed as a follow-up.

### A9. Migration of existing trees

Today each server's tree differs.

1. Release N adds the tree log in read-only mode: servers build and replicate
   it but keep applying changes locally.
2. A one-time ceremony exports every server's tree. A merge tool unions them:
   the root from the root server, each group from its creator's record, each
   device from the server it joined. Conflicts are listed for an admin to
   resolve.
3. The merged tree is committed as **height 1**, signed by the root
   management key offline, and verified by every server.
4. Release N+1 switches every write path to ops. Local-only writes end.

## Part B: Threshold Storage Key

### B1. Keys and roles

| Key | Where it lives | Purpose |
|---|---|---|
| Storage secret `s` | Never assembled. Holder *i* keeps share `s_i`. | Threshold decryption only |
| Storage public key `S = s·G` | Public, recorded in the holder plan | Wrapping data keys |
| Server data key (DEK) | Wrapped on that server's disk; unwrapped in memory | Encrypts that server's files |
| Boot set (gossip identity key, own share) | Sealed by the vTPM (B6) | Starting up and authenticating before unlock |

The storage key is a separate key role with its own domain-separation tag
(`LEMONADE-NEXUS-STORAGE-V1`). It never signs and never authorizes. FROST,
vote keys, and the epoch chain are untouched.

### B2. Why threshold decryption, not rebuilding the key

Rebuilding `s` on every restarting server would give each one the whole
network's storage secret. One compromised running server would then expose
every server's files. Instead:

- Each server's DEK is wrapped to `S` with ECIES: a random `r`, the stored
  point `R = r·G`, and the DEK encrypted under `KDF(r·S)`.
- To unlock, the server sends `R` to the holders. Each holder returns
  `s_i·R` with a Chaum-Pedersen (DLEQ) proof that it used the same `s_i` as
  its public share commitment.
- The server verifies each proof, combines 65% of the partials with Lagrange
  coefficients into `s·R = r·S`, derives the wrap key, and unwraps its DEK in
  memory.
- A holder learns nothing about the DEK. A server learns only its own DEK.
  `s` exists nowhere.

### B3. Library

No custom cryptography (`AGENTS.md`). A new Rust crate, `storage-threshold`,
wraps these libraries behind a C ABI like `frost-ffi`; panics never cross it.

| Need | Library | Audit |
|---|---|---|
| Dealerless key generation over Ristretto255 | `frost-ristretto255` with the `internals` feature, pinned to the same version as `frost-ed25519` (2.2.0) | NCC Group, 2023-10-23 (v0.6.0) |
| Share refresh with the same holder set and threshold; removing holders | `frost-ristretto255` `refresh_dkg_*` | Not audited |
| Enrolling a new holder at the same threshold | `frost-ristretto255` `repair_share_*` | Not audited |
| Lagrange combination of partials | `frost-ristretto255` helpers | Audited with key generation |
| DLEQ (Chaum-Pedersen) proof for each partial | `elastic-elgamal` 0.3.1 `LogEqualityProof` | Not audited |

Both libraries use `curve25519-dalek` 4.1.3, so the lockfile stays on one
curve implementation. Written in this repository: the C ABI wrapper, the
partial and proof wrapper (about 60 lines), the combiner (about 30 lines),
and key derivation and encryption in C++ with the existing primitives. The
unaudited library paths get an external review before Phase 5 ships.

No audited library changes the threshold while keeping `S`. B5 therefore
rotates the key when the threshold must change.

### B4. Holder set

- **Eligible:** every admitted server with a passing eligibility attestation
  in the current epoch (Tier 1 and Tier 2 alike).
- **Selected:** if more than 50 are eligible, the first 50 by
  `H(checkpoint_seed ‖ node_id)`, using the finalized checkpoint as the seed,
  like leader selection. No server chooses its own rank.
- **Recorded:** Tier 1 finalizes a `StorageHolderPlan` through consensus with
  the next-epoch plan: the holder list, the threshold, `S`, and each holder's
  public share commitment.
- **Threshold:** `t = ceil(0.65 × n)`, with at least 5 holders before the
  storage key is created.

### B5. Re-sharing

- When a holder is lost (its attestation lapses or it stays unreachable past
  a timeout) or a new holder is added, Tier 1 finalizes an updated
  `StorageHolderPlan` right away, without waiting for the epoch boundary.
  Prompt action restores full tolerance after each loss: at 5 holders, one
  loss is survivable, and after the change the next loss is survivable again
  once the set is back to strength.
- **If the threshold stays the same** (65% of the new holder count rounds to
  the same `t`), the holders refresh their shares for the new set and keep
  `S`: removed holders drop out of the refresh, and a new holder is enrolled
  through share repair. No file and no data key changes.
- **If the threshold changes,** the holders run a key rotation (B5a) instead:
  a fresh key generation among the new set at the new threshold, a new `S`,
  and each server rewraps its data key. Files are not touched. This is the
  same operation as the daily rotation, started early.
- A re-share needs at least `t_old` old holders to contribute. The
  consensus quorum (about 67% of Tier 1) alone cannot move the key to new
  holders; honest holders contribute only to a finalized plan whose new
  holders all hold a fresh attestation.
- Removed holders' old shares stop combining with the new ones.
- Even when the holder set is unchanged, the holders refresh their shares
  every epoch. A share copied before a refresh does not combine with shares
  after it, so an attacker must collect 65% of the shares within one epoch.

### B5a. Key rotation

| Key | Rotates | What it costs |
|---|---|---|
| FROST epoch signing key | Every epoch (existing: each epoch runs a fresh DKG) | Nothing new |
| Storage shares `s_i` | Every epoch (B5), same `S` | One re-share: about 5,000 small messages at 50 holders |
| Storage secret `s` (new `S`) | Daily, and on demand | A fresh key generation among the holders. Each server rewraps its DEK to the new `S` through one threshold unlock. Files are not touched. |
| Server data key (DEK) | Monthly, and on demand after a suspected compromise | The server re-encrypts its files under a new DEK in the background, then deletes the old ciphertext |

- Rotation of `s` is finalized through consensus like a holder plan: a
  `StorageKeyRotation` names the new `S`, its share commitments, and the
  epoch it takes effect. The old `S` stays valid for unwrapping until every
  server has rewrapped, with a bounded grace period (proposed: one epoch).
- A server that misses a rotation unwraps with the old `S` during the grace
  period, or rewraps through the holders of the new `S` afterwards.
- Every rotation is logged with its epoch, so an operator can see when each
  key last changed.

### B6. Sealing the boot set

A server must authenticate and hold its own share before it can unlock
anything, so these two items cannot depend on the DEK:

- `nexus-attestd` gains `Seal` and `Unseal` operations. It seals a blob to the
  SVSM vTPM under a policy bound to the approved release's PCRs and returns
  the sealed blob to the server, which stores it. `nexus-attestd` still never
  reads the server's data directory.
- The gossip identity key and the server's storage share are stored sealed.
- **Before B6 ships,** the boot set keeps today's machine-bound wrapping, and
  `keypair.json` moves to mode 600 and the same wrapping. This is a documented
  limit, not the target.

### B7. Unlock at startup

1. The server unseals its boot set.
2. It requests partials from the holders with a new security message,
   `StorageUnlockRequest {network, epoch, R, nonce}`.
3. Each holder challenges the requester with a new attestation purpose,
   `StorageUnlock`, bound to the request nonce. Holders that are not Tier 1
   may challenge for this purpose only; the router's `NotMember` gate changes
   accordingly.
4. On a passing verdict for the approved profile, the holder answers with
   `StorageUnlockPartial {s_i·R, DLEQ proof}`, sealed to the requester with
   the request digest as associated data.
5. With `t` valid partials the server unwraps its DEK and opens its files in
   memory. With fewer it retries with backoff and serves nothing that needs
   its files.

Budgets: one pending unlock per requester per holder, and a per-epoch limit,
like attestation budgets.

### B8. Cold start

- Holders' shares are sealed by the vTPM, not by the DEK, so holders can
  answer before they unlock their own files.
- After a full outage, the network unlocks once `t` holders are up and
  attested. Below `t`, no server unlocks. That is the cost of the threshold.
- There is no offline recovery key. Prompt re-sharing (B5) keeps the holder
  set healthy; the key is lost only if more holders than the tolerance drop
  at the same time, before a re-share runs.

### B9. What the DEK encrypts

Everything in the table under [Current State](#current-state) except the boot
set: the node identity key, vote keys, JWT secret, TLS and ACME keys, ACL and
DDNS keys (derived from the DEK instead of the gossip key), the tree log and
snapshots, and account data. `wrap_local.key` is retired.

### B10. Migration

1. A release creates `S` once at least 5 holders are attested, through a
   dealerless key generation among them.
2. Each server creates a DEK, wraps it to `S`, re-encrypts its files, verifies
   that it can unlock through the holders, and only then deletes the
   plaintext.
3. A server that cannot reach `t` holders keeps its old files and retries.

## Part C: Key-Generation Race Fix

The first r17 founding split because round-2 messages that arrive before round
1 completes are dropped (`DkgSession.cpp:224-226`, `SecurityRouter.cpp:590-601`).
Only the founding path re-sends; epoch-transition and adoption runs send round 1
once, so a dropped message stalls until the 300 s timeout.

- Buffer round-2 messages that arrive early, bounded to one per sender per
  session, and replay them when round 1 completes.
- Re-send round 1 and cached round 2 on every DKG path, not only founding.
- The storage key generation (B10) and re-share (B5) use the same pattern.

This part does not change the trust model and can ship first.

## Phases

| Phase | Content | Depends on |
|---|---|---|
| 0 | Part C race fix. `keypair.json` mode 600. | — |
| 1 | `TreeOp`, node versions, deterministic validation, all write paths produce ops (applied locally, behind a flag). | — |
| 2 | Tree batches in consensus, `TreeLog`, commit-then-apply on Tier 1. | 1 |
| 3 | Log replication to Tier 2 and lagging servers with QC verification. Tree merge ceremony and switch-over (A9). | 2 |
| 4 | `storage-threshold` crate: library review, key generation, re-share, share refresh, DLEQ, threshold ECIES. | — |
| 5 | `StorageHolderPlan` in consensus, unlock protocol, `StorageUnlock` attestation purpose, per-epoch share refresh, daily `StorageKeyRotation`. | 2, 4 |
| 6 | `nexus-attestd` Seal and Unseal; boot set sealed. | — |
| 7 | DEK file migration; plaintext removed; monthly DEK rotation. | 5, 6 |

Phases 1, 4, and 6 can run in parallel.

## Tests Required

Each phase adds tests for the valid path and these rejection cases:

- **Tree ops:** replayed `op_id`, stale `base_version`, wrong network, bad
  signature, author without permission, an admin changing its own anchor
  entry, an unjoined principal, oversize batch, a block whose state root does
  not match, a block time behind its parent or too far ahead.
- **Tree log:** restart and replay, catch-up across an epoch change, an entry
  with a forged or wrong-epoch QC, two servers applying the same log reaching
  the same digest.
- **Storage key:** fewer than `t` partials, a partial with an invalid DLEQ
  proof, a partial for a different `R`, a requester without a passing
  attestation, a replayed unlock request, a re-share contributed by fewer
  than `t_old` holders, a removed holder's share after re-share, a share from
  before a refresh combined with shares after it, unlock with the old `S`
  after its grace period, a server that missed a rotation catching up, an
  interrupted DEK rotation resuming without data loss, cold start with
  exactly `t` and with `t − 1` holders.
- **Race fix:** round 2 arriving before round 1 on every DKG path completes
  without a stall.

## Open Decisions

1. **Genesis and root management keys** stay on the root server for now.
   Revisit before Phase 7.

Decided: libraries for `storage-threshold` (B3), with an external review of
the unaudited paths before Phase 5; a threshold change rotates the key
instead of re-sharing to a new threshold (B5); no offline recovery key (B8); nodes hold per-node versions and the
sync library replicates (A7); the API waits up to 10 s, then reports pending
(A2).
