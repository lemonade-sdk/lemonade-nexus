---
layout: default
title: "Design: Tree Consensus and Threshold Storage Key"
---

# Design: Tree Consensus and Threshold Storage Key

Status: **approved**. Phases 1 to 3 are implemented and always run (no
setting turns them off): Tier 1 servers order tree operations through
consensus and apply them only after commit, and a Tier 1 member that joins or
lags applies the replicated log. A server that holds a tree from before tree
operations awaits the one-time merge commit. Tier 2 servers hold no tree
(decided 2026-10-24; see [A7](#a7-tier-2-and-lagging-servers)). See
[Configuration](Configuration#tree-operations) for the behavior
and limits, and [Tree Merge Ceremony](Tree-Merge-Ceremony) for the
migration runbook. Phase 4, the `storage-threshold` library
(`crates/storage-threshold`), is implemented and tested. Phase 5 (holder
plans and key rotations in consensus, the unlock protocol, the `StorageUnlock`
attestation purpose, per-epoch share refresh, and daily rotation) is
implemented and always on, with no setting to turn it off; see
[B11](#b11-phase-5-implementation) and
[Configuration](Configuration#threshold-storage-key). The external review of
the unaudited library paths in [B3](#b3-library) was not commissioned: that
gate was waived on 2026-10-22, not satisfied. Phase 6 is implemented:
`nexus-attestd` seals and unseals, and the gossip identity key moves to a
sealed copy through a one-way migration (see [B6](#b6-sealing-the-boot-set)
for the binding, the migration, the upgrade path, and the limits). Phase 7 is
implemented and always on (see
[B12](#b12-phase-7-implementation)); it had the same review gate, also
waived. The design
changes the trust model, so `AGENTS.md` requires review of each later phase
and its migration plan before code.

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
   HotStuff consensus, so every Tier 1 server applies the same changes in
   the same order. Tier 2 servers hold no tree (A7).
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
  replica fetches at most 8 uncommitted blocks (`kMaxSyncChainBlocks`). A
  running replica that fell further behind fetches the committed chain from a
  peer in pages of 8 blocks (`SyncRequest::after_height`); a peer serves only
  blocks it holds, so a page starts no lower than that peer's restart anchor.
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
                 | establish_root | set_endpoint | accept_invite | move_node
                 | delete_account
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
- `accept_invite` (kind 8) makes a session-authenticated identity a member
  of a group. The submitter consumed the link token; every replica checks the
  inviter's current authority and the permission bounds
  (`rules::invite_acceptance_refusal`). `move_node` (kind 9) moves a device or
  subgroup under another group (`rules::move_refusal`). Both are appended
  values; no existing kind is renumbered. See [Security](Security) for the
  rules.
- A `join` with a link token and an `accept_invite` carry a link extension,
  appended to the canonical encoding only when present (tag
  `lemonade-nexus/tree-op-link-extension:v1`), so an op without it keeps the
  encoding and op id of earlier releases. The extension holds the invite's
  signed mint (`invite_grant`). Every replica verifies the grant (a trusted
  submitter of the block's epoch signed it, for this network, unexpired at
  the block time, bound to the op) and records its redemption id in the
  committed id set until the invite expires, so a second redemption on any
  server is refused as `Replayed`. A linked `join` with the extension gives
  same-group sibling devices `read` and `connect_private` on the new device
  even when the sibling's key already holds an entry there
  (`rules::grant_link_peer_access`); a `join` without it keeps the earlier
  result. See [Security](Security#invite-replication).
- `delete_account` (kind 10) deletes the principal's own account in one
  atomic step. Its target is the account id that the principal's key
  derives, and its base version is 0. Every replica computes the same scope
  (`rules::account_scope`) from the committed tree: the Customer and Endpoint
  nodes the key owns, everything beneath them, and the assignments of the
  swept keys on every other node except the root. The submitter checked a
  fresh, purpose-bound signature by the account key before it signed the op.
  Each replica runs the per-node cleanup and the account cleanup when it
  applies the op. See [Security](Security#account-deletion).
- Every write path in `TreeApiHandler` produces an op. The local-only methods
  (`insert_join_node`, `update_node_direct`, `grant_assignment`,
  `set_assignment`, `delete_node_direct`, and the direct forms of invite,
  move, and account deletion) are removed.

### A2. Submission

1. The API server, a Tier 1 member, validates the op statically (format,
   signature, size) and sends it over the backbone to the other Tier 1
   servers. A Tier 2 server takes no tree request (see
   [A7](#a7-tier-2-and-lagging-servers)).
2. Each Tier 1 server keeps a bounded pending pool, keyed by `op_id`, with
   per-author limits.
3. The API answers when the op commits or is refused, waiting up to 10 s.
   After that it returns `202` with the `op_id`, the app shows the change as
   pending, and polls until it commits.

Phase 2 implementation: replicas trust op signatures from the block epoch's
frozen Tier 1 set only, so a Tier 2 server cannot sign an op a replica
accepts. The poll route is `GET /api/tree/op/{op_id}`.

Finalized state names only the Tier 1 set (and, at a boundary, the eligible
candidates for selection). Root-signed admission certificates are identity,
not authority, so they cannot become a list of trusted submitters, and a Tier
1 server that signed a Tier 2 server's request would assert a session it did
not authenticate. A Tier 2 server therefore answers every tree route, writes
and reads alike, with a plain `421` that carries no redirect and no data
([A7](#a7-tier-2-and-lagging-servers)). The earlier `503` for writes on Tier 2
is replaced by that refusal.

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

Phase 2 implementation: `Proposal` keeps its layout. A tree block's
`transitions_digest` field carries `ops_digest` (the digest of the batch's
canonical wire form, domain-separated from every stage digest), which enforces
"never both" by construction. The batch follows the certificate in the
`HotStuffProposal` message only, as a typed block payload
(`BlockPayload.hpp`); commit proofs and sync replies carry the header. Blocks
without a batch keep their proposal digest and wire bytes, so stored commit
proofs and handoff links still decode. `kMaxConsensusBlockBytes` is now
48,000. New payload kinds (for example Phase 5's `StorageHolderPlan` and
`StorageKeyRotation`) add a `BlockPayloadKind` value and an
`IBlockPayloadHandler`.

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

Phase 2 implementation: `parent_root` is the state root of the previous tree
block in the chain (the tree log head, or the nearest uncommitted tree
ancestor), and the proposal's `previous_state_root` carries it. Phase 3 adds
the committed op ids to the root:
`H(parent_root ‖ ops_digest ‖ tree_digest_after ‖ committed_digest_after)`
(domain `lemonade-nexus/tree-state-root:v2`, tree log format 2), so a
snapshot's ids are bound by a certified root and an edited snapshot is not
used. The tree log
is therefore a hash chain: a server that missed a tree block cannot match the
next one, and halts instead of applying it. The first entry chains to a base
root over the tree the log started from.

### A6. Commit, apply, and the tree log

- `SecurityDriver::on_commits` passes committed tree blocks to a new
  `TreeLog`. It appends each block durably as `tree/log/<height>.json` with
  its commit QC, then applies the ops to `PermissionTreeService` in order.
- The tree log height is independent of consensus views and continues across
  epochs. Activation still resets consensus; ops pending at that moment are
  resubmitted to the new epoch's pool.
- Snapshots every 1,000 heights bound replay time. A snapshot is the tree's
  canonical encoding plus its digest, cross-checked against the state root.
- The gossip transfer pool for tree records is retired once all Tier 1
  servers run the tree log. A Tier 2 server runs no transfer pool.

### A7. Tier 2 and lagging servers

Decision (2026-10-24): Tier 2 servers hold no tree. They are pure proxies of
end-to-end encrypted data and connections. They do not store, replicate,
read, write, redirect, or forward the tree, do not serve the tree API, and do
not terminate or vouch for a client tree session. Clients send every tree
read and write directly to a Tier 1 server, which they verify from finalized
membership (see [Client SDK](Client-SDK#tier-1-servers)). The original plan,
in which Tier 2 servers applied the replicated log and served the same tree,
is withdrawn.

- Replication reuses the existing sync library (`nexus::sync`, already used
  for DNS and account envelopes): a new `"tree"` stream whose entries are
  committed log blocks keyed by height, with the same digest and catch-up
  exchange over the backbone. Consensus fixes the order; the sync library
  only carries it, so last-writer-wins never decides a permission change.
- Replication runs between Tier 1 members only. A member that joins Tier 1,
  or that lags, catches up from the other members.
- A receiving server verifies each block's QC against the epoch's vote keys
  and follows the authority chain across epochs. It applies only verified
  entries, in height order.
- A server that cannot verify an entry stops applying and keeps serving the
  last verified state. It never applies unverified data.
- A server that is not a Tier 1 member runs no tree log, takes no replicated
  entry, and keeps no tree file. A server that leaves Tier 1 deletes its tree
  copy (best-effort overwrite) once finalized state shows that its last epoch
  ended. See [Architecture](Architecture#the-tree-on-tier-1-only).

Phase 3 implementation:

- The `"tree"` stream indexes committed heights under one origin
  (`tree-log`) in an `OriginReplica`; the entry bytes stay in the tree log and
  are read on demand. Catch-up sends entries in height order, at most 16 per
  request, as 16 KiB `TreeLogSync` chunks that the receiver reassembles within
  a 32 MiB budget. Only Tier 1 serves, only a Tier 1 member takes entries,
  and only backbone traffic from certified peers is accepted.
- A receiver verifies the commit proof (`verify_commit_proof`) under the vote
  keys and quorum of the epoch the entry's header names. It takes them from
  `SecurityDriver::authority_for_epoch`, which holds every epoch authority the
  driver verified from the pinned Genesis certificate and the finalized
  handoffs. An epoch it has not verified yet is held and hinted to the chain
  walker; it is never applied on a peer's word.
- The log height is not inside the proof. An entry is applied only when it
  chains to the log head (`previous_root`); an entry that does not chain is
  refused, not acted on, because a peer can renumber a genuine entry. A
  server whose log base differs from the mesh's therefore refuses every entry
  and reports it in `GET /api/tree/sync`.
- A Tier 1 server that sees a committed block that does not follow its log is
  "behind": it applies nothing out of order, catches up through replication,
  and resumes with the next committed block that chains.
- The gossip record transfer pool carries no tree records.

### A8. Effect on clients

- Peer lists, permissions, and the tree become identical on every Tier 1
  server. Tier 2 servers hold none of them.
- A later step can give clients proof: a server returns a node with the QC
  that committed it, so an app can reject a peer entry a compromised server
  invented. This closes the "lying server" case and is listed as a follow-up.

### A9. Migration of existing trees

Today each server's tree differs.

1. One release switches every write path to tree operations. A server that
   holds a tree from before awaits the merge: it serves that tree for reads,
   refuses tree writes (retryable `503`), and votes for no tree block, so no
   block can take height 1 first.
2. After the rolling update reaches every server, the root server's
   operator runs one script. It collects a signed export of every current
   Tier 1 member's tree, plus the root server's own tree from its backup (a
   Tier 2 server deleted its tree at startup). The root server merges them by
   a fixed rule: the root from the root server, each device from the server it
   joined, each group from its creator's record, then a documented tie-break.
   Nodes that share an identifier and nodes that do not reach the root are
   dropped and reported.
3. The merged tree is committed as **height 1**, signed by the root
   management key inside the root server's process, and verified by every
   Tier 1 server.

Implementation: the merge commit is a tree log entry of kind `merge` at
height 1: its body is the canonical encoding of the merged nodes, its root
chains to the empty base, and the root management key signs a canonical JSON
preimage that names the network, height, block time, roots, and node count. A
log accepts it only on top of the empty base, so it is one-shot. The root
management key and the data key exist only inside the running servers, so
the exports, the backup read, the merge, and the signature run there:
`scripts/nexus-tree-migrate` only carries bytes between the root server's
control socket and the Tier 1 members' `POST /api/tree/merge/export` and
`POST /api/tree/merge/commit` routes. When the commit applies, a server's
pre-merge tree is replaced by the merged tree. `nexus-tree-merge`,
`--sign-tree-merge`, and `--install-tree-merge` remain for plaintext test
data only. See [Tree Merge Ceremony](Tree-Merge-Ceremony).

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
| Dealerless key generation over Ristretto255 | `frost-ristretto255`, with the `internals` feature of `frost-core`, pinned to the same version as `frost-ed25519` (2.2.0) | NCC Group, 2023-10-23 (v0.6.0) |
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
  storage key is created. After holders are lost, re-sharing continues while
  at least 3 holders remain (see [Open Decisions](#open-decisions)).

### B5. Re-sharing

- When a holder is lost (its attestation lapses or it stays unreachable past
  a timeout) or a new holder is added, Tier 1 finalizes an updated
  `StorageHolderPlan` right away, without waiting for the epoch boundary.
  Prompt action restores full tolerance after each loss: at 5 holders, one
  loss is survivable, and after the change the next loss is survivable again
  once the set is back to strength.
- **If the threshold stays the same** (65% of the new holder count rounds to
  the same `t`) and no holder is added, the holders refresh their shares for
  the new set and keep `S`: removed holders drop out of the refresh. No file
  and no data key changes. Share repair is not used: a new holder enters
  through a key rotation (B5a) even when `t` stays the same
  (`StorageRecords.cpp`, `reshare()`). For example, 5 to 6 holders keeps
  `t = 4` and still rotates.
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
  server has rewrapped, with a hard cap.
- **Implemented.** Each server keeps a signed *wrap claim* finalized in the
  storage chain: the `S` and `R` of its committed wrapped DEK and, while it
  stages a rewrap or a replacement, of the staged one. A rewrap is staged in
  `data-key.next.json`, claimed, and proved through the new plan's holders;
  only then does it replace `data-key.json`, and the server claims the new
  wrap alone. That claim is its acknowledgement of the rotation. The previous
  plan (the retiring plan) unwraps while any server's latest finalized claim
  still names its `S`, and never after the hard cap
  (`kStorageRetiringCapMs`, 7 rotation intervals of block time after the
  rotation). While the retiring plan is live, no new rotation is selected
  (a boundary refreshes instead), so at most one retiring plan exists.
- A server that misses a rotation, even across several rotation intervals,
  unwraps with the old `S` while the retiring plan is live, then rewraps.
  After the cap its wrapped key opens nothing. A server that never returns
  delays the next rotation by at most the cap; an admitted server can do the
  same on purpose, which costs rotation, not confidentiality.
- Every rotation is logged with its epoch, so an operator can see when each
  key last changed.

### B6. Sealing the boot set

A server must authenticate and hold its own share before it can unlock
anything, so these two items cannot depend on the DEK:

- `nexus-attestd` gains `Seal` and `Unseal` operations. It seals to the SVSM
  vTPM under a policy bound to the approved release's PCRs and returns the
  result to the server, which stores it. `nexus-attestd` still never reads the
  server's data directory.
- The gossip identity key and the server's storage share are stored sealed.

**Implemented (Phase 6).**

| Item | Value |
|---|---|
| Policy | `TPM2_PolicyPCR` over the SHA-256 bank of PCR 8 and 9 (`kSvsmBootPcrs`), the two values a qualified release approval pins. PCR 10 is not bound: it advances with the IMA log. |
| Seal parent | ECC P-256 storage primary in the owner hierarchy, unique field `LEMONADE-NEXUS-SEAL-PARENT-V1`. Recreated per call. No persistent handle, no NV index. Not the EK, not the quote AK. |
| Sealed object | Keyed-hash object holding a random 32-byte key. No `USERWITHAUTH`; `ADMINWITHPOLICY`. Sessions are salted to the parent, so the key is encrypted to and from the TPM. |
| Secret encryption | XChaCha20-Poly1305 in the server process, under the sealed key. Associated data: purpose `sealed-blob`, the sealing domain, the PCR digest, and the TPM public area. |
| Domains | One per secret role: `gossip-identity` today; `storage-share` for Phase 5. |
| Files | `data/sealed/<domain>.sealed` (running boot chain), `data/sealed/<domain>.next.sealed` (staged for an approved next boot chain), `data/sealed/gossip-identity.state.json` (migration state and the public key). |

The daemon creates and unseals only the 32-byte key. The server encrypts and
decrypts the secret itself (`SealedBlobStore` with `attestd_seal_backend`), so
neither the secret nor its ciphertext crosses the socket, and a compromised
daemon does not obtain the server's keys.

Migration of the gossip identity (`identity/keypair.json`):

1. **Legacy file.** A host that cannot seal (no attestd client in the build, no
   TPM, or an older daemon) keeps `keypair.json` at mode 600. This is today's
   protection and the documented limit for certificate-only (Tier 2) hosts.
2. **Sealed, pending.** The server seals the key, unseals the sealed copy, and
   compares it with the file. Only then does it record the pending state and
   the kernel boot id. `keypair.json` stays.
3. **Sealed.** When the sealed copy unseals in a later boot (another boot id),
   the server records the sealed state, then overwrites and removes
   `keypair.json`. The two-boot rule protects against a vTPM that does not keep
   its owner seed across reboots.

While `keypair.json` exists it is the fallback when the sealed copy does not
unseal, and the server seals it again. After step 3 the server never creates a
new identity in place of a sealed one:

| Restart case | Result |
|---|---|
| Sealed copy present, PCR 8/9 match | Unseals; the same key. |
| PCR 8/9 changed, approved chain staged | The staged copy unseals, is sealed again to the running PCRs, and the staged file is removed. |
| PCR 8/9 changed, nothing staged | Startup stops with `policy_mismatch`. Files stay unchanged. Recovery: boot the previous boot entry. |
| Blob corrupt, from another TPM, or the vTPM owner seed changed | Startup stops with `corrupt`. Recovery: restore `data/sealed/` from a backup of this host. |
| Blob missing | Startup stops. Recovery: restore the file, or remove the state file to start with a new identity, which needs new enrollment. |
| Daemon unreachable | Retries for about 30 s, then stops. |

The same rules apply before step 3, except that `keypair.json` is used instead
of stopping.

Upgrade path. PCR 8 records the GRUB commands and the kernel command line; PCR
9 records the files GRUB reads (kernel, initramfs, GRUB configuration). The
server binary is measured into PCR 10 by IMA, not into PCR 8 or 9. On the
Tier 1 mesh, releases r11 to r21 all pin the same PCR 8 and 9, so a
binary-only release changes nothing that the seal binds. A release that
changes the boot chain installs an approval with new expected PCR 8 and 9. At
its next start on the old boot chain, the server verifies that approval
against Genesis and seals each boot-set secret a second time, to the expected
values (`<domain>.next.sealed`). After the reboot the staged copy unseals and
becomes the current copy. The current copy is replaced only after the new one
is durable, so booting back into the old chain still works until then. No step
needs Genesis or a new enrollment.

Limits:

- Simulator-tested only (swtpm). Not yet verified on the SEV-SNP SVSM vTPM: in
  particular whether that vTPM keeps its owner seed across reboots. If it does
  not, the migration stays in the pending state and `keypair.json` stays.
- A boot-chain change that no approval staged (a pending approval, a manual
  command-line edit) stops a fully migrated server until the previous boot
  entry boots.
- Overwriting `keypair.json` is best effort: journaling, snapshots, and SSD
  remapping can keep old blocks.
- On the root server the gossip identity is also the Genesis key, and it is
  sealed the same way.
- The vote keys and `wrap_local.key` keep the machine-bound wrapping (B12).
  With Phase 7 on, `keypair.enc` is also encrypted under the DEK.

### B7. Unlock at startup

1. The server unseals its boot set (Phase 6, `Core/BootSet.hpp`). The share
   goes into the same `SealedBlobStore` under the `storage-share` domain and
   gets the same upgrade staging.
2. It requests partials from the holders with a new security message,
   `StorageUnlockRequest {network, epoch, R, nonce}`.
3. Each holder challenges the requester with a new attestation purpose,
   `StorageUnlock`, bound to the request nonce. Holders that are not Tier 1
   may challenge for this purpose only; the router's `NotMember` gate changes
   accordingly.
4. On a passing verdict for the approved profile, the holder answers with
   `StorageUnlockPartial {s_i·R, DLEQ proof}`, sealed to the requester with
   the request digest as associated data. The holder answers only for an `R`
   that the requester's latest finalized wrap claim names for the plan's
   `S` (B5a). An `R` belongs to the first server that claimed it while its
   `S` is live, so a server that copies another server's `data-key.json`
   gets no partial for it.
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
snapshots, and account data. `wrap_local.key` is retired. B12 states what the
implementation covers and which of these items stay outside the vault.

A server whose platform cannot pass the `StorageUnlock` attestation never
unlocks a DEK: a holder answers only after a verdict that proves every claim
of the Tier 1 attestation profile (`StorageKeyService::on_verdict`). A Tier 2
server without SEV-SNP therefore never completes the B10 round trip, and its
files stay plaintext (B10 step 3). The root server of the production mesh is
such a server. It still holds a share and answers other servers' unlocks.

### B10. Migration

1. A release creates `S` once at least 5 holders are attested, through a
   dealerless key generation among them.
2. Each server creates a DEK, wraps it to `S`, re-encrypts its files, verifies
   that it can unlock through the holders, and only then deletes the
   plaintext.
3. A server that cannot reach `t` holders keeps its old files and retries.

### B11. Phase 5 implementation

Always on, no setting (`Security/Storage/`):

- **Records.** Two block payload kinds carry storage records:
  `StorageHolderPlan` (first key and share refresh) and `StorageKeyRotation`.
  A record is a *selection* (holders, `t`, operation) or a *final plan* (`S`,
  the share commitments, and every selected holder's identity signature over
  the exact plan bytes). Records chain by sequence and previous digest. A
  replica votes for a selection only when its own derivation gives the same
  bytes, and for a final plan only when every check in
  `check_storage_final` passes. Servers outside Tier 1 receive each record
  with its commit proof (`StoragePlanProof`) and verify the proof against the
  committing epoch's vote keys.
- **Selection.** At each epoch boundary the holders come from the finalized
  eligibility pool, ranked by `H(checkpoint_seed ‖ node_id)` with the
  finalized state root as the seed, at most 50. With no key and at least 5
  holders, the key is created. With a key, the shares refresh when the new
  holders are a subset of the current ones, `t` is unchanged, and no rotation
  is due; otherwise the key rotates. A rotation is due when block time is 24 h
  past the block time that created `S`, and it waits while the retiring plan
  is live (B5a). New holders join through a rotation; the crate's share
  repair is not used yet.
- **Holder loss.** A session that has no final plan 120 s of block time after
  its selection may be replaced: by the next boundary's selection, or by a
  retry without the holders whose round-1 package the replica never observed
  and, once any holder confirmed, without the holders whose confirmation it
  never observed (at most 3 attempts). Below 3 holders nothing is selected
  and the last plan stays.
- **Sessions.** Round 1 is broadcast; each round-2 package is sealed to its
  recipient with the network, the session (selection digest), and both holder
  identifiers bound inside the seal. Early round-2 packages are held and own
  packages are re-sent every 5 s (Part C, `RoundRelay.hpp`, shared with the
  FROST DKG). A holder seals its new share before it signs its confirmation.
- **Wrap claims.** A `StorageWrapClaim` message carries a server's signed
  claim to Tier 1, which finalizes claims in wrap batches (a third record
  stage, payload kind `StorageHolderPlan`). A claim names one or two wraps,
  each on the current `S` or the live retiring `S`; its counter must rise;
  no wrap may belong to another server.
- **Unlock.** A holder answers a `StorageUnlockRequest` only for the current
  plan, or the retiring plan while it is live (B5a), only for an `R` in the
  requester's latest finalized claim, after a passing `StorageUnlock`
  attestation bound to that request.
  Budgets: one pending request per requester, 8 per requester per epoch, 64
  pending in all; a replayed request digest is refused. The partial is sealed
  to the requester with the request digest bound inside the seal.
- **Data key.** `DataKeyService` creates the DEK, wraps it to `S`, claims
  the wrap, proves the unwrap through the holders, unlocks at startup, and
  stages, proves, and then commits a rewrap after a rotation.
- **Lost or foreign state.** `records.json` names the epoch chain that
  finalized its records (the Genesis certificate digest). Records of another
  chain are refused; a file without the binding binds when each commit proof
  verifies under this chain. Shares are pruned only against a bound chain
  with a current plan. When the files are encrypted, a missing
  `records.json` or `data-key.json`, a chain without a final plan, or a
  foreign chain stops startup with an error that names the files to restore.
- **Share storage.** On a host that can seal, shares are kept by
  `SealedStorageShareStore` in the boot set's `SealedBlobStore` under the
  domain `storage-share`, with the same backend and upgrade staging as the
  gossip identity. A host that cannot seal keeps `FileStorageShareStore` under
  today's machine-bound wrapping (the B6 limit).

### B12. Phase 7 implementation

Always on, no setting (`Security/Storage/StorageVault.hpp`):

- **Format.** A covered file is replaced in place by
  `"LNXVAULT" | 0x01 | key id (16) | nonce (24) | ciphertext`. The cipher is
  `EncryptedBlob` version 1 (XChaCha20-Poly1305) under
  `HKDF(DEK, "LEMONADE-NEXUS-STORAGE-V1", "lemonade-nexus-storage-file-key-v1")`.
  The associated data is `aead_aad("storage-file-at-rest", {domain, relative
  path, key id})`. The key id is a second HKDF output of the DEK.
- **Covered** (`StorageVault::default_coverage()`). Coverage generation 1:
  `identity/keypair.enc`, `identity/jwt_secret.hex`,
  `identity/ddns_credentials.enc`, `account/replica.json`,
  `link_tokens/ledger.json`, `link_replica/replica.json`, `tree/nodes`,
  `tree/deltas`, `tree/log`, and the TLS and ACME private keys
  (`certs/<fqdn>/privkey.pem` and `certs/account.key`). Coverage generation
  2: `tree/committed-ops.json`, `onboarding/admissions.json`, the account
  data store directories `chat-<hash>/` and `keyenv-<hash>/`, and the user
  credentials (`credentials/<user>.json` and `credentials/revoked.json`).
  `FileStorageService`, `KeyWrappingService`, `resolve_jwt_secret`, `TreeLog`,
  `PermissionTreeService`, `resolve_tls_cert`, `AcmeService`, and the
  credential file functions of both auth providers (`Auth/CredentialFile.hpp`)
  route these paths through the vault.
- **Credential reads fail closed.** A credential read is absent (a new user),
  unreadable (locked, refused by the vault, or not JSON), or present. An
  unreadable file is never treated as empty and never written over: the
  operation that needs it is refused. An unreadable user file stops the
  registration of new identities, because the file can name the key or the
  credential. An unreadable `revoked.json` counts every Ed25519 key and
  session as revoked, and revocation changes are refused until it opens. The
  auth providers are created after the data key unlocks (`main`), and they
  read the files again after a failed load.
- **Coverage additions.** Each coverage group names the generation that added
  it, and `vault-state.json` records the generation of the files (`coverage`;
  a state file without it records 1). On a server that is already
  `encrypted`, the files of a newer group are plaintext. Until the vault adopts
  them, that plaintext is authoritative, as before a migration commits, and
  `files_ready()` stays false, so the services that read covered files wait.
  With the DEK in memory and a verified unlock, the vault stages each file of
  the new groups, reads it back, and compares it with the plaintext. It then
  records the new generation with phase `promoting` (the switch point) and
  overwrites and replaces the plaintext. After that record the new groups
  refuse plaintext like every other group. A group of an earlier generation
  never accepts plaintext. A file in a new group that has the header but does
  not open under the DEK stops the adoption, and the files stay locked. A
  rotation that began before the update is discarded before its commit and
  runs again after the adoption.
- **Not covered, because the file is read before the unlock.** The vault
  refuses every read while the DEK is locked, and these readers run during the
  unlock (B8):
  - Everything under `security/`: the epoch and consensus state, the storage
    key records, the wrapped DEK (`data-key.json`, already wrapped to `S`), and
    `vault-state.json`.
  - `security/vote-key-<epoch>.json`. `EpochStore::store_vote_key` writes the
    vote private key wrapped by `KeyWrappingService` with an empty passphrase,
    so the key is derived from `identity/wrap_local.key` and
    `/etc/machine-id`. Consensus votes continue while the DEK is locked, so
    the vault cannot cover it. The wrap key is in the same data directory, so
    this wrapping binds the file to the machine; it does not protect the vote
    key from a reader of the whole data directory. Sealing the vote keys like
    the boot set (B6) is open work.
  - `identity/wrap_local.key`. The file share store and the vote keys read it
    before the unlock, so moving it under the DEK would stop a cold start.
  - `identity/peers.json` and `identity/ns_slots.json` (gossip starts before
    the unlock), and `ipam/allocations.json` (IPAM starts before the unlock).
    These hold mesh addresses that gossip also distributes.
  - The boot set (B6): the sealed copies in `sealed/`, and
    `identity/keypair.json` until the sealed migration removes it. A host
    that cannot seal keeps `keypair.json` (the B6 limit).
- **Not covered, because the file is public or protected another way.**
  `identity/keypair.pub`, `identity/server_cert.json`, the TLS certificate
  chain and `meta.json`, `certs/account_url.txt` (the account identifier that
  each ACME request names), and `identity/hostname`. The DNS replica
  (`dns/replica.json`): gossip replicates these records to every server, and
  each entry is origin-signed and verified again on load. ACL rows: `acl.db`
  already stores `perms_enc` under XChaCha20-Poly1305, keyed from the gossip
  identity (`ACLService::set_signing_keypair`). Moving ACL rows to a
  DEK-derived key is a re-keying choice, and a live SQLite file does not fit
  the whole-file vault container.
- **Not covered (legacy).** The per-token files under `link_tokens/` come
  from releases before `v2026.10.26` and stay plaintext so that
  `TokenLinkAuthProvider` can still redeem them. The current release mints no
  new ones; it only restores a legacy token whose redemption did not complete
  (`legacy_refund`).
- **Migration (B10).** `plaintext`, then `migrating` (stage
  `<file>.vault-new`, request a new unlock round trip, verify every staged
  copy against the plaintext), then `encrypted` (overwrite and replace). The
  plaintext is authoritative until `encrypted` is durable. A missing or
  damaged state file with encrypted files present loads as `encrypted`.
- **Startup.** With `encrypted` recorded, `main` runs the io context (gossip,
  attestation, the security mesh, holder duties) until the DEK is in memory,
  then starts the tree, the node identity, and everything after them. Startup
  stops, with an error that names the files to restore, when the storage
  state that opens the files is lost or belongs to another epoch chain
  (B11).
- **DEK rotation (B5a).** Every 30 days on the local clock, or on
  `POST /api/storage/rotate-data-key` (root administrator).
  `DataKeyService::begin_replacement` wraps a new DEK to the current S in
  `data-key.next.json` and proves it through the holders; the vault stages
  and verifies every file under it; `commit_replacement` replaces
  `data-key.json`, which is the switch point; the staged files then replace
  the old ciphertext.

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
| 3 | Log replication to joining and lagging Tier 1 servers with QC verification. Tree merge ceremony and switch-over (A9). Tier 2 servers hold no tree (A7, decided 2026-10-24). | 2 |
| 4 | `storage-threshold` crate: library review, key generation, re-share, share refresh, DLEQ, threshold ECIES. | — |
| 5 | `StorageHolderPlan` in consensus, unlock protocol, `StorageUnlock` attestation purpose, per-epoch share refresh, daily `StorageKeyRotation`. | 2, 4 |
| 6 | `nexus-attestd` Seal and Unseal; boot set sealed. **Implemented** (B6). | — |
| 7 | DEK file migration; plaintext removed; monthly DEK rotation. **Implemented** (B12), including the TLS and ACME private keys and coverage generation 2 (committed op ids, admission records, account data store, user credentials). Files read before the unlock, such as the vote keys and `wrap_local.key`, stay under machine-bound wrapping; B12 lists every file that is not covered and the reason. | 5, 6 |

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
  after the retiring plan's hard cap, a server stopped across two rotation
  intervals catching up, a rewrap interrupted before its verification, a
  request for another server's `R`, a holder that never confirms, lost or
  foreign storage state with encrypted files, an interrupted DEK rotation
  resuming without data loss, cold start with exactly `t` and with `t − 1`
  holders.
- **Race fix:** round 2 arriving before round 1 on every DKG path completes
  without a stall.

## Open Decisions

1. **Genesis and root management keys** stay on the root server for now.
   Revisit before Phase 7.

Decided: libraries for `storage-threshold` (B3), with an external review of
the unaudited paths before Phase 5; a threshold change rotates the key
instead of re-sharing to a new threshold (B5); no offline recovery key (B8); nodes hold per-node versions and the
sync library replicates (A7); the API waits up to 10 s, then reports pending
(A2); holder counts (B4, B5, B10): the storage key is created only with at
least 5 eligible, attested holders; after holders are lost, Tier 1 refreshes
or rotates promptly while at least 3 holders remain (a refresh when `t` stays
the same, otherwise a rotation at the new count: 4 holders give `t = 3`, 3
holders give `t = 2`); below 3 holders the last plan stays and no rotation
runs; holders are added back through rotation; the crate permits 3 to 50
holders for a refresh or rotation and 5 to 50 for the first key.
