---
layout: default
title: Tree Merge Ceremony
---

# Tree Merge Ceremony

Status: **supported one-time migration**. This runbook implements design
section A9 of
[Design: Tree Consensus and Threshold Storage Key](Design-Tree-Consensus-and-Storage-Key).
It is tested with unit and multi-server tests. It has not run against the live
mesh yet.

## Table of Contents
- [Purpose](#purpose)
- [What the merge trusts](#what-the-merge-trusts)
- [How a server behaves until the merge](#how-a-server-behaves-until-the-merge)
- [Before you start](#before-you-start)
- [Step 1: Roll out the release](#step-1-roll-out-the-release)
- [Step 2: Dry run on the root server](#step-2-dry-run-on-the-root-server)
- [Step 3: Sign and deliver](#step-3-sign-and-deliver)
- [Step 4: Check every Tier 1 server](#step-4-check-every-tier-1-server)
- [The merge rule](#the-merge-rule)
- [Recovery](#recovery)
- [Test data without encryption](#test-data-without-encryption)
- [Limits](#limits)

## Purpose

Before tree operations, each server kept and changed its own permission tree.
The trees differ. Tree operations need one tree that every server agrees on.
The merge collects every server's tree once, merges them by a fixed rule, and
commits the result as height 1 of the tree log. After the merge, every tree
change is a tree operation that Tier 1 consensus orders.

The owner runs one script, `nexus-tree-migrate`, on the root server: once as a
dry run, and once to sign and deliver. Everything else is the normal signed
release and the rolling update.

## What the merge trusts

- The merged tree is authorized only by the **root management key** signature
  (`root_pubkey` in the configuration). Every server verifies that signature
  against its own configured `root_pubkey` and the network id from its own
  `genesis_pubkey`. The server or person that delivers the commit is not
  trusted.
- The commit is valid only as height 1, on top of an empty tree log base. A
  server whose log already holds height 1 refuses another merge commit, and a
  merge entry at any other height does not verify. There is no command that
  replaces the tree after that.
- Each Tier 1 member gives its tree only for an export request that the root
  management key signed for that member (`lemonade-nexus/tree-export-request:v1`,
  at most 10 minutes from its clock, a nonce it has not served). It signs its
  export with its own gossip identity (`lemonade-nexus/tree-export-signature:v1`).
- The root server merges only when the exports are signed by exactly the
  current Tier 1 members by finalized membership, each once, plus its own
  backup export. Only the root server's export counts as the root server's.
- The root management key and the data key never leave the running servers.
  The script holds no key. On the root server's control socket (root peers
  only, [Upgrade Control](Upgrade-Control)) the key signs only an export
  request for a current member, and the preimage of a merge that the server
  built itself from verified exports, after the rebuilt tree digest equals the
  digest of the reviewed dry run.

## How a server behaves until the merge

A release with tree operations runs them on every server; there is no
setting. When a Tier 1 server holds a tree written before tree operations and
no tree log, it **awaits the merge**:

- It opens a tree log on the empty base and keeps its tree as it is. Tree
  reads, sessions, and tunnels keep working.
- Every tree write (join, group and node edits, assignments, invites, moves,
  deletions, account deletion, endpoint changes) answers `503` with
  `Retry-After: 30` and the reason. The write is not queued, so nothing applies
  later or twice.
- It proposes no tree block, withholds its vote from every tree block, and
  requests no root. No tree block can take height 1 before the merge commit.
- It applies only the merge commit. A consensus entry is refused and named in
  the status.
- `GET /api/tree/sync` shows `"mode": "awaiting-merge"`, `"healthy": true`,
  `"height": 0`, and `"pre_merge_nodes"`. The updater's health gate passes.
- A restart keeps this state.

When the merge commit arrives (by `POST /api/tree/merge/commit` or by the
`"tree"` stream from another member), the server verifies it, writes it as
height 1, and replaces its tree with the merged tree. A crash between the
write and the replacement is repaired at the next start from the log.

A server with an empty tree and no log starts a new log normally. A Tier 2
server holds no tree.

## Before you start

- You know which server holds the root management key (the root server). Its
  identity public key is `root_pubkey`. On the production mesh this is ns1.
- The root server's own tree: a Tier 2 server deleted its tree at startup. Use
  the backup taken before that release ran (on ns1:
  `/var/lib/lemonade-nexus-backup-20261025-boot/state.tar`). The script
  accepts a tar file or a directory and finds the data directory in it (the
  directory that holds `tree/nodes`).
- The backup's files open only with the data key the root server holds now.
  Run the merge before the root server's next monthly data key rotation.
- Every Tier 1 member must be reachable from the root server on its public
  API (`https://<address>:9100` by default, or `--server SIGNER=URL`).

## Step 1: Roll out the release

Publish the release as usual ([Releasing](Releasing#the-tree-operations-release-one-time)).
`nexus-updater` installs it on one server at a time. Each updated Tier 1
server awaits the merge. A server that still runs the old release keeps its
direct writes until its turn; those writes are part of its tree when the
merge collects it.

Wait until every server runs the release. The script refuses to continue while
a Tier 1 member answers the export route with `404` (old release).

## Step 2: Dry run on the root server

```bash
sudo nexus-tree-migrate \
    --backup /var/lib/lemonade-nexus-backup-20261025-boot/state.tar
```

The package installs the script as `/usr/bin/nexus-tree-migrate`.
`nexus-updater` replaces only the server binaries, so on an updated server
download `scripts/nexus-tree-migrate` from the release tag and run it with
`sudo python3`.

The script:

1. asks the root server for the network, the root key, and the current Tier 1
   members;
2. extracts the backup to `/var/lib/lemonade-nexus/tree-migration/backup`
   (regular files and directories only), and has the root server export it with
   its data key;
3. for each member, has the root server sign an export request, and sends it
   to the member's `POST /api/tree/merge/export`;
4. saves the exports in `/var/lib/lemonade-nexus/tree-migration/exports.json`
   (mode 0600);
5. has the root server build the merge and prints the report.

The report lists, for each server, the nodes the merge adds to, removes from,
and changes in its tree; every node decided by the tie-break; every dropped
node with the reason; and the tree digest. Nothing is signed.

Review it. A dropped device or group joins again after the merge.

## Step 3: Sign and deliver

```bash
sudo nexus-tree-migrate \
    --backup /var/lib/lemonade-nexus-backup-20261025-boot/state.tar \
    --commit --expect-tree-digest <tree digest from the dry run>
```

The script collects the exports again. The root server builds the merge
again, refuses unless the tree digest equals the one you reviewed, signs the
preimage with the root management key, and verifies the signature. The
script saves the commit to `/var/lib/lemonade-nexus/tree-migration/commit.json`
and sends it to every member's `POST /api/tree/merge/commit`. A member that
does not take it directly gets it from the others by replication.

## Step 4: Check every Tier 1 server

`GET /api/tree/sync` on the private API of each Tier 1 server must show
`"mode": "ops"`, `"healthy": true`, `"height": 1`, and the same
`"state_root"` as the script printed. Tree writes work again.

## The merge rule

Per node id, the first rule that decides wins (`tree::merge_tree_exports`,
`TreeMerge.hpp`):

1. An operator resolution decides. The supported migration passes none.
2. The root comes from the root server's export, when it holds one.
3. A node that one export holds, or that every holding export holds
   identically, is taken.
4. A device comes from the server whose IPAM file records its tunnel
   allocation (the server it joined).
5. A group comes from the server whose delta log records its `create_node`
   delta (its creator).
6. **Tie-break.** Among the copies with rule 4 or 5 evidence when two or more
   have it, else among all copies: the highest `version`; then the copy that
   the most exports hold identically; then the root server's copy; then the
   copy whose encoding is first in byte order.

Then, on the selected nodes:

7. Two nodes that share an endpoint identifier, a mesh key, or a tunnel
   address (independent IPAM files often gave one address to two devices):
   the root is kept; otherwise the node whose join an export records, then the
   node the most exports hold, then the smallest id. The others are dropped.
8. Every node that does not reach the root through its parents (a missing or
   dropped parent, or a cycle) is dropped.

The result depends only on the exports: their order, and the order of nodes
in them, does not change it. The merge refuses to produce a commit only for
malformed input (repeated server labels, not exactly one root server export,
a bad resolution, no root in any export).

## Recovery

- **The dry run refuses.** It names the cause: a member that runs the old
  release, a member that is not reachable (use `--server SIGNER=URL`), a member
  that does not await the merge, or a backup that does not open. Fix it and run
  the dry run again. Nothing changed.
- **The digest does not match at step 3.** A tree changed between the dry run
  and the commit (only possible through a server outside the merge). Run the
  dry run again and review it.
- **A member did not take the commit.** It receives it by replication. To send
  it again, run step 3 again: a member that holds it answers
  `already-installed`.
- **A server refuses consensus entries and reports that it awaits the merge.**
  It missed the merge (for example, it was offline and kept its old tree). It
  takes the merge commit by replication from any member; nothing else is
  needed.
- **A server halts tree operations at start.** The log does not verify, or the
  tree changed outside the log. Read `halt_reason` in `GET /api/tree/sync`.
  The server keeps serving its last committed tree and applies nothing until
  the cause is fixed.

## Test data without encryption

`nexus-tree-merge` (export, merge, finalize), `lemonade-nexus
--sign-tree-merge`, and `--install-tree-merge` work on plaintext data
directories only. They refuse a data directory whose files are under the data
key. Use them for test data; use `nexus-tree-migrate` for a mesh.

## Limits

- The merge decides by the evidence on disk and then by the tie-break; it
  cannot know which of two differing copies a user meant. The dry run shows
  every such decision for review.
- Dropped nodes are not in the merged tree. Those devices join again.
- Tree writes are refused on updated servers from their update until the
  merge.
- For an address URL the script checks the TLS certificate chain but not the
  name. The exports stay authenticated by their signatures.
- A backup under an earlier data key does not open.
- Pre-merge trees of other Tier 2 servers are not collected: only current
  Tier 1 members and the root server contribute. The production mesh has no
  other Tier 2 server.
