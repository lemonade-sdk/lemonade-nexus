---
layout: default
title: Tree Merge Ceremony
---

# Tree Merge Ceremony

Status: **experimental**. This runbook implements design section A9 of
[Design: Tree Consensus and Threshold Storage Key](Design-Tree-Consensus-and-Storage-Key).
It has been run only against test data. It has not been run against a live
mesh.

## Table of Contents
- [Purpose](#purpose)
- [What the ceremony trusts](#what-the-ceremony-trusts)
- [Before you start](#before-you-start)
- [Step 1: Run the tree log in read-only mode (release N)](#step-1-run-the-tree-log-in-read-only-mode-release-n)
- [Step 2: Freeze tree writes and export every tree](#step-2-freeze-tree-writes-and-export-every-tree)
- [Step 3: Merge the exports and resolve conflicts](#step-3-merge-the-exports-and-resolve-conflicts)
- [Step 4: Sign the merge offline with the root management key](#step-4-sign-the-merge-offline-with-the-root-management-key)
- [Step 5: Install the commit and let it replicate](#step-5-install-the-commit-and-let-it-replicate)
- [Step 6: Switch every server to ops mode (release N+1)](#step-6-switch-every-server-to-ops-mode-release-n1)
- [Recovery](#recovery)
- [Limits](#limits)

## Purpose

Before tree operations, each server kept and changed its own permission tree.
The trees differ. Tree operations need one tree that every server agrees on.
The ceremony merges every server's tree once and commits the result as height
1 of the tree log. After the ceremony, every tree change is a tree operation
that Tier 1 consensus orders.

## What the ceremony trusts

- The merged tree is authorized only by the **root management key** signature
  (`root_pubkey` in the configuration). Every server verifies that signature
  against its own configured `root_pubkey` and the network id from its own
  `genesis_pubkey`. The server or person that delivers the commit is not
  trusted.
- The commit is valid only as height 1, on top of an empty tree log base. A
  server whose log already holds height 1 refuses another merge commit. There
  is no command that replaces the tree after that.
- The merge tool reads and writes no key material. Only the root server's
  `--sign-tree-merge` command uses the root management key, and it signs only
  a canonical merge preimage for the configured network.

## Before you start

- Every server runs a release that contains this feature.
- You know which server holds the root management key (the root server). Its
  identity public key is `root_pubkey`.
- You have the mesh network id (64 hex digits). The startup log prints it, or
  derive it from `genesis_pubkey`.
- Plan a maintenance window. Tree writes made after the export in step 2 are
  lost when the servers switch to ops mode in step 6.

## Step 1: Run the tree log in read-only mode (release N)

On every server, set `tree_log_enabled` (`--tree-log` or `SP_TREE_LOG`) and
restart. Do not set `tree_ops_enabled`.

In read-only mode the server:

- builds an empty tree log at `data/tree/log`;
- runs the `"tree"` sync stream: Tier 1 serves log entries, and every server
  pulls them from Tier 1;
- keeps the direct tree write paths. The log never changes the live tree.

Check each server with `GET /api/tree/sync` on the private API. Expect
`"mode": "read-only"`, `"healthy": true`, and `"height": 0`.

## Step 2: Freeze tree writes and export every tree

1. Announce the window. Ask admins and users to make no tree changes (joins,
   group edits, deletes) until step 6 completes.
2. On each server, stop the service, copy the data directory, and start the
   service again. Run the export against the copy:

   ```bash
   nexus-tree-merge export --data-root /path/to/copy --server east --root-server --out east.json
   nexus-tree-merge export --data-root /path/to/copy --server west --out west.json
   ```

   Give each server a unique `--server` label. Mark exactly one export with
   `--root-server`: the server that holds the root management key.

The export records each node, the devices whose tunnel allocation the
server's IPAM file holds (the server each device joined), and the groups whose
`create_node` delta the server's delta log holds (each group's creator
record).

## Step 3: Merge the exports and resolve conflicts

Write a merge spec:

```json
{
  "network_id": "<64-hex network id>",
  "root_pubkey": "<64-hex root management key>",
  "exports": ["east.json", "west.json"],
  "resolutions": {}
}
```

Run the merge:

```bash
nexus-tree-merge merge --spec spec.json --out unsigned.json \
    --preimage preimage.json --report report.json
```

The merge rule, per node:

1. A resolution in the spec decides: a server label takes that server's
   copy, and `"drop"` removes the node.
2. The root comes from the root server.
3. A node that one export holds, or that every holding export holds
   identically, is taken.
4. A device comes from the server it joined.
5. A group comes from the server that holds its creator record.
6. Anything else is a conflict.

After selection, a node whose parent is missing (`orphan`) and two nodes that
share an endpoint identifier, mesh key, or tunnel address
(`duplicate_identifier`, `duplicate_mesh_key`, `duplicate_tunnel_address`) are
conflicts too. Independent IPAM files often gave the same tunnel address to
two devices; resolve this by dropping one device and joining it again after
step 6.

With conflicts, the tool prints one line per conflict, writes the report, and
exits with status 2. Add resolutions to the spec and run the merge again.
Without conflicts, it writes `unsigned.json` (the unsigned height-1 commit)
and `preimage.json` (the exact bytes the root management key signs), and
prints the height-1 state root.

## Step 4: Sign the merge offline with the root management key

Copy `preimage.json` to the root server. Run, with the same configuration the
service uses:

```bash
lemonade-nexus --data-root /var/lib/lemonade-nexus/data \
    --root-pubkey <root_pubkey> --genesis-pubkey <genesis_pubkey> \
    --sign-tree-merge preimage.json signature.b64
```

The command refuses a file that is not a canonical merge preimage for this
network, and refuses to sign unless this server's identity is the configured
root key. It prints the node count, tree digest, and state root. Compare them
with the merge output before you continue.

Copy `signature.b64` back and finalize:

```bash
nexus-tree-merge finalize --unsigned unsigned.json --signature signature.b64 \
    --out commit.json
```

`finalize` verifies the signature and writes the signed commit.

## Step 5: Install the commit and let it replicate

Install the commit on one Tier 1 server. Stop the service first: the tree log
belongs to the running process.

```bash
lemonade-nexus --data-root /var/lib/lemonade-nexus/data \
    --root-pubkey <root_pubkey> --genesis-pubkey <genesis_pubkey> \
    --install-tree-merge commit.json
```

The command verifies the signature against the configured anchors and writes
the commit as tree log height 1. Start the service again.

The `"tree"` stream carries the commit to every other server. Each server
verifies the root signature itself before it appends the commit. You can also
install the same file on every server by hand.

Wait until `GET /api/tree/sync` on every server shows `"height": 1` and the
same `"state_root"`. A server that shows a `last_refusal` that names the log
base started its log from a non-empty tree; see [Recovery](#recovery).

## Step 6: Switch every server to ops mode (release N+1)

On every server, set `tree_ops_enabled` (`--tree-ops` or `SP_TREE_OPS`) and
restart. At start, the server finds that its live tree is behind the committed
log and replaces it with the log state: the merged tree. From then on, every
tree write is a tree operation, Tier 1 orders it, and Tier 2 and lagging
servers apply the replicated log.

Check `GET /api/tree/sync`: `"mode": "ops"`, `"healthy": true`, and the same
`"state_root"` on every server. End the maintenance window.

## Recovery

- **A server refuses every entry and reports that the entry does not chain.**
  Its log started from another tree. Stop it, move `data/tree/log` aside,
  start it in read-only or ops mode with an empty tree, and let replication
  refill the log. In ops mode the server then replaces its live tree with the
  committed tree.
- **The merged tree is wrong, and no server has switched to ops mode.** Stop
  every server, move `data/tree/log` aside on each, and run the ceremony
  again from step 1. Do not do this after any server switched to ops mode:
  committed tree operations would be lost.
- **A server halts tree operations at start.** The log does not verify, or the
  live tree changed outside the log. Read `halt_reason` in
  `GET /api/tree/sync`. The server keeps serving its last committed tree and
  applies nothing until the cause is fixed.

## Limits

- Changes made between the export and the switch-over are lost.
- The conflict rules use the evidence a server has on disk (IPAM records and
  the delta log). A node with no evidence and different copies is always a
  conflict for an admin.
- The root management key stays on the root server (design Open Decision 1).
  "Offline" means the signing is a one-shot command, not a network request.
