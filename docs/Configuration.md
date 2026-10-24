---
layout: default
title: Configuration Reference
---

# Configuration Reference

## Table of Contents
- [Configuration Sources and Precedence](#configuration-sources-and-precedence)
- [Trust Anchors (Required for a Normal Start)](#trust-anchors-required-for-a-normal-start)
- [Network](#network)
- [Identity and Auth](#identity-and-auth)
- [DNS](#dns)
- [TLS / ACME](#tls--acme)
- [DDNS](#ddns)
- [Onboarding](#onboarding)
- [Experimental: Tree Operations](#experimental-tree-operations)
- [Experimental: Threshold Storage Key](#experimental-threshold-storage-key)
- [JSON Config Example](#json-config-example)
- [Retired and Inert Settings](#retired-and-inert-settings)

## Configuration Sources and Precedence

A normal start reads settings from four sources. **Highest priority first:**

1. **Environment variables** — `SP_*` (for the packaged service:
   `/etc/lemonade-nexus/lemonade-nexus.env`)
2. **CLI arguments** — for example `--http-port 8443`
3. **JSON config file** — `lemonade-nexus.json` (packaged default location:
   `/var/lib/lemonade-nexus/lemonade-nexus.json`)
4. **Defaults**

Two deliberate exceptions to "environment wins":

- **Explicit trust anchors win over the environment.** If you pass
  `--root-pubkey` or `--genesis-pubkey` on the command line, the corresponding
  `SP_ROOT_PUBKEY` / `SP_GENESIS_PUBKEY` environment values are ignored (with a
  warning). An environment variable must not silently replace an anchor the
  operator pinned in the start command.
- **Environment seed peers append.** `SP_SEED_PEERS` (comma-separated) is
  added to the seed list from the config file and `--seed-peer`; it does not
  replace it.

Note: an environment variable overrides a CLI value for *every other* setting
(for example `SP_HTTP_PORT` overrides `--http-port`). Keep the packaged
environment file for deliberate operator overrides only.

**Boolean environment variables** (`SP_CLOSED_REGISTRATION`,
`SP_DNS_SEED_DISCOVERY`, `SP_DDNS_ENABLED`, `SP_TREE_OPS`, `SP_TREE_LOG`)
take `1`, `true`, `yes`, or `on` for true and `0`, `false`, `no`, or `off`
for false, in any letter case. The server logs any other value at error level
and turns the setting off. Two exceptions: `SP_DNS_SEED_DISCOVERY` then keeps
its current value, and `SP_CLOSED_REGISTRATION` then closes registration.

## Trust Anchors (Required for a Normal Start)

A normal daemon start refuses to run without all three values:

| Setting | Purpose | Accepted encoding |
|---|---|---|
| `root_pubkey` | Mesh root management key. Verifies server admission certificates; without it no certificate can be verified. | Hex Ed25519 public key (64 hex characters) |
| `genesis_pubkey` | Pins the Genesis bootstrap anchor. The network identity derives from it, and the epoch authority chain verifies from it. Its unilateral authority ends at Epoch 1 activation. | Base64 Ed25519 public key (32 bytes) |
| `release_signing_pubkey` | Verifies signed release manifests. Without it no binary can be approved and the server can never reach Tier 1. | Ed25519 public key; base64 in the daemon config, hex or base64 via `nexus-bootstrap` |

```
--root-pubkey <hex>          SP_ROOT_PUBKEY
--genesis-pubkey <b64>       SP_GENESIS_PUBKEY
--release-signing-pubkey <key>  SP_RELEASE_SIGNING_PUBKEY
```

On the Genesis server, `nexus-bootstrap` writes all three (see
[Getting Started](Getting-Started)). On a joining server, the operator sets
`root_pubkey` and `genesis_pubkey` in the config before start; onboarding
verifies the bundle against them and never writes the config
(`release_signing_pubkey` is always configured by the operator).

These are the only trust inputs. There is no supported configuration switch to
force Tier 1, skip evidence, or change quorums or thresholds: those are
compiled protocol rules, not settings.

## Network

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--http-port <N>` | `SP_HTTP_PORT` | `http_port` | `9100` | Public HTTPS API |
| `--udp-port <N>` | `SP_UDP_PORT` | `udp_port` | `51940` | Mesh tunnel and hole punching (shared) |
| `--gossip-port <N>` | `SP_GOSSIP_PORT` | `gossip_port` | `9102` | Gossip and security protocol |
| `--stun-port <N>` | `SP_STUN_PORT` | `stun_port` | `3478` | STUN NAT traversal |
| `--relay-port <N>` | `SP_RELAY_PORT` | `relay_port` | `9103` | Relay forwarding |
| `--dns-port <N>` | `SP_DNS_PORT` | `dns_port` | `5335` | Local authoritative DNS, UDP+TCP |
| `--public-dns-port <N>` | `SP_PUBLIC_DNS_PORT` | `public_dns_port` | `53` | DNS port advertised to clients (NAT-mapped to `dns_port`) |
| `--private-http-port <N>` | `SP_PRIVATE_HTTP_PORT` | `private_http_port` | `9101` | Private API (virtual mesh addresses; loopback-backed) |
| `--bind-address <addr>` | `SP_BIND_ADDRESS` | `bind_address` | `0.0.0.0` | Listen address |
| `--public-ip <addr>` | `SP_PUBLIC_IP` | `public_ip` | (auto) | Public IP for DNS records and discovery |
| `--region <code>` | `SP_REGION` | `region` | (auto) | Cloud region code (lowercase DNS label) |
| `--mesh-interface <name>` | `SP_MESH_INTERFACE` | `mesh_interface` | `nexus0` | BoringTun dataplane instance name |

All six service ports plus the private port must be unique. Every port the
server binds is unprivileged; public `53` (and `443`, where used) is reached
by firewall/NAT mapping, not by the server binding it.

## Identity and Auth

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--data-root <path>` | `SP_DATA_ROOT` | `data_root` | `data` | Data directory (identity, state, security stores) |
| `--log-level <level>` | `SP_LOG_LEVEL` | `log_level` | `info` | `trace`, `debug`, `info`, `warn`, `error` |
| `--rp-id <domain>` | `SP_RP_ID` | `rp_id` | `lemonade-nexus.local` | WebAuthn relying party ID |
| `--seed-peer <host:port>` | `SP_SEED_PEERS` | `seed_peers` | | Gossip seed peers (repeatable / comma-separated; env appends) |
| `--server-hostname <name>` | `SP_SERVER_HOSTNAME` | `server_hostname` | (auto) | Server hostname for the TLS certificate |
| `--closed-registration` | `SP_CLOSED_REGISTRATION=1` | `open_registration` | open | New identities need a device link token to join |

## DNS

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--dns-base-domain <dom>` | `SP_DNS_BASE_DOMAIN` | `dns_base_domain` | `lemonade-nexus.io` | Discovery zone suffix |
| `--dns-ns-hostname <fqdn>` | `SP_DNS_NS_HOSTNAME` | `dns_ns_hostname` | (auto) | This server's NS hostname (pins its NS slot) |
| `--dns-provider <name>` | `SP_DNS_PROVIDER` | `dns_provider` | `local` | `local` (self-hosted authoritative) or `cloudflare` |
| `--no-dns-seed-discovery` | `SP_DNS_SEED_DISCOVERY=0` | `dns_seed_discovery` | on | Do not auto-discover seed peers from tier/region DNS records |

## TLS / ACME

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--acme-provider <name>` | `SP_ACME_PROVIDER` | `acme_provider` | `letsencrypt` | `letsencrypt`, `letsencrypt_staging`, `zerossl` |
| `--acme-eab-kid <kid>` | `SP_ACME_EAB_KID` | `acme_eab_kid` | | ZeroSSL External Account Binding key ID |
| `--acme-eab-hmac-key <key>` | `SP_ACME_EAB_HMAC_KEY` | `acme_eab_hmac_key` | | ZeroSSL EAB HMAC key (base64url) |

Listeners are withheld until a usable certificate exists for the server's
FQDNs; the background ACME thread retries with backoff and upgrades the
listener in place. There is no plaintext fallback.

## DDNS

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--ddns-domain <dom>` | `SP_DDNS_DOMAIN` | `ddns_domain` | | Base domain for DDNS (Namecheap) |
| `--ddns-password <pw>` | `SP_DDNS_PASSWORD` | `ddns_password` | | DDNS password |
| `--ddns-enabled` | `SP_DDNS_ENABLED=1` | `ddns_enabled` | `false` | Enable dynamic DNS updates |

Release manifest fetching (`SP_GITHUB_RELEASES_URL`,
`SP_MANIFEST_FETCH_INTERVAL`, `SP_MINIMUM_VERSION`) controls how the server
checks for signed manifests of other versions.

## Onboarding

Server-side (a server that holds the root key accepts onboarding by default):

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--no-onboard` | | `onboard_enabled` | on | Refuse onboarding requests |
| `--mint-admission-token` | | `mint_admission_token` | | Mint a single-use enrollment token and exit (root holder only) |
| `--token-candidate <b64>` | | `mint_token_candidate` | | Candidate gossip pubkey the token binds to (required with mint) |
| `--token-ttl <sec>` | | `mint_token_ttl_sec` | `600` | Minted-token lifetime (60–3600) |

Candidate-side:

| CLI Flag | Env Var | Description |
|----------|---------|-------------|
| `--onboard-server [fqdn[:port]]` | | Run the onboarding client against an existing server (verified HTTPS by FQDN). Requires `--root-pubkey`. |
| `--onboard-addr <ip>` | | Pin the connect IP while still verifying the FQDN certificate |
| `--onboard-id <label>` | | Requested DNS label for the new server |
| `--onboard-timeout <sec>` | | Give up waiting for admission after this (default 900) |
| `--onboard-token <tok>` | `SP_ONBOARD_TOKEN` | Single-use enrollment token for immediate admission |

## Experimental: Tree Operations

| CLI Flag | Env Var | JSON Key | Default | Description |
|----------|---------|----------|---------|-------------|
| `--tree-ops` | `SP_TREE_OPS=1` | `tree_ops_enabled` | off | Ops mode: order tree writes through Tier 1 consensus, apply them after commit, and replicate the tree log |
| `--tree-log` | `SP_TREE_LOG=1` | `tree_log_enabled` | off | Read-only mode: build and replicate the tree log; tree writes keep the direct paths. Ignored when `tree_ops_enabled` is set |

These settings are experimental. They implement Phases 1 to 3 of
[Design: Tree Consensus and Threshold Storage Key](Design-Tree-Consensus-and-Storage-Key).
Keep them off in production. With both off (the default), no tree operation
is built, proposed, applied, or replicated, the tree write paths are
unchanged, and the gossip record transfer pool runs as before. Read-only mode
is the first release of the migration; the
[Tree Merge Ceremony](Tree-Merge-Ceremony) runbook moves a mesh from
read-only mode to ops mode.

With ops mode on:

- Every tree write builds one signed tree operation (`TreeOp`). The routes are
  `POST /api/join`, `/api/tree/delta`, `/api/tree/node`,
  `/api/tree/node/update/{id}`, `/api/tree/node/assignments/{id}`,
  `/api/tree/node/delete/{id}`, and `/api/mesh/heartbeat` (a `SetEndpoint`
  operation, sent only when the endpoint changed). The application root is an
  `EstablishRoot` operation that names the configured `root_pubkey`.
  `POST /api/ipam/allocate` writes no tree node. It refuses a `tunnel` block
  with `409`, because the join operation assigns tunnel addresses; `private`
  and `shared` blocks do not change.
- **Start.** A server in ops mode that has no tree log starts a new log only
  when its persistent tree is empty. With a populated tree and no log, it
  halts tree operations and logs the reason: a log based on the local tree
  would differ from every other server's log and would foreclose the
  [Tree Merge Ceremony](Tree-Merge-Ceremony). Install the ceremony's commit,
  or start from an empty tree.
- The server signs each operation with its gossip identity key, with the
  domain tag `lemonade-nexus/tree-op-signature:v1`. Replicas trust a signature
  only from a member of the block epoch's frozen Tier 1 set. The signature
  identifies the submitting server only; the principal's tree assignments
  still decide whether the change is allowed.
- **Submission.** A Tier 1 server checks the operation against its committed
  tree, adds it to its pending pool (at most 1,024 operations, 512 per
  submitting server, 32 per principal), and forwards it to the other Tier 1
  members with the `TreeOpSubmit` security message. A server outside Tier 1
  answers tree writes with 503.
- **Ordering.** When a Tier 1 server leads a view and no epoch-boundary stage
  is pending, it proposes a batch from its pool: at most 128 operations and
  48,000 bytes of operation encodings. The batch travels with the proposal;
  the proposal's `transitions_digest` commits to it.
- **Validation.** A replica votes for a batch only if every operation
  validates in order against the tree of the block's parent (the committed
  tree plus the uncommitted ancestors). The rules are the permission and
  content rules, a `base_version` match, replay against the committed
  operation ids, and freshness against the block time (signed time at most
  300 s older or 60 s newer). The block time is binding: it must be later than
  the parent's and than the previous tree block's, and within 60 s of the
  replica's clock. The state root must match (see below).
- **Commit, then apply.** A committed batch is written to the tree log
  (`data/tree/log/<height>.json`, with its commit proof) before the tree
  changes. The log height continues across epochs. A snapshot is written
  every 1,000 heights. At startup the server verifies the log, and restores the
  tree from the log when an apply was interrupted.
- **Wait, then pending.** A write route waits up to 10 s for the commit. A
  committed write answers with the status code and body of the direct path.
  After 10 s the route answers `202` with `{"status": "pending", "op_id":
  ...}`; the client polls `GET /api/tree/op/{op_id}` (`pending`, `committed`,
  or `refused` with a reason). A pending join answers `202` without a tunnel
  address; the client joins again after the commit. A heartbeat does not wait.
- **Tunnel addresses.** The join operation's apply step derives the endpoint
  address from the tree: the first free `/32` at or after a start offset
  derived from the node id, inside `10.65.0.0`–`10.127.255.254`. A deleted
  node's address is free again at once. IPAM keeps `10.64.0.0/16` for server
  addresses.
- **Server-assigned fields.** For every writer that is not an admin of the
  root node, `tunnel_ip` and `private_subnet` are server-assigned and `type`
  is fixed: a create cannot set the addresses or make a Relay node, and an
  update cannot change the addresses or the type. A group admin is not a root
  admin: tunnel addresses and relays act on the whole plane. The direct write
  paths apply the same rule.
- **Forwarding.** The server forwards between two tunnel addresses only for
  nodes that the dataplane binds to them: the peer the server installed for
  the address at join must have the node's mesh key. A Relay node is open to
  every peer only when its management key is a root admin.
- **Delete cleanup.** Every server that applies a committed delete runs the
  post-delete cleanup itself: it revokes the device credential (unless
  another node still holds the key), releases the node's IPAM records,
  removes the dataplane peer, and removes the private DNS record.
- Each node that an operation writes gets `version` = previous version + 1
  (1 for a new node). Node JSON includes `version` only when it is not 0, so
  records written with the setting off keep their exact bytes.
  `canonical_node_json` and the tree hash never include `version`.
- Committed operation ids are persisted (`data/tree/committed-ops.json`, and
  the tree log under consensus), so replay stays refused after a restart.
- **State root.** A tree block's `proposed_state_root` is
  `H(previous_root ‖ ops_digest ‖ tree_digest ‖ committed_digest)`, where
  `previous_root` is the root of the previous tree block, `tree_digest` covers
  every node's canonical encoding and version, and `committed_digest` covers
  the committed operation ids. The tree log is therefore a hash chain: a
  server that missed a tree block cannot match the next one. Tree log format
  2 uses this root; a format 1 log (from an earlier build) does not open, and
  the server halts tree operations until the log is moved aside.
- **Replication.** Every server runs the `"tree"` sync stream over the
  backbone, with the same digest and catch-up exchange as DNS records and
  account envelopes. Entries are committed log blocks keyed by height. Tier 1
  servers serve them; any certified server pulls them from Tier 1 only. An
  entry larger than one datagram travels as 16 KiB chunks. Consensus fixes
  the order; the stream only carries it.
- **Verification.** A receiving server applies an entry only when it is the
  next height, its commit proof verifies under the frozen vote keys and
  quorum of the epoch the entry names, and it chains to the server's own log
  (`previous_root`). The server takes each epoch's vote keys from its own
  verified authority chain (the Genesis certificate, then every finalized
  handoff), so it follows the chain across epochs. An entry from an epoch the
  server has not verified yet is held (at most 64 entries) until the chain
  reaches it. An entry that does not verify or does not chain is refused and
  logged, and nothing after it applies.
- **Tier 2 servers** apply the same log and serve the same tree. They never
  vote.
- **Lagging servers.** A Tier 1 server that missed a tree block does not
  halt. It applies nothing out of order, catches up through replication, and
  resumes with the next committed block.
- **Transfer pool.** In ops mode the gossip record transfer pool no longer
  carries tree records (`Digest`, `DeltaRequest`, and `DeltaResponse` are
  dropped), because the committed log does.
- **IPAM records.** Each committed block updates the tunnel records in
  `data/ipam/allocations.json` for tree-derived addresses (`10.65.0.0` and
  above). These records never expire through the lease sweep and never move
  IPAM's sequential cursor.
- **Status.** `GET /api/tree/sync` (private API, authenticated) reports the
  mode, log height, state root, health and halt reason, whether the server is
  behind, held entries, the last refused entry, and per-peer sync status.
- **Fail closed.** A server whose log does not verify, whose tree changed
  outside the log, whose populated tree has no log, or whose state disagrees
  with a certified entry that chains to its log halts tree operations: it applies, votes for, proposes, and
  accepts no tree operation, and keeps serving its last committed tree.

With read-only mode on, the server builds the tree log from the empty tree,
runs the `"tree"` stream, verifies and appends replicated entries (the merge
commit, then committed blocks), and never changes the live tree. It proposes,
votes for, and accepts no tree operation. Tree writes use the direct paths,
and the record transfer pool keeps running.
- Status codes and response bodies are otherwise those of the direct write
  paths, with these differences:
  - A join, and any other write that changes several nodes, is all or
    nothing.
  - A delete through `/api/tree/delta` also removes the link grants that
    named the deleted key, as the direct delete route does.
  - No route deletes the root node.
  - A create or update through `/api/tree/delta` also enforces one endpoint
    identifier and one mesh key per node, as the direct routes do.
  - An operation larger than 48,000 bytes is refused.
  - A join without the Ed25519 challenge (`method` other than `ed25519`)
    answers 403, as with the setting off.
  - Without a configured submitter the write routes answer 500. They never
    fall back to the direct paths.

Limits:

- **Writes on Tier 1 only.** A Tier 2 server answers tree writes with 503. It
  cannot forward a write: replicas trust operation signatures from the frozen
  Tier 1 set only, and no finalized list of admitted submitters exists. A
  root-signed admission certificate is identity, not authority.
- **Same starting tree.** Servers agree on state roots only if every server
  started from the same tree: an empty one, or the merge commit. A new
  ops-mode tree log therefore starts only from an empty tree (see **Start**).
  A server whose log base differs, for example a log an earlier build started
  from a populated tree, refuses every replicated entry (the status names it).
  Existing, divergent trees need the [Tree Merge Ceremony](Tree-Merge-Ceremony).
- **Unproved commits.** A block that committed while the three blocks behind
  its commit were no longer held is logged without a commit proof. Peers
  refuse that copy and take the entry from another Tier 1 server.
- **Height is not certified.** The log height is not inside the commit proof.
  A replicated entry is applied only when it chains to the log head, so a
  renumbered entry is refused, not applied.
- **Replication index.** The sync stream indexes at most 1,048,576 heights;
  later heights are not offered.
- **Tree changed outside the log.** Turning the setting off, writing the tree,
  and turning it on again halts tree operations at startup. The server does
  not overwrite either side.
- **Server-filled base version.** Current clients send no base version, so
  the server reads it from the committed tree. When a concurrent write makes
  an operation stale, the server rebuilds it from the new state, at most three
  times. This keeps today's last-writer-wins behavior.
- **Asserted principals.** Session routes (`/api/tree/node*`, the heartbeat)
  carry no signature by the principal; the submitting Tier 1 server asserts
  the principal. The join device signature covers only the server challenge.
  The join parameters, including the link-token group, are asserted by the
  submitting server, and link-token validity is local state.
- **Root key from configuration.** Replicas accept an `EstablishRoot`
  operation only for their own configured `root_pubkey`. Tier 1 servers with
  different configured keys establish no root.
- **Versions while on only.** The direct paths do not maintain `version`.
  After the setting is turned off, a delta update replaces the stored record,
  including its version.

## Threshold Storage Key

Storage encryption is always on. There is no CLI flag, environment variable,
or JSON key for it. `--storage-key`, `--storage-files`, `SP_STORAGE_KEY`,
`SP_STORAGE_FILES`, and the `storage_key_enabled` and `storage_files_enabled`
JSON keys were removed. A unit file or config that still names them starts
normally and ignores them.

A node with fewer than five storage holders never creates a data key. It
starts and runs normally with its files unchanged. This is the pre-key state,
not an error and not a reduced-security mode. `/api/storage/status` reports
the vault mode and phase; it does not report the holder count.

**The B3 external review of the `storage-threshold` library paths was not
commissioned.** The flag was removed with that gate waived, not satisfied. The
design cites an audit of `frost` v0.6.0, while the lockfile ships
`frost-core` and `frost-ristretto255` 2.2.0, which that audit does not cover.
CI runs no `cargo test` step.

With the setting on:

- **Holder plans in consensus.** Tier 1 finalizes storage records as block
  payloads (`StorageHolderPlan`, `StorageKeyRotation`). At each epoch boundary
  the holders are the finalized eligible servers (Tier 1 and Tier 2), at most
  50, ranked by the finalized checkpoint. The first key needs at least 5
  holders. The shares refresh every epoch; the key rotates when the holder set
  grows, when `t` changes, and when block time is 24 h past the key's
  creation. A rotation keeps at least 3 holders; below 3 the last plan stays.
- **Records outside Tier 1.** Every server receives each finalized record
  with its commit proof (`StoragePlanProof`) and verifies it against the
  committing epoch's vote keys. A server asks a Tier 1 member for the live
  records every 30 s (`StoragePlanRequest`).
- **Key sessions.** Holders run the key generation or refresh over the
  security transport (`StorageKeyPackage`). Secret packages are sealed to
  their recipient with the session bound inside the seal. A session without a
  finalized plan after 120 s of block time is replaced; a retry leaves out the
  holders that never sent their round-1 package.
- **Unlock.** A server unlocks its data key by sending `StorageUnlockRequest`
  to the holders of the plan its wrapped key names. Each holder first
  challenges the server with the `StorageUnlock` attestation purpose, bound to
  that request, and answers only a passing verdict, with a partial sealed to
  the server (`StorageUnlockPartial`). A holder outside Tier 1 may challenge
  for this purpose only. Per holder: one pending request per requester, 8
  requests per requester per epoch, 64 pending requests in all; replayed
  requests are refused. With fewer than `t` partials the server retries with
  backoff (5 s to 60 s) and stays locked.
- **Data key.** On first use the server creates a 32-byte data key, wraps it
  to the storage public key, and proves the unwrap through the holders. After
  a rotation it rewraps the key from memory. A key wrapped to the previous
  storage key still unlocks through the epoch after the rotation's effective
  epoch, then never. Covered files are encrypted whenever a data key exists
(below).
- **Share storage.** When the host can seal (nexus-attestd with Seal and
  Unseal), the holder's shares are sealed beside the gossip identity under the
  domain `storage-share`: `data/sealed/storage-share.sealed`, with the same
  upgrade staging (`storage-share.next.sealed`). A host that cannot seal keeps
  `data/security/storage/sealed/storage-share.share` (mode 600, under the
  machine-bound wrapping of the epoch vote keys). A share found in that file
  on a host that can now seal moves into the sealed store after the sealed
  copy unseals to the same bytes. A sealed share that reports Missing,
  PolicyMismatch, or Corrupt is never replaced by the file copy.
- **Files.** `data/security/storage/records.json` (the live records and their
  proofs) and `data/security/storage/data-key.json` (the wrapped data key).
- **nexus-attestd.** The daemon must know the `StorageUnlock` purpose (value
  4). An older daemon refuses the challenge, so the holder's attestation fails
  closed and the requester stays locked.

Limits:

- **Hosts without sealing.** Shares stay in the machine-bound file wrapping
  (design B6 limit).
- **Holder loss is found by sessions.** A holder that goes away is replaced
  when a session runs: at the next epoch boundary, at the daily rotation, or
  after a session timeout. A holder that sends round 1 and then withholds its
  round-2 packages is not left out by the retry rule; the session fails until
  the next boundary or rotation.
- **Records need the epoch authority.** A server verifies a record only for
  an epoch whose authority its driver verified. A server whose authority lags
  falls behind on records and drops out of later holder sets by silence.
- **Records read from disk.** After a restart the server uses its stored
  records to unlock, but it wraps no new data key until a fresh proof
  confirms the current record.
- **Restart during a session.** A holder that restarts during a session does
  not resume it; the session retries.
- **Payload order.** Tier 1 asks the tree-batch handler before the storage
  handlers, so a constant tree backlog delays storage records.
- **Grace period.** A server that stays offline past the grace period after a
  rotation cannot unlock the data key wrapped to the old storage key.

## JSON Config Example

```json
{
  "http_port": 9100,
  "udp_port": 51940,
  "gossip_port": 9102,
  "stun_port": 3478,
  "relay_port": 9103,
  "dns_port": 5335,
  "public_dns_port": 53,
  "private_http_port": 9101,
  "data_root": "/var/lib/lemonade-nexus/data",
  "region": "us-west",
  "dns_base_domain": "lemonade-nexus.io",
  "server_hostname": "ns1",
  "acme_provider": "letsencrypt",
  "log_level": "info",
  "root_pubkey": "<hex ed25519 root management key>",
  "genesis_pubkey": "<base64 ed25519 genesis anchor>",
  "release_signing_pubkey": "<release signing key>",
  "seed_peers": ["<server-ip>:9102"]
}
```

The packaged bootstrap writes this file for you. Edit it with `sudoedit`; the
service unit mounts it read-only.

## Command-Mode Flags

These flags select a one-shot command instead of running the daemon:

| Flag | Description |
|----------|-------------|
| `--first-run` | Bootstrap the node identity and print the trust anchors to pin (`Identity pubkey` = root, `Gossip pubkey` = Genesis). One-time, per node. |
| `--verify-platform [blob]` | Verify this host's platform evidence (AMD signature chain, guest policy, memory-encryption guarantees) and exit. Optional: a pre-captured evidence blob instead of the local helper. |
| `--enroll-server <pubkey> <id>` | Root-side: enroll a server identity (used by the onboarding approve path and manual enrollment). |
| `--revoke-server <pubkey>` | Root-side: revoke a server identity. |
| `--enroll-tpm-ak <b64>` | With enrollment: pin the server's platform binding key (base64 DER SPKI) in its certificate. |
| `--enroll-tpm-ek-cert <path>` | With enrollment: attach the server's TPM EK certificate (PEM) for audit/validation. |
| `--add-manifest <path>` | Load a signed release manifest from a local file and exit. |
| `--sign-tree-merge <preimage> <out>` | Root-side: sign a canonical tree merge preimage for this network with the root management key, write the base64 signature to `<out>`, and exit. See [Tree Merge Ceremony](Tree-Merge-Ceremony). |
| `--install-tree-merge <commit.json>` | Verify a signed tree merge commit against the configured `root_pubkey` and network, write it as tree log height 1, and exit. Run with the service stopped. |
| `--github-releases-url <url>` | Override the GitHub releases URL for manifest fetching (env: `SP_GITHUB_RELEASES_URL`). |
| `--manifest-fetch-interval <sec>` | Manifest fetch interval (env: `SP_MANIFEST_FETCH_INTERVAL`). |
| `--minimum-version <ver>` | Minimum client version gate (env: `SP_MINIMUM_VERSION`). |

`--config <path>`, `--data-root <path>`, `--log-level <level>`, and the
port flags apply to the command as well where relevant. Note two current
mismatches in the `--help` text: it still lists `--require-peer-confirmation`,
which the binary does not accept (see
[Retired and Inert Settings](#retired-and-inert-settings)), and it does not
list the parsed `--onboard-timeout` flag.

## Retired and Inert Settings

The following settings no longer do anything and are not recognized:

- `require_tee_attestation`, `tee_platform_override`,
  `require_binary_attestation`, `tee_attestation_validity_sec` — the old TEE
  knobs were unreachable, inert, or dead. Attestation is enforced by the
  compiled protocol, not by configuration.
- `admission_quorum_ratio`, `enrollment_*`, `onboard_min_tier1_for_vote`,
  `--require-peer-confirmation` — the old quorum/enrollment votes were
  removed with the retired governance system. Admission is root-gated
  approval or a single-use token.

These inert settings are listed so that older runbooks and environment files
can be read correctly; remove them from your configuration when you touch
it.

### Files under the data key (Phase 7)

It implements Phase 7 of the design (sections B9, B10, B5a) and runs on every
node. There is no way to turn it off.

Migration is one-way. Once the vault records `encrypted`, a node that cannot
reassemble the data key serves nothing that reads covered files, with no
plaintext fallback and no timeout. Back up `data/security/storage/` and
`data/sealed/` before upgrading a node. If those are lost after the migration
the data key cannot be recovered, and reinstalling an older binary does not
return the node to service.

Covered files, under the data root: `identity/keypair.enc`,
`identity/jwt_secret.hex`, `identity/ddns_credentials.enc`,
`account/replica.json`, `tree/nodes/*.json`, `tree/deltas/*.json`, and
`tree/log/*.json`. Each file is replaced in place by an encrypted object
(XChaCha20-Poly1305 under a key derived from the data key; the associated data
binds the purpose `storage-file-at-rest`, the file's domain, its relative
path, and the data key id). The state is in
`data/security/storage/vault-state.json`.

Migration runbook:

1. Start the server. Files stay plaintext until the data key exists and one
   unlock through the holders has proved it, which needs at least five
   holders.
2. The server encrypts each covered file to `<file>.vault-new`, asks the
   holders for a new unlock round trip, then decrypts every staged file and
   compares it with the plaintext. Only then does it record `encrypted`,
   overwrite each plaintext (best effort), and replace it with the staged
   copy. The log line `migration complete; plaintext removed` marks the end.
3. A server that cannot reach `t` holders keeps its plaintext and retries. A
   crash at any step resumes from the state file without data loss.
4. After the migration, each start waits for the data key before it starts
   the services that read covered files (tree, node identity, auth, DDNS,
   account data, HTTP API). Gossip, attestation, and holder duties run while
   it waits, so a locked node still answers peer unlock requests using its own
   share. With fewer than `t` holders reachable the server serves nothing that
   needs the files and keeps waiting. It never reads them as plaintext.

Rotation runbook:

- The data key rotates 30 days after the last migration or rotation, on the
  server's local clock. It is per server, not a consensus rule.
- On demand (for example after a suspected compromise), a root administrator
  calls `POST /api/storage/rotate-data-key` on the private API.
  `GET /api/storage/status` reports the mode, phase, and last rotation time.
- The server creates a new data key, wraps it to the current storage public
  key in `data-key.next.json`, proves the unwrap through the holders,
  re-encrypts every file to `<file>.vault-new`, and verifies each. The
  replacement of `data-key.json` is the switch point. Before it, an
  interrupted rotation is discarded and starts again; after it, the staged
  files replace the old ciphertext.

Limits:

- Not covered yet: the TLS and ACME private keys (the HTTP server loads them
  by path), the ACL rows (SQLite, keyed from the gossip identity), the epoch
  vote keys, and `wrap_local.key`. The vote keys and the file share store are
  read before the unlock, so moving them, or the local secret they depend on,
  under the data key would stop a cold start; `wrap_local.key` therefore stays.
- CLI modes do not unlock the data key. After the migration, CLI modes that
  read the node identity or the tree log (`--enroll-server`, release signing,
  tree merge tools) fail closed.
- The gossip record transfer pool (`tree/retained_deltas`) stays plaintext.
- Rollback of a file to an older ciphertext under the same data key is not
  detected.
- Overwriting plaintext is best effort, as in Phase 6.
