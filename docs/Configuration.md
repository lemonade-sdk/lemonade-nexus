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
| `--closed-registration` | `SP_CLOSED_REGISTRATION` | `open_registration` | open | New identities need a device link token to join |

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
| `--ddns-enabled` | `SP_DDNS_ENABLED` | `ddns_enabled` | `false` | Enable dynamic DNS updates |

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
| `--tree-ops` | `SP_TREE_OPS` (any value) | `tree_ops_enabled` | off | Order tree writes through Tier 1 consensus and apply them after commit (Phase 2) |

This setting is experimental. It implements Phases 1 and 2 of
[Design: Tree Consensus and Threshold Storage Key](Design-Tree-Consensus-and-Storage-Key).
Keep it off in production. With the setting off, no tree operation is built,
proposed, or applied, and the tree write paths are unchanged.

With the setting on:

- Every tree write builds one signed tree operation (`TreeOp`). The routes are
  `POST /api/join`, `/api/tree/delta`, `/api/tree/node`,
  `/api/tree/node/update/{id}`, `/api/tree/node/assignments/{id}`,
  `/api/tree/node/delete/{id}`, and `/api/mesh/heartbeat` (a `SetEndpoint`
  operation, sent only when the endpoint changed). The application root is an
  `EstablishRoot` operation that names the configured `root_pubkey`.
  `POST /api/ipam/allocate` writes no tree node and does not change.
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
  addresses and `/api/ipam/allocate`.
- Each node that an operation writes gets `version` = previous version + 1
  (1 for a new node). Node JSON includes `version` only when it is not 0, so
  records written with the setting off keep their exact bytes.
  `canonical_node_json` and the tree hash never include `version`.
- Committed operation ids are persisted (`data/tree/committed-ops.json`, and
  the tree log under consensus), so replay stays refused after a restart.
- **State root.** A tree block's `proposed_state_root` is
  `H(previous_root ‖ ops_digest ‖ tree_digest)`, where `previous_root` is the
  root of the previous tree block and `tree_digest` covers every node's
  canonical encoding and version. The tree log is therefore a hash chain: a
  server that missed a tree block cannot match the next one.
- **Fail closed.** A server whose log does not verify, whose tree changed
  outside the log, or that sees a committed block it cannot apply against its
  own log halts tree operations: it applies, votes for, proposes, and accepts
  no tree operation, and keeps serving its last committed tree.
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

- **Tier 1 only.** Only Tier 1 servers order and apply tree operations. Tier 2
  servers neither receive committed blocks nor accept writes (Phase 3 adds log
  replication). A Tier 2 server cannot forward a write, because replicas trust
  operation signatures from the frozen Tier 1 set only.
- **Same starting tree.** A new tree log starts from the server's current
  tree. Replicas agree on state roots only if every Tier 1 server started from
  the same tree, for example an empty one. Existing, divergent trees need the
  merge ceremony (Phase 3, design A9).
- **Missed blocks.** A server that missed a committed tree block (for example
  through restart sync, which carries block headers only) halts tree
  operations at the next tree block. Phase 3 replication repairs it.
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
- **Snapshot ids.** A snapshot's committed operation ids are not covered by
  the state root. A snapshot whose ids were edited on disk is not detected.
- **IPAM records.** Tree-derived addresses are not written to
  `data/ipam/allocations.json`; the delete cascade's IPAM release finds no
  record for them.
- **Versions while on only.** The direct paths do not maintain `version`.
  After the setting is turned off, a delta update replaces the stored record,
  including its version.

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
