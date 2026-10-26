---
layout: default
title: Architecture
---

# Architecture

## Table of Contents
- [Components](#components)
- [Startup and Lifecycle](#startup-and-lifecycle)
- [Service Boundaries](#service-boundaries)
- [Application State vs Security State](#application-state-vs-security-state)
- [Storage](#storage)
- [API Routing](#api-routing)

## Components

| Component | Path | Responsibility |
|---|---|---|
| Server | `projects/LemonadeNexus/` | Public and private APIs, mesh transport, application services, security runtime |
| Security protocol | `projects/LemonadeNexus/{include,src}/Security/` | Attestation, eligibility, HotStuff consensus, epochs, FROST authority, durable security stores |
| Evidence helper | `projects/LemonadeNexusAttestd/` | Privilege-separated `nexus-attestd` daemon (TPM/IMA evidence only) |
| SDK | `projects/LemonadeNexusSDK/` | C++ client SDK and C ABI (`ln_*`) |
| Sidecar | `projects/LemonadeNexusSidecar/` | Sidecar integration |
| Client | `apps/LemonadeNexusClient/` | Flutter desktop client (Dart FFI over the C ABI) |
| Rust crates | `crates/` | BoringTun FFI, virtual netstack (smoltcp), FROST integration |
| Packaging | `packaging/`, `cmake/packaging.cmake` | DEB/RPM/productbuild/NSIS definitions, systemd units, nftables DNS NAT |

The server separates **mesh transport**, **application services**, and the
**security protocol**. A transport connection or a valid certificate does not
grant Tier 1 authority; see [Security](Security).

## Startup and Lifecycle

On a normal start (`main.cpp`), the server:

1. Loads configuration (JSON file, CLI, environment — see
   [Configuration](Configuration)) and validates the three trust anchors
   (`root_pubkey`, `genesis_pubkey`, `release_signing_pubkey`). A normal start
   without them is refused.
2. Opens crypto, file storage, key wrapping, and the application services
   (permission tree, IPAM, ACL, DNS, relay, routing, auth). The permission
   tree starts closed: it loads only when finalized membership names this
   server as Tier 1 (see [The tree on Tier 1 only](#the-tree-on-tier-1-only)).
3. Starts the security mesh: derives the network ID from the pinned Genesis
   anchor, authenticates any persisted epoch/anchor state as *candidate* data
   (see [Security — Restored authority](Security#restored-authority)), and
   begins the security driver. The attestation profile gaps are logged at
   this point.
4. Brings up the userspace dataplane: BoringTun sessions on UDP `51940`, the
   smoltcp netstack for the client plane (`10.64.0.0/10`) and the server
   backbone (`172.16.0.0/22`), and TCP forwards from the virtual addresses to
   the loopback private listener on `9101`. Gossip binds virtual UDP on the
   backbone address for Tier 1 catch-up sync; the netstack delivers those
   datagrams in process, with no socket bridge.
5. Starts the HTTP listeners. **Both control-plane listeners are withheld
   until usable TLS certificates exist** — HTTPS or nothing, no plaintext
   fallback. A background ACME thread retries with backoff and upgrades the
   listener in place.
6. Registers discovery DNS records (SEIP, `_config` TXT, `private.`/`backend.`
   A records, NS slot, tier records) and starts gossipping with the seed
   peers.

Shutdown is ordered: security driver, gossip, dataplane, then HTTP.

## Service Boundaries

- **Public API (TCP `9100`):** discovery and health (`/api/health`,
  `/api/stats`, `/api/servers`, `/api/tls/status`), Tier 1 membership
  (`/api/tier1/authority`, `/api/tier1/proof`), authentication
  (`/api/auth*`), client join (`/api/join`), and server onboarding
  (`/api/onboard/info|challenge|request|poll|ack`). Authentication and join
  are served by Tier 1 servers only.
- **Private API (virtual mesh addresses, TCP `9101`, loopback-backed):**
  authenticated application operations — tree, IPAM, mesh, routing, relay,
  certificates, account data, onboarding administration
  (`/api/onboard/pending|approve|deny|token`). Every private route is
  JWT-gated.
- **Security transport (UDP `9102`):** signed gossip envelopes carrying
  attestation, consensus, DKG, and epoch messages. Authentication, size
  bounds, per-peer budgets, and deduplication are applied before any parse;
  envelopes are never relayed. Sensitive pairwise DKG payloads are additionally
  sealed to the recipient.
- **Evidence helper (local socket):** the server asks `nexus-attestd` for
  platform evidence, routes SVSM AK activation to it, and has it seal and
  unseal the boot set (the gossip identity key) to PCR 8 and 9. The helper
  holds the TPM/IMA access; the server holds the identity and never touches the
  TPM. See [Attestation](Attestation) and
  [Sealed boot set](Design-Tree-Consensus-and-Storage-Key#b6-sealing-the-boot-set).

## The tree on Tier 1 only

Only a current Tier 1 member, by finalized epoch membership, holds the
permission tree. A Tier 2 server is a pure proxy of end-to-end encrypted data
and connections. It does not store, replicate, read, write, redirect, or
forward the tree. It does not serve the tree API, and it does not issue or
accept a client session. `TreeRole` (`Tree/TreeRole.hpp`) applies the role
from the membership snapshot on every security tick:

| Membership | Tree | Files |
|---|---|---|
| Member | Loaded and served. The tree log, its replication, and endpoint forwarding run. | Kept |
| Not a member | Closed. Every tree route answers `421` with only `{"error":"this server does not serve the tree"}`: no redirect and no data. The dataplane forwards no packet between peers. | Deleted: each file under `data/tree/` is overwritten with zeros, flushed, and removed (best effort) |
| Not known (before Epoch 1, or before the persisted state verifies) | Closed and not served | Kept |

The gated routes are `/api/join`, `/api/auth*`, `/api/link/*`, `/api/tree/*`,
`/api/ipam/*`, `/api/mesh/*`, `/api/routing/*`, `/api/chats*`,
`/api/account/keys/*`, `/api/certs/*`, and the root-admin routes
(`/api/relay/register`, `/api/onboard/pending|approve|deny|token`,
`/api/storage/*`, `/api/credentials/unrevoke`), whose admin permission is a
tree permission (`Api/TreeRouteGate.hpp`).

A server that enters Tier 1 starts from its files, which are empty on a
server that was Tier 2, and catches up through Tier 1 tree log replication.
A server that leaves Tier 1 closes
the tree, stops the tree services, and deletes the files in the same tick
that its last epoch ends.

The Genesis server issues the bootstrap certificate and never becomes Active,
so it holds no tree unless a later epoch selects it. Before Epoch 1 activates
no server holds the tree, and no client can join.

Clients find Tier 1 servers without trusting the server that answers. Any
server returns the authority chain (`GET /api/tier1/authority`), and the
client verifies it against its pinned Genesis key. Only a current member
answers `GET /api/tier1/proof` with a signature, by its node identity key,
over the client's nonce, the network, the epoch, and the host and port the
client reached. See [Client SDK](Client-SDK).

**Fallback:** if no tunnel address exists, no private listener is created and
the private routes are registered on the public listener instead. The server
logs a security warning (`SECURITY: No tunnel_bind_ip configured — private
API routes are exposed on the public HTTP server`). Route authentication still
applies; network isolation does not.

## Application State vs Security State

Two distinct state domains exist, with different authority models:

| | Application state | Security state |
|---|---|---|
| Contents | Permission tree, IPAM allocations, ACL grants, DNS records, relay data, account data | Bootstrap certificate, epochs, vote keys, authority chain, consensus stores, eligibility observations, revocation cache |
| Authority | Permission rules and identity/root-gated mutation paths (transitional; not yet consensus-authorized) | Finalized consensus state only |
| Replication | Gossip (signed, root-certificate-gated). The tree exists on Tier 1 members only. | Security envelopes on the gossip transport |
| Recovery | Rebuilt/synced from peers | Reauthenticated from the pinned Genesis anchor at startup |

Account data replicates only in part: group-key envelopes sync between
servers over the backbone, and each receiver re-checks the uploading
device's permission against its own tree. A Tier 2 server holds no tree, so
it accepts no envelope. Encrypted chat blobs stay on the server that stored
them. See [IP Ranges](IP-Ranges) for the envelope rules.

Receiving an author-signed application record transfers it; it does not
authorize or apply a remote mutation. See
[Security — Application Authority Gaps](Security#application-authority-gaps).

## Storage

The data root (packaged: `/var/lib/lemonade-nexus/data`) holds:

```text
data/
├── identity/              # Node identity (wrapped keypair), gossip keypair,
│                          # server certificate, JWT secret, hostname
├── mesh/                  # BoringTun dataplane state
├── certs/                 # ACME TLS certificates per domain
├── tree/                  # Permission tree nodes, delta log, transfer pool, and
│                          # tree log (Tier 1 members only; deleted on Tier 2)
├── ipam/                  # IP allocations
├── attestation/           # Evidence cache
├── security/              # Durable security stores
│   ├── epoch store (bootstrap cert, current epoch, authority history)
│   ├── hotstuff-safety-<epoch>.json / hotstuff-commit-<epoch>.json
│   ├── hotstuff-chain-<epoch>.json  # block headers the high certificate names
│   ├── eligibility store
│   └── revocation/        # AMD KDS CRL cache
├── acl.db                 # SQLite ACL store (application state)
└── ...
```

- **File-backed records** are signed JSON envelopes written through a durable
  write path (temporary file + rename + filesystem sync; the Windows branch
  commits the rename explicitly).
- **SQLite** backs the application ACL store.
- The security stores treat corruption as a distinct state from absence:
  corrupt files fail closed; they are never silently treated as absent.
- The trust configuration file is **outside** the data root and mounted
  read-only for the service; onboarding only reads it (reporting the approved
  anchors and recommended seed peers) and makes no config mutation.

## API Routing

Request handlers are CRTP-structured services. Each handler registers its
public routes on the public server and its private routes on the private
server through one registration pass, which is re-runnable because the
listener object is swapped when TLS is activated in the background:

| Handler | Public routes | Private routes |
|---|---|---|
| `PublicApiHandler` | `/api/health`, `/api/stats`, `/api/servers`, `/api/tls/status` | — |
| `Tier1ApiHandler` | `/api/tier1/authority`, `/api/tier1/proof` | — |
| `AuthApiHandler` | `/api/auth`, `/api/auth/challenge`, `/api/auth/register` | — |
| `TreeApiHandler` | `/api/join` | Tree node/delta/children operations |
| `OnboardApiHandler` | `/api/onboard/info`, `challenge`, `request`, `poll`, `ack` | `/api/onboard/pending`, `approve/{id}`, `deny/{id}`, `token` |
| `MeshApiHandler`, `RoutingApiHandler`, `RelayApiHandler`, `CertApiHandler`, `AccountDataApiHandler`, `AdminApiHandler` | (discovery reads where applicable) | Authenticated application operations |

A pre-routing gate runs before every handler: on a server that does not
hold the tree, each tree route answers `421` before its handler runs (see
[The tree on Tier 1 only](#the-tree-on-tier-1-only)).

The retired `/api/trust/*`, `/api/enrollment/status`, and
`/api/governance/*` routes no longer exist. The matching C ABI functions
remain exported for compatibility and return `LN_ERR_UNSUPPORTED`.
