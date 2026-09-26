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
   (permission tree, IPAM, ACL, DNS, relay, routing, auth).
3. Starts the security mesh: derives the network ID from the pinned Genesis
   anchor, authenticates any persisted epoch/anchor state as *candidate* data
   (see [Security — Restored authority](Security#restored-authority)), and
   begins the security driver. The attestation profile gaps are logged at
   this point.
4. Brings up the userspace dataplane: BoringTun sessions on UDP `51940`, the
   smoltcp netstack for the client plane (`10.64.0.0/10`) and the server
   backbone (`172.16.0.0/22`), and TCP forwards from the virtual addresses to
   the loopback private listener on `9101`.
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
  `/api/stats`, `/api/servers`, `/api/tls/status`), authentication
  (`/api/auth*`), client join (`/api/join`), and server onboarding
  (`/api/onboard/info|challenge|request|poll|ack`).
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
  platform evidence. The helper holds the TPM/IMA access; the server holds
  the identity and never touches the TPM. See [Attestation](Attestation).

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
| Replication | Gossip (signed, root-certificate-gated) | Security envelopes on the gossip transport |
| Recovery | Rebuilt/synced from peers | Reauthenticated from the pinned Genesis anchor at startup |

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
├── tree/                  # Permission tree nodes and the signed transfer pool
├── ipam/                  # IP allocations
├── attestation/           # Evidence cache
├── security/              # Durable security stores
│   ├── epoch store (bootstrap cert, current epoch, authority history)
│   ├── hotstuff-safety-<epoch>.json / hotstuff-commit-<epoch>.json
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
  read-only for the service; onboarding write-back (root/Genesis keys and
  seed peers) is the one documented config mutation.

## API Routing

Request handlers are CRTP-structured services. Each handler registers its
public routes on the public server and its private routes on the private
server through one registration pass, which is re-runnable because the
listener object is swapped when TLS is activated in the background:

| Handler | Public routes | Private routes |
|---|---|---|
| `PublicApiHandler` | `/api/health`, `/api/stats`, `/api/servers`, `/api/tls/status` | — |
| `AuthApiHandler` | `/api/auth`, `/api/auth/challenge`, `/api/auth/register` | — |
| `TreeApiHandler` | `/api/join` | Tree node/delta/children operations |
| `OnboardApiHandler` | `/api/onboard/info`, `challenge`, `request`, `poll`, `ack` | `/api/onboard/pending`, `approve/{id}`, `deny/{id}`, `token` |
| `MeshApiHandler`, `RoutingApiHandler`, `RelayApiHandler`, `CertApiHandler`, `AccountDataApiHandler`, `AdminApiHandler` | (discovery reads where applicable) | Authenticated application operations |

The retired `/api/trust/*`, `/api/enrollment/status`, and
`/api/governance/*` routes no longer exist. The matching C ABI functions
remain exported for compatibility and return `LN_ERR_UNSUPPORTED`.
