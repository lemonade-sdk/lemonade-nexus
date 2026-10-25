---
layout: default
title: Client SDK Overview
---

# Client SDK Overview

For the full API reference with code examples, see the [SDK Guide](SDK-Guide).

## What the SDK Does

`LemonadeNexusSDK` handles everything a client application needs to join and
participate in the mesh VPN:

- **Identity** — Ed25519 keypair generation, seed derivation, persistence
- **Authentication** — Ed25519 challenge-response (primary) and passkey
  (backup); password is a deprecated server stub
- **Network joining** — one call does auth, node creation, IP allocation,
  and mesh configuration
- **Mesh P2P** — automatic peer discovery, heartbeat, direct tunnels between
  clients, relay fallback
- **Tree operations** — read/create/update/delete nodes in the permission
  tree
- **Local services** — publish a local port to mesh peers and open egress
  bridges to peer services
- **Latency monitoring** — probe servers, auto-switch to the best one
- **Tier 1 verification** — tree, session, and private-API traffic goes only
  to Tier 1 servers the SDK verifies from the pinned Genesis key

The mesh dataplane is in-process userspace BoringTun plus a smoltcp netstack:
no kernel module, no TUN device, no elevated privileges, on every platform.

## Language Bindings

| Language | Interface | Header |
|----------|-----------|--------|
| C++ | `lnsdk::LemonadeNexusClient` class | `LemonadeNexusSDK/LemonadeNexusClient.hpp` |
| C | `ln_*` FFI functions | `LemonadeNexusSDK/lemonade_nexus.h` |
| Dart/Flutter | Generated FFI wrapper (`lib/src/sdk/`) | Consumes the C ABI |

The shared library exports only the `ln_*` C API (hidden visibility); the C++
class and the Dart wrapper both sit on top of it.

## Tier 1 Servers

Only Tier 1 servers hold the permission tree. A Tier 2 server refuses every
tree route, so the SDK never sends one there. Pin the network's Genesis public
key (`genesis_pubkey` in the server config) before the first tree call:

- C++: `client.set_genesis_key(genesis_b64, min_epoch)`
- C: `ln_set_genesis_key(client, genesis_b64, min_epoch)`

The SDK then:

1. Walks the authority chain from the key (`GET /api/tier1/authority` on any
   server) and verifies the Genesis certificate and every finalized handoff
   with its commit proof.
2. Asks each candidate server (the configured servers, and the servers they
   list in `/api/servers` that are members) for an endpoint proof over a fresh
   nonce (`GET /api/tier1/proof`). It keeps a server only when a member of the
   verified epoch signed a proof for that exact host and port, in that epoch.
3. Sends `/api/auth*`, `/api/join`, and the other tree routes only to those
   servers. It starts with the server that answered last and fails over to
   the next one when a server does not answer or answers `421`. A session is
   bound to the server that issued it; private-API calls go only to that
   server, and only while it is still a verified Tier 1 server.

It verifies again every five minutes and after a server refuses a tree route.
`refresh_tier1()` / `ln_tier1_refresh()` verifies now, and
`tier1_membership()` / `ln_tier1_membership()` returns the last result.

Without a pinned key, a chain that does not verify, a stale epoch, or no
reachable verified server, the SDK sends no tree request: the call fails with
`http_status` 0 (`LN_ERR_CONNECT`) and an error that says why. Store the
returned `epoch` and pass it as `min_epoch` on the next start: the SDK then
refuses an older membership. A client with no stored epoch can be held at an
old epoch only if every server it reaches withholds the newer handoffs and
every member it reaches signs the older epoch.

## Authentication Status

| Method | Status |
|--------|--------|
| Ed25519 challenge-response | Primary. Requires an identity (`set_identity` / `ln_set_identity`). Auto-registers new pubkeys on first use. |
| Passkey / WebAuthn | Backup. Challenge bound to the user; assertion verified server-side. |
| Password | **Deprecated.** The server stub always fails; the SDK keeps the functions for compatibility. |
| Token link | One-time device-link tokens for adding devices to an account group. |

## Linking

Build the shared library first:

```bash
cmake --build build --target LemonadeNexusSDKShared --parallel
```

For a C/C++ consumer, link against the shared library (or the static
`LemonadeNexusSDK` target when building inside this CMake project):

```cmake
find_library(LEMONADE_NEXUS_SDK liblemonade_nexus_sdk REQUIRED)
target_link_libraries(myapp PRIVATE ${LEMONADE_NEXUS_SDK})
```

The shared library is self-contained: OpenSSL, libsodium, BoringTun, and the
netstack are embedded.

## Platform Notes

- **macOS:** builds are CI-verified; use `-DOPENSSL_FORCE_BUNDLED=ON` for
  distributable binaries.
- **Windows:** build definitions exist; CI is currently disabled, so validate
  locally.
- The SDK ships as a native dynamic library (`.so` / `.dylib` / `.dll`);
  there is no per-platform VPN backend to manage.
