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
