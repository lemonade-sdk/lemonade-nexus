---
layout: default
title: Client SDK Overview
---

# Client SDK Overview

For the full SDK reference with code examples, see the [SDK Guide](SDK-Guide.md).

## What the SDK Does

The LemonadeNexusSDK handles everything a client application needs to join and participate in the mesh VPN:

- **Identity** — Ed25519 keypair generation/derivation, persistence
- **Authentication** — challenge-response, passkey, password
- **Network joining** — composite endpoint that does auth + node creation + IP allocation + WG config in one call
- **WireGuard tunnel** — cross-platform tunnel bring-up/tear-down
- **Mesh P2P** — automatic peer discovery, heartbeat, direct tunnels between clients
- **Tree operations** — read/create/update/delete nodes in the permission tree
- **Latency monitoring** — probe servers, auto-switch to the best one

## Language Bindings

| Language | Interface | Header |
|----------|-----------|--------|
| C++ | `LemonadeNexusClient` class | `LemonadeNexusClient.hpp` |
| C | `ln_*` FFI functions | `lemonade_nexus.h` |
| Swift | `NexusSDK` wrapper | Uses C FFI via `CLemonadeNexusSDK` |

## Linking

```cmake
target_link_libraries(myapp PRIVATE LemonadeNexusSDK sodium ssl crypto)
```

Swift Package Manager:
```swift
.linkedLibrary("LemonadeNexusSDK"),
.linkedLibrary("sodium"),
.linkedLibrary("lemonade_boringtun_ffi"),
```
