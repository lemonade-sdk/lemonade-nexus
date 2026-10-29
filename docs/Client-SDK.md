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

A client that has no stored key can discover it on first connect:

- C++: `client.discover_genesis_key(hosts)`
- C: `ln_discover_genesis_key(client, hosts_json, &json)`

Discovery runs only when no key is pinned. It asks each candidate server for
`GET /api/onboard/info` over verified HTTPS: the hosts the caller passes (for
example, servers found through DNS discovery), the configured servers, and the
servers they list in `/api/servers`. It asks at most 16 distinct hosts. Each
server reports its configured `genesis_pubkey` and the `network_id` that
derives from it. The SDK pins the key only when all of these are true:

1. Every server that reports a key reports the same key, network id, and DNS
   base domain.
2. The network id derives from the key under the compiled ruleset versions.
3. At least 3 distinct agreeing hosts are inside that DNS domain.

A disagreement, a malformed key, a network id that does not derive from the
key, or no DNS domain fails closed with `LN_ERR_REJECTED`. Fewer than 3
agreeing hosts fails closed with `LN_ERR_CONNECT`. A network with fewer than 3
reachable servers needs an explicit `set_genesis_key`. On success the key is
pinned as with `set_genesis_key`, and the call returns
`{"genesis_pubkey","network_id","dns_base_domain","hosts"}`. Store the key and
pin it with `set_genesis_key` on later runs.

Discovery never replaces a pinned key, even one pinned while it runs. A key
change is always an explicit `set_genesis_key` call.

**Trust limit:** discovery is trust on first use. The key is not signed by
anything the client already trusts. Trust rests on verified-HTTPS ownership of
the network's DNS domain and on agreement of several servers. An attacker who
can obtain certificates for at least 3 names in that domain, or who controls
every server the client reaches, can supply a false key on first connect.
After the key is pinned, the Tier 1 verification below does not depend on DNS
or on the servers' honesty.

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
   server, and only while it is still a verified Tier 1 server. When that
   server leaves the membership (it announces the next epoch in its heartbeat
   answers before the handoff and answers `421` after it), the SDK verifies
   the membership again and moves the session to another verified server
   with the device identity; the announcement itself chooses nothing (see
   [SDK Guide — Session moves](SDK-Guide#session-moves)).

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

## Direct Paths (Hole Punching)

When mesh networking is on (`enable_mesh` / `ln_mesh_enable`), the SDK tries a
direct path to every peer before it uses a relay:

- Every `stun_refresh_interval_sec` (default 60), the SDK sends a STUN Binding
  request from the BoringTun dataplane socket to the session server's STUN
  service (UDP `3478` on the host of the server's mesh endpoint). The answer
  is the NAT mapping that the mesh traffic uses. Set the interval to `0` to
  turn this off.
- STUN answers are not authenticated. The SDK accepts an answer only from the
  queried address, with its own transaction id, and with a valid IPv4
  `XOR-MAPPED-ADDRESS`. It publishes the address only when the STUN server
  could have observed it: a public address from any server, a private address
  only from a private or loopback server, and a loopback address only from a
  loopback server.
- The heartbeat (`POST /api/mesh/heartbeat`) publishes the address. The
  server stores it as the node's endpoint. A heartbeat with an empty endpoint
  (no STUN answer yet) keeps the stored endpoint.
- Peers receive the endpoint in the verified Tier 1 server's peer list
  (`GET /api/mesh/peers`). The SDK ignores a listed endpoint that is not a
  dotted IPv4 unicast address. It accepts a loopback endpoint only when the
  session server is also on loopback.
- The SDK then sends probes: BoringTun handshake initiations from the
  dataplane socket to the peer's listed endpoint. It sends a burst of five
  probes one second apart, then two probes at each pair slot (every 15
  seconds). A pair slot is a wall-clock time that both peers compute from
  their two public keys, so both sides probe at about the same moment. A
  probe changes no state. Only a valid handshake answer moves the peer to the
  probed address.
- A peer with a fresh handshake on its direct path gets no probes. At most 16
  probes go out in one pass.

`ln_mesh_status` and `ln_mesh_peers` report a direct peer's address in
`endpoint`.

## Relay Fallback

The SDK moves a peer onto a relay when the dataplane cannot reach it directly:

- The peer has no direct endpoint in the server's peer list, or its direct
  endpoint gave no handshake within 20 seconds.
- Both peers choose the same relay on their own. The candidates are the
  verified Tier 1 servers (relay port `9103`) and the relays that
  `GET /api/relay/list` returns. A relay's id is its base64 node identity key.
- Each peer requests a relay ticket for its own session from its verified
  Tier 1 server (`POST /api/relay/ticket`) and sends the relay an `Allocate`
  request. The relay pairs the two requests by a rendezvous that only the two
  peers can derive (see [Security](Security#relay-sessions)).
- After the relay pairs them, the peer's BoringTun traffic goes through the
  relay. The relay carries only ciphertext.

A relay that refuses, does not answer, or gives no handshake is skipped for
five minutes, and the peer is retried with backoff. Set `prefer_direct` to
`false` in the mesh config to relay every peer.

With `prefer_direct` (the default), the SDK keeps probing a relayed peer's
listed endpoint, two probes at each pair slot (every 60 seconds). When the
peer answers there with a valid handshake, the peer moves to the direct path
and the SDK closes the relay session. This does not count as a relay failure.

`ln_mesh_status` and `ln_mesh_peers` report a relayed peer with an empty
`endpoint` and its relay address (`ip:port`) in `relay_endpoint`.

A peer that publishes no direct endpoint (no STUN answer, or STUN turned off)
always uses a relay.

## Authentication Status

| Method | Status |
|--------|--------|
| Ed25519 challenge-response | Primary. Requires an identity (`set_identity` / `ln_set_identity`). Auto-registers new pubkeys on first use. |
| Passkey / WebAuthn | Backup. Challenge bound to the user; assertion verified server-side. |
| Password | **Deprecated.** The server stub always fails; the SDK keeps the functions for compatibility. |
| Token link | One-time invite codes for a group: a new device joins under the group; an existing account becomes a member of it (`ln_invite_create`, `ln_invite_accept`). See [SDK Guide](SDK-Guide#invites-and-other-networks). |

## Account Deletion

`delete_account()` / `ln_account_delete(client, &out_json)` permanently
deletes the account of the identity set with `set_identity` /
`ln_set_identity`. It cannot be undone. The SDK gets a challenge from the
session's server over the private API and signs a deletion proof with the
identity key, so a copied session token cannot delete an account. The server
side is described in [Security](Security#account-deletion).

On status `"deleted"` the SDK stops the mesh, clears its session token and
node id, and (C ABI) stops the account image service. The answer can be
status `"pending"` with an `op_id`. The SDK then keeps
its session, and the deletion takes effect when Tier 1 commits it.

The SDK does not delete local files. After a deletion, the application
deletes:

- the identity file (the `ln_identity_save` path), or the stored identity
  seed;
- the account image cache (the `ln_account_avatar_configure` `cache_root`);
- the certificate directory (the `ln_mesh_port_set_cert_dir` path);
- any stored copy of the session token or node id.

The Flutter client removes the account's keyring entry (group key), the
stored session, and the group loopback certificates, signs out, and then
removes the revoked device identity from the per-user identity store and
creates a new one (see the client README, "Device identity").

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

- **macOS:** builds are CI-verified. On arm64 the build links the pinned
  static OpenSSL archive, so the dylib loads no Homebrew or system OpenSSL.
- **Windows:** build definitions exist; CI is currently disabled, so validate
  locally.
- The SDK ships as a native dynamic library (`.so` / `.dylib` / `.dll`);
  there is no per-platform VPN backend to manage.
