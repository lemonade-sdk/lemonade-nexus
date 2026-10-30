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
| Dart/Flutter | `packages/lemonade_nexus_sdk` (FFI wrapper, `NexusWorker`, DNS discovery; ships the iOS/Android library) | Consumes the C ABI |

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
- The heartbeat (`POST /api/mesh/heartbeat`, every 5 seconds) publishes the
  address. The server stores it as the node's endpoint. A heartbeat with an
  empty endpoint (no STUN answer yet) keeps the stored endpoint. A new
  address goes out in a heartbeat at once, not at the next interval.
- The heartbeat answer carries `peers_revision`, an opaque string that
  changes when the device's peer list changes: a peer joins or leaves, or a
  listed peer's mesh key, tunnel address, private subnet, endpoint,
  hostname, or live session with the server changes. When the value differs
  from the previous answer, the SDK fetches the peer list at once instead of
  at the next `peer_refresh_interval_sec` (default 30). A peer that joined
  or moved is therefore seen within one heartbeat. The value carries no peer
  data; peers still come only from `GET /api/mesh/peers`. Servers without
  the field leave the 30-second refresh as the only schedule.
- The SDK also holds a long-poll on the peer list:
  `GET /api/mesh/peers/<node_id>?wait_revision=<revision>&timeout=25` on its
  own connection to the session server. The server answers as soon as the
  device's `peers_revision` differs from the sent value, or after the
  timeout with the unchanged list. A committed tree change, a changed LAN
  endpoint list, or a changed live session wakes the waiting request, and the
  server checks the live session state again every 5 seconds. A changed
  answer makes the SDK refresh the peer list at once, so a peer that joins
  or moves on the same Tier 1 server is seen in well under a second, without
  waiting for a heartbeat. The SDK sends the next wait at once. After a
  failure it waits 1 second, doubled up to 30 seconds; after a `429` it
  waits 30 seconds; a server that answers without `peers_revision` does not
  hold waits, and the SDK asks again only after 5 minutes. The heartbeat
  stays the fallback in every case. `disable_mesh` closes the held request.
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
  peers are probed in one pass.
- A known peer whose listed endpoint changed, or that this device reads
  offline while the server saw it again, is *renewed*: it gets a new burst
  at once, and a handshake from its old path no longer counts as a working
  session. The relay fallback also skips the direct grace period for it.
- `refresh_mesh_peers()` / `ln_mesh_refresh()` and a changed
  `peers_revision` run the peer refresh, a STUN query, a new punch burst for
  every peer still being probed, and the relay fallback in one pass.
- When the SDK finds a wall-clock gap of more than 10 seconds between two
  passes of its background loop beyond the planned sleep (the app was
  suspended, or the computer slept), it resumes: it sends a fresh handshake
  initiation to every peer and the server, sends a heartbeat, refreshes the
  peer list, queries STUN, renews every peer, and runs the relay fallback.

`ln_mesh_status` and `ln_mesh_peers` report a direct peer's address in
`endpoint`.

### LAN-Direct Paths

Two devices behind one router that does not hairpin UDP never meet at their
public endpoints. They connect over the LAN instead:

- At join and `enable_mesh`, on every refresh request and resume, and every
  60 seconds, the SDK lists the host's IPv4 interface addresses
  (`list_interface_addresses`: `getifaddrs` on Linux, macOS, iOS, and Android;
  `GetAdaptersAddresses` on Windows). It keeps up to four private addresses
  (10/8, 172.16/12, 192.168/16) of interfaces that are up, and pairs them
  with the dataplane's UDP port (`select_local_endpoints`). It skips
  loopback, link-local, public, and mesh-plane addresses, and VPN, tunnel,
  container, and cellular interfaces (`utun`, `tun`, `wg`, `ppp`, `docker`,
  `rmnet`, `pdp_ip`, and others; on Windows, adapters that are not Ethernet or
  Wi-Fi, or that name themselves virtual or VPN). A carrier NAT address
  (100.64/10) counts only when STUN saw that very address.
- The heartbeat carries them as `local_endpoints`. A changed list goes out at
  once. The server lists them only to the peers that already list the
  device (see [Security](Security#direct-paths)), and `peers_revision`
  changes with them.
- A peer is on this device's network when its public endpoint has the same
  IP address as this device's reflexive address (one NAT), or when one of
  its LAN endpoints is inside one of this device's subnets. Only then does
  `ln_mesh_peers` list its `local_endpoints`, and only then are they probed.
- Each probe of such a peer is one handshake initiation, sent to its LAN
  endpoints first and to its public endpoint in the same moment. The
  BoringTun session runs over the address that answers. The relay fallback
  waits 1.5 seconds (`kLanAnswerWindow`) for a LAN answer before it pairs a
  relay, also after a renewal. A peer on another network does not wait.
- `MeshPeer::path` (`path` in `ln_mesh_peers` and `ln_mesh_status`, and in
  the mesh port device status) says where the traffic goes: `"lan"`,
  `"direct"`, `"relay"`, or `""` (no working path yet).
- A LAN path that gets no authenticated packet for the liveness window
  (three keepalive intervals plus 5 seconds) ends at the next monitor pass:
  the peer is probed again at every address and falls back to the public
  path or a relay. A relayed peer keeps getting upgrade probes at its LAN
  endpoints, and a refresh request probes them at once, so the LAN path
  returns when it answers.
- Servers without the field refuse a heartbeat that carries
  `local_endpoints` (HTTP `400`). The SDK then sends the heartbeat again
  without them, so the endpoint and the live session still reach the server.
  Clients without the field change nothing. A server keeps the LAN endpoints of the devices whose
  heartbeats reach it; two devices with sessions on different Tier 1 servers
  do not see each other's LAN endpoints.

## Relay Fallback

The SDK moves a peer onto a relay when the dataplane cannot reach it directly:

- The peer has no direct endpoint in the server's peer list, or its direct
  endpoint gave no handshake within 3 seconds of the first probe
  (`kDirectAnswerWindow`). A peer on this device's network also gets
  1.5 seconds for its LAN endpoints (`kLanAnswerWindow`). The punch goes on
  in the background (see below).
- Both peers choose the same relay on their own. The candidates are the
  verified Tier 1 servers (relay port `9103`) and the relays that
  `GET /api/relay/list` returns. A relay's id is its base64 node identity key.
- Each peer requests a relay ticket for its own session from its verified
  Tier 1 server (`POST /api/relay/ticket`) and sends the relay an `Allocate`
  request. The relay pairs the two requests by a rendezvous that only the two
  peers can derive (see [Security](Security#relay-sessions)).
- After the relay pairs them, the peer's BoringTun traffic goes through the
  relay. The relay carries only ciphertext.
- The relay pairs two requests only when both sides derived the rendezvous
  in the same 300-second wall-clock window, and it ends a request that
  waited 30 seconds for the other side. A request that is still waiting
  when the window changes is asked again for the new window at once. A
  request the other side did not join is asked again after one second for
  five minutes after the peer appeared, moved, or came back, so a request is
  waiting whenever the other side asks, on whatever schedule its SDK
  version uses. After that, such a request backs off like a failure.

A relay that refuses, does not answer, or gives no handshake is skipped for
five minutes, and the peer is retried with backoff. Set `prefer_direct` to
`false` in the mesh config to relay every peer.

With `prefer_direct` (the default), the SDK keeps probing a relayed peer's
listed endpoint and LAN endpoints: it finishes the first burst, then sends two probes at each
pair slot (every 60 seconds). When the peer answers there with a valid
handshake, the peer moves to the direct path and the SDK closes the relay
session. This does not count as a relay failure. A relay request whose path
is not in use yet closes the same way when the direct handshake arrives
first. A relay that carries traffic stays open; it is abandoned only after
180 seconds plus the grace period without an authenticated packet.

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
- **iOS and Android:** `scripts/build-sdk-mobile.sh` builds the SDK alone
  (`LEMONADE_NEXUS_SDK_ONLY`) as an XCFramework (device arm64, simulator
  arm64/x86_64, iOS 15+) and as `liblemonade_nexus_sdk.so` for arm64-v8a,
  armeabi-v7a and x86_64 (API 24+, static C++ runtime, 16 KB pages). Both
  export only the `ln_*` API. The Flutter plugin `packages/lemonade_nexus_sdk`
  ships them; see its `native/README.md`. The mesh runs in userspace, so no
  VPN or Network Extension entitlement is needed; the mesh port listens on
  loopback only while the app runs.
- The SDK ships as a native dynamic library (`.so` / `.dylib` / `.dll`);
  there is no per-platform VPN backend to manage.
