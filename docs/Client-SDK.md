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

## Logging

The SDK logs through one process-wide logger that writes to stdout. The level
is info, or debug when `LN_DEBUG` is set in the environment at the first
`ln_create` / `ln_create_tls`. A host whose stdout is lost (a Windows service,
a mobile app) routes the lines to its own logger instead:

```c
static void on_log(int level, const char* logger, const char* message, void* user) {
    /* level: 0 trace, 1 debug, 2 info, 3 warn, 4 error, 5 critical.
       logger is "lemonade-nexus-sdk"; message has no timestamp or level
       prefix. Both strings are valid only during this call. */
}

ln_set_log_callback(on_log, NULL);   /* before the first ln_create */
ln_set_log_callback(NULL, NULL);     /* back to stdout */
```

The callback runs on SDK threads while the SDK holds internal locks: it must
return quickly, must not throw, and must not call any `ln_*` function. Make
the call before the first `ln_create`, or while no client exists; the logger
swap is not synchronized against a log line in progress on another thread.
The level in force stays as it is. The setting is process-wide, not per
client.

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
servers they list in `/api/servers`. When those are fewer than 3 distinct
hosts (one seed, or a seed whose `/api/servers` did not answer), it also asks
the servers the region's SEIP records name (`<region>.seip.<domain>`; the
region comes from `set_discovery_target` / `ln_set_discovery_target`,
`ServerConfig::discovery_domain` and `discovery_region`, or a known server's
SEIP FQDN). Those servers are candidates only. It asks at most 16 distinct
hosts. Each server reports its configured `genesis_pubkey` and the
`network_id` that derives from it. The SDK pins the key only when all of
these are true:

1. Every server that reports a key reports the same key, network id, and DNS
   base domain.
2. The network id derives from the key under the compiled ruleset versions.
3. At least 3 distinct agreeing hosts are inside that DNS domain.

A disagreement, a malformed key, a network id that does not derive from the
key, or no DNS domain fails closed with `LN_ERR_REJECTED`. Fewer than 3
agreeing hosts fails closed with `LN_ERR_CONNECT`; the error names each host
asked and what it answered, for example
`found 1; asked 3 host(s): sn01.example:9100 agrees; sn02.example:9100
unreachable (SSL server verification failed); sn03.example:9100 HTTP 429`
(the other outcomes are `no claim` and `outside domain <domain>`). A network
with fewer than 3 reachable servers needs an explicit `set_genesis_key`. On
success the key is pinned as with `set_genesis_key`, and the call returns
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
   with its commit proof. It asks for pages of 32 handoffs (`max_links=32`);
   a server that predates that parameter sends 4. When a server answers
   `429`, the SDK waits a second and asks for the same page again, at most 30
   times per server, before it treats the server as unreachable.
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

A refresh starts from the server pool: the configured seeds, the servers
`/api/servers` listed on first connect, and, after a join, the session server
first. The join keeps the other known servers behind the session server, so
an outage of the session server leaves the client servers to ask. When no
known server answers at all, the SDK resolves the region's SEIP records
(`<region>.seip.<domain>`, the same records the first DNS discovery reads;
see [DNS Discovery](DNS-Discovery)) and verifies the servers they name with
the same chain walk and endpoint proofs before it uses one. The region comes
from `ServerConfig::discovery_domain` and `discovery_region`
(`set_discovery_target` / `ln_set_discovery_target` sets them on a created
client), or from the session server's SEIP FQDN `<id>.<region>.seip.<domain>`
when they are not set; without either, no fallback runs and a warning log
line says so. The DNS step runs at most once a minute, so a long outage costs
one lookup a minute rather than one per tree call; it supplies candidates
only, and it never touches the pinned Genesis key. One info log line names
what the lookup found. A refresh that still fails names every server it asked
(`tried:` for the chain walk, `probed:` for the endpoint proofs) and what each
one answered: `unreachable` with the transport's reason (for example
`unreachable (SSL server verification failed)`), or `HTTP <status>`.
`refresh_tier1()` / `ln_tier1_refresh()` verifies now, and
`tier1_membership()` / `ln_tier1_membership()` returns the last result.
`tier1_walk_progress()` / `ln_tier1_progress()` reports the chain walk that
runs now (`active`, `epoch`, `target`, `pages_done`, `pages_total`) without
waiting for it, so an application can show progress while a join or sign-in
waits. The Flutter plugin exposes it as `tier1Progress`.

Without a pinned key, a chain that does not verify, a stale epoch, or no
reachable verified server, the SDK sends no tree request: the call fails with
`http_status` 0 (`LN_ERR_CONNECT`) and an error that says why. Store the
returned `epoch` and `chain` and pass both to `set_epoch_floor` /
`ln_set_epoch_floor` on the next start: the SDK then refuses an older
membership of that chain. A client with no stored epoch can be held at an
old epoch only if every server it reaches withholds the newer handoffs and
every member it reaches signs the older epoch. Catching up has no limit: a
client that was away for any number of epochs pages the chain forward.

`chain` names the chain instance (the Epoch 1 anchor). Genesis signs one
Epoch 1; a network founded again after losing its data is another chain under
the same key. When the servers serve another chain, the refresh fails with
`http_status` 409 and `refounded: true` in `ln_tier1_refresh` and
`ln_tier1_membership`; the SDK neither applies the stored floor to that chain
nor adopts it. The application tells the user to leave the network and join it
again, which clears the stored floor with the account.

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
- The heartbeat (`POST /api/mesh/heartbeat`, every 3 seconds by default,
  `heartbeat_interval_sec`) publishes the address. The server stores it as
  the node's endpoint. A heartbeat with an empty endpoint (no STUN answer
  yet) keeps the stored endpoint. A new address goes out in a heartbeat at
  once, not at the next interval.
- Each accepted heartbeat, and the device's own open event socket, makes
  the device present at the server. Tier 1 servers share presence, so a
  peer list on any Tier 1 server reports the device's `is_online` (present
  within 10 seconds) and `last_seen` (the latest presence time).
- The heartbeat answer carries `peers_revision`, an opaque string that
  changes when the device's peer list changes: a peer joins or leaves, or a
  listed peer's mesh key, tunnel address, private subnet, endpoint,
  hostname, or online state (`is_online`) changes. When the value differs
  from the previous answer, the SDK fetches the peer list at once instead of
  at the next `peer_refresh_interval_sec` (default 30). The answer also
  carries `devices_revision`, which changes with the device list of the
  device's groups; a new value reports a possible device list change
  (`set_mesh_devices_callback`) within one heartbeat, which is how a build
  without the event socket sees it. A peer that joined
  or moved is therefore seen within one heartbeat. The value carries no peer
  data; peers still come only from `GET /api/mesh/peers`. Servers without
  the field leave the 30-second refresh as the only schedule.
- The SDK holds the event socket open to the session server:
  `GET /api/events?node_id=<node_id>`, a WebSocket on the private API
  connection with the session's bearer token. The server sends
  `{"event":"revisions","peers_revision","devices_revision"}` when the socket
  opens and again whenever either value changes. A new `peers_revision`
  refreshes the peer list at once. A new `devices_revision`, every socket
  that opens, and a resume after a suspension report a possible device list
  change (`set_mesh_devices_callback`); the mesh port then reads its device
  list again. The socket pings every 15 seconds and ends after two missed
  answers. After a failure it waits 1 second, doubled up to 30 seconds. A
  server without the socket answers `404`; the SDK then uses the long-poll
  below for 5 minutes and tries the socket again. An SDK built against a
  cpp-httplib older than 0.47.0 (a distribution's library: Ubuntu ships
  0.26.0, Debian 13 backports 0.41.0) has no event socket, because that
  WebSocket client cannot dial the private FQDN through the loopback egress
  with the certificate verified; `LemonadeNexusClient::event_socket_supported()`
  is then false, the SDK keeps the long-poll, and the heartbeat's
  `devices_revision` reports device list changes. With cpp-httplib 0.47.0
  to 0.50.0 (Fedora ships 0.48.0) the SDK always closes an open socket
  before it releases the client, which keeps that library's teardown from
  writing through a freed TLS session; with 0.47.0 to 0.53.0 a cancel or a
  resume shuts the socket down instead of closing it from the other thread,
  because that library's `close()` reads the peer's reply beside the thread
  that is reading, and the reading thread then closes the socket.
- Without the event socket, the SDK holds a long-poll on the peer list:
  `GET /api/mesh/peers/<node_id>?wait_revision=<revision>&timeout=25` on its
  own connection to the session server. The server answers as soon as the
  device's `peers_revision` differs from the sent value, or after the
  timeout with the unchanged list. A committed tree change, a changed LAN
  endpoint list, or a listed peer going online or offline wakes the waiting
  request, and the server checks the LAN endpoint lists again every 5
  seconds. A changed
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
  initiation to every peer and the server, resets its private transport,
  sends a heartbeat, refreshes the peer list, queries STUN, renews every
  peer, forgets the relay backoff, and runs the relay fallback. See
  "Suspension and resume" below for what the host should do.

`ln_mesh_status` and `ln_mesh_peers` report a direct peer's address in
`endpoint`.

### Suspension and resume

The SDK detects a suspension by itself from the wall-clock gap above, but
only when its loop thread next runs, and a request already waiting on a
connection the OS closed meanwhile holds the private transport until its
read timeout (15 seconds, twice). A host that knows when it came back does
better by saying so:

- Call `ln_suspend` (`LemonadeNexusClient::suspend()`, Dart
  `LemonadeNexusSdk.suspend()`) when the process is about to be suspended
  (an iOS app left the foreground and the host's grace period ended,
  Android stopped the app), after `ln_stop_mesh_port` and `ln_mesh_disable`
  when the host uses them. iOS and Android defunct the sockets of a
  suspended app: a defunct UDP socket receives nothing afterwards, and a
  defunct loopback listener refuses every connect. So the SDK gives up the
  dataplane socket and the loopback egress listeners the private API dials
  through now, keeping the netstack and every peer and session, and drops
  the private-API connections so the server sees clean closes. It never
  blocks on the network.
- Call `ln_resume` (`LemonadeNexusClient::resume()`, Dart
  `LemonadeNexusSdk.resume()`) every time the process returns to the
  foreground (iOS `applicationDidBecomeActive`, Flutter
  `AppLifecycleState.resumed`, a laptop's wake notification). It is safe at
  any time and never blocks on the network. It opens a new dataplane UDP
  socket (also when the host never called `ln_suspend`: the old socket may
  be defunct) and re-keys the tunnel from it first, so every peer learns the
  new path, then drops every private-API connection from before the suspension (a
  request waiting on one fails at once and dials again), closes the event
  socket so it opens again, clears the private transport's breaker and the
  30-second unanswered window that would otherwise force a session move,
  drops the pooled public connections, and runs the resume pass at once with
  the relay backoff and relay cooldowns forgotten. One resume costs one Tier
  1 verification: the relay fallback reuses the verification the first
  private request made.
- Read `tunnel_up` in `ln_mesh_status` (`MeshStatus.tunnelUp`) for the
  tunnel to the session server instead of inferring it from the peers. It is
  true while the server's dataplane peer sent a packet or a handshake within
  the last 20 seconds (the SDK's own heartbeat crosses the tunnel every 3
  seconds, so this is several missed heartbeats), or the mesh was enabled
  less than 20 seconds ago and has carried nothing yet; false while the mesh
  is not enabled. A host that expects the mesh up and reads false should
  call `ln_resume` and, when it stays false for another window, rebuild the
  mesh (`ln_mesh_disable`, `ln_join_network`, `ln_mesh_enable`).
- SIGPIPE: iOS closes the sockets of a suspended app, and a TLS write to one
  of them raises SIGPIPE, which kills the process before any error reaches
  the caller. The SDK ignores SIGPIPE for the process when the first client
  is created, and sets `SO_NOSIGPIPE` on every socket it opens on Apple
  platforms. A host that installs its own SIGPIPE handler must keep it
  ignored or tolerant.

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
- The kept addresses are ordered fastest link first, by the interface's
  reported link speed (`/sys/class/net/<name>/speed` on Linux,
  `SIOCGIFMEDIA` on macOS, `TransmitLinkSpeed` on Windows; Wi-Fi and
  unreadable links report 0, which sorts last), so a peer tries this
  device's fastest address before a slower one. The endpoint list carries no
  speed on the wire, so this order is local only; a peer orders by its own
  links. When two interfaces share one subnet (a host multihomed on the same
  LAN), only the faster one is advertised: a socket bound to `0.0.0.0`
  answers a probe from its default-route interface whatever address the probe
  went to, so the second same-subnet address is never a distinct direct path.
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
  without them, so the endpoint and the device's presence still reach the
  server.
  Clients without the field change nothing. Tier 1 servers share the LAN
  endpoints with device presence, so two devices with sessions on different
  Tier 1 servers see each other's LAN endpoints. A server from before that
  sharing lists only the LAN endpoints of the devices whose heartbeats reach
  it.

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

A committed deletion revokes the identity key before its answer travels back,
and the tunnel the answer takes can end with the account. When the request
gets no answer, or no session is left to ask for the challenge, the SDK
authenticates once more. A key the server refuses as revoked confirms the
deletion: the answer is status `"deleted"` with `confirmed: "revoked"` and an
empty `account_id`. A key the server still accepts leaves the failure as it
is, so the caller can retry.

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

libsodium, BoringTun, and the netstack are embedded in the shared library.
A Linux SDK-only build (`-DLEMONADE_NEXUS_SDK_ONLY=ON`, as the release and the
Linux client build it) links the system OpenSSL 3 (`libssl.so.3`); a full
Linux build with the default `LEMONADE_NEXUS_STATIC_DEPS=ON` links the pinned
static OpenSSL. On macOS, Windows, iOS, and Android it embeds the pinned static
OpenSSL.

## Platform Notes

- **Linux:** the release and the Linux Flutter client CI job build the SDK
  alone on Ubuntu 24.04 x86-64.
- **macOS:** builds are CI-verified. On arm64 the build links the pinned
  static OpenSSL archive, so the dylib loads no Homebrew or system OpenSSL.
- **Windows:** the Flutter client workflow builds the SDK DLL and checks its
  exports. The native test matrix has its Windows entries disabled, so the
  SDK tests do not run on Windows in CI.
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
