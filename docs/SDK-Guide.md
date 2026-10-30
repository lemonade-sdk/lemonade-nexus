---
layout: default
title: SDK Guide
---

# SDK Guide

## Table of Contents
- [Overview](#overview)
- [Quick Start (C++)](#quick-start-c)
- [Quick Start (C API)](#quick-start-c-api)
- [Tier 1 Servers](#tier-1-servers)
- [Identity Management](#identity-management)
- [Identity Storage](#identity-storage)
- [Authentication](#authentication)
- [Joining the Network](#joining-the-network)
- [Invites and Other Networks](#invites-and-other-networks)
- [Deleting an Account](#deleting-an-account)
- [Tree Operations](#tree-operations)
- [Mesh P2P and Local Services](#mesh-p2p-and-local-services)
- [Error Handling](#error-handling)
- [Retired C Functions](#retired-c-functions)
- [Best Practices](#best-practices)

## Overview

The **LemonadeNexusSDK** is a C++ library with a C FFI layer
(`ln_*` functions) for integrating the mesh VPN into any application. It
handles identity, authentication, network joining, peer-to-peer mesh
networking, and local service publishing. The mesh dataplane is in-process
userspace BoringTun plus a smoltcp netstack — no kernel module, no TUN
device, no elevated privileges.

## Quick Start (C++)

```cpp
#include <LemonadeNexusSDK/LemonadeNexusClient.hpp>
#include <iostream>

int main() {
    // host must be the server's certificate FQDN; the public API is
    // verified HTTPS by default
    lnsdk::ServerConfig config{"server.example.com", 9100};
    lnsdk::LemonadeNexusClient client{config};

    // Tree, session, and private-API calls go only to Tier 1 servers the
    // SDK verifies from the network's Genesis key (genesis_pubkey).
    if (!client.set_genesis_key("<base64 Genesis public key>").ok) {
        std::cerr << "malformed Genesis key\n";
        return 1;
    }

    const auto health = client.check_health();
    if (!health.ok) {
        std::cerr << health.error << '\n';
        return 1;
    }
    std::cout << health.value.status << '\n';

    // Identity: generate once, then persist and reload on later runs
    lnsdk::Identity identity;
    if (!identity.load("identity.json")) {
        identity.generate();
        if (!identity.save("identity.json")) {
            std::cerr << "could not persist identity\n";
            return 1;
        }
    }
    client.set_identity(identity);

    // Primary authentication: Ed25519 challenge-response
    const auto auth = client.authenticate_ed25519();
    if (!auth.ok) {
        std::cerr << "auth failed: " << auth.error << '\n';
        return 1;
    }

    // Join: create endpoint node, allocate tunnel IP, start the dataplane.
    // With a valid identity the username/password arguments are unused
    // (they remain only for the deprecated password fallback).
    const auto join = client.join_network("", "");
    if (!join.ok) {
        std::cerr << "join failed: " << join.error << '\n';
        return 1;
    }
    std::cout << "Node ID: "   << join.value.node_id << '\n';
    std::cout << "Tunnel IP: " << join.value.tunnel_ip << '\n';

    // P2P mesh for direct client-to-client connections
    client.enable_mesh();
}
```

Every C++ method returns `Result<T>` with `.ok`, `.value`, `.http_status`,
and `.error`. There is no `operator->`.

## Quick Start (C API)

```c
#include <LemonadeNexusSDK/lemonade_nexus.h>
#include <stdio.h>

int main(void) {
    ln_client_t* client = ln_create_tls("server.example.com", 9100);
    /* Tree, session, and private-API calls go only to verified Tier 1 servers. */
    ln_set_genesis_key(client, "<base64 Genesis public key>", 0);

    ln_identity_t* id = ln_identity_generate();
    ln_set_identity(client, id);

    char* auth_json = NULL;
    ln_error_t err = ln_auth_ed25519(client, &auth_json);  /* challenge-response */
    ln_free(auth_json);
    if (err != LN_OK) {
        printf("auth failed: %d\n", err);
        ln_identity_destroy(id);
        ln_destroy(client);
        return 1;
    }

    char* join_json = NULL;
    err = ln_join_network(client, "", "", &join_json);
    ln_free(join_json);
    if (err != LN_OK) {
        ln_identity_destroy(id);
        ln_destroy(client);
        return 1;
    }

    ln_mesh_enable(client);   /* P2P with default config */

    ln_identity_destroy(id);
    ln_destroy(client);
    return 0;
}
```

Password-derived identities exist for compatibility (`ln_derive_seed` +
`ln_identity_from_seed`), but the server's password *authentication* is a
deprecated stub that always fails; use an Ed25519 identity.

## Tier 1 Servers

| C++ | C | Purpose |
|---|---|---|
| `set_genesis_key(b64, min_epoch)` | `ln_set_genesis_key(client, b64, min_epoch)` | Pin the Genesis key and the lowest epoch to accept |
| `discover_genesis_key(hosts)` | `ln_discover_genesis_key(client, hosts_json, &json)` | First connect only: pin the key that at least 3 servers in the network domain agree on (trust on first use) |
| `discover_servers(domain, region, port)` | `ln_discover_servers(domain, region, port, &json)` | Bootstrap without a configured host: resolve `<region>.seip.<domain>` and read each server's certificate name; the names are candidates for `ln_create_tls`, not trusted servers |
| `refresh_tier1()` | `ln_tier1_refresh(client, &json)` | Verify the membership now |
| `tier1_membership()` | `ln_tier1_membership(client, &json)` | The last verified membership, no network I/O |

The JSON is `{"epoch", "members", "servers":[{"node_id","host","port"}]}`.
The SDK refreshes on its own every five minutes and after a server refuses a
tree route. See [Client SDK — Tier 1 Servers](Client-SDK#tier-1-servers) for
what it verifies and how it fails closed.

A session belongs to the Tier 1 server that issued it. Tier 1 rotates one
member out at each epoch boundary. A member that the finalized next-epoch
plan leaves out says so in its heartbeat answers before the handoff
(`tier1_departure: {next_epoch}`), and refuses tree routes with `421` after
it. On either sign, and when a membership refresh finds the server gone, the
SDK verifies the membership again from the pinned Genesis key and moves the
session by itself: it authenticates with the device identity through another
verified Tier 1 server, joins again, and restarts the mesh orchestrator as it
was. The notice is a hint; the SDK picks the new server from the membership
it verified, never from the notice. The move is reported through
`set_session_moved_callback()` / `ln_set_session_moved_callback()` (see
[Session moves](#session-moves)).

A fourth sign is a dead private path. A Tier 1 server that restarts in place
keeps its seat and its public API but forgets the client's dataplane peer, so
every private-API request fails before the handshake completes while the
membership still lists the server. When such requests have gone unanswered
at the connect or handshake level for 30 s (an HTTP error status is an
answer; one lost handshake does not count, the window starts at the first
failure and any answer resets it), the SDK verifies the membership again
over the public API and, when the server is still a member that answered,
moves the session anyway: it authenticates through a verified member, the
same server included, and the fresh join adds the peer back. When nothing
can be verified, the device itself lost the network: the session stays, and
the SDK waits for the next window. One move starts per window.

Only when the SDK cannot move the session (no identity set, or the silent
join failed) does it drop the session: `check_health()` reports it once,
private-API calls are refused, and `mesh_status().needs_rejoin` stays true
until `join_network()` succeeds again. That join authenticates through a
current Tier 1 server instead of reusing the dropped token.

## Identity Management

```cpp
// Random keypair
lnsdk::Identity identity;
identity.generate();

// Or from a 32-byte seed (e.g. PBKDF2-derived)
std::vector<uint8_t> seed =
    lnsdk::Identity::derive_seed("username", "password");
identity.from_seed(seed);

// Persistence: {"public_key": "<b64>", "private_key": "<b64>"}
identity.save("identity.json");
identity.load("identity.json");

// Public key in the server's "ed25519:<base64>" form
std::string pk = identity.pubkey_string();

client.set_identity(identity);
```

The client's mesh keypair is derived from this identity (identity-bound
X25519), so possession of the identity is what the server checks.

## Identity Storage

`identity.json` holds the private key in the clear, protected by file
permissions only. The per-user identity store keeps one identity for the
OS user and protects it with the OS keystore. Use the store for desktop
applications and the hand-off to move the identity to a daemon.

### Per-user store

The store wraps the 32-byte Ed25519 seed with a random 32-byte
key-encryption key (KEK) using libsodium `crypto_secretbox`. The KEK lives in
the OS keystore. The identity file holds the public key, the wrapped seed,
and a reference to the KEK. The file alone yields nothing secret.

| Platform | Keystore (`backend`) | Store directory |
|---|---|---|
| macOS | Login keychain, generic password, service `ai.lemonadeserver.nexus`, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, no iCloud sync (`keychain`) | `~/Library/Application Support/LemonadeNexus/identity/` |
| Windows | DPAPI, user scope, `CRYPTPROTECT_UI_FORBIDDEN`, fixed optional entropy; the protected blob is kept in the file (`dpapi`) | `%LOCALAPPDATA%\LemonadeNexus\identity\` |
| Linux | Secret Service through `libsecret-1.so.0`, loaded at run time (`libsecret`) | `${XDG_DATA_HOME:-~/.local/share}/lemonade-nexus/identity/` |

The directory is created with mode 0700 and the file `identity.v2.json`
with mode 0600. The home directory is that of the effective user
(`getpwuid(geteuid())` or the known folder of the process token). `SUDO_USER`
is never used: a process started with `sudo` is root and gets root's store.
`HOME` is used only when the account database has no directory for the
user.

There is no fallback. When no keystore is usable (no libsecret, no session
bus, no Secret Service, a daemon without a user session) the calls return
`LN_ERR_UNSUPPORTED` and write nothing. When the keystore is locked or
refuses access the calls return `LN_ERR_AUTH`.

```c
char* status = NULL;
ln_identity_user_status(&status);   /* {present, backend, unlocked, public_key?, dir} */
ln_free(status);

ln_error_t err;
ln_identity_t* id = ln_identity_user_load(&err);
if (!id && err == LN_ERR_NOT_FOUND) {
    id = ln_identity_user_create(&err);
}
if (!id) {
    /* LN_ERR_UNSUPPORTED: no keystore; LN_ERR_AUTH: locked or denied;
       LN_ERR_REJECTED: the stored file failed verification. */
}

/* One-time migration from identity.json (text already in memory) */
ln_identity_t* old = ln_identity_from_json(text);
err = ln_identity_user_import(old);     /* LN_ERR_REJECTED when one is present */
ln_identity_destroy(old);

ln_identity_user_remove();              /* keystore item first, then the file */
```

`ln_identity_user_create` and `ln_identity_user_import` refuse when a file
is present; call `ln_identity_user_remove` first to replace an identity. The
C++ interface is `lnsdk::IdentityStore` in `IdentityStore.hpp`.

### Hand-off to another process

A daemon that runs outside the user's session cannot open the user's
keystore. The hand-off moves the identity from the user's process to the
daemon over a local channel without plaintext on the wire.

1. Receiver: `ln_identity_handoff_begin(&request)` creates an ephemeral
   X25519 key and the request `{alg:"x25519-sealedbox-v1", pubkey, nonce,
   expires_at}`. The request is valid for 60 s.
2. Sender: `ln_identity_handoff_seal(identity, request)` seals
   `nonce || seed` to the ephemeral key with a libsodium sealed box and
   returns `{alg, nonce, sealed}`.
3. Receiver: `ln_identity_handoff_open(handle, envelope, &err)` opens the
   envelope once and returns the identity.

The first `open` on a handle wipes the ephemeral secret whatever the
result. A second `open`, an expired request, a wrong `alg`, or an envelope
for another request returns `LN_ERR_REJECTED`; an envelope that does not
open for the request returns `LN_ERR_AUTH`; a malformed envelope returns
`LN_ERR_PARSE`. Destroy the handle with `ln_identity_handoff_destroy`. The
C++ interface is `lnsdk::IdentityHandoff` in `IdentityHandoff.hpp`.

### What is and is not protected

- Reading the identity file, a backup of it, or the directory listing does
  not reveal the key. The wrapped seed needs the KEK from the keystore.
- Another OS user on the same machine cannot read the file (mode 0600) and
  cannot use the keystore item (keychain ACL, DPAPI user scope, Secret
  Service session).
- An attacker who runs code in the user's session with access to the
  user's keystore can read the KEK and therefore the key. The keystore
  binds the key to the user, not to one application.
- A root or administrator who reads process memory can read the key of a
  process that holds it. This is unchanged from `identity.json`.
- The envelope of a hand-off carries ciphertext only. A captured envelope
  cannot be opened again because the ephemeral key is consumed.
- Seeds, KEKs, and sealed-box plaintext live in guarded memory
  (`SecureBuffer`) and are wiped after use. `lnsdk::Identity` wipes its
  private key when it is destroyed or moved from.

## Authentication

```cpp
// Primary: Ed25519 challenge-response
// (server sends a nonce, the identity signs it, the server verifies)
auto auth = client.authenticate_ed25519();

// Backup: passkey / WebAuthn
auto challenge = client.issue_passkey_challenge(user_id);
// ... platform authenticator produces the assertion ...
auto auth2 = client.authenticate_passkey(passkey_data);
auto reg  = client.register_passkey_credential(user_id, cred);

// Deprecated: password stub (server always fails it)
auto auth3 = client.authenticate("username", "password");
```

## Joining the Network

```cpp
auto result = client.join_network("", "");
```

Join is composite — one call does everything:

1. Authenticate (Ed25519 challenge-response when an identity is set)
2. Create the endpoint node in the permission tree
3. Receive the tunnel IP that the join operation assigns from the tree (`10.65.x.x`)
4. Bring the in-process dataplane up

**Response fields:**

| Field | Example | Description |
|-------|---------|-------------|
| `node_id` | `09ba6947...` | Your unique node ID |
| `tunnel_ip` | `10.65.12.34/32` | Your mesh tunnel IP |
| `server_tunnel_ip` | `10.64.252.37` | The tunnel IP of the server that answered the join; its private API listens there |
| `mesh_pubkey` | `base64...` | Server's mesh public key |
| `mesh_endpoint` | `<ip>:51940` | Server's mesh endpoint |

After joining, private API calls (tree, IPAM, mesh, routing, certs) route
over the mesh to the server's private API.

**Device name.** Call `client.set_device_name("Work PC")` (C ABI:
`ln_set_device_name`) before the join that creates the device's node; the
join sends it as `hostname`. Without a name the server names the device
`endpoint-<8 hex digits>`. The `username` argument of `join_network` is not a
device name. A device that already has its node keeps its stored name; rename
it with `update_node`. When the name folds to a mesh-port label that another
device of the target group holds (see `ln_check_device_name`), the server
refuses that name and the SDK joins again under the server's default name: the
join succeeds and reports `device_name_refused` with `device_name_suggestion`,
a free name taken from a device-name check of the invite. A name longer than
64 bytes, with a control character or one of ``;|&$`(){}<>'"\``, or without a
letter or digit is refused before any request (peers drop a listed device
whose name carries those characters). When the join creates a new group (no
invite), the server also gives the group that name.

## Invites and Other Networks

An invite is single use and names one group. One call creates it: without a
target it is for your own top-level group, with a target it is for that group
(a subgroup, or another user's group where you hold `add_child`). The answer
carries the invite in two forms that name the same invite: `code`, 8 decimal
digits to read out or type, and `link_token`, the full token (`lnk_` and 64
hex digits) for a link or a QR code.

```cpp
auto own = client.create_link_token(600);                       // own group
auto sub = client.create_link_token(600, "group-id",            // chosen group
                                    {"read", "connect_private"});
// sub.value["code"] is the 8-digit code to share; sub.value["link_token"]
// is the full token. Both are returned once.
```

Everywhere below, `code` is either form: the SDK passes it through
unchanged, and the server treats exactly 8 digits as a code. The SDK refuses
any other shape (`invite_format_error`) before it sends a request. The code
works for at most 10 minutes (`code_expires_at`), the token until
`expires_at`. A server refuses code attempts from an address after 5 wrong
codes within 10 minutes, and all codes after 100 wrong codes from anywhere
within 10 minutes; the token still works then.

| C++ | C | Purpose |
|-----|---|---------|
| `create_link_token(ttl, target, perms)` | `ln_invite_create(client, target_or_NULL, perms_json_or_NULL, ttl, &json)` | Create an invite |
| `accept_invite(code)` | `ln_invite_accept(client, code, &json)` | Join another network with an existing account |
| `list_memberships()` | `ln_memberships_list(client, &json)` | Groups this identity belongs to |
| `leave_membership(group)` | `ln_membership_leave(client, group, &json)` | Leave a group joined by invite |
| `move_node(node, parent)` | `ln_move_node(client, node, parent, &json)` | Move a device or subgroup |
| `check_device_name(name, group, code)` | `ln_check_device_name(client, name, group_or_NULL, code_or_NULL, &json)` | Check a device name before a join or rename |

- A code works on any Tier 1 server, not only on the server that created
  it, so the client can redeem it through whichever server it reaches. A code
  used in the first second after it was created can still be refused by a
  server that has not received it yet; try again.
- A **new device** uses the code with `set_link_token(code)` before
  `join_network`; it is placed under the invite's group. The new device and
  the devices already in that group, the owner's first device included, list
  each other as mesh peers.
- An **existing account** uses `accept_invite(code)`. It keeps its own network
  and becomes a member of the invite's group. Its device can then reach that
  group's devices, and they can reach it, as the invite's permissions allow.
  The inviter never sees the member's other devices.
- An invite never grants `admin`, `edit_node`, or `delete_node`, and never
  grants more than the inviter holds. The server checks the inviter's
  authority again when the code is used.
- A device that joined with an invite still leaves with `leave_network()`
  (`ln_leave_network`): the server lets a device delete its own node, and
  nothing else, without `delete_node`. The device key stays valid, so the
  device can join again later with a new invite and the same identity. When
  an admin removes the device instead, or the account is deleted, the
  server revokes the key, and a later join needs a new identity.
- **Device names are unique within a group.** The mesh port folds a device
  name to one DNS label ("Work PC" and "work-pc" are both `work-pc`), so a
  join or a rename (`update_node` with `hostname`) whose label another device
  of the same group holds is refused with HTTP 409 and an error that names
  that device; so is a name with no letter or digit. Check a name first:
  `check_device_name(name, group_node_id, "")` for a group you can read, or
  `check_device_name(name, "", code)` for the group an invite targets (the
  code is not spent). The answer is `{label, available, conflicts:
  [{node_id, device_name}], suggestion}`; `suggestion` is a free label such
  as `work-pc-2`. It is advisory: the server decides when the name is used.
  The call needs a session and a verified Tier 1 server, not a mesh session,
  so a new device can check the name it will join with.
- Every C function writes a caller-owned JSON string to `out_json` (also on
  most failures, with an `"error"` field). Release it with `ln_free()`. Input
  strings are not retained.

See [Security](Security#invites-and-group-membership) for the full rules.

## Deleting an Account

```cpp
auto r = client.delete_account();  // irreversible
if (r && r.value["status"] == "deleted") {
    // Delete the identity file and local caches here.
}
```

```c
char* json = NULL;
if (ln_account_delete(client, &json) == LN_OK) { /* delete local files */ }
ln_free(json);
```

- The call needs an identity and an established mesh session. It signs a
  fresh deletion proof with the identity key; a session token alone is not
  enough.
- The server removes the account's groups and devices and everything beneath
  them (other users' devices there lose access to this network), this
  identity's memberships and grants, its key envelopes, chats, invites,
  passkeys, certificates, and DNS names, and revokes its key. The
  application root is never removed.
- On `"deleted"` the client stops the mesh and clears its session. A
  `"pending"` answer means Tier 1 has not committed the deletion yet.
- Local files stay. See [Client SDK](Client-SDK#account-deletion) for the list
  to delete, and [Security](Security#account-deletion) for the rules.

## Tree Operations

```cpp
// Read
auto node = client.get_tree_node("node-id");
auto children = client.get_children("parent-id");

// Mutate (the SDK signs the delta with your identity)
lnsdk::TreeNode child;
child.hostname = "my-device";
child.type = lnsdk::NodeType::Endpoint;
auto created = client.create_child_node("parent-id", child);

nlohmann::json updates;
updates["hostname"] = "new-name";  // 409 when a sibling device folds to the same label
auto updated = client.update_node("node-id", updates);
auto deleted = client.delete_node("node-id");
```

Mutations are author-signed deltas. Receiving a signed record from another
node transfers it; it does not authorize or apply a remote mutation on its
own.

## Mesh P2P and Local Services

```cpp
lnsdk::MeshConfig cfg;
cfg.peer_refresh_interval_sec = 30;
cfg.heartbeat_interval_sec = 5;
cfg.prefer_direct = true;
client.enable_mesh(cfg);

client.set_mesh_callback([](const lnsdk::MeshTunnelStatus& s) {
    // s.peer_count, s.online_count, s.peers...
});

auto status = client.mesh_status();
// status.is_up, status.peer_count, status.online_count, status.peers...
// status.needs_rejoin: the session's Tier 1 server left the membership and
// the SDK could not move the session by itself; call join_network() again.
client.refresh_mesh_peers();

// Publish a local service to mesh peers:
// our-mesh-IP:8080 -> tcp:127.0.0.1:8080 (re-applied on re-join)
client.expose_service(8080, "tcp:127.0.0.1:8080");

// Open a loopback bridge to a peer's published service
uint16_t local_port = client.open_egress("10.64.0.11", 8080);

client.disable_mesh();
```

C ABI equivalents: `ln_mesh_enable`, `ln_mesh_enable_config`,
`ln_mesh_disable`, `ln_mesh_status`, `ln_mesh_peers`, `ln_mesh_refresh`,
`ln_mesh_expose_service`, `ln_mesh_open_egress`, plus
`ln_private_api_call` for generic authenticated private routes.
`ln_mesh_peers` and the `peers` of `ln_mesh_status` carry every `MeshPeer`
field, including `peer_permissions`, `mgmt_pubkey`, `last_seen`, `last_rx`,
`local_endpoints` and `path`.

**Peer liveness.** A monitor pass every 5 s sets each peer's `is_online`
(`lnsdk::peer_signal_fresh` and `lnsdk::next_peer_liveness` in
`MeshOrchestrator.hpp`). An authenticated packet from the peer, keepalives
included, within three keepalive intervals plus 5 s keeps it online. Before
the first packet, a live WireGuard session (handshake under 200 s; BoringTun
rejects a session after 180 s) or a recent server contact (`last_seen`
within 15 s plus one peer refresh interval) counts. A relayed peer also
stays online while the server's `last_seen` is that recent. An online peer
reads offline only after two stale passes in a row, so one late keepalive
or peer refresh does not flip it. The mesh port routes only to online peers.

**LAN-direct paths.** The SDK reports the device's private LAN addresses
with the dataplane port in each heartbeat (`local_endpoints`), and probes
the LAN endpoints of a peer on the same network before its public endpoint
and before a relay. Two devices behind a router that does not hairpin UDP
then connect over the LAN instead of a relay. Each `MeshPeer` reports:

- `local_endpoints`: the peer's LAN endpoints that the SDK probes. They are
  empty when the peer is on another network (another public address and no
  shared subnet).
- `path`: `"lan"` (the session runs over a LAN endpoint), `"direct"` (over
  another direct address, normally the punched public endpoint), `"relay"`,
  or `""` (no working path yet, or the path went silent).

The mesh port device status carries the same `path`. Call
`ln_mesh_refresh` / `refresh_mesh_peers()` after a network change: the SDK
reads the interface addresses again and reports a new list at once. See
[Client SDK](Client-SDK#lan-direct-paths) for the rules and
[Security](Security#direct-paths) for what is disclosed.

**Mobile apps.** On iOS 14 and later, the first datagram an app sends to a
LAN address shows the system's Local Network permission prompt. An app that
embeds the SDK must declare `NSLocalNetworkUsageDescription` in its
`Info.plist`, with a sentence that says why (for example, "Connects directly
to your other devices on this network."). The SDK sends only unicast UDP, so
no Bonjour service entry (`NSBonjourServices`) is needed. If the user denies
the permission, the LAN probes fail without an error and the device uses the
public path or a relay, as before. Android needs no permission beyond
`INTERNET` for unicast UDP to LAN addresses.

### Service catalog and route policy

A device that exposes its lemond (or another HTTP service) to mesh peers
registers a catalog of the service's route families. From then on the SDK
terminates HTTP at that port's mesh ingress and forwards a request to the
service only when the calling peer may use the family of that route. Ports
without a catalog keep the raw byte bridge.

```c
const char* catalog =
    "{\"version\": 3,"
    " \"app\": {\"name\": \"lemonade\", \"version\": \"2026.46.0\"},"
    " \"families\": ["
    "   {\"name\": \"inference\", \"routes\": ["
    "      {\"methods\": [\"POST\"], \"path\": \"/api/v1/chat/completions\"},"
    "      {\"methods\": [\"GET\"], \"prefix\": \"/api/v1/models\"}]},"
    "   {\"name\": \"management\", \"routes\": ["
    "      {\"methods\": [\"GET\"], \"path\": \"/api/v1/system-info\"}]}]}";
ln_mesh_service_set_catalog(client, 13305, catalog);
ln_mesh_expose_service(client, 13305, "tcp:127.0.0.1:13305");
ln_set_ingress_denied_callback(client, on_refusal, NULL);
```

C++: `client.set_service_catalog(13305, json)`, `client.service_catalog(13305)`
and `client.set_ingress_denied_callback(fn)`; the rules live in
`lnsdk::service_ingress` (`LemonadeNexusSDK/ServiceIngress.hpp`).

**Catalog format.** `version` is a required unsigned integer; `app` is
optional. A family name matches `[a-z0-9][a-z0-9_.-]{0,62}` and appears once.
A route lists at least one method and exactly one of `path` (an exact match)
or `prefix` (the prefix itself and every path below it, by path segment);
both are absolute. The same method with the same path or prefix appears only
once in the catalog. At most 64 families, 1024 routes and 256 KiB of JSON. The
order matters: the first route in catalog order that matches a request's
method and path names the family. Registering a catalog again replaces the
previous one; `ln_mesh_service_catalog` returns the registered one, or `{}`.

**Attribution.** The dataplane accepts a packet only when its inner source
address lies inside the sending peer's allowed IPs (its tunnel address on a
direct path; on the hub path the server binds the address to the peer's key
before it forwards). The ingress reads that source address and looks the
peer up in the latest peer list (`ln_mesh_peers`): its node id, its key and
its `peer_permissions`, the permissions the peer's key holds on this device
and its ancestor groups. A connection that no listed peer accounts for is
refused.

**Decision.** `GET /.nexus/catalog` is answered by the SDK itself for any
attributed peer with the registered catalog, so a client can learn the app
name, version and families before it sends a request. Every other request is
matched to a family and allowed when `peer_permissions` contains `admin` or
`svc:<family>`. The local service then receives it with these headers, set by
the SDK after any client-supplied `X-Nexus-*` header was removed:

| Header | Value |
|---|---|
| `X-Nexus-Peer-Node` | the peer's node id |
| `X-Nexus-Peer-Key` | the peer's management key when the peer list carries it, otherwise its mesh public key |
| `X-Nexus-Peer-Permissions` | the peer's permissions, comma-separated |
| `X-Nexus-Family` | the matched family |
| `X-Nexus-Catalog-Version` | the catalog version |

Status, `Content-Type` and streamed bodies (server-sent events, chunked
responses) pass through unchanged, as they do through the mesh port.

**Refusals.** Every refusal answers HTTP 403 with
`Content-Type: application/json` and the body

```json
{"error": "<short reason>", "code": "nexus_permission_denied",
 "family": "management", "required": "svc:management", "catalog_version": 3,
 "app": {"name": "lemonade", "version": "2026.46.0"}}
```

where `code` is `nexus_permission_denied` (the peer lacks the family
permission), `nexus_route_unregistered` (no route matches; `family` and
`required` are empty) or `nexus_peer_unattributed` (no listed peer accounts
for the connection). Each refusal is also reported to the callback of
`ln_set_ingress_denied_callback` as

```json
{"kind": "denied", "vport": 13305, "peer_node_id": "...", "peer_key": "...",
 "peer_tunnel_ip": "10.64.0.3", "method": "POST", "path": "/api/v1/...",
 "family": "inference", "required": "svc:inference", "catalog_version": 3,
 "time": 1790000000}
```

with `kind` one of `denied`, `unregistered` or `unattributed`. The host logs
unregistered requests from this event; the event never carries a request
body. The callback owns `event_json` and releases it with `ln_free()`. It runs
on an SDK thread while the refused request waits, so it must return promptly;
when the setter returns, the previous callback is not running and is not
called again. Do not call the setter, or `ln_destroy`, from the callback.

**What is not affected.** The mesh port's own `local` selection
(`MeshPort::forward_local`) connects to the local service URL directly; it
never enters the netstack, so this device's own traffic is not attributed or
filtered. On the sending side, the mesh port reads each reachable device's
`/.nexus/catalog` and reports the app name, version and families in
`ln_mesh_port_status` under `devices`, and the catalog this device registered
under `catalog`.

### Session moves

The SDK moves a session whose Tier 1 server leaves the membership, or stops
answering over the mesh while its public API still answers (see
[Tier 1 Servers](#tier-1-servers)). Nothing is required from the application;
one callback tells it what happened, so it can inform the user:

```cpp
client.set_session_moved_callback([](const lnsdk::SessionMoveEvent& e) {
    // e.from_node_id, e.from_host: the server that issued the old session
    // e.to_node_id, e.to_host: the server that issued the new one (empty
    //   when none did)
    // e.epoch: the Tier 1 epoch the SDK verified for the move
    // e.silent: true when the SDK re-authenticated and joined by itself;
    //   false when the application must call join_network() (needs_rejoin
    //   is set) and e.error says why
});
```

The callback runs on an SDK background thread, or on the thread whose call
found the server gone, outside the client's locks. When
`set_session_moved_callback()` returns, the previous callback is not running
and is not called again. Do not call that method, or destroy the client, from
the callback.

C: `ln_set_session_moved_callback(client, fn, user)` with
`void fn(char* event_json, void* user)`. `event_json` is
`{from_node_id, from_host, to_node_id, to_host, epoch, silent, error}`. The
callback owns `event_json` and releases it with `ln_free()`, during the call
or later from any thread; this lets a binding hand the event to another
thread. `fn` NULL clears the callback. No callback runs after `ln_destroy()`
returns. Dart: `LemonadeNexusSdk.sessionMoves` is a `Stream<SessionMoveEvent>`
with the same fields.

A silent move issues a new server-bound session token; an application that
stores the token reads `session_token()` / `ln_get_session_token()` again
after the event.

### Mesh port

The mesh port is a listener on `127.0.0.1:13306` that serves the devices of
this device's group by name. It never binds another address.

```c
ln_mesh_port_set_cert_dir(client, "/path/to/private/certs/group-loopback");
ln_error_t rc = ln_mesh_port_start(client, 0, "http://127.0.0.1:13305");
if (rc == LN_ERR_PORT_IN_USE) {
    /* Another process (for example lemond) owns the port. Do not retry. */
}
ln_mesh_port_set_selection(client, "auto", NULL);

char* status = NULL;
ln_mesh_port_status(client, &status);  /* URLs, selection, TLS state */
ln_free(status);

ln_mesh_port_stop(client);
```

- The port serves plain HTTP until the group loopback certificate
  `*.<group-label>.lo.<base>` is in the certificate directory, then TLS. The
  first certificate replaces the plain listener with a TLS listener on the same
  port. That switch waits until no plain request is open, so a running stream
  is never cut: `tls.state` reports `activating` while the plain listener
  drains and keeps serving, then `active`. A request that arrives during the
  few milliseconds of the switch itself gets 503 with `Retry-After`. The SDK
  certificate renewer keeps the certificate current, and the port reloads each
  renewed certificate in place: the TLS listener and its connections stay up
  and each new handshake presents the new certificate.
- With the `auto` selection, `/api/v1/models` merges the local models with
  `<device>/<model>` entries from each reachable Tier 3 device. The devices are
  probed concurrently with a 3 s deadline and the result is cached for a few
  seconds. Each `<device>/<model>` entry carries `"loaded": true` or `false`
  from that device's `/api/v1/health` `all_models_loaded`, and the status lists
  `models_count` and `loaded_count` per device from the same probe, so an app
  can show every model with a loaded badge without another request. A model
  name that matches a local model ID exactly stays local, even
  when it contains `/`; otherwise `<device>/<model>` names that device. A
  device that answers 401 or 403 to the peer key is never chosen by `auto`.
- The TLS server name and the `Host` header must name the same host, otherwise
  the answer is 421. Another device's `<device>.<group-label>.lo.<base>` is
  forwarded over mesh egress to its lemond on mesh port 13305. That device must
  be online and Tier 3 (409 otherwise), and this device must hold
  `connect_private`, `connect_shared` or `admin` on it (403 otherwise). An
  unknown name answers 404.
- The port closes its loopback bridge to a device when the device's mesh
  address or its relay path changes (it moves onto a relay, onto a new relay
  allocation, or back to a direct path), so the next request opens a fresh
  bridge. A forwarded request whose bridge answers nothing within 10 s gets a
  new bridge and is sent once more; a request that reached the device and
  failed before its first response byte can therefore run twice. An
  application that holds a port from `ln_mesh_open_egress` should call it
  again before each connection.
- This device's own name and the loopback names serve the selection: `local`
  (the local service URL given to `ln_mesh_port_start`), `auto`, or one node ID.
  Without a selection, or when the selected device is offline, the answer is
  409. The port never falls back to another device.
- One process owns the port. A second `ln_mesh_port_start` on the same port
  returns `LN_ERR_PORT_IN_USE`.

The C++ class is `lnsdk::MeshPort` in `LemonadeNexusSDK/MeshPort.hpp`.

## Error Handling

C++:

```cpp
auto result = client.check_health();
if (!result.ok) {
    std::cerr << "error: " << result.error
              << " (http " << result.http_status << ")\n";
    return;
}
```

C error codes (`ln_error_t`):

| Value | Constant | Meaning |
|-------|----------|---------|
| 0 | `LN_OK` | Success |
| -1 | `LN_ERR_NULL_ARG` | Null pointer argument |
| -2 | `LN_ERR_CONNECT` | Connection/transport failed |
| -3 | `LN_ERR_AUTH` | Authentication failed (401/403) |
| -4 | `LN_ERR_NOT_FOUND` | Not found (404) |
| -5 | `LN_ERR_REJECTED` | Request rejected |
| -6 | `LN_ERR_NO_IDENTITY` | No identity attached |
| -7 | `LN_ERR_PARSE` | Malformed response (2xx with unparseable body) |
| -8 | `LN_ERR_UNSUPPORTED` | Retired operation; no server endpoint exists |
| -9 | `LN_ERR_PORT_IN_USE` | Another socket owns the requested loopback port |
| -99 | `LN_ERR_INTERNAL` | Internal error |

## Retired C Functions

These symbols remain exported for ABI stability. They always return
`LN_ERR_UNSUPPORTED`; the server routes they called no longer exist:

- `ln_trust_status` (`/api/trust/status`)
- `ln_trust_peer` (`/api/trust/peer/{pubkey}`)
- `ln_enrollment_status` (`/api/enrollment/status`)
- `ln_governance_proposals` (`/api/governance/proposals`)
- `ln_governance_propose` (`/api/governance/propose`)

Do not build new functionality on them.

## Best Practices

1. **Use an identity.** Ed25519 challenge-response is the primary path;
   password authentication is a deprecated stub.
2. **Store the identity securely.** Keychain/credential storage, never a
   plaintext file in the app bundle.
3. **Always TLS.** `ln_create_tls()` / the default `ServerConfig` — the
   server has no plaintext fallback anyway.
4. **Hosts must be certificate FQDNs.** A bare IP cannot verify a
   certificate.
5. **Prefer the convenience methods** (`create_child_node`, `update_node`,
   `delete_node`) over hand-built deltas.
6. **Handle join failure gracefully** — retry with backoff; re-join with the
   preserved identity after a server failure.
7. **Session tokens expire** — re-authenticate on 401.
8. **Clean up on exit** — `disable_mesh()`, then destroy the client and
   identity handles.
