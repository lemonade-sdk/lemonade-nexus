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

`check_health()` also fails when the session's server is no longer a verified
Tier 1 server; join again, and the SDK picks another one.

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

## Invites and Other Networks

An invite is a single-use code for one group. One call creates it: without a
target it is for your own top-level group, with a target it is for that group
(a subgroup, or another user's group where you hold `add_child`).

```cpp
auto own = client.create_link_token(600);                       // own group
auto sub = client.create_link_token(600, "group-id",            // chosen group
                                    {"read", "connect_private"});
// sub.value["link_token"] is the code to share.
```

| C++ | C | Purpose |
|-----|---|---------|
| `create_link_token(ttl, target, perms)` | `ln_invite_create(client, target_or_NULL, perms_json_or_NULL, ttl, &json)` | Create an invite |
| `accept_invite(code)` | `ln_invite_accept(client, code, &json)` | Join another network with an existing account |
| `list_memberships()` | `ln_memberships_list(client, &json)` | Groups this identity belongs to |
| `leave_membership(group)` | `ln_membership_leave(client, group, &json)` | Leave a group joined by invite |
| `move_node(node, parent)` | `ln_move_node(client, node, parent, &json)` | Move a device or subgroup |

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
updates["hostname"] = "new-name";
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
  SDK certificate renewer keeps the certificate current, and the port reloads
  each renewed certificate for new connections.
- The TLS server name and the `Host` header must name the same host, otherwise
  the answer is 421. Another device's `<device>.<group-label>.lo.<base>` is
  forwarded over mesh egress to its lemond on mesh port 13305. That device must
  be online and Tier 3 (409 otherwise), and this device must hold
  `connect_private`, `connect_shared` or `admin` on it (403 otherwise). An
  unknown name answers 404.
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
