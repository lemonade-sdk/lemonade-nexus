---
layout: default
title: SDK Guide
---

# SDK Guide

## Table of Contents
- [Overview](#overview)
- [Quick Start (C++)](#quick-start-c)
- [Quick Start (C API)](#quick-start-c-api)
- [Identity Management](#identity-management)
- [Authentication](#authentication)
- [Joining the Network](#joining-the-network)
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
3. Allocate the tunnel IP from IPAM (`10.64.0.x`)
4. Bring the in-process dataplane up

**Response fields:**

| Field | Example | Description |
|-------|---------|-------------|
| `node_id` | `09ba6947...` | Your unique node ID |
| `tunnel_ip` | `10.64.0.10/32` | Your mesh tunnel IP |
| `server_tunnel_ip` | `10.64.0.1` | Server's tunnel IP |
| `mesh_pubkey` | `base64...` | Server's mesh public key |
| `mesh_endpoint` | `<ip>:51940` | Server's mesh endpoint |

After joining, private API calls (tree, IPAM, mesh, routing, certs) route
over the mesh to the server's private API.

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
