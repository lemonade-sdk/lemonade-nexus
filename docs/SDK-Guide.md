# SDK Guide

## Table of Contents
- [Overview](#overview)
- [Quick Start (C++)](#quick-start-c)
- [Quick Start (C API)](#quick-start-c-api)
- [Identity Management](#identity-management)
- [Authentication](#authentication)
- [Joining the Network](#joining-the-network)
- [WireGuard Tunnel](#wireguard-tunnel)
- [Tree Operations](#tree-operations)
- [Mesh P2P](#mesh-p2p)
- [Best Practices](#best-practices)
- [Error Handling](#error-handling)
- [Platform Notes](#platform-notes)

## Overview

The **LemonadeNexusSDK** is a C++ library with a C FFI layer for integrating the mesh VPN into any application. It handles identity, authentication, network joining, WireGuard tunnel management, and peer-to-peer mesh networking.

## Quick Start (C++)

```cpp
#include <LemonadeNexusSDK/LemonadeNexusClient.hpp>

// Connect to a server
lnsdk::ServerConfig config;
config.servers.push_back({"server.example.com", 9100, true}); // host, port, tls

lnsdk::LemonadeNexusClient client(config);

// Derive identity from username/password (deterministic: same creds = same keypair)
client.derive_identity("user@example.com", "password123");

// Join the mesh (auth + create node + allocate IP + WG config)
auto result = client.join_network("user@example.com", "");
if (result.ok) {
    std::cout << "Node ID: " << result.value.node_id << "\n";
    std::cout << "Tunnel IP: " << result.value.tunnel_ip << "\n";
    // WireGuard tunnel is automatically configured
}

// Enable mesh P2P for direct client-to-client connections
lnsdk::MeshConfig mesh_cfg;
mesh_cfg.heartbeat_interval_sec = 5;
client.enable_mesh(mesh_cfg);
```

## Quick Start (C API)

```c
#include "lemonade_nexus.h"

// Create client (TLS)
ln_client_t* client = ln_create_tls("server.example.com", 9100);

// Generate or derive identity
ln_identity_t* id = ln_identity_from_seed(client, "user", "pass");

// Authenticate
char* auth_json = NULL;
ln_auth_ed25519(client, &auth_json);
ln_free(auth_json);

// Join network
char* join_json = NULL;
ln_join_network(client, &join_json);
// join_json contains: tunnel_ip, node_id, wg_endpoint, etc.
ln_free(join_json);

// Bring up WireGuard tunnel
char* tunnel_json = NULL;
ln_tunnel_up(client, NULL, &tunnel_json);
ln_free(tunnel_json);

// Clean up
ln_destroy(client);
```

## Identity Management

```cpp
// Option 1: Derive from credentials (deterministic)
client.derive_identity("username", "password");
// PBKDF2(SHA256, 100k iterations) → 32-byte seed → Ed25519 keypair

// Option 2: Random keypair
auto identity = client.generate_identity();

// Option 3: Load from disk
client.load_identity("/path/to/identity.json");

// Save to disk
client.save_identity("/path/to/identity.json");

// Get public key (base64)
auto pubkey = client.public_key_string();
// Returns "ed25519:base64..." format
```

**Key derivation chain:**
```
username + password
    → PBKDF2(SHA256, 100k rounds)
    → 32-byte seed
    → Ed25519 keypair (identity)
    → X25519 keypair (WireGuard, derived from Ed25519)
```

## Authentication

```cpp
// Ed25519 challenge-response (primary)
auto auth = client.authenticate_ed25519();
// Server sends nonce → client signs → server verifies

// Passkey registration (macOS Secure Enclave)
auto reg = client.register_passkey(credential_id, pub_x, pub_y);

// Passkey authentication
auto auth = client.authenticate_passkey(credential_id, auth_data, client_data, signature);

// Password auth
auto auth = client.authenticate("username", "password");
```

## Joining the Network

```cpp
auto result = client.join_network("username", "password");
```

The join flow is composite — one call does everything:
1. Authenticate (Ed25519 challenge-response)
2. Create endpoint node in the permission tree
3. Allocate tunnel IP from IPAM (10.64.0.10+)
4. Get server's WireGuard public key and endpoint
5. Configure WireGuard tunnel (bring up if possible)

**Response fields:**
| Field | Example | Description |
|-------|---------|-------------|
| `node_id` | `09ba6947...` | Your unique node ID |
| `tunnel_ip` | `10.64.0.10/32` | Your WireGuard tunnel IP |
| `server_tunnel_ip` | `10.64.0.1` | Server's tunnel IP |
| `server_private_fqdn` | `private.<id>.<region>.seip.<domain>` | Server's private HTTPS hostname |
| `wg_server_pubkey` | `base64...` | Server's WireGuard X25519 key |
| `wg_endpoint` | `67.x.x.x:51940` | Server's WireGuard endpoint |

After joining, private API calls (tree, IPAM, mesh) route through HTTPS over the WireGuard tunnel via the `server_private_fqdn`.

## WireGuard Tunnel

```cpp
// Tunnel is usually brought up automatically during join_network()
// Manual control:

WireGuardConfig config;
config.private_key = "base64...";
config.public_key = "base64...";
config.tunnel_ip = "10.64.0.10/32";
config.server_public_key = "base64...";
config.server_endpoint = "67.x.x.x:51940";
config.keepalive = 5;  // 5-second persistent keepalive

auto result = client.bring_up_tunnel(config);
auto result = client.bring_down_tunnel();

// Get config as JSON (for external tunnel management on iOS/Android)
auto json = client.wireguard_config_json();
```

## Tree Operations

All tree operations go through the private API (HTTPS over WG tunnel):

```cpp
// Read a node
auto node = client.get_tree_node("node-id");

// List children
auto children = client.get_children("parent-id");

// Create a child node
auto result = client.create_child_node("parent-id", "endpoint");

// Update a node
auto result = client.update_node("node-id", {{"hostname", "new-name"}});

// Delete a node
auto result = client.delete_node("node-id");
```

## Mesh P2P

Enable peer-to-peer connections between clients:

```cpp
MeshConfig cfg;
cfg.peer_refresh_interval_sec = 30;  // Poll server for peer updates
cfg.heartbeat_interval_sec = 5;      // Report endpoint to server
cfg.prefer_direct = true;            // Prefer direct P2P over relay

client.enable_mesh(cfg);

// Set callback for mesh state changes
client.set_mesh_callback([](const MeshTunnelStatus& status) {
    std::cout << "Peers: " << status.peer_count
              << " Online: " << status.online_count << "\n";
});

// Get current mesh status
auto status = client.mesh_status();
// status.is_up, status.peer_count, status.online_count, status.peers[]

client.disable_mesh();
```

## Best Practices

1. **Always derive identity before auth** — PBKDF2 is deterministic, same credentials = same keypair across devices
2. **Store identity in Keychain** — never write keys to plaintext files
3. **Use TLS** for the initial connection — `ln_create_tls()` not `ln_create()`
4. **Let the SDK handle key conversion** — Ed25519 → X25519 is automatic
5. **Don't construct deltas directly** — use server endpoints (`create_child_node`, `update_node`, etc.)
6. **Enable mesh** for P2P connectivity between clients
7. **Handle join failure gracefully** — retry with exponential backoff
8. **Session tokens expire** — re-authenticate if you get HTTP 401
9. **Clean up on exit** — call `bring_down_tunnel()` and `disable_mesh()`
10. **Use the private FQDN** — after join, all sensitive API calls route through HTTPS over the WG tunnel

## Error Handling

All C++ methods return `Result<T>`:

```cpp
auto result = client.join_network("user", "pass");
if (!result.ok) {
    std::cerr << "Error: " << result.error << "\n";
    std::cerr << "HTTP status: " << result.http_status << "\n";
    return;
}
auto& join = result.value;
```

C API error codes:
| Code | Constant | Meaning |
|------|----------|---------|
| 0 | `LN_OK` | Success |
| 1 | `LN_ERR_NULL_ARG` | Null pointer argument |
| 2 | `LN_ERR_CONNECT` | Connection failed |
| 3 | `LN_ERR_AUTH` | Authentication failed |
| 4 | `LN_ERR_PARSE` | JSON parse error |
| 5 | `LN_ERR_INTERNAL` | Internal error |

## Platform Notes

| Platform | WireGuard Backend | Notes |
|----------|------------------|-------|
| **Linux** | Kernel module (preferred), BoringTun fallback | Best performance with kernel WG |
| **macOS** | BoringTun via privilege-escalated helper | AppleScript password dialog for utun creation |
| **Windows** | wireguard-nt kernel driver (auto-downloaded) | Requires admin privileges |
| **iOS** | Config-only | App uses `NEPacketTunnelProvider`, SDK generates WG config |
| **Android** | Config-only | App uses `VpnService`, SDK generates WG config |

On mobile platforms, the SDK generates the WireGuard configuration string and the host app manages the VPN lifecycle through OS APIs.
