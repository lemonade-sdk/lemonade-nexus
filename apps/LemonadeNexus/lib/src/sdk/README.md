# Lemonade Nexus SDK for Flutter

Dart SDK for the Lemonade Nexus WireGuard mesh VPN platform.

## Files

| File | Description |
|------|-------------|
| `ffi_bindings.dart` | Low-level FFI bindings to the C SDK (~70 functions) |
| `models.dart` | Type-safe Dart model classes for JSON responses |
| `lemonade_nexus_sdk.dart` | High-level async Dart API |
| `README.md` | This documentation |

## C SDK Functions Wrapped

### Memory Management (1)
- `ln_free` - Free strings returned by C SDK

### Client Lifecycle (3)
- `ln_create` - Create client (plaintext HTTP)
- `ln_create_tls` - Create client (TLS)
- `ln_destroy` - Destroy client

### Identity Management (8)
- `ln_identity_generate` - Generate Ed25519 keypair
- `ln_identity_load` - Load identity from file
- `ln_identity_save` - Save identity to file
- `ln_identity_pubkey` - Get public key string
- `ln_identity_destroy` - Free identity
- `ln_set_identity` - Attach identity to client
- `ln_identity_from_seed` - Create identity from seed
- `ln_derive_seed` - Derive seed from username/password

### Health (1)
- `ln_health` - GET /api/health

### Authentication (5)
- `ln_auth_password` - Username/password auth
- `ln_auth_passkey` - Passkey/FIDO2 auth
- `ln_auth_token` - Token auth
- `ln_auth_ed25519` - Ed25519 challenge-response
- `ln_register_passkey` - Register passkey credential

### Tree Operations (6)
- `ln_tree_get_node` - Get node by ID
- `ln_tree_submit_delta` - Submit CRDT delta
- `ln_create_child_node` - Create child node
- `ln_update_node` - Update node
- `ln_delete_node` - Delete node
- `ln_tree_get_children` - Get children of node

### IPAM (1)
- `ln_ipam_allocate` - Allocate IP block

### Relay (3)
- `ln_relay_list` - List relay servers
- `ln_relay_ticket` - Get relay ticket
- `ln_relay_register` - Register with relay

### Certificates (3)
- `ln_cert_status` - Get cert status
- `ln_cert_request` - Request TLS cert
- `ln_cert_decrypt` - Decrypt cert bundle

### Group Membership (4)
- `ln_add_group_member` - Add member to group
- `ln_remove_group_member` - Remove member
- `ln_get_group_members` - List group members
- `ln_join_group` - Join group (create endpoint + IP)

### High-level Operations (2)
- `ln_join_network` - Auth + create node + allocate IP
- `ln_leave_network` - Leave network

### Auto-switching (4)
- `ln_enable_auto_switching` - Enable latency-based switching
- `ln_disable_auto_switching` - Disable switching
- `ln_current_latency_ms` - Get current RTT
- `ln_server_latencies` - Get all server latencies

### WireGuard Tunnel (6)
- `ln_tunnel_up` - Bring up tunnel
- `ln_tunnel_down` - Tear down tunnel
- `ln_tunnel_status` - Get tunnel status
- `ln_get_wg_config` - Get wg-quick config
- `ln_get_wg_config_json` - Get config as JSON
- `ln_wg_generate_keypair` - Generate Curve25519 keypair

### Mesh P2P (6)
- `ln_mesh_enable` - Enable mesh (default config)
- `ln_mesh_enable_config` - Enable mesh (custom config)
- `ln_mesh_disable` - Disable mesh
- `ln_mesh_status` - Get mesh status
- `ln_mesh_peers` - Get mesh peers
- `ln_mesh_refresh` - Force peer refresh

### Stats & Server Listing (2)
- `ln_stats` - GET /api/stats
- `ln_servers` - GET /api/servers

### Trust & Attestation (2)
- `ln_trust_status` - Get trust status
- `ln_trust_peer` - Get peer trust info

### DDNS (1)
- `ln_ddns_status` - Get DDNS status

### Enrollment (1)
- `ln_enrollment_status` - Get enrollment entries

### Governance (2)
- `ln_governance_proposals` - List proposals
- `ln_governance_propose` - Submit proposal

### Attestation Manifests (1)
- `ln_attestation_manifests` - Get manifests

### Session Management (4)
- `ln_set_session_token` - Set session token
- `ln_get_session_token` - Get session token
- `ln_set_node_id` - Set node ID
- `ln_get_node_id` - Get node ID

**Total: 69 functions**

## Usage

### Basic Connection

```dart
import 'package:lemonade_nexus/src/sdk/lemonade_nexus_sdk.dart';

final sdk = LemonadeNexusSdk();

try {
  // Connect via TLS
  await sdk.connectTls('vpn.example.com', 443);

  // Generate identity
  final identity = await sdk.generateIdentity();
  print('Public key: ${identity.pubkey}');

  // Authenticate
  final auth = await sdk.authPassword('username', 'password');
  if (auth.authenticated) {
    print('Logged in as: ${auth.userId}');
  }

  // Join network
  final network = await sdk.joinNetwork(
    username: 'username',
    password: 'password',
  );

  if (network.success) {
    print('Node ID: ${network.nodeId}');
    print('Tunnel IP: ${network.tunnelIp}');
  }
} finally {
  sdk.dispose();
}
```

### WireGuard Tunnel

```dart
// Generate keypair
final keypair = await sdk.generateWgKeypair();

// Create config
final config = WgConfig(
  privateKey: keypair.privateKey,
  publicKey: keypair.publicKey,
  tunnelIp: network.tunnelIp!,
  serverPublicKey: serverPublicKey,
  serverEndpoint: '${server.host}:${server.port}',
  dnsServer: '8.8.8.8',
  listenPort: 0,  // Auto
  allowedIps: ['0.0.0.0/0'],
  keepalive: 25,
);

// Bring up tunnel
await sdk.tunnelUp(config);

// Check status
final status = await sdk.getTunnelStatus();
print('Tunnel is ${status.isUp ? "up" : "down"}');
print('RX: ${status.rxBytes} bytes');
print('TX: ${status.txBytes} bytes');
```

### Mesh P2P

```dart
// Enable mesh with custom config
await sdk.enableMeshWithConfig({
  'peer_refresh_interval_sec': 30,
  'heartbeat_interval_sec': 10,
  'stun_refresh_interval_sec': 60,
  'prefer_direct': true,
  'auto_connect': true,
});

// Get mesh status
final meshStatus = await sdk.getMeshStatus();
print('Peers: ${meshStatus.peerCount}');
print('Online: ${meshStatus.onlineCount}');

// List peers
final peers = await sdk.getMeshPeers();
for (final peer in peers) {
  if (peer.isOnline) {
    print('${peer.hostname}: ${peer.tunnelIp} (${peer.latencyMs}ms)');
  }
}
```

### Tree Operations

```dart
// Get root node children
final children = await sdk.getChildren('root');

// Create endpoint node
final endpoint = await sdk.createChildNode(
  parentId: 'customer-123',
  nodeType: 'endpoint',
);

// Update node
await sdk.updateNode(
  nodeId: endpoint.id,
  updates: {
    'hostname': 'my-device',
    'platform': 'windows',
  },
);
```

## Error Handling

All SDK methods throw either `SdkException` or `JsonParseException`:

```dart
try {
  await sdk.authPassword('user', 'pass');
} on SdkException catch (e) {
  print('SDK error: ${e.error.name} - ${e.message}');
} on JsonParseException catch (e) {
  print('JSON parse error: ${e.error}');
  print('Raw JSON: ${e.rawJson}');
}
```

## Error Codes

| Code | Name | Description |
|------|------|-------------|
| 0 | `LN_OK` | Success |
| -1 | `LN_ERR_NULL_ARG` | Null argument |
| -2 | `LN_ERR_CONNECT` | Connection failed |
| -3 | `LN_ERR_AUTH` | Authentication failed |
| -4 | `LN_ERR_NOT_FOUND` | Resource not found |
| -5 | `LN_ERR_REJECTED` | Request rejected |
| -6 | `LN_ERR_NO_IDENTITY` | No identity attached |
| -99 | `LN_ERR_INTERNAL` | Internal error |

## Memory Management

The SDK handles all FFI memory management automatically:
- C strings are freed after conversion
- Identity handles are tracked and freed on dispose
- Client handles are freed on dispose

Always call `sdk.dispose()` when done to release resources.

## Platform Support

| Platform | Status | Library Name |
|----------|--------|--------------|
| Windows | Supported | `lemonade_nexus.dll` |
| macOS | Supported | `liblemonade_nexus.dylib` |
| Linux | Supported | `liblemonade_nexus.so` |

## Building the C SDK

See `projects/LemonadeNexusSDK/` for C SDK build instructions.

## Code Generation

The models use `json_serializable` for JSON parsing. Run:

```bash
flutter pub run build_runner build --delete-conflicting-outputs
```

This generates `models.g.dart` from the `models.dart` annotations.
