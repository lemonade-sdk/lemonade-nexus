# Lemonade Nexus SDK for Flutter

Dart FFI wrapper for the Lemonade Nexus C SDK.

## Files

| File | Description |
|------|-------------|
| `ffi_bindings.dart` | Low-level FFI bindings to the C ABI |
| `models.dart` (+ `models.g.dart`) | Type-safe Dart models for JSON responses (`json_serializable`) |
| `lemonade_nexus_sdk.dart` | High-level async Dart API |
| `sdk.dart` | Barrel export |

The C ABI surface is defined in
[`projects/LemonadeNexusSDK/include/LemonadeNexusSDK/lemonade_nexus.h`](../../../../../projects/LemonadeNexusSDK/include/LemonadeNexusSDK/lemonade_nexus.h).
Keep the binding list in sync with that header; do not track a manual
function count here.

## Function groups (by C ABI section)

- **Memory:** `ln_free`
- **Lifecycle:** `ln_create`, `ln_create_tls`, `ln_destroy`
- **Identity:** `ln_identity_generate`, `ln_identity_load`,
  `ln_identity_save`, `ln_identity_pubkey`, `ln_identity_destroy`,
  `ln_set_identity`, `ln_identity_from_seed`, `ln_derive_seed`
- **Health/stats/discovery:** `ln_health`, `ln_stats`, `ln_servers`,
  `ln_server_latencies`
- **Authentication:** `ln_auth_ed25519` (primary), `ln_auth_passkey`,
  `ln_auth_passkey_challenge`, `ln_register_passkey`, `ln_auth_password`
  (deprecated server stub — kept for compatibility), `ln_auth_token`
- **Join/leave:** `ln_join_network`, `ln_leave_network`
- **Tree:** `ln_tree_get_node`, `ln_tree_get_children`,
  `ln_tree_submit_delta`, `ln_create_child_node`, `ln_update_node`,
  `ln_delete_node`, `ln_add_group_member`, `ln_remove_group_member`,
  `ln_get_group_members`, `ln_join_group`
- **IPAM / relay / certs:** `ln_ipam_allocate`, `ln_relay_list`,
  `ln_relay_ticket`, `ln_relay_register`, `ln_cert_status`,
  `ln_cert_request`, `ln_cert_decrypt`
- **Mesh:** `ln_mesh_enable`, `ln_mesh_enable_config`, `ln_mesh_disable`,
  `ln_mesh_status`, `ln_mesh_peers`, `ln_mesh_refresh`,
  `ln_mesh_expose_service`, `ln_mesh_open_egress`, `ln_generate_keypair`
- **Routing (connect-by-identifier):** `ln_routing_profile`,
  `ln_routing_request`, `ln_routing_connection_status`
- **Sessions/devices:** `ln_set_session_token`, `ln_get_session_token`,
  `ln_set_node_id`, `ln_get_node_id`, `ln_set_link_token`,
  `ln_link_token_create`
- **Private API / misc:** `ln_private_api_call`, `ln_ddns_status`,
  `ln_attestation_manifests`, group-key envelopes (`ln_group_key_generate`,
  `ln_group_key_wrap`, `ln_group_key_unwrap`)
- **Retired ABI stubs** — the server routes are gone; the symbols remain
  exported and return `LN_ERR_UNSUPPORTED`: `ln_trust_status`,
  `ln_trust_peer`, `ln_enrollment_status`, `ln_governance_proposals`,
  `ln_governance_propose`

## Usage

```dart
import 'package:nexus_client/src/sdk/lemonade_nexus_sdk.dart';

final sdk = LemonadeNexusSdk();

try {
  // Connect via TLS; host must be the server's certificate FQDN
  await sdk.connectTls('server.example.com', 9100);

  // Primary path: Ed25519 identity (generate once, persist, reload)
  final identity = await sdk.generateIdentity();
  print('Public key: ${identity.pubkey}');

  final auth = await sdk.authEd25519();
  if (auth.authenticated) {
    final network = await sdk.joinNetwork();
    if (network.success) {
      print('Node ID: ${network.nodeId}');
      print('Tunnel IP: ${network.tunnelIp}');
    }
  }
} finally {
  sdk.dispose();
}
```

`authPassword(...)` is bound for compatibility, but the server's password
authentication is a deprecated stub that always fails.

## Error Codes

The C ABI returns `ln_error_t`: `LN_OK` (0), `LN_ERR_NULL_ARG` (-1),
`LN_ERR_CONNECT` (-2), `LN_ERR_AUTH` (-3), `LN_ERR_NOT_FOUND` (-4),
`LN_ERR_REJECTED` (-5), `LN_ERR_NO_IDENTITY` (-6), `LN_ERR_PARSE` (-7),
`LN_ERR_UNSUPPORTED` (-8), `LN_ERR_INTERNAL` (-99).

Dart methods throw `SdkException` (carrying the error code) or
`JsonParseException`.

## Memory Management

The wrapper frees C strings after conversion and releases identity and
client handles on dispose. Always call `sdk.dispose()` when done.

## Platform Support

| Platform | Status | Library Name |
|----------|--------|--------------|
| Windows | Build definitions present; CI disabled | `lemonade_nexus_sdk.dll` |
| macOS | CI-verified | `liblemonade_nexus_sdk.dylib` |
| Linux | Not a client target (server platform) | `liblemonade_nexus_sdk.so` |

## Code Generation

The models use `json_serializable`. Regenerate after changing `models.dart`:

```bash
flutter pub run build_runner build --delete-conflicting-outputs
```
