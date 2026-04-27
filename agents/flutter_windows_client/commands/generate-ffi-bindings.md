# Command: Generate FFI Bindings

## Description
Delegates FFI wrapper creation to the FFI Bindings Agent for all 40+ C SDK functions.

## Purpose
Create type-safe Dart FFI wrappers that provide clean, idiomatic Dart access to the C SDK.

## Delegation Target
**FFI Bindings Agent** (`../ffi_bindings_agent/agent.md`)

## Steps

### 1. Invoke FFI Agent
```
Delegate to FFI Bindings Agent:
"Generate complete FFI bindings for lemonade_nexus.h"
```

### 2. FFI Agent Deliverables
- `ffi_bindings.dart` - Raw FFI function bindings
- `sdk_wrapper.dart` - Idiomatic Dart wrapper classes
- `types.dart` - Dart model classes for JSON data
- `native_library.dart` - Dynamic library loading

### 3. Integration Verification
- Verify all 40+ functions wrapped
- Test library loading on Windows
- Validate JSON parsing for complex types

## C SDK Functions to Wrap

### Memory Management (1)
- `ln_free` - Free allocated strings

### Client Lifecycle (3)
- `ln_create` - Create client (plaintext)
- `ln_create_tls` - Create client (TLS)
- `ln_destroy` - Destroy client

### Identity Management (8)
- `ln_identity_generate` - Generate keypair
- `ln_identity_load` - Load from file
- `ln_identity_save` - Save to file
- `ln_identity_pubkey` - Get public key
- `ln_identity_destroy` - Destroy identity
- `ln_set_identity` - Attach to client
- `ln_identity_from_seed` - Create from seed
- `ln_derive_seed` - Derive from password

### Health & Authentication (5)
- `ln_health` - Health check
- `ln_auth_password` - Password auth
- `ln_auth_passkey` - Passkey auth
- `ln_auth_token` - Token auth
- `ln_auth_ed25519` - Challenge-response

### Tree Operations (7)
- `ln_tree_get_node` - Get node
- `ln_tree_submit_delta` - Submit delta
- `ln_create_child_node` - Create child
- `ln_update_node` - Update node
- `ln_delete_node` - Delete node
- `ln_tree_get_children` - Get children
- `ln_get_group_members` - Get members

### Network Operations (10)
- `ln_ipam_allocate` - Allocate IP
- `ln_relay_list` - List relays
- `ln_relay_ticket` - Get relay ticket
- `ln_relay_register` - Register relay
- `ln_cert_status` - Cert status
- `ln_cert_request` - Request cert
- `ln_cert_decrypt` - Decrypt cert
- `ln_stats` - Server stats
- `ln_servers` - List servers
- `ln_join_group` - Join group

### Mesh & Tunnel (10)
- `ln_mesh_enable` - Enable mesh
- `ln_mesh_enable_config` - Enable with config
- `ln_mesh_disable` - Disable mesh
- `ln_mesh_status` - Mesh status
- `ln_mesh_peers` - List peers
- `ln_mesh_refresh` - Refresh peers
- `ln_tunnel_up` - Bring tunnel up
- `ln_tunnel_down` - Tear tunnel down
- `ln_tunnel_status` - Tunnel status
- `ln_get_wg_config` - Get WireGuard config

### Additional (8)
- `ln_enable_auto_switching` - Auto-switch
- `ln_disable_auto_switching` - Disable switch
- `ln_current_latency_ms` - Current latency
- `ln_server_latencies` - All latencies
- `ln_trust_status` - Trust status
- `ln_trust_peer` - Peer trust
- `ln_ddns_status` - DDNS status
- `ln_enrollment_status` - Enrollment

## Expected Output
- Complete FFI bindings in `lib/src/sdk/`
- Type-safe Dart API
- JSON parsing for all complex types
- Error handling wrappers

## Success Criteria
- All 40+ functions accessible from Dart
- No memory leaks (proper ln_free calls)
- Clean error messages
- Type-safe API
