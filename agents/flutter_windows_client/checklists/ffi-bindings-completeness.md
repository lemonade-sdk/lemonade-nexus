# Checklist: FFI Bindings Completeness

## Purpose
Ensure all C SDK functions have complete, tested Dart FFI wrappers.

## Function Coverage

### Memory Management (1 function)
- [ ] `ln_free` - Free allocated strings
- [ ] Proper memory management pattern implemented
- [ ] No memory leaks in testing

### Client Lifecycle (3 functions)
- [ ] `ln_create` - Create client (plaintext)
- [ ] `ln_create_tls` - Create client (TLS)
- [ ] `ln_destroy` - Destroy client
- [ ] Client wrapper class created

### Identity Management (8 functions)
- [ ] `ln_identity_generate` - Generate keypair
- [ ] `ln_identity_load` - Load from file
- [ ] `ln_identity_save` - Save to file
- [ ] `ln_identity_pubkey` - Get public key
- [ ] `ln_identity_destroy` - Destroy identity
- [ ] `ln_set_identity` - Attach to client
- [ ] `ln_identity_from_seed` - Create from seed
- [ ] `ln_derive_seed` - Derive from password
- [ ] Identity wrapper class created

### Health & Authentication (5 functions)
- [ ] `ln_health` - Health check
- [ ] `ln_auth_password` - Password auth
- [ ] `ln_auth_passkey` - Passkey auth
- [ ] `ln_auth_token` - Token auth
- [ ] `ln_auth_ed25519` - Challenge-response
- [ ] Auth service wrapper created

### Tree Operations (5 functions)
- [ ] `ln_tree_get_node` - Get node
- [ ] `ln_tree_submit_delta` - Submit delta
- [ ] `ln_create_child_node` - Create child
- [ ] `ln_update_node` - Update node
- [ ] `ln_delete_node` - Delete node

### Tree - Children & Groups (4 functions)
- [ ] `ln_tree_get_children` - Get children
- [ ] `ln_add_group_member` - Add member
- [ ] `ln_remove_group_member` - Remove member
- [ ] `ln_get_group_members` - Get members
- [ ] `ln_join_group` - Join group

### IPAM & Relay (4 functions)
- [ ] `ln_ipam_allocate` - Allocate IP
- [ ] `ln_relay_list` - List relays
- [ ] `ln_relay_ticket` - Get relay ticket
- [ ] `ln_relay_register` - Register relay

### Certificates (3 functions)
- [ ] `ln_cert_status` - Cert status
- [ ] `ln_cert_request` - Request cert
- [ ] `ln_cert_decrypt` - Decrypt cert

### Mesh Networking (6 functions)
- [ ] `ln_mesh_enable` - Enable mesh
- [ ] `ln_mesh_enable_config` - Enable with config
- [ ] `ln_mesh_disable` - Disable mesh
- [ ] `ln_mesh_status` - Mesh status
- [ ] `ln_mesh_peers` - List peers
- [ ] `ln_mesh_refresh` - Refresh peers

### WireGuard Tunnel (5 functions)
- [ ] `ln_tunnel_up` - Bring tunnel up
- [ ] `ln_tunnel_down` - Tear tunnel down
- [ ] `ln_tunnel_status` - Tunnel status
- [ ] `ln_get_wg_config` - Get WireGuard config
- [ ] `ln_get_wg_config_json` - Get config as JSON
- [ ] `ln_wg_generate_keypair` - Generate keys

### Auto-Switching (4 functions)
- [ ] `ln_enable_auto_switching` - Enable auto-switch
- [ ] `ln_disable_auto_switching` - Disable auto-switch
- [ ] `ln_current_latency_ms` - Current latency
- [ ] `ln_server_latencies` - All latencies

### Stats & Servers (2 functions)
- [ ] `ln_stats` - Server stats
- [ ] `ln_servers` - List servers

### Trust & Attestation (4 functions)
- [ ] `ln_trust_status` - Trust status
- [ ] `ln_trust_peer` - Peer trust
- [ ] `ln_ddns_status` - DDNS status
- [ ] `ln_enrollment_status` - Enrollment

### Governance (2 functions)
- [ ] `ln_governance_proposals` - List proposals
- [ ] `ln_governance_propose` - Create proposal

### Session Management (4 functions)
- [ ] `ln_set_session_token` - Set token
- [ ] `ln_get_session_token` - Get token
- [ ] `ln_set_node_id` - Set node ID
- [ ] `ln_get_node_id` - Get node ID

## Code Quality

### FFI Bindings
- [ ] Native typedefs defined correctly
- [ ] Dart typedefs match native signatures
- [ ] Function lookups in constructor
- [ ] Late final fields for functions

### Memory Management
- [ ] Proper try/finally blocks
- [ ] ln_free called for SDK strings
- [ ] calloc.free for Dart allocations
- [ ] No memory leaks detected

### Error Handling
- [ ] Error codes mapped to exceptions
- [ ] Descriptive error messages
- [ ] Original errors preserved
- [ ] Custom exception classes

### Type Safety
- [ ] Strong typing throughout
- [ ] Nullable types where appropriate
- [ ] Generic types for collections
- [ ] Enum types for status codes

## Documentation

### Code Documentation
- [ ] Dart doc comments on all public APIs
- [ ] Parameter documentation
- [ ] Return value documentation
- [ ] Exception documentation

### Usage Examples
- [ ] Example code for each function
- [ ] Common patterns documented
- [ ] Error handling examples
- [ ] Memory management examples

## Testing

### Unit Tests
- [ ] Tests for each FFI function
- [ ] Memory management tests
- [ ] Error handling tests
- [ ] Edge case tests

### Integration Tests
- [ ] End-to-end function tests
- [ ] Real SDK integration tests
- [ ] Performance tests
- [ ] Stress tests

## Final Verification

- [ ] All 60+ functions wrapped
- [ ] All tests passing
- [ ] No memory leaks
- [ ] Documentation complete
- [ ] Code review completed

## Sign-off

- Reviewed by: _______________
- Date: _______________
- Status: [ ] Pass [ ] Fail [ ] Conditional
