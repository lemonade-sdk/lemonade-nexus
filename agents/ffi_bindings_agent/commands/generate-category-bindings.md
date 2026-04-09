# Command: Generate Category Bindings

## Description
Generate FFI bindings for a specific function category.

## Purpose
Focused binding generation for one functional area at a time.

## Categories

### Identity Management (8 functions)
- `ln_identity_generate`
- `ln_identity_load`
- `ln_identity_save`
- `ln_identity_pubkey`
- `ln_identity_destroy`
- `ln_set_identity`
- `ln_identity_from_seed`
- `ln_derive_seed`

### Authentication (5 functions)
- `ln_auth_password`
- `ln_auth_passkey`
- `ln_auth_token`
- `ln_auth_ed25519`
- `ln_health`

### Tunnel Operations (6 functions)
- `ln_tunnel_up`
- `ln_tunnel_down`
- `ln_tunnel_status`
- `ln_get_wg_config`
- `ln_get_wg_config_json`
- `ln_wg_generate_keypair`

### Mesh Networking (6 functions)
- `ln_mesh_enable`
- `ln_mesh_enable_config`
- `ln_mesh_disable`
- `ln_mesh_status`
- `ln_mesh_peers`
- `ln_mesh_refresh`

### Tree Operations (9 functions)
- `ln_tree_get_node`
- `ln_tree_submit_delta`
- `ln_create_child_node`
- `ln_update_node`
- `ln_delete_node`
- `ln_tree_get_children`
- `ln_add_group_member`
- `ln_remove_group_member`
- `ln_get_group_members`

### Other Categories
- Client Lifecycle (3)
- IPAM/Relay (4)
- Certificates (3)
- Auto-Switching (4)
- Stats/Discovery (2)
- Trust/Attestation (4)
- Governance (2)
- Session (4)

## Usage
```
"Generate FFI bindings for [CATEGORY] category"
Example: "Generate FFI bindings for Authentication category"
```

## Output
- Category-specific FFI code
- Category wrapper class
- Category-specific tests
