#pragma once

#include <string>
#include <string_view>

namespace nexus::api {

/// Map a stored/sent wg_pubkey to the Curve25519 key the mesh dataplane keys
/// on: a raw key passes through unchanged; an "ed25519:"-prefixed key is
/// converted to X25519. Malformed input is returned unchanged (never throws).
[[nodiscard]] std::string normalize_mesh_pubkey(std::string_view wg_pubkey);

/// What POST /api/join must do to a returning device's stored endpoint node and
/// its dataplane peer. The decision is pure; the handler applies it (tree write,
/// peer remove/add). A fresh key each launch left a stale server peer whose
/// allowed_ips route shadowed the new key, so a rotation must both rewrite the
/// stored key and drop the previous peer before adding the new one.
struct MeshRekeyPlan {
    bool        update_node       = false;  ///< rewrite node: tunnel_ip and/or wg_pubkey changed
    bool        remove_stale_peer = false;  ///< drop the previous dataplane peer first
    std::string stale_peer_key;             ///< normalized key to remove (when remove_stale_peer)
    std::string new_peer_key;               ///< normalized key to add
};

/// `prev_*` are the currently-stored values ("" when the node is new); `new_*`
/// are from this join. `new_wg` empty means the join carried no key.
[[nodiscard]] MeshRekeyPlan plan_mesh_rekey(std::string_view prev_ip,
                                            std::string_view new_ip,
                                            std::string_view prev_wg,
                                            std::string_view new_wg);

} // namespace nexus::api
