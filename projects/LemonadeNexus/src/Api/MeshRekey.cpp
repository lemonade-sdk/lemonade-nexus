#include <LemonadeNexus/Api/MeshRekey.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>

#include <cstring>
#include <span>

namespace nexus::api {

std::string normalize_mesh_pubkey(std::string_view wg_pubkey) {
    constexpr std::string_view ed_prefix = "ed25519:";
    if (!wg_pubkey.starts_with(ed_prefix)) return std::string(wg_pubkey);
    try {
        auto ed_bytes = crypto::from_base64(wg_pubkey.substr(ed_prefix.size()));
        if (ed_bytes.size() == crypto::kEd25519PublicKeySize) {
            crypto::Ed25519PublicKey ed_pk{};
            std::memcpy(ed_pk.data(), ed_bytes.data(), ed_bytes.size());
            auto x_pk = crypto::SodiumCryptoService::ed25519_pk_to_x25519(ed_pk);
            return crypto::to_base64(std::span<const uint8_t>(x_pk.data(), x_pk.size()));
        }
    } catch (...) {}
    return std::string(wg_pubkey);
}

MeshRekeyPlan plan_mesh_rekey(std::string_view prev_ip, std::string_view new_ip,
                              std::string_view prev_wg, std::string_view new_wg) {
    MeshRekeyPlan plan;
    plan.new_peer_key = normalize_mesh_pubkey(new_wg);

    // Rewrite the stored node when the IP OR the key changed. The old code
    // updated only on an IP change, so a re-join (same IP) with a rotated key
    // left a stale wg_pubkey on the node.
    plan.update_node = (prev_ip != new_ip) || (prev_wg != new_wg);

    // Drop the previous dataplane peer when the key actually rotated — compared
    // on the normalized (Curve25519) key, since that is what the dataplane uses.
    if (!prev_wg.empty()) {
        auto prev_key = normalize_mesh_pubkey(prev_wg);
        if (prev_key != plan.new_peer_key) {
            plan.remove_stale_peer = true;
            plan.stale_peer_key = prev_key;
        }
    }
    return plan;
}

} // namespace nexus::api
