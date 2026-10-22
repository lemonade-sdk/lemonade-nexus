#include <LemonadeNexus/Tree/TreeOpSubmitter.hpp>

#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>

#include <chrono>

namespace nexus::tree {

TreeOpSubmitter::TreeOpSubmitter(PermissionTreeService& tree,
                                 crypto::SodiumCryptoService& crypto,
                                 const security::NetworkId& network_id,
                                 const crypto::Ed25519Keypair& server_key)
    : tree_(tree), crypto_(crypto), server_key_(server_key) {
    policy_.network_id = network_id;
    policy_.trusted_submitters.push_back(
        "ed25519:" + crypto::to_base64(std::span<const uint8_t>(
                         server_key.public_key.data(), server_key.public_key.size())));
}

uint64_t TreeOpSubmitter::now_sec() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
                                     std::chrono::system_clock::now().time_since_epoch())
                                     .count());
}

TreeOp TreeOpSubmitter::seal(TreeOp op, uint64_t now) const {
    op.network_id = policy_.network_id;
    if (op.signed_at == 0) op.signed_at = now;
    crypto_.random_bytes(std::span<uint8_t>(op.nonce));
    sign_tree_op(crypto_, op, server_key_);
    op.submitted_by = op.author;
    return op;
}

TreeOpVerdict TreeOpSubmitter::submit(TreeOp op) {
    const auto now = now_sec();
    return tree_.submit_local_op(seal(std::move(op), now), policy_, now);
}

TreeOpVerdict TreeOpSubmitter::dry_run(TreeOp op) const {
    const auto now = now_sec();
    return tree_.validate_local_op(seal(std::move(op), now), policy_, now);
}

}  // namespace nexus::tree
