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

TreeOpSubmitter::TreeOpSubmitter(PermissionTreeService& tree,
                                 crypto::SodiumCryptoService& crypto,
                                 const security::NetworkId& network_id,
                                 const crypto::Ed25519Keypair& server_key,
                                 TreeOpGateway gateway, std::chrono::milliseconds commit_wait)
    : TreeOpSubmitter(tree, crypto, network_id, server_key) {
    gateway_ = std::move(gateway);
    commit_wait_ = commit_wait;
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

TreeOpSubmission TreeOpSubmitter::submit(TreeOp op) {
    const auto now = now_sec();
    TreeOp sealed = seal(std::move(op), now);
    TreeOpSubmission out;
    out.op_id = op_id_hex(sealed);
    if (!gateway_) {
        out.verdict = tree_.submit_local_op(sealed, policy_, now);
        return out;
    }
    auto admission = gateway_(std::move(sealed));
    if (!admission.verdict.ok() || !admission.ticket) {
        out.verdict = std::move(admission.verdict);
        return out;
    }
    out.ticket = admission.ticket;
    const auto outcome = admission.ticket->wait_for(commit_wait_);
    switch (outcome.status) {
        case TreeOpStatus::Committed:
            break;
        case TreeOpStatus::Refused:
            out.verdict = outcome.verdict;
            break;
        case TreeOpStatus::Pending:
            out.pending = true;
            break;
    }
    return out;
}

TreeOpAdmission TreeOpSubmitter::submit_async(TreeOp op) {
    const auto now = now_sec();
    TreeOp sealed = seal(std::move(op), now);
    if (gateway_) return gateway_(std::move(sealed));
    TreeOpAdmission out;
    out.ticket = std::make_shared<TreeOpTicket>(op_id_hex(sealed));
    out.verdict = tree_.submit_local_op(sealed, policy_, now);
    out.ticket->settle(TreeOpOutcome{
        out.verdict.ok() ? TreeOpStatus::Committed : TreeOpStatus::Refused, out.verdict, 0});
    if (!out.verdict.ok()) out.ticket.reset();
    return out;
}

TreeOpVerdict TreeOpSubmitter::dry_run(TreeOp op) const {
    const auto now = now_sec();
    return tree_.validate_local_op(seal(std::move(op), now), policy_, now);
}

}  // namespace nexus::tree
