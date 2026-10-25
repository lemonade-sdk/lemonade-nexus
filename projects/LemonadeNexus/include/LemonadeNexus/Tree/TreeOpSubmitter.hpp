#pragma once

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>
#include <LemonadeNexus/Tree/TreeOpPool.hpp>
#include <LemonadeNexus/Tree/TreeOps.hpp>

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>

namespace nexus::crypto { class SodiumCryptoService; }

namespace nexus::tree {

class PermissionTreeService;

/// Result of one submission.
struct TreeOpSubmission {
    /// ok when the op committed (consensus) or applied (local). A refusal
    /// says why nothing changed.
    TreeOpVerdict verdict;
    /// The op is queued for consensus but did not commit within the wait; the
    /// caller answers "pending" with `op_id` (design A2). `verdict` is ok.
    bool pending = false;
    /// Lowercase hex op id of the sealed op.
    std::string op_id;
    /// The queued op's ticket (consensus only), for work that must follow the
    /// commit even after the request has answered.
    std::shared_ptr<TreeOpTicket> ticket;
};

/// Turns a request handler's unsigned TreeOp into a signed one and submits it.
///
/// seal() binds the op to this server's network, sets the signed time, draws a
/// fresh nonce, and signs with this server's key. The submission then goes one
/// of two ways, fixed at construction:
///   - Consensus (the server): a TreeOpGateway (TreeConsensus::submit) queues
///     the op for Tier 1 ordering, and submit() waits up to the commit wait
///     for the commit. Nothing is applied before the commit.
///   - Local (single-process tests and tools only): the op is validated and
///     applied at once through PermissionTreeService::submit_local_op, with
///     this server's key as the only trusted submitter and the local time as
///     the block time.
///
/// Not owning: `tree`, `crypto`, and `server_key` must outlive the submitter.
/// `server_key` is referenced, never copied, so the private key stays in one
/// place. Thread-safe to the extent PermissionTreeService and the gateway are.
class TreeOpSubmitter {
public:
    /// Local application.
    TreeOpSubmitter(PermissionTreeService& tree, crypto::SodiumCryptoService& crypto,
                    const security::NetworkId& network_id,
                    const crypto::Ed25519Keypair& server_key);

    /// Consensus ordering through `gateway`; submit() waits up to
    /// `commit_wait` for the commit.
    TreeOpSubmitter(PermissionTreeService& tree, crypto::SodiumCryptoService& crypto,
                    const security::NetworkId& network_id,
                    const crypto::Ed25519Keypair& server_key, TreeOpGateway gateway,
                    std::chrono::milliseconds commit_wait);

    /// Seal and submit `op`. Consensus: queue it and wait for the commit;
    /// pending when the wait ends first. Local: validate and apply now.
    [[nodiscard]] TreeOpSubmission submit(TreeOp op);

    /// Seal and queue `op` without waiting (consensus), or apply it now
    /// (local, which returns an already settled ticket).
    [[nodiscard]] TreeOpAdmission submit_async(TreeOp op);

    /// Seal `op` as submit does and validate it against the current tree
    /// without submitting it. Only this server's key is trusted here, so a
    /// refusal is final but acceptance is not a promise of commit.
    [[nodiscard]] TreeOpVerdict dry_run(TreeOp op) const;

    /// The configured root management key ("ed25519:<base64>") that an
    /// EstablishRoot op may name in local application and dry runs.
    void set_root_key(std::string root_key) { policy_.root_key = std::move(root_key); }

    /// True when ops go through consensus.
    [[nodiscard]] bool ordered() const { return static_cast<bool>(gateway_); }

    /// This server's submitter key, "ed25519:<base64>".
    [[nodiscard]] const std::string& author() const {
        return policy_.trusted_submitters.front();
    }

    /// The network ops are bound to.
    [[nodiscard]] const security::NetworkId& network_id() const { return policy_.network_id; }

private:
    [[nodiscard]] TreeOp seal(TreeOp op, uint64_t now) const;
    [[nodiscard]] static uint64_t now_sec();

    PermissionTreeService&        tree_;
    crypto::SodiumCryptoService&  crypto_;
    const crypto::Ed25519Keypair& server_key_;
    TreeOpPolicy                  policy_;
    TreeOpGateway                 gateway_;
    std::chrono::milliseconds     commit_wait_{0};
};

}  // namespace nexus::tree
