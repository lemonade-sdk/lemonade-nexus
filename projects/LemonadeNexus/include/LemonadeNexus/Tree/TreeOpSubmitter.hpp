#pragma once

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>
#include <LemonadeNexus/Tree/TreeOps.hpp>

#include <cstdint>
#include <string>

namespace nexus::crypto { class SodiumCryptoService; }

namespace nexus::tree {

class PermissionTreeService;

/// Phase 1 local submission of tree operations (ServerConfig::tree_ops_enabled).
///
/// A request handler builds an unsigned TreeOp; the submitter binds it to this
/// server's network, signs it with this server's key, and passes it to
/// PermissionTreeService::submit_local_op with the local time as the block
/// time. The only trusted submitter is this server's own key: Phase 1 never
/// accepts ops from other servers.
///
/// Not owning: `tree`, `crypto`, and `server_key` must outlive the submitter.
/// `server_key` is referenced, never copied, so the private key stays in one
/// place. Thread-safe to the extent PermissionTreeService is.
class TreeOpSubmitter {
public:
    TreeOpSubmitter(PermissionTreeService& tree, crypto::SodiumCryptoService& crypto,
                    const security::NetworkId& network_id,
                    const crypto::Ed25519Keypair& server_key);

    /// Seal `op` (network id; signed time = now when it is 0; a fresh nonce;
    /// author, op id, signature; submitted_by) and submit it with block time
    /// = now.
    [[nodiscard]] TreeOpVerdict submit(TreeOp op);

    /// Seal `op` as submit does and validate it against the current tree
    /// without applying it.
    [[nodiscard]] TreeOpVerdict dry_run(TreeOp op) const;

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
};

}  // namespace nexus::tree
