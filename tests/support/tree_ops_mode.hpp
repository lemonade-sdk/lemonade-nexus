#pragma once

// Gives an HTTP test fixture the tree-operation submitter that the request
// handlers write through. Tree operations are the only tree write path, so
// every fixture that serves tree routes needs one. Without a consensus
// gateway the submitter applies each op locally (submit_local_op).

#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeOpSubmitter.hpp>

#include <memory>

namespace test_support {

/// Owns the submitter key and submitter for one fixture.
struct TreeOpsMode {
    nexus::crypto::Ed25519Keypair                key{};
    std::unique_ptr<nexus::tree::TreeOpSubmitter> submitter;

    /// A submitter for `tree` (all-zero test network id).
    nexus::tree::TreeOpSubmitter* enable(nexus::tree::PermissionTreeService& tree,
                                         nexus::crypto::SodiumCryptoService& crypto) {
        key = crypto.ed25519_keygen();
        submitter = std::make_unique<nexus::tree::TreeOpSubmitter>(
            tree, crypto, nexus::security::NetworkId{}, key);
        return submitter.get();
    }
};

}  // namespace test_support
