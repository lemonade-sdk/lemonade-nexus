#pragma once

// Switches an HTTP test fixture to the tree-operation write paths when the
// suite is built as its flag-on variant (NEXUS_TEST_TREE_OPS, see
// add_nexus_tree_ops_test in tests/CMakeLists.txt). In the normal build it
// changes nothing, so one source file asserts identical HTTP behavior for
// both settings of ServerConfig::tree_ops_enabled.

#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeOpSubmitter.hpp>

#include <memory>

namespace test_support {

#ifdef NEXUS_TEST_TREE_OPS
inline constexpr bool kTreeOpsBuild = true;
#else
inline constexpr bool kTreeOpsBuild = false;
#endif

/// Owns the submitter key and submitter for one fixture.
struct TreeOpsMode {
    nexus::crypto::Ed25519Keypair                key{};
    std::unique_ptr<nexus::tree::TreeOpSubmitter> submitter;

    /// In the flag-on build: set `config.tree_ops_enabled` and return a
    /// submitter for `tree` (all-zero test network id). Otherwise nullptr.
    nexus::tree::TreeOpSubmitter* enable(nexus::core::ServerConfig& config,
                                         nexus::tree::PermissionTreeService& tree,
                                         nexus::crypto::SodiumCryptoService& crypto) {
        if (!kTreeOpsBuild) return nullptr;
        config.tree_ops_enabled = true;
        key = crypto.ed25519_keygen();
        submitter = std::make_unique<nexus::tree::TreeOpSubmitter>(
            tree, crypto, nexus::security::NetworkId{}, key);
        return submitter.get();
    }
};

}  // namespace test_support
