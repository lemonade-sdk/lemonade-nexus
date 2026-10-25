#pragma once

// Signed release approvals for the release-chain and upgrade tests: a Genesis
// key delegates one release key, and the release key signs format-3
// approvals with a release number and the previous release's hashes. Every
// approval passes the production verifier (the compiled release line).

#include <LemonadeNexus/Security/Attestation/ReleaseApproval.hpp>
#include <LemonadeNexus/Security/Genesis/BootstrapCertificate.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include "support/attestation_fixtures.hpp"
#include "support/release_line.hpp"

#include <gtest/gtest.h>
#include <sodium.h>

#include <string>

namespace nexus_test {

/// The hash a test release N gives every approved path: distinct per release
/// and per path, 64 lowercase hex characters.
inline std::string release_hash(uint64_t release_number, char path_tag) {
    std::string out = std::to_string(release_number);
    out.push_back(path_tag);
    std::string hex;
    static constexpr char kHex[] = "0123456789abcdef";
    for (const char c : out) {
        hex.push_back(kHex[(static_cast<unsigned char>(c) >> 4) & 0xF]);
        hex.push_back(kHex[static_cast<unsigned char>(c) & 0xF]);
    }
    hex.resize(64, '0');
    return hex;
}

struct ReleaseSigner {
    nexus::crypto::Ed25519PublicKey genesis_pk{};
    nexus::crypto::Ed25519PrivateKey genesis_sk{};
    nexus::crypto::Ed25519PublicKey release_pk{};
    nexus::crypto::Ed25519PrivateKey release_sk{};
    nexus::security::NetworkId network{};

    /// A fresh release key under the given Genesis key.
    ReleaseSigner(const nexus::crypto::Ed25519PublicKey& genesis_public,
                  const nexus::crypto::Ed25519PrivateKey& genesis_private)
        : genesis_pk(genesis_public), genesis_sk(genesis_private) {
        EXPECT_GE(sodium_init(), 0);
        EXPECT_EQ(crypto_sign_keypair(release_pk.data(), release_sk.data()), 0);
        network = nexus::security::derive_network_id(
            genesis_pk, nexus::security::constants::kSecurityRulesetVersion,
            nexus::security::constants::kConsensusRulesetVersion);
    }

    /// A fresh Genesis key and release key.
    ReleaseSigner() {
        EXPECT_GE(sodium_init(), 0);
        EXPECT_EQ(crypto_sign_keypair(genesis_pk.data(), genesis_sk.data()), 0);
        EXPECT_EQ(crypto_sign_keypair(release_pk.data(), release_sk.data()), 0);
        network = nexus::security::derive_network_id(
            genesis_pk, nexus::security::constants::kSecurityRulesetVersion,
            nexus::security::constants::kConsensusRulesetVersion);
    }

    /// Release `number` with its own hashes and, when `previous` is non-zero,
    /// the hashes of release `previous` as the overlap. `format` 2 builds an
    /// r21-style approval without a number.
    [[nodiscard]] nexus::security::ReleaseApprovalBundleV1 approval(
        uint64_t number, uint64_t previous = 0,
        uint32_t format = nexus::security::kReleaseApprovalFormatVersion) const {
        using namespace nexus::security;
        ReleaseApprovalBundleV1 bundle;
        const auto network_hex = nexus::crypto::to_hex(network);
        const auto release_b64 = nexus::crypto::to_base64(release_pk);
        bundle.authority.network_id_hex = network_hex;
        bundle.authority.release_signing_pubkey_b64 = release_b64;
        auto a = release_approval_template();
        fill_reference_boot_line(a);
        a.format_version = format;
        a.release_id = "v-test-" + std::to_string(number);
        a.nexus_version = "0.9.7";
        a.final_patched_tree = std::string(40, '1');
        a.network_id_hex = network_hex;
        a.release_number = format >= kReleaseApprovalFormatVersion ? number : 0;
        a.approved_paths = {
            {"/usr/bin/lemonade-nexus", {release_hash(number, 'n')}},
            {"/usr/bin/nexus-attestd", {release_hash(number, 'a')}},
        };
        if (previous != 0 && format >= kReleaseApprovalFormatVersion) {
            a.previous_release_paths = {
                {"/usr/bin/lemonade-nexus", {release_hash(previous, 'n')}},
                {"/usr/bin/nexus-attestd", {release_hash(previous, 'a')}},
            };
        }
        a.qualification_state = "PENDING_LIVE_QUALIFICATION";
        a.signer_pubkey_b64 = release_b64;
        bundle.approval = a;
        sign(bundle);
        return bundle;
    }

    void sign(nexus::security::ReleaseApprovalBundleV1& bundle) const {
        using namespace nexus::security;
        bundle.authority.genesis_signature_b64 =
            ed25519_sign_b64(canonical_release_authority_json(bundle.authority), genesis_sk);
        bundle.approval.signature_b64 =
            ed25519_sign_b64(canonical_release_approval_json(bundle.approval), release_sk);
    }
};

}  // namespace nexus_test
