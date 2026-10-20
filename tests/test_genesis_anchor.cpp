#include <LemonadeNexus/Core/GenesisAnchor.hpp>

#include <LemonadeNexus/Security/Genesis/BootstrapCertificate.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <filesystem>

namespace {

using namespace nexus;

TEST(GenesisAnchor, RejectsMalformedKey) {
    EXPECT_FALSE(core::load_genesis_anchor(""));
    EXPECT_FALSE(core::load_genesis_anchor("not-base64!"));
    // Valid base64, wrong length for an Ed25519 key.
    EXPECT_FALSE(core::load_genesis_anchor("AAAA"));
}

TEST(GenesisAnchor, DerivesNetworkIdAndReportsMissingBundle) {
    ASSERT_GE(sodium_init(), 0);
    crypto::Ed25519PublicKey pk{};
    crypto::Ed25519PrivateKey sk{};
    ASSERT_EQ(crypto_sign_keypair(pk.data(), sk.data()), 0);

    const auto anchor = core::load_genesis_anchor(
        crypto::to_base64(pk),
        std::filesystem::path("/nonexistent/release-approval.json"));
    ASSERT_TRUE(anchor);
    EXPECT_EQ(anchor->genesis_public_key, pk);
    EXPECT_EQ(anchor->network_id,
              security::derive_network_id(
                  pk, security::constants::kSecurityRulesetVersion,
                  security::constants::kConsensusRulesetVersion));
    // A missing bundle is reported, not fatal; callers decide.
    EXPECT_FALSE(anchor->release);
    EXPECT_FALSE(anchor->release_error.empty());
}

}  // namespace
