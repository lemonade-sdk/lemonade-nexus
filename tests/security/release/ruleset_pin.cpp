// The ruleset versions feed network_id. An in-place release must keep them,
// or every server's epoch state, storage records, and release approvals
// stop matching its network (Design-Auto-Update Phase 0.1). A ruleset change
// is a separate, consensus-finalized transition with its own migration; it
// is never a side effect of a release.
//
// This test fails when a release changes either version or the network id
// derivation. Update the pinned values only together with that transition.

#include <LemonadeNexus/Security/Attestation/ReleaseApproval.hpp>
#include <LemonadeNexus/Security/Genesis/BootstrapCertificate.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>

namespace {

using namespace nexus;
using namespace nexus::security;

TEST(ReleaseRulesetPin, TheNetworkIdInputsAreUnchangedAcrossReleases) {
    static_assert(constants::kSecurityRulesetVersion == 1,
                  "kSecurityRulesetVersion feeds network_id; a release must not change it");
    static_assert(constants::kConsensusRulesetVersion == 1,
                  "kConsensusRulesetVersion feeds network_id; a release must not change it");
    EXPECT_EQ(constants::kSecurityRulesetVersion, 1);
    EXPECT_EQ(constants::kConsensusRulesetVersion, 1);
}

TEST(ReleaseRulesetPin, TheNetworkIdDerivationIsUnchanged) {
    crypto::Ed25519PublicKey genesis{};
    for (std::size_t i = 0; i < genesis.size(); ++i) genesis[i] = static_cast<uint8_t>(i);
    const auto network = derive_network_id(genesis, constants::kSecurityRulesetVersion,
                                           constants::kConsensusRulesetVersion);
    EXPECT_EQ(crypto::to_hex(network),
              "961621be612598b26a648dd77cbd0bbf950fc22e49ca9249ea8fb80281a89b6b");
}

TEST(ReleaseRulesetPin, TheApprovalTemplateCarriesTheCompiledRulesets) {
    // The verifier refuses an approval whose rulesets differ from the
    // compiled ones, so a release that changed them would also stop
    // accepting the approvals of the previous release.
    const auto approval = release_approval_template();
    EXPECT_EQ(approval.security_ruleset, constants::kSecurityRulesetVersion);
    EXPECT_EQ(approval.consensus_ruleset, constants::kConsensusRulesetVersion);
    EXPECT_EQ(approval.format_version, kReleaseApprovalFormatVersion);
}

}  // namespace
