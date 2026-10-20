#include <LemonadeNexus/Security/Attestation/ReleaseApproval.hpp>

#include <LemonadeNexus/Security/Attestation/AttestationProfileId.hpp>
#include <LemonadeNexus/Security/Attestation/Providers/SnpSvsmVtpmProvider.hpp>
#include <LemonadeNexus/Security/Genesis/BootstrapCertificate.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include "support/attestation_fixtures.hpp"

#include <gtest/gtest.h>
#include <sodium.h>

#include <array>
#include <optional>
#include <string>

namespace {

using namespace nexus;
using namespace nexus::security;

struct SignedFixture {
    crypto::Ed25519PublicKey genesis_pk{};
    crypto::Ed25519PrivateKey genesis_sk{};
    crypto::Ed25519PublicKey authority_pk{};
    crypto::Ed25519PrivateKey authority_sk{};
    NetworkId network{};
    ReleaseApprovalBundleV1 bundle;

    SignedFixture() {
        EXPECT_GE(sodium_init(), 0);
        EXPECT_EQ(crypto_sign_keypair(genesis_pk.data(), genesis_sk.data()), 0);
        EXPECT_EQ(crypto_sign_keypair(authority_pk.data(), authority_sk.data()), 0);
        network = derive_network_id(genesis_pk, constants::kSecurityRulesetVersion,
                                    constants::kConsensusRulesetVersion);
        const auto network_hex = crypto::to_hex(network);
        const auto authority_b64 = crypto::to_base64(authority_pk);

        bundle.authority.network_id_hex = network_hex;
        bundle.authority.release_signing_pubkey_b64 = authority_b64;

        auto& a = bundle.approval;
        a.release_id = "release-test";
        a.nexus_version = "0.9.7";
        a.source_commit = "dd80e7f99d104e6be71ee9c30e32d39ea911bec8";
        a.starting_patched_tree = "148bcf279cd18a7c46295fcd76db022ed5451422";
        a.final_patched_tree = "1111111111111111111111111111111111111111";
        a.network_id_hex = network_hex;
        a.security_wire_version = constants::kSecurityWireVersion;
        a.security_ruleset = constants::kSecurityRulesetVersion;
        a.consensus_ruleset = constants::kConsensusRulesetVersion;
        a.attestation_profile = "SnpSvsmVtpm";
        a.attestation_profile_ruleset = kAttestationProfileRulesetVersion;
        a.attestd_wire_version = constants::kAttestdWireVersion;
        a.ima_policy_id = "nexus-tier1-ima-v1";
        a.ima_policy_sha256 =
            "b3cabc30317af8b7127a175d7b4f906a40203e7ebe28122d82a713e03dad4092";
        a.kernel = {
            "7.1.0-coconut-svsm-tier1+",
            "d9854417fea45a490b632b0e7860827b34443f94da0877e34a0633bbb5078584",
            "dfb88d060ef4fca3b51ce87b95803ad6b64addaad840d4aecb63bc85e9bcd552",
            "8735b602a2e2b86dcc5bd06426e345a09f9c279ceaeb989acd6db0b11279a2be",
            "a43447d3a1658efc13eb1349f1d14e9727630280e5449c5c5459885f9eb88de5",
        };
        a.svsm_launch_measurement_hex =
            "2f073e15d2501910b6208ca52a349d16247d443f326cee2b46292d608821"
            "c6e84c2490814e22a2b5ba860a37208d1d9a";
        a.min_tcb = {0x0c, 0, 0x1c, 0};
        a.approved_paths = {
            {"/usr/bin/lemonade-nexus", {std::string(64, '1')}},
            {"/usr/bin/nexus-attestd", {std::string(64, '2')}},
            {"/usr/lib/x86_64-linux-gnu/libc.so.6", {std::string(64, '3')}},
        };
        a.evidence_collector_path = "/usr/bin/nexus-attestd";
        a.qualification_state = "PENDING_LIVE_QUALIFICATION";
        a.signer_pubkey_b64 = authority_b64;
        resign();
    }

    void resign() {
        bundle.authority.genesis_signature_b64 = nexus_test::ed25519_sign_b64(
            canonical_release_authority_json(bundle.authority), genesis_sk);
        bundle.approval.signature_b64 = nexus_test::ed25519_sign_b64(
            canonical_release_approval_json(bundle.approval), authority_sk);
    }
};

TEST(ReleaseApproval, GenesisDelegationAndReleaseSignatureAreBothRequired) {
    SignedFixture fixture;
    std::string error;
    EXPECT_TRUE(verify_release_approval_bundle(
        fixture.bundle, fixture.genesis_pk, fixture.network, error)) << error;

    fixture.bundle.approval.signature_b64[0] ^= 1;
    EXPECT_FALSE(verify_release_approval_bundle(
        fixture.bundle, fixture.genesis_pk, fixture.network, error));
    EXPECT_EQ(error, "release approval signature is invalid");
}

TEST(ReleaseApproval, WrongReleaseAuthorityAndWrongGenesisFailClosed) {
    SignedFixture fixture;
    SignedFixture rogue;
    std::string error;
    EXPECT_FALSE(verify_release_approval_bundle(
        fixture.bundle, rogue.genesis_pk, fixture.network, error));
    EXPECT_EQ(error, "release authority delegation has no valid Genesis signature");

    fixture.bundle.approval.signer_pubkey_b64 = crypto::to_base64(rogue.authority_pk);
    fixture.bundle.approval.signature_b64 = nexus_test::ed25519_sign_b64(
        canonical_release_approval_json(fixture.bundle.approval), rogue.authority_sk);
    EXPECT_FALSE(verify_release_approval_bundle(
        fixture.bundle, fixture.genesis_pk, fixture.network, error));
    EXPECT_EQ(error, "release approval network or signer does not match the Genesis delegation");
}

TEST(ReleaseApproval, UnsignedDelegationAndUnsignedApprovalFailClosed) {
    SignedFixture fixture;
    std::string error;
    fixture.bundle.authority.genesis_signature_b64.clear();
    EXPECT_FALSE(verify_release_approval_bundle(
        fixture.bundle, fixture.genesis_pk, fixture.network, error));
    EXPECT_EQ(error, "release authority delegation has no valid Genesis signature");

    fixture.resign();
    fixture.bundle.approval.signature_b64.clear();
    EXPECT_FALSE(verify_release_approval_bundle(
        fixture.bundle, fixture.genesis_pk, fixture.network, error));
    EXPECT_EQ(error, "release approval signature is invalid");
}

TEST(ReleaseApproval, CandidateMutationAndPathTransplantAreNotAccepted) {
    SignedFixture fixture;
    std::string error;
    fixture.bundle.approval.approved_paths[2].path = "/tmp/libc.so.6";
    EXPECT_FALSE(verify_release_approval_bundle(
        fixture.bundle, fixture.genesis_pk, fixture.network, error));
    EXPECT_EQ(error, "release approval signature is invalid");
}

TEST(ReleaseApproval, PendingPcrsKeepSvsmAdmissionClosed) {
    SignedFixture fixture;
    std::string error;
    ASSERT_TRUE(verify_release_approval_bundle(
        fixture.bundle, fixture.genesis_pk, fixture.network, error)) << error;
    const auto profile = profile_from_release_approval(fixture.bundle.approval);
    EXPECT_EQ(profile.snp.min_tcb.bootloader, 0x0c);
    EXPECT_EQ(profile.snp.min_tcb.snp, 0x1c);
    EXPECT_TRUE(profile.expected_pcrs.empty());
    EXPECT_EQ(SnpSvsmVtpmProvider(profile).readiness(),
              AttestationFailure::ProfileIncomplete);
}

TEST(ReleaseApproval, RequiredExecutablesAndDependenciesAreConjunctive) {
    SignedFixture fixture;
    std::string error;

    fixture.bundle.approval.approved_paths.erase(
        fixture.bundle.approval.approved_paths.begin());
    fixture.resign();
    EXPECT_FALSE(verify_release_approval_bundle(
        fixture.bundle, fixture.genesis_pk, fixture.network, error));
    EXPECT_EQ(error, "release approval omits a required executable or collector binding");

    SignedFixture complete;
    const auto profile = profile_from_release_approval(complete.bundle.approval);
    EXPECT_EQ(profile.approved_paths.size(), 3u);
    EXPECT_EQ(profile.approved_paths[0].path, "/usr/bin/lemonade-nexus");
    EXPECT_EQ(profile.approved_paths[1].path, "/usr/bin/nexus-attestd");
    EXPECT_EQ(profile.approved_paths[2].path,
              "/usr/lib/x86_64-linux-gnu/libc.so.6");
}

TEST(ReleaseApproval, AQualifiedApprovalMakesTheSvsmProviderReady) {
    // The pins a qualified approval carries and the pins readiness demands
    // must be the same set, or no valid approval can ever arm the verifier.
    SignedFixture fixture;
    fixture.bundle.approval.qualification_state = "LIVE_BOOT_APPROVED";
    fixture.bundle.approval.expected_pcrs = {
        {8, std::string(64, '8')}, {9, std::string(64, '9')}};
    fixture.resign();
    std::string error;
    ASSERT_TRUE(verify_release_approval_bundle(
        fixture.bundle, fixture.genesis_pk, fixture.network, error)) << error;
    const auto profile = profile_from_release_approval(fixture.bundle.approval);
    EXPECT_EQ(SnpSvsmVtpmProvider(profile).readiness(), std::nullopt);
}

TEST(ReleaseApproval, QualifiedPcrsAreExternalAndDoNotChangeExecutablePolicy) {
    SignedFixture fixture;
    const auto before = canonical_release_approval_json(fixture.bundle.approval);
    fixture.bundle.approval.qualification_state = "LIVE_BOOT_APPROVED";
    fixture.bundle.approval.expected_pcrs = {
        {8, std::string(64, '8')}, {9, std::string(64, '9')}};
    fixture.resign();
    std::string error;
    EXPECT_TRUE(verify_release_approval_bundle(
        fixture.bundle, fixture.genesis_pk, fixture.network, error)) << error;
    EXPECT_NE(before, canonical_release_approval_json(fixture.bundle.approval));
    const auto profile = profile_from_release_approval(fixture.bundle.approval);
    ASSERT_EQ(profile.expected_pcrs.size(), 2u);
}

TEST(ReleaseApproval, AnOlderCollectorWireVersionIsRejectedEvenResigned) {
    SignedFixture fixture;
    fixture.bundle.approval.attestd_wire_version = 3;
    fixture.resign();
    std::string error;
    EXPECT_FALSE(verify_release_approval_bundle(
        fixture.bundle, fixture.genesis_pk, fixture.network, error));
    EXPECT_EQ(error, "release protocol identity does not match the compiled protocol");
}

TEST(ReleaseApproval, ThePreviousReleaseLineIdentityIsRejectedEvenResigned) {
    SignedFixture fixture;
    fixture.bundle.approval.source_commit =
        "c2ea54553a2d4532aa37269b3586f7f7d0540a4d";
    fixture.bundle.approval.starting_patched_tree =
        "4957f06d7f02de4b4e143004e4cc369c79a791c5";
    fixture.resign();
    std::string error;
    EXPECT_FALSE(verify_release_approval_bundle(
        fixture.bundle, fixture.genesis_pk, fixture.network, error));
    EXPECT_EQ(error, "release source identity does not match this current-head line");
}

TEST(ReleaseApproval, TemplatePinsTheCurrentReleaseLine) {
    // Pins are re-issued at each release cut; this names the line in force.
    const auto t = release_approval_template();
    EXPECT_EQ(t.source_commit, "dd80e7f99d104e6be71ee9c30e32d39ea911bec8");
    EXPECT_EQ(t.starting_patched_tree,
              "148bcf279cd18a7c46295fcd76db022ed5451422");
}

TEST(ReleaseApproval, GenoaFloorBoundariesRejectObservedHost) {
    const TcbVersion floor{0x0c, 0, 0x1c, 0};
    EXPECT_FALSE((TcbVersion{0x0b, 0, 0x1c, 0}.at_least(floor)));
    EXPECT_TRUE((TcbVersion{0x0c, 0, 0x1c, 0}.at_least(floor)));
    EXPECT_FALSE((TcbVersion{0x0c, 0, 0x1b, 0}.at_least(floor)));
    EXPECT_TRUE((TcbVersion{0x0c, 0, 0x1d, 0}.at_least(floor)));
    EXPECT_FALSE((TcbVersion{0x09, 0, 0x17, 0}.at_least(floor)));
}

}  // namespace
