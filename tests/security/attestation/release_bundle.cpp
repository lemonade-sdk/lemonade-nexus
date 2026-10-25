// The release-bundle generator feeds the signing ceremony: digests must come
// from the real bytes, the compiled template must match the verifier, and the
// generated bundle (once test-signed) must pass the production verifier.

#include <LemonadeNexus/Security/Attestation/ReleaseBundleGenerator.hpp>

#include <LemonadeNexus/Security/Genesis/BootstrapCertificate.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include "support/attestation_fixtures.hpp"
#include "support/release_line.hpp"

#include <gtest/gtest.h>
#include <sodium.h>

#include <filesystem>
#include <fstream>
#include <string>

namespace {

using namespace nexus;
using namespace nexus::security;
namespace fs = std::filesystem;

fs::path write_artifact(const std::string& name, const std::string& content) {
    const fs::path path = fs::temp_directory_path() / ("nexus_release_bundle_" + name);
    std::ofstream(path, std::ios::binary | std::ios::trunc) << content;
    return path;
}

std::string hex_sha256(const std::string& content) {
    std::array<unsigned char, crypto_hash_sha256_BYTES> digest{};
    crypto_hash_sha256(digest.data(),
                       reinterpret_cast<const unsigned char*>(content.data()),
                       content.size());
    return crypto::to_hex(digest);
}

struct GeneratorFixture : ::testing::Test {
    crypto::Ed25519PublicKey genesis_pk{};
    crypto::Ed25519PrivateKey genesis_sk{};
    crypto::Ed25519PublicKey authority_pk{};
    crypto::Ed25519PrivateKey authority_sk{};
    NetworkId network{};
    ReleaseBundleSpec spec;

    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        ASSERT_EQ(crypto_sign_keypair(genesis_pk.data(), genesis_sk.data()), 0);
        ASSERT_EQ(crypto_sign_keypair(authority_pk.data(), authority_sk.data()), 0);
        network = derive_network_id(genesis_pk, constants::kSecurityRulesetVersion,
                                    constants::kConsensusRulesetVersion);
        spec.release_id = "release-bundle-test";
        spec.nexus_version = "0.9.7";
        spec.release_number = 2026102401;
        spec.final_patched_tree = std::string(40, '2');
        spec.network_id_hex = crypto::to_hex(network);
        spec.signer_pubkey_b64 = crypto::to_base64(authority_pk);
        spec.qualification_state = "LIVE_BOOT_APPROVED";
        spec.expected_pcrs = {{8, std::string(64, '8')}, {9, std::string(64, '9')}};
        nexus_test::fill_reference_boot_line(spec);
        spec.artifacts = {
            {"/usr/bin/lemonade-nexus", write_artifact("app", "app bytes")},
            {"/usr/bin/nexus-attestd", write_artifact("attestd", "collector bytes")},
            {"/usr/lib/x86_64-linux-gnu/libc.so.6", write_artifact("libc", "libc bytes")},
        };
    }
};

TEST_F(GeneratorFixture, DigestsComeFromTheActualBytes) {
    std::string error;
    const auto approval = generate_release_approval(spec, error);
    ASSERT_TRUE(approval.has_value()) << error;
    ASSERT_EQ(approval->approved_paths.size(), 3u);
    EXPECT_EQ(approval->approved_paths[0].sha256.front(), hex_sha256("app bytes"));
    EXPECT_EQ(approval->approved_paths[1].sha256.front(), hex_sha256("collector bytes"));
    EXPECT_EQ(approval->approved_paths[2].sha256.front(), hex_sha256("libc bytes"));
    // The template supplied the protocol identity; the spec supplied the boot
    // line (from the fleet profile) and the observations.
    EXPECT_EQ(approval->evidence_collector_path, "/usr/bin/nexus-attestd");
    EXPECT_EQ(approval->svsm_launch_measurements_hex, spec.svsm_launch_measurements);
    EXPECT_EQ(approval->kernel.bzimage_sha256, spec.kernel.bzimage_sha256);
    EXPECT_EQ(approval->ima_policy_sha256, spec.ima_policy_sha256);
    EXPECT_EQ(approval->source_commit, spec.source_commit);
}

TEST_F(GeneratorFixture, SpecMeasurementsAreCanonicalizedAndFailClosed) {
    std::string error;
    {   // Empty is refused: there is no compiled set to fall back on.
        auto s = spec;
        s.svsm_launch_measurements.clear();
        EXPECT_FALSE(generate_release_approval(s, error).has_value());
    }
    {   // One entry per approved shape, sorted into canonical order.
        auto s = spec;
        s.svsm_launch_measurements = {std::string(96, 'b'), std::string(96, 'a')};
        const auto approval = generate_release_approval(s, error);
        ASSERT_TRUE(approval.has_value()) << error;
        const std::vector<std::string> expected{std::string(96, 'a'),
                                                std::string(96, 'b')};
        EXPECT_EQ(approval->svsm_launch_measurements_hex, expected);
    }
    {   // Duplicates are an authoring error, never silently merged.
        auto s = spec;
        s.svsm_launch_measurements = {std::string(96, 'a'), std::string(96, 'a')};
        EXPECT_FALSE(generate_release_approval(s, error).has_value());
    }
    {   // Uppercase and short values are not measurements.
        auto s = spec;
        s.svsm_launch_measurements = {std::string(96, 'A')};
        EXPECT_FALSE(generate_release_approval(s, error).has_value());
        s.svsm_launch_measurements = {std::string(95, 'a')};
        EXPECT_FALSE(generate_release_approval(s, error).has_value());
    }
}

TEST_F(GeneratorFixture, ATestSignedGeneratedBundlePassesTheProductionVerifier) {
    std::string error;
    const auto approval = generate_release_approval(spec, error);
    ASSERT_TRUE(approval.has_value()) << error;

    const auto json_text = unsigned_release_bundle_json(*approval);
    auto bundle = parse_release_approval_bundle(json_text, error);
    ASSERT_TRUE(bundle.has_value()) << error;

    // The ceremony: Genesis delegates the signer, the signer signs the approval.
    bundle->authority.genesis_signature_b64 = nexus_test::ed25519_sign_b64(
        canonical_release_authority_json(bundle->authority), genesis_sk);
    bundle->approval.signature_b64 = nexus_test::ed25519_sign_b64(
        canonical_release_approval_json(bundle->approval), authority_sk);

    EXPECT_TRUE(verify_release_approval_bundle(*bundle, genesis_pk, network, error)) << error;
    // The parsed approval is byte-identical policy: same canonical digest.
    EXPECT_EQ(release_approval_digest_hex(bundle->approval),
              release_approval_digest_hex(*approval));
}

TEST_F(GeneratorFixture, EachInvalidSpecIsRefusedWithAReason) {
    std::string error;
    {   // Missing required executable.
        auto s = spec;
        s.artifacts.erase(s.artifacts.begin());
        EXPECT_FALSE(generate_release_approval(s, error).has_value());
    }
    {   // Unreadable artifact file.
        auto s = spec;
        s.artifacts[0].file = fs::temp_directory_path() / "nexus_release_bundle_absent";
        EXPECT_FALSE(generate_release_approval(s, error).has_value());
    }
    {   // Path-limit overflow is reported, not silently truncated.
        auto s = spec;
        for (std::size_t i = 0; s.artifacts.size() <= constants::kMaxSummarisedPaths; ++i) {
            s.artifacts.push_back({"/usr/lib/extra-" + std::to_string(i),
                                   s.artifacts[0].file});
        }
        EXPECT_FALSE(generate_release_approval(s, error).has_value());
    }
    {   // Pending approvals carry no guessed PCRs.
        auto s = spec;
        s.qualification_state = "PENDING_LIVE_QUALIFICATION";
        EXPECT_FALSE(generate_release_approval(s, error).has_value());
        s.expected_pcrs.clear();
        EXPECT_TRUE(generate_release_approval(s, error).has_value()) << error;
    }
    {   // Qualified approvals carry exactly PCR8 and PCR9.
        auto s = spec;
        s.expected_pcrs = {{7, std::string(64, '7')}, {9, std::string(64, '9')}};
        EXPECT_FALSE(generate_release_approval(s, error).has_value());
    }
    {   // Duplicate installed paths cannot share one release.
        auto s = spec;
        s.artifacts.push_back(s.artifacts[2]);
        EXPECT_FALSE(generate_release_approval(s, error).has_value());
    }
    {   // A hand-typed final tree must at least be a 40-hex tree hash.
        auto s = spec;
        s.final_patched_tree = "not-a-tree";
        EXPECT_FALSE(generate_release_approval(s, error).has_value());
    }
}

TEST_F(GeneratorFixture, ReviewedDigestsStandInForFilesTheBuildDoesNotProduce) {
    spec.artifacts[2] = {"/usr/lib/x86_64-linux-gnu/libc.so.6", {}, {std::string(64, 'c')}};
    std::string error;
    const auto approval = generate_release_approval(spec, error);
    ASSERT_TRUE(approval.has_value()) << error;
    EXPECT_EQ(approval->approved_paths[2].sha256, std::vector<std::string>{std::string(64, 'c')});

    spec.artifacts[2] = {"/usr/lib/x86_64-linux-gnu/libc.so.6", {}, {"NOT-HEX"}};
    EXPECT_FALSE(generate_release_approval(spec, error).has_value());
    spec.artifacts[2] = {"/usr/lib/x86_64-linux-gnu/libc.so.6", {}, {}};
    EXPECT_FALSE(generate_release_approval(spec, error).has_value());
}

TEST_F(GeneratorFixture, ThePreviousApprovalFillsOnlyThePreviousReleasePaths) {
    std::string error;
    auto previous = generate_release_approval(spec, error);
    ASSERT_TRUE(previous.has_value()) << error;
    previous->approved_paths.push_back({"/usr/bin/retired-tool", {std::string(64, 'e')}});
    const auto preimage = canonical_release_approval_json(*previous);
    std::array<unsigned char, crypto_sign_BYTES> sig{};
    crypto_sign_detached(sig.data(), nullptr,
                         reinterpret_cast<const unsigned char*>(preimage.data()), preimage.size(),
                         authority_sk.data());
    previous->signature_b64 = crypto::to_base64(sig);

    spec.release_number = 2026102501;
    spec.artifacts[0] = {"/usr/bin/lemonade-nexus", write_artifact("app2", "app bytes v2")};
    spec.previous = *previous;
    const auto next = generate_release_approval(spec, error);
    ASSERT_TRUE(next.has_value()) << error;
    // approved_paths lists this release only: a witness counts a server as
    // upgraded only when every measured hash is this release's.
    EXPECT_EQ(next->approved_paths[0].sha256,
              std::vector<std::string>{hex_sha256("app bytes v2")});
    ASSERT_EQ(next->previous_release_paths.size(), 3u) << "dropped paths are not carried over";
    EXPECT_EQ(next->previous_release_paths[0].path, "/usr/bin/lemonade-nexus");
    EXPECT_EQ(next->previous_release_paths[0].sha256,
              std::vector<std::string>{hex_sha256("app bytes")});
    // Attestation accepts both releases during the rollout.
    const auto profile = profile_from_release_approval(*next);
    EXPECT_EQ(profile.approved_paths[0].sha256,
              (std::vector<std::string>{hex_sha256("app bytes v2"), hex_sha256("app bytes")}));

    // The previous approval and explicit previous paths do not mix.
    auto both = spec;
    both.previous_release_paths = {{"/usr/bin/lemonade-nexus", {std::string(64, 'f')}}};
    EXPECT_FALSE(generate_release_approval(both, error).has_value());

    // A previous approval the release key did not sign contributes nothing.
    spec.previous->signature_b64 = crypto::to_base64(std::array<unsigned char, 64>{});
    EXPECT_FALSE(generate_release_approval(spec, error).has_value());
}

TEST_F(GeneratorFixture, TheBootLineIsRequiredAndWellFormed) {
    std::string error;
    for (int field = 0; field < 4; ++field) {
        auto s = spec;
        if (field == 0) s.kernel.vmlinux_sha256 = "abc";
        if (field == 1) s.ima_policy_sha256.clear();
        if (field == 2) s.source_commit = "zz";
        if (field == 3) s.kernel.release.clear();
        EXPECT_FALSE(generate_release_approval(s, error).has_value()) << field;
    }
}

}  // namespace
