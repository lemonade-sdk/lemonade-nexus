// The release-bundle generator feeds the signing ceremony: digests must come
// from the real bytes, the compiled template must match the verifier, and the
// generated bundle (once test-signed) must pass the production verifier.

#include <LemonadeNexus/Security/Attestation/ReleaseBundleGenerator.hpp>

#include <LemonadeNexus/Security/Genesis/BootstrapCertificate.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include "support/attestation_fixtures.hpp"

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
        spec.final_patched_tree = std::string(40, '2');
        spec.network_id_hex = crypto::to_hex(network);
        spec.signer_pubkey_b64 = crypto::to_base64(authority_pk);
        spec.qualification_state = "LIVE_BOOT_APPROVED";
        spec.expected_pcrs = {{8, std::string(64, '8')}, {9, std::string(64, '9')}};
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
    // The template supplied the compiled line; the spec supplied observations.
    EXPECT_EQ(approval->evidence_collector_path, "/usr/bin/nexus-attestd");
    EXPECT_FALSE(approval->svsm_launch_measurements_hex.empty());
}

TEST_F(GeneratorFixture, SpecMeasurementsAreCanonicalizedAndFailClosed) {
    std::string error;
    {   // Empty keeps the compiled template set.
        const auto approval = generate_release_approval(spec, error);
        ASSERT_TRUE(approval.has_value()) << error;
        EXPECT_EQ(approval->svsm_launch_measurements_hex,
                  release_approval_template().svsm_launch_measurements_hex);
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

}  // namespace
