// Boot-chain staging for an accepted release approval, against the
// FakeSealer test double (no TPM). The control handler that accepts only the
// release chain's current approval is tested in
// tests/security/upgrade/upgrade_control.cpp.

#include "support/fake_sealer.hpp"
#include "support/release_line.hpp"

#include <LemonadeNexus/Core/BootChainStaging.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Attestation/ReleaseApproval.hpp>
#include <LemonadeNexus/Security/Attestation/ReleaseBundleGenerator.hpp>
#include <LemonadeNexus/Security/Genesis/BootstrapCertificate.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Sealing/SealedBlobStore.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <random>

namespace {

namespace fs = std::filesystem;
using namespace nexus;
using json = nlohmann::json;
using seal_test::FakeSealer;
using seal_test::pcrs_of;

struct TempDir {
    fs::path path;
    TempDir() {
        std::random_device rd;
        path = fs::path("/tmp") / ("nuc-" + std::to_string(rd() % 1000000));
        fs::create_directories(path);
    }
    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

// ---------------------------------------------------------------------------
// Boot-chain staging
// ---------------------------------------------------------------------------

struct StagingFixture : ::testing::Test {
    TempDir dir;
    FakeSealer sealer;
    crypto::Ed25519PublicKey genesis_pk{};
    crypto::Ed25519PrivateKey genesis_sk{};
    crypto::Ed25519PublicKey release_pk{};
    crypto::Ed25519PrivateKey release_sk{};
    security::NetworkId network{};

    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        crypto_sign_keypair(genesis_pk.data(), genesis_sk.data());
        crypto_sign_keypair(release_pk.data(), release_sk.data());
        network = security::derive_network_id(genesis_pk,
                                              security::constants::kSecurityRulesetVersion,
                                              security::constants::kConsensusRulesetVersion);
        // A current blob sealed to the running PCRs (0x11, 0x22).
        security::SealedBlobStore store{dir.path / "sealed", sealer.backend()};
        const std::string secret = "gossip-identity-secret";
        ASSERT_EQ(store.seal("gossip-identity",
                             std::span<const uint8_t>(
                                 reinterpret_cast<const uint8_t*>(secret.data()), secret.size()))
                      .status,
                  security::SealStatus::Ok);
    }

    std::string sign(const crypto::Ed25519PrivateKey& sk, std::string_view m) {
        std::array<unsigned char, crypto_sign_BYTES> sig{};
        crypto_sign_detached(sig.data(), nullptr, reinterpret_cast<const unsigned char*>(m.data()),
                             m.size(), sk.data());
        return crypto::to_base64(sig);
    }

    security::ReleaseApprovalBundleV1 approval(char pcr8, char pcr9) {
        auto a = security::release_approval_template();
        nexus_test::fill_reference_boot_line(a);
        a.release_number = 2026102401;
        a.release_id = "v2026.10.24";
        a.nexus_version = "2026.10.24";
        a.final_patched_tree = std::string(40, 'a');
        a.network_id_hex = crypto::to_hex(network);
        a.signer_pubkey_b64 = crypto::to_base64(release_pk);
        a.qualification_state = "LIVE_BOOT_APPROVED";
        a.expected_pcrs = {{8, std::string(64, pcr8)}, {9, std::string(64, pcr9)}};
        a.approved_paths = {{"/usr/bin/lemonade-nexus", {std::string(64, '1')}},
                            {"/usr/bin/nexus-attestd", {std::string(64, '2')}}};
        security::ReleaseAuthorityV1 authority;
        authority.network_id_hex = a.network_id_hex;
        authority.release_signing_pubkey_b64 = a.signer_pubkey_b64;
        auto root = json::parse(security::unsigned_release_bundle_json(a));
        root["authority"]["genesis_signature"] =
            sign(genesis_sk, security::canonical_release_authority_json(authority));
        root["approval"]["signature"] =
            sign(release_sk, security::canonical_release_approval_json(a));
        std::string error;
        auto bundle = security::parse_release_approval_bundle(root.dump(), error);
        EXPECT_TRUE(bundle) << error;
        EXPECT_TRUE(security::verify_release_approval_bundle(*bundle, genesis_pk, network, error))
            << error;
        return *bundle;
    }

    core::BootChainStagingInputs inputs() { return {dir.path / "sealed", sealer.backend()}; }
};

TEST_F(StagingFixture, StagesTheBootSetForTheApprovedPcrs) {
    const auto r = core::stage_boot_chain_for_approval(inputs(), approval('b', 'c'));
    ASSERT_TRUE(r.ok) << r.detail;
    ASSERT_EQ(r.staged, std::vector<std::string>{"gossip-identity"});
    std::ifstream in(dir.path / "sealed" / "gossip-identity.next.sealed");
    const std::string text{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    const auto blob = security::decode_sealed_blob(text);
    ASSERT_TRUE(blob);
    EXPECT_EQ(blob->pcr_digest, security::boot_pcr_digest(pcrs_of(0xbb, 0xcc)));
    // The current blob is untouched: the old chain still unseals.
    security::SealedBlobStore store{dir.path / "sealed", sealer.backend()};
    EXPECT_EQ(store.unseal("gossip-identity").status, security::SealStatus::Ok);

    // After a reboot into the new chain, the staged blob unseals.
    sealer.pcrs = pcrs_of(0xbb, 0xcc);
    EXPECT_EQ(store.unseal("gossip-identity").status, security::SealStatus::Ok);
}

TEST_F(StagingFixture, RefusesAnApprovalWithoutQualifiedPcrs) {
    auto pending = approval('b', 'c');
    pending.approval.qualification_state = "PENDING_LIVE_QUALIFICATION";
    pending.approval.expected_pcrs.clear();
    const auto r = core::stage_boot_chain_for_approval(inputs(), pending);
    EXPECT_FALSE(r.ok);
    EXPECT_FALSE(fs::exists(dir.path / "sealed" / "gossip-identity.next.sealed"));
}

TEST_F(StagingFixture, RefusesWhenTheCurrentBlobDoesNotUnseal) {
    sealer.reachable = false;
    const auto r = core::stage_boot_chain_for_approval(inputs(), approval('b', 'c'));
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.detail.find("cannot unseal"), std::string::npos) << r.detail;
}

TEST_F(StagingFixture, NothingToStageWhenThePcrsAreTheRunningChain) {
    // "1"*64 and "2"*64 are the running PCRs (0x11..., 0x22...).
    const auto same = core::stage_boot_chain_for_approval(inputs(), approval('1', '2'));
    ASSERT_TRUE(same.ok) << same.detail;
    EXPECT_TRUE(same.staged.empty());
    EXPECT_FALSE(fs::exists(dir.path / "sealed" / "gossip-identity.next.sealed"));
}

}  // namespace
