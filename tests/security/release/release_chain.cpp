// The release chain (Design-Auto-Update Phase 0.1 and Phase 2): a newer
// approval supersedes the held one only under the Genesis-pinned release
// signer, for this network, with a strictly greater release number, and the
// highest number survives restart.

#include <LemonadeNexus/Security/Attestation/AttestationVerifier.hpp>
#include <LemonadeNexus/Security/Attestation/ReleaseChain.hpp>

#include "support/release_fixture.hpp"

#include <gtest/gtest.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>

namespace {

using namespace nexus;
using namespace nexus::security;
using nexus_test::release_hash;
using nexus_test::ReleaseSigner;
namespace fs = std::filesystem;

constexpr uint64_t kN = 2026102401;
constexpr uint64_t kN1 = 2026102501;
constexpr uint64_t kN2 = 2026102601;

class ReleaseChainTest : public ::testing::Test {
protected:
    void SetUp() override {
        dir = fs::temp_directory_path() /
              ("nexus_release_chain_" + std::to_string(::getpid()) + "_" +
               ::testing::UnitTest::GetInstance()->current_test_info()->name());
        fs::remove_all(dir);
    }
    void TearDown() override { fs::remove_all(dir); }

    [[nodiscard]] ReleaseChain chain() const {
        return ReleaseChain(dir, signer.genesis_pk, signer.network);
    }

    ReleaseSigner signer;
    fs::path dir;
};

TEST_F(ReleaseChainTest, TheInstalledApprovalPinsTheSignerOnFirstLoad) {
    auto c = chain();
    ASSERT_TRUE(c.load(signer.approval(kN)));
    EXPECT_TRUE(c.pinned());
    ASSERT_TRUE(c.current().has_value());
    EXPECT_EQ(c.highest_release_number(), kN);
    EXPECT_EQ(c.record()->release_signing_pubkey_b64, crypto::to_base64(signer.release_pk));
}

TEST_F(ReleaseChainTest, ANewerApprovalIsAdoptedAndPersisted) {
    auto c = chain();
    ASSERT_TRUE(c.load(signer.approval(kN)));
    EXPECT_EQ(c.offer(signer.approval(kN1, kN)), ReleaseOfferResult::Adopted);
    EXPECT_EQ(c.highest_release_number(), kN1);
    EXPECT_EQ(c.offer(signer.approval(kN1, kN)), ReleaseOfferResult::Current);

    auto reloaded = chain();
    ASSERT_TRUE(reloaded.load(std::nullopt));
    EXPECT_EQ(reloaded.highest_release_number(), kN1);
    ASSERT_TRUE(reloaded.current().has_value());
    EXPECT_EQ(reloaded.current()->approval.release_number, kN1);
}

TEST_F(ReleaseChainTest, AForgedSignatureIsRefused) {
    auto c = chain();
    ASSERT_TRUE(c.load(signer.approval(kN)));
    auto forged = signer.approval(kN1, kN);
    forged.approval.signature_b64[3] ^= 1;
    EXPECT_EQ(c.offer(forged), ReleaseOfferResult::Invalid);
    // A forged hash under the original signature is the same failure.
    auto edited = signer.approval(kN1, kN);
    edited.approval.approved_paths.front().sha256 = {std::string(64, 'f')};
    EXPECT_EQ(c.offer(edited), ReleaseOfferResult::Invalid);
    EXPECT_EQ(c.highest_release_number(), kN);
}

TEST_F(ReleaseChainTest, AnotherNetworkIsRefused) {
    auto c = chain();
    ASSERT_TRUE(c.load(signer.approval(kN)));
    // Same release key, delegated by another Genesis key: another network.
    ReleaseSigner other;
    other.release_pk = signer.release_pk;
    other.release_sk = signer.release_sk;
    EXPECT_EQ(c.offer(other.approval(kN1, kN)), ReleaseOfferResult::Invalid);
}

TEST_F(ReleaseChainTest, AnotherGenesisDelegatedReleaseKeyIsRefused) {
    auto c = chain();
    ASSERT_TRUE(c.load(signer.approval(kN)));
    // Genesis signed a second delegation: the pin keeps the founding signer,
    // so Genesis cannot install a new release authority after the fact.
    ReleaseSigner second(signer.genesis_pk, signer.genesis_sk);
    EXPECT_EQ(c.offer(second.approval(kN1, kN)), ReleaseOfferResult::WrongSigner);
    EXPECT_EQ(c.highest_release_number(), kN);
}

TEST_F(ReleaseChainTest, AnEqualOrLowerReleaseNumberIsRefused) {
    auto c = chain();
    ASSERT_TRUE(c.load(signer.approval(kN1)));
    // Equal number, different content.
    auto same_number = signer.approval(kN1, kN);
    EXPECT_EQ(c.offer(same_number), ReleaseOfferResult::Stale);
    EXPECT_EQ(c.offer(signer.approval(kN)), ReleaseOfferResult::Stale);
    EXPECT_EQ(c.highest_release_number(), kN1);
}

TEST_F(ReleaseChainTest, AnOldApprovalReplayedAfterRestartIsRefused) {
    {
        auto c = chain();
        ASSERT_TRUE(c.load(signer.approval(kN)));
        ASSERT_EQ(c.offer(signer.approval(kN1, kN)), ReleaseOfferResult::Adopted);
    }
    // The restarted server's package still holds release N (the updater
    // handed N+1 over before the swap). N stays refused and N+1 stays
    // current: no downgrade.
    auto restarted = chain();
    ASSERT_TRUE(restarted.load(signer.approval(kN)));
    EXPECT_EQ(restarted.highest_release_number(), kN1);
    ASSERT_TRUE(restarted.current().has_value());
    EXPECT_EQ(restarted.current()->approval.release_number, kN1);
    EXPECT_EQ(restarted.offer(signer.approval(kN)), ReleaseOfferResult::Stale);
    EXPECT_EQ(restarted.offer_json(release_approval_bundle_json(signer.approval(kN))),
              ReleaseOfferResult::Stale);
}

TEST_F(ReleaseChainTest, AnOversizeOfferIsRefusedBeforeParsing) {
    auto c = chain();
    ASSERT_TRUE(c.load(signer.approval(kN)));
    EXPECT_EQ(c.offer_json(std::string(kMaxReleaseApprovalBytes + 1, '{')),
              ReleaseOfferResult::Oversize);
    EXPECT_EQ(c.offer_json("{not json"), ReleaseOfferResult::Invalid);
}

TEST_F(ReleaseChainTest, NoPinMeansNoAdoption) {
    auto c = chain();
    ASSERT_TRUE(c.load(std::nullopt));
    EXPECT_FALSE(c.pinned());
    EXPECT_EQ(c.offer(signer.approval(kN)), ReleaseOfferResult::Unavailable);
}

TEST_F(ReleaseChainTest, ACorruptRecordFailsClosed) {
    {
        auto c = chain();
        ASSERT_TRUE(c.load(signer.approval(kN)));
    }
    std::ofstream(dir / kReleaseChainFile, std::ios::trunc) << "{\"format_version\":1}";
    auto c = chain();
    EXPECT_FALSE(c.load(signer.approval(kN1, kN)));
    EXPECT_FALSE(c.healthy());
    EXPECT_FALSE(c.current().has_value());
    EXPECT_EQ(c.offer(signer.approval(kN2, kN1)), ReleaseOfferResult::Unavailable);
    EXPECT_FALSE(c.bind_commitment(release_approval_digest(signer.approval(kN).approval)));
}

TEST_F(ReleaseChainTest, TheFoundingCommitmentBindsThroughThePinApproval) {
    const auto founding = signer.approval(kN);
    const Digest committed = release_approval_digest(founding.approval);
    {
        auto c = chain();
        ASSERT_TRUE(c.load(founding));
        // Adopted before the first restart: the pin approval still binds.
        ASSERT_EQ(c.offer(signer.approval(kN1, kN)), ReleaseOfferResult::Adopted);
        EXPECT_TRUE(c.bind_commitment(committed));
    }
    auto c = chain();
    ASSERT_TRUE(c.load(signer.approval(kN2, kN1)));
    EXPECT_EQ(c.highest_release_number(), kN2);
    EXPECT_TRUE(c.bind_commitment(committed));
    // Bound once; another digest never binds after that.
    EXPECT_FALSE(c.bind_commitment(release_approval_digest(signer.approval(kN1).approval)));
}

TEST_F(ReleaseChainTest, AnR21FoundingNeedsTheMigrationFileWithThePinnedSigner) {
    // The network was founded on a format-2 approval; the first auto-update
    // release pins its signer from its own (format-3) approval.
    const auto r21 = signer.approval(1, 0, kReleaseApprovalFormatV2);
    const Digest committed = release_approval_digest(r21.approval);
    auto c = chain();
    ASSERT_TRUE(c.load(signer.approval(kN)));
    EXPECT_FALSE(c.bind_commitment(committed)) << "no founding approval is available";

    // A migration file signed by another (Genesis-delegated) key is refused.
    ReleaseSigner second(signer.genesis_pk, signer.genesis_sk);
    const auto foreign = second.approval(1, 0, kReleaseApprovalFormatV2);
    std::ofstream(dir / kFoundingApprovalFile) << release_approval_bundle_json(foreign);
    EXPECT_FALSE(c.bind_commitment(release_approval_digest(foreign.approval)));

    // A file whose digest is not the commitment is refused.
    std::ofstream(dir / kFoundingApprovalFile, std::ios::trunc)
        << release_approval_bundle_json(signer.approval(2, 0, kReleaseApprovalFormatV2));
    EXPECT_FALSE(c.bind_commitment(committed));

    // The real founding approval, same release signer: bound and persisted.
    std::ofstream(dir / kFoundingApprovalFile, std::ios::trunc)
        << release_approval_bundle_json(r21);
    EXPECT_TRUE(c.bind_commitment(committed));
    fs::remove(dir / kFoundingApprovalFile);
    auto reloaded = chain();
    ASSERT_TRUE(reloaded.load(signer.approval(kN)));
    EXPECT_TRUE(reloaded.bind_commitment(committed));
}

TEST_F(ReleaseChainTest, ReleasesNAndNPlusOneAttestEachOtherButNMinusOneStops) {
    auto c = chain();
    ASSERT_TRUE(c.load(signer.approval(kN, 2026102301)));
    ASSERT_EQ(c.offer(signer.approval(kN1, kN)), ReleaseOfferResult::Adopted);
    const auto profile = profile_from_release_approval(c.current()->approval);
    for (const char tag : {'n', 'a'}) {
        const std::string path = tag == 'n' ? "/usr/bin/lemonade-nexus" : "/usr/bin/nexus-attestd";
        EXPECT_TRUE(path_approved(profile, path, release_hash(kN1, tag))) << path;
        EXPECT_TRUE(path_approved(profile, path, release_hash(kN, tag))) << path;
        EXPECT_FALSE(path_approved(profile, path, release_hash(2026102301, tag))) << path;
    }
}

}  // namespace
