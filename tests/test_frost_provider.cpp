#include <LemonadeNexus/Crypto/FrostProvider.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <cstdint>
#include <string>
#include <vector>

using nexus::crypto::Ed25519Signature;
using nexus::crypto::FrostBytes;
using nexus::crypto::FrostCommitment;
using nexus::crypto::FrostDkgOutcome;
using nexus::crypto::FrostDkgRound1;
using nexus::crypto::FrostDkgRound2;
using nexus::crypto::FrostNonces;
using nexus::crypto::FrostPeerBytesMap;
using nexus::crypto::FrostProvider;
using nexus::crypto::FrostStatus;
using nexus::crypto::ParticipantIndex;

namespace {

// Runs a full dealerless DKG for n participants with threshold t and returns
// one outcome per participant, indexed by identifier - 1.
std::vector<FrostDkgOutcome> run_dkg(uint16_t n, uint16_t t) {
    std::vector<FrostDkgRound1> round1;
    FrostPeerBytesMap round1_packages;
    for (ParticipantIndex id = 1; id <= n; ++id) {
        auto result = FrostProvider::dkg_part1(id, n, t);
        EXPECT_TRUE(result.ok()) << "part1 for " << id;
        round1_packages[id] = result.value->package();
        round1.push_back(std::move(*result.value));
    }

    std::vector<FrostDkgRound2> round2;
    std::vector<FrostPeerBytesMap> round1_others(n);
    // recipient -> (sender -> package)
    std::vector<FrostPeerBytesMap> round2_for(n + 1);
    for (ParticipantIndex id = 1; id <= n; ++id) {
        FrostPeerBytesMap others = round1_packages;
        others.erase(id);
        round1_others[id - 1] = others;
        auto result = FrostProvider::dkg_part2(std::move(round1[id - 1]), others);
        EXPECT_TRUE(result.ok()) << "part2 for " << id;
        for (const auto& [recipient, package] : result.value->packages_for_recipients()) {
            round2_for[recipient][id] = package;
        }
        round2.push_back(std::move(*result.value));
    }

    std::vector<FrostDkgOutcome> outcomes;
    for (ParticipantIndex id = 1; id <= n; ++id) {
        auto result = FrostProvider::dkg_part3(std::move(round2[id - 1]), round1_others[id - 1],
                                               round2_for[id]);
        EXPECT_TRUE(result.ok()) << "part3 for " << id;
        outcomes.push_back(std::move(*result.value));
    }
    return outcomes;
}

struct SigningRun {
    FrostPeerBytesMap commitments;
    FrostPeerBytesMap shares;
};

SigningRun sign_with(std::vector<FrostDkgOutcome>& group, const std::vector<ParticipantIndex>& signers,
                     std::span<const uint8_t> message) {
    SigningRun run;
    std::vector<FrostNonces> nonces(group.size() + 1);
    for (const ParticipantIndex id : signers) {
        auto commit = FrostProvider::signing_commit(group[id - 1].key_share);
        EXPECT_TRUE(commit.ok()) << "commit for " << id;
        run.commitments[id] = commit.value->commitments;
        nonces[id] = std::move(commit.value->nonces);
    }
    for (const ParticipantIndex id : signers) {
        auto share = FrostProvider::sign(group[id - 1].key_share, std::move(nonces[id]), message,
                                         run.commitments);
        EXPECT_TRUE(share.ok()) << "sign for " << id;
        if (share.ok()) {
            run.shares[id] = *share.value;
        }
    }
    return run;
}

std::vector<uint8_t> message_bytes(const std::string& text) {
    return {text.begin(), text.end()};
}

TEST(FrostProvider, FiveOfFiveDkgProducesOneGroupKey) {
    auto group = run_dkg(5, 5);
    ASSERT_EQ(group.size(), 5u);
    for (std::size_t i = 0; i < group.size(); ++i) {
        EXPECT_TRUE(group[i].key_share.valid());
        EXPECT_EQ(group[i].key_share.identifier(), static_cast<ParticipantIndex>(i + 1));
        EXPECT_EQ(group[i].group_public_key, group[0].group_public_key);
        EXPECT_FALSE(group[i].public_key_package.empty());
    }
    constexpr nexus::crypto::Ed25519PublicKey kZero{};
    EXPECT_NE(group[0].group_public_key, kZero);
}

TEST(FrostProvider, ThresholdSignatureVerifiesAsPlainEd25519) {
    ASSERT_GE(sodium_init(), 0);
    auto group = run_dkg(7, 5);
    const auto message = message_bytes("lemonade-nexus authority object digest");

    const auto run = sign_with(group, {1, 3, 4, 6, 7}, message);
    ASSERT_EQ(run.shares.size(), 5u);

    auto aggregate = FrostProvider::aggregate(message, run.commitments, run.shares,
                                              group[0].public_key_package);
    ASSERT_TRUE(aggregate.ok());

    EXPECT_TRUE(FrostProvider::verify(group[0].group_public_key, message, *aggregate.value));
    EXPECT_EQ(crypto_sign_verify_detached(aggregate.value->data(), message.data(), message.size(),
                                          group[0].group_public_key.data()),
              0);

    // The wrong message must not verify.
    const auto other = message_bytes("another object");
    EXPECT_FALSE(FrostProvider::verify(group[0].group_public_key, other, *aggregate.value));
}

TEST(FrostProvider, BelowThresholdCannotProduceShares) {
    auto group = run_dkg(5, 5);
    const auto message = message_bytes("m");

    FrostPeerBytesMap commitments;
    std::vector<FrostNonces> nonces(6);
    for (ParticipantIndex id = 1; id <= 4; ++id) {
        auto commit = FrostProvider::signing_commit(group[id - 1].key_share);
        ASSERT_TRUE(commit.ok());
        commitments[id] = commit.value->commitments;
        nonces[id] = std::move(commit.value->nonces);
    }
    auto share = FrostProvider::sign(group[0].key_share, std::move(nonces[1]), message, commitments);
    EXPECT_FALSE(share.ok());
    EXPECT_EQ(share.status, FrostStatus::CryptoFailure);
}

TEST(FrostProvider, TamperedShareRejectedAtAggregation) {
    auto group = run_dkg(5, 5);
    const auto message = message_bytes("m");
    auto run = sign_with(group, {1, 2, 3, 4, 5}, message);
    ASSERT_EQ(run.shares.size(), 5u);

    run.shares[3][0] ^= 0x01;
    auto aggregate = FrostProvider::aggregate(message, run.commitments, run.shares,
                                              group[0].public_key_package);
    EXPECT_FALSE(aggregate.ok());
    EXPECT_EQ(aggregate.status, FrostStatus::CryptoFailure);
}

TEST(FrostProvider, NoncesAreConsumedBySigning) {
    auto group = run_dkg(5, 5);
    const auto message = message_bytes("m");

    FrostPeerBytesMap commitments;
    std::vector<FrostNonces> nonces(6);
    for (ParticipantIndex id = 1; id <= 5; ++id) {
        auto commit = FrostProvider::signing_commit(group[id - 1].key_share);
        ASSERT_TRUE(commit.ok());
        commitments[id] = commit.value->commitments;
        nonces[id] = std::move(commit.value->nonces);
    }

    ASSERT_TRUE(nonces[1].valid());
    auto first = FrostProvider::sign(group[0].key_share, std::move(nonces[1]), message, commitments);
    ASSERT_TRUE(first.ok());
    EXPECT_FALSE(nonces[1].valid());

    // The same nonce object cannot sign again, even for the same message.
    auto second = FrostProvider::sign(group[0].key_share, std::move(nonces[1]), message, commitments);
    EXPECT_FALSE(second.ok());
    EXPECT_EQ(second.status, FrostStatus::InvalidArgument);
}

TEST(FrostProvider, EveryCommitmentIsFresh) {
    auto group = run_dkg(5, 5);
    auto first = FrostProvider::signing_commit(group[0].key_share);
    auto second = FrostProvider::signing_commit(group[0].key_share);
    ASSERT_TRUE(first.ok());
    ASSERT_TRUE(second.ok());
    EXPECT_NE(first.value->commitments, second.value->commitments);
}

TEST(FrostProvider, FreshDkgGivesFreshGroupKey) {
    auto epoch_a = run_dkg(5, 5);
    auto epoch_b = run_dkg(5, 5);
    EXPECT_NE(epoch_a[0].group_public_key, epoch_b[0].group_public_key);
}

TEST(FrostProvider, OldEpochSharesCannotSignForNewKey) {
    auto epoch_a = run_dkg(5, 5);
    auto epoch_b = run_dkg(5, 5);
    const auto message = message_bytes("epoch b operation");

    const auto run = sign_with(epoch_a, {1, 2, 3, 4, 5}, message);
    auto aggregate = FrostProvider::aggregate(message, run.commitments, run.shares,
                                              epoch_a[0].public_key_package);
    ASSERT_TRUE(aggregate.ok());
    EXPECT_FALSE(FrostProvider::verify(epoch_b[0].group_public_key, message, *aggregate.value));
}

TEST(FrostProvider, InvalidInputsAreRefused) {
    EXPECT_EQ(FrostProvider::dkg_part1(0, 5, 5).status, FrostStatus::InvalidArgument);

    FrostDkgRound1 moved_from;
    EXPECT_EQ(FrostProvider::dkg_part2(std::move(moved_from), {}).status,
              FrostStatus::InvalidArgument);

    nexus::crypto::FrostKeyShare no_share;
    EXPECT_EQ(FrostProvider::signing_commit(no_share).status, FrostStatus::InvalidArgument);
}

}  // namespace
