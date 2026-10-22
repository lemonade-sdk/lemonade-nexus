#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Crypto/StorageThreshold.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <cstdint>
#include <map>
#include <optional>
#include <vector>

using nexus::crypto::SecureBuffer;
using nexus::crypto::SodiumCryptoService;
using nexus::crypto::StorageBytes;
using nexus::crypto::StorageHolderId;
using nexus::crypto::StorageKeyShare;
using nexus::crypto::StoragePartial;
using nexus::crypto::StoragePeerBytesMap;
using nexus::crypto::StoragePoint;
using nexus::crypto::StorageResult;
using nexus::crypto::StorageStatus;
using nexus::crypto::StorageThreshold;
using nexus::crypto::StorageUnlockContext;
using nexus::crypto::StorageWrappedDataKey;

namespace {

struct Group {
    std::map<StorageHolderId, StorageKeyShare> shares;
    StorageBytes plan;
    StoragePoint storage_public_key{};
};

std::vector<StorageHolderId> range(StorageHolderId first, StorageHolderId last) {
    std::vector<StorageHolderId> out;
    for (StorageHolderId id = first; id <= last; ++id) {
        out.push_back(id);
    }
    return out;
}

StoragePeerBytesMap without(const StoragePeerBytesMap& map, StorageHolderId skip) {
    StoragePeerBytesMap out = map;
    out.erase(skip);
    return out;
}

/// Key generation among `ids`: the first key, or a rotation when `rotation`
/// is set (a rotation may keep 3 or 4 holders).
Group run_dkg(const std::vector<StorageHolderId>& ids, bool rotation = false) {
    const auto n = static_cast<uint16_t>(ids.size());
    std::map<StorageHolderId, nexus::crypto::StorageDkgRound1> round1;
    StoragePeerBytesMap packages;
    for (const auto id : ids) {
        auto result = rotation ? StorageThreshold::dkg_rotation_part1(id, n)
                               : StorageThreshold::dkg_part1(id, n);
        EXPECT_TRUE(result.ok()) << "part1 for " << id;
        packages[id] = result.value->package();
        round1.emplace(id, std::move(*result.value));
    }
    std::map<StorageHolderId, nexus::crypto::StorageDkgRound2> round2;
    std::map<StorageHolderId, StoragePeerBytesMap> inbox;
    for (auto& [id, state] : round1) {
        auto result = StorageThreshold::dkg_part2(std::move(state), without(packages, id));
        EXPECT_TRUE(result.ok()) << "part2 for " << id;
        for (const auto& [recipient, bytes] : result.value->packages_for_recipients()) {
            inbox[recipient][id] = bytes;
        }
        round2.emplace(id, std::move(*result.value));
    }
    Group group;
    for (auto& [id, state] : round2) {
        auto result = StorageThreshold::dkg_part3(std::move(state), without(packages, id), inbox[id]);
        EXPECT_TRUE(result.ok()) << "part3 for " << id;
        if (!group.plan.empty()) {
            EXPECT_EQ(group.plan, result.value->plan) << "plans differ at " << id;
        }
        group.plan = result.value->plan;
        group.storage_public_key = result.value->storage_public_key;
        group.shares.emplace(id, std::move(result.value->share));
    }
    return group;
}

/// Refresh among `participants`; each needs a share in `current`. Returns
/// the first failure status.
StorageResult<Group> run_refresh(const std::map<StorageHolderId, const StorageKeyShare*>& current,
                                 const StorageBytes& old_plan,
                                 const std::vector<StorageHolderId>& participants) {
    StorageResult<Group> out;
    const auto n = static_cast<uint16_t>(participants.size());
    std::map<StorageHolderId, nexus::crypto::StorageRefreshRound1> round1;
    StoragePeerBytesMap packages;
    for (const auto id : participants) {
        auto result = StorageThreshold::refresh_part1(*current.at(id), n);
        if (!result.ok()) {
            out.status = result.status;
            return out;
        }
        packages[id] = result.value->package();
        round1.emplace(id, std::move(*result.value));
    }
    std::map<StorageHolderId, nexus::crypto::StorageRefreshRound2> round2;
    std::map<StorageHolderId, StoragePeerBytesMap> inbox;
    for (auto& [id, state] : round1) {
        auto result = StorageThreshold::refresh_part2(std::move(state), without(packages, id));
        if (!result.ok()) {
            out.status = result.status;
            return out;
        }
        for (const auto& [recipient, bytes] : result.value->packages_for_recipients()) {
            inbox[recipient][id] = bytes;
        }
        round2.emplace(id, std::move(*result.value));
    }
    Group group;
    for (auto& [id, state] : round2) {
        auto result = StorageThreshold::refresh_part3(std::move(state), without(packages, id),
                                                      inbox[id], *current.at(id), old_plan);
        if (!result.ok()) {
            out.status = result.status;
            return out;
        }
        if (!group.plan.empty()) {
            EXPECT_EQ(group.plan, result.value->plan);
        }
        group.plan = result.value->plan;
        group.storage_public_key = result.value->storage_public_key;
        group.shares.emplace(id, std::move(result.value->share));
    }
    out.status = StorageStatus::Ok;
    out.value.emplace(std::move(group));
    return out;
}

std::map<StorageHolderId, const StorageKeyShare*> all_shares(const Group& group) {
    std::map<StorageHolderId, const StorageKeyShare*> out;
    for (const auto& [id, share] : group.shares) {
        out[id] = &share;
    }
    return out;
}

StorageResult<StorageKeyShare> enroll(const Group& group, const std::vector<StorageHolderId>& helpers,
                                      StorageHolderId new_holder) {
    std::map<StorageHolderId, StoragePeerBytesMap> inbox;
    for (const auto h : helpers) {
        auto deltas = StorageThreshold::repair_part1(group.shares.at(h), group.plan, helpers, new_holder);
        if (!deltas.ok()) {
            StorageResult<StorageKeyShare> out;
            out.status = deltas.status;
            return out;
        }
        for (const auto& [recipient, delta] : *deltas.value) {
            inbox[recipient][h] = delta;
        }
    }
    StoragePeerBytesMap sigmas;
    for (const auto h : helpers) {
        auto sigma = StorageThreshold::repair_part2(group.shares.at(h), inbox[h]);
        EXPECT_TRUE(sigma.ok());
        sigmas[h] = *sigma.value;
    }
    return StorageThreshold::repair_part3(group.plan, new_holder, sigmas);
}

StorageUnlockContext context() {
    StorageUnlockContext ctx;
    randombytes_buf(ctx.network_id.data(), ctx.network_id.size());
    randombytes_buf(ctx.plan_digest.data(), ctx.plan_digest.size());
    randombytes_buf(ctx.request_nonce.data(), ctx.request_nonce.size());
    ctx.epoch = 42;
    return ctx;
}

StoragePeerBytesMap partials(const Group& group, const std::vector<StorageHolderId>& holders,
                             const StorageUnlockContext& ctx, const StoragePoint& ephemeral) {
    StoragePeerBytesMap out;
    for (const auto h : holders) {
        auto partial = StorageThreshold::create_partial(group.shares.at(h), group.plan, ctx, ephemeral);
        EXPECT_TRUE(partial.ok()) << "partial for " << h;
        out[h] = StorageBytes(partial.value->begin(), partial.value->end());
    }
    return out;
}

std::vector<uint8_t> bytes_of(const SecureBuffer& buffer) {
    return {buffer.data(), buffer.data() + buffer.size()};
}

class StorageThresholdTest : public ::testing::Test {
protected:
    void SetUp() override {
        crypto_.start();
        data_key_.resize(32);
        randombytes_buf(data_key_.data(), data_key_.size());
    }

    StorageWrappedDataKey wrap(const Group& group) {
        auto wrapped = StorageThreshold::wrap_data_key(crypto_, group.storage_public_key, data_key_,
                                                       server_id_);
        EXPECT_TRUE(wrapped.ok());
        return *wrapped.value;
    }

    StorageResult<SecureBuffer> unwrap(const StorageWrappedDataKey& wrapped, const Group& group,
                                       const StorageUnlockContext& ctx,
                                       const StoragePeerBytesMap& parts) {
        return StorageThreshold::unwrap_data_key(crypto_, wrapped, group.plan, ctx, parts, server_id_);
    }

    /// Unwrap with exactly t holders succeeds and with t - 1 fails. This is
    /// the library side of a cold start where only those holders are up.
    void expect_exact_threshold(uint16_t n, bool rotation = false) {
        const auto group = run_dkg(range(1, n), rotation);
        const auto t = *StorageThreshold::threshold_for(n);
        const auto wrapped = wrap(group);
        const auto ctx = context();
        // The last t holders are the ones still up.
        auto parts = partials(group, range(static_cast<StorageHolderId>(n - t + 1), n), ctx,
                              wrapped.ephemeral_point);
        auto unwrapped = unwrap(wrapped, group, ctx, parts);
        ASSERT_TRUE(unwrapped.ok()) << "n = " << n;
        EXPECT_EQ(bytes_of(*unwrapped.value), data_key_);
        parts.erase(parts.begin());
        EXPECT_EQ(unwrap(wrapped, group, ctx, parts).status, StorageStatus::BelowThreshold)
            << "n = " << n;
    }

    SodiumCryptoService crypto_;
    std::vector<uint8_t> data_key_;
    std::vector<uint8_t> server_id_{'s', 'e', 'r', 'v', 'e', 'r', '-', '1'};
};

}  // namespace

TEST(StorageThresholdParams, ThresholdIsCeilingOf65Percent) {
    EXPECT_FALSE(StorageThreshold::threshold_for(0).has_value());
    EXPECT_FALSE(StorageThreshold::threshold_for(51).has_value());
    for (uint16_t n = 1; n <= 50; ++n) {
        const uint16_t expected = static_cast<uint16_t>((65u * n + 99u) / 100u);
        EXPECT_EQ(StorageThreshold::threshold_for(n), expected) << "n = " << n;
    }
    const std::map<uint16_t, uint16_t> design_table{{5, 4}, {7, 5}, {10, 7}, {20, 13}, {31, 21}, {50, 33}};
    for (const auto& [n, t] : design_table) {
        EXPECT_EQ(StorageThreshold::threshold_for(n), t);
    }
}

TEST(StorageThresholdParams, KeyGenerationRejectsOutOfRangeCounts) {
    for (uint16_t n = 0; n < StorageThreshold::kMinHolders; ++n) {
        EXPECT_EQ(StorageThreshold::dkg_part1(1, n).status, StorageStatus::HolderCount) << n;
    }
    EXPECT_EQ(StorageThreshold::dkg_part1(1, 51).status, StorageStatus::HolderCount);
    EXPECT_EQ(StorageThreshold::dkg_part1(0, 5).status, StorageStatus::InvalidArgument);
}

TEST(StorageThresholdParams, RotationAndRefreshKeepAtLeastThreeHolders) {
    EXPECT_EQ(StorageThreshold::kMinReshareHolders, 3);
    for (uint16_t n = 0; n < StorageThreshold::kMinReshareHolders; ++n) {
        EXPECT_EQ(StorageThreshold::dkg_rotation_part1(1, n).status, StorageStatus::HolderCount)
            << n;
    }
    EXPECT_EQ(StorageThreshold::dkg_rotation_part1(1, 51).status, StorageStatus::HolderCount);
    EXPECT_TRUE(StorageThreshold::dkg_rotation_part1(1, 3).ok());
    EXPECT_TRUE(StorageThreshold::dkg_rotation_part1(1, 4).ok());
    // The first key still needs five.
    EXPECT_EQ(StorageThreshold::dkg_part1(1, 4).status, StorageStatus::HolderCount);
}

// After holder loss the key rotates at the new count: n = 4 gives t = 3 and
// n = 3 gives t = 2. Exactly t holders unwrap; t - 1 do not.
TEST_F(StorageThresholdTest, RotationToFourAndThreeHolders) {
    for (const uint16_t n : {4, 3}) {
        const auto group = run_dkg(range(1, n), true);
        auto info = StorageThreshold::validate_plan(group.plan);
        ASSERT_TRUE(info.ok()) << n;
        EXPECT_EQ(info.value->holder_count, n);
        EXPECT_EQ(info.value->threshold, n == 4 ? 3 : 2);
        expect_exact_threshold(n, true);
    }
}

// A 4-holder plan refreshes in place; shrinking it to 3 changes t and is
// refused, so the caller rotates.
TEST_F(StorageThresholdTest, FourHolderRefreshAndShrinkToThree) {
    const auto group = run_dkg(range(1, 4), true);
    auto refreshed = run_refresh(all_shares(group), group.plan, range(1, 4));
    ASSERT_TRUE(refreshed.ok());
    EXPECT_EQ(refreshed.value->storage_public_key, group.storage_public_key);
    EXPECT_EQ(StorageThreshold::refresh_part1(group.shares.at(1), 3).status,
              StorageStatus::ThresholdChange);
    const auto three = run_dkg(range(1, 3), true);
    EXPECT_EQ(StorageThreshold::refresh_part1(three.shares.at(1), 2).status,
              StorageStatus::HolderCount);
}

TEST_F(StorageThresholdTest, KeyGenerationWrapAndUnwrap) {
    const auto group = run_dkg(range(1, 7));
    auto info = StorageThreshold::validate_plan(group.plan);
    ASSERT_TRUE(info.ok());
    EXPECT_EQ(info.value->holder_count, 7);
    EXPECT_EQ(info.value->threshold, 5);
    EXPECT_EQ(info.value->storage_public_key, group.storage_public_key);
    EXPECT_EQ(info.value->holders, range(1, 7));
    for (const auto& [id, share] : group.shares) {
        EXPECT_EQ(share.holder(), id);
        EXPECT_EQ(share.threshold(), 5);
        EXPECT_EQ(share.storage_public_key(), group.storage_public_key);
    }

    const auto wrapped = wrap(group);
    const auto ctx = context();
    for (const auto& set : {range(1, 5), range(3, 7), range(1, 7)}) {
        auto unwrapped = unwrap(wrapped, group, ctx, partials(group, set, ctx, wrapped.ephemeral_point));
        ASSERT_TRUE(unwrapped.ok());
        EXPECT_EQ(bytes_of(*unwrapped.value), data_key_);
    }
}

TEST_F(StorageThresholdTest, ExactlyTAndTMinusOneHolders) {
    for (const uint16_t n : {5, 6, 7, 10, 20, 31}) {
        expect_exact_threshold(n);
    }
}

TEST_F(StorageThresholdTest, ExactlyTAndTMinusOneHoldersAtCap) {
    expect_exact_threshold(50);
}

TEST_F(StorageThresholdTest, FewerThanTPartials) {
    const auto group = run_dkg(range(1, 5));
    const auto wrapped = wrap(group);
    const auto ctx = context();
    EXPECT_EQ(unwrap(wrapped, group, ctx, partials(group, range(1, 3), ctx, wrapped.ephemeral_point)).status,
              StorageStatus::BelowThreshold);
    EXPECT_EQ(unwrap(wrapped, group, ctx, {}).status, StorageStatus::BelowThreshold);
}

TEST_F(StorageThresholdTest, InvalidDleqPartial) {
    const auto group = run_dkg(range(1, 5));
    const auto wrapped = wrap(group);
    const auto ctx = context();
    auto parts = partials(group, range(1, 4), ctx, wrapped.ephemeral_point);

    auto bad_proof = parts;
    bad_proof[2][50] ^= 0x01;
    EXPECT_EQ(StorageThreshold::verify_partial(group.plan, ctx, wrapped.ephemeral_point, 2, bad_proof[2]),
              StorageStatus::InvalidProof);
    EXPECT_EQ(unwrap(wrapped, group, ctx, bad_proof).status, StorageStatus::InvalidProof);

    // A valid partial presented as another holder's.
    auto swapped = parts;
    swapped[2] = parts[3];
    EXPECT_EQ(unwrap(wrapped, group, ctx, swapped).status, StorageStatus::InvalidProof);

    // t valid partials plus one invalid one still fail closed.
    auto extra = parts;
    extra[5] = parts[1];
    EXPECT_EQ(unwrap(wrapped, group, ctx, extra).status, StorageStatus::InvalidProof);

    for (const auto& [h, p] : parts) {
        EXPECT_EQ(StorageThreshold::verify_partial(group.plan, ctx, wrapped.ephemeral_point, h, p),
                  StorageStatus::Ok);
    }
}

TEST_F(StorageThresholdTest, PartialForADifferentR) {
    const auto group = run_dkg(range(1, 5));
    const auto wrapped = wrap(group);
    const auto other = wrap(group);
    ASSERT_NE(wrapped.ephemeral_point, other.ephemeral_point);
    const auto ctx = context();
    auto parts = partials(group, range(1, 4), ctx, wrapped.ephemeral_point);
    parts[1] = partials(group, {1}, ctx, other.ephemeral_point)[1];
    EXPECT_EQ(unwrap(wrapped, group, ctx, parts).status, StorageStatus::InvalidProof);
}

TEST_F(StorageThresholdTest, PartialBoundToRequestNonceAndEpoch) {
    const auto group = run_dkg(range(1, 5));
    const auto wrapped = wrap(group);
    const auto ctx = context();
    const auto parts = partials(group, range(1, 4), ctx, wrapped.ephemeral_point);
    auto replay = ctx;
    replay.request_nonce[0] ^= 0x01;
    EXPECT_EQ(unwrap(wrapped, group, replay, parts).status, StorageStatus::InvalidProof);
    auto later = ctx;
    later.epoch += 1;
    EXPECT_EQ(unwrap(wrapped, group, later, parts).status, StorageStatus::InvalidProof);
    auto other_network = ctx;
    other_network.network_id[0] ^= 0x01;
    EXPECT_EQ(unwrap(wrapped, group, other_network, parts).status, StorageStatus::InvalidProof);
}

TEST_F(StorageThresholdTest, WrappedKeyBoundToServerAndKey) {
    const auto group = run_dkg(range(1, 5));
    const auto other = run_dkg(range(1, 5));
    const auto wrapped = wrap(group);
    const auto ctx = context();
    const auto parts = partials(group, range(1, 4), ctx, wrapped.ephemeral_point);

    const std::vector<uint8_t> other_server{'s', 'e', 'r', 'v', 'e', 'r', '-', '2'};
    EXPECT_EQ(StorageThreshold::unwrap_data_key(crypto_, wrapped, group.plan, ctx, parts, other_server)
                  .status,
              StorageStatus::CryptoFailure);

    auto tampered = wrapped;
    tampered.ciphertext.ciphertext[0] ^= 0x01;
    EXPECT_EQ(unwrap(tampered, group, ctx, parts).status, StorageStatus::CryptoFailure);

    // A wrapped key that names another storage key than the plan.
    EXPECT_EQ(unwrap(wrapped, other, ctx, parts).status, StorageStatus::InvalidArgument);

    EXPECT_EQ(StorageThreshold::wrap_data_key(crypto_, group.storage_public_key, {}, server_id_).status,
              StorageStatus::InvalidArgument);
    EXPECT_EQ(StorageThreshold::wrap_data_key(crypto_, StoragePoint{}, data_key_, server_id_).status,
              StorageStatus::InvalidArgument);
}

TEST_F(StorageThresholdTest, RefreshKeepsKeyAndRetiresPreRefreshShares) {
    const auto group = run_dkg(range(1, 5));
    const auto wrapped = wrap(group);
    auto refreshed = run_refresh(all_shares(group), group.plan, range(1, 5));
    ASSERT_TRUE(refreshed.ok());
    EXPECT_EQ(refreshed.value->storage_public_key, group.storage_public_key);
    EXPECT_NE(refreshed.value->plan, group.plan);

    const auto ctx = context();
    auto unwrapped = unwrap(wrapped, *refreshed.value, ctx,
                            partials(*refreshed.value, range(2, 5), ctx, wrapped.ephemeral_point));
    ASSERT_TRUE(unwrapped.ok());
    EXPECT_EQ(bytes_of(*unwrapped.value), data_key_);

    // A pre-refresh share cannot answer for the new plan, and its partial
    // does not combine with post-refresh partials.
    EXPECT_EQ(StorageThreshold::create_partial(group.shares.at(1), refreshed.value->plan, ctx,
                                               wrapped.ephemeral_point)
                  .status,
              StorageStatus::ShareMismatch);
    auto mixed = partials(*refreshed.value, range(2, 4), ctx, wrapped.ephemeral_point);
    mixed[1] = partials(group, {1}, ctx, wrapped.ephemeral_point)[1];
    EXPECT_EQ(unwrap(wrapped, *refreshed.value, ctx, mixed).status, StorageStatus::InvalidProof);
}

TEST_F(StorageThresholdTest, RemovedHolderAfterReshare) {
    // 6 holders (t = 4) to 5 holders (t = 4).
    const auto group = run_dkg(range(1, 6));
    const auto wrapped = wrap(group);
    auto refreshed = run_refresh(all_shares(group), group.plan, range(1, 5));
    ASSERT_TRUE(refreshed.ok());
    auto info = StorageThreshold::validate_plan(refreshed.value->plan);
    ASSERT_TRUE(info.ok());
    EXPECT_EQ(info.value->holders, range(1, 5));

    const auto ctx = context();
    EXPECT_EQ(StorageThreshold::create_partial(group.shares.at(6), refreshed.value->plan, ctx,
                                               wrapped.ephemeral_point)
                  .status,
              StorageStatus::ShareMismatch);
    auto parts = partials(*refreshed.value, range(1, 3), ctx, wrapped.ephemeral_point);
    parts[6] = partials(group, {6}, ctx, wrapped.ephemeral_point)[6];
    EXPECT_EQ(unwrap(wrapped, *refreshed.value, ctx, parts).status, StorageStatus::InvalidProof);
    EXPECT_EQ(StorageThreshold::plan_commitment(refreshed.value->plan, 6).status,
              StorageStatus::InvalidArgument);
}

TEST_F(StorageThresholdTest, ThresholdChangeRotatesTheKey) {
    const auto group = run_dkg(range(1, 7));
    // 7 holders (t = 5) to 6 holders (t = 4): refresh is refused.
    EXPECT_EQ(StorageThreshold::refresh_part1(group.shares.at(1), 6).status,
              StorageStatus::ThresholdChange);
    // Rotation: a fresh key among the 6, and the data key is rewrapped
    // through one threshold unlock of the old key.
    const auto wrapped = wrap(group);
    const auto rotated = run_dkg(range(1, 6));
    EXPECT_NE(rotated.storage_public_key, group.storage_public_key);
    const auto ctx = context();
    auto old_unlock = unwrap(wrapped, group, ctx, partials(group, range(1, 5), ctx, wrapped.ephemeral_point));
    ASSERT_TRUE(old_unlock.ok());
    auto rewrapped = StorageThreshold::wrap_data_key(crypto_, rotated.storage_public_key,
                                                     old_unlock.value->span(), server_id_);
    ASSERT_TRUE(rewrapped.ok());
    auto new_unlock = unwrap(*rewrapped.value, rotated, ctx,
                             partials(rotated, range(3, 6), ctx, rewrapped.value->ephemeral_point));
    ASSERT_TRUE(new_unlock.ok());
    EXPECT_EQ(bytes_of(*new_unlock.value), data_key_);
}

TEST_F(StorageThresholdTest, ReshareByFewerThanTOldHolders) {
    // Plan of 6 (t = 4). Enroll 7 and 8, then refresh among {1, 2, 3, 7, 8}:
    // only three old holders contribute.
    const auto group = run_dkg(range(1, 6));
    auto seven = enroll(group, {1, 2, 3, 4}, 7);
    auto eight = enroll(group, {3, 4, 5, 6}, 8);
    ASSERT_TRUE(seven.ok());
    ASSERT_TRUE(eight.ok());
    auto current = all_shares(group);
    current[7] = &*seven.value;
    current[8] = &*eight.value;
    EXPECT_EQ(run_refresh(current, group.plan, {1, 2, 3, 7, 8}).status,
              StorageStatus::BelowThreshold);
    // Enrollment itself needs t helpers.
    EXPECT_EQ(enroll(group, {1, 2, 3}, 9).status, StorageStatus::BelowThreshold);
}

TEST_F(StorageThresholdTest, EnrollmentReplacesALostHolder) {
    // Holder 5 is lost; holder 6 joins at the same threshold.
    const auto group = run_dkg(range(1, 5));
    const auto wrapped = wrap(group);
    auto six = enroll(group, {1, 2, 3, 4}, 6);
    ASSERT_TRUE(six.ok());
    EXPECT_EQ(six.value->holder(), 6);
    auto current = all_shares(group);
    current[6] = &*six.value;
    auto refreshed = run_refresh(current, group.plan, {1, 2, 3, 4, 6});
    ASSERT_TRUE(refreshed.ok());
    EXPECT_EQ(refreshed.value->storage_public_key, group.storage_public_key);
    const auto ctx = context();
    auto unwrapped = unwrap(wrapped, *refreshed.value, ctx,
                            partials(*refreshed.value, {2, 3, 4, 6}, ctx, wrapped.ephemeral_point));
    ASSERT_TRUE(unwrapped.ok());
    EXPECT_EQ(bytes_of(*unwrapped.value), data_key_);
}

TEST_F(StorageThresholdTest, EnrollmentWithFewerThanTSigmas) {
    const auto group = run_dkg(range(1, 5));
    const std::vector<StorageHolderId> helpers{1, 2, 3, 4};
    std::map<StorageHolderId, StoragePeerBytesMap> inbox;
    for (const auto h : helpers) {
        auto deltas = StorageThreshold::repair_part1(group.shares.at(h), group.plan, helpers, 6);
        ASSERT_TRUE(deltas.ok());
        for (const auto& [recipient, delta] : *deltas.value) {
            inbox[recipient][h] = delta;
        }
    }
    StoragePeerBytesMap sigmas;
    for (const auto h : helpers) {
        sigmas[h] = *StorageThreshold::repair_part2(group.shares.at(h), inbox[h]).value;
    }
    auto short_sigmas = sigmas;
    short_sigmas.erase(4);
    EXPECT_EQ(StorageThreshold::repair_part3(group.plan, 6, short_sigmas).status,
              StorageStatus::BelowThreshold);
    auto tampered = sigmas;
    tampered[2][0] ^= 0x01;
    EXPECT_EQ(StorageThreshold::repair_part3(group.plan, 6, tampered).status,
              StorageStatus::CryptoFailure);
    EXPECT_TRUE(StorageThreshold::repair_part3(group.plan, 6, sigmas).ok());
}

TEST_F(StorageThresholdTest, ShareSerializationRoundTrip) {
    const auto group = run_dkg(range(1, 5));
    auto sealed = StorageThreshold::serialize_share(group.shares.at(3));
    ASSERT_TRUE(sealed.ok());
    auto restored = StorageThreshold::deserialize_share(sealed.value->span());
    ASSERT_TRUE(restored.ok());
    EXPECT_EQ(restored.value->holder(), 3);
    EXPECT_EQ(restored.value->storage_public_key(), group.storage_public_key);

    const auto wrapped = wrap(group);
    const auto ctx = context();
    auto parts = partials(group, {1, 2, 4}, ctx, wrapped.ephemeral_point);
    auto partial = StorageThreshold::create_partial(*restored.value, group.plan, ctx, wrapped.ephemeral_point);
    ASSERT_TRUE(partial.ok());
    parts[3] = StorageBytes(partial.value->begin(), partial.value->end());
    EXPECT_TRUE(unwrap(wrapped, group, ctx, parts).ok());

    EXPECT_EQ(StorageThreshold::deserialize_share({}).status, StorageStatus::InvalidArgument);
    const std::vector<uint8_t> garbage{1, 2, 3, 4};
    EXPECT_EQ(StorageThreshold::deserialize_share(garbage).status, StorageStatus::Serialization);
}

TEST_F(StorageThresholdTest, MalformedPlanRejected) {
    EXPECT_EQ(StorageThreshold::validate_plan({}).status, StorageStatus::InvalidArgument);
    const std::vector<uint8_t> garbage{0, 1, 2, 3, 4, 5};
    EXPECT_EQ(StorageThreshold::validate_plan(garbage).status, StorageStatus::Serialization);
    const auto group = run_dkg(range(1, 5));
    auto truncated = group.plan;
    truncated.resize(truncated.size() / 2);
    EXPECT_NE(StorageThreshold::validate_plan(truncated).status, StorageStatus::Ok);
}
