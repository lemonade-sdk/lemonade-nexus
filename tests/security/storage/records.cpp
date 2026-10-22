// Storage holder records (design B4, B5, B5a): canonical encoding, holder
// ranking, the deterministic selection every replica derives, and the checks
// a final plan must pass. The derivation runs here on hand-built chain states,
// so each holder-count rule is pinned without a mesh.

#include <LemonadeNexus/Crypto/StorageThreshold.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Storage/StorageRecords.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <algorithm>
#include <map>
#include <random>
#include <vector>

using namespace nexus::security;
namespace constants = nexus::security::constants;
using nexus::crypto::StorageThreshold;

namespace {

constexpr uint64_t kT0 = 1'800'000'000'000ULL;

NetworkId network() {
    NetworkId id{};
    id.fill(0xAB);
    return id;
}

struct Identity {
    nexus::crypto::Ed25519Keypair keys;
    NodeId id;
};

std::vector<Identity> identities(std::size_t count, uint8_t salt = 0) {
    std::vector<Identity> out;
    for (std::size_t i = 0; i < count; ++i) {
        Identity identity;
        std::array<uint8_t, crypto_sign_SEEDBYTES> seed{};
        seed[0] = 0x51;
        seed[1] = salt;
        seed[2] = static_cast<uint8_t>(i);
        crypto_sign_seed_keypair(identity.keys.public_key.data(),
                                 identity.keys.private_key.data(), seed.data());
        identity.id.bytes = identity.keys.public_key;
        out.push_back(identity);
    }
    return out;
}

std::vector<NodeId> ids_of(const std::vector<Identity>& identities_in) {
    std::vector<NodeId> out;
    for (const auto& identity : identities_in) out.push_back(identity.id);
    return out;
}

StorageEligibleSnapshot snapshot(EpochId target, std::vector<NodeId> pool, uint8_t seed = 0x5E) {
    StorageEligibleSnapshot s;
    s.target_epoch = target;
    s.eligibility_commitment.fill(static_cast<uint8_t>(target.underlying()));
    s.checkpoint_seed.fill(seed);
    s.pool = std::move(pool);
    return s;
}

std::vector<NodeId> nodes_of(const std::vector<StorageHolder>& holders) {
    std::vector<NodeId> out;
    for (const auto& holder : holders) out.push_back(holder.node);
    return out;
}

/// A final plan for `selection` without real key material: enough for the
/// derivation rules, which never read the plan bytes.
StorageFinalPlan fake_final(const StorageChainState& state, uint64_t block_time,
                            EpochId epoch = 2) {
    StorageFinalPlan plan;
    plan.network_id = network();
    plan.sequence = state.sequence + 1;
    plan.previous_record = state.head;
    plan.selection = state.pending_digest;
    plan.operation = state.pending->operation;
    plan.effective_epoch = epoch;
    plan.threshold = state.pending->threshold;
    plan.storage_public_key.fill(static_cast<uint8_t>(state.sequence + 1));
    plan.key_plan = {1, 2, 3};
    plan.holders = state.pending->holders;
    plan.confirmations.resize(plan.holders.size());
    plan.block_time_ms = block_time;
    if (plan.operation == StorageOperation::Refresh) {
        plan.key_created_ms = state.current->key_created_ms;
        plan.storage_public_key = state.current->storage_public_key;
        plan.retiring_plan = state.current->retiring_plan;
        plan.retiring_until = state.current->retiring_until;
    } else {
        plan.key_created_ms = block_time;
        if (plan.operation == StorageOperation::Rotate) {
            plan.retiring_plan = state.current_digest;
            plan.retiring_until = epoch + constants::kStorageGraceEpochs;
        }
    }
    return plan;
}

/// A state whose current plan holds `holders` (first key), created at kT0.
StorageChainState with_plan(const std::vector<NodeId>& holders) {
    StorageChainState state;
    const auto selection = derive_storage_selection(
        network(), state, nullptr, {}, kT0);
    EXPECT_FALSE(selection.has_value());
    const auto snap = snapshot(2, holders);
    auto create = derive_storage_selection(network(), state, &snap, {}, kT0);
    EXPECT_TRUE(create.has_value());
    EXPECT_TRUE(apply_storage_record(state, *create));
    EXPECT_TRUE(apply_storage_record(state, fake_final(state, kT0 + 1)));
    return state;
}

// --- Encoding -------------------------------------------------------------------

TEST(StorageRecords, CanonicalEncodingRoundTripsAndRefusesEverythingElse) {
    const auto people = identities(5);
    const auto snap = snapshot(2, ids_of(people));
    StorageChainState state;
    const auto selection = derive_storage_selection(network(), state, &snap, {}, kT0);
    ASSERT_TRUE(selection.has_value());
    const auto bytes = encode_storage_record(*selection);
    ASSERT_FALSE(bytes.empty());
    const auto back = decode_storage_record(bytes);
    ASSERT_TRUE(back.has_value());
    EXPECT_EQ(encode_storage_record(*back), bytes);
    EXPECT_EQ(storage_record_digest(*back), storage_record_digest(*selection));

    auto trailing = bytes;
    trailing.push_back(0);
    EXPECT_FALSE(decode_storage_record(trailing).has_value());
    for (std::size_t cut = 1; cut < bytes.size(); cut += 7) {
        EXPECT_FALSE(decode_storage_record(std::span(bytes).first(cut)).has_value());
    }
    // Holders out of identifier order are not a canonical record.
    StorageSelection swapped = *selection;
    std::swap(swapped.holders[0], swapped.holders[1]);
    EXPECT_TRUE(encode_storage_record(swapped).empty());

    // The payload kind must match the operation.
    BlockPayload payload = storage_record_payload(*selection);
    EXPECT_EQ(payload.kind, BlockPayloadKind::StorageHolderPlan);
    EXPECT_TRUE(storage_record_from_payload(payload).has_value());
    payload.kind = BlockPayloadKind::StorageKeyRotation;
    EXPECT_FALSE(storage_record_from_payload(payload).has_value());
    payload.kind = BlockPayloadKind::TreeBatch;
    EXPECT_FALSE(storage_record_from_payload(payload).has_value());
}

// --- Holder selection (B4) ---------------------------------------------------------

TEST(StorageRecords, RankingIsDeterministicAndCappedAtFifty) {
    auto pool = ids_of(identities(60));
    Digest seed{};
    seed.fill(0x22);
    const auto ranked = rank_storage_holders(seed, pool);
    EXPECT_EQ(ranked.size(), constants::kStorageMaxHolders);
    std::mt19937 shuffle(7);
    for (int i = 0; i < 5; ++i) {
        std::shuffle(pool.begin(), pool.end(), shuffle);
        EXPECT_EQ(rank_storage_holders(seed, pool), ranked);
    }
    // Another checkpoint seed ranks differently; no node picks its rank.
    Digest other{};
    other.fill(0x23);
    EXPECT_NE(rank_storage_holders(other, pool), ranked);
}

TEST(StorageRecords, FirstKeyNeedsFiveHoldersAndEveryReplicaDerivesTheSameBytes) {
    const auto five = ids_of(identities(5));
    StorageChainState state;
    auto four = five;
    four.pop_back();
    const auto small = snapshot(2, four);
    EXPECT_FALSE(derive_storage_selection(network(), state, &small, {}, kT0).has_value());

    const auto snap = snapshot(2, five);
    const auto first = derive_storage_selection(network(), state, &snap, {}, kT0);
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(first->operation, StorageOperation::Create);
    EXPECT_EQ(first->threshold, 4);
    EXPECT_EQ(first->holders.size(), 5u);
    for (std::size_t i = 0; i < first->holders.size(); ++i) {
        EXPECT_EQ(first->holders[i].holder_id, i + 1);
    }
    // A second replica with an identical chain and the same finalized pool,
    // listed in another order, derives identical bytes.
    StorageChainState replica;
    auto reversed = five;
    std::reverse(reversed.begin(), reversed.end());
    const auto snap2 = snapshot(2, reversed);
    const auto second = derive_storage_selection(network(), replica, &snap2, {}, kT0);
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(encode_storage_record(*first), encode_storage_record(*second));
}

TEST(StorageRecords, APendingSelectionBlocksUntilItsSessionTimesOut) {
    const auto five = ids_of(identities(5));
    StorageChainState state;
    const auto snap = snapshot(2, five);
    ASSERT_TRUE(apply_storage_record(
        state, *derive_storage_selection(network(), state, &snap, {}, kT0)));
    EXPECT_FALSE(derive_storage_selection(network(), state, &snap, {}, kT0 + 1000).has_value());
    // After the timeout with nobody silent, the same holders try again.
    const auto retry = derive_storage_selection(network(), state, &snap, {},
                                                kT0 + constants::kStorageSessionTimeoutMs);
    ASSERT_TRUE(retry.has_value());
    EXPECT_EQ(retry->attempt, 1u);
    EXPECT_EQ(retry->holders, state.pending->holders);
    // A silent holder of a first-key session leaves 4: below the creation
    // minimum, nothing is selected.
    const std::set<NodeId> silent{five[2]};
    EXPECT_FALSE(derive_storage_selection(network(), state, &snap, silent,
                                          kT0 + constants::kStorageSessionTimeoutMs)
                     .has_value());
}

// --- Re-sharing (B5) --------------------------------------------------------------

TEST(StorageRecords, BoundaryRefreshKeepsIdentifiersAndSWhenTheSetHolds) {
    const auto five = ids_of(identities(5));
    StorageChainState state = with_plan(five);
    const auto next = snapshot(3, five);
    const auto refresh = derive_storage_selection(network(), state, &next, {}, kT0 + 3'600'000);
    ASSERT_TRUE(refresh.has_value());
    EXPECT_EQ(refresh->operation, StorageOperation::Refresh);
    EXPECT_EQ(refresh->holders, state.current->holders);
    EXPECT_EQ(refresh->base_plan, state.current_digest);
    EXPECT_EQ(refresh->target_epoch, 3u);
    // Each boundary is used once.
    ASSERT_TRUE(apply_storage_record(state, *refresh));
    ASSERT_TRUE(apply_storage_record(state, fake_final(state, kT0 + 3'600'001, 3)));
    EXPECT_FALSE(
        derive_storage_selection(network(), state, &next, {}, kT0 + 3'700'000).has_value());
}

TEST(StorageRecords, AddingAHolderRotatesTheKey) {
    const auto six = ids_of(identities(6));
    std::vector<NodeId> five(six.begin(), six.begin() + 5);
    StorageChainState state = with_plan(five);
    // 6 holders keep t = 4, but the new one has no share: rotate.
    const auto next = snapshot(3, six);
    const auto selection = derive_storage_selection(network(), state, &next, {}, kT0 + 1000);
    ASSERT_TRUE(selection.has_value());
    EXPECT_EQ(selection->operation, StorageOperation::Rotate);
    EXPECT_EQ(selection->holders.size(), 6u);
    EXPECT_EQ(storage_record_kind(*selection), BlockPayloadKind::StorageKeyRotation);
}

TEST(StorageRecords, RemovingAHolderRefreshesOnlyWhenTStays) {
    // 20 to 19 holders keeps t = 13: a refresh without the lost holder.
    const auto twenty = ids_of(identities(20));
    StorageChainState state = with_plan(twenty);
    auto nineteen = nodes_of(state.current->holders);
    const NodeId lost = nineteen.back();
    nineteen.pop_back();
    const auto next = snapshot(3, nineteen);
    const auto refresh = derive_storage_selection(network(), state, &next, {}, kT0 + 1000);
    ASSERT_TRUE(refresh.has_value());
    EXPECT_EQ(refresh->operation, StorageOperation::Refresh);
    EXPECT_EQ(refresh->threshold, 13);
    EXPECT_EQ(refresh->holders.size(), 19u);
    for (const auto& holder : refresh->holders) {
        EXPECT_NE(holder.node, lost);
        // Every kept holder keeps its identifier.
        const auto it = std::find(state.current->holders.begin(), state.current->holders.end(),
                                  holder);
        EXPECT_NE(it, state.current->holders.end());
    }

    // 5 to 4 changes t (4 to 3): rotate instead.
    const auto five = ids_of(identities(5, 1));
    StorageChainState small = with_plan(five);
    std::vector<NodeId> four = nodes_of(small.current->holders);
    four.pop_back();
    const auto shrink = snapshot(3, four);
    const auto rotate = derive_storage_selection(network(), small, &shrink, {}, kT0 + 1000);
    ASSERT_TRUE(rotate.has_value());
    EXPECT_EQ(rotate->operation, StorageOperation::Rotate);
    EXPECT_EQ(rotate->threshold, 3);
}

TEST(StorageRecords, ARefreshWithFewerThanTOldHoldersIsNeverDerived) {
    // Plan of 6 (t = 4). A refresh among 3 of them would need t = 2 and so
    // fewer than t_old contributors; the derivation rotates instead, so a
    // proposal that claims such a refresh never matches any replica.
    const auto six = ids_of(identities(6));
    StorageChainState state = with_plan(six);
    std::vector<NodeId> three = nodes_of(state.current->holders);
    three.resize(3);
    const auto snap = snapshot(3, three);
    const auto derived = derive_storage_selection(network(), state, &snap, {}, kT0 + 1000);
    ASSERT_TRUE(derived.has_value());
    EXPECT_EQ(derived->operation, StorageOperation::Rotate);
    StorageSelection forged = *derived;
    forged.operation = StorageOperation::Refresh;
    forged.threshold = 4;
    forged.base_plan = state.current_digest;
    EXPECT_NE(encode_storage_record(forged), encode_storage_record(*derived));
}

TEST(StorageRecords, HolderLossShrinksToFourAndThreeThenStops) {
    const auto five = ids_of(identities(5));
    StorageChainState state = with_plan(five);
    const uint64_t day = constants::kStorageRotationIntervalMs;
    auto current = nodes_of(state.current->holders);

    // A due rotation among the 5; one holder is silent; the retry has 4.
    auto rotation = derive_storage_selection(network(), state, nullptr, {}, kT0 + day + 1);
    ASSERT_TRUE(rotation.has_value());
    EXPECT_EQ(rotation->operation, StorageOperation::Rotate);
    EXPECT_EQ(rotation->holders.size(), 5u);
    ASSERT_TRUE(apply_storage_record(state, *rotation));
    std::set<NodeId> silent{current[4]};
    auto retry = derive_storage_selection(network(), state, nullptr, silent,
                                          kT0 + day + 1 + constants::kStorageSessionTimeoutMs);
    ASSERT_TRUE(retry.has_value());
    EXPECT_EQ(retry->operation, StorageOperation::Rotate);
    EXPECT_EQ(retry->holders.size(), 4u);
    EXPECT_EQ(retry->threshold, 3);
    EXPECT_EQ(retry->attempt, 1u);
    ASSERT_TRUE(apply_storage_record(state, *retry));
    const uint64_t t4 = kT0 + day + 2 + constants::kStorageSessionTimeoutMs;
    ASSERT_TRUE(apply_storage_record(state, fake_final(state, t4)));
    EXPECT_EQ(state.current->threshold, 3);

    // Another loss: 3 holders, t = 2.
    current = nodes_of(state.current->holders);
    rotation = derive_storage_selection(network(), state, nullptr, {}, t4 + day);
    ASSERT_TRUE(rotation.has_value());
    ASSERT_TRUE(apply_storage_record(state, *rotation));
    silent = {current[3]};
    retry = derive_storage_selection(network(), state, nullptr, silent,
                                     t4 + day + constants::kStorageSessionTimeoutMs);
    ASSERT_TRUE(retry.has_value());
    EXPECT_EQ(retry->holders.size(), 3u);
    EXPECT_EQ(retry->threshold, 2);
    ASSERT_TRUE(apply_storage_record(state, *retry));
    const uint64_t t3 = t4 + day + 1 + constants::kStorageSessionTimeoutMs;
    ASSERT_TRUE(apply_storage_record(state, fake_final(state, t3)));
    EXPECT_EQ(state.current->holders.size(), 3u);

    // One more loss would leave 2: no retry is selected; the 3-holder plan
    // stays current.
    current = nodes_of(state.current->holders);
    rotation = derive_storage_selection(network(), state, nullptr, {}, t3 + day);
    ASSERT_TRUE(rotation.has_value());
    ASSERT_TRUE(apply_storage_record(state, *rotation));
    silent = {current[2]};
    const auto none = derive_storage_selection(
        network(), state, nullptr, silent, t3 + day + 1 + constants::kStorageSessionTimeoutMs);
    // The retry is refused; the only selection left is a fresh rotation of
    // the same 3 holders (the daily rule), never a 2-holder plan.
    if (none.has_value()) {
        EXPECT_EQ(none->holders.size(), 3u);
        EXPECT_EQ(none->attempt, 0u);
    }
}

// --- Rotation (B5a) ----------------------------------------------------------------

TEST(StorageRecords, RotationIsDueByBlockTimeOnly) {
    const auto five = ids_of(identities(5));
    StorageChainState state = with_plan(five);
    const uint64_t day = constants::kStorageRotationIntervalMs;
    EXPECT_FALSE(derive_storage_selection(network(), state, nullptr, {}, kT0 + day).has_value());
    const auto due = derive_storage_selection(network(), state, nullptr, {}, kT0 + day + 1);
    ASSERT_TRUE(due.has_value());
    EXPECT_EQ(due->operation, StorageOperation::Rotate);
    EXPECT_EQ(due->holders.size(), 5u);
    // At a boundary, a due rotation wins over a refresh of the same set.
    const auto next = snapshot(3, five);
    const auto boundary = derive_storage_selection(network(), state, &next, {}, kT0 + day + 1);
    ASSERT_TRUE(boundary.has_value());
    EXPECT_EQ(boundary->operation, StorageOperation::Rotate);
}

TEST(StorageRecords, RotationRetiresTheOldPlanForOneEpochAndRefreshCarriesIt) {
    const auto five = ids_of(identities(5));
    StorageChainState state = with_plan(five);
    const Digest first = state.current_digest;
    const StorageFinalPlan first_plan = *state.current;
    const uint64_t day = constants::kStorageRotationIntervalMs;
    ASSERT_TRUE(apply_storage_record(
        state, *derive_storage_selection(network(), state, nullptr, {}, kT0 + day + 1)));
    ASSERT_TRUE(apply_storage_record(state, fake_final(state, kT0 + day + 2, 4)));
    ASSERT_TRUE(state.retiring.has_value());
    EXPECT_EQ(state.retiring_digest, first);
    EXPECT_EQ(state.current->retiring_plan, first);
    EXPECT_EQ(state.current->retiring_until, 5u);

    // A refresh in the grace epoch keeps the retiring plan named.
    const auto next = snapshot(5, five);
    ASSERT_TRUE(apply_storage_record(
        state, *derive_storage_selection(network(), state, &next, {}, kT0 + day + 3)));
    ASSERT_TRUE(apply_storage_record(state, fake_final(state, kT0 + day + 4, 5)));
    EXPECT_EQ(state.current->operation, StorageOperation::Refresh);
    EXPECT_EQ(state.current->retiring_plan, first);
    EXPECT_EQ(state.retiring_digest, first);

    // A server that learns only the latest plan can still take the retiring
    // plan when it arrives later, and nothing else.
    StorageChainState late;
    ASSERT_TRUE(apply_storage_record(late, *state.current));
    EXPECT_FALSE(late.retiring.has_value());
    EXPECT_TRUE(apply_storage_record(late, first_plan));
    EXPECT_EQ(late.retiring_digest, first);
    EXPECT_FALSE(apply_storage_record(late, first_plan));
}

// --- Final plan checks --------------------------------------------------------------

class StorageFinalPlanTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        people = identities(5, 9);
        const auto snap = snapshot(2, ids_of(people));
        ASSERT_TRUE(apply_storage_record(
            state, *derive_storage_selection(network(), state, &snap, {}, kT0)));
        // A real key generation among the selected holder identifiers.
        const auto& selection = *state.pending;
        const auto n = static_cast<uint16_t>(selection.holders.size());
        std::map<uint16_t, nexus::crypto::StorageDkgRound1> round1;
        nexus::crypto::StoragePeerBytesMap packages;
        for (const auto& holder : selection.holders) {
            auto r = StorageThreshold::dkg_part1(holder.holder_id, n);
            ASSERT_TRUE(r.ok());
            packages[holder.holder_id] = r.value->package();
            round1.emplace(holder.holder_id, std::move(*r.value));
        }
        std::map<uint16_t, nexus::crypto::StorageDkgRound2> round2;
        std::map<uint16_t, nexus::crypto::StoragePeerBytesMap> inbox;
        for (auto& [id, state1] : round1) {
            auto others = packages;
            others.erase(id);
            auto r = StorageThreshold::dkg_part2(std::move(state1), others);
            ASSERT_TRUE(r.ok());
            for (const auto& [to, bytes] : r.value->packages_for_recipients()) {
                inbox[to][id] = bytes;
            }
            round2.emplace(id, std::move(*r.value));
        }
        for (auto& [id, state2] : round2) {
            auto others = packages;
            others.erase(id);
            auto r = StorageThreshold::dkg_part3(std::move(state2), others, inbox[id]);
            ASSERT_TRUE(r.ok());
            plan = r.value->plan;
        }
        for (const auto& holder : selection.holders) {
            confirmations[holder.node] = sign(holder, plan);
        }
    }

    nexus::crypto::Ed25519Signature sign(const StorageHolder& holder,
                                         const std::vector<uint8_t>& bytes) const {
        const auto& identity = *std::find_if(people.begin(), people.end(), [&](const auto& p) {
            return p.id == holder.node;
        });
        const Digest digest =
            storage_confirmation_digest(network(), state.pending_digest, bytes, holder);
        nexus::crypto::Ed25519Signature signature{};
        crypto_sign_detached(signature.data(), nullptr, digest.data(), digest.size(),
                             identity.keys.private_key.data());
        return signature;
    }

    std::vector<Identity> people;
    StorageChainState state;
    std::vector<uint8_t> plan;
    std::map<NodeId, nexus::crypto::Ed25519Signature> confirmations;
};

TEST_F(StorageFinalPlanTest, EveryHolderSignedTheExactPlan) {
    const auto final_plan = make_storage_final(state, plan, confirmations, 2, kT0 + 10);
    ASSERT_TRUE(final_plan.has_value());
    EXPECT_EQ(check_storage_final(state, *final_plan, 2), StorageFinalFailure::None);
    EXPECT_EQ(final_plan->key_created_ms, kT0 + 10);
    // Byte-for-byte: the record round-trips.
    EXPECT_TRUE(decode_storage_record(encode_storage_record(*final_plan)).has_value());
}

TEST_F(StorageFinalPlanTest, AMissingOrForeignConfirmationRefusesThePlan) {
    auto missing = confirmations;
    missing.erase(missing.begin());
    EXPECT_FALSE(make_storage_final(state, plan, missing, 2, kT0 + 10).has_value());

    auto final_plan = *make_storage_final(state, plan, confirmations, 2, kT0 + 10);
    // A signature over other plan bytes does not confirm this plan.
    auto other = plan;
    other.back() ^= 0x01;
    final_plan.confirmations[1] = sign(state.pending->holders[1], other);
    EXPECT_EQ(check_storage_final(state, final_plan, 2), StorageFinalFailure::ConfirmationInvalid);
}

TEST_F(StorageFinalPlanTest, DerivedFieldsAndTheSelectionMustMatch) {
    const auto good = *make_storage_final(state, plan, confirmations, 2, kT0 + 10);
    auto wrong_epoch = good;
    EXPECT_EQ(check_storage_final(state, wrong_epoch, 3), StorageFinalFailure::FieldMismatch);
    auto wrong_key = good;
    wrong_key.storage_public_key[0] ^= 0x01;
    EXPECT_EQ(check_storage_final(state, wrong_key, 2), StorageFinalFailure::KeyMismatch);
    auto wrong_holders = good;
    wrong_holders.holders[0].holder_id = 9;
    EXPECT_EQ(check_storage_final(state, wrong_holders, 2), StorageFinalFailure::SelectionMismatch);
    auto stale_time = good;
    stale_time.block_time_ms = kT0 - 1;
    EXPECT_EQ(check_storage_final(state, stale_time, 2), StorageFinalFailure::ChainMismatch);
    StorageChainState empty;
    EXPECT_EQ(check_storage_final(empty, good, 2), StorageFinalFailure::NoPendingSelection);
}

}  // namespace
