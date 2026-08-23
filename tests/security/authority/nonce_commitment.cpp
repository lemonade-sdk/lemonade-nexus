#include <LemonadeNexus/Security/Authority/NonceCommitmentStore.hpp>

#include <gtest/gtest.h>

using nexus::security::NodeId;
using nexus::security::NonceCommitment;
using nexus::security::NonceCommitmentStore;

namespace {

NodeId node(uint8_t byte) {
    NodeId id;
    id.bytes.fill(byte);
    return id;
}

NonceCommitment commitment(uint64_t session, uint8_t participant_byte, uint8_t value) {
    NonceCommitment record;
    record.epoch = 5;
    record.key_generation = 5;
    record.session_id = session;
    record.participant = node(participant_byte);
    record.commitment = {value, value, value};
    return record;
}

TEST(NonceCommitmentStore, SessionRegistersOnce) {
    NonceCommitmentStore store;
    EXPECT_TRUE(store.register_session(5, 100));
    EXPECT_FALSE(store.register_session(5, 100));
    EXPECT_TRUE(store.session_registered(5, 100));
    EXPECT_FALSE(store.session_registered(5, 101));
}

TEST(NonceCommitmentStore, SameSessionIdInAnotherEpochIsIndependent) {
    NonceCommitmentStore store;
    EXPECT_TRUE(store.register_session(5, 100));
    EXPECT_TRUE(store.register_session(6, 100));
}

TEST(NonceCommitmentStore, InsertNeedsRegisteredSession) {
    NonceCommitmentStore store;
    EXPECT_FALSE(store.insert(commitment(100, 0xA1, 0x01)));
    ASSERT_TRUE(store.register_session(5, 100));
    EXPECT_TRUE(store.insert(commitment(100, 0xA1, 0x01)));
}

TEST(NonceCommitmentStore, RepeatedCommitmentBytesRejected) {
    // A restored signer that replays a used commitment must fail even in a
    // fresh session.
    NonceCommitmentStore store;
    ASSERT_TRUE(store.register_session(5, 100));
    ASSERT_TRUE(store.register_session(5, 101));
    ASSERT_TRUE(store.insert(commitment(100, 0xA1, 0x01)));

    auto replay = commitment(101, 0xA1, 0x01);
    EXPECT_FALSE(store.insert(replay));
    EXPECT_TRUE(store.commitment_exists(5, 5, commitment(100, 0xA1, 0x01).commitment));
}

TEST(NonceCommitmentStore, OneCommitmentPerParticipantPerSession) {
    NonceCommitmentStore store;
    ASSERT_TRUE(store.register_session(5, 100));
    ASSERT_TRUE(store.insert(commitment(100, 0xA1, 0x01)));
    EXPECT_FALSE(store.insert(commitment(100, 0xA1, 0x02)));
    EXPECT_TRUE(store.insert(commitment(100, 0xA2, 0x03)));
}

TEST(NonceCommitmentStore, EmptyCommitmentRejected) {
    NonceCommitmentStore store;
    ASSERT_TRUE(store.register_session(5, 100));
    auto record = commitment(100, 0xA1, 0x01);
    record.commitment.clear();
    EXPECT_FALSE(store.insert(record));
}

TEST(NonceCommitmentStore, DifferentKeyGenerationIsADifferentGroup) {
    NonceCommitmentStore store;
    ASSERT_TRUE(store.register_session(5, 100));
    ASSERT_TRUE(store.register_session(6, 200));

    ASSERT_TRUE(store.insert(commitment(100, 0xA1, 0x01)));

    // The same bytes under the next epoch group key are a fresh commitment.
    NonceCommitment next = commitment(200, 0xA1, 0x01);
    next.epoch = 6;
    next.key_generation = 6;
    EXPECT_TRUE(store.insert(next));
    EXPECT_FALSE(store.commitment_exists(6, 5, next.commitment));
}

}  // namespace
