#include <LemonadeNexus/Security/Authority/AuthorityObject.hpp>

#include <gtest/gtest.h>

using nexus::security::AuthorityObject;
using nexus::security::AuthorityOperation;
using nexus::security::authority_object_digest;
using nexus::security::Digest;

namespace {

AuthorityObject sample() {
    AuthorityObject object;
    object.network_id.fill(0x11);
    object.epoch = 7;
    object.key_generation = 7;
    object.operation = AuthorityOperation::EpochTransition;
    object.operation_id = 42;
    object.previous_state_digest.fill(0x22);
    object.finalized_state_digest.fill(0x33);
    object.consensus_certificate_digest.fill(0x44);
    return object;
}

TEST(AuthorityObject, DigestIsDeterministic) {
    EXPECT_EQ(authority_object_digest(sample()), authority_object_digest(sample()));
}

TEST(AuthorityObject, EveryFieldChangesTheDigest) {
    const Digest base = authority_object_digest(sample());

    auto object = sample();
    object.network_id.fill(0x12);
    EXPECT_NE(authority_object_digest(object), base);

    object = sample();
    object.epoch = 8;
    EXPECT_NE(authority_object_digest(object), base);

    object = sample();
    object.key_generation = 8;
    EXPECT_NE(authority_object_digest(object), base);

    object = sample();
    object.operation = AuthorityOperation::Checkpoint;
    EXPECT_NE(authority_object_digest(object), base);

    object = sample();
    object.operation_id = 43;
    EXPECT_NE(authority_object_digest(object), base);

    object = sample();
    object.previous_state_digest.fill(0x23);
    EXPECT_NE(authority_object_digest(object), base);

    object = sample();
    object.finalized_state_digest.fill(0x34);
    EXPECT_NE(authority_object_digest(object), base);

    object = sample();
    object.consensus_certificate_digest.fill(0x45);
    EXPECT_NE(authority_object_digest(object), base);
}

TEST(AuthorityObject, EpochAndKeyGenerationAreIndependentFields) {
    // key_generation equals epoch for the main authority key, but the digest
    // must still separate them: a future key domain may diverge.
    auto left = sample();
    left.epoch = 9;
    left.key_generation = 7;
    auto right = sample();
    right.epoch = 7;
    right.key_generation = 9;
    EXPECT_NE(authority_object_digest(left), authority_object_digest(right));
}

}  // namespace
