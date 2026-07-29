// Tests for the account group-key envelope (lnsdk::GroupKey) — the client half
// that lets a linked device receive the Cluster group key zero-knowledge: the
// key is sealed to a device's public key and only that device can open it.

#include <gtest/gtest.h>

#include <LemonadeNexusSDK/GroupKey.hpp>
#include <LemonadeNexusSDK/Identity.hpp>

#include <sodium.h>

#include <span>

using lnsdk::GroupKey;
using lnsdk::GroupKeyEnvelope;
using lnsdk::Identity;

namespace {

Identity make_identity() {
    Identity id;
    id.generate();
    return id;
}

std::span<const uint8_t> priv_span(const Identity& id) {
    return std::span<const uint8_t>(id.private_key());
}

} // namespace

TEST(GroupKeyEnvelope, GenerateProduces32RandomBytes) {
    ASSERT_GE(sodium_init(), 0);
    auto k = GroupKey::generate();
    ASSERT_FALSE(k.empty());
    EXPECT_EQ(Identity::from_base64(k).size(), 32u);
    EXPECT_NE(GroupKey::generate(), GroupKey::generate());
}

TEST(GroupKeyEnvelope, WrapThenUnwrapRoundTrips) {
    ASSERT_GE(sodium_init(), 0);
    auto b = make_identity();
    auto key = GroupKey::generate();

    auto env = GroupKey::wrap(b.pubkey_string(), key);
    ASSERT_TRUE(env.has_value());
    ASSERT_FALSE(env->wrapped_key.empty());

    auto out = GroupKey::unwrap(priv_span(b), *env);
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(*out, key);
}

TEST(GroupKeyEnvelope, WrongRecipientCannotUnwrap) {
    ASSERT_GE(sodium_init(), 0);
    auto a = make_identity();
    auto b = make_identity();
    auto key = GroupKey::generate();

    auto env = GroupKey::wrap(b.pubkey_string(), key);  // sealed to B
    ASSERT_TRUE(env.has_value());

    EXPECT_FALSE(GroupKey::unwrap(priv_span(a), *env).has_value());  // A cannot open
}

TEST(GroupKeyEnvelope, EachWrapUsesAFreshEphemeralButOpensTheSameKey) {
    ASSERT_GE(sodium_init(), 0);
    auto b = make_identity();
    auto key = GroupKey::generate();

    auto e1 = GroupKey::wrap(b.pubkey_string(), key);
    auto e2 = GroupKey::wrap(b.pubkey_string(), key);
    ASSERT_TRUE(e1.has_value() && e2.has_value());
    EXPECT_NE(e1->wrapped_key, e2->wrapped_key);
    EXPECT_EQ(GroupKey::unwrap(priv_span(b), *e1), GroupKey::unwrap(priv_span(b), *e2));
}

TEST(GroupKeyEnvelope, MalformedInputsReturnNullopt) {
    ASSERT_GE(sodium_init(), 0);
    auto b = make_identity();
    auto key = GroupKey::generate();

    EXPECT_FALSE(GroupKey::wrap("ed25519:QUJD", key).has_value());   // 3-byte pubkey
    EXPECT_FALSE(GroupKey::wrap(b.pubkey_string(), "short").has_value());  // bad key size

    GroupKeyEnvelope corrupt;
    corrupt.wrapped_key = "!!!not-base64!!!";
    EXPECT_FALSE(GroupKey::unwrap(priv_span(b), corrupt).has_value());
}
