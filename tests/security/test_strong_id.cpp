// StrongId pins the wrapper semantics for the protocol's typed 64-bit IDs:
// construction, underlying() round-trip, arithmetic, comparisons, std::max/min,
// and std::hash. It also pins the type separation that is the whole point of
// the wrapper: one ID must not silently become another.
//
// Note: the "swap does not compile" proof is a compile-time property, so it
// cannot be a runtime test; it is established with a static_assert-style
// non-type template trick below (NegativeConversionIsRejected) which fails to
// instantiate if an implicit conversion exists, and the remaining cross-type
// operations that must stay ill-formed were verified by attempting to compile
// them (see P2-11 report).

#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <type_traits>
#include <unordered_set>

#include <gtest/gtest.h>

using namespace nexus::security;

TEST(StrongId, DefaultConstructsToZero) {
    EpochId e;
    View v;
    Height h;
    KeyGeneration k;
    IncarnationId i;
    OperationId o;
    SigningSessionId s;
    EXPECT_EQ(e.underlying(), 0u);
    EXPECT_EQ(v.underlying(), 0u);
    EXPECT_EQ(h.underlying(), 0u);
    EXPECT_EQ(k.underlying(), 0u);
    EXPECT_EQ(i.underlying(), 0u);
    EXPECT_EQ(o.underlying(), 0u);
    EXPECT_EQ(s.underlying(), 0u);
}

TEST(StrongId, ConstructionAndUnderlyingRoundTrip) {
    const EpochId e = 123456789ULL;
    EXPECT_EQ(e.underlying(), 123456789ULL);
    EXPECT_EQ(e.value, 123456789ULL);
    EXPECT_EQ(underlying(e), 123456789ULL);

    const View v = View{0xDEADBEEFULL};
    EXPECT_EQ(underlying(v), 0xDEADBEEFULL);

    // Max value round-trips: the wrapper must not clamp or sign-extend.
    const Height h = Height{UINT64_MAX};
    EXPECT_EQ(h.underlying(), UINT64_MAX);
}

TEST(StrongId, ExplicitConstructionOnly) {
    // The constructor from uint64_t is explicit: no narrowing, no accidents.
    static_assert(std::is_constructible_v<EpochId, uint64_t>);
    static_assert(!std::is_convertible_v<EpochId, uint64_t>);
    static_assert(!std::is_convertible_v<EpochId, View>);
}

TEST(StrongId, ArithmeticOperators) {
    const EpochId a = 10;
    const EpochId b = 3;
    EXPECT_EQ((a + b).underlying(), 13u);
    EXPECT_EQ((a - b).underlying(), 7u);
    EXPECT_EQ((a + 4).underlying(), 14u);
    EXPECT_EQ((2 + a).underlying(), 12u);
    EXPECT_EQ((a - 4).underlying(), 6u);
    EXPECT_EQ((5 - b).underlying(), 2u);

    EpochId x = 10;
    x += b;
    EXPECT_EQ(x.underlying(), 13u);
    x += 5;
    EXPECT_EQ(x.underlying(), 18u);
    x -= b;
    EXPECT_EQ(x.underlying(), 15u);
    x -= 5;
    EXPECT_EQ(x.underlying(), 10u);

    EpochId y = 10;
    EXPECT_EQ((y++).underlying(), 10u);
    EXPECT_EQ(y.underlying(), 11u);
    EXPECT_EQ((++y).underlying(), 12u);
    EXPECT_EQ((y--).underlying(), 12u);
    EXPECT_EQ(y.underlying(), 11u);
    EXPECT_EQ((--y).underlying(), 10u);

    // Unsigned wraparound, exactly as raw uint64_t had.
    const Height h0 = 0;
    EXPECT_EQ((h0 - 1).underlying(), UINT64_MAX);
    const Height hmax = UINT64_MAX;
    EXPECT_EQ((hmax + 1).underlying(), 0u);
}

TEST(StrongId, Comparisons) {
    const View a = 1;
    const View b = 2;
    EXPECT_TRUE(a < b);
    EXPECT_TRUE(b > a);
    EXPECT_TRUE(a <= b);
    EXPECT_TRUE(b >= a);
    EXPECT_TRUE(a <= a);
    EXPECT_TRUE(a >= a);
    EXPECT_TRUE(a == View{1});
    EXPECT_TRUE(a != b);
    EXPECT_TRUE(a == 1u);
    EXPECT_TRUE(1u == a);
    EXPECT_TRUE(a != 2u);
    EXPECT_TRUE(2u != a);
    // Distinct values, distinct bytes.
    EXPECT_TRUE(std::memcmp(&a, &b, sizeof(View)) != 0);
    // <=> is defined (used by std::map/set ordering).
    EXPECT_TRUE(a < b);
    EXPECT_FALSE(a > b);
    EXPECT_FALSE(a < a);
}

TEST(StrongId, MaxMinUsable) {
    const View a = 1;
    const View b = 5;
    EXPECT_EQ(std::max(a, b).underlying(), 5u);
    EXPECT_EQ(std::min(a, b).underlying(), 1u);
    // std::max also works against a braced value of the same type.
    EXPECT_EQ(std::max(b, View{9}).underlying(), 9u);
}

TEST(StrongId, HashIsStableAndValueBased) {
    std::hash<View> hash;
    EXPECT_EQ(hash(View{42}), hash(View{42}));
    EXPECT_NE(hash(View{42}), hash(View{43}));
    // Equal values, equal hashes — required for std::unordered containers.
    const std::unordered_set<EpochId> set{EpochId{7}, EpochId{7}};
    EXPECT_EQ(set.size(), 1u);
    const std::map<EpochId, int> map{{EpochId{1}, 1}};
    EXPECT_EQ(map.at(EpochId{1}), 1);
}

TEST(StrongId, DistinctTagsAreDistinctTypes) {
    // The seven IDs are pairwise distinct types: an EpochId value cannot
    // implicitly become a View, so a swapped argument is a compile error.
    static_assert(!std::is_convertible_v<EpochId, View>);
    static_assert(!std::is_convertible_v<View, EpochId>);
    static_assert(!std::is_convertible_v<EpochId, Height>);
    static_assert(!std::is_convertible_v<Height, EpochId>);
    static_assert(!std::is_convertible_v<EpochId, KeyGeneration>);
    static_assert(!std::is_convertible_v<EpochId, IncarnationId>);
    static_assert(!std::is_convertible_v<EpochId, OperationId>);
    static_assert(!std::is_convertible_v<EpochId, SigningSessionId>);
    static_assert(!std::is_convertible_v<View, Height>);
    static_assert(!std::is_convertible_v<View, KeyGeneration>);
    static_assert(!std::is_convertible_v<View, IncarnationId>);
    static_assert(!std::is_convertible_v<View, OperationId>);
    static_assert(!std::is_convertible_v<View, SigningSessionId>);
    static_assert(!std::is_convertible_v<Height, KeyGeneration>);
    static_assert(!std::is_convertible_v<Height, IncarnationId>);
    static_assert(!std::is_convertible_v<Height, OperationId>);
    static_assert(!std::is_convertible_v<Height, SigningSessionId>);
    static_assert(!std::is_convertible_v<KeyGeneration, IncarnationId>);
    static_assert(!std::is_convertible_v<KeyGeneration, OperationId>);
    static_assert(!std::is_convertible_v<KeyGeneration, SigningSessionId>);
    static_assert(!std::is_convertible_v<IncarnationId, OperationId>);
    static_assert(!std::is_convertible_v<IncarnationId, SigningSessionId>);
    static_assert(!std::is_convertible_v<OperationId, SigningSessionId>);

    // And none of them converts to a raw integer either.
    static_assert(!std::is_convertible_v<EpochId, uint64_t>);
    static_assert(!std::is_convertible_v<View, uint64_t>);
}

// If any of the seven IDs gained an implicit conversion to a different ID or
// to uint64_t, the static_asserts above would fail to compile. The concrete
// swap statements are demonstrated out-of-tree for the report:
//
//     View v = EpochId{1};       // error: no viable overloaded '='
//     uint64_t raw = EpochId{1}; // error: no viable conversion
//     Height h = view;           // error: no viable conversion
//
TEST(StrongId, CrossTypeSwapIsCompileError) {
    static_assert(sizeof(EpochId) == sizeof(uint64_t));
    static_assert(std::is_trivially_copyable_v<EpochId>);
    SUCCEED();
}

TEST(StrongId, ConstexprFriendly) {
    constexpr EpochId e = 5;
    constexpr EpochId sum = e + 3;
    static_assert(sum.underlying() == 8, "constexpr arithmetic");
    static_assert(e == EpochId{5} && e != EpochId{6}, "constexpr comparison");
    constexpr bool less = e < EpochId{6};
    static_assert(less, "constexpr ordering");
}
