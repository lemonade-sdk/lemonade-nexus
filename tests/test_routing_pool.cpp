#include <LemonadeNexusSDK/RoutingConnectionPool.hpp>

#include <gtest/gtest.h>

using namespace lnsdk;

TEST(RoutingPool, InFlightCapBlocksNewSetups) {
    RoutingConnectionPool pool({/*max_endpoints=*/10, /*max_in_flight=*/2});
    std::string ev;
    EXPECT_TRUE(pool.try_begin("a", 1, ev));
    EXPECT_TRUE(pool.try_begin("b", 2, ev));
    EXPECT_FALSE(pool.try_begin("c", 3, ev));   // in-flight cap reached
    EXPECT_EQ(pool.in_flight(), 2u);

    pool.mark_established("a", 4);
    EXPECT_EQ(pool.in_flight(), 1u);
    EXPECT_TRUE(pool.try_begin("c", 5, ev));     // room frees up
}

TEST(RoutingPool, IdempotentReuse) {
    RoutingConnectionPool pool({10, 4});
    std::string ev;
    EXPECT_TRUE(pool.try_begin("a", 1, ev));
    EXPECT_TRUE(pool.try_begin("a", 2, ev));     // same identifier, no new slot
    EXPECT_EQ(pool.size(), 1u);
    EXPECT_EQ(pool.in_flight(), 1u);
}

TEST(RoutingPool, EvictsLruEstablishedAtCap) {
    RoutingConnectionPool pool({/*max_endpoints=*/2, /*max_in_flight=*/4});
    std::string ev;
    ASSERT_TRUE(pool.try_begin("a", 1, ev)); pool.mark_established("a", 1);
    ASSERT_TRUE(pool.try_begin("b", 2, ev)); pool.mark_established("b", 2);

    pool.touch("a", 5);                          // b is now least-recently-used
    ASSERT_TRUE(pool.try_begin("c", 6, ev));     // at cap -> evict LRU (b)
    EXPECT_EQ(ev, "b");
    EXPECT_EQ(pool.size(), 2u);
    EXPECT_FALSE(pool.state_of("b").has_value());
    EXPECT_TRUE(pool.state_of("a").has_value());
    EXPECT_TRUE(pool.state_of("c").has_value());
}

TEST(RoutingPool, CannotEvictWhenAllInFlight) {
    RoutingConnectionPool pool({/*max_endpoints=*/2, /*max_in_flight=*/4});
    std::string ev;
    ASSERT_TRUE(pool.try_begin("a", 1, ev));     // Requested (in-flight)
    ASSERT_TRUE(pool.try_begin("b", 2, ev));     // Requested (in-flight)
    EXPECT_FALSE(pool.try_begin("c", 3, ev));    // at cap, nothing evictable
    EXPECT_TRUE(ev.empty());
}
