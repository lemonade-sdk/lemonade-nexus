#include <LemonadeNexus/Network/RateLimiter.hpp>

#include <gtest/gtest.h>

using namespace nexus::network;

TEST(RateLimiterTest, AllowsInitialBurst) {
    RateLimitConfig config{.requests_per_minute = 60, .burst_size = 5};
    RateLimiter limiter{config};

    // First 5 requests should be allowed (burst)
    for (int i = 0; i < 5; ++i) {
        EXPECT_TRUE(limiter.allow("192.168.1.1")) << "Request " << i << " should be allowed";
    }
}

TEST(RateLimiterTest, BlocksAfterBurstExhausted) {
    RateLimitConfig config{.requests_per_minute = 60, .burst_size = 3};
    RateLimiter limiter{config};

    // Exhaust burst
    for (int i = 0; i < 3; ++i) {
        limiter.allow("10.0.0.1");
    }

    // Next request should be blocked (no time passed for refill)
    EXPECT_FALSE(limiter.allow("10.0.0.1"));
}

TEST(RateLimiterTest, DifferentClientsHaveSeparateBuckets) {
    RateLimitConfig config{.requests_per_minute = 60, .burst_size = 2};
    RateLimiter limiter{config};

    // Exhaust client A's burst
    limiter.allow("client_a");
    limiter.allow("client_a");
    EXPECT_FALSE(limiter.allow("client_a"));

    // Client B should still have full burst
    EXPECT_TRUE(limiter.allow("client_b"));
    EXPECT_TRUE(limiter.allow("client_b"));
}

TEST(RateLimiterTest, NewClientGetsFullBurst) {
    RateLimitConfig config{.requests_per_minute = 120, .burst_size = 10};
    RateLimiter limiter{config};

    // First request from a new client should always be allowed
    EXPECT_TRUE(limiter.allow("new_client"));
}

TEST(RateLimiterTest, CleanupDoesNotCrash) {
    RateLimitConfig config{.requests_per_minute = 60, .burst_size = 5};
    RateLimiter limiter{config};

    limiter.allow("test_ip");
    limiter.cleanup();  // Should not crash
}

TEST(RateLimiterTest, DefaultConfig) {
    RateLimitConfig config;
    EXPECT_EQ(config.requests_per_minute, 120u);
    EXPECT_EQ(config.burst_size, 20u);
}
