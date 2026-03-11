#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace nexus::network {

struct RateLimitConfig {
    uint32_t requests_per_minute{120};
    uint32_t burst_size{20};
};

/// Token-bucket rate limiter keyed by client IP address.
class RateLimiter {
public:
    explicit RateLimiter(const RateLimitConfig& config);

    /// Returns true if the request should be allowed.
    [[nodiscard]] bool allow(const std::string& client_ip);

    /// Evict stale buckets (call periodically or on each request).
    void cleanup();

private:
    struct Bucket {
        double   tokens;
        uint64_t last_refill_ms;
    };

    RateLimitConfig config_;
    double          tokens_per_ms_;
    mutable std::mutex mutex_;
    std::unordered_map<std::string, Bucket> buckets_;
    uint64_t cleanup_counter_{0};
};

} // namespace nexus::network
