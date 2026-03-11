#include <LemonadeNexus/Network/RateLimiter.hpp>

#include <chrono>

namespace nexus::network {

static uint64_t now_ms() {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

RateLimiter::RateLimiter(const RateLimitConfig& config)
    : config_{config}
    , tokens_per_ms_{static_cast<double>(config.requests_per_minute) / 60000.0}
{
}

bool RateLimiter::allow(const std::string& client_ip) {
    std::lock_guard lock(mutex_);

    auto now = now_ms();
    auto it = buckets_.find(client_ip);

    if (it == buckets_.end()) {
        // New client: start with full burst minus this request
        buckets_[client_ip] = Bucket{
            static_cast<double>(config_.burst_size) - 1.0,
            now
        };
        // Periodic cleanup every 1000 requests
        if (++cleanup_counter_ % 1000 == 0) {
            cleanup();
        }
        return true;
    }

    auto& bucket = it->second;

    // Refill tokens based on elapsed time
    double elapsed = static_cast<double>(now - bucket.last_refill_ms);
    bucket.tokens += elapsed * tokens_per_ms_;
    bucket.last_refill_ms = now;

    // Cap at burst size
    if (bucket.tokens > static_cast<double>(config_.burst_size)) {
        bucket.tokens = static_cast<double>(config_.burst_size);
    }

    // Try to consume a token
    if (bucket.tokens >= 1.0) {
        bucket.tokens -= 1.0;
        return true;
    }

    return false;
}

void RateLimiter::cleanup() {
    auto now = now_ms();
    constexpr uint64_t kStaleMs = 300000; // 5 minutes

    for (auto it = buckets_.begin(); it != buckets_.end(); ) {
        if (now - it->second.last_refill_ms > kStaleMs) {
            it = buckets_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace nexus::network
