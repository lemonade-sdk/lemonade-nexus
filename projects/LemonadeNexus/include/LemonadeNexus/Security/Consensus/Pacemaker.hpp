#pragma once

// View timeout backoff. Pure logic: no timers, no clock.
//
// Timeout values affect liveness only. They never enter message validity or
// the safety quorum.
//
// Architecture reference: Security Architecture Final Draft 1.1, section 17.

#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <chrono>
#include <cstdint>

namespace nexus::security {

class Pacemaker {
public:
    [[nodiscard]] std::chrono::milliseconds timeout() const {
        return std::chrono::milliseconds(timeout_ms_);
    }

    void on_timeout();
    void on_committed_block();

private:
    uint64_t timeout_ms_ = constants::kViewTimeoutBaseMs;
    uint32_t consecutive_commits_ = 0;
};

}  // namespace nexus::security
