#include <LemonadeNexus/Security/Consensus/Pacemaker.hpp>

#include <algorithm>

namespace nexus::security {

void Pacemaker::on_timeout() {
    timeout_ms_ = std::min(timeout_ms_ * constants::kViewTimeoutBackoffFactor,
                           constants::kViewTimeoutMaxMs);
    consecutive_commits_ = 0;
}

void Pacemaker::on_committed_block() {
    ++consecutive_commits_;
    if (consecutive_commits_ >= constants::kTimeoutResetAfterCommittedBlocks) {
        timeout_ms_ = constants::kViewTimeoutBaseMs;
        consecutive_commits_ = 0;
    }
}

}  // namespace nexus::security
