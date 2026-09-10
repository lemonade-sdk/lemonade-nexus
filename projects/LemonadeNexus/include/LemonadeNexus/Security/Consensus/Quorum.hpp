#pragma once

// Quorum math has one home: the compiled constants. This class only gives
// consensus code a named entry point — it never restates a formula.

#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <cstddef>

namespace nexus::security {

class Quorum {
public:
    [[nodiscard]] static constexpr std::size_t max_byzantine_faults(std::size_t n) {
        return constants::max_byzantine_faults(n);
    }

    [[nodiscard]] static constexpr std::size_t consensus_quorum(std::size_t n) {
        return constants::consensus_quorum(n);
    }

    [[nodiscard]] static constexpr std::size_t authority_threshold(std::size_t n) {
        return constants::authority_threshold(n);
    }
};

}  // namespace nexus::security
