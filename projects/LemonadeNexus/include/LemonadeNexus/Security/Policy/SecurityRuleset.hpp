#pragma once

// One typed view of the compiled security behavior.
//
// Construct it only from SecurityConstants — never from operator
// configuration. It exists so protocol code and tests can pass the active
// ruleset around as a value instead of reaching into the constants namespace.

#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstddef>

namespace nexus::security {

struct SecurityRuleset {
    SecurityRulesetVersion security_version = constants::kSecurityRulesetVersion;
    ConsensusRulesetVersion consensus_version = constants::kConsensusRulesetVersion;

    [[nodiscard]] std::size_t max_byzantine_faults(std::size_t n) const {
        return constants::max_byzantine_faults(n);
    }

    [[nodiscard]] std::size_t consensus_quorum(std::size_t n) const {
        return constants::consensus_quorum(n);
    }

    [[nodiscard]] std::size_t authority_threshold(std::size_t n) const {
        return constants::authority_threshold(n);
    }

    [[nodiscard]] std::size_t tier1_target_count(std::size_t admitted) const {
        return constants::tier1_target_count(admitted);
    }
};

[[nodiscard]] constexpr SecurityRuleset compiled_ruleset() { return SecurityRuleset{}; }

}  // namespace nexus::security
