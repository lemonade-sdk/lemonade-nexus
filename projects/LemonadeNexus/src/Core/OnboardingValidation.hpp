#pragma once

// Internal onboarding validation. Not the public include tree and not the
// ln_* SDK surface; test_onboarding gets a narrow PRIVATE path to it.

#include <string>

namespace nexus::crypto { class SodiumCryptoService; }
namespace nexus::core   { struct ApprovedOnboardingBundle; }

namespace nexus::core::onboarding_validation {

// "" when the Genesis identity derives the certificate network ID; else an error.
[[nodiscard]] std::string check_bundle_genesis_binding(
    crypto::SodiumCryptoService& crypto, const ApprovedOnboardingBundle& bundle);

}  // namespace nexus::core::onboarding_validation
