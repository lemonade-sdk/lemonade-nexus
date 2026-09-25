#include "OnboardingValidation.hpp"

#include <LemonadeNexus/Core/OnboardingTypes.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Security/Genesis/BootstrapCertificate.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <cstring>

namespace nexus::core::onboarding_validation {

std::string check_bundle_genesis_binding(
        crypto::SodiumCryptoService& crypto, const ApprovedOnboardingBundle& bundle) {
    const auto genesis_bytes = crypto::from_base64(
        crypto::canonical_key_b64(bundle.genesis_pubkey));
    if (genesis_bytes.size() != crypto::kEd25519PublicKeySize) {
        return "bundle genesis_pubkey is not a base64 Ed25519 public key";
    }
    crypto::Ed25519PublicKey genesis_pk{};
    std::memcpy(genesis_pk.data(), genesis_bytes.data(), genesis_bytes.size());
    const auto derived = security::derive_network_id(
        genesis_pk, security::constants::kSecurityRulesetVersion,
        security::constants::kConsensusRulesetVersion);
    std::vector<uint8_t> cert_network;
    try {
        cert_network = crypto::from_hex(bundle.certificate.network_id);
    } catch (...) {
        return "certificate network_id is not hex";
    }
    if (cert_network.size() != derived.size() ||
        std::memcmp(cert_network.data(), derived.data(), derived.size()) != 0) {
        return "the bundle's Genesis identity does not derive the certificate's network id";
    }
    return {};
}

}  // namespace nexus::core::onboarding_validation
