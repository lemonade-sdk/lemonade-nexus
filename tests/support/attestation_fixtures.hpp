#pragma once

// Shared attestation fixture state: the release-pinnable PCR set, detached
// Ed25519 signing to base64, and the seeded EK -> AK activation record that
// lets a suite start past the enrollment redirect.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationProfileId.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationState.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace nexus_test {

// Exactly the release-pinnable set (kSvsmBootPcrs): readiness requires
// the same shape a qualified approval carries.
inline std::vector<std::pair<uint32_t, std::string>> svsm_boot_pcr_pins() {
    return {{8, std::string(64, '8')}, {9, std::string(64, '9')}};
}

/// Detached Ed25519 signature over `message`, base64-encoded.
inline std::string ed25519_sign_b64(std::string_view message,
                                    const nexus::crypto::Ed25519PrivateKey& key) {
    nexus::crypto::Ed25519Signature signature{};
    EXPECT_EQ(crypto_sign_detached(
        signature.data(), nullptr,
        reinterpret_cast<const unsigned char*>(message.data()), message.size(),
        key.data()), 0);
    return nexus::crypto::to_base64(signature);
}

/// Seeds a stored EK -> AK activation record (enrollment itself has dedicated
/// protocol coverage) so challenges keep their requested purpose instead of
/// being redirected to enrollment. Suites root their attestation state
/// differently, so the caller names the observer's svsm-activations directory.
inline void seed_svsm_activation(const nexus::security::NetworkId& network,
                                 const nexus::security::NodeId& node_id,
                                 const nexus::crypto::Ed25519PublicKey& node_key,
                                 const std::filesystem::path& store_dir) {
    using namespace nexus::security;
    const std::vector<uint8_t> spki{1, 2, 3, 4};
    SvsmAkActivationRecord record;
    record.network_id = network;
    record.node_id = node_id;
    record.node_key = node_key;
    record.incarnation = 1;
    record.profile_id = kTier1AttestationProfileId;
    record.profile_ruleset = kAttestationProfileRulesetVersion;
    record.ek_name = {0, 0x0b, 1};
    record.ak_name = {0, 0x0b, 2};
    record.ak_spki_b64 = nexus::crypto::to_base64(spki);
    record.ak_spki_digest = raw_ima_digest(spki);
    record.activation_receipt.fill(0x08);
    record.enrollment_evidence_digest.fill(0x09);
    SvsmActivationStore store(store_dir);
    ASSERT_TRUE(store.store(record));
}

}  // namespace nexus_test
