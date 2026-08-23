#pragma once

// The compiled Linux Tier 1 attestation profile.
//
// The verified binary carries the first profile; binary attestation is what
// protects it. There is deliberately no loader from operator configuration —
// an operator input here would let one host weaken the bar every verifier
// applies. A new profile requires a new verified release.
//
// Architecture reference: sections 22 and 23.A.

#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>
#include <LemonadeNexus/Security/SnpVerify.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace nexus::security {

struct LinuxAttestationProfile {
    uint32_t profile_version{};

    SnpPolicyRequirements snp;

    /// Base64 DER SPKI of the enrolled vTPM attestation key. Empty pins none.
    std::string required_ak_spki_b64;

    /// Digest of the required IMA policy (architecture 6.3). Bound into the
    /// profile digest now; enforcement waits on an evidence field the platform
    /// chain does not carry yet.
    Digest ima_policy_digest{};
    bool enforce_ima_policy{true};

    /// Hex SHA-256 digests from the approved release ledger. The measured
    /// binary must match one of them; an empty list approves none.
    std::vector<std::string> approved_binary_sha256;

    bool require_no_new_privs{true};
    bool require_seccomp{true};

    SecurityRulesetVersion security_ruleset{};
};

/// The attestation_policy_digest carried in every challenge. Every field is
/// encoded, so two profiles that differ in effect differ in digest.
[[nodiscard]] Digest profile_digest(const LinuxAttestationProfile& profile);

}  // namespace nexus::security
