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
#include <string_view>
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

/// A prerequisite the profile leaves unpinned. A profile carrying any gap
/// cannot tell a good platform from a bad one, so the verifier refuses every
/// candidate rather than accepting on silence.
enum class ProfileGap : uint16_t {
    ProfileVersionUnset,
    NoPinnedLaunchMeasurement,
    NoTcbFloor,
    NoApprovedBinary,
    NoImaPolicyDigest,
    SecurityRulesetMismatch,
};

[[nodiscard]] std::string_view profile_gap_name(ProfileGap gap);

/// Every gap in `profile`, in declaration order. Empty means complete.
/// `required_ak_spki_b64` is deliberately absent: an attestation key is pinned
/// per enrolled node, not once for the whole mesh.
[[nodiscard]] std::vector<ProfileGap> profile_gaps(const LinuxAttestationProfile& profile);

/// True when the profile pins everything it needs to decide.
[[nodiscard]] bool profile_is_complete(const LinuxAttestationProfile& profile);

/// The shape of Linux attestation profile version 1.
///
/// The returned profile is deliberately INCOMPLETE: it fixes the rules but pins
/// no measurement, no TCB floor, no IMA policy digest and no approved binary,
/// because those values may only be read from a host that already satisfies the
/// rules. Until such a host exists, every candidate fails with ProfileIncomplete.
/// That is the intended behavior. Filling these in from an unqualified host
/// would pin the wrong values and make the profile decide nothing.
[[nodiscard]] LinuxAttestationProfile linux_attestation_profile_v1();

/// The attestation_policy_digest carried in every challenge. Every field is
/// encoded, so two profiles that differ in effect differ in digest.
[[nodiscard]] Digest profile_digest(const LinuxAttestationProfile& profile);

}  // namespace nexus::security
