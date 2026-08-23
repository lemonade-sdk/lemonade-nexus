#include <LemonadeNexus/Security/Attestation/LinuxAttestationProfile.hpp>

#include <LemonadeNexus/Security/CanonicalEncoding.hpp>

#include <string_view>

namespace nexus::security {

namespace {

inline constexpr std::string_view kProfileDomain = "lemonade-nexus/attestation-profile:v1";

void add_bool(CanonicalEncoder& encoder, bool value) {
    encoder.add_u16(value ? 1 : 0);
}

}  // namespace

Digest profile_digest(const LinuxAttestationProfile& profile) {
    CanonicalEncoder encoder(kProfileDomain);
    encoder.add_u32(profile.profile_version);

    // SnpPolicyRequirements, field by field in declaration order. No struct
    // memory is hashed, so layout and padding cannot leak into the digest.
    add_bool(encoder, profile.snp.require_debug_disabled);
    add_bool(encoder, profile.snp.require_no_migration_agent);
    add_bool(encoder, profile.snp.require_vmpl0);
    encoder.add_u16(profile.snp.min_tcb.bootloader);
    encoder.add_u16(profile.snp.min_tcb.tee);
    encoder.add_u16(profile.snp.min_tcb.snp);
    encoder.add_u16(profile.snp.min_tcb.microcode);
    encoder.add_string(profile.snp.expected_measurement_hex);

    encoder.add_string(profile.required_ak_spki_b64);
    encoder.add_bytes(profile.ima_policy_digest);
    add_bool(encoder, profile.enforce_ima_policy);

    encoder.add_u64(profile.approved_binary_sha256.size());
    for (const auto& binary_sha256 : profile.approved_binary_sha256) {
        encoder.add_string(binary_sha256);
    }

    add_bool(encoder, profile.require_no_new_privs);
    add_bool(encoder, profile.require_seccomp);
    encoder.add_u16(profile.security_ruleset);
    return encoder.digest();
}

}  // namespace nexus::security
