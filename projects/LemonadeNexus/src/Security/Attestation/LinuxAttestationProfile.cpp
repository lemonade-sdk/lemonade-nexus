#include <LemonadeNexus/Security/Attestation/LinuxAttestationProfile.hpp>

#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <string_view>

namespace nexus::security {

namespace {

inline constexpr std::string_view kProfileDomain = "lemonade-nexus/attestation-profile:v1";

void add_bool(CanonicalEncoder& encoder, bool value) {
    encoder.add_u16(value ? 1 : 0);
}

}  // namespace

std::string_view profile_gap_name(ProfileGap gap) {
    switch (gap) {
        case ProfileGap::ProfileVersionUnset:      return "profile_version is 0";
        case ProfileGap::NoPinnedLaunchMeasurement:
            return "no launch measurement pinned: any SNP guest image would pass";
        case ProfileGap::NoTcbFloor:
            return "no TCB floor: firmware with known issues would pass";
        case ProfileGap::NoApprovedBinary:
            return "no approved binary digest: no release can ever be approved";
        case ProfileGap::NoImaPolicyDigest:
            return "IMA enforcement is on but no policy digest is pinned";
        case ProfileGap::SecurityRulesetMismatch:
            return "profile security_ruleset is not the compiled ruleset";
    }
    return "unknown gap";
}

std::vector<ProfileGap> profile_gaps(const LinuxAttestationProfile& profile) {
    std::vector<ProfileGap> gaps;
    if (profile.profile_version == 0) {
        gaps.push_back(ProfileGap::ProfileVersionUnset);
    }
    if (profile.snp.expected_measurement_hex.empty()) {
        gaps.push_back(ProfileGap::NoPinnedLaunchMeasurement);
    }
    // An all-zero floor accepts every firmware level, which is the same as
    // having no floor at all.
    if (profile.snp.min_tcb.bootloader == 0 && profile.snp.min_tcb.tee == 0 &&
        profile.snp.min_tcb.snp == 0 && profile.snp.min_tcb.microcode == 0) {
        gaps.push_back(ProfileGap::NoTcbFloor);
    }
    if (profile.approved_binary_sha256.empty()) {
        gaps.push_back(ProfileGap::NoApprovedBinary);
    }
    if (profile.enforce_ima_policy && profile.ima_policy_digest == Digest{}) {
        gaps.push_back(ProfileGap::NoImaPolicyDigest);
    }
    if (profile.security_ruleset != constants::kSecurityRulesetVersion) {
        gaps.push_back(ProfileGap::SecurityRulesetMismatch);
    }
    return gaps;
}

bool profile_is_complete(const LinuxAttestationProfile& profile) {
    return profile_gaps(profile).empty();
}

LinuxAttestationProfile linux_attestation_profile_v1() {
    LinuxAttestationProfile profile;
    profile.profile_version = 1;

    // The SEV-SNP bar. These are rules, not observations, so they are pinned
    // here and never read from a host.
    profile.snp.require_debug_disabled = true;
    profile.snp.require_no_migration_agent = true;
    profile.snp.require_vmpl0 = true;

    profile.enforce_ima_policy = true;
    profile.require_no_new_privs = true;
    profile.require_seccomp = true;
    profile.security_ruleset = constants::kSecurityRulesetVersion;

    // snp.min_tcb, snp.expected_measurement_hex, ima_policy_digest and
    // approved_binary_sha256 stay unset on purpose. See the header.
    return profile;
}

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

    encoder.add_u64(profile.expected_pcrs.size());
    for (const auto& [index, value_hex] : profile.expected_pcrs) {
        encoder.add_u32(index);
        encoder.add_string(value_hex);
    }

    add_bool(encoder, profile.require_no_new_privs);
    add_bool(encoder, profile.require_seccomp);
    encoder.add_u16(profile.security_ruleset);
    return encoder.digest();
}

}  // namespace nexus::security
