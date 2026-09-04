#include <LemonadeNexus/Security/Attestation/LinuxAttestationProfile.hpp>

#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <algorithm>
#include <filesystem>
#include <string>
#include <string_view>
#include <unordered_set>

namespace nexus::security {

namespace {

inline constexpr std::string_view kProfileDomain = "lemonade-nexus/attestation-profile:v1";

void add_bool(CanonicalEncoder& encoder, bool value) {
    encoder.add_u16(value ? 1 : 0);
}

/// The form two approved paths are compared in. "/usr/bin/./nexus" and
/// "/usr/bin/nexus" name one component, so they are one duplicate.
std::string canonical_path(const std::string& path) {
    return std::filesystem::path(path).lexically_normal().generic_string();
}

}  // namespace

std::string_view ima_policy_proof_name(ImaPolicyProof proof) {
    switch (proof) {
        case ImaPolicyProof::KernelReadback: return "kernel-readback";
    }
    return "unknown";
}

std::string_view profile_gap_name(ProfileGap gap) {
    switch (gap) {
        case ProfileGap::ProfileVersionUnset:      return "profile_version is 0";
        case ProfileGap::NoPinnedLaunchMeasurement:
            return "no launch measurement pinned: any SNP guest image would pass";
        case ProfileGap::NoTcbFloor:
            return "no TCB floor: firmware with known issues would pass";
        case ProfileGap::NoApprovedPaths:
            return "no approved paths: no measured component can ever be looked up";
        case ProfileGap::TooManyApprovedPaths:
            return "more approved paths than kMaxSummarisedPaths";
        case ProfileGap::ApprovedPathNotAbsolute:
            return "an approved path is not absolute, so it names no file the kernel measures";
        case ProfileGap::DuplicateApprovedPath:
            return "two approved paths name the same component under different digest sets";
        case ProfileGap::NoApprovedBinary:
            return "an approved path lists no release digest, so it can never be satisfied";
        case ProfileGap::NoImaPolicyDigest:
            return "no IMA policy digest pinned: the measuring policy is unproven";
        case ProfileGap::ImaNotRequired:
            return "the IMA log is not required, so no binary can be measured";
        case ProfileGap::NoVmplPolicy:
            return "no VMPL policy chosen: which level may request a report is undecided";
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
    if (profile.approved_paths.empty()) {
        gaps.push_back(ProfileGap::NoApprovedPaths);
    }
    if (profile.approved_paths.size() > constants::kMaxSummarisedPaths) {
        gaps.push_back(ProfileGap::TooManyApprovedPaths);
    }
    if (std::any_of(profile.approved_paths.begin(), profile.approved_paths.end(),
                    [](const ApprovedPath& p) {
                        return p.path.empty() || !std::filesystem::path(p.path).is_absolute();
                    })) {
        gaps.push_back(ProfileGap::ApprovedPathNotAbsolute);
    }
    {
        std::unordered_set<std::string> seen;
        for (const auto& approved : profile.approved_paths) {
            if (!seen.insert(canonical_path(approved.path)).second) {
                gaps.push_back(ProfileGap::DuplicateApprovedPath);
                break;
            }
        }
    }
    // A path with no digests approves nothing, which is the old NoApprovedBinary
    // failure moved to where the digests now live.
    if (std::any_of(profile.approved_paths.begin(), profile.approved_paths.end(),
                    [](const ApprovedPath& p) {
                        return p.sha256.empty() ||
                               std::any_of(p.sha256.begin(), p.sha256.end(),
                                           [](const std::string& h) { return h.empty(); });
                    })) {
        gaps.push_back(ProfileGap::NoApprovedBinary);
    }
    // The IMA log is where binary integrity comes from; a profile that does not
    // demand it cannot prove runtime integrity under any policy proof.
    if (!profile.require_ima) {
        gaps.push_back(ProfileGap::ImaNotRequired);
    }
    // Unconditional: no proof method may proceed without a pinned digest.
    if (profile.ima_policy_digest == Digest{}) {
        gaps.push_back(ProfileGap::NoImaPolicyDigest);
    }
    if (!profile.vmpl_policy.has_value()) {
        gaps.push_back(ProfileGap::NoVmplPolicy);
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
    // The HCL/paravisor shape: the paravisor owns VMPL0 and requests the
    // report. A different provider chooses a different level.
    profile.vmpl_policy = VmplPolicy::RequireVmpl0;

    profile.require_ima = true;
    profile.ima_policy_proof = ImaPolicyProof::KernelReadback;
    profile.require_no_new_privs = true;
    profile.require_seccomp = true;
    profile.security_ruleset = constants::kSecurityRulesetVersion;

    // snp.min_tcb, snp.expected_measurement_hex, ima_policy_digest and
    // approved_paths stay unset on purpose. See the header.
    return profile;
}

Digest profile_digest(const LinuxAttestationProfile& profile) {
    CanonicalEncoder encoder(kProfileDomain);
    encoder.add_u32(profile.profile_version);

    // SnpPolicyRequirements, field by field in declaration order. No struct
    // memory is hashed, so layout and padding cannot leak into the digest.
    add_bool(encoder, profile.snp.require_debug_disabled);
    add_bool(encoder, profile.snp.require_no_migration_agent);
    // Encoded as "chosen or not" plus the choice, so a profile that never
    // chose cannot share a digest with one that chose Unconstrained.
    add_bool(encoder, profile.vmpl_policy.has_value());
    encoder.add_u16(static_cast<uint16_t>(
        profile.vmpl_policy.value_or(VmplPolicy::Unconstrained)));
    encoder.add_u16(profile.snp.min_tcb.bootloader);
    encoder.add_u16(profile.snp.min_tcb.tee);
    encoder.add_u16(profile.snp.min_tcb.snp);
    encoder.add_u16(profile.snp.min_tcb.microcode);
    encoder.add_string(profile.snp.expected_measurement_hex);

    encoder.add_string(profile.required_ak_spki_b64);
    encoder.add_bytes(profile.ima_policy_digest);
    encoder.add_u16(static_cast<uint16_t>(profile.ima_policy_proof));
    add_bool(encoder, profile.require_ima);

    // Path and digests together, in declaration order. Moving a digest between
    // paths changes the digest, because which component a release approves is
    // itself the policy.
    encoder.add_u64(profile.approved_paths.size());
    for (const auto& approved : profile.approved_paths) {
        encoder.add_string(approved.path);
        encoder.add_u64(approved.sha256.size());
        for (const auto& binary_sha256 : approved.sha256) {
            encoder.add_string(binary_sha256);
        }
    }

    encoder.add_u64(profile.expected_pcrs.size());
    for (const auto& [index, value_hex] : profile.expected_pcrs) {
        encoder.add_u32(index);
        encoder.add_string(value_hex);
    }

    add_bool(encoder, profile.require_no_new_privs);
    add_bool(encoder, profile.require_seccomp);
    add_bool(encoder, profile.require_endorsement_revocation);
    encoder.add_u16(profile.security_ruleset);
    return encoder.digest();
}

}  // namespace nexus::security
