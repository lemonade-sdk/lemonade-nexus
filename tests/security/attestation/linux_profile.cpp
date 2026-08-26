#include <LemonadeNexus/Security/Attestation/LinuxAttestationProfile.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <functional>
#include <utility>

using nexus::security::Digest;
using nexus::security::LinuxAttestationProfile;
using nexus::security::profile_digest;

namespace {

Digest patterned_digest(uint8_t seed) {
    Digest out{};
    for (std::size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<uint8_t>(seed + i);
    }
    return out;
}

LinuxAttestationProfile base_profile() {
    LinuxAttestationProfile profile;
    profile.profile_version = 1;
    profile.snp.require_debug_disabled = true;
    profile.snp.require_no_migration_agent = true;
    profile.snp.vmpl_policy = nexus::security::VmplPolicy::RequireVmpl0;
    profile.snp.min_tcb = {2, 0, 6, 55};
    profile.snp.expected_measurement_hex = "aa11";
    profile.required_ak_spki_b64 = "QUsx";
    profile.ima_policy_digest = patterned_digest(0x60);
    profile.enforce_ima_policy = true;
    profile.approved_binary_sha256 = {"01ab", "02cd"};
    profile.require_no_new_privs = true;
    profile.require_seccomp = true;
    profile.security_ruleset = 1;
    return profile;
}

struct ProfileMutation {
    const char* name;
    std::function<void(LinuxAttestationProfile&)> apply;
};

const ProfileMutation kProfileMutations[] = {
    {"profile_version", [](LinuxAttestationProfile& p) { p.profile_version += 1; }},
    {"snp.require_debug_disabled",
     [](LinuxAttestationProfile& p) { p.snp.require_debug_disabled = false; }},
    {"snp.require_no_migration_agent",
     [](LinuxAttestationProfile& p) { p.snp.require_no_migration_agent = false; }},
    {"snp.vmpl_policy", [](LinuxAttestationProfile& p) {
         p.snp.vmpl_policy = nexus::security::VmplPolicy::RequireAboveVmpl0; }},
    {"snp.min_tcb.bootloader", [](LinuxAttestationProfile& p) { p.snp.min_tcb.bootloader += 1; }},
    {"snp.min_tcb.tee", [](LinuxAttestationProfile& p) { p.snp.min_tcb.tee += 1; }},
    {"snp.min_tcb.snp", [](LinuxAttestationProfile& p) { p.snp.min_tcb.snp += 1; }},
    {"snp.min_tcb.microcode", [](LinuxAttestationProfile& p) { p.snp.min_tcb.microcode += 1; }},
    {"snp.expected_measurement_hex",
     [](LinuxAttestationProfile& p) { p.snp.expected_measurement_hex = "bb22"; }},
    {"required_ak_spki_b64", [](LinuxAttestationProfile& p) { p.required_ak_spki_b64 = "QUsy"; }},
    {"ima_policy_digest", [](LinuxAttestationProfile& p) { p.ima_policy_digest[0] ^= 1; }},
    {"enforce_ima_policy", [](LinuxAttestationProfile& p) { p.enforce_ima_policy = false; }},
    {"approved list entry", [](LinuxAttestationProfile& p) { p.approved_binary_sha256[0] = "03ef"; }},
    {"approved list extra entry",
     [](LinuxAttestationProfile& p) { p.approved_binary_sha256.push_back("03ef"); }},
    {"approved list order",
     [](LinuxAttestationProfile& p) {
         std::swap(p.approved_binary_sha256[0], p.approved_binary_sha256[1]);
     }},
    {"require_no_new_privs", [](LinuxAttestationProfile& p) { p.require_no_new_privs = false; }},
    {"require_seccomp", [](LinuxAttestationProfile& p) { p.require_seccomp = false; }},
    {"security_ruleset", [](LinuxAttestationProfile& p) { p.security_ruleset += 1; }},
};

TEST(LinuxAttestationProfile, DigestIsDeterministic) {
    EXPECT_EQ(profile_digest(base_profile()), profile_digest(base_profile()));
}

TEST(LinuxAttestationProfile, EveryFieldChangesDigest) {
    const Digest base = profile_digest(base_profile());
    for (const auto& mutation : kProfileMutations) {
        LinuxAttestationProfile mutated = base_profile();
        mutation.apply(mutated);
        EXPECT_NE(profile_digest(mutated), base) << mutation.name;
    }
}

TEST(LinuxAttestationProfile, EveryBooleanFlipChangesDigest) {
    bool LinuxAttestationProfile::* fields[] = {
        &LinuxAttestationProfile::enforce_ima_policy,
        &LinuxAttestationProfile::require_no_new_privs,
        &LinuxAttestationProfile::require_seccomp,
    };
    const Digest base = profile_digest(base_profile());
    for (auto field : fields) {
        LinuxAttestationProfile mutated = base_profile();
        mutated.*field = !(mutated.*field);
        EXPECT_NE(profile_digest(mutated), base);
    }
}

TEST(LinuxAttestationProfile, EmptyApprovedListIsEncodedNotSkipped) {
    LinuxAttestationProfile empty_list = base_profile();
    empty_list.approved_binary_sha256 = {};

    LinuxAttestationProfile one_empty_entry = base_profile();
    one_empty_entry.approved_binary_sha256 = {""};

    // The element count is encoded, so zero entries and one empty entry differ.
    EXPECT_NE(profile_digest(empty_list), profile_digest(one_empty_entry));
}

TEST(LinuxAttestationProfile, ListBoundariesCannotShift) {
    LinuxAttestationProfile split = base_profile();
    split.approved_binary_sha256 = {"ab", "cd"};

    LinuxAttestationProfile joined = base_profile();
    joined.approved_binary_sha256 = {"abcd"};

    EXPECT_NE(profile_digest(split), profile_digest(joined));
}

// --- Completeness -------------------------------------------------------------
//
// A profile that leaves a prerequisite unpinned cannot tell a good platform
// from a bad one. Completeness is therefore a property the verifier checks
// before anything else, and these tests pin which gaps it must notice.

using nexus::security::ProfileGap;
using nexus::security::profile_gaps;
using nexus::security::profile_is_complete;
using nexus::security::linux_attestation_profile_v1;

namespace {

/// base_profile() carries a stale ruleset; the completeness rule compares
/// against the compiled one, so align it here.
LinuxAttestationProfile complete_profile() {
    LinuxAttestationProfile profile = base_profile();
    profile.security_ruleset = nexus::security::constants::kSecurityRulesetVersion;
    return profile;
}

bool has_gap(const LinuxAttestationProfile& profile, ProfileGap gap) {
    const auto gaps = profile_gaps(profile);
    return std::find(gaps.begin(), gaps.end(), gap) != gaps.end();
}

}  // namespace

TEST(LinuxAttestationProfileCompleteness, AFullyPinnedProfileIsComplete) {
    EXPECT_TRUE(profile_is_complete(complete_profile()));
    EXPECT_TRUE(profile_gaps(complete_profile()).empty());
}

TEST(LinuxAttestationProfileCompleteness, ADefaultProfileIsIncomplete) {
    // The default-constructed profile pins nothing. It must never read as usable.
    EXPECT_FALSE(profile_is_complete(LinuxAttestationProfile{}));
}

// The shipped v1 profile fixes the rules but pins no observed values, because
// no qualifying host has supplied them yet. It must fail closed, by design.
TEST(LinuxAttestationProfileCompleteness, ShippedV1IsDeliberatelyIncomplete) {
    const auto v1 = linux_attestation_profile_v1();
    EXPECT_EQ(v1.profile_version, 1u);
    EXPECT_EQ(v1.security_ruleset, nexus::security::constants::kSecurityRulesetVersion);
    EXPECT_TRUE(v1.snp.require_debug_disabled);
    EXPECT_TRUE(v1.snp.require_no_migration_agent);
    // The HCL/paravisor shape. Not a global rule: an SVSM profile pins
    // RequireAboveVmpl0 instead, because there the guest is not the most
    // privileged component.
    EXPECT_EQ(v1.snp.vmpl_policy, nexus::security::VmplPolicy::RequireVmpl0);

    EXPECT_FALSE(profile_is_complete(v1));
    EXPECT_TRUE(has_gap(v1, ProfileGap::NoPinnedLaunchMeasurement));
    EXPECT_TRUE(has_gap(v1, ProfileGap::NoTcbFloor));
    EXPECT_TRUE(has_gap(v1, ProfileGap::NoApprovedBinary));
    EXPECT_TRUE(has_gap(v1, ProfileGap::NoImaPolicyDigest));
    // The rules it DOES fix are already right, so these are not gaps.
    EXPECT_FALSE(has_gap(v1, ProfileGap::ProfileVersionUnset));
    EXPECT_FALSE(has_gap(v1, ProfileGap::SecurityRulesetMismatch));
}

TEST(LinuxAttestationProfileCompleteness, EachUnpinnedPrerequisiteIsItsOwnGap) {
    {   // No launch measurement: any SNP guest image would pass.
        auto p = complete_profile();
        p.snp.expected_measurement_hex.clear();
        EXPECT_FALSE(profile_is_complete(p));
        EXPECT_TRUE(has_gap(p, ProfileGap::NoPinnedLaunchMeasurement));
    }
    {   // An all-zero TCB floor accepts every firmware level, so it is no floor.
        auto p = complete_profile();
        p.snp.min_tcb = {};
        EXPECT_FALSE(profile_is_complete(p));
        EXPECT_TRUE(has_gap(p, ProfileGap::NoTcbFloor));
    }
    {   // One non-zero component is still a floor.
        auto p = complete_profile();
        p.snp.min_tcb = {0, 0, 0, 1};
        EXPECT_FALSE(has_gap(p, ProfileGap::NoTcbFloor));
    }
    {
        auto p = complete_profile();
        p.approved_binary_sha256.clear();
        EXPECT_FALSE(profile_is_complete(p));
        EXPECT_TRUE(has_gap(p, ProfileGap::NoApprovedBinary));
    }
    {
        auto p = complete_profile();
        p.profile_version = 0;
        EXPECT_FALSE(profile_is_complete(p));
        EXPECT_TRUE(has_gap(p, ProfileGap::ProfileVersionUnset));
    }
    {
        auto p = complete_profile();
        p.security_ruleset = nexus::security::constants::kSecurityRulesetVersion + 1;
        EXPECT_FALSE(profile_is_complete(p));
        EXPECT_TRUE(has_gap(p, ProfileGap::SecurityRulesetMismatch));
    }
}

// The IMA policy digest is required only while IMA enforcement is on. Turning
// enforcement off removes the gap, and that is a weaker profile — not an
// incomplete one — so the distinction has to stay visible.
TEST(LinuxAttestationProfileCompleteness, ImaPolicyDigestTracksEnforcement) {
    auto p = complete_profile();
    p.ima_policy_digest = Digest{};
    p.enforce_ima_policy = true;
    EXPECT_TRUE(has_gap(p, ProfileGap::NoImaPolicyDigest));

    p.enforce_ima_policy = false;
    EXPECT_FALSE(has_gap(p, ProfileGap::NoImaPolicyDigest));
}

TEST(LinuxAttestationProfileCompleteness, EveryGapNamesItself) {
    for (const auto gap : {ProfileGap::ProfileVersionUnset,
                           ProfileGap::NoPinnedLaunchMeasurement,
                           ProfileGap::NoTcbFloor,
                           ProfileGap::NoApprovedBinary,
                           ProfileGap::NoImaPolicyDigest,
                           ProfileGap::SecurityRulesetMismatch}) {
        EXPECT_FALSE(nexus::security::profile_gap_name(gap).empty());
        EXPECT_NE(nexus::security::profile_gap_name(gap), "unknown gap");
    }
}

// An attestation key is pinned per enrolled node, not once for the mesh, so its
// absence must NOT make the profile incomplete.
TEST(LinuxAttestationProfileCompleteness, PinnedAkIsNotAProfilePrerequisite) {
    auto p = complete_profile();
    p.required_ak_spki_b64.clear();
    EXPECT_TRUE(profile_is_complete(p));
}

}  // namespace
