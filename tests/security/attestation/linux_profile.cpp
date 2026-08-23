#include <LemonadeNexus/Security/Attestation/LinuxAttestationProfile.hpp>

#include <gtest/gtest.h>

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
    profile.snp.require_vmpl0 = true;
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
    {"snp.require_vmpl0", [](LinuxAttestationProfile& p) { p.snp.require_vmpl0 = false; }},
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

}  // namespace
