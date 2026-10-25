#pragma once

// The r21 boot line (release/fleet-profile.json) for tests that build release
// approvals. Since Design-Auto-Update Phase 0.3 the template carries no boot
// line: the generator takes it from the fleet profile, and the verifier checks
// only its form.

#include <LemonadeNexus/Security/Attestation/ReleaseApproval.hpp>
#include <LemonadeNexus/Security/Attestation/ReleaseBundleGenerator.hpp>

#include <string>
#include <vector>

namespace nexus_test {

inline nexus::security::ReleaseKernelIdentityV1 reference_kernel() {
    return {"7.1.0-coconut-svsm-tier1+",
            "d9854417fea45a490b632b0e7860827b34443f94da0877e34a0633bbb5078584",
            "dfb88d060ef4fca3b51ce87b95803ad6b64addaad840d4aecb63bc85e9bcd552",
            "8735b602a2e2b86dcc5bd06426e345a09f9c279ceaeb989acd6db0b11279a2be",
            "a43447d3a1658efc13eb1349f1d14e9727630280e5449c5c5459885f9eb88de5"};
}

inline std::vector<std::string> reference_svsm_measurements() {
    return {"2f073e15d2501910b6208ca52a349d16247d443f326cee2b46292d608821"
            "c6e84c2490814e22a2b5ba860a37208d1d9a",
            "bca89f077c4d647b08ce1fb83cfa92ff12789815378baa0de00ca883e40e"
            "79313e3df3f88b9798a7eb53ab1b3ff59a54"};
}

inline constexpr const char* kReferenceSourceCommit = "dd80e7f99d104e6be71ee9c30e32d39ea911bec8";
inline constexpr const char* kReferenceStartingTree = "148bcf279cd18a7c46295fcd76db022ed5451422";
inline constexpr const char* kReferenceImaPolicyId = "nexus-tier1-ima-v1";
inline constexpr const char* kReferenceImaPolicy =
    "b3cabc30317af8b7127a175d7b4f906a40203e7ebe28122d82a713e03dad4092";

/// Fills the boot line of an approval built from release_approval_template().
inline void fill_reference_boot_line(nexus::security::ReleaseApprovalV1& a) {
    a.source_commit = kReferenceSourceCommit;
    a.starting_patched_tree = kReferenceStartingTree;
    a.ima_policy_id = kReferenceImaPolicyId;
    a.ima_policy_sha256 = kReferenceImaPolicy;
    a.kernel = reference_kernel();
    a.svsm_launch_measurements_hex = reference_svsm_measurements();
}

/// Fills the boot line of a generator spec.
inline void fill_reference_boot_line(nexus::security::ReleaseBundleSpec& spec) {
    spec.source_commit = kReferenceSourceCommit;
    spec.starting_patched_tree = kReferenceStartingTree;
    spec.ima_policy_id = kReferenceImaPolicyId;
    spec.ima_policy_sha256 = kReferenceImaPolicy;
    spec.kernel = reference_kernel();
    spec.svsm_launch_measurements = reference_svsm_measurements();
}

}  // namespace nexus_test
