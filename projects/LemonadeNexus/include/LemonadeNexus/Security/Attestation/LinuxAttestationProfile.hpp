#pragma once

// The compiled Tier 1 attestation profile. Not operator-configurable: a profile
// change requires an approved release.

#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>
#include <LemonadeNexus/Security/SnpVerify.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace nexus::security {

/// How the verifier learns the approved measurement policy is in force. No
/// value means "do not check": a kernel satisfying no method is unsupported.
enum class ImaPolicyProof : uint16_t {
    /// Prover forwards the kernel's own active-rule digest. Needs
    /// CONFIG_IMA_READ_POLICY.
    KernelReadback = 1,
};

[[nodiscard]] std::string_view ima_policy_proof_name(ImaPolicyProof proof);

/// One REQUIRED component: where it lives, and which releases of IT are
/// approved.
///
/// Every entry is mandatory, not selectable: a passing attestation proves, for
/// EVERY entry, that the path was measured and its LAST measurement is in the
/// entry's own digest set. A prover cannot satisfy the profile with a subset,
/// and an absent required component fails closed. See binary_approved.
///
/// The digests belong to the path, not to the profile. A global digest set
/// would let an approved release of one component satisfy the path reserved
/// for another. Binding them here makes that unrepresentable.
struct ApprovedPath {
    /// Absolute, as the kernel records it in the IMA log.
    std::string path;
    /// Hex SHA-256 of each approved release of this component. Empty approves
    /// nothing, which makes the profile incomplete.
    std::vector<std::string> sha256;
};

struct LinuxAttestationProfile {
    uint32_t profile_version{};

    SnpPolicyRequirements snp;

    /// Per-node enrollment state, not global policy: excluded from profile_gaps.
    std::string required_ak_spki_b64;

    /// Require IMA log replay and approved binary measurement.
    bool require_ima{true};

    /// The approved IMA policy. The digest is mandatory under every method.
    Digest ima_policy_digest{};
    ImaPolicyProof ima_policy_proof{ImaPolicyProof::KernelReadback};

    /// The required runtime components — every entry mandatory, see
    /// ApprovedPath. Bounded by kMaxSummarisedPaths so a checkpoint summary can
    /// be sized from the profile rather than from the log. A release pinning
    /// this list must include the audited executable dependencies (the shared
    /// objects the components map), not just the two Nexus executables.
    std::vector<ApprovedPath> approved_paths;

    /// The one component that obtains platform evidence — the quote binding
    /// covers ITS measurement. Must name an approved_paths entry exactly, and
    /// the evidence must identify itself with this path: the prover never
    /// chooses which approved component supplies the binding. Compiled, never
    /// configured.
    std::string evidence_collector_path;

    /// Approved boot state, one pinned hex value per quoted PCR. One of two
    /// boot-integrity inputs; snp.expected_measurement_hex is the other, and
    /// completeness requires both.
    std::vector<std::pair<uint32_t, std::string>> expected_pcrs;

    /// Explicit VMPL policy. Unset makes the profile incomplete.
    std::optional<VmplPolicy> vmpl_policy;

    bool require_no_new_privs{true};
    bool require_seccomp{true};

    /// Require current endorsement revocation data. Absent or expired data
    /// fails new attestation and never shrinks a live epoch.
    bool require_endorsement_revocation{true};

    SecurityRulesetVersion security_ruleset{};
};

/// A condition that makes the compiled profile incomplete or invalid.
enum class ProfileGap : uint16_t {
    ProfileVersionUnset,
    NoPinnedLaunchMeasurement,
    NoTcbFloor,
    ImaNotRequired,
    NoApprovedPaths,
    TooManyApprovedPaths,
    ApprovedPathNotAbsolute,
    DuplicateApprovedPath,
    NoApprovedBinary,
    NoEvidenceCollector,
    CollectorNotApproved,
    NoImaPolicyDigest,
    NoVmplPolicy,
    SecurityRulesetMismatch,
};

[[nodiscard]] std::string_view profile_gap_name(ProfileGap gap);

/// Every gap in `profile`, in declaration order. Empty means complete.
[[nodiscard]] std::vector<ProfileGap> profile_gaps(const LinuxAttestationProfile& profile);

[[nodiscard]] bool profile_is_complete(const LinuxAttestationProfile& profile);

/// Template for profile version 1: fixes the rules, pins no measured values, so
/// every candidate fails ProfileIncomplete until a release pins them from an
/// already-qualified host.
[[nodiscard]] LinuxAttestationProfile linux_attestation_profile_v1();

/// The attestation_policy_digest carried in every challenge. Every field is
/// encoded, so two profiles differing in effect differ in digest.
[[nodiscard]] Digest profile_digest(const LinuxAttestationProfile& profile);

}  // namespace nexus::security
