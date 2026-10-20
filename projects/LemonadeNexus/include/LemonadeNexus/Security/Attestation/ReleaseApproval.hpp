#pragma once

// Release-global Tier-1 policy is authenticated outside the executable whose
// digest it approves. Genesis delegates one Ed25519 release authority, and
// that authority signs a canonical approval record. Neither object contains
// node enrollment state.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Attestation/LinuxAttestationProfile.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <filesystem>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace nexus::security {

inline constexpr uint32_t kReleaseAuthorityFormatVersion = 1;
/// Version 2: svsm_launch_measurements is a set, one entry per approved VM
/// shape. A version-1 verifier must refuse the new form, never half-read it.
inline constexpr uint32_t kReleaseApprovalFormatVersion = 2;
inline constexpr std::string_view kReleaseApprovalPath =
    "/usr/lib/lemonade-nexus/release/release-approval.json";

struct ReleaseAuthorityV1 {
    uint32_t format_version{kReleaseAuthorityFormatVersion};
    std::string network_id_hex;
    std::string release_signing_pubkey_b64;
    std::string genesis_signature_b64;
};

struct ReleaseKernelIdentityV1 {
    std::string release;
    std::string bzimage_sha256;
    std::string vmlinux_sha256;
    std::string module_tree_sha256;
    std::string module_certificate_der_sha256;
};

struct ReleaseApprovalV1 {
    uint32_t format_version{kReleaseApprovalFormatVersion};
    std::string release_id;
    std::string nexus_version;
    std::string source_commit;
    std::string starting_patched_tree;
    std::string final_patched_tree;
    std::string network_id_hex;

    uint16_t security_wire_version{};
    SecurityRulesetVersion security_ruleset{};
    ConsensusRulesetVersion consensus_ruleset{};
    std::string attestation_profile;
    uint16_t attestation_profile_ruleset{};
    uint16_t attestd_wire_version{};

    std::string ima_policy_id;
    std::string ima_policy_sha256;
    ReleaseKernelIdentityV1 kernel;
    /// Approved SVSM launch measurements, one per approved VM shape (the
    /// measurement is a function of launch inputs, vCPU topology included).
    /// Canonical form, enforced at verification: non-empty, each entry 96
    /// lowercase hex characters, sorted ascending, no duplicates. A live
    /// measurement passes only on an exact match with a member.
    std::vector<std::string> svsm_launch_measurements_hex;
    TcbVersion min_tcb{};
    std::vector<ApprovedPath> approved_paths;
    std::string evidence_collector_path;

    // Empty while qualification is pending. A qualified approval contains
    // exactly PCR 8 and PCR 9; PCR 10 remains verifier checkpoint state.
    std::vector<std::pair<uint32_t, std::string>> expected_pcrs;
    std::string qualification_state;

    std::string signer_pubkey_b64;
    std::string signature_b64;
};

struct ReleaseApprovalBundleV1 {
    ReleaseAuthorityV1 authority;
    ReleaseApprovalV1 approval;
};

[[nodiscard]] std::string canonical_release_authority_json(
    const ReleaseAuthorityV1& authority);
[[nodiscard]] std::string canonical_release_approval_json(
    const ReleaseApprovalV1& approval);
/// SHA-256 of the canonical approval form: the value the bootstrap
/// certificate commits as release_approval_digest.
[[nodiscard]] Digest release_approval_digest(const ReleaseApprovalV1& approval);
[[nodiscard]] std::string release_approval_digest_hex(
    const ReleaseApprovalV1& approval);

/// The compiled release line as an approval skeleton; observation fields stay
/// empty for the generator to fill, so template and verifier cannot drift.
[[nodiscard]] ReleaseApprovalV1 release_approval_template();

// Verifies Genesis delegation first, then the release signature, then every
// compiled protocol/release invariant. Hashes are not exposed to callers until
// all three checks succeed.
[[nodiscard]] bool verify_release_approval_bundle(
    const ReleaseApprovalBundleV1& bundle,
    const crypto::Ed25519PublicKey& genesis_public_key,
    const NetworkId& expected_network_id,
    std::string& error);

[[nodiscard]] std::optional<ReleaseApprovalBundleV1> parse_release_approval_bundle(
    std::string_view json_text, std::string& error);

[[nodiscard]] std::optional<ReleaseApprovalBundleV1> load_release_approval_bundle(
    const std::filesystem::path& path,
    const crypto::Ed25519PublicKey& genesis_public_key,
    const NetworkId& expected_network_id,
    std::string& error);

// Converts only an already verified approval. Pending PCR8/PCR9 deliberately
// leave the profile incomplete, keeping production Tier-1 admission disabled.
[[nodiscard]] LinuxAttestationProfile profile_from_release_approval(
    const ReleaseApprovalV1& approval);

}  // namespace nexus::security
