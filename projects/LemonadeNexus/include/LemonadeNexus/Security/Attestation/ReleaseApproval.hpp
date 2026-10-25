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
inline constexpr uint32_t kReleaseApprovalFormatV2 = 2;
/// Version 3: the approval carries a monotonic release_number and the
/// previous release's executable hashes (previous_release_paths), so a newer
/// approval can supersede an older one in place (Design-Auto-Update Phase 2).
/// A version-2 verifier refuses this form.
inline constexpr uint32_t kReleaseApprovalFormatVersion = 3;
/// Upper bound of a release number: the tag date as YYYYMMDD times 100 plus
/// the release of that day (vYYYY.MM.DD.N).
inline constexpr uint64_t kMaxReleaseNumber = 9999123199ULL;
/// The compiled TCB floor (AMD-SB-3030 bootloader, AMD-SB-3034 SNP firmware).
/// An approval may raise it, never lower it. It is one of the compiled floors
/// the design keeps; the other floors are the protocol identity (wire and
/// ruleset versions, attestation profile, attestd wire version), which name
/// what this binary itself implements.
inline constexpr TcbVersion kReleaseMinTcb{0x0c, 0x00, 0x1c, 0x00};
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
    /// Format 3: the monotonic release number (YYYYMMDD * 100 + N). A server
    /// accepts a newer approval only with a strictly greater number than every
    /// approval it accepted before. Zero in a format-2 approval.
    uint64_t release_number{};

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
    /// The hashes of THIS release, one entry per required path. A witness
    /// treats a server as running this release only when every measured hash
    /// is listed here.
    std::vector<ApprovedPath> approved_paths;
    /// Format 3: the previous release's hashes for the same paths. Attestation
    /// also accepts these, so servers on release N and N+1 attest each other
    /// during a rollout. Every path must also appear in approved_paths. Empty
    /// approves no previous release.
    std::vector<ApprovedPath> previous_release_paths;
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

/// The compiled protocol identity as an approval skeleton: wire and ruleset
/// versions, the attestation profile, the TCB floor, and the collector path.
/// The boot line (source identity, kernel, IMA policy, SVSM launch
/// measurements) and every observation stay empty; the generator fills them
/// from release/fleet-profile.json (Design-Auto-Update Phase 0.3).
[[nodiscard]] ReleaseApprovalV1 release_approval_template();

/// The complete signed bundle as JSON, in the form parse_release_approval_bundle
/// reads. Used to persist and forward an accepted approval byte-exactly in
/// meaning (the signatures cover the canonical preimages, not this layout).
[[nodiscard]] std::string release_approval_bundle_json(const ReleaseApprovalBundleV1& bundle);

/// Checks only the Genesis delegation, the network, the signer binding, and
/// the release signature, for format 2 or 3. It does NOT check the compiled
/// release line. Use it only to identify the release signer of an approval
/// whose digest a Genesis-signed bootstrap certificate already commits (the
/// founding approval); never to accept an approval for attestation.
[[nodiscard]] bool verify_release_approval_signatures(
    const ReleaseApprovalBundleV1& bundle,
    const crypto::Ed25519PublicKey& genesis_public_key,
    const NetworkId& expected_network_id,
    std::string& error);

// Verifies Genesis delegation first, then the release signature, then the
// compiled protocol identity and TCB floor, then the form of every release
// field. The boot line (kernel, IMA policy, SVSM launch measurements) is
// verified against the signed approval only: it is release data, so a newer
// approval may change it. Callers that adopt an approval must also apply the
// signer pin and the release-number rule (ReleaseChain). Hashes are not
// exposed to callers until every check succeeds. Requires format 3.
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
// The SVSM launch measurements, TCB floor, IMA policy, and kernel identity come
// from the approval.
// Each approved path accepts the hashes of this release and of the previous
// release (previous_release_paths).
[[nodiscard]] LinuxAttestationProfile profile_from_release_approval(
    const ReleaseApprovalV1& approval);

}  // namespace nexus::security
