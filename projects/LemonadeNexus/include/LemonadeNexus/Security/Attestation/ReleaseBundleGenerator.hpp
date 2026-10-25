#pragma once

// Build-time generation of the unsigned release-approval bundle. Digests come
// from the actual artifact bytes; the protocol identity comes from the
// compiled template (release_approval_template); the boot line (source
// identity, kernel, IMA policy, SVSM launch measurements) comes from the
// reviewed release/fleet-profile.json through the spec. No signing happens
// here: the output is the data a separately authorized signing ceremony
// completes.

#include <LemonadeNexus/Security/Attestation/ReleaseApproval.hpp>

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace nexus::security {

struct ReleaseArtifact {
    /// Installed path, exactly as the kernel records it in the IMA log.
    std::string installed_path;
    /// Local file whose bytes are hashed. Missing or unreadable fails closed.
    /// Empty when `sha256` gives the digests instead.
    std::filesystem::path file;
    /// Reviewed digests (64 lowercase hex) for a file the build does not
    /// produce, such as a fleet system library from release/fleet-profile.json.
    /// Used only when `file` is empty.
    std::vector<std::string> sha256;
};

struct ReleaseBundleSpec {
    std::string release_id;
    std::string nexus_version;
    /// Monotonic release number (YYYYMMDD * 100 + N); 1..kMaxReleaseNumber.
    uint64_t release_number = 0;
    /// The previous release's hashes for the same paths. Every path must also
    /// be an artifact path. Leave empty when `previous` is set.
    std::vector<ApprovedPath> previous_release_paths;
    /// Git tree hash of the exact built source; computed by the caller
    /// (`git rev-parse 'HEAD^{tree}'`), never hand-typed.
    std::string final_patched_tree;
    std::string network_id_hex;
    /// Public half of the delegated release-signing key.
    std::string signer_pubkey_b64;
    /// PENDING_LIVE_QUALIFICATION (no PCRs) or LIVE_BOOT_APPROVED (exactly
    /// PCR8 and PCR9).
    std::string qualification_state;
    std::vector<std::pair<uint32_t, std::string>> expected_pcrs;
    /// The boot line (Design-Auto-Update Phase 0.3), from
    /// release/fleet-profile.json. Required.
    std::string source_commit;
    std::string starting_patched_tree;
    std::string ima_policy_id;
    std::string ima_policy_sha256;
    ReleaseKernelIdentityV1 kernel;
    /// Approved SVSM launch measurements, one per approved VM shape, each 96
    /// lowercase hex. Required. The generator sorts them; duplicates fail
    /// closed.
    std::vector<std::string> svsm_launch_measurements;
    /// Both required executables plus the audited dependency closure.
    std::vector<ReleaseArtifact> artifacts;
    /// The previous release's approval, for the one-release overlap window
    /// (design Phase 2). Its signature must verify under signer_pubkey_b64 for
    /// this network. Its approved_paths become previous_release_paths for
    /// every path the new release still lists; a path the new release drops
    /// is not carried over. approved_paths keeps only this release's hashes.
    std::optional<ReleaseApprovalV1> previous;
    /// The rollout of `previous` halted (a finalized Halt record). Servers
    /// then run either the halted release or the release before it, so
    /// previous_release_paths carries both (release_overlap_paths). The
    /// release workflow sets this only from a verified rollout proof, and
    /// nexus-rollout-check refuses an approval whose overlap does not match
    /// the proven rollout state. Requires `previous`.
    bool previous_halted = false;
};

/// The previous_release_paths that follow `previous`, one entry per path of
/// previous.approved_paths. After a completed rollout: that release's own
/// hashes. After a halted rollout: its own hashes, then the hashes of its
/// previous_release_paths for the same path (the release before it),
/// without duplicates. The caller drops paths the new release does not list.
[[nodiscard]] std::vector<ApprovedPath> release_overlap_paths(const ReleaseApprovalV1& previous,
                                                              bool previous_halted);

/// Fills the compiled template with digests of the actual files. Fail-closed:
/// any invalid spec yields nullopt and a reason in `error`.
///
/// approved_paths lists only this release's digests, the built one first.
/// nexus-release-tool relies on the first entry being the newest build.
[[nodiscard]] std::optional<ReleaseApprovalV1> generate_release_approval(
    const ReleaseBundleSpec& spec, std::string& error);

/// The unsigned bundle JSON (empty signature fields), exactly in the form
/// load_release_approval_bundle parses once the ceremony fills the signatures.
[[nodiscard]] std::string unsigned_release_bundle_json(const ReleaseApprovalV1& approval);

}  // namespace nexus::security
