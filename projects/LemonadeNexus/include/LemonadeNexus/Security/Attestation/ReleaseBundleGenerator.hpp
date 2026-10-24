#pragma once

// Build-time generation of the unsigned release-approval bundle. Digests come
// from the actual artifact bytes; identities come from the compiled release
// line (release_approval_template). No signing happens here: the output is
// the data a separately authorized signing ceremony completes.

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
    /// Approved SVSM launch measurements, one per approved VM shape, each 96
    /// lowercase hex. Empty keeps the compiled template set. The generator
    /// sorts them; duplicates fail closed.
    std::vector<std::string> svsm_launch_measurements;
    /// Both required executables plus the audited dependency closure.
    std::vector<ReleaseArtifact> artifacts;
    /// The previous release's approval, for the one-release overlap window
    /// (design Phase 2). Its signature must verify under signer_pubkey_b64.
    /// Its digests are appended after the new digest of every path the new
    /// release still lists; a path the new release drops is not carried over.
    std::optional<ReleaseApprovalV1> previous;
};

/// Fills the compiled template with digests of the actual files. Fail-closed:
/// any invalid spec yields nullopt and a reason in `error`.
///
/// Order of each path's digests: the new release's digest first, then the
/// previous release's. nexus-updater relies on the first entry being the
/// newest build.
[[nodiscard]] std::optional<ReleaseApprovalV1> generate_release_approval(
    const ReleaseBundleSpec& spec, std::string& error);

/// The unsigned bundle JSON (empty signature fields), exactly in the form
/// load_release_approval_bundle parses once the ceremony fills the signatures.
[[nodiscard]] std::string unsigned_release_bundle_json(const ReleaseApprovalV1& approval);

}  // namespace nexus::security
