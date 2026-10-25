#pragma once

// Boot-chain staging on request (design: OS updates and reboot, step 3).
//
// Before nexus-updater reboots into a new boot chain, it asks the server to
// seal a second copy of every boot-set secret to the PCR 8/9 values of the new
// release approval (Core/UpgradeControl.hpp, op stage_boot_chain). The server
// does not take those values from the updater: it stages only for the approval
// its release chain already accepted (Genesis delegation, pinned signer,
// monotonic release number).
//
// The staging uses SealedBlobStore's existing upgrade path: with the next
// boot chain set, a successful unseal writes the next slot. Only next slots
// are written; current blobs stay as they are, so a reboot back into the old
// chain still unseals.

#include <LemonadeNexus/Security/Attestation/ReleaseApproval.hpp>
#include <LemonadeNexus/Security/Sealing/SealedBlobStore.hpp>

#include <filesystem>
#include <string>
#include <vector>

namespace nexus::core {

struct BootChainStagingInputs {
    /// <data_root>/sealed.
    std::filesystem::path sealed_directory;
    security::SealBackend backend;
};

struct BootChainStageResult {
    bool ok = false;
    /// Sealing domains that now have a next blob for the approval's PCRs.
    std::vector<std::string> staged;
    std::string detail;
};

/// Stage every sealed boot-set secret for the PCR 8/9 of `accepted`, which the
/// caller has verified and accepted (ReleaseChain::current). ok only when the
/// approval carries qualified PCRs and every current blob has a next blob
/// bound to those PCRs afterwards (or the PCRs are the running chain's, so
/// nothing needs staging). Runs TPM operations through `backend`; call it
/// from the thread that owns the sealed directory (the security io thread).
[[nodiscard]] BootChainStageResult stage_boot_chain_for_approval(
    const BootChainStagingInputs& inputs, const security::ReleaseApprovalBundleV1& accepted);

}  // namespace nexus::core
