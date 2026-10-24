#pragma once

// Boot-chain staging on request (design: OS updates and reboot, step 3).
//
// Before nexus-updater reboots into a new boot chain, it asks the server to
// seal a second copy of every boot-set secret to the PCR 8/9 values of the
// new release approval. The server does not trust the updater for those
// values: it verifies the approval against its own Genesis anchor first.
//
// The staging uses SealedBlobStore's existing upgrade path: with the next
// boot chain set, a successful unseal writes the next slot. Only next slots
// are written; current blobs stay as they are, so a reboot back into the old
// chain still unseals.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>
#include <LemonadeNexus/Security/Sealing/SealedBlobStore.hpp>
#include <LemonadeNexus/Update/UpdateControl.hpp>

#include <filesystem>
#include <string_view>

namespace nexus::core {

struct BootChainStagingInputs {
    crypto::Ed25519PublicKey genesis_public_key{};
    security::NetworkId network_id{};
    /// <data_root>/sealed.
    std::filesystem::path sealed_directory;
    security::SealBackend backend;
};

/// Verify `approval_json`, then stage every sealed boot-set secret for its
/// PCR 8/9. ok only when the approval verifies, carries qualified PCRs, and
/// every current blob has a next blob bound to those PCRs afterwards (or the
/// PCRs are the running chain's, so nothing needs staging). Runs TPM
/// operations through `backend`; call it from the thread that owns the
/// sealed directory.
[[nodiscard]] update::BootChainStageResult stage_boot_chain_for_approval(
    const BootChainStagingInputs& inputs, std::string_view approval_json);

}  // namespace nexus::core
