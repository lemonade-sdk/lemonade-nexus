#pragma once

// The boot set (design B6): secrets a server needs before it can unlock
// anything else. Today that is the gossip identity key, which is also the
// server's security-mesh NodeId key (and the Genesis key on the root server).
// The same SealedBlobStore holds the server's storage share
// (Security/Storage/StorageShareStore.hpp) and the vote-key wrapping key
// (Security/Epoch/EpochStore.hpp), each under its own sealing domain. The
// vote-key wrapping key follows the same migration states and rules as this
// file.
//
// One-way migration from identity/keypair.json to a sealed copy:
//
//   1. LegacyFile     keypair.json only. Hosts without sealing stay here; that
//                     is today's protection and the documented limit for
//                     certificate-only (Tier 2) hosts.
//   2. SealedPending  the key is sealed and the sealed copy unsealed in this
//                     boot. keypair.json stays, because a vTPM that does not
//                     keep its owner seed across reboots would lose the key.
//   3. Sealed         the sealed copy unsealed in a later boot (a different
//                     kernel boot id) than the one that sealed it. Only then is
//                     keypair.json overwritten and removed.
//
// Fail closed: once a sealed copy exists, the server never creates a new
// identity in its place. While keypair.json still exists (states 1 and 2) it is
// the fallback when the sealed copy does not unseal; after state 3 a failed
// unseal stops startup with a recovery instruction.
//
// Sealing protects the key on disk. It is not an attestation input: Tier 1
// eligibility and the attestation profile are unchanged by it.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Sealing/SealedBlobStore.hpp>

#include <chrono>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

namespace nexus::storage { class FileStorageService; }

namespace nexus::core {

/// Sealing domain of the gossip identity key.
inline constexpr std::string_view kGossipIdentitySealDomain = "gossip-identity";

/// Directory, under the data root, of the SealedBlobStore for the boot set.
inline constexpr std::string_view kSealedDirectory = "sealed";

enum class GossipIdentityProtection : uint8_t {
    LegacyFile,
    SealedPending,
    Sealed,
};

[[nodiscard]] std::string_view gossip_identity_protection_name(GossipIdentityProtection value);

struct BootSetConfig {
    std::filesystem::path data_root;
    /// Production: nexus::attestd::attestd_seal_backend(). Empty when this
    /// build has no sealing; the identity then stays in keypair.json.
    security::SealBackend backend;
    /// Expected PCR 8/9 of the installed, verified release approval; staged so
    /// a boot-chain upgrade unseals after its reboot. nullopt stages nothing.
    std::optional<security::BootPcrValues> next_boot_chain;
    /// Returns this kernel boot's id. Empty means unknown, which keeps the
    /// migration in SealedPending. Defaults to /proc/sys/kernel/random/boot_id.
    std::function<std::string()> boot_id;
    /// Create a new identity when none exists anywhere.
    bool create_if_absent{true};
    /// While a sealed copy exists and the daemon is unreachable, retry this
    /// many times, `retry_delay` apart, before giving up.
    int unreachable_attempts{10};
    std::chrono::milliseconds retry_delay{3000};
};

struct GossipIdentity {
    crypto::Ed25519Keypair   keypair;
    GossipIdentityProtection protection{GossipIdentityProtection::LegacyFile};
    /// True when this call generated the key.
    bool                     created{false};
};

/// Load the gossip identity and advance its migration one step if possible.
/// nullopt means startup must stop; `error` then says why and how to recover.
/// Never logs key material.
[[nodiscard]] std::optional<GossipIdentity> load_gossip_identity(
    storage::FileStorageService& storage, const BootSetConfig& config, std::string& error);

/// The gossip public key (base64) without unsealing: from keypair.json, or
/// from the boot-set state file once keypair.json is gone.
[[nodiscard]] std::optional<std::string> gossip_public_key_b64(
    storage::FileStorageService& storage, const std::filesystem::path& data_root);

/// The kernel boot id from /proc/sys/kernel/random/boot_id; empty elsewhere.
[[nodiscard]] std::string read_kernel_boot_id();

}  // namespace nexus::core
