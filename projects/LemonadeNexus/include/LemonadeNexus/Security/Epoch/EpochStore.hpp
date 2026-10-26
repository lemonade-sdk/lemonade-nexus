#pragma once

// Durable epoch state (class structure 35).
//
// Persists what a node must restore after a restart: the bootstrap
// certificate, the current epoch state with its vote keys and checkpoint,
// the history of epoch authority keys, and this node's own epoch vote key
// wrapped at rest. FROST shares are never stored: a restart destroys the
// share, and the mesh tolerates that loss (architecture 20).
//
// Every write is crash-atomic. A corrupt file is reported as Corrupt, never
// as absent: a node must not treat lost epoch state as a fresh start.
//
// Own vote keys at rest (design B6). Consensus votes while the data key is
// locked (B8), so the storage vault cannot cover the vote keys. Two files can
// hold the key of one epoch:
//
//   vote-key-<epoch>.json         machine-bound copy: KeyWrappingService with
//                                 an empty passphrase, so the wrapping key
//                                 comes from identity/wrap_local.key and
//                                 /etc/machine-id. It binds the file to the
//                                 machine; a reader of the whole data
//                                 directory can unwrap it.
//   vote-key-<epoch>.sealed.json  sealed copy: XChaCha20-Poly1305 under a key
//                                 derived from the vote-key wrapping key. That
//                                 key is a per-server random 32-byte key,
//                                 sealed in the boot set under the domain
//                                 kVoteKeyWrapSealDomain and used for nothing
//                                 else. The associated data binds the epoch,
//                                 the node id, and the vote public key.
//
// One-way migration, with the same states and rules as the gossip identity
// (Core/BootSet.hpp):
//
//   1. MachineBound   machine-bound copies only. Hosts that cannot seal stay
//                     here; that is today's protection and its limit.
//   2. SealedPending  the wrapping key is sealed and the sealed copy unsealed
//                     in this boot. Every vote key is written to both files,
//                     machine-bound copy first. The machine-bound copies stay,
//                     because a vTPM that does not keep its owner seed across
//                     reboots would lose the wrapping key.
//   3. Sealed         the sealed wrapping key unsealed in a later boot (a
//                     different kernel boot id). Every machine-bound copy gets
//                     a verified sealed copy first; then the state is recorded,
//                     and only then are the machine-bound copies overwritten
//                     and removed.
//
// Fail closed: once a sealed wrapping key exists, a new one replaces it only
// while the migration is pending, because the machine-bound copies still hold
// every vote key. After state 3 a wrapping key that does not unseal, or that
// is missing, stops startup with a recovery instruction, and a machine-bound
// copy is never read again.
//
// Sealing protects the keys on disk. It is not an attestation input and it
// changes no consensus or eligibility rule.

#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/SecureBuffer.hpp>
#include <LemonadeNexus/Security/Consensus/VoteKey.hpp>
#include <LemonadeNexus/Security/Epoch/AuthorityChain.hpp>
#include <LemonadeNexus/Security/Epoch/EpochState.hpp>
#include <LemonadeNexus/Security/Genesis/BootstrapCertificate.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace nexus::security {

class SealedBlobStore;

/// Sealing domain of the vote-key wrapping key in the boot set (B6).
inline constexpr std::string_view kVoteKeyWrapSealDomain = "vote-key-wrap";

/// How this node's own vote keys are protected at rest. See the file comment.
enum class VoteKeyProtection : uint8_t {
    MachineBound,
    SealedPending,
    Sealed,
    /// A sealed wrapping key exists but cannot be used, and the rules allow no
    /// fallback. No vote key is read or written; startup must stop.
    Refused,
};

[[nodiscard]] std::string_view vote_key_protection_name(VoteKeyProtection value);

/// Inputs of EpochStore::open_vote_key_sealing.
struct VoteKeySealing {
    /// The boot set's SealedBlobStore (Core/BootSet.hpp kSealedDirectory), with
    /// or without a backend. Not owning; must outlive the call. The migration
    /// state file sits beside the sealed blobs. nullptr keeps MachineBound.
    SealedBlobStore* sealed = nullptr;
    /// Encrypts the sealed copies. Not owning; must outlive the store.
    /// nullptr keeps MachineBound.
    crypto::SodiumCryptoService* crypto = nullptr;
    /// Returns this kernel boot's id. Unset or empty means unknown, which
    /// keeps the migration in SealedPending.
    std::function<std::string()> boot_id;
    /// While a sealed wrapping key exists and the daemon is unreachable, retry
    /// this many times, `retry_delay` apart, before giving up.
    int unreachable_attempts{10};
    std::chrono::milliseconds retry_delay{3000};
};

struct StoredEpoch {
    EpochState state;
    std::map<NodeId, crypto::Ed25519PublicKey> vote_keys;
    Digest checkpoint{};
};

struct EpochAuthorityRecord {
    EpochId epoch = 0;
    crypto::Ed25519PublicKey group_public_key{};
    Digest tier1_set_digest{};
    Digest dkg_transcript_digest{};
};

enum class EpochLoadResult { Absent, Corrupt };

class EpochStore {
public:
    /// `wrapping` writes the machine-bound copies of the own vote key; without
    /// it the vote key is not persisted and a restart loses voting for the
    /// epoch (liveness only). open_vote_key_sealing adds the sealed copies.
    EpochStore(std::filesystem::path directory, crypto::KeyWrappingService* wrapping);

    [[nodiscard]] bool store_bootstrap(const BootstrapCertificate& certificate);
    [[nodiscard]] std::variant<BootstrapCertificate, EpochLoadResult> load_bootstrap() const;

    [[nodiscard]] bool store_epoch(const StoredEpoch& epoch);
    [[nodiscard]] std::variant<StoredEpoch, EpochLoadResult> load_epoch() const;

    /// Appends one record; historical keys stay for historical examination.
    [[nodiscard]] bool append_authority(const EpochAuthorityRecord& record);
    [[nodiscard]] std::variant<std::vector<EpochAuthorityRecord>, EpochLoadResult>
    load_authority_history() const;

    /// Cache of the latest authority produced by verification. The public
    /// record digest detects accidental corruption but does not authenticate
    /// the cache; callers must reconstruct and compare its proof chain.
    [[nodiscard]] bool store_authority_anchor(const VerifiedEpochAuthority& anchor);
    [[nodiscard]] std::variant<VerifiedEpochAuthority, EpochLoadResult>
    load_authority_anchor() const;

    /// The verified handoff links this node holds, as encoded wire envelopes,
    /// oldest first. Loading returns bytes; the caller re-decodes and
    /// re-verifies — the store never vouches for chain content.
    [[nodiscard]] bool append_chain_link(std::span<const uint8_t> encoded);
    [[nodiscard]] std::variant<std::vector<std::vector<uint8_t>>, EpochLoadResult>
    load_chain_links() const;

    /// The epoch-1 member and vote-key listing the bootstrap certificate
    /// commits to by digest — the base a chain page serves to fresh nodes.
    [[nodiscard]] bool store_chain_base(
        const std::vector<std::pair<NodeId, crypto::Ed25519PublicKey>>& listing);
    [[nodiscard]] std::variant<std::vector<std::pair<NodeId, crypto::Ed25519PublicKey>>,
                               EpochLoadResult>
    load_chain_base() const;

    /// Unseals or creates the vote-key wrapping key and advances the vote-key
    /// migration one step if possible (see the file comment). Call once, on
    /// the thread that owns the sealed directory, before the first vote key is
    /// loaded or stored. It blocks while it retries an unreachable daemon.
    /// Without this call, or without a KeyWrappingService, the store stays
    /// MachineBound. Refused means startup must stop; `error` then says why
    /// and how to recover. Never logs key material.
    [[nodiscard]] VoteKeyProtection open_vote_key_sealing(const VoteKeySealing& sealing,
                                                          std::string& error);
    [[nodiscard]] VoteKeyProtection vote_key_protection() const { return protection_; }

    /// Persists this node's vote key for `key.epoch` as the protection
    /// requires: the machine-bound copy (MachineBound), both copies with the
    /// machine-bound copy first (SealedPending), or the sealed copy only
    /// (Sealed). False when the copy the next start depends on is not
    /// durable, when no wrapping is configured, or when the protection is
    /// Refused.
    [[nodiscard]] bool store_vote_key(const EpochVoteKey& key);
    /// This node's vote key for `epoch`, or nullopt when it is absent, does not
    /// authenticate, names another epoch, node, or public key, or when the two
    /// copies disagree. Sealed reads only the sealed copy; MachineBound reads
    /// only the machine-bound copy.
    [[nodiscard]] std::optional<EpochVoteKey> load_vote_key(EpochId epoch, const NodeId& node) const;
    /// Overwrites and removes both copies of the vote key for `epoch`. Best
    /// effort (security::scrub_file).
    void discard_vote_key(EpochId epoch);

    [[nodiscard]] const std::filesystem::path& directory() const { return directory_; }

private:
    [[nodiscard]] bool write_atomic(const std::filesystem::path& path,
                                    const std::string& content) const;
    [[nodiscard]] std::optional<std::string> read_all(const std::filesystem::path& path) const;

    [[nodiscard]] std::filesystem::path machine_bound_path(EpochId epoch) const;
    [[nodiscard]] std::filesystem::path sealed_copy_path(EpochId epoch) const;
    [[nodiscard]] std::optional<EpochVoteKey> read_machine_bound(EpochId epoch) const;
    [[nodiscard]] std::optional<EpochVoteKey> read_sealed_copy(EpochId epoch) const;
    [[nodiscard]] bool write_machine_bound(const EpochVoteKey& key) const;
    [[nodiscard]] bool write_sealed_copy(const EpochVoteKey& key) const;
    /// Epochs with a machine-bound copy on disk, ascending.
    [[nodiscard]] std::vector<EpochId> machine_bound_epochs() const;
    /// Gives every readable machine-bound copy a sealed copy that opens under
    /// the current wrapping key and holds the same key. False when one could
    /// not be written.
    [[nodiscard]] bool copy_into_sealed() const;
    /// Scrubs each machine-bound copy whose sealed copy opens and agrees, or
    /// whose own content no longer opens.
    void drop_machine_bound() const;
    /// Derives the file key and the key id from the wrapping key.
    void use_wrap_key(std::span<const uint8_t> wrap_key);
    [[nodiscard]] VoteKeyProtection seal_new_wrap_key(SealedBlobStore& sealed,
                                                      const VoteKeySealing& sealing,
                                                      const std::filesystem::path& state_file);

    std::filesystem::path directory_;
    crypto::KeyWrappingService* wrapping_;
    crypto::SodiumCryptoService* crypto_ = nullptr;
    VoteKeyProtection protection_ = VoteKeyProtection::MachineBound;
    /// AEAD key of the sealed copies, in guarded memory. Empty unless the
    /// protection is SealedPending or Sealed. The wrapping key itself is not
    /// kept after the derivation.
    crypto::SecureBuffer file_key_;
    /// Public identifier of the wrapping key, recorded in the state file and
    /// in each sealed copy.
    std::array<uint8_t, 16> key_id_{};
};

}  // namespace nexus::security
