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

#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Security/Consensus/VoteKey.hpp>
#include <LemonadeNexus/Security/Epoch/AuthorityChain.hpp>
#include <LemonadeNexus/Security/Epoch/EpochState.hpp>
#include <LemonadeNexus/Security/Genesis/BootstrapCertificate.hpp>

#include <filesystem>
#include <map>
#include <optional>
#include <span>
#include <variant>
#include <vector>

namespace nexus::security {

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
    /// `wrapping` protects the own vote key at rest; without it the vote key
    /// is not persisted and a restart loses voting for the epoch (liveness
    /// only).
    EpochStore(std::filesystem::path directory, crypto::KeyWrappingService* wrapping);

    [[nodiscard]] bool store_bootstrap(const BootstrapCertificate& certificate);
    [[nodiscard]] std::variant<BootstrapCertificate, EpochLoadResult> load_bootstrap() const;

    [[nodiscard]] bool store_epoch(const StoredEpoch& epoch);
    [[nodiscard]] std::variant<StoredEpoch, EpochLoadResult> load_epoch() const;

    /// Appends one record; historical keys stay for historical examination.
    [[nodiscard]] bool append_authority(const EpochAuthorityRecord& record);
    [[nodiscard]] std::variant<std::vector<EpochAuthorityRecord>, EpochLoadResult>
    load_authority_history() const;

    /// The latest verified authority anchor, so a restart resumes the chain
    /// walk from here instead of Genesis. The record binds its own digest; a
    /// mismatch loads as Corrupt, never as a different anchor.
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

    [[nodiscard]] bool store_vote_key(const EpochVoteKey& key);
    [[nodiscard]] std::optional<EpochVoteKey> load_vote_key(EpochId epoch, const NodeId& node) const;
    void discard_vote_key(EpochId epoch);

    [[nodiscard]] const std::filesystem::path& directory() const { return directory_; }

private:
    [[nodiscard]] bool write_atomic(const std::filesystem::path& path,
                                    const std::string& content) const;
    [[nodiscard]] std::optional<std::string> read_all(const std::filesystem::path& path) const;

    std::filesystem::path directory_;
    crypto::KeyWrappingService* wrapping_;
};

}  // namespace nexus::security
