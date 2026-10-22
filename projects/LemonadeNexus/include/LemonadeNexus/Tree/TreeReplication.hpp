#pragma once

// Verification of tree log entries that arrive through replication (design
// A7).
//
// A server that did not take part in a commit (a Tier 2 server, or a Tier 1
// server that missed blocks) receives committed log entries from peers over
// the "tree" sync stream. The peer that delivers an entry is not trusted: the
// entry carries its own evidence, and the receiver checks it against facts it
// verified itself.
//
//   - A consensus entry (kind Batch) carries the proposal header and the
//     three-chain commit proof. The proof is verified under the frozen vote
//     keys and quorum of the epoch the header names. The receiver takes that
//     epoch's authority from its own verified authority chain
//     (SecurityDriver::authority_for_epoch), which follows the chain from the
//     pinned Genesis certificate through every finalized handoff. An entry
//     from an epoch the receiver has not verified yet is not applied.
//   - The merge commit (kind Merge, height 1) carries the root management
//     key's signature (TreeMerge.hpp).
//
// Structure (the state-root chain, the batch, the recorded roots) is checked
// by replay_entry (TreeLog.hpp) against the receiver's own log, in strict
// height order.

#include <LemonadeNexus/Security/Epoch/AuthorityChain.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>
#include <LemonadeNexus/Tree/TreeLog.hpp>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace nexus::tree {

/// The verified authority of one epoch, or nullopt when this server has not
/// verified that epoch. Must return only authority derived from the verified
/// chain, never from an announcement or local configuration.
using EpochAuthorityLookup =
    std::function<std::optional<security::VerifiedEpochAuthority>(security::EpochId)>;

/// Outcome of checking the consensus evidence of a replicated entry.
enum class EntryEvidence : uint8_t {
    Ok,
    /// The evidence is well formed, but this server has not verified the
    /// authority of the epoch it names. Retry after the authority chain
    /// advances; this is not a forgery.
    UnknownEpoch,
    /// The evidence is missing, malformed, or does not verify. Never applied.
    Refused,
};

struct EntryEvidenceVerdict {
    EntryEvidence result = EntryEvidence::Refused;
    std::string reason;
    /// The epoch the evidence names (0 when it names none).
    security::EpochId epoch = 0;
};

/// Check the consensus evidence of a Batch entry:
///   - `commit` holds "epoch", "proposal" (the header), and "proof" (the
///     commit proof), all well formed;
///   - the header is the proof's committed block, names `network_id`, the
///     compiled rulesets, and the recorded epoch;
///   - the header states the entry's block time, ops digest, and roots, and
///     the ops digest is the block payload digest of the batch bytes;
///   - the proof verifies (verify_commit_proof) under the epoch authority's
///     vote keys and consensus quorum, for that epoch and network.
/// A Merge entry is refused here; verify_merge_signature checks it.
[[nodiscard]] EntryEvidenceVerdict verify_certified_entry(const TreeLogEntry& entry,
                                                          const security::NetworkId& network_id,
                                                          const EpochAuthorityLookup& authority);

/// The consensus epoch an entry's evidence names (0 for none or a merge).
[[nodiscard]] security::EpochId entry_epoch(const TreeLogEntry& entry);

/// Most bytes of one encoded entry on the replication stream. A merge commit
/// is the largest entry (kMaxTreeMergeBodyBytes of body plus framing).
inline constexpr std::size_t kMaxReplicatedEntryBytes = 16u * 1024u * 1024u;

/// Wire form of an entry on the replication stream: msgpack of
/// tree_log_entry_to_json.
[[nodiscard]] std::vector<uint8_t> encode_replicated_entry(const TreeLogEntry& entry);

/// Inverse of encode_replicated_entry. nullopt for oversize or malformed
/// bytes; never throws.
[[nodiscard]] std::optional<TreeLogEntry> decode_replicated_entry(std::span<const uint8_t> bytes);

}  // namespace nexus::tree
