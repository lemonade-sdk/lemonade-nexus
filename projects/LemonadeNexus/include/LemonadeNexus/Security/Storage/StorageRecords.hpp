#pragma once

// Storage-key holder records (design B4, B5, B5a): the consensus payloads that
// select the holders of the threshold storage key and finalize its plan, and
// the pure rules every replica uses to derive, check, and apply them.
//
// A record has one of two stages:
//
// - StorageSelection. Tier 1 finalizes who holds the key next, the threshold,
//   and the operation: the first key (Create), a share refresh that keeps S
//   (Refresh), or a key rotation (Rotate). Every replica derives the selection
//   itself from finalized inputs and votes only for identical bytes.
// - StorageFinalPlan. The session result: S, every holder's share commitment
//   (the storage-threshold plan bytes), and each selected holder's identity
//   signature over those exact bytes. The holders' byte-for-byte comparison of
//   the plan they derived is therefore part of the finalized record.
//
// Records chain by sequence and previous-record digest. A rotation record has
// payload kind StorageKeyRotation; every other record has StorageHolderPlan.
//
// The storage key is its own key role. These records never grant Tier 1
// authority and never authorize a tree or epoch change.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Consensus/BlockPayload.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>
#include <LemonadeNexus/Security/Transport/SecurityCodec.hpp>

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <span>
#include <string_view>
#include <variant>
#include <vector>

namespace nexus::security {

/// The canonical 32-byte encoding of a Ristretto255 point (S, R, Y_i).
using StoragePointBytes = std::array<uint8_t, 32>;

enum class StorageOperation : uint16_t {
    /// The first storage key: a key generation among at least 5 holders.
    Create = 1,
    /// A share refresh: same S and threshold; the holder set may lose holders.
    Refresh = 2,
    /// A key rotation: a new key generation and a new S, among at least 3
    /// holders. Also how holders are added.
    Rotate = 3,
};

enum class StorageRecordStage : uint16_t {
    Selection = 1,
    Final = 2,
};

[[nodiscard]] std::string_view storage_operation_name(StorageOperation operation);

/// One holder and the storage-threshold identifier the plan assigns it.
struct StorageHolder {
    NodeId node{};
    /// Nonzero.
    uint16_t holder_id = 0;

    auto operator<=>(const StorageHolder&) const = default;
};

/// Tier 1's finalized choice of the next holder set (design B4, B5).
struct StorageSelection {
    NetworkId network_id{};
    uint64_t sequence = 0;
    /// Digest of the record before this one; zero for the first record.
    Digest previous_record{};
    /// The epoch whose finalized eligibility pool the holders came from.
    EpochId target_epoch{};
    StorageOperation operation = StorageOperation::Create;
    /// 0 for a boundary or rotation selection; incremented by each retry
    /// after a session timeout.
    uint32_t attempt = 0;
    /// The finalized eligibility commitment and checkpoint seed of the
    /// boundary the holders were ranked under. Zero for a daily rotation of
    /// the current holder set.
    Digest eligibility_commitment{};
    Digest checkpoint_seed{};
    uint16_t threshold = 0;
    /// Refresh only: digest of the final plan whose shares refresh.
    Digest base_plan{};
    /// The binding block time (Unix milliseconds) of the block carrying it.
    uint64_t block_time_ms = 0;
    /// Ascending holder_id.
    std::vector<StorageHolder> holders;
};

/// The finalized holder plan: the result of one selection's session.
struct StorageFinalPlan {
    NetworkId network_id{};
    uint64_t sequence = 0;
    Digest previous_record{};
    /// Digest of the selection this plan completes.
    Digest selection{};
    StorageOperation operation = StorageOperation::Create;
    /// The epoch in which consensus finalized this plan.
    EpochId effective_epoch{};
    uint16_t threshold = 0;
    StoragePointBytes storage_public_key{};
    /// The storage-threshold plan bytes: S and each holder's Y_i.
    std::vector<uint8_t> key_plan;
    /// Same holders and order as the selection.
    std::vector<StorageHolder> holders;
    /// One identity signature per holder, in holder order, over
    /// storage_confirmation_digest().
    std::vector<crypto::Ed25519Signature> confirmations;
    /// The last final plan with a different S that still unwraps data keys,
    /// and the last epoch it does (design B5a grace period). Zero when none.
    Digest retiring_plan{};
    EpochId retiring_until{};
    uint64_t block_time_ms = 0;
    /// Block time of the record that created this S: the daily rotation
    /// counts from here.
    uint64_t key_created_ms = 0;
};

using StorageRecord = std::variant<StorageSelection, StorageFinalPlan>;

/// The canonical encoding (CanonicalEncoder fields). Empty when a field
/// exceeds its bound.
[[nodiscard]] std::vector<uint8_t> encode_storage_record(const StorageRecord& record);

/// Decodes exactly the bytes encode_storage_record() produces; anything else,
/// including a different encoding of the same values, is refused.
[[nodiscard]] std::optional<StorageRecord> decode_storage_record(std::span<const uint8_t> bytes);

/// SHA-256 of the canonical encoding.
[[nodiscard]] Digest storage_record_digest(const StorageRecord& record);

/// StorageKeyRotation for a Rotate record, StorageHolderPlan otherwise.
[[nodiscard]] BlockPayloadKind storage_record_kind(const StorageRecord& record);

/// The block payload that carries `record`.
[[nodiscard]] BlockPayload storage_record_payload(const StorageRecord& record);

/// Decodes a storage payload and checks that its kind matches the record.
[[nodiscard]] std::optional<StorageRecord> storage_record_from_payload(const BlockPayload& payload);

[[nodiscard]] uint64_t storage_record_sequence(const StorageRecord& record);
[[nodiscard]] uint64_t storage_record_block_time(const StorageRecord& record);

/// t = ceil(0.65 * n) for 1 <= n <= 50 (the crate's formula).
[[nodiscard]] std::optional<uint16_t> storage_threshold_for(std::size_t holder_count);

/// What a holder signs to confirm the plan it derived in one session.
[[nodiscard]] Digest storage_confirmation_digest(const NetworkId& network_id,
                                                 const Digest& selection_digest,
                                                 std::span<const uint8_t> key_plan,
                                                 const StorageHolder& holder);

/// The binding sealed inside a round-2 package: network, session, sender, and
/// recipient, under the storage domain.
[[nodiscard]] Digest storage_pairwise_binding(const NetworkId& network_id, const Digest& session,
                                              uint16_t sender_id, uint16_t recipient_id);

/// The digest of one unlock request: what the attestation context and the
/// sealed partial bind to.
[[nodiscard]] Digest storage_unlock_request_digest(const NetworkId& network_id,
                                                   const StorageUnlockRequestMsg& request);

/// A node's rank in the holder selection: H(checkpoint_seed || node_id) under
/// the storage domain. Lower ranks first; no node chooses its own rank.
[[nodiscard]] Digest storage_holder_rank(const Digest& checkpoint_seed, const NodeId& node);

/// The first kStorageMaxHolders nodes of `pool` by rank.
[[nodiscard]] std::vector<NodeId> rank_storage_holders(const Digest& checkpoint_seed,
                                                       std::vector<NodeId> pool);

/// The finalized eligibility facts one boundary contributes (design B4).
struct StorageEligibleSnapshot {
    EpochId target_epoch{};
    Digest eligibility_commitment{};
    Digest checkpoint_seed{};
    /// Every eligible node: admitted, with a passing eligibility attestation
    /// in the epoch before target_epoch, Tier 1 and Tier 2 alike.
    std::vector<NodeId> pool;
};

/// The finalized storage chain as one node knows it.
struct StorageChainState {
    uint64_t sequence = 0;
    Digest head{};
    uint64_t last_block_time_ms = 0;
    /// The highest target epoch of a committed boundary selection.
    EpochId last_boundary_epoch{};

    std::optional<StorageSelection> pending;
    Digest pending_digest{};
    std::optional<StorageFinalPlan> current;
    Digest current_digest{};
    /// The plan named by current->retiring_plan, when this node holds it.
    std::optional<StorageFinalPlan> retiring;
    Digest retiring_digest{};
};

/// Applies one finalized record. A record newer than the head replaces the
/// state it supersedes; an older final plan is accepted only when it is the
/// current plan's retiring plan. Returns false when the record changes
/// nothing.
bool apply_storage_record(StorageChainState& state, const StorageRecord& record);

/// The selection the next storage block must carry, or nullopt for none.
/// Deterministic in its inputs:
///  - a pending selection blocks everything until its session timed out (in
///    block time); then the next boundary's selection replaces it, or a retry
///    without `silent` (holders of the pending selection whose round-1
///    package this replica never observed), up to kStorageMaxSessionAttempts;
///  - a boundary newer than the last committed one selects from its pool:
///    Create with at least 5 holders; with a current plan, Refresh when the
///    holders are a subset of the current ones, t is unchanged, and no
///    rotation is due, else Rotate with at least 3 holders;
///  - otherwise, a due daily rotation rotates among the current holders.
/// Fewer than 3 holders (5 for Create) selects nothing: the last plan stays.
[[nodiscard]] std::optional<StorageSelection> derive_storage_selection(
    const NetworkId& network_id, const StorageChainState& state,
    const StorageEligibleSnapshot* snapshot, const std::set<NodeId>& silent,
    uint64_t block_time_ms);

/// Why a proposed final plan does not follow from the state.
enum class StorageFinalFailure : uint16_t {
    None,
    NoPendingSelection,
    SelectionMismatch,
    ChainMismatch,
    PlanInvalid,
    KeyMismatch,
    ConfirmationInvalid,
    FieldMismatch,
};

/// The final plan the pending selection's session produced, from the plan
/// bytes and the holders' confirmations, keyed by holder node. nullopt when
/// a confirmation is missing or the plan does not fit the selection.
[[nodiscard]] std::optional<StorageFinalPlan> make_storage_final(
    const StorageChainState& state, std::span<const uint8_t> key_plan,
    const std::map<NodeId, crypto::Ed25519Signature>& confirmations, EpochId effective_epoch,
    uint64_t block_time_ms);

/// Full check of a proposed final plan against the state: it must complete
/// the pending selection, the plan must validate with exactly the selected
/// holder identifiers and threshold (and keep S for a refresh), every holder
/// must have signed the exact plan bytes, and every derived field must match.
[[nodiscard]] StorageFinalFailure check_storage_final(const StorageChainState& state,
                                                      const StorageFinalPlan& plan,
                                                      EpochId effective_epoch);

}  // namespace nexus::security
