#pragma once

// Application data a consensus block carries (design A3).
//
// A proposal commits to its payload through `transitions_digest`: a block
// carries either an epoch-boundary stage digest or a payload digest, never
// both, so the stage logic is unchanged and the proposal digest and its wire
// layout stay those of a block without a payload. The payload bytes travel
// beside the proposal in the HotStuffProposal message only; commit proofs and
// sync replies carry the header, which is enough to verify the commitment.
//
// Payload kinds are append-only. Each kind has one handler on the lifecycle
// driver (IBlockPayloadHandler) that proposes, validates, and applies it. A
// later kind (for example a storage holder plan) adds an enum value and a
// handler; consensus code does not change.

#include <LemonadeNexus/Security/Consensus/CommitProof.hpp>
#include <LemonadeNexus/Security/Consensus/ConsensusTypes.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstdint>
#include <optional>
#include <vector>

namespace nexus::security {

class HotStuffService;

/// What a block payload holds. Values append only; earlier values are stable.
enum class BlockPayloadKind : uint16_t {
    /// An ordered batch of tree operations (nexus::tree::TreeBatch wire form).
    TreeBatch = 1,
};

/// True for a kind this build knows. The codec refuses any other value.
[[nodiscard]] bool block_payload_kind_known(uint16_t kind);

struct BlockPayload {
    BlockPayloadKind kind = BlockPayloadKind::TreeBatch;
    /// The kind's canonical wire form, at most constants::kMaxBlockPayloadBytes.
    std::vector<uint8_t> body;
};

/// The digest a proposal carries in `transitions_digest` for this payload:
/// CanonicalEncoder under kBftProtocolDomain with kind string "block-payload",
/// the kind, and the body bytes. Distinct from every stage digest by domain.
[[nodiscard]] Digest block_payload_digest(const BlockPayload& payload);

/// A block a payload handler proposes. The driver passes the roots and the
/// payload digest to HotStuffService::make_proposal and sets timestamp_hint.
struct ProposedPayload {
    BlockPayload payload;
    Digest previous_state_root{};
    Digest proposed_state_root{};
    /// Binding block time for this kind (Unix milliseconds for a tree batch).
    uint64_t timestamp_hint = 0;
};

/// A committed payload block, handed to its handler in commit order.
struct CommittedPayload {
    ConsensusCommit commit;
    Proposal proposal;
    const BlockPayload* payload = nullptr;
    /// The three-chain commit proof, when the blocks behind it are still held.
    std::optional<CommitProof> proof;
};

/// The per-kind extension point of the lifecycle driver. All calls arrive on
/// the driver's thread. A handler decides nothing about safety: the driver
/// and HotStuffService keep vote-once, locking, and commit rules; the handler
/// only answers whether this node independently agrees with a payload, which
/// gates this node's vote exactly like SecurityDriver::accepts_transition.
///
/// A virtual interface, not the repository CRTP pattern: handlers are
/// registered at runtime (one per enabled feature), and the call rate is one
/// per block.
class IBlockPayloadHandler {
public:
    virtual ~IBlockPayloadHandler() = default;

    [[nodiscard]] virtual BlockPayloadKind kind() const = 0;

    /// A payload for the block this leader proposes on top of the high
    /// certificate's block, or nullopt for none. `consensus` is the live
    /// service; its chain state holds the parent and the uncommitted
    /// ancestors.
    [[nodiscard]] virtual std::optional<ProposedPayload> propose(
        const HotStuffService& consensus) = 0;

    /// Whether this node independently agrees with `payload` for `proposal`.
    /// False withholds this node's vote; the block still enters chain state.
    /// `proposal.transitions_digest` already matches the payload digest.
    [[nodiscard]] virtual bool validate(const HotStuffService& consensus,
                                        const Proposal& proposal,
                                        const BlockPayload& payload) = 0;

    /// A block carrying this kind committed. Called once per block, in
    /// commit order, across epochs. A block whose payload this node does not
    /// hold (for example one adopted through restart sync) never reaches the
    /// handler, so a handler must detect a gap from its own chaining (the tree
    /// log's state roots do).
    virtual void on_committed(const CommittedPayload& committed) = 0;

    /// Consensus restarted (epoch activation, restore): uncommitted blocks are
    /// gone. Committed state is unaffected.
    virtual void on_consensus_reset() = 0;
};

}  // namespace nexus::security
