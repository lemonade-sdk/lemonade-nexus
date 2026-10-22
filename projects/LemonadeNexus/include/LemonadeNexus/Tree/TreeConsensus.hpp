#pragma once

// Tree operations through Tier 1 consensus (design A2 to A6): the block
// payload handler for tree batches.
//
// Submission (A2): an API thread hands a sealed op to submit(). It is
// pre-checked against the committed tree, queued in the pending pool, and
// forwarded to the other Tier 1 members, which queue it too. The request
// waits on the op's ticket.
//
// Ordering (A3, A4, A5): when this node leads and no epoch-boundary stage is
// pending, propose() builds a batch from the pool against the parent's tree
// state (committed state plus the uncommitted ancestors) with a binding block
// time. validate() decides this node's vote: every op must validate in order
// against the parent's state, the block time must advance and stay within
// kTreeBlockClockSkewMs of this node's clock, and the state roots must match.
//
// Commit then apply (A6): on_committed() appends the block to the TreeLog and
// only then applies its ops to the PermissionTreeService. Any disagreement
// between the committed block and this node's log (a missed block, a root
// mismatch, a write failure) halts the handler: it stops applying, voting,
// and proposing tree blocks, and keeps serving the last committed tree. It
// never applies a block it cannot verify against its own log.
//
// Threads: submit(), status(), healthy(), and set_members() may run on any
// thread. Everything else runs on the security io thread.

#include <LemonadeNexus/Security/Consensus/BlockPayload.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>
#include <LemonadeNexus/Security/Transport/SecurityCodec.hpp>
#include <LemonadeNexus/Tree/TreeChain.hpp>
#include <LemonadeNexus/Tree/TreeLog.hpp>
#include <LemonadeNexus/Tree/TreeOpPool.hpp>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace nexus::crypto { class SodiumCryptoService; }

namespace nexus::tree {

class PermissionTreeService;

/// How long an API request waits for its op to commit before it answers
/// "pending" (design A2).
inline constexpr uint64_t kTreeOpCommitWaitMs = 10'000;

/// Wire budget of one tree batch, leaving room in the proposal envelope for
/// the header, the justify certificate at the largest population, and the
/// payload framing.
inline constexpr std::size_t kTreeBatchWireBudget = 54'000;

struct TreeConsensusConfig {
    /// This server's node id (its gossip identity key).
    security::NodeId self{};
    security::NetworkId network_id{};
    /// The configured root management key ("ed25519:<base64>"), or empty.
    std::string root_key;
    /// Unix time in milliseconds. The one local clock input: the proposer's
    /// block time and the voter's block-time bound (design A4).
    std::function<uint64_t()> wall_clock_ms;
    TreeOpPoolLimits pool_limits{};
    /// Phase 7: the tree log is read and written through this vault. Not
    /// owning; nullptr keeps plain files.
    security::StorageVault* vault = nullptr;
};

class TreeConsensus final : public security::IBlockPayloadHandler {
public:
    /// Not owning: `tree` and `crypto` must outlive this object.
    TreeConsensus(TreeConsensusConfig config, PermissionTreeService& tree,
                  crypto::SodiumCryptoService& crypto, std::filesystem::path log_directory);

    /// Open the tree log and reconcile it with the persistent tree: equal
    /// digests are clean; a tree behind an unapplied log tail is restored from
    /// the log; any other difference halts (the tree changed outside the
    /// log). Call once, before consensus delivers blocks. False when halted.
    [[nodiscard]] bool start();

    /// False once halted; halt_reason() says why. Thread-safe.
    [[nodiscard]] bool healthy() const;
    [[nodiscard]] std::string halt_reason() const;

    /// The current Tier 1 membership for submissions and forwarded ops (the
    /// owner refreshes it each tick). Block validation uses the block epoch's
    /// membership from consensus instead. Thread-safe.
    void set_members(std::vector<security::NodeId> members);

    /// Pre-check a sealed op against the committed tree and queue it. Refused
    /// with Unavailable when this server is not a Tier 1 member, the handler
    /// is halted, or the pool is full; otherwise with the pre-check's
    /// verdict. A queued op is forwarded to the other members through the
    /// broadcast hook. Thread-safe.
    [[nodiscard]] TreeOpAdmission submit(TreeOp sealed);

    /// Sends a forwarded op to the other Tier 1 members. Called from submit()
    /// on an API thread, so the hook must hand the work to the io thread.
    void set_broadcast(std::function<void(security::TreeOpSubmitMsg)> broadcast) {
        broadcast_ = std::move(broadcast);
    }

    /// An op another Tier 1 member forwarded: decoded, pre-checked, and
    /// queued without a ticket. Invalid bytes are dropped. io thread.
    void receive_forwarded(const security::TreeOpSubmitMsg& message, const security::NodeId& from);

    /// Pending, committed, or refused, for an op id this server saw. nullopt
    /// when it never saw it or forgot it. Thread-safe.
    [[nodiscard]] std::optional<TreeOpOutcome> status(const std::string& op_id) const;

    /// Pool upkeep: refuse queued ops that no longer validate against the
    /// committed tree (stale, replayed, base version moved) and, when no root
    /// exists, ask the root hook for a root op. Rate-limited internally. io
    /// thread.
    void maintain();

    /// Called by maintain() when the tree has no root, this server is a Tier 1
    /// member, and a root key is configured: the owner seals and submits an
    /// EstablishRoot op. io thread.
    void set_root_request(std::function<void()> request) { root_request_ = std::move(request); }

    /// The committed log (tests and Phase 3 replication). io thread.
    [[nodiscard]] const TreeLog& log() const { return log_; }

    /// The policy a block in an epoch with `members` is validated under.
    [[nodiscard]] TreeOpPolicy policy_for(const std::vector<security::NodeId>& members) const;

    // --- IBlockPayloadHandler ---
    [[nodiscard]] security::BlockPayloadKind kind() const override {
        return security::BlockPayloadKind::TreeBatch;
    }
    [[nodiscard]] std::optional<security::ProposedPayload> propose(
        const security::HotStuffService& consensus) override;
    [[nodiscard]] bool validate(const security::HotStuffService& consensus,
                                const security::Proposal& proposal,
                                const security::BlockPayload& payload) override;
    void on_committed(const security::CommittedPayload& committed) override;
    void on_consensus_reset() override {}

private:
    /// The tree after `block_digest` (committed state plus every uncommitted
    /// tree ancestor up to and including that block), or nullopt when an
    /// ancestor is unknown or does not replay to its own roots.
    [[nodiscard]] std::optional<TreeChainState> state_after(
        const security::HotStuffService& consensus, const security::Digest& block_digest) const;
    void halt(const std::string& reason);
    void revalidate_pool();
    [[nodiscard]] bool is_member(const security::NodeId& node) const;

    TreeConsensusConfig config_;
    PermissionTreeService& tree_;
    crypto::SodiumCryptoService& crypto_;
    TreeLog log_;
    TreeOpPool pool_;
    std::function<void(security::TreeOpSubmitMsg)> broadcast_;
    std::function<void()> root_request_;

    mutable std::mutex mutex_;  // guards halted_, halt_reason_, members_
    bool halted_ = true;        // until start() succeeds
    std::string halt_reason_ = "not started";
    std::vector<security::NodeId> members_;

    uint64_t last_maintain_ms_ = 0;
    uint64_t last_root_request_ms_ = 0;
};

}  // namespace nexus::tree
