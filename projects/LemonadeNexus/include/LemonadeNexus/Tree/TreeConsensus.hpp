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
// only then applies its ops to the PermissionTreeService.
//
// Replication (A7): receive_replicated() takes committed entries that peers
// deliver over the "tree" sync stream. It verifies each entry's evidence (the
// commit proof under the block epoch's verified vote keys, or the merge
// signature under the configured root management key), then applies it only
// when it is the next height and chains to this log. A server that missed a
// block (on_committed sees a block that does not follow its log) does not
// halt: it is "behind", applies nothing out of order, and catches up through
// replication; the next committed block that chains resumes it.
//
// Fail closed: an entry whose evidence does not verify, or that does not
// chain to this log, is refused and not applied, and nothing after it applies
// until a verified entry for that height arrives. (The log height is not
// covered by the commit proof, so an unchained entry may be a renumbered
// genuine one; a server whose log base differs from the mesh's refuses every
// entry and reports it in its status.) A log that does not verify at start,
// a certified entry that chains but does not replay to its roots, or a write
// failure halts the handler: it stops applying, voting, and proposing tree
// blocks, and keeps serving the last committed tree.
//
// The committed log always drives the persistent tree. There is no other
// write path.
//
// Awaiting the merge (design A9): a server whose tree was written before tree
// operations holds that tree and no log. start() then opens a log on the empty
// base and keeps the pre-merge tree as it is: the tree stays readable, but the
// handler refuses every submission and forwarded op, proposes nothing, and
// withholds its vote from every tree block. The only entry it takes is the
// merge commit at height 1, signed by the root management key (TreeMerge.hpp),
// through receive_replicated() (the "tree" sync stream, or the merge commit
// route POST /api/tree/merge/commit). Applying it replaces the pre-merge
// tree with the merged tree, and the handler then runs normally. A committed
// tree block that does not follow a merge commit is refused, never applied
// over the pre-merge tree. A restart in this state awaits the merge again.
//
// Threads: submit(), status(), healthy(), and set_members() may run on any
// thread. Everything else runs on the security io thread.

#include <LemonadeNexus/Security/Consensus/BlockPayload.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>
#include <LemonadeNexus/Security/Transport/SecurityCodec.hpp>
#include <LemonadeNexus/Tree/TreeChain.hpp>
#include <LemonadeNexus/Tree/TreeLog.hpp>
#include <LemonadeNexus/Tree/TreeOpPool.hpp>
#include <LemonadeNexus/Tree/TreeReplication.hpp>

#include <atomic>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
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

/// Most replicated entries held for a later height (a gap, or an epoch whose
/// authority is not verified yet). They are verified when their turn comes.
inline constexpr std::size_t kMaxReplicaHeldEntries = 64;
/// Most bytes of entry content held for later heights.
inline constexpr std::size_t kMaxReplicaHeldBytes = 8u * 1024u * 1024u;

/// What receive_replicated() did with an entry.
enum class ReplicaResult : uint8_t {
    Applied,       ///< verified and applied (with any held entries it unblocked)
    Duplicate,     ///< this log already holds the height; nothing changed
    Gap,           ///< a later height; held, not applied
    UnknownEpoch,  ///< the epoch's authority is not verified here yet; held
    Refused,       ///< the evidence does not verify; dropped, not applied
    Halted,        ///< the handler is halted, or this entry halted it
};

/// A thread-safe summary of the tree log for status reports.
struct TreeLogStatus {
    bool healthy = false;
    /// The pre-merge tree is held and the merge commit has not arrived: tree
    /// writes are refused (see the file comment).
    bool awaiting_merge = false;
    /// Nodes of the pre-merge tree while awaiting the merge; 0 otherwise.
    std::size_t pre_merge_nodes = 0;
    std::string halt_reason;
    uint64_t height = 0;
    uint64_t applied_height = 0;
    security::Digest root{};
    /// A committed block did not follow this log; waiting for replication.
    bool behind = false;
    /// Replicated entries held for a later height.
    std::size_t held = 0;
    /// The last refused replicated entry, or empty.
    std::string last_refusal;
};

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
    /// the log; any other difference halts (the tree changed outside the log).
    /// Without a log, an empty tree starts a new log on the empty base. A
    /// populated tree with no log, or with a log still at the empty base,
    /// awaits the merge commit (see the file comment); it is never taken as a
    /// log base, because that base would differ from other servers' and would
    /// block the merge commit (height 1 on the empty base). Call when this
    /// server holds the tree (TreeRole.hpp): once at Tier 1 entry, and again
    /// after a deactivate(). Until it succeeds the handler is halted and
    /// refuses every block, op, and replicated entry. False when halted.
    [[nodiscard]] bool start();

    /// Stop running the tree log: halt with `reason`, refuse every pending
    /// op, and drop held replicated entries. The log stays closed until the
    /// next start(). A server that leaves Tier 1 deactivates before it
    /// deletes the log files (TreeRole.hpp). io thread.
    void deactivate(const std::string& reason);

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

    /// The committed log (tests). io thread.
    [[nodiscard]] const TreeLog& log() const { return log_; }

    // --- Replication (design A7) ---

    /// Where the verified epoch authorities come from (the driver's verified
    /// chain). Unset, every consensus entry is UnknownEpoch. io thread.
    void set_authority_source(EpochAuthorityLookup lookup) { authority_ = std::move(lookup); }

    /// Told the epoch an entry names when its authority is not verified yet,
    /// so the owner can ask for the authority chain. io thread.
    void set_epoch_hint(std::function<void(security::EpochId)> hint) {
        epoch_hint_ = std::move(hint);
    }

    /// Called after each entry is durably appended, with its height (the sync
    /// stream offers it to peers). io thread.
    void set_appended_hook(std::function<void(uint64_t)> hook) { appended_hook_ = std::move(hook); }

    /// Called after the persistent tree followed the log. io thread.
    void set_applied_hook(std::function<void()> hook) { applied_hook_ = std::move(hook); }

    /// Verify and apply one replicated entry (see the file comment). io thread.
    [[nodiscard]] ReplicaResult receive_replicated(const TreeLogEntry& entry);

    /// True while the handler holds a pre-merge tree and awaits the merge
    /// commit. Thread-safe.
    [[nodiscard]] bool awaiting_merge() const;

    /// The encoded entry at `height` (encode_replicated_entry) for serving a
    /// peer, or nullopt when this log does not hold it. Reads the entry file
    /// only. Thread-safe.
    [[nodiscard]] std::optional<std::vector<uint8_t>> encoded_entry(uint64_t height) const;

    /// A summary for status reports. Thread-safe.
    [[nodiscard]] TreeLogStatus status_summary() const;

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
    /// Append `entry` (whose replay produced `next` and `result`) and apply it
    /// to the persistent tree. False when halted.
    bool commit_entry(const TreeLogEntry& entry, TreeChainState next,
                      const TreeBlockResult& result);
    /// Verify and apply the entry for height log_.height() + 1.
    [[nodiscard]] ReplicaResult apply_next(const TreeLogEntry& entry);
    /// Hold an entry for a later height, within kMaxReplicaHeldEntries and
    /// kMaxReplicaHeldBytes.
    void hold(const TreeLogEntry& entry);
    /// Apply held entries while the next height is held and verifies.
    void drain_held();
    void refresh_status();
    void note_refusal(const std::string& reason);
    [[nodiscard]] bool is_member(const security::NodeId& node) const;

    TreeConsensusConfig config_;
    PermissionTreeService& tree_;
    crypto::SodiumCryptoService& crypto_;
    TreeLog log_;
    TreeOpPool pool_;
    std::function<void(security::TreeOpSubmitMsg)> broadcast_;
    std::function<void()> root_request_;
    EpochAuthorityLookup authority_;
    std::function<void(security::EpochId)> epoch_hint_;
    std::function<void(uint64_t)> appended_hook_;
    std::function<void()> applied_hook_;
    /// Replicated entries for later heights, by height. io thread.
    std::map<uint64_t, TreeLogEntry> held_;

    mutable std::mutex mutex_;  // guards halted_, halt_reason_, awaiting_merge_, members_, status_
    bool halted_ = true;        // until start() succeeds
    bool awaiting_merge_ = false;
    std::size_t pre_merge_nodes_ = 0;
    std::string halt_reason_ = "not started";
    std::vector<security::NodeId> members_;
    TreeLogStatus status_;
    bool behind_ = false;  // io thread; mirrored into status_

    uint64_t last_maintain_ms_ = 0;
    uint64_t last_root_request_ms_ = 0;
};

}  // namespace nexus::tree
