#pragma once

#include <LemonadeNexus/Core/IService.hpp>
#include <LemonadeNexus/Tree/ITreeProvider.hpp>
#include <LemonadeNexus/Tree/TreeOps.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>

#include <nlohmann/json.hpp>

#include <functional>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>

namespace nexus::tree {

/// Manages the hierarchical permission tree.
/// Nodes are cached in-memory and persisted via FileStorageService.
/// Signatures are verified through SodiumCryptoService.
class PermissionTreeService : public core::IService<PermissionTreeService>,
                               public ITreeProvider<PermissionTreeService> {
    friend class core::IService<PermissionTreeService>;
    friend class ITreeProvider<PermissionTreeService>;

public:
    PermissionTreeService(storage::FileStorageService& storage,
                           crypto::SodiumCryptoService& crypto);

    /// Drop the tree from memory and stop writing tree files: every later
    /// write path fails without touching storage until start() loads the
    /// tree again. Reads see an empty tree. A server that leaves Tier 1
    /// closes its tree before it deletes the files (TreeRole.hpp). Safe to
    /// call more than once. Thread-safe.
    void close();

    /// False from close() until the next start(): the write paths refuse.
    /// Thread-safe.
    [[nodiscard]] bool is_open() const;

    /// Bootstrap the root node if none exists.  Called during join when
    /// the tree is empty — the first authenticated user becomes root.
    /// Returns true if created, false if root already exists.
    bool bootstrap_root(const TreeNode& root_node);

    /// Insert a node directly during the join flow.
    /// Bypasses the strict delta permission/signature checks because
    /// the join handler has already authenticated the caller.
    /// Returns true on success.
    bool insert_join_node(const TreeNode& node);

    /// Update a node directly, bypassing delta signing.
    /// The caller (HTTP handler) is responsible for permission checks.
    bool update_node_direct(const std::string& node_id, const TreeNode& updated);

    /// Atomically update only the listen_endpoint field of a node.
    /// Reads the current node, sets listen_endpoint, and persists — all under
    /// a single lock.  This avoids the TOCTOU race of read → modify → write.
    bool update_node_endpoint(const std::string& node_id,
                               const std::string& new_endpoint);

    /// Delete a node directly, bypassing delta signing.
    /// The caller (HTTP handler) is responsible for permission checks.
    bool delete_node_direct(const std::string& node_id);

    /// True if any surviving node has this management pubkey as its owner
    /// (node.mgmt_pubkey). Used by the delete path to avoid blocklisting an
    /// owner's key when they delete one of their own (self-owned) devices — the
    /// owner key still owns their group and sibling endpoints.
    [[nodiscard]] bool is_mgmt_pubkey_in_use(const std::string& mgmt_pubkey) const;

    /// Grant an assignment (pubkey + permissions) on a node.
    /// Idempotent: no-op if the pubkey already has an assignment.
    /// Used after Ed25519 key registration to give new keys add_child on root.
    bool grant_assignment(const std::string& node_id, const Assignment& assignment);

    /// True when `signer` holds `admin` on `node_id` or on one of its
    /// ancestors: an admin of a group administers the group's devices (reads
    /// their full assignment lists, removes them). Permissions are otherwise
    /// not inherited.
    [[nodiscard]] bool administers(std::string_view signer, std::string_view node_id) const;

    /// Outcome of an administrative assignment change, an invite acceptance,
    /// or a move.
    enum class AssignmentChange { Applied, NotFound, Forbidden, Invalid, Conflict, StorageError };

    /// Set exactly the permissions `principal` holds on `node_id`, replacing
    /// any entries it had (an empty list removes it). The same rules as an
    /// assignment delta apply: `signer` must hold `admin` on the node or an
    /// ancestor, and a principal given any permission must have joined inside
    /// that admin's subtree. A signer cannot change its own entry on the node
    /// that grants its admin, so no admin locks itself out. Unknown
    /// permission names are Invalid. A member may remove its own entry from a
    /// group it entered through an invite (see rules::assignment_change_refusal).
    /// `reason` receives the refusal text.
    [[nodiscard]] AssignmentChange set_assignment(const std::string& node_id,
                                                  std::string_view signer,
                                                  std::string_view principal,
                                                  const std::vector<std::string>& permissions,
                                                  std::string& reason);

    /// Direct-write form of the AcceptInvite tree operation: make `invitee` a
    /// member of `target_id` with exactly `permissions`, as invited by
    /// `inviter`. The caller has consumed the link token; this checks
    /// rules::invite_acceptance_refusal against the current tree and then
    /// applies the same plan as the tree operation. No other node changes.
    /// `reason` receives the refusal text. Thread-safe.
    [[nodiscard]] AssignmentChange accept_invite(const std::string& target_id,
                                                 std::string_view invitee,
                                                 std::string_view inviter,
                                                 const std::vector<std::string>& permissions,
                                                 std::string& reason);

    /// Direct-write form of the MoveNode tree operation: move `node_id` under
    /// `new_parent_id` for `signer`, after rules::move_refusal, with the same
    /// plan as the tree operation (the node keeps its id, addresses, and own
    /// assignments; see plan_op). `reason` receives the refusal text.
    /// Thread-safe.
    [[nodiscard]] AssignmentChange move_node(const std::string& node_id,
                                             const std::string& new_parent_id,
                                             std::string_view signer, std::string& reason);

    /// The connect rule (rules::endpoint_may_connect) for endpoint
    /// `from_node_id`, acting as `principal`, to `to_node_id`. False when
    /// either node is missing. Thread-safe.
    [[nodiscard]] bool may_connect(std::string_view principal, std::string_view from_node_id,
                                   std::string_view to_node_id) const;

    // --- Tree operations (see TreeOps.hpp) ---

    /// Validate `op` against the current tree, `policy`, and this service's
    /// committed op ids at `block_time_sec`, without applying it. Under
    /// consensus this is the submitting server's pre-check; the block's
    /// validation decides. Thread-safe.
    [[nodiscard]] TreeOpVerdict validate_local_op(const TreeOp& op, const TreeOpPolicy& policy,
                                                  uint64_t block_time_sec) const;

    /// Validate `op` as validate_local_op does and, when it is accepted, apply
    /// it through apply_op, both under one lock so no other write intervenes.
    /// Local application without consensus: single-process tests and tools
    /// only. The server never calls it; with tree operations on it applies ops
    /// from committed blocks only (TreeConsensus). Thread-safe.
    [[nodiscard]] TreeOpVerdict submit_local_op(const TreeOp& op, const TreeOpPolicy& policy,
                                                uint64_t block_time_sec);

    /// The one mutation path for tree operations: write the nodes plan_op
    /// computes (each with its incremented version), keep the identifier
    /// index in sync, and record the op id and statement id as committed
    /// (persisted, so replay stays refused after a restart). An op from a
    /// signed delta is also appended to the delta log and offered to the
    /// retention sink, as do_apply_delta does. Precondition: the op passed
    /// validate_op against the current tree. A refused plan changes nothing.
    /// A storage failure can leave an op that writes several nodes partly
    /// persisted; under consensus the tree log restores the committed state at
    /// the next start (TreeConsensus). Thread-safe.
    [[nodiscard]] TreeOpVerdict apply_op(const TreeOp& op);

    /// Apply the ops of one committed block in order, as apply_op does, under
    /// one lock, then prune committed ids to `block_time_sec` and persist them
    /// once. Stops at the first op that does not apply and returns its
    /// verdict. Thread-safe.
    [[nodiscard]] TreeOpVerdict apply_committed_ops(const std::vector<TreeOp>& ops,
                                                    uint64_t block_time_sec);

    /// Set the function called after apply_op, apply_committed_ops, or
    /// submit_local_op removed nodes. It receives each removed node as it was
    /// before the op, runs on the thread that applied the op, and runs after
    /// the tree lock is released, so it may read the tree. Every server that
    /// applies a committed block calls it, so per-server cleanup of a deleted
    /// node runs everywhere. replace_all never calls it: a restore or merge is
    /// not a delete. An empty function clears it. Thread-safe.
    void set_removed_nodes_hook(std::function<void(const std::vector<TreeNode>&)> hook);

    /// A copy of every node, keyed by id. Thread-safe.
    [[nodiscard]] rules::NodeMap nodes_snapshot() const;

    /// compute_tree_digest of the current tree. Thread-safe.
    [[nodiscard]] security::Digest tree_digest() const;

    /// Replace the whole tree with `nodes` and the committed ids with
    /// `committed`: persist every changed node, remove every stored node
    /// `nodes` does not hold, and rebuild the identifier index. The tree log
    /// uses it to restore committed state after an interrupted apply. False
    /// when a write failed; the in-memory tree is `nodes` either way.
    /// Thread-safe.
    [[nodiscard]] bool replace_all(const rules::NodeMap& nodes, const CommittedOpIds& committed);

    // --- Delta statement authorization (shared with record acceptance) ---

    /// Outcome of evaluating a delta statement against the current tree.
    /// ContextMissing means the check node (parent for create_node, target
    /// otherwise) or its assignment context is absent — the statement cannot
    /// be evaluated yet; it is not an authorization decision.
    enum class DeltaAuthorization { Authorized, Denied, ContextMissing };

    /// The permission an operation requires. None for unknown operations.
    [[nodiscard]] static acl::Permission required_permission_for(
            std::string_view operation);

    /// Evaluate a delta statement's authorization against the current tree
    /// with the same rules do_apply_delta enforces: the signer must hold the
    /// operation-derived permission via an assignment on the check node
    /// (parent for create_node, target otherwise). No certificate is part of
    /// the author contract.
    [[nodiscard]] DeltaAuthorization authorize_delta_statement(
            std::string_view operation,
            std::string_view target_node_id,
            const nlohmann::json& node_data,
            std::string_view signer_pubkey) const;

    /// Retention sink for locally applied deltas (record transfer only —
    /// applying the delta is independent of retention). The sink receives the
    /// signed statement with a precomputed record hash; refusing it does not
    /// roll back the applied mutation.
    void set_delta_retention_sink(std::function<bool(const storage::FileStorageService::RetainedDelta&)> sink);
    [[nodiscard]] bool retain_applied_delta(const TreeDelta& delta);

    // --- Endpoint identifier resolution (routing layer) ---

    /// Re-derive the canonical identifier from a node's inputs (pure).
    [[nodiscard]] std::string derive_endpoint_identifier(const TreeNode& node) const;

    /// True iff the stored endpoint_identifier matches the re-derived value.
    [[nodiscard]] bool validate_identifier_binding(const TreeNode& node) const;

    /// Resolve an endpoint identifier to its node via the reverse index.
    [[nodiscard]] std::optional<TreeNode> resolve_by_identifier(
            std::string_view identifier) const;

    /// Descendants beneath `root_parent_id` (excluding it). Own cycle guard +
    /// depth/node caps so a malformed parent_id loop can't wedge the tree.
    /// Callers MUST still filter per node — permissions are not inherited.
    [[nodiscard]] std::vector<TreeNode> collect_subtree(
            std::string_view root_parent_id,
            std::size_t max_depth = 32,
            std::size_t max_nodes = 4096) const;

    /// True iff `node_id` lies strictly beneath `ancestor_id`.
    [[nodiscard]] bool is_descendant_of(std::string_view node_id,
                                        std::string_view ancestor_id) const;

    /// Routing-layer authorization chokepoint. Returns the target node only if
    /// the identifier resolves, its binding validates, and the connect rule
    /// (may_connect) allows the caller's node to reach it: the target is in the
    /// caller's parent-group subtree with a ConnectPrivate or ConnectShared
    /// grant on it, or a group membership from an accepted invite covers the
    /// pair. nullopt otherwise. caller_pubkey must be normalized.
    [[nodiscard]] std::optional<TreeNode> resolve_authorized(
            std::string_view caller_pubkey,
            std::string_view caller_node_id,
            std::string_view identifier) const;

    // IService
    void on_start();
    void on_stop();
    [[nodiscard]] static constexpr std::string_view name() { return "PermissionTreeService"; }

    // ITreeProvider
    [[nodiscard]] bool do_apply_delta(const TreeDelta& delta);
    [[nodiscard]] std::optional<TreeNode> do_get_node(std::string_view node_id) const;
    [[nodiscard]] std::vector<TreeNode> do_get_children(std::string_view parent_id) const;
    [[nodiscard]] bool do_validate_signature_chain(std::string_view node_id) const;
    [[nodiscard]] bool do_check_permission(std::string_view signer_pubkey,
                                            std::string_view node_id,
                                            acl::Permission perm) const;
    [[nodiscard]] crypto::Hash256 do_get_tree_hash() const;
    [[nodiscard]] std::vector<TreeNode> do_get_nodes_by_type(NodeType type) const;

private:
    /// Persist a tree node to storage wrapped in a SignedEnvelope.
    bool persist_node(const TreeNode& node);

    /// Remove a tree node from storage.
    bool remove_node(std::string_view node_id);

    /// The AssignmentChange for a refused rule.
    [[nodiscard]] static AssignmentChange change_for(rules::AssignmentRefusal refusal);

    /// Plan `op` with plan_op and persist its writes without consensus,
    /// keeping each node's version (the direct paths do not maintain it).
    /// The caller holds mutex_ and has already checked the op's rules. Only
    /// for ops whose plan writes nodes and removes none.
    [[nodiscard]] AssignmentChange apply_planned_direct_locked(const TreeOp& op,
                                                               std::string& reason);

    /// apply_op with mutex_ held. Appends each node the op removes, as it was
    /// before the op, to `removed`.
    [[nodiscard]] TreeOpVerdict apply_op_locked(const TreeOp& op, std::vector<TreeNode>& removed);

    /// Call the removed-nodes hook with `removed`, unless it is empty. Caller
    /// must not hold mutex_: the hook may read the tree.
    void notify_removed(const std::vector<TreeNode>& removed) const;

    mutable std::mutex removed_hook_mtx_;
    std::function<void(const std::vector<TreeNode>&)> removed_hook_;

    /// Append an applied delta to the delta log and offer it to the retention
    /// sink. Neither failure rolls back the applied mutation. Returns the log
    /// sequence number (0 when the append failed). Caller holds mutex_.
    uint64_t record_applied_delta_locked(const TreeDelta& delta);

    std::function<bool(const storage::FileStorageService::RetainedDelta&)> delta_retention_sink_;

    /// Evict stale entries from the replay cache.
    void evict_replay_cache();

    storage::FileStorageService& storage_;
    crypto::SodiumCryptoService& crypto_;
    mutable std::mutex           mutex_;
    std::unordered_map<std::string, TreeNode> nodes_;

    // Reverse index: endpoint_identifier -> node_id. Kept in sync with nodes_ in
    // on_start / insert_join_node / update_node_direct / delete_node_direct /
    // apply_op / replace_all so resolve_by_identifier is O(1) and new colliding registrations
    // are rejected.
    std::unordered_map<std::string, std::string> identifier_index_;

    // Replay protection: SHA-256 hash of canonical delta → timestamp of receipt
    std::unordered_map<std::string, uint64_t> recent_deltas_;

    // Op ids and statement ids applied through apply_op (tree operations).
    // Persisted in tree/committed-ops.json after every apply.
    CommittedOpIds committed_ops_;
    // The stored record exists but does not parse: the committed ids are
    // unknown, so validate_local_op and submit_local_op refuse every op.
    bool committed_ops_unreadable_ = false;

    // False after close(): persist_node, remove_node, the delta log append,
    // and the committed-ids write refuse, so a request that raced the close
    // cannot recreate a tree file. Guarded by mutex_. True from construction
    // so a tree used without start() keeps its existing behavior.
    bool holds_files_ = true;

    /// Write committed_ops_ to tree/committed-ops.json. Caller holds mutex_.
    bool persist_committed_ops_locked() const;
    /// persist_committed_ops_locked when `verdict` is ok; logs a failure.
    /// Caller holds mutex_.
    void persist_committed_ops_after(const TreeOpVerdict& verdict);
    /// Load tree/committed-ops.json into committed_ops_. Caller holds mutex_.
    void load_committed_ops_locked();
};

} // namespace nexus::tree
