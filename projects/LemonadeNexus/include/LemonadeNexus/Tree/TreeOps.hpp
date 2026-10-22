#pragma once

// Tree operations (design: docs/Design-Tree-Consensus-and-Storage-Key.md,
// Part A, Phase 1).
//
// A TreeOp is one signed change to the permission tree. validate_op decides
// deterministically whether an op is acceptable against a given tree state;
// plan_op computes the exact node writes it makes. Both depend only on their
// arguments: the op, the tree state, the supplied block time, and the set of
// committed op ids. Neither reads a clock or any local observation, so every
// machine that holds the same inputs reaches the same result.
//
// Phase 1 applies ops locally only (PermissionTreeService::submit_local_op),
// behind ServerConfig::tree_ops_enabled. Consensus ordering, the tree log, and
// replication are later phases. In Phase 1 every op is wrapped and signed by
// the server that received the request ("submitter"); the end-user authority
// comes from the op's principal and, where one exists, the statement the
// principal signed (a TreeDelta or a join challenge).

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>
#include <LemonadeNexus/Tree/TreeRules.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace nexus::crypto { class SodiumCryptoService; }

namespace nexus::tree {

/// Encoding version of TreeOp. validate_op refuses any other value.
inline constexpr uint32_t kTreeOpVersion = 1;

/// Domain of the canonical op encoding; op_id is SHA-256 over that encoding.
inline constexpr std::string_view kTreeOpDomain = "lemonade-nexus/tree-op:v1";
/// Domain of the bytes the submitter signs (they carry op_id only).
inline constexpr std::string_view kTreeOpSignatureDomain = "lemonade-nexus/tree-op-signature:v1";
/// Domain of a wrapped statement's replay id (delta or join challenge).
inline constexpr std::string_view kTreeOpStatementDomain = "lemonade-nexus/tree-op-statement:v1";

/// Freshness, relative to the block time: an op is fresh when its signed time
/// is at most kTreeOpMaxAgeSec older and at most kTreeOpMaxFutureSec newer
/// than the block time. These are the delta freshness bounds with the local
/// wall clock replaced by the block time.
inline constexpr uint64_t kTreeOpMaxAgeSec = 300;
inline constexpr uint64_t kTreeOpMaxFutureSec = 60;

/// Largest canonical op encoding validate_op accepts. Equal to the planned
/// tree-batch cap (design A3), so any valid op fits in one consensus block.
inline constexpr std::size_t kMaxTreeOpEncodedBytes = 48000;

/// What an op changes.
enum class TreeOpKind : uint16_t {
    CreateNode    = 1,  ///< add one node (target = new node id)
    UpdateFields  = 2,  ///< replace one node's fields; identity fields stay fixed
    SetAssignment = 3,  ///< set exactly the permissions one principal holds on the target
    DeleteNode    = 4,  ///< remove the target and the link grants that named its key
    Join          = 5,  ///< device join (POST /api/join), applied as one atomic step
};

/// Where the principal's authority for an op comes from.
enum class TreeOpSource : uint16_t {
    /// The submitter authenticated the principal's session (bearer token).
    /// Nothing the principal signed travels with the op.
    Session = 1,
    /// The principal signed a TreeDelta (POST /api/tree/delta); the op carries
    /// it and validate_op verifies it.
    Delta   = 2,
    /// The device signed the submitter's join challenge; the op carries the
    /// challenge and signature and validate_op verifies them.
    Device  = 3,
};

/// The join request a submitter wraps in a Join op. The device signature
/// covers only the challenge (the existing /api/join contract); the other
/// fields are the submitter's request parameters.
struct JoinStatement {
    std::string device_pubkey;        ///< "ed25519:<base64>", the authenticated identity
    std::string challenge;            ///< base64 challenge the submitter issued
    std::string challenge_signature;  ///< base64 Ed25519 signature over the raw challenge bytes
    bool        hostname_present{false};
    std::string hostname;             ///< used when hostname_present
    bool        mesh_pubkey_present{false};
    std::string mesh_pubkey;          ///< used when mesh_pubkey_present
    std::string cpu_id;               ///< self-reported label seed
    std::string net_mac;              ///< self-reported label seed
    std::string region;
    bool        is_inference{false};
    std::string link_group_id;        ///< non-empty for a linked join (device-link token)
    std::string link_owner_pubkey;    ///< owner key from the link token
    /// Tunnel address the submitter's IPAM allocated ("a.b.c.d/32" inside
    /// 10.64.0.0/10). Empty means "no address change" (used for a dry run
    /// before allocation). Not re-derived: see the Phase 1 limits in
    /// docs/Configuration.md.
    std::string tunnel_ip;
};

/// Kind-specific op content. Which fields are encoded, validated, and applied
/// depends on (kind, source); the others must stay empty and are ignored.
struct TreeOpBody {
    TreeOpSource             source{TreeOpSource::Session};
    TreeNode                 node;                    ///< Session CreateNode / UpdateFields
    TreeDelta                delta;                   ///< Delta source
    std::string              assignment_principal;    ///< SetAssignment
    std::vector<std::string> assignment_permissions;  ///< SetAssignment
    JoinStatement            join;                    ///< Join
};

/// One signed change to the tree.
struct TreeOp {
    uint32_t            version{kTreeOpVersion};
    security::NetworkId network_id{};     ///< binds the op to one network
    TreeOpKind          kind{TreeOpKind::CreateNode};
    std::string         target;           ///< node id the op creates or changes
    /// The target's version the author saw. 0 when the op creates the target.
    uint64_t            base_version{0};
    /// Unix seconds the op (or its wrapped statement) was signed. Freshness is
    /// judged against the block time, never against a local clock.
    uint64_t            signed_at{0};
    /// Submitter-chosen random bytes. Two requests with the same content in
    /// the same second are two ops with distinct op ids; replay of one op is
    /// still refused. A wrapped statement's own replay id does not include it.
    std::array<uint8_t, 16> nonce{};
    /// Identity whose tree permissions authorize the op ("ed25519:<base64>").
    std::string         principal;
    TreeOpBody          body;
    /// Submitter key that signed the op ("ed25519:<base64>").
    std::string         author;
    /// SHA-256 of the canonical encoding without the signature. Set by
    /// sign_tree_op; validate_op recomputes and compares it.
    crypto::Hash256     op_id{};
    /// Base64 Ed25519 signature by `author` over the domain-separated op_id.
    std::string         signature;
    /// Server that received the op. For routing only: unsigned, not in op_id.
    std::string         submitted_by;
};

/// Who may sign ops for this tree, and which network the tree belongs to.
struct TreeOpPolicy {
    security::NetworkId      network_id{};
    /// Submitter keys ("ed25519:<base64>"), compared by key bytes.
    std::vector<std::string> trusted_submitters;
};

/// Read-only view of a tree state that validate_op and plan_op evaluate.
/// Holds references: `nodes` and `policy` must outlive the view.
class TreeState {
public:
    using NodeMap = rules::NodeMap;

    TreeState(const NodeMap& nodes, const TreeOpPolicy& policy)
        : nodes_(nodes), policy_(policy) {}

    /// The node with this id, or nullptr.
    [[nodiscard]] const TreeNode* find(std::string_view id) const;
    [[nodiscard]] const NodeMap& nodes() const { return nodes_; }
    [[nodiscard]] const TreeOpPolicy& policy() const { return policy_; }

private:
    const NodeMap&      nodes_;
    const TreeOpPolicy& policy_;
};

/// Op ids and wrapped-statement ids that are already committed. Replay is
/// checked against this set, never against a clock cache. Not thread-safe;
/// the owner serializes access.
class CommittedOpIds {
public:
    /// True when `id` (lowercase hex) is committed.
    [[nodiscard]] bool contains(const std::string& id) const;
    /// Record `id` with the signed time of the op that committed it.
    void insert(const std::string& id, uint64_t signed_at);
    /// Drop ids whose op was signed before `cutoff`. Only safe for ids that
    /// can no longer pass freshness, so the caller derives `cutoff` from the
    /// block time minus the freshness window and a margin.
    void prune_signed_before(uint64_t cutoff);
    [[nodiscard]] std::size_t size() const { return ids_.size(); }

private:
    std::unordered_map<std::string, uint64_t> ids_;
};

/// Why validate_op or apply refused an op. None means accepted.
enum class TreeOpRefusal : uint8_t {
    None,
    Malformed,           ///< bad version, kind/source pair, field, or address format
    WrongNetwork,        ///< network_id differs from the tree's network
    Oversize,            ///< canonical encoding exceeds kMaxTreeOpEncodedBytes
    BadOpId,             ///< op_id is not the digest of the encoding
    UntrustedSubmitter,  ///< author is not a trusted submitter
    BadSignature,        ///< author signature does not verify
    BadStatement,        ///< wrapped delta or join statement does not verify or match
    Stale,               ///< signed time outside the freshness window of the block time
    Replayed,            ///< op id or statement id already committed
    NotFound,            ///< target (or required context node) does not exist
    AlreadyExists,       ///< create target already exists
    StaleBaseVersion,    ///< base_version differs from the target's version
    Forbidden,           ///< principal lacks the required permission or admin rule
    Invalid,             ///< invalid assignment principal or permission name
    ContentRefused,      ///< delta content rules refuse the change
    Conflict,            ///< endpoint identifier, mesh key, or join placement conflict
    StorageError,        ///< local persistence failed while applying
};

/// Outcome of validation or application. `reason` is a human-readable
/// explanation; for SetAssignment refusals it is the text the assignment API
/// returns.
struct TreeOpVerdict {
    TreeOpRefusal refusal{TreeOpRefusal::None};
    std::string   reason;

    [[nodiscard]] bool ok() const { return refusal == TreeOpRefusal::None; }
};

/// The node writes an accepted op makes. Writes carry their new versions;
/// both lists are sorted by node id.
struct TreeOpEffect {
    std::vector<TreeNode>    writes;
    std::vector<std::string> removals;
};

/// Canonical encoding of everything except `op_id`, `signature`, and
/// `submitted_by` (layout: CanonicalEncoder, domain kTreeOpDomain).
[[nodiscard]] std::vector<uint8_t> encode_tree_op(const TreeOp& op);

/// SHA-256 over encode_tree_op(op).
[[nodiscard]] crypto::Hash256 compute_op_id(const TreeOp& op);

/// Lowercase hex of op.op_id.
[[nodiscard]] std::string op_id_hex(const TreeOp& op);

/// Replay id of the statement the op wraps (lowercase hex): the delta for the
/// Delta source, the device key and challenge for the Device source. nullopt
/// for the Session source.
[[nodiscard]] std::optional<std::string> statement_id_hex(const TreeOp& op);

/// Set `op.author` to `key`'s public key, then `op.op_id`, then sign. Call
/// after every other signed field is final.
void sign_tree_op(crypto::SodiumCryptoService& crypto, TreeOp& op,
                  const crypto::Ed25519Keypair& key);

/// The node id a join derives from the device key: the first 32 hex digits of
/// SHA-256 over the raw 32-byte key (the Ed25519 auth provider's user id).
/// Empty when `device_pubkey` is not an "ed25519:" key that decodes to 32 bytes.
[[nodiscard]] std::string derive_join_node_id(crypto::SodiumCryptoService& crypto,
                                              std::string_view device_pubkey);

/// Decide whether `op` is acceptable against `state` at `block_time_sec`.
/// Checks, in order: format and kind/source pair, network, size, op id,
/// trusted submitter and signature, freshness against the block time, replay
/// against `committed`, the wrapped statement, target existence and
/// base_version, the principal's permission and the content rules shared with
/// the delta and assignment paths (rules::), and finally that plan_op succeeds.
/// Deterministic: the same arguments give the same verdict on every machine.
[[nodiscard]] TreeOpVerdict validate_op(crypto::SodiumCryptoService& crypto,
                                        const TreeOp& op, const TreeState& state,
                                        uint64_t block_time_sec,
                                        const CommittedOpIds& committed);

/// The node writes `op` makes against `nodes`, without authentication or
/// permission checks (validate_op performs those). Structural preconditions
/// that the writes depend on (target present or absent, identifier and mesh
/// key uniqueness, join placement) are checked here, so a refused plan leaves
/// the tree unchanged. Every written node's version is its previous version
/// plus one (1 for a new node). Deterministic.
[[nodiscard]] TreeOpVerdict plan_op(const TreeOp& op, const TreeState::NodeMap& nodes,
                                    TreeOpEffect& effect);

}  // namespace nexus::tree
