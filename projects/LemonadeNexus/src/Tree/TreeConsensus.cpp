#include <LemonadeNexus/Tree/TreeConsensus.hpp>

#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Security/Consensus/HotStuffService.hpp>
#include <LemonadeNexus/Security/Consensus/HotStuffState.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>

#include <spdlog/spdlog.h>

#include <algorithm>

namespace nexus::tree {

namespace {

/// Pool upkeep runs at most this often.
constexpr uint64_t kMaintainIntervalMs = 5'000;
/// A missing root is requested at most this often.
constexpr uint64_t kRootRequestIntervalMs = 30'000;

std::string short_hex(const security::Digest& digest) {
    return crypto::to_hex(std::span<const uint8_t>(digest.data(), 8));
}

}  // namespace

TreeConsensus::TreeConsensus(TreeConsensusConfig config, PermissionTreeService& tree,
                             crypto::SodiumCryptoService& crypto,
                             std::filesystem::path log_directory)
    : config_(std::move(config)),
      tree_(tree),
      crypto_(crypto),
      log_(std::move(log_directory)),
      pool_(config_.pool_limits) {}

bool TreeConsensus::start() {
    const auto current = tree_.nodes_snapshot();
    if (log_.open(current) != TreeLog::OpenResult::Ok) {
        halt("the tree log is corrupt");
        return false;
    }
    const auto log_digest = compute_tree_digest(log_.state().nodes);
    if (compute_tree_digest(current) != log_digest) {
        if (log_.applied_height() >= log_.height()) {
            // Every logged block was applied, yet the tree differs: something
            // wrote the tree outside the log (for example with tree
            // operations off). Neither side is overwritten.
            halt("the persistent tree differs from the committed tree log");
            return false;
        }
        // The log is ahead of the tree: a block was logged but its apply did
        // not finish. The log is the committed state; restore the tree to it.
        if (!tree_.replace_all(log_.state().nodes, log_.state().committed) ||
            tree_.tree_digest() != log_digest) {
            halt("the persistent tree cannot be restored from the tree log");
            return false;
        }
        spdlog::warn("[TreeConsensus] restored the tree from the tree log at height {}",
                     log_.height());
    }
    if (log_.applied_height() != log_.height() && !log_.mark_applied(log_.height())) {
        halt("cannot record the applied tree log height");
        return false;
    }
    std::lock_guard lock(mutex_);
    halted_ = false;
    halt_reason_.clear();
    return true;
}

bool TreeConsensus::healthy() const {
    std::lock_guard lock(mutex_);
    return !halted_;
}

std::string TreeConsensus::halt_reason() const {
    std::lock_guard lock(mutex_);
    return halt_reason_;
}

void TreeConsensus::halt(const std::string& reason) {
    {
        std::lock_guard lock(mutex_);
        if (halted_ && !halt_reason_.empty() && halt_reason_ != "not started") return;
        halted_ = true;
        halt_reason_ = reason;
    }
    spdlog::error("[TreeConsensus] halted at tree log height {}: {}. Tree blocks are no longer "
                  "applied, voted for, or proposed here; the last committed tree stays served.",
                  log_.height(), reason);
}

void TreeConsensus::set_members(std::vector<security::NodeId> members) {
    std::lock_guard lock(mutex_);
    members_ = std::move(members);
}

bool TreeConsensus::is_member(const security::NodeId& node) const {
    std::lock_guard lock(mutex_);
    return std::find(members_.begin(), members_.end(), node) != members_.end();
}

TreeOpPolicy TreeConsensus::policy_for(const std::vector<security::NodeId>& members) const {
    TreeOpPolicy policy;
    policy.network_id = config_.network_id;
    policy.root_key = config_.root_key;
    for (const auto& member : members) {
        policy.trusted_submitters.push_back(
            "ed25519:" + crypto::to_base64(std::span<const uint8_t>(member.bytes.data(),
                                                                    member.bytes.size())));
    }
    return policy;
}

TreeOpAdmission TreeConsensus::submit(TreeOp sealed) {
    TreeOpAdmission out;
    std::vector<security::NodeId> members;
    {
        std::lock_guard lock(mutex_);
        if (halted_) {
            out.verdict = {TreeOpRefusal::Unavailable, "tree log halted: " + halt_reason_};
            return out;
        }
        members = members_;
    }
    if (std::find(members.begin(), members.end(), config_.self) == members.end()) {
        out.verdict = {TreeOpRefusal::Unavailable,
                       "this server is not a Tier 1 member; tree writes need a Tier 1 server"};
        return out;
    }
    out.verdict = tree_.validate_local_op(sealed, policy_for(members),
                                          config_.wall_clock_ms() / 1000);
    if (!out.verdict.ok()) return out;

    const auto signature = tree_op_signature_bytes(sealed);
    if (!signature) {
        out.verdict = {TreeOpRefusal::BadSignature, "op signature is not 64 bytes"};
        return out;
    }
    security::TreeOpSubmitMsg forward{encode_tree_op(sealed), *signature};
    auto ticket = std::make_shared<TreeOpTicket>(op_id_hex(sealed));
    switch (pool_.add(std::move(sealed), ticket)) {
        case TreeOpPool::Admit::Added:
            break;
        case TreeOpPool::Admit::Duplicate:
            out.verdict = {TreeOpRefusal::Replayed, "op already submitted"};
            return out;
        case TreeOpPool::Admit::Full:
        case TreeOpPool::Admit::AuthorLimit:
        case TreeOpPool::Admit::PrincipalLimit:
            out.verdict = {TreeOpRefusal::Unavailable, "the pending tree operation pool is full"};
            return out;
    }
    if (broadcast_) broadcast_(std::move(forward));
    out.ticket = std::move(ticket);
    return out;
}

void TreeConsensus::receive_forwarded(const security::TreeOpSubmitMsg& message,
                                      const security::NodeId& from) {
    if (!healthy()) return;
    auto op = decode_tree_op(message.encoded_op, message.signature);
    if (!op) {
        spdlog::debug("[TreeConsensus] dropped a malformed forwarded op from {}",
                      crypto::to_hex(std::span<const uint8_t>(from.bytes.data(), 8)));
        return;
    }
    if (pool_.contains(op_id_hex(*op))) return;
    std::vector<security::NodeId> members;
    {
        std::lock_guard lock(mutex_);
        members = members_;
    }
    if (members.empty()) return;
    const auto verdict =
        tree_.validate_local_op(*op, policy_for(members), config_.wall_clock_ms() / 1000);
    if (!verdict.ok()) {
        spdlog::debug("[TreeConsensus] dropped a forwarded op: {}", verdict.reason);
        return;
    }
    (void)pool_.add(std::move(*op), nullptr);
}

std::optional<TreeOpOutcome> TreeConsensus::status(const std::string& op_id) const {
    return pool_.status(op_id);
}

std::optional<TreeChainState> TreeConsensus::state_after(
    const security::HotStuffService& consensus, const security::Digest& block_digest) const {
    // Walk down to the committed boundary, collecting uncommitted tree blocks.
    // Committed blocks are already in the log.
    std::vector<security::Digest> uncommitted;
    security::Digest cursor = block_digest;
    while (cursor != consensus.genesis_digest()) {
        const security::Proposal* block = consensus.block(cursor);
        if (block == nullptr) return std::nullopt;
        if (block->height <= consensus.last_committed_height()) break;
        if (const auto* payload = consensus.block_payload(cursor);
            payload != nullptr && payload->kind == security::BlockPayloadKind::TreeBatch) {
            uncommitted.push_back(cursor);
        }
        cursor = block->parent_digest;
    }
    TreeChainState state = log_.state();
    for (auto it = uncommitted.rbegin(); it != uncommitted.rend(); ++it) {
        const security::Proposal* block = consensus.block(*it);
        const security::BlockPayload* payload = consensus.block_payload(*it);
        if (block->previous_state_root != state.root) return std::nullopt;
        const auto batch = decode_tree_batch(payload->body);
        if (!batch) return std::nullopt;
        const auto result = apply_certified_batch(state, *batch, block->timestamp_hint,
                                                  block->transitions_digest);
        if (!result.verdict.ok() || result.root != block->proposed_state_root) {
            return std::nullopt;
        }
    }
    return state;
}

std::optional<security::ProposedPayload> TreeConsensus::propose(
    const security::HotStuffService& consensus) {
    if (!healthy() || pool_.size() == 0) return std::nullopt;
    // The block extends the high certificate's block, as make_proposal does.
    const security::Digest parent_digest = consensus.state().high_qc.proposal_digest;
    const auto state = state_after(consensus, parent_digest);
    if (!state) return std::nullopt;
    const security::Proposal* parent = consensus.block(parent_digest);
    const uint64_t now = config_.wall_clock_ms();
    const uint64_t block_time = std::max({now, state->last_block_time_ms + 1,
                                          parent != nullptr ? parent->timestamp_hint + 1 : 0});
    if (block_time > now + kTreeBlockClockSkewMs) return std::nullopt;

    const auto selection = select_batch(crypto_, *state, pool_.pending(), block_time,
                                        policy_for(consensus.members()), kMaxTreeBatchOps,
                                        kTreeBatchWireBudget);
    if (selection.batch.ops.empty()) return std::nullopt;
    auto bytes = encode_tree_batch(selection.batch);
    if (!bytes) return std::nullopt;

    security::ProposedPayload out;
    out.payload.kind = security::BlockPayloadKind::TreeBatch;
    out.payload.body = std::move(*bytes);
    TreeChainState next = *state;
    const auto result = apply_certified_batch(next, selection.batch, block_time,
                                              security::block_payload_digest(out.payload));
    if (!result.verdict.ok()) return std::nullopt;
    out.previous_state_root = state->root;
    out.proposed_state_root = result.root;
    out.timestamp_hint = block_time;
    return out;
}

bool TreeConsensus::validate(const security::HotStuffService& consensus,
                             const security::Proposal& proposal,
                             const security::BlockPayload& payload) {
    if (!healthy() || payload.kind != security::BlockPayloadKind::TreeBatch) return false;
    const auto batch = decode_tree_batch(payload.body);
    if (!batch) return false;

    // The block time is binding (design A4): it advances past the parent and
    // stays within the skew bound of this node's clock.
    const uint64_t now = config_.wall_clock_ms();
    const uint64_t block_time = proposal.timestamp_hint;
    if (block_time > now + kTreeBlockClockSkewMs || block_time + kTreeBlockClockSkewMs < now) {
        spdlog::info("[TreeConsensus] vote withheld: block time {} is outside {} ms of this "
                     "clock ({})", block_time, kTreeBlockClockSkewMs, now);
        return false;
    }
    if (const security::Proposal* parent = consensus.block(proposal.parent_digest);
        parent != nullptr && block_time <= parent->timestamp_hint) {
        spdlog::info("[TreeConsensus] vote withheld: block time does not advance past the "
                     "parent");
        return false;
    }

    auto state = state_after(consensus, proposal.parent_digest);
    if (!state || proposal.previous_state_root != state->root) {
        spdlog::info("[TreeConsensus] vote withheld: the block does not extend this node's "
                     "tree state");
        return false;
    }
    const auto result = check_batch(crypto_, *state, *batch, block_time,
                                    proposal.transitions_digest,
                                    policy_for(consensus.members()));
    if (!result.verdict.ok()) {
        spdlog::info("[TreeConsensus] vote withheld: op {} of the batch is refused: {}",
                     result.failed_index, result.verdict.reason);
        return false;
    }
    if (result.root != proposal.proposed_state_root) {
        spdlog::info("[TreeConsensus] vote withheld: state root {} does not match {}",
                     short_hex(proposal.proposed_state_root), short_hex(result.root));
        return false;
    }
    return true;
}

void TreeConsensus::on_committed(const security::CommittedPayload& committed) {
    if (!healthy() || committed.payload == nullptr ||
        committed.payload->kind != security::BlockPayloadKind::TreeBatch) {
        return;
    }
    const security::Proposal& proposal = committed.proposal;
    const auto batch = decode_tree_batch(committed.payload->body);
    if (!batch) {
        halt("a committed tree batch does not decode");
        return;
    }
    TreeChainState next = log_.state();
    if (proposal.previous_state_root != next.root) {
        halt("a committed tree block does not follow this server's tree log; a tree block was "
             "missed");
        return;
    }
    const uint64_t block_time = proposal.timestamp_hint;
    const auto result =
        apply_certified_batch(next, *batch, block_time, proposal.transitions_digest);
    if (!result.verdict.ok() || result.root != proposal.proposed_state_root) {
        halt("a committed tree block does not replay to its state root");
        return;
    }

    TreeLogEntry entry;
    entry.height = log_.height() + 1;
    entry.block_time_ms = block_time;
    entry.batch = committed.payload->body;
    entry.ops_digest = proposal.transitions_digest;
    entry.previous_root = proposal.previous_state_root;
    entry.tree_digest = result.tree_digest;
    entry.state_root = result.root;
    const auto& c = committed.commit;
    entry.commit = nlohmann::json{
        {"epoch", c.epoch.underlying()},
        {"consensus_height", c.height.underlying()},
        {"view", c.view.underlying()},
        {"proposal_digest", crypto::to_base64(c.proposal_digest)},
        {"qc_digest", crypto::to_base64(c.qc_digest)},
        {"proposal", security::proposal_to_json(proposal)}};
    if (committed.proof.has_value()) {
        entry.commit["proof"] = security::commit_proof_to_json(*committed.proof);
    }
    // Commit, then apply: the block is durable in the log before the tree
    // changes, so a crash between the two is repaired from the log at start.
    if (!log_.append(entry, std::move(next))) {
        halt("cannot write the tree log");
        return;
    }
    const auto applied = tree_.apply_committed_ops(batch->ops, block_time / 1000);
    if (!applied.ok() || tree_.tree_digest() != result.tree_digest) {
        spdlog::warn("[TreeConsensus] the persistent tree did not follow block {} ({}); "
                     "restoring it from the log", entry.height, applied.reason);
        if (!tree_.replace_all(log_.state().nodes, log_.state().committed) ||
            tree_.tree_digest() != result.tree_digest) {
            halt("the persistent tree cannot follow the tree log");
            return;
        }
    }
    if (!log_.mark_applied(entry.height)) {
        spdlog::warn("[TreeConsensus] cannot record applied height {}; the next start "
                     "re-checks it", entry.height);
    }
    spdlog::info("[TreeConsensus] committed tree block {} ({} ops, root {})", entry.height,
                 batch->ops.size(), short_hex(entry.state_root));
    for (const auto& op : batch->ops) {
        pool_.settle(op_id_hex(op), TreeOpOutcome{TreeOpStatus::Committed, {}, entry.height});
    }
    revalidate_pool();
}

void TreeConsensus::revalidate_pool() {
    std::vector<security::NodeId> members;
    {
        std::lock_guard lock(mutex_);
        members = members_;
    }
    // Without a membership snapshot every op would look untrusted; wait for one.
    if (members.empty()) return;
    const auto policy = policy_for(members);
    const uint64_t now_sec = config_.wall_clock_ms() / 1000;
    for (const auto& op : pool_.pending()) {
        auto verdict = tree_.validate_local_op(op, policy, now_sec);
        if (!verdict.ok()) {
            pool_.settle(op_id_hex(op), TreeOpOutcome{TreeOpStatus::Refused, std::move(verdict), 0});
        }
    }
}

void TreeConsensus::maintain() {
    const uint64_t now = config_.wall_clock_ms();
    if (now - last_maintain_ms_ < kMaintainIntervalMs && last_maintain_ms_ != 0) return;
    last_maintain_ms_ = now;
    if (!healthy()) return;
    revalidate_pool();
    if (!root_request_ || config_.root_key.empty() || log_.state().nodes.contains("root") ||
        !is_member(config_.self) || now - last_root_request_ms_ < kRootRequestIntervalMs) {
        return;
    }
    const auto pending = pool_.pending();
    if (std::any_of(pending.begin(), pending.end(), [](const TreeOp& op) {
            return op.kind == TreeOpKind::EstablishRoot;
        })) {
        return;
    }
    last_root_request_ms_ = now;
    root_request_();
}

}  // namespace nexus::tree
