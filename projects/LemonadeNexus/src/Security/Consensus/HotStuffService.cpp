#include <LemonadeNexus/Security/Consensus/HotStuffService.hpp>

#include <LemonadeNexus/Security/Consensus/QuorumValidation.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <algorithm>
#include <stdexcept>
#include <utility>

namespace nexus::security {

HotStuffService::HotStuffService(HotStuffConfig config,
                                 EpochVoteKey own_vote_key,
                                 IConsensusStore& store)
    : config_(std::move(config)), own_key_(std::move(own_vote_key)), store_(store) {
    if (config_.leader_order.empty()) {
        throw std::invalid_argument("HotStuffService: empty leader order");
    }
    if (config_.quorum == 0) {
        throw std::invalid_argument("HotStuffService: zero quorum");
    }

    // The epoch starts from the genesis anchor.
    high_qc_ = genesis_qc();
    locked_qc_ = high_qc_;

    const auto stored = store_.load(config_.epoch);
    if (const auto* result = std::get_if<IConsensusStore::LoadResult>(&stored)) {
        if (*result == IConsensusStore::LoadResult::Absent) {
            // Fresh epoch: no vote ever left this node.
            synced_ = true;
            return;
        }
        // Corrupt safety state can hide a vote already cast. The service
        // fails permanently; Corrupt is never treated as fresh (11.12).
        failed_ = true;
        return;
    }

    // Restart inside a live epoch: adopt the stored floor, then require an
    // external quorum-certified sync before any vote (11.12).
    const auto& state = std::get<HotStuffState>(stored);
    if (state.epoch != config_.epoch || state.consensus_ruleset != config_.consensus_ruleset) {
        failed_ = true;
        return;
    }
    last_voted_view_ = state.last_voted_view;
    high_qc_ = state.high_qc;
    locked_qc_ = state.locked_qc;
    current_view_ = std::max(high_qc_.view + 1, last_voted_view_ + 1);
    synced_ = false;
}

void HotStuffService::sync_to_certified(View certified_view_floor) {
    // A corrupt store stays unusable; sync cannot revive it.
    if (failed_) return;
    last_voted_view_ = std::max(last_voted_view_, certified_view_floor);
    current_view_ = std::max(current_view_, certified_view_floor + 1);
    synced_ = true;
}

HotStuffState HotStuffService::state() const {
    HotStuffState state;
    state.epoch = config_.epoch;
    state.consensus_ruleset = config_.consensus_ruleset;
    state.last_voted_view = last_voted_view_;
    state.high_qc = high_qc_;
    state.locked_qc = locked_qc_;
    return state;
}

QuorumCertificate HotStuffService::genesis_qc() const {
    QuorumCertificate certificate{};
    certificate.qc_format_version = constants::kQcFormatVersion;
    certificate.consensus_ruleset = config_.consensus_ruleset;
    certificate.network_id = config_.network_id;
    certificate.epoch = config_.epoch;
    certificate.height = 0;
    certificate.view = 0;
    certificate.proposal_digest = config_.genesis_digest;
    return certificate;
}

// Exactly the synthetic genesis form passes without signatures. Any other
// empty-signer certificate must fail normal validation.
bool HotStuffService::is_genesis_justify(const QuorumCertificate& justify) const {
    return justify.signers.empty() && justify.view == 0 && justify.height == 0 &&
           justify.proposal_digest == config_.genesis_digest &&
           justify.qc_format_version == constants::kQcFormatVersion &&
           justify.consensus_ruleset == config_.consensus_ruleset &&
           justify.network_id == config_.network_id && justify.epoch == config_.epoch;
}

void HotStuffService::advance_high_qc(const QuorumCertificate& certificate) {
    if (certificate.view > high_qc_.view) high_qc_ = certificate;
}

std::optional<ConsensusFailure> HotStuffService::view_window_failure(View view) const {
    const View window = constants::kMaxFutureViewDistance;
    if (view + window < current_view_) return ConsensusFailure::StaleView;
    if (view > current_view_ + window) return ConsensusFailure::ViewTooFar;
    return std::nullopt;
}

std::size_t HotStuffService::pending_count() const {
    std::size_t count = 0;
    for (const auto& [digest, record] : blocks_) {
        if (record.proposal.height > last_committed_height_) ++count;
    }
    return count;
}

// Walks parent digests from the proposal through known blocks. Locked at
// genesis means every proposal extends the lock.
bool HotStuffService::extends_locked(const Proposal& proposal) const {
    const Digest& locked = locked_qc_.proposal_digest;
    if (locked == config_.genesis_digest) return true;

    const Digest* parent = &proposal.parent_digest;
    while (true) {
        if (*parent == locked) return true;
        if (*parent == config_.genesis_digest) return false;
        const auto it = blocks_.find(*parent);
        if (it == blocks_.end()) return false;
        parent = &it->second.proposal.parent_digest;
    }
}

ProposalResult HotStuffService::receive_proposal(const Proposal& proposal,
                                                 const QuorumCertificate& justify) {
    ProposalResult result;

    // 1. Nothing is acted on before restart sync or after store corruption.
    if (failed_ || !synced_) {
        result.rejected = ConsensusFailure::NotSynced;
        return result;
    }

    // 2. Header binding.
    if (proposal.security_ruleset != config_.security_ruleset ||
        proposal.consensus_ruleset != config_.consensus_ruleset) {
        result.rejected = ConsensusFailure::RulesetMismatch;
        return result;
    }
    if (proposal.network_id != config_.network_id) {
        result.rejected = ConsensusFailure::NetworkMismatch;
        return result;
    }
    if (proposal.epoch != config_.epoch) {
        result.rejected = ConsensusFailure::EpochMismatch;
        return result;
    }

    // 3. The proposal must commit to the exact justify it ships with.
    if (qc_digest(justify) != proposal.justify_qc_digest) {
        result.rejected = ConsensusFailure::JustifyInvalid;
        return result;
    }

    // 4. REQUIRE_PARENT_QC: the parent IS the justified block.
    if (proposal.parent_digest != justify.proposal_digest) {
        result.rejected = ConsensusFailure::ParentQcMismatch;
        return result;
    }

    // 5. The justify is evidence. It validates, or it is the genesis anchor.
    if (!is_genesis_justify(justify)) {
        const QcValidationContext context{config_.consensus_ruleset, config_.network_id,
                                          config_.epoch, config_.quorum};
        if (validate_quorum_certificate(justify, context, config_.vote_keys)) {
            result.rejected = ConsensusFailure::JustifyInvalid;
            return result;
        }
    }

    // 6. A valid justify proves the network reached its view.
    current_view_ = std::max(current_view_, justify.view + 1);
    if (proposal.view < current_view_) {
        result.rejected = ConsensusFailure::StaleView;
        return result;
    }
    if (proposal.view > current_view_ + constants::kMaxFutureViewDistance) {
        result.rejected = ConsensusFailure::ViewTooFar;
        return result;
    }

    // 7. Leader of the view.
    if (proposal.leader != config_.leader_order[proposal.view % config_.leader_order.size()]) {
        result.rejected = ConsensusFailure::WrongLeader;
        return result;
    }
    const Digest digest = proposal_digest(proposal);

    // 8. Two conflicting proposals for one view are objective evidence (11.6).
    if (const auto seen = accepted_by_view_.find(proposal.view);
        seen != accepted_by_view_.end() && seen->second != digest) {
        evidence_.push_back({proposal.leader, proposal.view, seen->second, digest, false});
        result.rejected = ConsensusFailure::Equivocation;
        return result;
    }

    // 9. Height rule. The height must chain onto the justified parent; a
    //    wrong height contradicts the justify and is a ParentQcMismatch.
    if (proposal.parent_digest == config_.genesis_digest) {
        if (proposal.height != 1) {
            result.rejected = ConsensusFailure::ParentQcMismatch;
            return result;
        }
    } else if (const auto parent = blocks_.find(proposal.parent_digest);
               parent != blocks_.end()) {
        if (proposal.height != parent->second.proposal.height + 1) {
            result.rejected = ConsensusFailure::ParentQcMismatch;
            return result;
        }
    } else {
        // Chain state cannot be evaluated. The justify itself passed step 5
        // and still advances what this node knows.
        advance_high_qc(justify);
        result.rejected = ConsensusFailure::MissingParent;
        return result;
    }
    if (!blocks_.contains(digest) && pending_count() >= constants::kMaxPendingProposals) {
        result.rejected = ConsensusFailure::PendingLimit;
        return result;
    }

    // 10. Accept into chain state.
    blocks_[digest] = BlockRecord{proposal, justify, digest};
    qc_by_block_[justify.proposal_digest] = justify;
    accepted_by_view_[proposal.view] = digest;
    advance_high_qc(justify);

    // 11. Lock and commit.
    apply_chain_rules(justify, result.commits);

    // 12. Vote-once and safe-node rule (11.6).
    const bool safe = proposal.view > last_voted_view_ &&
                      (extends_locked(proposal) || justify.view > locked_qc_.view);
    if (!safe) {
        result.safe_node_refused = true;
        return result;
    }

    HotStuffState pending;
    pending.epoch = config_.epoch;
    pending.consensus_ruleset = config_.consensus_ruleset;
    pending.last_voted_view = proposal.view;
    pending.high_qc = high_qc_;
    pending.locked_qc = locked_qc_;

    // The store call MUST precede vote construction. An emitted vote whose
    // state is not on disk is a double vote after restart. On refusal the
    // view is not treated as voted: a later retry may still vote once.
    if (!store_.store_before_vote(pending)) {
        result.rejected = ConsensusFailure::StorageRejected;
        return result;
    }
    last_voted_view_ = proposal.view;

    Vote vote{};
    vote.consensus_ruleset = config_.consensus_ruleset;
    vote.network_id = config_.network_id;
    vote.epoch = config_.epoch;
    vote.height = proposal.height;
    vote.view = proposal.view;
    vote.proposal_digest = digest;
    vote.voter = config_.self;
    vote.signature = sign_digest(own_key_, vote_signing_digest(vote));
    result.vote = vote;
    return result;
}

// Paper Algorithm 3 under the strict parent == justify rule. With b* the new
// proposal: b2 is its parent, qc1 the QC b2 shipped with, b1 the block qc1
// certifies, qc0 the QC b1 shipped with, and b0 the block qc0 certifies.
void HotStuffService::apply_chain_rules(const QuorumCertificate& justify,
                                        std::vector<ConsensusCommit>& commits) {
    const auto b2 = blocks_.find(justify.proposal_digest);
    if (b2 == blocks_.end()) return;  // the parent is genesis

    // LOCK_ON_TWO_CHAIN: justify over b2 completes the two-chain b1 <- b2.
    const QuorumCertificate& qc1 = b2->second.justify;
    if (qc1.view > locked_qc_.view) locked_qc_ = qc1;

    const auto b1 = blocks_.find(qc1.proposal_digest);
    if (b1 == blocks_.end()) return;
    const QuorumCertificate& qc0 = b1->second.justify;
    const auto b0 = blocks_.find(qc0.proposal_digest);
    if (b0 == blocks_.end()) return;  // genesis is never committed

    // COMMIT_ON_THREE_CHAIN: b0 <- b1 <- b2 with direct parent links, which
    // the strict rule guarantees. Commit b0 and every uncommitted ancestor.
    if (b0->second.proposal.height <= last_committed_height_) return;

    std::vector<const BlockRecord*> chain;
    const BlockRecord* current = &b0->second;
    while (true) {
        chain.push_back(current);
        const Digest& parent = current->proposal.parent_digest;
        if (parent == config_.genesis_digest) break;
        const auto it = blocks_.find(parent);
        if (it == blocks_.end() || it->second.proposal.height <= last_committed_height_) break;
        current = &it->second;
    }
    std::reverse(chain.begin(), chain.end());

    for (const BlockRecord* record : chain) {
        // The child stored this QC on accept; a miss is a broken invariant
        // and the block is then not committed.
        const auto certifying = qc_by_block_.find(record->digest);
        if (certifying == qc_by_block_.end()) return;
        ConsensusCommit commit{};
        commit.epoch = config_.epoch;
        commit.height = record->proposal.height;
        commit.view = record->proposal.view;
        commit.proposal_digest = record->digest;
        commit.proposed_state_root = record->proposal.proposed_state_root;
        commit.qc_digest = qc_digest(certifying->second);
        commits.push_back(commit);
        committed_digests_.insert(record->digest);
        last_committed_height_ = record->proposal.height;
    }

    // A failed commit record cannot un-commit consensus; only the safety
    // file protects votes.
    static_cast<void>(store_.store_commit(commits.back()));
    prune_committed();
}

// Drops proposals at or below the committed height that are not on the
// committed chain. Committed blocks stay: later chain walks need them.
void HotStuffService::prune_committed() {
    for (auto it = blocks_.begin(); it != blocks_.end();) {
        const bool below = it->second.proposal.height <= last_committed_height_;
        if (below && !committed_digests_.contains(it->first)) {
            accepted_by_view_.erase(it->second.proposal.view);
            qc_by_block_.erase(it->first);
            it = blocks_.erase(it);
        } else {
            ++it;
        }
    }
}

std::variant<std::monostate, QuorumCertificate, ConsensusFailure> HotStuffService::receive_vote(
    const Vote& vote) {
    if (failed_ || !synced_) return ConsensusFailure::NotSynced;
    if (vote.consensus_ruleset != config_.consensus_ruleset) {
        return ConsensusFailure::RulesetMismatch;
    }
    if (vote.network_id != config_.network_id) return ConsensusFailure::NetworkMismatch;
    if (vote.epoch != config_.epoch) return ConsensusFailure::EpochMismatch;

    // Ledgers are bounded to a view window before any signature work, so a
    // member cannot grow them without limit (11.9).
    if (const auto bound = view_window_failure(vote.view)) return *bound;

    const auto key = config_.vote_keys.find(vote.voter);
    if (key == config_.vote_keys.end()) return ConsensusFailure::UnknownSigner;
    if (!verify_digest(key->second, vote_signing_digest(vote), vote.signature)) {
        return ConsensusFailure::InvalidSignature;
    }

    auto& ledger = votes_by_view_[vote.view];
    if (const auto existing = ledger.find(vote.voter); existing != ledger.end()) {
        if (existing->second.proposal_digest == vote.proposal_digest) return std::monostate{};
        // Two signed votes for one (epoch, view) are objective evidence
        // (11.6). The first vote stays; the second never counts.
        evidence_.push_back({vote.voter, vote.view, existing->second.proposal_digest,
                             vote.proposal_digest, true});
        return ConsensusFailure::DuplicateSigner;
    }
    ledger.emplace(vote.voter, vote);

    // Votes for an unknown proposal still collect: the leader may learn the
    // proposal later. A QC forms for a digest; chain state is not judged.
    // The ledger is ordered by node_id, so signers come out sorted.
    std::vector<const Vote*> matching;
    for (const auto& [node, entry] : ledger) {
        if (entry.proposal_digest == vote.proposal_digest && entry.height == vote.height) {
            matching.push_back(&entry);
        }
    }
    if (matching.size() < config_.quorum) return std::monostate{};

    const auto formed_key = std::make_tuple(vote.view, vote.height, vote.proposal_digest);
    if (!formed_qcs_.insert(formed_key).second) return std::monostate{};

    QuorumCertificate certificate{};
    certificate.qc_format_version = constants::kQcFormatVersion;
    certificate.consensus_ruleset = vote.consensus_ruleset;
    certificate.network_id = vote.network_id;
    certificate.epoch = vote.epoch;
    certificate.height = vote.height;
    certificate.view = vote.view;
    certificate.proposal_digest = vote.proposal_digest;
    for (const Vote* entry : matching) {
        certificate.signers.push_back({entry->voter, entry->signature});
    }

    qc_by_block_[certificate.proposal_digest] = certificate;
    advance_high_qc(certificate);
    current_view_ = std::max(current_view_, vote.view + 1);
    return certificate;
}

std::variant<std::monostate, TimeoutCertificate, ConsensusFailure>
HotStuffService::receive_timeout(const TimeoutVote& vote) {
    if (failed_ || !synced_) return ConsensusFailure::NotSynced;
    if (vote.consensus_ruleset != config_.consensus_ruleset) {
        return ConsensusFailure::RulesetMismatch;
    }
    if (vote.network_id != config_.network_id) return ConsensusFailure::NetworkMismatch;
    if (vote.epoch != config_.epoch) return ConsensusFailure::EpochMismatch;

    if (const auto bound = view_window_failure(vote.view)) return *bound;

    const auto key = config_.vote_keys.find(vote.voter);
    if (key == config_.vote_keys.end()) return ConsensusFailure::UnknownSigner;
    if (!verify_digest(key->second, timeout_vote_signing_digest(vote), vote.signature)) {
        return ConsensusFailure::InvalidSignature;
    }

    // One timeout per node per view: the first one counts. A later one with
    // another high_qc claim is a legitimate refresh, not equivocation, and
    // is simply not counted.
    auto& ledger = timeouts_by_view_[vote.view];
    if (!ledger.emplace(vote.voter, vote).second) return std::monostate{};
    if (ledger.size() < config_.quorum) return std::monostate{};
    if (!formed_tcs_.insert(vote.view).second) return std::monostate{};

    TimeoutCertificate certificate{};
    certificate.consensus_ruleset = config_.consensus_ruleset;
    certificate.network_id = config_.network_id;
    certificate.epoch = config_.epoch;
    certificate.view = vote.view;
    // Each signer carries its OWN high_qc_digest, as it signed it.
    for (const auto& [node, entry] : ledger) {
        certificate.signers.push_back({node, entry.high_qc_digest, entry.signature});
    }

    current_view_ = std::max(current_view_, vote.view + 1);
    return certificate;
}

std::variant<Proposal, ConsensusFailure> HotStuffService::make_proposal(
    const Digest& previous_state_root,
    const Digest& proposed_state_root,
    const Digest& transitions_digest) {
    if (failed_ || !synced_) return ConsensusFailure::NotSynced;
    if (config_.self != config_.leader_order[current_view_ % config_.leader_order.size()]) {
        return ConsensusFailure::NotLeader;
    }

    // The parent is the high_qc block.
    Height height = 0;
    if (high_qc_.proposal_digest == config_.genesis_digest) {
        height = 1;
    } else if (const auto parent = blocks_.find(high_qc_.proposal_digest);
               parent != blocks_.end()) {
        height = parent->second.proposal.height + 1;
    } else {
        return ConsensusFailure::MissingParent;
    }

    Proposal proposal{};
    proposal.security_ruleset = config_.security_ruleset;
    proposal.consensus_ruleset = config_.consensus_ruleset;
    proposal.network_id = config_.network_id;
    proposal.epoch = config_.epoch;
    proposal.height = height;
    proposal.view = current_view_;
    proposal.leader = config_.self;
    proposal.parent_digest = high_qc_.proposal_digest;
    proposal.justify_qc_digest = qc_digest(high_qc_);
    proposal.previous_state_root = previous_state_root;
    proposal.proposed_state_root = proposed_state_root;
    proposal.transitions_digest = transitions_digest;
    // The caller may set it. It never enters a validity decision.
    proposal.timestamp_hint = 0;
    return proposal;
}

TimeoutVote HotStuffService::make_timeout_vote() const {
    if (failed_ || !synced_) {
        throw std::logic_error("HotStuffService: not synced");
    }
    TimeoutVote vote{};
    vote.consensus_ruleset = config_.consensus_ruleset;
    vote.network_id = config_.network_id;
    vote.epoch = config_.epoch;
    vote.view = current_view_;
    vote.high_qc_digest = qc_digest(high_qc_);
    vote.voter = config_.self;
    vote.signature = sign_digest(own_key_, timeout_vote_signing_digest(vote));
    return vote;
}

}  // namespace nexus::security
