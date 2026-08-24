#pragma once

// Chained HotStuff replica for one epoch.
//
// The service owns the safety state machine: vote-once-per-view, the
// safe-node rule, the two-chain lock, and the three-chain commit. It holds
// no timers and no transport. The caller feeds it proposals, votes, and
// timeouts; it returns what may leave the node.
//
// Safety invariants this class enforces:
//   - No vote leaves before its safety state is on disk.
//   - No vote at or below last_voted_view, and none before restart sync.
//   - A justify QC is evidence: it must validate, or be the genesis anchor.
//   - The parent IS the justified block (REQUIRE_PARENT_QC).
//
// Architecture reference: Security Architecture Final Draft 1.0, sections
// 11.3 to 11.7, 11.9, and 11.12.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Consensus/ConsensusStore.hpp>
#include <LemonadeNexus/Security/Consensus/ConsensusTypes.hpp>
#include <LemonadeNexus/Security/Consensus/HotStuffState.hpp>
#include <LemonadeNexus/Security/Consensus/VoteKey.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstddef>
#include <map>
#include <optional>
#include <set>
#include <tuple>
#include <variant>
#include <vector>

namespace nexus::security {

struct HotStuffConfig {
    SecurityRulesetVersion security_ruleset;
    ConsensusRulesetVersion consensus_ruleset;
    NetworkId network_id;
    EpochId epoch;
    Digest genesis_digest;
    std::vector<NodeId> leader_order;
    std::map<NodeId, crypto::Ed25519PublicKey> vote_keys;
    std::size_t quorum;
    NodeId self;
};

struct ProposalResult {
    std::optional<Vote> vote;
    // Protocol rejections only. A withheld vote is not a rejection.
    std::optional<ConsensusFailure> rejected;
    std::vector<ConsensusCommit> commits;
    // The vote-once or safe-node rule withheld the vote. This is normal
    // protocol behavior; the proposal still entered chain state.
    bool safe_node_refused = false;
};

// Two signed messages from one node for one (epoch, view).
struct EquivocationRecord {
    NodeId node;
    View view;
    Digest first;
    Digest second;
    bool is_vote = false;
};

class HotStuffService {
public:
    // Loads the epoch safety state. Absent: fresh epoch, voting may begin.
    // Stored state: restart, no vote until sync_to_certified(). Corrupt:
    // permanently unusable. Throws std::invalid_argument on an empty leader
    // order or a zero quorum.
    HotStuffService(HotStuffConfig config, EpochVoteKey own_vote_key, IConsensusStore& store);

    [[nodiscard]] ProposalResult receive_proposal(const Proposal& proposal,
                                                  const QuorumCertificate& justify);

    // monostate: counted, no certificate yet. A QC forms once per
    // (view, digest) at exactly config.quorum distinct voters.
    [[nodiscard]] std::variant<std::monostate, QuorumCertificate, ConsensusFailure> receive_vote(
        const Vote& vote);

    [[nodiscard]] std::variant<std::monostate, TimeoutCertificate, ConsensusFailure>
    receive_timeout(const TimeoutVote& vote);

    // The caller feeds the proposal back through receive_proposal with
    // high_qc as justify to vote on it. timestamp_hint is left at zero.
    [[nodiscard]] std::variant<Proposal, ConsensusFailure> make_proposal(
        const Digest& previous_state_root,
        const Digest& proposed_state_root,
        const Digest& transitions_digest);

    // Throws std::logic_error before sync or when unusable.
    [[nodiscard]] TimeoutVote make_timeout_vote() const;

    // The floor comes from quorum-certified state the caller fetched from
    // the active Tier 1 set. This service only enforces "no vote at or
    // below the floor".
    void sync_to_certified(View certified_view_floor);

    [[nodiscard]] HotStuffState state() const;
    [[nodiscard]] View current_view() const { return current_view_; }
    /// Adopts one certified block into chain state without voting: restart
    /// recovery replays facts, it never re-decides them. `certifying` must be
    /// a valid certificate over exactly this block.
    [[nodiscard]] std::optional<ConsensusFailure> adopt_certified_block(
        const Proposal& proposal, const QuorumCertificate& justify,
        const QuorumCertificate& certifying, std::vector<ConsensusCommit>& commits_out);

    /// The chain above the last committed block, oldest first, each with its
    /// justify. The last entry is the block the high certificate certifies.
    [[nodiscard]] std::vector<std::pair<Proposal, QuorumCertificate>> uncommitted_chain() const;

    [[nodiscard]] NodeId leader_of(View view) const {
        return config_.leader_order[view % config_.leader_order.size()];
    }
    [[nodiscard]] bool synced() const { return synced_; }
    [[nodiscard]] bool usable() const { return !failed_; }
    [[nodiscard]] const std::vector<EquivocationRecord>& equivocation_evidence() const {
        return evidence_;
    }

private:
    struct BlockRecord {
        Proposal proposal;
        // The QC the proposal shipped with. It certifies the parent.
        QuorumCertificate justify;
        Digest digest;
    };

    [[nodiscard]] QuorumCertificate genesis_qc() const;
    [[nodiscard]] bool is_genesis_justify(const QuorumCertificate& justify) const;
    [[nodiscard]] bool extends_locked(const Proposal& proposal) const;
    [[nodiscard]] std::size_t pending_count() const;
    [[nodiscard]] std::optional<ConsensusFailure> view_window_failure(View view) const;
    void advance_high_qc(const QuorumCertificate& certificate);
    void apply_chain_rules(const QuorumCertificate& justify,
                           std::vector<ConsensusCommit>& commits);
    void prune_committed();

    HotStuffConfig config_;
    EpochVoteKey own_key_;
    IConsensusStore& store_;

    bool failed_ = false;
    bool synced_ = false;

    View current_view_ = 1;
    View last_voted_view_ = 0;
    QuorumCertificate high_qc_{};
    QuorumCertificate locked_qc_{};
    Height last_committed_height_ = 0;

    std::map<Digest, BlockRecord> blocks_;
    // Block digest -> the QC that certifies that block.
    std::map<Digest, QuorumCertificate> qc_by_block_;
    std::map<View, Digest> accepted_by_view_;
    std::set<Digest> committed_digests_;

    std::map<View, std::map<NodeId, Vote>> votes_by_view_;
    std::set<std::tuple<View, Height, Digest>> formed_qcs_;
    std::map<View, std::map<NodeId, TimeoutVote>> timeouts_by_view_;
    std::set<View> formed_tcs_;

    // One parentless adoption is allowed after a restart: the sync anchor.
    // Its quorum certificate proves the content; everything above it links.
    bool anchor_adopted_ = false;

    std::vector<EquivocationRecord> evidence_;
};

}  // namespace nexus::security
