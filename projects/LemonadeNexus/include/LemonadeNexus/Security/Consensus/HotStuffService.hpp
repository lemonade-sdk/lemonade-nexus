#pragma once

// Chained HotStuff replica for one epoch.
//
// The service owns the safety state machine: vote-once-per-view, the
// safe-node rule, the two-chain lock, and the three-chain commit. It holds
// no timers and no transport. The caller feeds it proposals, votes, and
// timeouts; it returns what may leave the node.
//
// Safety invariants this class enforces:
//   - No vote leaves before its safety state is on disk, and no safety state
//     reaches disk before the blocks its high certificate names.
//   - No vote at or below last_voted_view, and none before restart sync.
//   - A justify QC is evidence: it must validate, or be the genesis anchor.
//   - The parent IS the justified block (REQUIRE_PARENT_QC).
//
// Architecture reference: Security Architecture Final Draft 1.1, sections 17,
// 18 and 19.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Consensus/BlockPayload.hpp>
#include <LemonadeNexus/Security/Consensus/CommitProof.hpp>
#include <LemonadeNexus/Security/Consensus/ConsensusStore.hpp>
#include <LemonadeNexus/Security/Consensus/ConsensusTypes.hpp>
#include <LemonadeNexus/Security/Consensus/HotStuffState.hpp>
#include <LemonadeNexus/Security/Consensus/VoteKey.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstddef>
#include <functional>
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

    /// Decides whether a proposed state transition is one this node has
    /// independently arrived at.
    ///
    /// A proposal carries its transition only as a digest. Consensus cannot
    /// read it, so without this the replicas vote for a handoff none of them
    /// evaluated: the commit then means different things on different nodes,
    /// and only the proposer activates. That splits the mesh across two epochs.
    ///
    /// Unset means no transition can be evaluated, so any non-empty digest is
    /// refused. An empty digest is an ordinary block and always passes.
    /// Not consulted for a proposal that arrives with a payload.
    std::function<bool(const Digest& transitions_digest)> transition_validator;

    /// Decides whether this node independently agrees with a block payload
    /// (BlockPayload.hpp). Called only after the payload matched the
    /// proposal's transitions digest and the proposal passed every header and
    /// chain check, so the parent is in chain state. Unset refuses every
    /// payload. Like transition_validator, a refusal withholds the vote and
    /// the block still enters chain state.
    std::function<bool(const Proposal& proposal, const BlockPayload& payload)> payload_validator;
};

struct ProposalResult {
    std::optional<Vote> vote;
    // Protocol rejections only. A withheld vote is not a rejection.
    std::optional<ConsensusFailure> rejected;
    std::vector<ConsensusCommit> commits;
    // The vote-once or safe-node rule withheld the vote. This is normal
    // protocol behavior; the proposal still entered chain state.
    bool safe_node_refused = false;
    // The proposal carries a transition this node has not independently
    // arrived at, so the vote is withheld — a vote is what authorizes. The
    // block still enters chain state: refusing to track a certified chain
    // would partition this replica by its own disagreement, while a quorum
    // that DID derive the transition commits it regardless.
    bool transition_refused = false;
};

/// A proposal refused only because its parent block is unknown. It is held
/// so it can be judged again, in full, once catch-up delivers the parent.
struct OrphanProposal {
    Proposal proposal;
    QuorumCertificate justify;
    std::optional<BlockPayload> payload;
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
    //
    // On restart it also restores the stored chain (IConsensusStore::
    // load_chain) into chain state, without a vote and without a commit.
    // Every certificate is validated again first; the restore stops at the
    // first block that fails. A missing or damaged chain record restores
    // nothing, and restart sync supplies the blocks from peers.
    HotStuffService(HotStuffConfig config, EpochVoteKey own_vote_key, IConsensusStore& store);

    /// `payload` is the block payload the proposal message carried, or
    /// nullptr. A payload that does not match `proposal.transitions_digest`
    /// is not stored and withholds the vote (transition_refused).
    [[nodiscard]] ProposalResult receive_proposal(const Proposal& proposal,
                                                  const QuorumCertificate& justify,
                                                  const BlockPayload* payload = nullptr);

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

    /// Returns the held orphan proposal when its parent is now in chain state,
    /// and releases it. Returns nothing while the parent is still unknown.
    ///
    /// receive_proposal() holds one orphan: the highest-view proposal it
    /// refused with MissingParent after every header, justify, view and
    /// leader check passed. The caller feeds the returned proposal back
    /// through receive_proposal(), which judges it again from the start, so
    /// holding it grants nothing. Without this, a replica that missed one
    /// block stays one block behind: each later proposal names the block it
    /// refused before.
    [[nodiscard]] std::optional<OrphanProposal> take_linkable_orphan();

    /// The chain above the last committed block, oldest first, each with its
    /// justify. The last entry is the block the high certificate certifies.
    [[nodiscard]] std::vector<std::pair<Proposal, QuorumCertificate>> uncommitted_chain() const;

    /// One bounded page of the certified chain, for a replica that fell
    /// behind by more than one uncommitted chain (SyncRequest::after_height).
    /// At most kMaxSyncChainBlocks entries.
    using CertifiedPage = CertifiedChain;
    /// The committed blocks above `after`, then the uncommitted chain when
    /// the page reaches it, with the certificate over the last block. Only
    /// certified blocks of this replica's committed chain are served; the
    /// receiver validates every certificate again (adopt_certified_block).
    /// nullopt when this replica holds no committed block at height
    /// after + 1: it is not ahead, or it restarted above that height and
    /// holds no blocks below its sync anchor.
    [[nodiscard]] std::optional<CertifiedPage> certified_page_after(Height after) const;

    /// True while a proposal waits for its parent (take_linkable_orphan).
    [[nodiscard]] bool holds_orphan() const { return orphan_.has_value(); }

    /// The portable three-chain proof for a committed block, when the blocks
    /// and certificates behind it are still held. A node outside the epoch
    /// verifies this instead of trusting the sender.
    [[nodiscard]] std::optional<CommitProof> commit_proof(const Digest& proposal_digest) const;

    /// The header of a block in chain state, or nullptr. Committed blocks
    /// stay in chain state; blocks pruned off the committed chain do not.
    [[nodiscard]] const Proposal* block(const Digest& proposal_digest) const;

    /// The payload a block in chain state arrived with, or nullptr when the
    /// block is unknown or arrived without one (a stage block, an empty
    /// block, or a block adopted through restart sync).
    [[nodiscard]] const BlockPayload* block_payload(const Digest& proposal_digest) const;

    /// The epoch's anchor digest: the parent of the epoch's first block.
    [[nodiscard]] const Digest& genesis_digest() const { return config_.genesis_digest; }

    /// Height of the last block this replica committed in this epoch.
    [[nodiscard]] Height last_committed_height() const { return last_committed_height_; }

    /// The epoch's frozen voting membership, sorted by node id.
    [[nodiscard]] std::vector<NodeId> members() const {
        std::vector<NodeId> out;
        out.reserve(config_.vote_keys.size());
        for (const auto& [node, key] : config_.vote_keys) out.push_back(node);
        return out;
    }

    [[nodiscard]] NodeId leader_of(View view) const {
        return config_.leader_order[view.underlying() % config_.leader_order.size()];
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
        // The payload that matched the proposal's transitions digest, if one
        // arrived with it.
        std::optional<BlockPayload> payload;
    };

    [[nodiscard]] QuorumCertificate genesis_qc() const;
    [[nodiscard]] bool is_genesis_justify(const QuorumCertificate& justify) const;
    [[nodiscard]] bool extends_locked(const Proposal& proposal) const;
    [[nodiscard]] std::size_t pending_count() const;
    [[nodiscard]] std::optional<ConsensusFailure> view_window_failure(View view) const;
    /// The header and certificate checks every adopted or restored block
    /// passes: binding, justify, and a valid certificate over this block.
    [[nodiscard]] std::optional<ConsensusFailure> certified_block_failure(
        const Proposal& proposal, const QuorumCertificate& justify,
        const QuorumCertificate& certifying) const;
    void restore_stored_chain();
    /// Stores the uncommitted chain below the high certificate when it
    /// changed. False only when the store refused it.
    [[nodiscard]] bool store_certified_chain();
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
    // Committed height -> block digest, for certified_page_after().
    std::map<Height, Digest> committed_by_height_;

    std::map<View, std::map<NodeId, Vote>> votes_by_view_;
    std::set<std::tuple<View, Height, Digest>> formed_qcs_;
    std::map<View, std::map<NodeId, TimeoutVote>> timeouts_by_view_;
    std::set<View> formed_tcs_;

    // At most one proposal waits for its parent; see take_linkable_orphan().
    std::optional<OrphanProposal> orphan_;

    // One parentless adoption is allowed after a restart: the sync anchor.
    // Its quorum certificate proves the content; everything above it links.
    bool anchor_adopted_ = false;
    // Chain state holds blocks restored from this node's own chain record.
    // They do not use up the sync anchor: peers that moved on past them may
    // still anchor this replica once.
    bool restored_ = false;
    // qc_digest of the certificate the stored chain record ends with.
    std::optional<Digest> stored_chain_qc_;

    std::vector<EquivocationRecord> evidence_;
};

}  // namespace nexus::security
