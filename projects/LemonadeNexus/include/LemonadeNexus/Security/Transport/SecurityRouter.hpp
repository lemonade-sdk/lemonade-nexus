#pragma once

// The router between the mesh transport and the security services.
//
// Inbound: bound, budget, decode, bind the envelope to the authenticated
// peer, check the compiled rulesets, the network, and the epoch window,
// drop duplicates, then hand the typed message to exactly one service. Every
// check runs before any signature or FROST work. The router never decides
// eligibility, safety, quorum, DKG validity, or authorization; the services
// do, and the router only carries their answers back onto the wire.
//
// Outbound: the services tell the router what to send and to whom. The
// transport never fans out on its own.

#include <LemonadeNexus/Security/Attestation/AttestationTransfer.hpp>
#include <LemonadeNexus/Security/Attestation/EvidenceProducer.hpp>
#include <LemonadeNexus/Security/SecurityRuntime.hpp>
#include <LemonadeNexus/Security/Transport/PairwiseSeal.hpp>
#include <LemonadeNexus/Security/Transport/SecurityCodec.hpp>
#include <LemonadeNexus/Security/Transport/SecurityTransport.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <utility>
#include <vector>

namespace nexus::security {

/// Window for the rate-limited drop log line. A logging knob, not a protocol
/// constant: it never changes what is dropped.
inline constexpr uint64_t kDropLogWindowMs = 60'000;

enum class DropReason : uint16_t {
    Oversized,
    Flooded,
    Malformed,
    UnknownKind,
    SenderMismatch,
    RulesetMismatch,
    NetworkMismatch,
    EpochOutOfWindow,
    Duplicate,
    NoService,
    /// A remote challenger that is not a Tier 1 member of the current epoch:
    /// its evidence could never reach a verifier that counts it. For a
    /// StorageUnlock challenge: a challenger this node has no pending unlock
    /// request to.
    NotMember,
    /// A challenger answered more challenges than the per-challenger budget
    /// allows inside one window.
    BudgetExceeded,
    SealFailure,
    ServiceRejected,
    /// The envelope names another security wire version. A peer on a release
    /// with another wire, not a malformed message (Wire-Compatibility.md).
    /// scripts/mixed-version-mesh.sh matches this number.
    WireVersionMismatch = 14,
};

struct RouteResult {
    bool delivered = false;
    std::optional<DropReason> dropped;
    /// The service's typed failure when dropped == ServiceRejected.
    std::optional<uint16_t> service_code;
};

/// Protocol outcomes the lifecycle driver acts on. The router reports; it
/// does not decide what happens next.
class ISecurityEvents {
public:
    virtual ~ISecurityEvents() = default;
    virtual void on_vote_sent(const Vote&, const NodeId&) {}
    /// A vote the local replica validated: correct network, epoch and consensus
    /// ruleset, signed under the epoch vote key the mesh froze for that member,
    /// at a stated height. That is the participation proof — the subject
    /// asserted none of it, and nothing about it is a health score.
    virtual void on_vote_accepted(const Vote&) {}
    virtual void on_certificate(const QuorumCertificate&) {}
    /// The justify certificate of an accepted proposal: a validated quorum of
    /// signed votes, seen identically by every replica. Participation
    /// witnessing derives from this, so no member's evidence depends on
    /// which leader happened to collect the votes.
    virtual void on_justify_quorum(const QuorumCertificate&) {}
    virtual void on_timeout_certificate(const TimeoutCertificate&) {}
    virtual void on_commits(const std::vector<ConsensusCommit>&) {}
    virtual void on_dkg_round1_complete(EpochId) {}
    virtual void on_dkg_complete(EpochId) {}
    virtual void on_dkg_failed(DkgFailure, std::optional<NodeId>) {}
    virtual void on_authority_signature(const AuthoritySignature&) {}
    /// The evidence rides along: a passing verdict also carries the epoch
    /// vote key the node bound.
    virtual void on_attestation_verdict(const AttestationVerdict&, const AttestationEvidence&) {}
    virtual void on_epoch_announcement(const EpochAnnouncement&, const NodeId&) {}
    virtual void on_genesis_founding(const GenesisFounding&, const NodeId&) {}
    virtual void on_dkg_transcript_attest(const DkgTranscriptAttest&) {}
    virtual void on_bootstrap_certificate(const BootstrapCertificate&, const NodeId&) {}
    /// One observer's signed statement about one candidate. The ledger decides
    /// whether it counts; the router only carries it.
    virtual void on_eligibility_observation(const EligibilityObservation&) {}
    virtual void on_genesis_eligibility_attest(const GenesisEligibilityAttest&) {}
    /// A current Tier 1 member asks a candidate to prove it is a live
    /// participant anchored to finalized state. The answer proves possession of
    /// the node identity key and grants nothing.
    virtual void on_participation_challenge(const ParticipationChallenge&, const NodeId&) {}
    virtual void on_participation_response(const ParticipationResponse&) {}
    /// The adoption exchange. Every one of these carries a finalized commit
    /// proof (or, for state-ready, a certificate) that the driver verifies in
    /// full before acting; the router only delivers.
    virtual void on_next_epoch_plan(const NextEpochPlanProof&) {}
    virtual void on_candidate_state_ready(const CandidateStateReadyMsg&) {}
    virtual void on_readiness_proof(const ReadinessProofMsg&) {}
    virtual void on_epoch_handoff_proof(const EpochHandoffProofMsg&) {}
    /// A sync response arriving before this node holds any epoch state: the
    /// pending-candidate recovery path.
    virtual void on_candidate_sync_response(const SyncResponse&, const NodeId&) {}
    /// A validated certificate from a peer: proof the network reached its
    /// view. The driver derives the restart view floor from these.
    virtual void on_sync_certificate(const QuorumCertificate&, const NodeId&) {}
    /// The handoff-chain exchange. The request is answered from local
    /// records; the page is candidate data the driver verifies from its own
    /// trusted anchor, link by link.
    virtual void on_authority_chain_request(const AuthorityChainRequest&, const NodeId&) {}
    virtual void on_authority_chain_page(const AuthorityChainPage&, const NodeId&) {}
    /// A tree operation from a current Tier 1 member, for this node's pending
    /// pool. The router checked only the sender's membership; the op itself is
    /// unverified bytes until the pool's owner validates it.
    virtual void on_tree_op_submit(const TreeOpSubmitMsg&, const NodeId&) {}
    /// Storage-key traffic (kinds StoragePlanProof to StorageWrapClaim). The
    /// router bound the body's sender to the transport identity and checked
    /// the network; the storage service checks the epoch, the session or plan,
    /// and every proof itself.
    virtual void on_storage_message(const SecurityMessage&) {}
    /// Release adoption and upgrade-turn traffic (kind Upgrade). The router
    /// bound the sender and checked the network; the upgrade service checks
    /// every signature, record, and proof itself.
    virtual void on_upgrade_message(const SecurityMessage&) {}
};

struct SecurityRouterConfig {
    NetworkId network_id{};
    /// The pinned bootstrap anchor. During the genesis window it is the only
    /// identity authorized to issue a remote challenge; after an epoch is
    /// active, current members are. It is network state — the network id
    /// derives from it — not a certificate this node has seen.
    NodeId genesis_anchor_id{};
    /// Answers whether an identity is in the anchor-authenticated founding
    /// set, so founders can challenge one another before any epoch exists.
    /// The list is accepted only from the anchor; unset admits only the anchor.
    std::function<bool(const NodeId&)> founding_member;
    /// Answers whether `holder` may make this node attest for a storage unlock:
    /// true only while this node has a pending unlock request to that holder
    /// whose attestation context is `context`. An all-zero context asks
    /// whether any request to that holder is pending (an SVSM activation
    /// offer carries no context). This is the only path by which a holder
    /// outside Tier 1 can challenge, and only for the StorageUnlock purpose
    /// (or the enrollment that precedes it). Unset admits no such challenger.
    std::function<bool(const NodeId& holder, const Digest& context)> storage_unlock_challenger;
};

class SecurityRouter {
public:
    SecurityRouter(SecurityRouterConfig config, SecurityRuntime& runtime,
                   ISecurityTransport& transport, ISecurityEvents& events,
                   PairwiseSealer& sealer, IEvidenceProducer* evidence_producer);

    /// Inbound entry from the transport. `now_ms` drives the flood window.
    RouteResult receive(const NodeId& authenticated_sender, std::span<const uint8_t> envelope,
                        uint64_t now_ms);

    /// Fills the compiled rulesets, the network, and this node as sender.
    [[nodiscard]] SecurityMessage compose(SecurityMessageKind kind, SecurityBody body,
                                          EpochId epoch) const;

    /// Applies an own message through the same dispatch as inbound traffic.
    /// The gates do not run: the message never crossed the wire. Pass
    /// `now_ms` for the flood and challenge-production windows.
    RouteResult deliver_local(SecurityMessage message, uint64_t now_ms);

    [[nodiscard]] bool send(const NodeId& to, const SecurityMessage& message);
    std::size_t broadcast(const SecurityMessage& message);

    /// Sends a pairwise DKG message with its payload sealed to the recipient.
    [[nodiscard]] bool send_sealed_dkg(const DkgMessage& message);

    /// Total drops recorded for one reason since construction.
    [[nodiscard]] uint64_t drops(DropReason reason) const {
        const auto it = drop_counts_.find(reason);
        return it == drop_counts_.end() ? 0 : it->second;
    }

private:
    /// Counts the drop, keeps the verbose debug line, and emits one info line
    /// per (reason, code) and window; repeats inside the window are counted
    /// and reported by the next line.
    RouteResult drop(DropReason reason, std::optional<uint16_t> code = std::nullopt);

    [[nodiscard]] bool within_budget(const NodeId& sender, uint64_t now_ms);
    /// True when `from` is authorized to issue a challenge to this node in
    /// the current lifecycle phase: the pinned anchor while no epoch is
    /// active, a current Tier 1 member once one is.
    [[nodiscard]] bool challenger_is_member(const NodeId& from) const;
    /// The challenge gate: membership by phase for every purpose except
    /// StorageUnlock, which only this node's pending unlock request to `from`
    /// authorizes.
    [[nodiscard]] bool challenger_authorized(const AttestationChallenge& challenge,
                                             const NodeId& from) const;
    [[nodiscard]] bool storage_challenger(const NodeId& from, const Digest& context) const;
    [[nodiscard]] bool within_challenge_budget(const NodeId& from, uint64_t now_ms);

    [[nodiscard]] bool remember(std::span<const uint8_t> envelope);
    [[nodiscard]] bool sender_bound(const SecurityMessage& message,
                                    const NodeId& authenticated_sender) const;
    [[nodiscard]] bool epoch_in_window(const SecurityMessage& message) const;

    RouteResult dispatch(SecurityMessage& message, uint64_t now_ms);
    RouteResult route_proposal(const ProposalMessage& message, const NodeId& from);
    RouteResult route_vote(const Vote& vote);
    RouteResult route_timeout(const TimeoutVote& vote);
    RouteResult route_dkg(DkgMessage& message);
    RouteResult route_commitment(const FrostCommitmentMessage& message);
    RouteResult route_share(const FrostShareMessage& message);
    RouteResult route_challenge(const AttestationChallenge& challenge, const NodeId& from,
                                uint64_t now_ms);
    RouteResult route_evidence(const AttestationEvidence& evidence);
    RouteResult route_evidence_start(const AttestationEvidenceStart& start, uint64_t now_ms);
    RouteResult route_evidence_chunk(const AttestationEvidenceChunk& chunk,
                                     const NodeId& from, uint64_t now_ms);
    RouteResult route_evidence_end(const AttestationEvidenceEnd& end,
                                   const NodeId& from, uint64_t now_ms);
    RouteResult settle_transfer(EvidenceTransferResult result);
    RouteResult route_activation_offer(const SvsmAkActivationOfferMessage& offer,
                                       const NodeId& from);
    RouteResult route_activation_response(const SvsmAkActivationResponseMessage& response);
    RouteResult route_announcement(const EpochAnnouncement& announcement, const NodeId& from);
    RouteResult route_sync_request(const SyncRequest& request, const NodeId& from);
    RouteResult route_sync_response(const SyncResponse& response, const NodeId& from,
                                    uint64_t now_ms);

    struct PeerBudget {
        uint64_t window_start_ms = 0;
        uint32_t count = 0;
    };

    struct ChallengeBudget {
        uint64_t window_start_ms = 0;
        uint32_t count = 0;
    };

    struct DropLogWindow {
        uint64_t window_start_ms = 0;
        uint64_t suppressed = 0;
    };

    SecurityRouterConfig config_;
    SecurityRuntime& runtime_;
    ISecurityTransport& transport_;
    ISecurityEvents& events_;
    PairwiseSealer& sealer_;
    IEvidenceProducer* evidence_producer_;
    AttestationTransferReceiver transfer_receiver_;

    std::map<NodeId, PeerBudget> budgets_;
    std::map<NodeId, ChallengeBudget> challenge_budgets_;
    // Paging catch-up (route_sync_response): the last page asked of each peer
    // and when, so one peer is not asked for the same page in a loop.
    struct PageRequest {
        Height after_height{};
        uint64_t sent_ms = 0;
    };
    std::map<NodeId, PageRequest> page_requests_;
    std::vector<Digest> seen_ring_;
    std::set<Digest> seen_;
    std::size_t seen_next_ = 0;

    // Drop accounting. The router runs on one io thread, so plain integers.
    // Keys are bounded: reasons by the enum, codes by the services' failure
    // enums. drop_now_ms_ is the last transport-stamped time, for the log
    // window only — a local message never advances it.
    std::map<DropReason, uint64_t> drop_counts_;
    std::map<std::pair<uint16_t, uint16_t>, DropLogWindow> drop_log_;
    uint64_t drop_now_ms_ = 0;
};

}  // namespace nexus::security
