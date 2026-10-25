#pragma once

// The lifecycle driver: the one place protocol outcomes turn into next steps.
//
// The driver reacts to router events and to time. It bootstraps through
// Genesis, runs the epoch cadence, drives the pacemaker, proposes when this
// node leads, applies committed handoffs, and recovers after a restart. It
// decides nothing the services own: eligibility, safety, quorum, DKG
// validity, and authorization stay where they are.
//
// The driver is deliberately clock-free: the caller feeds `tick(now_ms)`.
// The service wrapper runs it from timers; tests run it from a counter.

#include <LemonadeNexus/Security/Attestation/EvidenceProducer.hpp>
#include <LemonadeNexus/Security/Authority/RoundRelay.hpp>
#include <LemonadeNexus/Security/Consensus/Pacemaker.hpp>
#include <LemonadeNexus/Security/Eligibility/EligibilityService.hpp>
#include <LemonadeNexus/Security/Epoch/AuthorityChain.hpp>
#include <LemonadeNexus/Security/Epoch/EpochStore.hpp>
#include <LemonadeNexus/Security/Genesis/GenesisService.hpp>
#include <LemonadeNexus/Security/SecurityRuntime.hpp>
#include <LemonadeNexus/Security/Transport/SecurityRouter.hpp>

#include <functional>
#include <map>
#include <optional>
#include <set>

namespace nexus::security {

enum class DriverPhase : uint16_t {
    Failed,
    Idle,
    /// Named in a finalized next-epoch plan and preparing for that epoch.
    /// Permission to prepare, and nothing else: no vote, no share, no DKG for
    /// any current epoch, no Tier 1 API.
    PendingNextEpoch,
    GenesisCollecting,
    /// Founders observing each other, before any DKG. The founding eligibility
    /// transcript comes out of this round and every founder must sign the same
    /// one.
    GenesisEligibility,
    FoundingDkg,
    AwaitingBootstrap,
    Syncing,
    Active,
};

struct SecurityDriverConfig {
    NodeId self;
    crypto::Ed25519Keypair identity;
    crypto::Ed25519PublicKey genesis_public_key{};
    /// Digest of the verified release approval this process loaded; all-zero
    /// when none is packaged. A new founding and its bootstrap certificate
    /// must name this exact value or they are refused.
    Digest release_approval_digest{};
    /// Decides at restart whether a stored bootstrap certificate's release
    /// commitment is acceptable. Unset requires it to equal
    /// release_approval_digest. The mesh service sets it to
    /// ReleaseChain::bind_commitment, which accepts the founding approval when
    /// it carries the pinned release signer and this network, so a newer
    /// approval supersedes it without Genesis. False fails the driver.
    std::function<bool(const Digest& committed_approval)> release_commitment;
    uint64_t sync_window_ms = 2000;

    /// Answers whether a candidate holds a root-signed transport certificate.
    /// One of the Tier 1 prerequisites, and the mesh knows it rather than the
    /// platform. Unset leaves the fact false and nobody becomes eligible.
    std::function<bool(const NodeId&)> certificate_source;
};

class SecurityDriver final : public ISecurityEvents {
public:
    SecurityDriver(SecurityDriverConfig config, SecurityRuntime& runtime, SecurityRouter& router,
                   EpochStore& store, GenesisService* genesis);

    /// Restores durable state. Corrupt state fails the driver permanently:
    /// lost epoch state is never a fresh start.
    void start(uint64_t now_ms);

    /// Time-driven work: sync windows, the pacemaker, re-attestation, and
    /// the epoch cadence.
    void tick(uint64_t now_ms);

    /// A peer became reachable. Genesis challenges candidates here.
    void on_peer(const NodeId& peer, uint64_t now_ms);

    /// The epoch vote key this node presents for an epoch; created on first
    /// use and persisted wrapped.
    [[nodiscard]] std::optional<crypto::Ed25519PublicKey> vote_key_for_epoch(EpochId epoch);

    [[nodiscard]] DriverPhase phase() const { return phase_; }

    /// Fires on every entry into Active and once at genesis certificate
    /// issuance: the moments this node first holds finalized epoch authority.
    /// Runs on the io thread; set before start.
    void set_epoch_established_callback(std::function<void()> cb) {
        on_epoch_established_ = std::move(cb);
    }
    [[nodiscard]] bool genesis_node() const;
    [[nodiscard]] std::optional<EpochId> current_epoch() const;
    [[nodiscard]] Height last_committed_height() const { return last_committed_height_; }

    /// True when this node is in the current epoch's frozen Tier 1 set. The
    /// mesh decided that; this is a read, never a decision.
    [[nodiscard]] bool is_tier1_member() const;

    /// The verified epoch authority this node holds, or nullptr before any
    /// verification reached one. A read of derived facts, never a grant.
    [[nodiscard]] const VerifiedEpochAuthority* verified_authority() const {
        return authority_.has_value() ? &*authority_ : nullptr;
    }

    /// The verified authority of `epoch`, or nullopt when this node has not
    /// verified it. Every value comes from the authenticated chain: the
    /// Genesis certificate for Epoch 1 and one verified finalized handoff per
    /// later epoch, rebuilt from the durable chain at start. Replication
    /// verifies a committed tree block's proof against the block epoch's
    /// frozen vote keys with this. A read, never a grant. io thread.
    [[nodiscard]] std::optional<VerifiedEpochAuthority> authority_for_epoch(EpochId epoch) const;

    /// The stored authority chain from Genesis: the bootstrap certificate,
    /// the epoch-1 vote-key listing, and every stored handoff with its commit
    /// proof, oldest first. Candidate data for a remote verifier
    /// (RolloutProof.hpp); nullopt before this node holds the Genesis base.
    /// io thread.
    [[nodiscard]] std::optional<AuthorityChainPage> authority_chain() const;

    /// Unauthenticated evidence that the mesh reached `epoch` (for example a
    /// replicated tree block that names it). A hint and nothing more: it can
    /// prompt an authority chain request, never an answer. io thread.
    void note_epoch_hint(EpochId epoch) { chain_hint_epoch_ = std::max(chain_hint_epoch_, epoch); }

    // --- ISecurityEvents ---
    void on_vote_sent(const Vote&, const NodeId&) override {}
    void on_certificate(const QuorumCertificate& certificate) override;
    void on_timeout_certificate(const TimeoutCertificate& certificate) override;
    void on_commits(const std::vector<ConsensusCommit>& commits) override;
    void on_dkg_round1_complete(EpochId) override {}
    void on_dkg_complete(EpochId target) override;
    void on_dkg_failed(DkgFailure failure, std::optional<NodeId> culprit) override;
    void on_authority_signature(const AuthoritySignature&) override {}
    void on_attestation_verdict(const AttestationVerdict& verdict,
                                const AttestationEvidence& evidence) override;
    void on_epoch_announcement(const EpochAnnouncement& announcement, const NodeId& from) override;
    void on_genesis_founding(const GenesisFounding& founding, const NodeId& from) override;
    void on_dkg_transcript_attest(const DkgTranscriptAttest& attest) override;
    void on_bootstrap_certificate(const BootstrapCertificate& certificate,
                                  const NodeId& from) override;
    void on_sync_certificate(const QuorumCertificate& certificate, const NodeId& from) override;
    void on_vote_accepted(const Vote& vote) override;
    void on_justify_quorum(const QuorumCertificate& certificate) override;
    void on_eligibility_observation(const EligibilityObservation& observation) override;
    void on_genesis_eligibility_attest(const GenesisEligibilityAttest& attest) override;
    void on_participation_challenge(const ParticipationChallenge& challenge,
                                    const NodeId& from) override;
    void on_participation_response(const ParticipationResponse& response) override;
    void on_next_epoch_plan(const NextEpochPlanProof& package) override;
    void on_candidate_state_ready(const CandidateStateReadyMsg& message) override;
    void on_readiness_proof(const ReadinessProofMsg& message) override;
    void on_epoch_handoff_proof(const EpochHandoffProofMsg& message) override;
    void on_candidate_sync_response(const SyncResponse& response, const NodeId& from) override;
    void on_authority_chain_request(const AuthorityChainRequest& request,
                                    const NodeId& from) override;
    void on_authority_chain_page(const AuthorityChainPage& page, const NodeId& from) override;
    void on_tree_op_submit(const TreeOpSubmitMsg& message, const NodeId& from) override;
    void on_storage_message(const SecurityMessage& message) override;
    void on_upgrade_message(const SecurityMessage& message) override;

    /// The handoff this node has independently prepared, or an empty digest
    /// when it has none. Consensus asks this before voting for a proposal
    /// that carries a transition, so a handoff commits only when a quorum
    /// arrived at the same one.
    [[nodiscard]] Digest pending_handoff_digest() const;

    /// The eligibility state this node would finalize at this epoch boundary,
    /// or an empty digest when it is not at one. Finalizing it is what turns
    /// local observations into the pool every honest node selects from.
    [[nodiscard]] Digest pending_eligibility_digest() const;

    /// The next-epoch plan this node derives from the finalized eligibility
    /// state, or an empty digest outside a boundary. Committing it is what
    /// authorizes selected candidates to prepare.
    [[nodiscard]] Digest pending_plan_digest() const;

    /// The readiness set this node has verified for the committed plan, or an
    /// empty digest until every selected member proved preparation. Committing
    /// it is what authorizes the next-epoch DKG.
    [[nodiscard]] Digest pending_readiness_digest() const;

    /// Whether this node independently arrived at the proposed transition. The
    /// one entry point consensus uses; it accepts a handoff or an eligibility
    /// commitment and nothing else.
    [[nodiscard]] bool accepts_transition(const Digest& transitions_digest) const;

    /// Adds the handler for one block payload kind (BlockPayload.hpp). The
    /// handler proposes that kind when this node leads and no stage is
    /// pending, answers accepts_payload, and receives the kind's commits. Not
    /// owning: the handler must outlive the driver or be registered again
    /// after a rebuild. Set before start; io-thread only.
    void register_payload_handler(IBlockPayloadHandler& handler);

    /// Whether this node independently agrees with a block payload: the
    /// registered handler for its kind decides. No handler, no vote. The
    /// consensus payload_validator calls this.
    [[nodiscard]] bool accepts_payload(const Proposal& proposal, const BlockPayload& payload) const;

    /// Receives tree operations that current Tier 1 members forward
    /// (SecurityRouter checked the membership). Unset drops them.
    void set_tree_op_sink(std::function<void(const TreeOpSubmitMsg&, const NodeId&)> sink) {
        tree_op_sink_ = std::move(sink);
    }

    /// Receives storage-key traffic (SecurityRouter checked the sender binding
    /// and the network only). Unset drops it.
    void set_storage_sink(std::function<void(const SecurityMessage&)> sink) {
        storage_sink_ = std::move(sink);
    }

    /// Receives every verdict for the StorageUnlock purpose. Such a verdict
    /// never reaches eligibility or final readiness. Unset drops it.
    void set_storage_verdict_sink(std::function<void(const AttestationVerdict&)> sink) {
        storage_verdict_sink_ = std::move(sink);
    }

    /// Receives Upgrade traffic (SecurityRouter checked the sender binding and
    /// the network only). Unset drops it.
    void set_upgrade_sink(std::function<void(const SecurityMessage&)> sink) {
        upgrade_sink_ = std::move(sink);
    }

    /// Receives every verdict for the UpgradeHealth purpose. Such a verdict
    /// never reaches eligibility or final readiness. Unset drops it.
    void set_upgrade_verdict_sink(std::function<void(const AttestationVerdict&)> sink) {
        upgrade_verdict_sink_ = std::move(sink);
    }

    /// Fires when this node finalizes the eligibility state for the next epoch
    /// and its own recomputation reproduces it: `pool` is the frozen eligible
    /// pool and `finalized` the commit that finalized it. A read of finalized
    /// facts; the storage holder selection derives from it (design B4).
    void set_eligibility_finalized_callback(
        std::function<void(const FinalizedEligibility& finalized, const Tier1Set& pool)> cb) {
        on_eligibility_finalized_ = std::move(cb);
    }


    /// True when `node` is in the anchor-authenticated founding this driver
    /// accepted. Feeds the router's pre-epoch challenger gate so founders can
    /// run the mutual eligibility round.
    [[nodiscard]] bool is_founding_member(const NodeId& node) const;

    /// The canonical final-attestation context for one selected node under
    /// one plan, or an empty digest when the plan does not name the node.
    /// Pure derivation; public so a verifier of captured traffic can rebuild
    /// the exact value a challenge bound.
    [[nodiscard]] static Digest plan_attest_context(const NextEpochPlan& plan,
                                                    const NodeId& node);

    [[nodiscard]] const EligibilityService& eligibility() const { return eligibility_; }

private:
    [[nodiscard]] std::optional<AuthorityChainPage> chain_page(EpochId have_epoch,
                                                             std::size_t max_links) const;
    [[nodiscard]] NodeId genesis_id() const;
    void set_phase(DriverPhase next, const char* reason);
    [[nodiscard]] EpochVoteKey take_own_vote_key(EpochId epoch);
    void issue_genesis_challenge(const NodeId& peer);
    void send_founding();
    void start_founding_dkg();
    void maybe_start_next_dkg();
    /// Fails an authorized DKG that sat incomplete past the compiled window
    /// and excludes the participants whose round-1 silence every member
    /// observed. Liveness recovery; nothing here activates anything.
    void maybe_fail_stalled_dkg(uint64_t now_ms);
    /// Re-sends the own round-1 broadcast and produced round-2 packages on
    /// kDkgResendMs: from the live session while it runs, then from the kept
    /// outbox after this node's own session completed, because a peer may
    /// still be missing a package. Stops at activation, at abandonment, or
    /// after twice the stall window. The founding DKG's running session has
    /// its own cadence in run_bootstrap_liveness.
    void maybe_resend_dkg(uint64_t now_ms);
    /// Takes the completed DKG result, keeping this node's own packages for
    /// maybe_resend_dkg.
    [[nodiscard]] std::optional<DkgResult> take_dkg_result_keeping_outbox();
    void maybe_propose(View view);
    void progress(uint64_t now_ms);
    void begin_sync(uint64_t now_ms);
    void finish_sync();
    void run_epoch_cadence(uint64_t now_ms);
    void attest_self_for(EpochId epoch, const Digest& context);
    [[nodiscard]] bool eligibility_verdict_ok(const AttestationVerdict& verdict) const;
    [[nodiscard]] std::optional<NextEpochPlan> derive_plan() const;
    [[nodiscard]] std::optional<CandidateReadiness> derive_readiness() const;
    [[nodiscard]] std::optional<EpochHandoff> derive_handoff() const;
    void on_plan_committed(const ConsensusCommit& commit);
    void on_readiness_committed(const ConsensusCommit& commit);
    /// Challenges the selected set for the plan-bound final attestation.
    /// `stale_only` re-asks just the nodes whose proof aged past the
    /// freshness window, at most once per window each.
    void issue_final_challenges(bool stale_only);
    void maybe_renew_final_attestation();
    /// The attempt's budget ran dry with readiness incomplete: exclude the
    /// never-fulfilled nodes for this boundary and replace the attempt.
    void fail_starved_attempt();
    void broadcast_transcript_attest(EpochId target);
    void maybe_adopt_attested_transcript();
    void abandon_boundary(const char* reason);
    /// Sets and persists the verified authority anchor.
    void install_authority(VerifiedEpochAuthority authority);
    /// Asks the mesh for chain links when something hints this node is
    /// behind. The ask is idempotent and free of authority.
    void maybe_request_chain();
    void broadcast_proof(SecurityMessageKind kind, SecurityBody body, EpochId epoch);
    [[nodiscard]] bool candidate_verify_proof(const Digest& transitions_digest,
                                              const CommitProof& proof) const;
    void do_activate(const Digest& checkpoint);
    void persist_current_epoch(const Digest& checkpoint);
    void announce_epoch(const Digest& checkpoint, const Digest& dkg_transcript_digest);

    [[nodiscard]] Digest genesis_attestation_root(const Tier1Set& founders) const;

    /// Installs the frozen observer set for `epoch` and restores durable
    /// observations. Corrupt eligibility state fails the driver: lost history
    /// is never a clean slate.
    [[nodiscard]] bool enter_eligibility_epoch(EpochId epoch, const Tier1Set& members);
    [[nodiscard]] bool epoch_aged(uint64_t now_ms) const;
    void publish(const EligibilityObservation& observation, EpochId epoch);
    void begin_founding_observations();
    /// Paced retries (re-challenge, re-broadcast) that keep the bootstrap live.
    void run_bootstrap_liveness(uint64_t now_ms);
    void challenge_founding_edge(const NodeId& peer);
    void broadcast_eligibility_attest();
    void challenge_participation(const NodeId& candidate);
    void record_founding_observation(const AttestationVerdict& verdict);
    void maybe_attest_founding_eligibility();
    void drain_objective_faults();

    SecurityDriverConfig config_;
    SecurityRuntime& runtime_;
    SecurityRouter& router_;
    EpochStore& store_;
    GenesisService* genesis_;

    DriverPhase phase_ = DriverPhase::Idle;
    std::function<void()> on_epoch_established_;
    uint64_t now_ms_ = 0;

    // Own per-epoch vote keys; the private halves live here and in the store.
    // The public halves stay known after the private key moves into consensus.
    std::map<EpochId, EpochVoteKey> vote_keys_mine_;
    std::map<EpochId, crypto::Ed25519PublicKey> vote_pubs_mine_;

    // Genesis-side bootstrap state.
    std::map<NodeId, crypto::Ed25519PublicKey> founder_vote_keys_;
    std::map<NodeId, Digest> founder_evidence_digests_;
    bool founding_sent_ = false;

    // Founder-side bootstrap state.
    std::optional<GenesisFounding> founding_;
    std::optional<DkgResult> pending_dkg_;
    /// This node's own packages from a completed DKG, re-sent until the epoch
    /// it produced activates or the attempt is abandoned.
    struct DkgOutbox {
        EpochId epoch = 0;
        std::optional<DkgMessage> round1;
        std::vector<DkgMessage> round2;
        uint64_t kept_ms = 0;
    };
    std::optional<DkgOutbox> dkg_outbox_;
    /// The founding eligibility state this node computed and signed. The
    /// bootstrap certificate must name exactly this value or it is refused.
    Digest founding_eligibility_digest_{};
    std::map<NodeId, Digest> founding_eligibility_attests_;
    /// Before Epoch 1 there is no certified height, so the founding round
    /// counts its own rounds to keep observation heights monotonic.
    Height founding_round_ = 0;
    uint64_t last_bootstrap_retry_ms_ = 0;
    uint64_t founding_dkg_started_ms_ = 0;
    ResendCadence dkg_resend_{constants::kDkgResendMs};
    /// When each founding edge was last challenged; answers can outlive the
    /// cadence, so an edge is re-asked only after a grace period.
    std::map<NodeId, uint64_t> founding_challenge_ms_;
    /// Re-sent on the cadence while awaiting the certificate / for a bounded
    /// tail after issuing it: both are otherwise single datagrams.
    std::optional<DkgTranscriptAttest> pending_transcript_attest_;
    std::optional<BootstrapCertificate> issued_certificate_;
    uint64_t certificate_issued_ms_ = 0;

    // Consensus driving.
    Pacemaker pacemaker_;
    uint64_t last_progress_ms_ = 0;
    View last_proposed_view_ = 0;
    Digest last_committed_root_{};
    Height last_committed_height_ = 0;

    // Restart sync.
    uint64_t sync_started_ms_ = 0;
    View best_synced_view_ = 0;
    bool any_sync_response_ = false;
    std::set<NodeId> sync_sources_;

    // Epoch cadence.
    uint64_t epoch_started_ms_ = 0;
    uint64_t last_reattest_ms_ = 0;

    // Mesh eligibility. The next-epoch pool comes from here and nowhere else.
    EligibilityService eligibility_;

    // Member-side boundary pipeline. The committed plan, the freshness clock
    // for final verdicts, the state-ready and failed sets, and the finalized
    // readiness. All reset at activation or abandonment.
    std::optional<NextEpochPlan> plan_;
    CommitProof plan_proof_;
    uint32_t plans_committed_ = 0;
    std::set<NodeId> boundary_failed_;
    std::map<NodeId, uint64_t> final_verdict_ms_;
    /// When each selected node was last challenged for the final attestation;
    /// the renewal pass rate-limits itself with this.
    std::map<NodeId, uint64_t> final_challenge_ms_;
    std::set<NodeId> state_ready_;
    std::optional<CandidateReadiness> readiness_;
    CommitProof readiness_proof_;
    /// When the readiness commit authorized the ceremony; zero outside one.
    uint64_t dkg_authorized_ms_ = 0;
    /// Ceremony participants' signed outcomes, for members outside it.
    std::map<NodeId, DkgTranscriptAttest> transition_attests_;

    // Candidate-side adoption state: everything this node verified for the
    // plan that names it. Grants nothing; it is what preparation runs on.
    struct CandidateAdoption {
        NextEpochPlan plan;
        Digest plan_digest{};
        std::vector<NodeId> current_members;
        std::map<NodeId, crypto::Ed25519PublicKey> current_vote_keys;
        bool state_synced = false;
        QuorumCertificate verified_qc{};
        bool dkg_authorized = false;
        Digest readiness_digest{};
    };
    std::optional<CandidateAdoption> adoption_;
    /// The pinned-genesis anchor a candidate verifies membership listings
    /// against. Stored only after its signature verified.
    std::optional<BootstrapCertificate> anchor_;
    /// The one verified epoch authority this node holds: from the Genesis
    /// certificate for Epoch 1, advanced by one verified finalized handoff
    /// per epoch after that. Grants nothing; it is what everything else is
    /// verified against.
    std::optional<VerifiedEpochAuthority> authority_;
    /// Every epoch authority this node verified, by epoch: the authenticated
    /// chain from start() plus each authority installed since. Grants nothing.
    std::map<EpochId, VerifiedEpochAuthority> authority_history_;
    /// The highest epoch any announcement or plan has named. A hint that can
    /// prompt a chain request; it never becomes state by itself.
    EpochId chain_hint_epoch_ = 0;
    uint64_t chain_request_ms_ = 0;
    std::size_t consumed_equivocations_ = 0;
    /// Peers whose transport certificate the mesh verified. Tier 2 candidates
    /// are challenged from here; the list decides nothing on its own.
    std::set<NodeId> certified_peers_;
    /// Outstanding participation challenges, one per candidate. Matched before
    /// the challenge is consumed, so a replayed answer cannot deny a live one.
    std::map<NodeId, ParticipationChallenge> pending_participation_;

    /// Block payload handlers by kind; ordered, so the leader asks them in a
    /// fixed order. Not owning.
    std::map<BlockPayloadKind, IBlockPayloadHandler*> payload_handlers_;
    std::function<void(const TreeOpSubmitMsg&, const NodeId&)> tree_op_sink_;
    std::function<void(const SecurityMessage&)> storage_sink_;
    std::function<void(const AttestationVerdict&)> storage_verdict_sink_;
    std::function<void(const SecurityMessage&)> upgrade_sink_;
    std::function<void(const AttestationVerdict&)> upgrade_verdict_sink_;
    std::function<void(const FinalizedEligibility&, const Tier1Set&)> on_eligibility_finalized_;
};

}  // namespace nexus::security
