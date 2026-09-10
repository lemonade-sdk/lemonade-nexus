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

    /// The canonical final-attestation context for one selected node under
    /// one plan, or an empty digest when the plan does not name the node.
    /// Pure derivation; public so a verifier of captured traffic can rebuild
    /// the exact value a challenge bound.
    [[nodiscard]] static Digest plan_attest_context(const NextEpochPlan& plan,
                                                    const NodeId& node);

    [[nodiscard]] const EligibilityService& eligibility() const { return eligibility_; }

private:
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
    /// Advances the anchor through any stored links past it. Local recovery
    /// only: every link is re-verified before it counts.
    void catch_up_authority_from_store();
    /// Asks the mesh for chain links when something hints this node is
    /// behind. The ask is idempotent and free of authority.
    void maybe_request_chain();
    void broadcast_proof(SecurityMessageKind kind, SecurityBody body, EpochId epoch);
    [[nodiscard]] bool candidate_verify_proof(const Digest& transitions_digest,
                                              const CommitProof& proof) const;
    void do_activate(const Digest& checkpoint);
    void persist_current_epoch(const Digest& checkpoint);
    void announce_epoch(const Digest& checkpoint);

    [[nodiscard]] Digest genesis_attestation_root(const Tier1Set& founders) const;

    /// Installs the frozen observer set for `epoch` and restores durable
    /// observations. Corrupt eligibility state fails the driver: lost history
    /// is never a clean slate.
    [[nodiscard]] bool enter_eligibility_epoch(EpochId epoch, const Tier1Set& members);
    [[nodiscard]] bool epoch_aged(uint64_t now_ms) const;
    void publish(const EligibilityObservation& observation, EpochId epoch);
    void begin_founding_observations();
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
    /// The founding eligibility state this node computed and signed. The
    /// bootstrap certificate must name exactly this value or it is refused.
    Digest founding_eligibility_digest_{};
    std::map<NodeId, Digest> founding_eligibility_attests_;
    /// Before Epoch 1 there is no certified height, so the founding round
    /// counts its own rounds to keep observation heights monotonic.
    Height founding_round_ = 0;

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
};

}  // namespace nexus::security
