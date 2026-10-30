#pragma once

// The live eligibility path.
//
// The service holds what this node observed, the faults it can prove, and the
// platform claims it verified, and turns them into one deterministic
// EligibilityState. It grants nothing: the state becomes authoritative only
// when HotStuff finalizes its digest, and the frozen pool stays withheld unless
// this node's own recomputation still matches what was finalized.
//
// That last rule is what makes a rollback safe. A node whose durable
// observations were rolled back recomputes a different state, cannot match the
// finalized digest, and therefore cannot select. A rollback costs availability;
// it never creates authority.
//
// Architecture reference: Security Architecture Final Draft 1.1, section 13.

#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>
#include <LemonadeNexus/Security/Eligibility/EligibilityState.hpp>
#include <LemonadeNexus/Security/Eligibility/EligibilityStore.hpp>
#include <LemonadeNexus/Security/Eligibility/ParticipationProof.hpp>
#include <LemonadeNexus/Security/Epoch/Tier1Set.hpp>

#include <functional>
#include <map>
#include <optional>
#include <set>
#include <vector>

namespace nexus::security {

/// What one authenticated security-plane message proved about its sender.
///
/// There are two ways to fill this in and they produce the same fact. For a
/// current Tier 1 member the caller assembles it from a consensus vote the
/// local replica already validated — signed under the epoch vote key the mesh
/// froze, naming the network, epoch and consensus ruleset, at a height. For a
/// candidate that holds no vote key it comes from a verified participation
/// response. The subject asserts none of it either way, and no field here is a
/// health score.
struct ParticipationProof {
    NetworkId network_id{};
    EpochId epoch{};
    ConsensusRulesetVersion consensus_ruleset{};
    NodeId subject{};
    IncarnationId incarnation{};
    /// The height the subject voted at. At or above the observer's own
    /// finalized floor is what proves the subject is synchronized.
    Height subject_height{};
};

/// A consensus-finalized eligibility state.
struct FinalizedEligibility {
    /// The transitions digest the block carried.
    Digest commitment{};
    /// The certificate that committed it.
    Digest consensus_reference{};
    Height height{};
    /// The committed state root at that height. The next-epoch plan anchors
    /// its checkpoint here, so every honest node names the same one.
    Digest state_root{};
    EpochId next_epoch{};
};

enum class EligibilityRestore { Fresh, Restored, Corrupt };

class EligibilityService {
public:
    EligibilityService(NetworkId network_id, NodeId self, crypto::Ed25519Keypair identity,
                       std::filesystem::path directory);

    /// Installs the frozen observer set for an established epoch and restores
    /// durable observations. Any finalization from before is dropped: a
    /// restarted node must reach finality again through the mesh, never read it
    /// off its own disk.
    [[nodiscard]] EligibilityRestore enter_epoch(EpochId epoch, std::vector<NodeId> members);

    /// The pre-Epoch-1 context: the founding set observes itself, so every
    /// founder must be seen by every other one.
    [[nodiscard]] EligibilityRestore enter_genesis(std::vector<NodeId> founders);

    /// Answers whether a candidate holds a root-signed transport certificate.
    /// Unset leaves the fact false, which is one of the Tier 1 prerequisites,
    /// so an unwired mesh fails closed rather than admitting anyone.
    void set_certificate_source(std::function<bool(const NodeId&)> source);

    /// Records the platform half of a verdict this node verified. Two passing
    /// verdicts in one epoch that disagree about the incarnation are objective
    /// evidence of a duplicate incarnation, and record it as a fault.
    ///
    /// A fault is a permanent fact about a node, so it is written at once and
    /// never held in a write window.
    void record_verdict(const AttestationVerdict& verdict);

    /// Signs this node's statement about the attestation it verified for
    /// `subject`.
    ///
    /// The claims come from the verdict this node's own verifier produced and
    /// recorded, never from a value a caller supplies: an observer may sign
    /// platform claims only for evidence it verified itself, and there is no
    /// path here that relays someone else's. Returns nullopt when nothing is
    /// provable.
    [[nodiscard]] std::optional<EligibilityObservation> observe_attestation(
        const NodeId& subject, Height height, const Digest& state_reference);

    /// Signs this node's statement that the subject participated. Every fact in
    /// the proof is checked against the current context first; a proof that
    /// fails any of them yields no observation.
    [[nodiscard]] std::optional<EligibilityObservation> observe_participation(
        const ParticipationProof& proof, Height height, const Digest& state_reference);

    /// The candidate path: verifies one participation response against the
    /// challenge that provoked it, then signs the same observation a validated
    /// vote would produce. Holding no epoch vote key is not a disqualification;
    /// it only means the subject cannot prove participation by voting.
    [[nodiscard]] std::optional<EligibilityObservation> observe_participation_response(
        const ParticipationResponse& response, const ParticipationChallenge& challenge,
        Height height, const Digest& state_reference);

    /// Records an observation from any observer, including this node's own.
    /// An accepted observation marks the store dirty; flush() writes it.
    [[nodiscard]] ObservationOutcome accept(const EligibilityObservation& observation);

    /// Records proved misbehavior and writes the fault set at once, so a fault
    /// never sits in a delay window.
    void record_fault(const NodeId& subject, ObjectiveFault fault);

    /// The state this node would finalize for the given boundary.
    [[nodiscard]] EligibilityState compute_state(EpochId next_epoch) const;

    /// True when every observer has stated both facts about every other member.
    /// That is the complete mutual round the Genesis founding transcript
    /// commits to, and the point at which the transcript is deterministic.
    [[nodiscard]] bool mutual_round_complete() const;

    /// Records that consensus committed an eligibility commitment. The caller
    /// passes the digest the block carried, so a node that arrived elsewhere
    /// simply never calls this and never selects.
    void finalize(const FinalizedEligibility& finalized);
    void clear_finalization() { finalized_.reset(); }
    [[nodiscard]] const FinalizedEligibility* finalized() const {
        return finalized_.has_value() ? &*finalized_ : nullptr;
    }

    /// The frozen next-epoch pool. Empty unless a finalized state exists for
    /// this boundary AND this node's recomputation still matches it.
    [[nodiscard]] std::optional<Tier1Set> frozen_pool(EpochId next_epoch) const;

    /// Writes what changed since the last write: the observations of the
    /// current epoch when an accepted observation made them dirty, and the
    /// fault set when it differs from the last written one. Returns false when
    /// a needed write failed; the dirty state then stays set, so the next call
    /// tries again.
    ///
    /// accept() only marks the observations dirty. The caller decides when to
    /// write (SecurityDriver writes at most once per
    /// kEligibilityFlushIntervalMs and on shutdown). A crash in between loses
    /// at most the observations accepted since the last write. That is a
    /// same-epoch rollback, which costs availability and never creates
    /// authority (see the file comment). Faults are not delayed: record_fault()
    /// writes them at once.
    [[nodiscard]] bool flush();

    /// True when accepted observations wait for flush().
    [[nodiscard]] bool dirty() const { return observations_dirty_; }

    [[nodiscard]] Height max_observed_height() const {
        return ledger_.max_height(context_.epoch);
    }
    [[nodiscard]] const MeshFactContext& context() const { return context_; }
    [[nodiscard]] const EligibilityLedger& ledger() const { return ledger_; }
    [[nodiscard]] const EligibilityStore& store() const { return store_; }

    /// Every node the state judges: the current committee plus any subject
    /// enough observers have spoken about. Sorted.
    [[nodiscard]] std::vector<NodeId> candidates() const;

    /// True when this node may witness at all. Only a current committee member
    /// signs observations.
    [[nodiscard]] bool is_observer() const { return observed(self_); }

private:
    [[nodiscard]] bool observed(const NodeId& node) const;
    [[nodiscard]] std::optional<EligibilityObservation> sign_participation(
        const NodeId& subject, IncarnationId incarnation, Height height,
        const Digest& state_reference);
    [[nodiscard]] EligibilityRestore install(EpochId epoch, MeshFactContext context);

    NetworkId network_id_;
    NodeId self_;
    crypto::Ed25519Keypair identity_;
    EligibilityStore store_;

    MeshFactContext context_;
    EligibilityLedger ledger_;

    std::map<NodeId, AttestationVerdict> verdicts_;
    std::map<NodeId, IncarnationId> incarnations_;

    std::function<bool(const NodeId&)> certificate_source_;
    std::optional<FinalizedEligibility> finalized_;

    /// True when accepted observations wait for flush(). Only flush() clears
    /// it, so a failed write stays pending for the next attempt.
    bool observations_dirty_ = false;

    /// The fault set as last written successfully. Empty optional means nothing
    /// is known to be on disk, so the next write writes the file once.
    std::optional<std::map<NodeId, std::set<ObjectiveFault>>> faults_written_;
};

}  // namespace nexus::security
