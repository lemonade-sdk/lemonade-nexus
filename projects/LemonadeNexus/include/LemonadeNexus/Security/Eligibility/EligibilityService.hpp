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
#include <LemonadeNexus/Security/Epoch/Tier1Set.hpp>

#include <functional>
#include <map>
#include <optional>
#include <vector>

namespace nexus::security {

/// What one authenticated security-plane message proved about its sender.
///
/// The caller assembles this from a consensus vote the local replica already
/// validated: the vote is signed under the epoch vote key the mesh froze for
/// that member, names the network, epoch and consensus ruleset, and votes at a
/// height. The subject asserts none of it, and no field here is a health score.
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
    void record_verdict(const AttestationVerdict& verdict);

    /// Signs this node's statement that it verified a fresh attestation from
    /// the subject. Returns nullopt when nothing is provable — a failing
    /// verdict, this node itself, or a subject outside the observed set.
    [[nodiscard]] std::optional<EligibilityObservation> observe_attestation(
        const AttestationVerdict& verdict, Height height, const Digest& state_reference);

    /// Signs this node's statement that the subject participated. Every fact in
    /// the proof is checked against the current context first; a proof that
    /// fails any of them yields no observation.
    [[nodiscard]] std::optional<EligibilityObservation> observe_participation(
        const ParticipationProof& proof, Height height, const Digest& state_reference);

    /// Records an observation from any observer, including this node's own.
    [[nodiscard]] ObservationOutcome accept(const EligibilityObservation& observation);

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

    /// Writes observations and faults. Called after every accepted change, so a
    /// restart resumes from what the mesh actually said.
    [[nodiscard]] bool persist();

    [[nodiscard]] const MeshFactContext& context() const { return context_; }
    [[nodiscard]] const EligibilityLedger& ledger() const { return ledger_; }
    [[nodiscard]] const EligibilityStore& store() const { return store_; }

private:
    [[nodiscard]] bool observed(const NodeId& node) const;
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
};

}  // namespace nexus::security
