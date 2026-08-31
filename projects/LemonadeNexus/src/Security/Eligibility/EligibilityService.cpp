#include <LemonadeNexus/Security/Eligibility/EligibilityService.hpp>

#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <algorithm>
#include <utility>

namespace nexus::security {

namespace {

/// The incarnation an epoch freezes for a member this node has not itself
/// attested yet. Every incarnation in the tree is 1; a member that presents a
/// different one inside a frozen epoch is what DuplicateIncarnation catches.
constexpr IncarnationId kFrozenIncarnation = 1;

}  // namespace

EligibilityService::EligibilityService(NetworkId network_id, NodeId self,
                                       crypto::Ed25519Keypair identity,
                                       std::filesystem::path directory)
    : network_id_(network_id),
      self_(self),
      identity_(std::move(identity)),
      store_(std::move(directory)) {}

// --- Context -----------------------------------------------------------------

EligibilityRestore EligibilityService::install(EpochId epoch, MeshFactContext context) {
    context_ = std::move(context);
    ledger_ = EligibilityLedger{};
    verdicts_.clear();
    incarnations_.clear();
    // A restart never inherits finality. It has to be reached again through the
    // mesh, which is what stops a rolled-back snapshot from carrying authority.
    finalized_.reset();

    auto faults = store_.load_faults();
    if (const auto* result = std::get_if<EligibilityLoadResult>(&faults)) {
        if (*result == EligibilityLoadResult::Corrupt) {
            return EligibilityRestore::Corrupt;
        }
    } else {
        ledger_.merge_faults(
            std::get<std::map<NodeId, std::set<ObjectiveFault>>>(faults));
    }

    const auto loaded = store_.load(epoch, context_, ledger_);
    if (const auto* result = std::get_if<EligibilityLoadResult>(&loaded)) {
        return *result == EligibilityLoadResult::Corrupt ? EligibilityRestore::Corrupt
                                                         : EligibilityRestore::Fresh;
    }
    store_.discard_before(epoch);
    return EligibilityRestore::Restored;
}

EligibilityRestore EligibilityService::enter_epoch(EpochId epoch, std::vector<NodeId> members) {
    return install(epoch, established_fact_context(network_id_, epoch, std::move(members)));
}

EligibilityRestore EligibilityService::enter_genesis(std::vector<NodeId> founders) {
    return install(0, genesis_fact_context(network_id_, std::move(founders)));
}

void EligibilityService::set_certificate_source(std::function<bool(const NodeId&)> source) {
    certificate_source_ = std::move(source);
}

bool EligibilityService::observed(const NodeId& node) const {
    return std::find(context_.observers.begin(), context_.observers.end(), node) !=
           context_.observers.end();
}

// --- Evidence ----------------------------------------------------------------

void EligibilityService::record_verdict(const AttestationVerdict& verdict) {
    if (!verdict.passed) {
        return;
    }
    const auto held = incarnations_.find(verdict.node_id);
    if (held != incarnations_.end() && held->second != verdict.incarnation) {
        // Two identity-signed bundles naming different incarnations inside one
        // frozen epoch. That is proved misbehavior, not a judgement about a
        // peer, so it is recorded as a fault.
        record_fault(verdict.node_id, ObjectiveFault::DuplicateIncarnation);
    }
    incarnations_[verdict.node_id] = verdict.incarnation;
    verdicts_[verdict.node_id] = verdict;
}

std::optional<EligibilityObservation> EligibilityService::observe_attestation(
    const NodeId& subject, Height height, const Digest& state_reference) {
    // Only a current committee member witnesses, and never itself.
    if (!is_observer() || subject == self_) {
        return std::nullopt;
    }
    // The claims come from what this node's own verifier produced. There is no
    // parameter here a caller could use to sign a claim set it did not verify.
    const auto held = verdicts_.find(subject);
    if (held == verdicts_.end()) {
        return std::nullopt;
    }
    const AttestationVerdict& verdict = held->second;
    if (!verdict.passed || verdict.node_id != subject) {
        return std::nullopt;
    }
    // Continuity counts distinct attestations, so a statement without one
    // proves nothing about how long the subject has been there.
    if (verdict.evidence_digest == Digest{}) {
        return std::nullopt;
    }

    EligibilityObservation observation;
    observation.network_id = context_.network_id;
    observation.epoch = context_.epoch;
    observation.subject = verdict.node_id;
    observation.subject_incarnation = verdict.incarnation;
    observation.kind = ObservationKind::Attestation;
    observation.attestation_digest = verdict.evidence_digest;
    // What this verifier proved. A quorum agreeing on one claim set is what
    // makes the platform half of eligibility a mesh fact rather than a local
    // opinion.
    observation.claims = verdict.claims;
    observation.height = height;
    observation.state_reference = state_reference;

    observation = sign_observation(std::move(observation), identity_);
    if (accept(observation) != ObservationOutcome::Accepted) {
        return std::nullopt;
    }
    return observation;
}

std::optional<EligibilityObservation> EligibilityService::observe_participation(
    const ParticipationProof& proof, Height height, const Digest& state_reference) {
    // Every fact the observation will assert is checked here. The subject
    // supplied none of them: they come from a message the local replica already
    // validated against the epoch's frozen membership and vote keys.
    if (proof.network_id != context_.network_id || proof.epoch != context_.epoch) {
        return std::nullopt;
    }
    if (proof.consensus_ruleset != constants::kConsensusRulesetVersion) {
        return std::nullopt;
    }
    // Only a current committee member witnesses, and never itself. The subject
    // need not be one: a candidate has to be able to prove participation before
    // it is selected, or Tier 1 could only ever be renewed and never entered.
    if (!is_observer() || proof.subject == self_) {
        return std::nullopt;
    }
    const auto held = incarnations_.find(proof.subject);
    const IncarnationId expected = held != incarnations_.end() ? held->second : kFrozenIncarnation;
    if (proof.incarnation != expected) {
        return std::nullopt;
    }
    // Synchronization, in both directions. Below the observer's own finalized
    // floor is a stale reference; implausibly above it is a future one, and
    // neither proves the subject is where the mesh is.
    if (proof.subject_height < height ||
        proof.subject_height > height + constants::kMaxFutureViewDistance) {
        return std::nullopt;
    }
    return sign_participation(proof.subject, proof.incarnation, height, state_reference);
}

std::optional<EligibilityObservation> EligibilityService::observe_participation_response(
    const ParticipationResponse& response, const ParticipationChallenge& challenge,
    Height height, const Digest& state_reference) {
    if (!is_observer() || response.node_id == self_) {
        return std::nullopt;
    }
    // The challenge must be one this node issued, for this network and epoch,
    // naming the finalized state this node holds.
    if (challenge.observer != self_ || challenge.network_id != context_.network_id ||
        challenge.epoch != context_.epoch) {
        return std::nullopt;
    }
    if (challenge.security_ruleset != constants::kSecurityRulesetVersion ||
        challenge.consensus_ruleset != constants::kConsensusRulesetVersion) {
        return std::nullopt;
    }
    if (challenge.anchor_height != height || challenge.anchor_state != state_reference) {
        return std::nullopt;
    }
    if (verify_participation_response(response, challenge) != ParticipationFailure::None) {
        return std::nullopt;
    }
    // A subject this node has attested must answer at the incarnation it
    // attested; one it has not yet attested answers at the frozen incarnation.
    const auto held = incarnations_.find(response.node_id);
    const IncarnationId expected = held != incarnations_.end() ? held->second : kFrozenIncarnation;
    if (response.incarnation != expected) {
        return std::nullopt;
    }
    return sign_participation(response.node_id, response.incarnation, height, state_reference);
}

std::optional<EligibilityObservation> EligibilityService::sign_participation(
    const NodeId& subject, IncarnationId incarnation, Height height,
    const Digest& state_reference) {
    EligibilityObservation observation;
    observation.network_id = context_.network_id;
    observation.epoch = context_.epoch;
    observation.subject = subject;
    observation.subject_incarnation = incarnation;
    observation.kind = ObservationKind::Participation;
    observation.height = height;
    observation.state_reference = state_reference;

    observation = sign_observation(std::move(observation), identity_);
    if (accept(observation) != ObservationOutcome::Accepted) {
        return std::nullopt;
    }
    return observation;
}

ObservationOutcome EligibilityService::accept(const EligibilityObservation& observation) {
    const ObservationOutcome outcome = ledger_.record(observation, context_);
    if (outcome == ObservationOutcome::Accepted) {
        (void)persist();
    }
    return outcome;
}

void EligibilityService::record_fault(const NodeId& subject, ObjectiveFault fault) {
    ledger_.record_fault(subject, fault);
    (void)store_.store_faults(ledger_.faults());
}

// --- State -------------------------------------------------------------------

EligibilityState EligibilityService::compute_state(EpochId next_epoch) const {
    EligibilityState state;
    state.network_id = context_.network_id;
    state.epoch = context_.epoch;
    state.next_epoch = next_epoch;
    state.security_ruleset = constants::kSecurityRulesetVersion;
    state.consensus_ruleset = constants::kConsensusRulesetVersion;
    state.quorum = context_.quorum;

    const auto observers = Tier1Set::from_nodes(context_.observers);
    if (!observers.has_value()) {
        return state;
    }
    state.observer_set = observers->digest();

    // Evidence belongs to the epoch its observations do. At Genesis that is the
    // bootstrap window, epoch 0, not the epoch being founded.
    const EpochId verdict_epoch = context_.epoch;

    for (const NodeId& subject : candidates()) {
        EligibilityRecord record;
        record.subject = subject;
        // Every input is a mesh fact. A node never attests itself, so reading
        // any of this from the local verifier's own view would make two honest
        // nodes compute different states and never finalize one.
        record.incarnation =
            ledger_.quorum_incarnation(subject, context_).value_or(kFrozenIncarnation);
        const MeshFactEvidence evidence = ledger_.evaluate(subject, record.incarnation, context_);

        Tier1MeshFacts facts;
        facts.certificate_valid = certificate_source_ && certificate_source_(subject);
        facts.current_epoch = verdict_epoch;
        facts.current_incarnation = record.incarnation;
        facts.uptime_valid = evidence.uptime_valid;
        facts.mesh_health_valid = evidence.mesh_health_valid;

        record.uptime_valid = evidence.uptime_valid;
        record.mesh_health_valid = evidence.mesh_health_valid;
        record.certificate_valid = facts.certificate_valid;
        record.platform_claims = platform_claims_digest(evidence.platform_claims);

        const auto fault = ledger_.faults().find(subject);
        if (fault != ledger_.faults().end()) {
            for (const auto kind : fault->second) {
                record.faults |= objective_fault_bit(kind);
            }
        }

        // The one decision, taken by the one policy that may take it.
        AttestationVerdict attested;
        attested.node_id = subject;
        attested.epoch = verdict_epoch;
        attested.incarnation = record.incarnation;
        attested.claims = evidence.platform_claims;
        record.eligible = Tier1EligibilityPolicy::evaluate(tier1_evidence_state(
                              attested, facts)) == Tier1Eligibility::Eligible;
        state.records.push_back(record);
    }
    return state;
}

std::vector<NodeId> EligibilityService::candidates() const {
    std::set<NodeId> all(context_.observers.begin(), context_.observers.end());
    // A subject a Byzantine minority alone named is not a candidate: f + 1
    // distinct observers must have spoken about it.
    const std::size_t minimum =
        constants::max_byzantine_faults(context_.observers.size()) + 1;
    for (const NodeId& subject : ledger_.subjects(context_.epoch, minimum)) {
        all.insert(subject);
    }
    return {all.begin(), all.end()};
}

bool EligibilityService::mutual_round_complete() const {
    if (context_.observers.size() < 2) {
        return false;
    }
    const std::size_t expected = context_.observers.size() - 1;
    for (const NodeId& subject : context_.observers) {
        const IncarnationId id =
            ledger_.quorum_incarnation(subject, context_).value_or(kFrozenIncarnation);
        const MeshFactEvidence evidence = ledger_.evaluate(subject, id, context_);
        if (evidence.continuity_observers < expected ||
            evidence.participation_observers < expected) {
            return false;
        }
    }
    return true;
}

void EligibilityService::finalize(const FinalizedEligibility& finalized) {
    finalized_ = finalized;
}

std::optional<Tier1Set> EligibilityService::frozen_pool(EpochId next_epoch) const {
    if (!finalized_.has_value() || finalized_->next_epoch != next_epoch) {
        return std::nullopt;
    }
    const EligibilityState state = compute_state(next_epoch);
    // The finalized digest is the authority. A local state that no longer
    // reproduces it — rolled back, edited, or simply behind — releases nothing.
    if (eligibility_commitment_digest(state) != finalized_->commitment) {
        return std::nullopt;
    }
    return Tier1Set::from_nodes(eligible_nodes(state));
}

bool EligibilityService::persist() {
    const bool observations = store_.store(context_.epoch, ledger_.snapshot());
    const bool faults = store_.store_faults(ledger_.faults());
    return observations && faults;
}

}  // namespace nexus::security
