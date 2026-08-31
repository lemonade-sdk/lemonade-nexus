#include <LemonadeNexus/Security/Eligibility/EligibilityLedger.hpp>

#include <LemonadeNexus/Security/Eligibility/EligibilityState.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <algorithm>
#include <utility>

namespace nexus::security {

std::string_view observation_outcome_name(ObservationOutcome outcome) {
    switch (outcome) {
        case ObservationOutcome::Accepted:           return "accepted";
        case ObservationOutcome::WrongNetwork:       return "wrong network";
        case ObservationOutcome::WrongEpoch:         return "wrong epoch";
        case ObservationOutcome::ObserverNotInTier1: return "observer is not a Tier 1 member";
        case ObservationOutcome::SignatureInvalid:   return "signature invalid";
        case ObservationOutcome::SelfObservation:    return "a node cannot observe itself";
        case ObservationOutcome::NotNewerThanHeld:   return "not newer than the held statement";
        case ObservationOutcome::MalformedForKind:   return "malformed for its kind";
    }
    return "unknown outcome";
}

MeshFactContext established_fact_context(const NetworkId& network_id, EpochId epoch,
                                          std::vector<NodeId> members) {
    MeshFactContext context;
    context.network_id = network_id;
    context.epoch = epoch;
    context.quorum = constants::consensus_quorum(members.size());
    context.observers = std::move(members);
    return context;
}

MeshFactContext genesis_fact_context(const NetworkId& network_id,
                                      std::vector<NodeId> founders) {
    MeshFactContext context;
    context.network_id = network_id;
    context.epoch = 0;
    // Before Epoch 1 there is no BFT quorum: the committee is the whole
    // founding set. Self-exclusion then puts the bar at every other founder.
    context.quorum = founders.size();
    context.observers = std::move(founders);
    return context;
}

std::size_t witness_threshold(const MeshFactContext& context, const NodeId& subject) {
    const bool in_committee =
        std::find(context.observers.begin(), context.observers.end(), subject) !=
        context.observers.end();
    if (!in_committee) {
        return context.quorum;
    }
    // One honest witness must always be out of the adversary's reach.
    const std::size_t floor = constants::max_byzantine_faults(context.observers.size()) + 1;
    return std::max(context.quorum > 0 ? context.quorum - 1 : 0, floor);
}

ObservationOutcome EligibilityLedger::record(const EligibilityObservation& observation,
                                              const MeshFactContext& context) {
    if (observation.network_id != context.network_id) {
        return ObservationOutcome::WrongNetwork;
    }
    if (observation.epoch != context.epoch) {
        return ObservationOutcome::WrongEpoch;
    }
    if (observation.observer == observation.subject) {
        return ObservationOutcome::SelfObservation;
    }
    if (std::find(context.observers.begin(), context.observers.end(), observation.observer) ==
        context.observers.end()) {
        return ObservationOutcome::ObserverNotInTier1;
    }
    if (observation.kind == ObservationKind::Attestation) {
        if (observation.attestation_digest == Digest{}) {
            return ObservationOutcome::MalformedForKind;
        }
        // Claims that contradict their own structure are a bug, not a proof.
        if (!platform_claims_are_consistent(observation.claims)) {
            return ObservationOutcome::MalformedForKind;
        }
    } else if (observation.attestation_digest != Digest{} ||
               platform_claim_bits(observation.claims) != 0 ||
               observation.claims.profile_id != AttestationProfileId::Unknown) {
        // A vote proves participation and nothing about hardware. An
        // observation that carries platform claims under this kind is
        // malformed rather than generous.
        return ObservationOutcome::MalformedForKind;
    }
    // Cheap checks first; the signature is the expensive one.
    if (!observation_signature_valid(observation)) {
        return ObservationOutcome::SignatureInvalid;
    }

    const Key key{observation.epoch, observation.subject, observation.observer,
                  observation.kind};
    auto it = records_.find(key);
    if (it == records_.end()) {
        Record record;
        record.latest = observation;
        record.incarnation = observation.subject_incarnation;
        if (observation.kind == ObservationKind::Attestation) {
            record.attestations.insert(observation.attestation_digest);
        }
        records_.emplace(key, std::move(record));
        return ObservationOutcome::Accepted;
    }

    // Height is monotonic and quorum-certified. A statement at or below the one
    // already held is a rewind, and accepting it would let an observer replay
    // its way back to a state the mesh has left.
    if (observation.height <= it->second.latest.height) {
        return ObservationOutcome::NotNewerThanHeld;
    }

    // A subject that changed incarnation is a different live node. Continuity
    // does not carry across: the count starts again.
    if (observation.subject_incarnation != it->second.incarnation) {
        it->second.attestations.clear();
        it->second.incarnation = observation.subject_incarnation;
    }
    it->second.latest = observation;
    if (observation.kind == ObservationKind::Attestation &&
        it->second.attestations.size() < constants::kMaxContinuityAttestations) {
        it->second.attestations.insert(observation.attestation_digest);
    }
    return ObservationOutcome::Accepted;
}

void EligibilityLedger::record_fault(const NodeId& subject, ObjectiveFault fault) {
    faults_[subject].insert(fault);
}

void EligibilityLedger::merge_faults(const std::map<NodeId, std::set<ObjectiveFault>>& faults) {
    for (const auto& [subject, kinds] : faults) {
        faults_[subject].insert(kinds.begin(), kinds.end());
    }
}

MeshFactEvidence EligibilityLedger::evaluate(const NodeId& subject,
                                              IncarnationId incarnation,
                                              const MeshFactContext& context) const {
    MeshFactEvidence evidence;
    evidence.quorum_required = witness_threshold(context, subject);
    evidence.fault_recorded = faults_.contains(subject);

    // A bar of zero would make both facts true on no evidence at all.
    if (evidence.quorum_required == 0) {
        return evidence;
    }

    // Claim sets seen for this subject, by digest: count and one exemplar.
    std::map<Digest, std::pair<std::size_t, VerifiedPlatformClaims>> claim_counts;

    // Deduplicated by observer identity: the map key holds one entry per
    // observer, so a cloned member speaking twice still counts once.
    for (const auto& [key, record] : records_) {
        if (key.epoch != context.epoch || key.subject != subject) {
            continue;
        }
        if (record.incarnation != incarnation) {
            continue;
        }
        // The observer must still be a member. A set frozen for the epoch
        // cannot shift, but an observation may outlive its observer's place in
        // an earlier one.
        if (std::find(context.observers.begin(), context.observers.end(), key.observer) ==
            context.observers.end()) {
            continue;
        }
        if (key.kind == ObservationKind::Attestation) {
            if (record.attestations.size() >= constants::kMinContinuityObservations) {
                ++evidence.continuity_observers;
            }
            auto& seen = claim_counts[platform_claims_digest(record.latest.claims)];
            ++seen.first;
            seen.second = record.latest.claims;
        } else {
            ++evidence.participation_observers;
        }
    }

    // The platform half is a quorum fact too. A quorum is a strict majority, so
    // at most one claim set can reach it and the winner is unambiguous.
    for (const auto& [digest, entry] : claim_counts) {
        if (entry.first >= evidence.quorum_required) {
            evidence.platform_claims = entry.second;
            evidence.claim_observers = entry.first;
            break;
        }
    }

    evidence.uptime_valid = evidence.continuity_observers >= evidence.quorum_required;
    evidence.mesh_health_valid = !evidence.fault_recorded &&
                                 evidence.participation_observers >= evidence.quorum_required;
    return evidence;
}

std::optional<IncarnationId> EligibilityLedger::quorum_incarnation(
    const NodeId& subject, const MeshFactContext& context) const {
    const std::size_t required = witness_threshold(context, subject);
    if (required == 0) {
        return std::nullopt;
    }
    // By observer identity, so one observer speaking of both kinds counts once.
    std::map<IncarnationId, std::set<NodeId>> observers;
    for (const auto& [key, record] : records_) {
        if (key.epoch != context.epoch || key.subject != subject) {
            continue;
        }
        if (std::find(context.observers.begin(), context.observers.end(), key.observer) ==
            context.observers.end()) {
            continue;
        }
        observers[record.incarnation].insert(key.observer);
    }
    for (const auto& [incarnation, seen] : observers) {
        if (seen.size() >= required) {
            return incarnation;
        }
    }
    return std::nullopt;
}

void EligibilityLedger::fill(Tier1MeshFacts& facts, const NodeId& subject,
                             IncarnationId incarnation,
                             const MeshFactContext& context) const {
    const MeshFactEvidence evidence = evaluate(subject, incarnation, context);
    facts.uptime_valid = evidence.uptime_valid;
    facts.mesh_health_valid = evidence.mesh_health_valid;
}

std::vector<NodeId> EligibilityLedger::subjects(EpochId epoch,
                                                std::size_t min_observers) const {
    std::map<NodeId, std::set<NodeId>> observers;
    for (const auto& [key, record] : records_) {
        if (key.epoch == epoch) {
            observers[key.subject].insert(key.observer);
        }
    }
    std::vector<NodeId> named;
    for (const auto& [subject, seen] : observers) {
        if (seen.size() >= min_observers) {
            named.push_back(subject);
        }
    }
    return named;
}

void EligibilityLedger::expire_before(EpochId epoch) {
    for (auto it = records_.begin(); it != records_.end();) {
        it = it->first.epoch < epoch ? records_.erase(it) : std::next(it);
    }
}

std::vector<EligibilityLedger::PersistedRecord> EligibilityLedger::snapshot() const {
    std::vector<PersistedRecord> out;
    out.reserve(records_.size());
    for (const auto& [key, record] : records_) {
        PersistedRecord persisted;
        persisted.latest = record.latest;
        persisted.incarnation = record.incarnation;
        persisted.attestations.assign(record.attestations.begin(), record.attestations.end());
        out.push_back(std::move(persisted));
    }
    return out;
}

bool EligibilityLedger::restore(const std::vector<PersistedRecord>& records,
                                 const MeshFactContext& context) {
    records_.clear();
    for (const auto& persisted : records) {
        // Every rule record() applies is applied again. A file an attacker
        // edited must not be able to assert a fact no observer signed.
        EligibilityLedger probe;
        if (probe.record(persisted.latest, context) != ObservationOutcome::Accepted) {
            records_.clear();
            return false;
        }
        if (persisted.attestations.size() > constants::kMaxContinuityAttestations) {
            records_.clear();
            return false;
        }
        if (persisted.incarnation != persisted.latest.subject_incarnation) {
            records_.clear();
            return false;
        }
        const Key key{persisted.latest.epoch, persisted.latest.subject,
                      persisted.latest.observer, persisted.latest.kind};
        if (records_.contains(key)) {
            records_.clear();
            return false;
        }
        Record record;
        record.latest = persisted.latest;
        record.incarnation = persisted.incarnation;
        if (persisted.latest.kind == ObservationKind::Attestation) {
            record.attestations.insert(persisted.attestations.begin(),
                                       persisted.attestations.end());
            // A record claiming continuity it cannot show is refused: the
            // digests are the proof, not the count.
            if (record.attestations.empty()) {
                records_.clear();
                return false;
            }
        } else if (!persisted.attestations.empty()) {
            records_.clear();
            return false;
        }
        records_.emplace(key, std::move(record));
    }
    return true;
}

}  // namespace nexus::security
