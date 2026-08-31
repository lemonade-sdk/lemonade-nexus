#pragma once

// Where observations become the two mesh facts.
//
// The ledger is pure and deterministic: the same observations and the same
// context always give the same answer, on every correct node. It holds no
// clock, reaches no network, and grants nothing — it produces two booleans that
// Tier1EligibilityPolicy combines with platform claims.
//
// Two rules shape everything here. One observer never makes a fact, so both
// facts need a quorum of the current Tier 1 set. And observers are deduplicated
// by node identity, so a cloned member counts once no matter how many copies
// speak.
//
// Architecture reference: Security Architecture Final Draft 1.1, section 13.

#include <LemonadeNexus/Security/Eligibility/EligibilityObservation.hpp>
#include <LemonadeNexus/Security/Policy/Tier1Evidence.hpp>

#include <cstddef>
#include <map>
#include <optional>
#include <set>
#include <string_view>
#include <vector>

namespace nexus::security {

/// Why an observation was refused. Every value is a refusal; an accepted
/// observation returns Accepted.
enum class ObservationOutcome : uint16_t {
    Accepted,
    WrongNetwork,
    WrongEpoch,
    ObserverNotInTier1,
    SignatureInvalid,
    SelfObservation,
    /// A statement at or below one already held from this observer for this
    /// subject and kind. Height is monotonic, so a lower one is a rewind.
    NotNewerThanHeld,
    MalformedForKind,
};

[[nodiscard]] std::string_view observation_outcome_name(ObservationOutcome outcome);

/// The current protocol state the ledger judges observations against.
struct MeshFactContext {
    NetworkId network_id{};
    EpochId epoch{};
    /// Members entitled to observe. Frozen for the epoch, so the set an
    /// observation is judged against cannot shift under it.
    std::vector<NodeId> observers;
    /// How many distinct observers make a fact.
    std::size_t quorum{};
};

/// The established-epoch context: the frozen Tier 1 set observes, and the
/// compiled consensus quorum is the bar.
[[nodiscard]] MeshFactContext established_fact_context(const NetworkId& network_id,
                                                        EpochId epoch,
                                                        std::vector<NodeId> members);

/// The Genesis context. Before Epoch 1 there is no Tier 1 quorum to observe
/// anything, so the founding set observes itself: every founder must be seen by
/// every other founder. That is the mutual attestation and mutual connectivity
/// the bootstrap rules require, and since no node observes itself the bar is
/// one less than the founding set. The bootstrap threshold is unchanged.
[[nodiscard]] MeshFactContext genesis_fact_context(const NetworkId& network_id,
                                                    std::vector<NodeId> founders);

/// What the ledger proved, and how far short it fell when it did not. Counts
/// are diagnostic; the booleans are the result.
struct MeshFactEvidence {
    bool uptime_valid{false};
    bool mesh_health_valid{false};

    /// Observers that saw enough distinct attestations to establish continuity.
    std::size_t continuity_observers{0};
    /// Observers that saw the subject participate.
    std::size_t participation_observers{0};
    std::size_t quorum_required{0};
    bool fault_recorded{false};

    /// The platform claims a quorum of observers agreed on, left default when
    /// no single claim set reached the quorum. A quorum is a strict majority,
    /// so at most one claim set can ever qualify.
    VerifiedPlatformClaims platform_claims;
    /// Observers holding that claim set.
    std::size_t claim_observers{0};
};

class EligibilityLedger {
public:
    /// Records one observation. Refuses anything that is not a signed statement
    /// from a current member of `context.observers`, for this network and this
    /// epoch.
    [[nodiscard]] ObservationOutcome record(const EligibilityObservation& observation,
                                            const MeshFactContext& context);

    /// Records proved misbehavior. A fault denies mesh health for the rest of
    /// the epoch: it is evidence, not an opinion, so there is no appeal here.
    void record_fault(const NodeId& subject, ObjectiveFault fault);

    /// Adds a restored fault set. Faults only accumulate: a proved fault has no
    /// transition back, so nothing here can drop one.
    void merge_faults(const std::map<NodeId, std::set<ObjectiveFault>>& faults);

    [[nodiscard]] MeshFactEvidence evaluate(const NodeId& subject,
                                            IncarnationId incarnation,
                                            const MeshFactContext& context) const;

    /// The incarnation a quorum of observers attributes to `subject`, or
    /// nullopt when no single value has one. A node never attests itself, so
    /// which incarnation is live is a mesh fact like any other.
    [[nodiscard]] std::optional<IncarnationId> quorum_incarnation(
        const NodeId& subject, const MeshFactContext& context) const;

    /// The two mesh facts for one candidate. Everything else in Tier1MeshFacts
    /// comes from elsewhere; this fills in only what the mesh observed.
    void fill(Tier1MeshFacts& facts, const NodeId& subject, IncarnationId incarnation,
              const MeshFactContext& context) const;

    /// Drops everything for epochs before `epoch`. Observations expire by
    /// epoch: a node stays eligible only while the mesh keeps seeing it.
    void expire_before(EpochId epoch);

    [[nodiscard]] std::size_t size() const { return records_.size(); }

    /// One observer's accumulated view of one subject, in a form that survives
    /// a restart. The latest statement carries the signature; the digests are
    /// what continuity counts.
    struct PersistedRecord {
        EligibilityObservation latest;
        std::vector<Digest> attestations;
        IncarnationId incarnation{};
    };

    [[nodiscard]] std::vector<PersistedRecord> snapshot() const;

    /// Rebuilds from a snapshot, re-verifying every signature and re-applying
    /// every structural rule. Durable state is not trusted state: a tampered
    /// file must not be able to assert a fact the mesh never made. Returns
    /// false and leaves the ledger empty when any record fails.
    [[nodiscard]] bool restore(const std::vector<PersistedRecord>& records,
                               const MeshFactContext& context);
    [[nodiscard]] const std::map<NodeId, std::set<ObjectiveFault>>& faults() const {
        return faults_;
    }

private:
    /// One observer's statements about one subject, keyed so a second statement
    /// of the same kind replaces rather than accumulates.
    struct Key {
        EpochId epoch;
        NodeId subject;
        NodeId observer;
        ObservationKind kind;
        auto operator<=>(const Key&) const = default;
    };

    struct Record {
        EligibilityObservation latest;
        /// Distinct attestations this observer verified for this subject in
        /// this epoch, at this incarnation. Continuity counts these.
        std::set<Digest> attestations;
        IncarnationId incarnation{};
    };

    std::map<Key, Record> records_;
    std::map<NodeId, std::set<ObjectiveFault>> faults_;
};

}  // namespace nexus::security
