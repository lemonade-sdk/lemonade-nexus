#pragma once

// Upgrade turns through consensus (Design-Auto-Update Phase 5).
//
// The rollout of one release is a chain of finalized UpgradeProgress records
// (BlockPayloadKind::UpgradeProgress):
//
//   Start     fixes the release, its approval digest, and the participant
//             order. The order is deterministic: Tier 2 servers first, then
//             Tier 1, each group ascending by SHA-256 of the release number
//             and the node id.
//   Turn      gives the next server in the order its turn. It carries that
//             server's signed Ready status: a request, never a grant. From
//             this record until Upgraded or Halt the server counts as down.
//   Upgraded  carries signed observations from a witness quorum of current
//             Tier 1 members. Each witness saw the server pass an
//             UpgradeHealth attestation at this chain position, with every
//             measured executable hash listed in the release's own paths.
//   Halt      carries the server's signed Failed status. It stops the
//             rollout of that release; only a newer release starts again.
//
// The rules here are pure and deterministic. The vote-time inputs (status
// freshness against the voter's clock, and that every other participant is
// live) belong to UpgradeService::validate; a record finalizes only when a
// consensus quorum agreed on them independently.
//
// Tier 2 servers have no authority in this protocol. A Tier 2 server only
// signs its own status. Witnesses are current Tier 1 members.

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Consensus/BlockPayload.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstdint>
#include <optional>
#include <set>
#include <span>
#include <string_view>
#include <vector>

namespace nexus::security {

inline constexpr uint8_t kUpgradeRecordVersion = 1;

enum class UpgradeEvent : uint8_t {
    Start = 1,
    Turn = 2,
    Upgraded = 3,
    Halt = 4,
};

/// Status flags. A status with Failed never also counts as Ready.
enum UpgradeStatusFlag : uint8_t {
    /// The updater staged `staged_release` and asks for a turn.
    kUpgradeStatusReady = 1,
    /// The updater's health gate failed for `staged_release` and it rolled
    /// back.
    kUpgradeStatusFailed = 2,
    /// The server holds verified epoch authority and its security driver has
    /// not failed.
    kUpgradeStatusHealthy = 4,
    /// The server can produce platform evidence. Only such a Tier 2 server
    /// joins the turn order; a witness must be able to attest it.
    kUpgradeStatusAttestable = 8,
};

/// A server's signed self-report, sent to the Tier 1 members on a cadence. It
/// is the liveness signal, the turn request (Ready), and the failure report
/// (Failed). It grants nothing.
struct UpgradeStatus {
    NetworkId network_id{};
    NodeId node{};
    /// The release number of the installed binary's packaged approval.
    uint64_t running_release = 0;
    /// The release the updater staged; zero when none.
    uint64_t staged_release = 0;
    /// The highest release number this server accepted (ReleaseChain). A
    /// receiver that holds a different one exchanges approvals with it.
    uint64_t accepted_release = 0;
    uint8_t flags = 0;
    /// The sender's Unix time in milliseconds. A voter refuses a Turn or Halt
    /// whose status is older than kUpgradeStatusMaxAgeMs by its own clock.
    uint64_t timestamp_ms = 0;
    /// Identity signature over upgrade_status_digest().
    crypto::Ed25519Signature signature{};
};

/// Fixed-size wire forms of the two signed statements (Upgrade messages).
[[nodiscard]] std::vector<uint8_t> encode_upgrade_status(const UpgradeStatus& status);
[[nodiscard]] std::optional<UpgradeStatus> decode_upgrade_status(std::span<const uint8_t> bytes);

[[nodiscard]] Digest upgrade_status_digest(const UpgradeStatus& status);
void sign_upgrade_status(UpgradeStatus& status, const crypto::Ed25519PrivateKey& key);
/// The node id is the identity public key, so the signature verifies against
/// `status.node`.
[[nodiscard]] bool verify_upgrade_status(const UpgradeStatus& status);

/// A Tier 1 witness's signed statement: `subject` passed an UpgradeHealth
/// attestation bound to (`release_number`, `chain_head`), and every measured
/// executable hash was in that release's own approved paths.
struct UpgradeObservation {
    NetworkId network_id{};
    uint64_t release_number = 0;
    NodeId subject{};
    Digest chain_head{};
    NodeId witness{};
    /// The verdict's evidence digest; never all-zero.
    Digest evidence_digest{};
    crypto::Ed25519Signature signature{};
};

[[nodiscard]] std::vector<uint8_t> encode_upgrade_observation(
    const UpgradeObservation& observation);
[[nodiscard]] std::optional<UpgradeObservation> decode_upgrade_observation(
    std::span<const uint8_t> bytes);

[[nodiscard]] Digest upgrade_observation_digest(const UpgradeObservation& observation);
void sign_upgrade_observation(UpgradeObservation& observation,
                              const crypto::Ed25519PrivateKey& key);
[[nodiscard]] bool verify_upgrade_observation(const UpgradeObservation& observation);

struct UpgradeParticipant {
    NodeId node{};
    /// A current Tier 1 member when the Start record was proposed.
    bool tier1 = false;

    bool operator==(const UpgradeParticipant&) const = default;
};

struct UpgradeRecord {
    uint8_t version = kUpgradeRecordVersion;
    NetworkId network_id{};
    /// 1 for the first record, then +1 per record.
    uint64_t sequence = 0;
    /// Digest of the record before; all-zero for the first.
    Digest previous{};
    UpgradeEvent event = UpgradeEvent::Start;
    uint64_t release_number = 0;
    /// Start only: the release approval digest.
    Digest approval_digest{};
    /// Start only: the participants in turn order.
    std::vector<UpgradeParticipant> order;
    /// Turn, Upgraded, Halt: the server the record is about.
    NodeId subject{};
    /// Turn (Ready) and Halt (Failed): the subject's signed status.
    std::optional<UpgradeStatus> status;
    /// Upgraded: the witness observations.
    std::vector<UpgradeObservation> observations;
};

/// Canonical bytes; empty when a field exceeds its bound.
[[nodiscard]] std::vector<uint8_t> encode_upgrade_record(const UpgradeRecord& record);
/// Bounded decoding; every byte must be consumed.
[[nodiscard]] std::optional<UpgradeRecord> decode_upgrade_record(std::span<const uint8_t> bytes);
[[nodiscard]] Digest upgrade_record_digest(const UpgradeRecord& record);
[[nodiscard]] BlockPayload upgrade_record_payload(const UpgradeRecord& record);
[[nodiscard]] std::optional<UpgradeRecord> upgrade_record_from_payload(
    const BlockPayload& payload);

/// The deterministic turn order of one release: every node in `others`
/// (Tier 2) first, then every node in `tier1`; each group ascending by
/// SHA-256(domain, release number, node id). A node in both lists counts as
/// Tier 1. Duplicates collapse.
[[nodiscard]] std::vector<UpgradeParticipant> derive_upgrade_order(
    uint64_t release_number, const std::vector<NodeId>& tier1, const std::vector<NodeId>& others);

/// The finalized rollout state that the records build.
struct UpgradeChainState {
    uint64_t sequence = 0;
    Digest head{};
    /// The rollout of the latest Start; zero before any Start.
    uint64_t release_number = 0;
    Digest approval_digest{};
    std::vector<UpgradeParticipant> order;
    std::set<NodeId> upgraded;
    /// The server whose turn is open; it counts as down until Upgraded or
    /// Halt.
    std::optional<NodeId> in_turn;
    bool halted = false;

    [[nodiscard]] bool active() const { return release_number != 0; }
    [[nodiscard]] bool participant(const NodeId& node) const;
    /// True when every participant reported Upgraded.
    [[nodiscard]] bool complete() const;
    /// The first participant in order that is not Upgraded.
    [[nodiscard]] std::optional<NodeId> next_subject() const;
};

/// Who may witness: the Tier 1 members of the epoch that judges the record,
/// with the witness threshold of the eligibility rules (witness_threshold).
struct UpgradeWitnessSet {
    NetworkId network_id{};
    EpochId epoch{};
    std::vector<NodeId> members;
};

enum class UpgradeRecordFailure : uint8_t {
    None = 0,
    Malformed,
    WrongNetwork,
    /// Wrong sequence or previous digest.
    NotChained,
    /// Start: the release is not newer than the current rollout.
    StaleRelease,
    /// Start: a turn is open.
    TurnOpen,
    /// Start: the order is empty, too long, duplicated, or not canonical.
    BadOrder,
    /// Turn/Upgraded/Halt: no rollout, or the rollout halted.
    RolloutClosed,
    /// Turn: the subject is not the next server in order.
    NotNext,
    /// Upgraded/Halt: the subject's turn is not open (or, for Upgraded
    /// without an open turn, the subject is not next).
    NotInTurn,
    /// The subject's status is missing, unsigned, or says something else.
    BadStatus,
    /// An observation is unsigned, bound elsewhere, or from a non-witness.
    BadObservation,
    /// Fewer distinct witnesses than the threshold.
    TooFewWitnesses,
};

[[nodiscard]] std::string_view upgrade_record_failure_name(UpgradeRecordFailure failure);

/// Checks that `record` extends `state`. With `as_base`, a Start record may
/// replace the state from any later sequence (a node that missed records
/// adopts a finalized Start); its release must still be newer. `witnesses`
/// judges observations; it is required for an Upgraded record.
[[nodiscard]] UpgradeRecordFailure check_upgrade_record(const UpgradeChainState& state,
                                                        const UpgradeRecord& record,
                                                        const UpgradeWitnessSet* witnesses,
                                                        bool as_base = false);

/// Applies a record that check_upgrade_record accepted.
void apply_upgrade_record(UpgradeChainState& state, const UpgradeRecord& record);

/// What the local turn gate tells the updater for one release.
enum class UpgradeGate : uint8_t {
    /// Restart now: finalized state opened this server's turn, or this server
    /// takes no part in the order and the rollout is complete.
    Go = 1,
    /// Not yet: a server ahead is not Upgraded, or a turn is open.
    Wait = 2,
    /// The rollout of this release halted.
    Halted = 3,
    /// Finalized state already shows this server Upgraded.
    Done = 4,
    /// No Start record for this release yet (or a newer release superseded
    /// it).
    NotStarted = 5,
};

[[nodiscard]] std::string_view upgrade_gate_name(UpgradeGate gate);

/// Pure: the gate answer from finalized state only.
[[nodiscard]] UpgradeGate evaluate_upgrade_gate(const UpgradeChainState& state,
                                                const NodeId& self, uint64_t release_number);

}  // namespace nexus::security
