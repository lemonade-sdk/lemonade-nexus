#pragma once

// Release adoption over the backbone and upgrade turns through consensus
// (Design-Auto-Update Phases 2 and 5).
//
// The service runs on every server, on the security io thread:
//   - It offers its newest accepted release approval to peers and adopts a
//     newer one from a peer or from the local updater (ReleaseChain rules).
//     Offers are size-bounded and rate-limited per peer.
//   - It sends a signed UpgradeStatus to the Tier 1 members on a cadence.
//   - On a Tier 1 member it witnesses: it challenges the server whose turn is
//     open (UpgradeHealth attestation) and signs an observation when the
//     server runs the release, attested and healthy.
//   - It proposes, validates, and applies UpgradeProgress records
//     (UpgradeProgress.hpp) through the driver's payload extension point.
//   - It keeps every finalized record with the commit proof that finalized
//     it. A member that lacks a record or a proof asks its peers for it, and
//     rebuilds a proof that no peer holds from the certified chain that the
//     peers' consensus still serves. Each proof is verified in full first.
//   - A member that holds a verified later record it cannot apply (a record
//     before it is lost with its proof) is behind the finalized head. It
//     proposes and votes for no record of the open rollout, but it judges a
//     Start that extends the newest such record (start_base()): a Start
//     resets the state it lacks, and the quorum that finalized that record
//     vouches for everything before it.
//   - It answers the local turn gate and health report for nexus-updater
//     (Core/UpgradeControl.hpp carries them over a root-only socket).
//
// The service decides nothing outside its records: consensus keeps safety,
// attestation keeps the verdicts, and the release chain keeps the approvals.
// A Tier 2 server only reports its own status and answers attestation.

#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>
#include <LemonadeNexus/Security/Attestation/ReleaseChain.hpp>
#include <LemonadeNexus/Security/Authority/RoundRelay.hpp>
#include <LemonadeNexus/Security/Consensus/BlockPayload.hpp>

#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Upgrade/RolloutProof.hpp>
#include <LemonadeNexus/Security/Upgrade/UpgradeProgress.hpp>

#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace nexus::security {

class SecurityDriver;
class SecurityRouter;
class SecurityRuntime;
struct SecurityMessage;
struct SyncResponse;

struct UpgradeServiceConfig {
    NodeId self{};
    crypto::Ed25519Keypair identity{};
    NetworkId network_id{};
    /// Durable records (data_root/security/upgrade).
    std::filesystem::path directory;
    /// The nexus-updater wake marker (Core/UpgradeControl.hpp
    /// kUpdaterWakePath in production). The service touches it when a
    /// finalized Start names this server as a participant and when a
    /// finalized Turn opens for this server; nexus-updater.path starts a
    /// cycle on the change. Empty: no marker is written.
    std::filesystem::path updater_wake;
    /// Unix time in milliseconds for status timestamps and freshness. Unset:
    /// this server sends no status and votes for no Turn or Halt.
    std::function<uint64_t()> wall_clock_ms;
    /// The release number of the installed binary's packaged approval; zero
    /// when none is packaged.
    uint64_t running_release = 0;
    /// The data key state for the health report: "unlocked", "locked", "retired", or
    /// "no_storage_key". Unset reports "unknown". Informational only: the
    /// turn rule and the Healthy flag never depend on it, because during a
    /// rollout a server can stay locked until enough holders run the new
    /// release (pending quorum), which is not a failure.
    std::function<std::string()> data_key_state;
    /// Whether this server can produce platform evidence (an attestation
    /// collector is configured). Reported in the status; a Tier 2 server that
    /// reports false takes no turn and restarts after the rollout completes.
    /// Unset reports false.
    std::function<bool()> attestable;
};

/// What the health report tells the updater (Design-Auto-Update Phase 4
/// step 7). Facts this process holds; the tree log catch-up is not among them.
struct UpgradeHealthReport {
    uint64_t running_release = 0;
    uint64_t accepted_release = 0;
    /// The security driver's phase name.
    std::string driver_phase;
    bool driver_failed = false;
    bool verified_authority = false;
    bool tier1_member = false;
    std::optional<uint64_t> epoch;
    /// See UpgradeServiceConfig::data_key_state. Not part of `healthy`.
    std::string data_key_state = "unknown";
    /// The same fact as the status Healthy flag: verified epoch authority and
    /// a driver that has not failed.
    bool healthy = false;
};

class UpgradeService {
public:
    /// Not owning: every reference and `chain` must outlive the service.
    /// `chain` may be null (no packaged approval): adoption is then off.
    UpgradeService(UpgradeServiceConfig config, SecurityDriver& driver, SecurityRouter& router,
                   SecurityRuntime& runtime, ReleaseChain* chain);
    ~UpgradeService();

    UpgradeService(const UpgradeService&) = delete;
    UpgradeService& operator=(const UpgradeService&) = delete;

    /// Registers the payload handler, the message and verdict sinks, and the
    /// eligibility listener with the driver. Call before the driver starts.
    void attach();

    /// Loads durable records. False when they are corrupt: the service then
    /// proposes and votes for nothing.
    [[nodiscard]] bool start(uint64_t now_ms);
    [[nodiscard]] bool healthy() const { return healthy_; }

    /// Steady-clock work: status reports, witness challenges, record sync.
    void tick(uint64_t now_ms);

    /// A peer became reachable: offer it the newest accepted approval.
    void on_peer(const NodeId& peer);

    // --- Inbound (driver sinks) ---
    void on_message(const SecurityMessage& message);
    void on_verdict(const AttestationVerdict& verdict);
    /// A sync reply (SecurityDriver::set_upgrade_chain_sink). Any three-chain
    /// in it over a held record that lacks its proof becomes that proof once
    /// it verifies under the vote keys and quorum of its epoch. Also advances
    /// this node's own search for such a proof.
    void on_certified_chain(const SyncResponse& response, const NodeId& from);

    // --- Payload handling (through the registered adapter) ---
    [[nodiscard]] std::optional<ProposedPayload> propose(const HotStuffService& consensus);
    [[nodiscard]] bool validate(const HotStuffService& consensus, const Proposal& proposal,
                                const BlockPayload& payload);
    void on_committed(const CommittedPayload& committed);

    // --- Local control (the updater, through Core/UpgradeControl) ---
    /// Offers an approval bundle (JSON). On Adopted it is relayed to peers.
    [[nodiscard]] ReleaseOfferResult offer_approval(std::string_view bundle_json);
    /// The updater staged `release_number` and asks for a turn. Clears an
    /// earlier failure report for another release.
    void stage(uint64_t release_number);
    /// The updater's health gate failed for `release_number` and it rolled
    /// back. Reported in the next status; a finalized Halt follows.
    void report_failed(uint64_t release_number);
    [[nodiscard]] UpgradeGate gate(uint64_t release_number) const;
    [[nodiscard]] UpgradeHealthReport health() const;

    // --- Reads ---
    [[nodiscard]] const UpgradeChainState& state() const { return state_; }
    [[nodiscard]] uint64_t staged_release() const { return staged_release_; }
    /// The newest approval the release chain accepted (Genesis delegation,
    /// pinned signer, monotonic number), or nullopt without one.
    [[nodiscard]] const std::optional<ReleaseApprovalBundleV1>& accepted_approval() const;
    /// This node's rollout proof (RolloutProof.hpp): the stored authority
    /// chain from Genesis and the records since the latest Start with their
    /// commit proofs. nullopt when this node lacks the Genesis base or the
    /// commit proof of any record. `genesis_public_key` is the configured
    /// anchor; the verifier checks it against the network id.
    [[nodiscard]] std::optional<RolloutProof> rollout_proof(
        const crypto::Ed25519PublicKey& genesis_public_key) const;
    /// Fires after a newer approval was adopted, with that approval. The owner
    /// replaces the attestation profile from it.
    void set_release_adopted_callback(std::function<void(const ReleaseApprovalBundleV1&)> cb) {
        on_release_adopted_ = std::move(cb);
    }
    /// Fires when a finalized Start record puts the accepted release below
    /// the network floor (ReleaseChain::raise_floor), at start or later. The
    /// release chain then holds no usable approval; the owner replaces the
    /// attestation profile so that it fails closed.
    void set_release_floor_callback(std::function<void()> cb) { on_release_floor_ = std::move(cb); }

private:
    class PayloadAdapter;
    /// A search of the peers' certified chain for the block that finalized a
    /// held record whose proof this node lacks.
    struct ProofSearch {
        uint64_t sequence = 0;
        NodeId peer{};
        /// Exclusive lower bound: the block of the nearest earlier record
        /// with a proof in this epoch, or zero.
        uint64_t lower = 0;
        /// The height the outstanding page request names (SyncRequest).
        uint64_t after = 0;
        uint64_t sent_ms = 0;
        /// The next page, sent on the next tick so that a search stays far
        /// below the peer's message budget.
        std::optional<uint64_t> next_after;
    };
    struct PendingWitness {
        NodeId subject{};
        Digest chain_head{};
        Digest context{};
        uint64_t release_number = 0;
        uint64_t sent_ms = 0;
    };
    /// The finalized record a Start extends from this node's view: its own
    /// head, or the newest verified record held ahead of a gap.
    struct StartBase {
        uint64_t sequence = 0;
        Digest head{};
        /// The record leaves a turn open: a Start is refused.
        bool turn_open = false;
    };

    [[nodiscard]] std::vector<NodeId> current_members() const;
    [[nodiscard]] EpochId current_epoch() const;
    [[nodiscard]] bool is_member(const NodeId& node) const;
    [[nodiscard]] bool live(const NodeId& node) const;
    [[nodiscard]] bool status_fresh(const UpgradeStatus& status) const;
    [[nodiscard]] bool locally_healthy() const;
    [[nodiscard]] std::optional<UpgradeWitnessSet> witnesses_for(EpochId epoch) const;
    /// Non-members with a fresh status that report Attestable: the Tier 2
    /// participants this node would order.
    [[nodiscard]] std::vector<NodeId> tier2_participants(
        const std::vector<NodeId>& members) const;
    /// The base of the next Start. With no verified record ahead of a gap it
    /// is this node's own state. Otherwise it is the newest pending record:
    /// that record's commit proof verified under its epoch's vote keys and
    /// quorum, so every record before it is finalized too, and only its event
    /// decides whether a turn is open after it. Whether it is the finalized
    /// head this node cannot tell; a Start finalizes only when a quorum, which
    /// includes members at the head, agrees on the same base.
    [[nodiscard]] StartBase start_base() const;
    [[nodiscard]] std::optional<UpgradeRecord> derive_start(const StartBase& base) const;
    [[nodiscard]] std::optional<UpgradeRecord> next_record() const;
    [[nodiscard]] bool uncommitted_upgrade_ancestor(const HotStuffService& consensus,
                                                    const Digest& from) const;
    [[nodiscard]] bool runs_release(const AttestationVerdict& verdict,
                                    const ReleaseApprovalV1& approval) const;
    [[nodiscard]] std::optional<UpgradeStatus> fresh_status(const NodeId& node) const;

    void send_status();
    void witness();
    void sync_records();
    void handle_offer(const SecurityMessage& message);
    void handle_status(const SecurityMessage& message);
    void handle_observation(const SecurityMessage& message);
    void handle_record_proof(const SecurityMessage& message);
    void handle_record_request(const SecurityMessage& message);
    /// The epoch that finalized `body` when `proof` verifies for it under that
    /// epoch's vote keys and quorum; nullopt when it does not verify or this
    /// node knows no such epoch.
    [[nodiscard]] std::optional<EpochId> verified_proof_epoch(const std::vector<uint8_t>& body,
                                                              const CommitProof& proof) const;
    /// Keeps `proof` for the held record encoded as `body` when that record
    /// has no proof and the proof verifies. True when it was kept.
    bool recover_proof(const std::vector<uint8_t>& body, const CommitProof& proof);
    /// The index in records_ of the first record held without its proof.
    [[nodiscard]] std::optional<std::size_t> first_unproven() const;
    /// The heights (exclusive) between which the block of records_[index]
    /// lies in the current epoch; nullopt when it cannot lie in it.
    [[nodiscard]] std::optional<std::pair<uint64_t, uint64_t>> search_bounds(
        std::size_t index) const;
    void search_proof(std::size_t index, const NodeId& peer);
    void request_page(uint64_t after);
    void broadcast_approval();
    void send_approval(const NodeId& peer);
    void adopted();
    /// Raises the release chain's floor to the finalized rollout release.
    void raise_release_floor();
    /// Applies a finalized record and keeps it with its proof. False when it
    /// does not extend the state.
    bool accept_record(const UpgradeRecord& record, std::optional<CommitProof> proof,
                       const UpgradeWitnessSet* witnesses, bool as_base);
    /// Touches config_.updater_wake so that nexus-updater.path starts a cycle.
    void wake_updater(std::string_view reason) const;
    void drain_pending();
    void broadcast_record(uint64_t sequence);
    void persist();
    [[nodiscard]] bool load();
    [[nodiscard]] std::vector<uint8_t> encode_record_proof(const UpgradeRecord& record,
                                                           const CommitProof& proof) const;
    [[nodiscard]] std::optional<CommitProof> stored_proof(const std::string& hex,
                                                          const UpgradeRecord& record) const;

    UpgradeServiceConfig config_;
    SecurityDriver& driver_;
    SecurityRouter& router_;
    SecurityRuntime& runtime_;
    ReleaseChain* chain_;
    std::unique_ptr<PayloadAdapter> handler_;
    std::function<void(const ReleaseApprovalBundleV1&)> on_release_adopted_;
    std::function<void()> on_release_floor_;

    bool healthy_ = true;
    uint64_t now_ms_ = 0;
    UpgradeChainState state_;
    /// Records since the latest Start, in order, with the proof that finalized
    /// each when this node holds it.
    std::vector<std::pair<UpgradeRecord, std::optional<CommitProof>>> records_;
    /// Verified finalized records that arrived ahead of a gap, by sequence.
    /// The newest one is the base of a Start while the gap stays (start_base).
    std::map<uint64_t, std::pair<UpgradeRecord, CommitProof>> pending_records_;
    std::optional<ProofSearch> proof_search_;

    // Local control.
    uint64_t staged_release_ = 0;
    uint64_t failed_release_ = 0;

    // Liveness and statuses (steady ms of the last valid status per node).
    std::map<NodeId, uint64_t> last_status_ms_;
    std::map<NodeId, UpgradeStatus> statuses_;
    /// Rate limit of approval offers per sender.
    std::map<NodeId, uint64_t> last_offer_ms_;
    /// Rate limit of approvals this node pushes after a status, per peer.
    std::map<NodeId, uint64_t> last_push_ms_;

    // Witnessing.
    std::optional<PendingWitness> pending_witness_;
    /// Observations for the open position, by witness.
    std::map<NodeId, UpgradeObservation> observations_;
    Digest observations_head_{};
    NodeId observations_subject_{};

    ResendCadence status_cadence_{constants::kUpgradeStatusIntervalMs};
    ResendCadence sync_cadence_{2 * constants::kUpgradeStatusIntervalMs};
    std::size_t sync_cursor_ = 0;
};

}  // namespace nexus::security
