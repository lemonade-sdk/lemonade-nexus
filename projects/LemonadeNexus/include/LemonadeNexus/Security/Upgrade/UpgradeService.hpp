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
#include <LemonadeNexus/Security/Upgrade/UpgradeProgress.hpp>

#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace nexus::security {

class SecurityDriver;
class SecurityRouter;
class SecurityRuntime;
struct SecurityMessage;

struct UpgradeServiceConfig {
    NodeId self{};
    crypto::Ed25519Keypair identity{};
    NetworkId network_id{};
    /// Durable records (data_root/security/upgrade).
    std::filesystem::path directory;
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
    /// Fires after a newer approval was adopted, with that approval. The owner
    /// replaces the attestation profile from it.
    void set_release_adopted_callback(std::function<void(const ReleaseApprovalBundleV1&)> cb) {
        on_release_adopted_ = std::move(cb);
    }

private:
    class PayloadAdapter;
    struct PendingWitness {
        NodeId subject{};
        Digest chain_head{};
        Digest context{};
        uint64_t release_number = 0;
        uint64_t sent_ms = 0;
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
    [[nodiscard]] std::optional<UpgradeRecord> derive_start() const;
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
    void broadcast_approval();
    void send_approval(const NodeId& peer);
    void adopted();
    /// Applies a finalized record and keeps it with its proof. False when it
    /// does not extend the state.
    bool accept_record(const UpgradeRecord& record, std::optional<CommitProof> proof,
                       const UpgradeWitnessSet* witnesses, bool as_base);
    void drain_pending();
    void broadcast_record(uint64_t sequence);
    void persist();
    [[nodiscard]] bool load();

    UpgradeServiceConfig config_;
    SecurityDriver& driver_;
    SecurityRouter& router_;
    SecurityRuntime& runtime_;
    ReleaseChain* chain_;
    std::unique_ptr<PayloadAdapter> handler_;
    std::function<void(const ReleaseApprovalBundleV1&)> on_release_adopted_;

    bool healthy_ = true;
    uint64_t now_ms_ = 0;
    UpgradeChainState state_;
    /// Records since the latest Start, in order, with the proof that finalized
    /// each when this node holds it.
    std::vector<std::pair<UpgradeRecord, std::optional<CommitProof>>> records_;
    /// Verified finalized records that arrived ahead of a gap, by sequence.
    std::map<uint64_t, std::pair<UpgradeRecord, CommitProof>> pending_records_;

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
