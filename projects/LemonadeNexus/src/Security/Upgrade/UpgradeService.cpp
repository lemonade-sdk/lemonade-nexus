#include <LemonadeNexus/Security/Upgrade/UpgradeService.hpp>

#include <LemonadeNexus/Security/Consensus/HotStuffService.hpp>
#include <LemonadeNexus/Security/DurableWrite.hpp>
#include <LemonadeNexus/Security/Eligibility/EligibilityLedger.hpp>
#include <LemonadeNexus/Security/Lifecycle/SecurityDriver.hpp>
#include <LemonadeNexus/Security/SecurityRuntime.hpp>
#include <LemonadeNexus/Security/Transport/SecurityRouter.hpp>

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <fstream>
#include <system_error>

namespace nexus::security {

namespace {

constexpr std::string_view kRecordsFile = "upgrade-records.json";
constexpr uint32_t kRecordsFormatVersion = 1;
/// Finalized records held ahead of a gap, and records served per request.
constexpr std::size_t kMaxPendingRecords = 64;
constexpr std::size_t kMaxRecordsPerReply = 64;
/// Statuses kept; far above any real participant count.
constexpr std::size_t kMaxTrackedStatuses = 2 * constants::kMaxUpgradeParticipants;

std::string short_id(const NodeId& node) {
    return crypto::to_hex(std::span<const uint8_t>(node.bytes.data(), 8));
}

const char* phase_label(DriverPhase phase) {
    switch (phase) {
        case DriverPhase::Failed: return "Failed";
        case DriverPhase::Idle: return "Idle";
        case DriverPhase::PendingNextEpoch: return "PendingNextEpoch";
        case DriverPhase::GenesisCollecting: return "GenesisCollecting";
        case DriverPhase::GenesisEligibility: return "GenesisEligibility";
        case DriverPhase::FoundingDkg: return "FoundingDkg";
        case DriverPhase::AwaitingBootstrap: return "AwaitingBootstrap";
        case DriverPhase::Syncing: return "Syncing";
        case DriverPhase::Active: return "Active";
    }
    return "?";
}

std::vector<uint8_t> u64_bytes(uint64_t value) {
    std::vector<uint8_t> out(8);
    for (int i = 7; i >= 0; --i) {
        out[static_cast<std::size_t>(i)] = static_cast<uint8_t>(value);
        value >>= 8;
    }
    return out;
}

}  // namespace

class UpgradeService::PayloadAdapter final : public IBlockPayloadHandler {
public:
    explicit PayloadAdapter(UpgradeService& service) : service_(service) {}

    [[nodiscard]] BlockPayloadKind kind() const override {
        return BlockPayloadKind::UpgradeProgress;
    }
    [[nodiscard]] std::optional<ProposedPayload> propose(
        const HotStuffService& consensus) override {
        return service_.propose(consensus);
    }
    [[nodiscard]] bool validate(const HotStuffService& consensus, const Proposal& proposal,
                                const BlockPayload& payload) override {
        return payload.kind == BlockPayloadKind::UpgradeProgress &&
               service_.validate(consensus, proposal, payload);
    }
    void on_committed(const CommittedPayload& committed) override {
        service_.on_committed(committed);
    }
    void on_consensus_reset() override {}

private:
    UpgradeService& service_;
};

UpgradeService::UpgradeService(UpgradeServiceConfig config, SecurityDriver& driver,
                               SecurityRouter& router, SecurityRuntime& runtime,
                               ReleaseChain* chain)
    : config_(std::move(config)),
      driver_(driver),
      router_(router),
      runtime_(runtime),
      chain_(chain),
      handler_(std::make_unique<PayloadAdapter>(*this)) {}

UpgradeService::~UpgradeService() = default;

void UpgradeService::attach() {
    driver_.register_payload_handler(*handler_);
    driver_.set_upgrade_sink([this](const SecurityMessage& message) { on_message(message); });
    driver_.set_upgrade_verdict_sink(
        [this](const AttestationVerdict& verdict) { on_verdict(verdict); });
}

bool UpgradeService::start(uint64_t now_ms) {
    now_ms_ = now_ms;
    healthy_ = load();
    if (!healthy_) {
        spdlog::warn("[upgrade] upgrade records are corrupt; this server proposes and votes "
                     "for no upgrade record");
    }
    raise_release_floor();
    return healthy_;
}

// --- Facts ------------------------------------------------------------------------

std::vector<NodeId> UpgradeService::current_members() const {
    if (const EpochManager* epochs = runtime_.epochs(); epochs != nullptr) {
        return epochs->current().tier1_members.members();
    }
    if (const VerifiedEpochAuthority* authority = driver_.verified_authority()) {
        return authority->members;
    }
    return {};
}

EpochId UpgradeService::current_epoch() const {
    if (const auto epoch = driver_.current_epoch()) return *epoch;
    if (const VerifiedEpochAuthority* authority = driver_.verified_authority()) {
        return authority->epoch;
    }
    return EpochId{};
}

bool UpgradeService::is_member(const NodeId& node) const {
    const auto members = current_members();
    return std::find(members.begin(), members.end(), node) != members.end();
}

bool UpgradeService::live(const NodeId& node) const {
    if (node == config_.self) return true;
    const auto it = last_status_ms_.find(node);
    return it != last_status_ms_.end() && now_ms_ >= it->second &&
           now_ms_ - it->second <= constants::kUpgradeLivenessWindowMs;
}

bool UpgradeService::status_fresh(const UpgradeStatus& status) const {
    if (!config_.wall_clock_ms) return false;
    const uint64_t now = config_.wall_clock_ms();
    const uint64_t age = now >= status.timestamp_ms ? now - status.timestamp_ms
                                                    : status.timestamp_ms - now;
    return age <= constants::kUpgradeStatusMaxAgeMs;
}

std::optional<UpgradeStatus> UpgradeService::fresh_status(const NodeId& node) const {
    const auto it = statuses_.find(node);
    if (it == statuses_.end() || !live(node) || !status_fresh(it->second)) return std::nullopt;
    return it->second;
}

bool UpgradeService::locally_healthy() const {
    return driver_.phase() != DriverPhase::Failed &&
           (runtime_.epochs() != nullptr || driver_.verified_authority() != nullptr);
}

std::optional<UpgradeWitnessSet> UpgradeService::witnesses_for(EpochId epoch) const {
    if (const EpochManager* epochs = runtime_.epochs();
        epochs != nullptr && epochs->current().id == epoch) {
        return UpgradeWitnessSet{config_.network_id, epoch,
                                 epochs->current().tier1_members.members()};
    }
    if (const auto authority = driver_.authority_for_epoch(epoch)) {
        return UpgradeWitnessSet{config_.network_id, epoch, authority->members};
    }
    return std::nullopt;
}

// --- Tick ---------------------------------------------------------------------------

void UpgradeService::tick(uint64_t now_ms) {
    now_ms_ = now_ms;
    if (!healthy_) return;
    if (status_cadence_.due(now_ms)) send_status();
    witness();
    if (sync_cadence_.due(now_ms)) sync_records();
}

void UpgradeService::send_status() {
    if (!config_.wall_clock_ms) return;
    UpgradeStatus status;
    status.network_id = config_.network_id;
    status.node = config_.self;
    status.running_release = config_.running_release;
    status.staged_release = staged_release_;
    status.accepted_release = chain_ != nullptr ? chain_->highest_release_number() : 0;
    if (staged_release_ != 0) {
        status.flags |= failed_release_ == staged_release_ ? kUpgradeStatusFailed
                                                           : kUpgradeStatusReady;
    }
    if (locally_healthy()) status.flags |= kUpgradeStatusHealthy;
    if (config_.attestable && config_.attestable()) status.flags |= kUpgradeStatusAttestable;
    status.timestamp_ms = config_.wall_clock_ms();
    sign_upgrade_status(status, config_.identity.private_key);
    statuses_[config_.self] = status;
    last_status_ms_[config_.self] = now_ms_;
    const auto message = router_.compose(
        SecurityMessageKind::Upgrade,
        UpgradeMsg{UpgradeTopic::Status, encode_upgrade_status(status), std::nullopt},
        current_epoch());
    for (const auto& member : current_members()) {
        if (member != config_.self) (void)router_.send(member, message);
    }
}

void UpgradeService::sync_records() {
    auto members = current_members();
    std::erase(members, config_.self);
    if (members.empty()) return;
    const NodeId& target = members[sync_cursor_++ % members.size()];
    (void)router_.send(target, router_.compose(SecurityMessageKind::Upgrade,
                                               UpgradeMsg{UpgradeTopic::RecordRequest,
                                                          u64_bytes(state_.sequence),
                                                          std::nullopt},
                                               current_epoch()));
}

// --- Witnessing ---------------------------------------------------------------------

bool UpgradeService::runs_release(const AttestationVerdict& verdict,
                                  const ReleaseApprovalV1& approval) const {
    if (verdict.measured_paths.empty() || approval.approved_paths.empty()) return false;
    for (const auto& required : approval.approved_paths) {
        const auto measured = std::find_if(
            verdict.measured_paths.begin(), verdict.measured_paths.end(),
            [&required](const ImaCheckpointPath& path) { return path.path == required.path; });
        if (measured == verdict.measured_paths.end() ||
            std::find(required.sha256.begin(), required.sha256.end(), measured->sha256) ==
                required.sha256.end()) {
            return false;
        }
    }
    return true;
}

void UpgradeService::witness() {
    if (!state_.active() || state_.halted || chain_ == nullptr || !is_member(config_.self)) {
        pending_witness_.reset();
        return;
    }
    std::optional<NodeId> subject = state_.in_turn;
    if (!subject.has_value()) {
        // A participant already on the release needs no turn; witnesses
        // check it in place.
        subject = state_.next_subject();
        const auto status = subject ? fresh_status(*subject) : std::nullopt;
        if (!status || status->running_release != state_.release_number) return;
    }
    if (!subject.has_value() || *subject == config_.self || !chain_->current() ||
        chain_->current_digest() != state_.approval_digest) {
        return;
    }
    if (observations_subject_ != *subject || observations_head_ != state_.head) {
        observations_.clear();
        observations_subject_ = *subject;
        observations_head_ = state_.head;
        pending_witness_.reset();
    }
    const EpochId epoch = current_epoch();
    if (const auto own = observations_.find(config_.self); own != observations_.end()) {
        // Re-send against loss until the position closes.
        if (pending_witness_ && now_ms_ - pending_witness_->sent_ms <
                                    constants::kUpgradeWitnessIntervalMs) {
            return;
        }
        const auto message = router_.compose(
            SecurityMessageKind::Upgrade,
            UpgradeMsg{UpgradeTopic::Observation, encode_upgrade_observation(own->second),
                       std::nullopt},
            epoch);
        for (const auto& member : current_members()) {
            if (member != config_.self) (void)router_.send(member, message);
        }
        pending_witness_ = PendingWitness{*subject, state_.head, Digest{},
                                          state_.release_number, now_ms_};
        return;
    }
    if (pending_witness_ && pending_witness_->subject == *subject &&
        pending_witness_->chain_head == state_.head &&
        now_ms_ - pending_witness_->sent_ms < constants::kUpgradeWitnessIntervalMs) {
        return;
    }
    // Challenge only a subject whose signed status says it runs the release
    // and is healthy; on_verdict requires the same before it observes. The
    // attempt budget per chain position is small, and an updater installs on
    // its own timer, minutes after its turn opens. Challenges sent before the
    // install would spend the whole budget and leave the turn open forever.
    const auto status = fresh_status(*subject);
    if (!status || status->running_release != state_.release_number ||
        (status->flags & kUpgradeStatusHealthy) == 0) {
        return;
    }
    const Digest context = upgrade_health_attestation_context(
        config_.network_id, state_.release_number, *subject, state_.head);
    auto challenge = runtime_.attestation().create_challenge(
        *subject, subject->bytes, 1, epoch, AttestationPurpose::UpgradeHealth, context);
    if (!challenge.has_value()) return;
    pending_witness_ =
        PendingWitness{*subject, state_.head, context, state_.release_number, now_ms_};
    (void)router_.send(*subject,
                       router_.compose(SecurityMessageKind::AttestationChallenge, *challenge,
                                       epoch));
}

void UpgradeService::on_verdict(const AttestationVerdict& verdict) {
    if (verdict.purpose != AttestationPurpose::UpgradeHealth || !pending_witness_ ||
        pending_witness_->context == Digest{} ||
        verdict.context_digest != pending_witness_->context ||
        verdict.node_id != pending_witness_->subject) {
        return;
    }
    const PendingWitness pending = *pending_witness_;
    if (state_.head != pending.chain_head || state_.release_number != pending.release_number ||
        chain_ == nullptr || !chain_->current() ||
        chain_->current_digest() != state_.approval_digest) {
        return;
    }
    if (!verdict.passed || verdict.evidence_digest == Digest{} ||
        !all_platform_claims_proved(verdict.claims)) {
        spdlog::info("[upgrade] {} did not pass upgrade-health attestation",
                     short_id(verdict.node_id));
        return;
    }
    if (!runs_release(verdict, chain_->current()->approval)) {
        spdlog::info("[upgrade] {} attested but does not run release {}",
                     short_id(verdict.node_id), state_.release_number);
        return;
    }
    const auto status = fresh_status(pending.subject);
    if (!status || (status->flags & kUpgradeStatusHealthy) == 0 ||
        status->running_release != state_.release_number) {
        return;
    }
    UpgradeObservation observation;
    observation.network_id = config_.network_id;
    observation.release_number = state_.release_number;
    observation.subject = pending.subject;
    observation.chain_head = state_.head;
    observation.witness = config_.self;
    observation.evidence_digest = verdict.evidence_digest;
    sign_upgrade_observation(observation, config_.identity.private_key);
    observations_subject_ = pending.subject;
    observations_head_ = state_.head;
    observations_[config_.self] = observation;
    pending_witness_.reset();
    witness();  // sends the observation now
}

// --- Inbound ------------------------------------------------------------------------

void UpgradeService::on_message(const SecurityMessage& message) {
    const auto* body = std::get_if<UpgradeMsg>(&message.body);
    if (body == nullptr || message.sender == config_.self || !healthy_) return;
    switch (body->topic) {
        case UpgradeTopic::ApprovalOffer: handle_offer(message); break;
        case UpgradeTopic::Status: handle_status(message); break;
        case UpgradeTopic::Observation: handle_observation(message); break;
        case UpgradeTopic::RecordProof: handle_record_proof(message); break;
        case UpgradeTopic::RecordRequest: handle_record_request(message); break;
    }
}


void UpgradeService::handle_offer(const SecurityMessage& message) {
    if (chain_ == nullptr) return;
    const auto& body = std::get<UpgradeMsg>(message.body).body;
    auto& last = last_offer_ms_[message.sender];
    if (last != 0 && now_ms_ - last < constants::kReleaseOfferWindowMs) return;
    last = now_ms_ == 0 ? 1 : now_ms_;
    while (last_offer_ms_.size() > constants::kSecurityTrackedPeers) {
        last_offer_ms_.erase(last_offer_ms_.begin());
    }
    const auto result = chain_->offer_json(
        std::string_view(reinterpret_cast<const char*>(body.data()), body.size()));
    if (result == ReleaseOfferResult::Adopted) {
        adopted();
    } else if (result == ReleaseOfferResult::Stale) {
        // The sender is behind; hand it the newer approval.
        send_approval(message.sender);
    } else if (result != ReleaseOfferResult::Current) {
        spdlog::debug("[upgrade] approval offer from {} refused: {}", short_id(message.sender),
                      release_offer_result_name(result));
    }
}

void UpgradeService::handle_status(const SecurityMessage& message) {
    const auto& body = std::get<UpgradeMsg>(message.body).body;
    const auto status = decode_upgrade_status(body);
    if (!status || status->node != message.sender || status->network_id != config_.network_id ||
        !status_fresh(*status) || !verify_upgrade_status(*status)) {
        return;
    }
    if (const auto held = statuses_.find(status->node);
        held != statuses_.end() && held->second.timestamp_ms > status->timestamp_ms) {
        return;
    }
    if (!statuses_.contains(status->node) && statuses_.size() >= kMaxTrackedStatuses) return;
    statuses_[status->node] = *status;
    last_status_ms_[status->node] = now_ms_;
    // Approvals spread by status: a sender that is behind gets ours, and a
    // sender that is ahead gets ours too, so its Stale answer returns the
    // newer one. Rate-limited per peer.
    if (chain_ != nullptr && chain_->current() &&
        status->accepted_release != chain_->highest_release_number()) {
        auto& last = last_push_ms_[status->node];
        if (last == 0 || now_ms_ - last >= constants::kReleaseOfferWindowMs) {
            last = now_ms_ == 0 ? 1 : now_ms_;
            send_approval(status->node);
        }
    }
}

void UpgradeService::handle_observation(const SecurityMessage& message) {
    if (!is_member(config_.self) || !state_.active() || state_.halted) return;
    const auto& body = std::get<UpgradeMsg>(message.body).body;
    const auto observation = decode_upgrade_observation(body);
    if (!observation || observation->witness != message.sender ||
        observation->network_id != config_.network_id || !is_member(observation->witness) ||
        observation->release_number != state_.release_number ||
        observation->chain_head != state_.head || observation->subject == observation->witness ||
        !verify_upgrade_observation(*observation)) {
        return;
    }
    const auto expected = state_.in_turn ? state_.in_turn : state_.next_subject();
    if (expected != observation->subject) return;
    if (observations_subject_ != observation->subject || observations_head_ != state_.head) {
        observations_.clear();
        observations_subject_ = observation->subject;
        observations_head_ = state_.head;
    }
    observations_[observation->witness] = *observation;
}

void UpgradeService::handle_record_proof(const SecurityMessage& message) {
    const auto& upgrade = std::get<UpgradeMsg>(message.body);
    if (!upgrade.proof.has_value() || upgrade.proof->chain.empty()) return;
    const auto record = decode_upgrade_record(upgrade.body);
    if (!record || record->network_id != config_.network_id ||
        record->sequence <= state_.sequence || pending_records_.contains(record->sequence)) {
        return;
    }
    const EpochId epoch = upgrade.proof->chain.front().proposal.epoch;
    std::size_t quorum = 0;
    std::map<NodeId, crypto::Ed25519PublicKey> vote_keys;
    if (const EpochManager* epochs = runtime_.epochs();
        epochs != nullptr && epochs->current().id == epoch) {
        quorum = epochs->current().consensus_quorum;
        vote_keys = epochs->current_vote_keys();
    } else if (const auto authority = driver_.authority_for_epoch(epoch)) {
        quorum = authority->consensus_quorum;
        vote_keys = authority->vote_keys;
    } else {
        return;  // Nothing to verify against; the record sync asks again later.
    }
    const QcValidationContext context{constants::kConsensusRulesetVersion, config_.network_id,
                                      epoch, quorum};
    const BlockPayload payload{BlockPayloadKind::UpgradeProgress, upgrade.body};
    if (verify_commit_proof(block_payload_digest(payload), *upgrade.proof, context, vote_keys) !=
        CommitProofFailure::None) {
        spdlog::debug("[upgrade] record proof from {} does not verify", short_id(message.sender));
        return;
    }
    const auto witnesses = witnesses_for(epoch);
    if (!witnesses) return;
    if (record->sequence == state_.sequence + 1 || record->event == UpgradeEvent::Start) {
        if (accept_record(*record, upgrade.proof, &*witnesses, true)) return;
    }
    if (pending_records_.size() < kMaxPendingRecords) {
        pending_records_.emplace(record->sequence, std::make_pair(*record, *upgrade.proof));
    }
    (void)router_.send(message.sender,
                       router_.compose(SecurityMessageKind::Upgrade,
                                       UpgradeMsg{UpgradeTopic::RecordRequest,
                                                  u64_bytes(state_.sequence), std::nullopt},
                                       current_epoch()));
}

void UpgradeService::handle_record_request(const SecurityMessage& message) {
    const auto& body = std::get<UpgradeMsg>(message.body).body;
    if (body.size() != 8) return;
    uint64_t have = 0;
    for (const uint8_t byte : body) have = (have << 8) | byte;
    std::size_t sent = 0;
    for (const auto& [record, proof] : records_) {
        if (record.sequence <= have || !proof.has_value()) continue;
        if (++sent > kMaxRecordsPerReply) break;
        (void)router_.send(message.sender,
                           router_.compose(SecurityMessageKind::Upgrade,
                                           UpgradeMsg{UpgradeTopic::RecordProof,
                                                      encode_upgrade_record(record), proof},
                                           current_epoch()));
    }
}

// --- Approvals ----------------------------------------------------------------------

ReleaseOfferResult UpgradeService::offer_approval(std::string_view bundle_json) {
    if (chain_ == nullptr) return ReleaseOfferResult::Unavailable;
    const auto result = chain_->offer_json(bundle_json);
    if (result == ReleaseOfferResult::Adopted) adopted();
    return result;
}

void UpgradeService::adopted() {
    if (chain_ == nullptr || !chain_->current()) return;
    if (on_release_adopted_) on_release_adopted_(*chain_->current());
    broadcast_approval();
}

void UpgradeService::raise_release_floor() {
    // The latest Start record finalized only when a quorum held its approval,
    // so its release number is the network floor for accepted releases.
    if (chain_ == nullptr || !state_.active()) return;
    if (chain_->raise_floor(state_.release_number) && chain_->below_floor() &&
        on_release_floor_) {
        on_release_floor_();
    }
}

void UpgradeService::broadcast_approval() {
    if (chain_ == nullptr || !chain_->current()) return;
    const auto text = release_approval_bundle_json(*chain_->current());
    (void)router_.broadcast(router_.compose(
        SecurityMessageKind::Upgrade,
        UpgradeMsg{UpgradeTopic::ApprovalOffer, std::vector<uint8_t>(text.begin(), text.end()),
                   std::nullopt},
        current_epoch()));
}

void UpgradeService::send_approval(const NodeId& peer) {
    if (chain_ == nullptr || !chain_->current() || peer == config_.self) return;
    const auto text = release_approval_bundle_json(*chain_->current());
    (void)router_.send(
        peer, router_.compose(SecurityMessageKind::Upgrade,
                              UpgradeMsg{UpgradeTopic::ApprovalOffer,
                                         std::vector<uint8_t>(text.begin(), text.end()),
                                         std::nullopt},
                              current_epoch()));
}

void UpgradeService::on_peer(const NodeId& peer) { send_approval(peer); }

// --- Records ------------------------------------------------------------------------

std::vector<NodeId> UpgradeService::tier2_participants(const std::vector<NodeId>& members) const {
    std::vector<NodeId> out;
    for (const auto& [node, status] : statuses_) {
        if (std::find(members.begin(), members.end(), node) == members.end() && live(node) &&
            status_fresh(status) && (status.flags & kUpgradeStatusAttestable) != 0) {
            out.push_back(node);
        }
    }
    return out;
}

std::optional<UpgradeRecord> UpgradeService::derive_start() const {
    if (chain_ == nullptr || !chain_->current() || state_.in_turn.has_value()) {
        return std::nullopt;
    }
    const auto& approval = chain_->current()->approval;
    if (approval.release_number <= state_.release_number) return std::nullopt;
    const auto members = current_members();
    // Every Tier 1 member reporting a status is also what shows the whole
    // committee runs a release that knows UpgradeProgress blocks.
    if (members.empty() ||
        !std::all_of(members.begin(), members.end(),
                     [this](const NodeId& node) { return live(node); })) {
        return std::nullopt;
    }
    // Nothing to roll out while every server already runs this release (a
    // network founded on it). Proposer-side only; voters judge the record.
    const auto tier2 = tier2_participants(members);
    const auto behind = [&](const NodeId& node) {
        const auto it = statuses_.find(node);
        return it != statuses_.end() && it->second.running_release < approval.release_number;
    };
    if (std::none_of(members.begin(), members.end(), behind) &&
        std::none_of(tier2.begin(), tier2.end(), behind)) {
        return std::nullopt;
    }
    UpgradeRecord record;
    record.event = UpgradeEvent::Start;
    record.release_number = approval.release_number;
    record.approval_digest = chain_->current_digest();
    record.order = derive_upgrade_order(approval.release_number, members, tier2);
    if (record.order.size() > constants::kMaxUpgradeParticipants) return std::nullopt;
    return record;
}

std::optional<UpgradeRecord> UpgradeService::next_record() const {
    std::optional<UpgradeRecord> record;
    const auto members = current_members();
    const auto threshold_for = [&](const NodeId& subject) {
        return witness_threshold(
            established_fact_context(config_.network_id, current_epoch(), members), subject);
    };
    const auto observed = [&](const NodeId& subject) -> std::optional<UpgradeRecord> {
        if (observations_subject_ != subject || observations_head_ != state_.head) {
            return std::nullopt;
        }
        std::vector<UpgradeObservation> held;
        for (const auto& [witness, observation] : observations_) {
            if (witness != subject &&
                std::find(members.begin(), members.end(), witness) != members.end()) {
                held.push_back(observation);
            }
        }
        if (held.empty() || held.size() < threshold_for(subject)) return std::nullopt;
        UpgradeRecord out;
        out.event = UpgradeEvent::Upgraded;
        out.release_number = state_.release_number;
        out.subject = subject;
        out.observations = std::move(held);
        return out;
    };
    if (state_.active() && !state_.halted) {
        if (state_.in_turn.has_value()) {
            const NodeId subject = *state_.in_turn;
            if (const auto status = fresh_status(subject);
                status && (status->flags & kUpgradeStatusFailed) != 0 &&
                status->staged_release == state_.release_number) {
                UpgradeRecord halt;
                halt.event = UpgradeEvent::Halt;
                halt.release_number = state_.release_number;
                halt.subject = subject;
                halt.status = *status;
                record = std::move(halt);
            } else {
                record = observed(subject);
            }
        } else if (const auto next = state_.next_subject()) {
            record = observed(*next);
            const auto status = fresh_status(*next);
            const bool everyone_live =
                std::all_of(members.begin(), members.end(),
                            [this](const NodeId& node) { return live(node); }) &&
                std::all_of(state_.order.begin(), state_.order.end(),
                            [this, &next](const UpgradeParticipant& entry) {
                                return entry.node == *next || live(entry.node);
                            });
            if (!record && status && everyone_live &&
                (status->flags & kUpgradeStatusReady) != 0 &&
                (status->flags & kUpgradeStatusFailed) == 0 &&
                status->staged_release == state_.release_number) {
                UpgradeRecord turn;
                turn.event = UpgradeEvent::Turn;
                turn.release_number = state_.release_number;
                turn.subject = *next;
                turn.status = *status;
                record = std::move(turn);
            }
        }
    }
    if (!record) record = derive_start();
    if (record) {
        record->network_id = config_.network_id;
        record->sequence = state_.sequence + 1;
        record->previous = state_.head;
    }
    return record;
}

bool UpgradeService::uncommitted_upgrade_ancestor(const HotStuffService& consensus,
                                                  const Digest& from) const {
    Digest cursor = from;
    while (cursor != consensus.genesis_digest()) {
        const Proposal* block = consensus.block(cursor);
        if (block == nullptr) return true;
        if (block->height <= consensus.last_committed_height()) return false;
        const BlockPayload* payload = consensus.block_payload(cursor);
        if (payload != nullptr && payload->kind == BlockPayloadKind::UpgradeProgress) return true;
        cursor = block->parent_digest;
    }
    return false;
}

std::optional<ProposedPayload> UpgradeService::propose(const HotStuffService& consensus) {
    if (!healthy_ || !config_.wall_clock_ms) return std::nullopt;
    if (uncommitted_upgrade_ancestor(consensus, consensus.state().high_qc.proposal_digest)) {
        return std::nullopt;
    }
    const auto record = next_record();
    if (!record) return std::nullopt;
    ProposedPayload out;
    out.payload = upgrade_record_payload(*record);
    if (out.payload.body.empty()) return std::nullopt;
    out.previous_state_root = state_.head;
    out.proposed_state_root = upgrade_record_digest(*record);
    out.timestamp_hint = 0;
    return out;
}

bool UpgradeService::validate(const HotStuffService& consensus, const Proposal& proposal,
                              const BlockPayload& payload) {
    if (!healthy_ || !config_.wall_clock_ms) return false;
    const auto record = upgrade_record_from_payload(payload);
    if (!record || record->network_id != config_.network_id) return false;
    if (uncommitted_upgrade_ancestor(consensus, proposal.parent_digest)) {
        spdlog::debug("[upgrade] vote withheld: an earlier upgrade block is not committed");
        return false;
    }
    if (proposal.previous_state_root != state_.head ||
        proposal.proposed_state_root != upgrade_record_digest(*record)) {
        spdlog::debug("[upgrade] vote withheld: record {} does not extend sequence {}",
                      record->sequence, state_.sequence);
        return false;
    }
    const auto witnesses = witnesses_for(proposal.epoch);
    const auto failure =
        check_upgrade_record(state_, *record, witnesses ? &*witnesses : nullptr, false);
    if (failure != UpgradeRecordFailure::None) {
        spdlog::debug("[upgrade] vote withheld: {}", upgrade_record_failure_name(failure));
        return false;
    }
    const auto members = current_members();
    const auto all_members_live = [&] {
        return std::all_of(members.begin(), members.end(),
                           [this](const NodeId& node) { return live(node); });
    };
    switch (record->event) {
        case UpgradeEvent::Start: {
            if (chain_ == nullptr || !chain_->current() ||
                chain_->current_digest() != record->approval_digest ||
                chain_->current()->approval.release_number != record->release_number ||
                !all_members_live()) {
                return false;
            }
            // Every voter orders the servers it sees live; a quorum agreeing
            // is what finalizes one participant set.
            return derive_upgrade_order(record->release_number, members,
                                        tier2_participants(members)) == record->order;
        }
        case UpgradeEvent::Turn: {
            if (!status_fresh(*record->status) || !all_members_live()) return false;
            return std::all_of(state_.order.begin(), state_.order.end(),
                               [this, &record](const UpgradeParticipant& entry) {
                                   return entry.node == record->subject || live(entry.node);
                               });
        }
        case UpgradeEvent::Halt:
            return status_fresh(*record->status);
        case UpgradeEvent::Upgraded:
            return true;
    }
    return false;
}

void UpgradeService::on_committed(const CommittedPayload& committed) {
    if (!healthy_ || committed.payload == nullptr) return;
    const auto record = upgrade_record_from_payload(*committed.payload);
    if (!record || record->network_id != config_.network_id) return;
    const auto witnesses = witnesses_for(committed.proposal.epoch);
    if (!accept_record(*record, committed.proof, witnesses ? &*witnesses : nullptr, true)) {
        spdlog::warn("[upgrade] committed record {} does not extend this node's chain at {}",
                     record->sequence, state_.sequence);
        return;
    }
    broadcast_record(record->sequence);
}

bool UpgradeService::accept_record(const UpgradeRecord& record, std::optional<CommitProof> proof,
                                   const UpgradeWitnessSet* witnesses, bool as_base) {
    if (record.sequence <= state_.sequence) return false;
    const auto failure = check_upgrade_record(state_, record, witnesses, as_base);
    if (failure != UpgradeRecordFailure::None) {
        spdlog::debug("[upgrade] record {} refused: {}", record.sequence,
                      upgrade_record_failure_name(failure));
        return false;
    }
    if (record.event == UpgradeEvent::Start) records_.clear();
    apply_upgrade_record(state_, record);
    records_.emplace_back(record, std::move(proof));
    observations_.clear();
    pending_witness_.reset();
    persist();
    if (record.event == UpgradeEvent::Start) raise_release_floor();
    switch (record.event) {
        case UpgradeEvent::Start:
            spdlog::info("[upgrade] release {} rollout started: {} participants",
                         record.release_number, record.order.size());
            break;
        case UpgradeEvent::Turn:
            spdlog::info("[upgrade] release {}: turn opened for {}", record.release_number,
                         short_id(record.subject));
            break;
        case UpgradeEvent::Upgraded:
            spdlog::info("[upgrade] release {}: {} upgraded ({} witnesses)",
                         record.release_number, short_id(record.subject),
                         record.observations.size());
            break;
        case UpgradeEvent::Halt:
            spdlog::warn("[upgrade] release {} halted: {} reported a failed upgrade",
                         record.release_number, short_id(record.subject));
            break;
    }
    drain_pending();
    return true;
}

void UpgradeService::drain_pending() {
    while (!pending_records_.empty()) {
        auto first = pending_records_.begin();
        if (first->first <= state_.sequence) {
            pending_records_.erase(first);
            continue;
        }
        if (first->first != state_.sequence + 1) return;
        auto [record, proof] = std::move(first->second);
        pending_records_.erase(first);
        const auto witnesses = witnesses_for(proof.chain.front().proposal.epoch);
        if (!witnesses ||
            !accept_record(record, std::move(proof), &*witnesses, false)) {
            return;
        }
    }
}

void UpgradeService::broadcast_record(uint64_t sequence) {
    for (const auto& [record, proof] : records_) {
        if (record.sequence != sequence || !proof.has_value()) continue;
        (void)router_.broadcast(router_.compose(
            SecurityMessageKind::Upgrade,
            UpgradeMsg{UpgradeTopic::RecordProof, encode_upgrade_record(record), proof},
            current_epoch()));
        return;
    }
}

// --- Local control ------------------------------------------------------------------

void UpgradeService::stage(uint64_t release_number) {
    staged_release_ = release_number;
    if (failed_release_ != release_number) failed_release_ = 0;
    send_status();
}

void UpgradeService::report_failed(uint64_t release_number) {
    if (release_number == 0) return;
    staged_release_ = release_number;
    failed_release_ = release_number;
    send_status();
}

UpgradeGate UpgradeService::gate(uint64_t release_number) const {
    // Corrupt records never open a turn.
    if (!healthy_) return UpgradeGate::Wait;
    return evaluate_upgrade_gate(state_, config_.self, release_number);
}

const std::optional<ReleaseApprovalBundleV1>& UpgradeService::accepted_approval() const {
    static const std::optional<ReleaseApprovalBundleV1> kNone;
    return chain_ != nullptr && chain_->healthy() ? chain_->current() : kNone;
}

UpgradeHealthReport UpgradeService::health() const {
    UpgradeHealthReport report;
    report.running_release = config_.running_release;
    report.accepted_release = chain_ != nullptr ? chain_->highest_release_number() : 0;
    report.driver_phase = phase_label(driver_.phase());
    report.driver_failed = driver_.phase() == DriverPhase::Failed;
    report.verified_authority = driver_.verified_authority() != nullptr;
    report.tier1_member = driver_.is_tier1_member();
    if (const auto epoch = current_epoch(); epoch != EpochId{}) {
        report.epoch = epoch.underlying();
    }
    if (config_.data_key_state) report.data_key_state = config_.data_key_state();
    report.healthy = locally_healthy();
    return report;
}

// --- Persistence --------------------------------------------------------------------

std::vector<uint8_t> UpgradeService::encode_record_proof(const UpgradeRecord& record,
                                                         const CommitProof& proof) const {
    return encode_security_message(router_.compose(
        SecurityMessageKind::Upgrade,
        UpgradeMsg{UpgradeTopic::RecordProof, encode_upgrade_record(record), proof},
        proof.chain.empty() ? EpochId{} : proof.chain.front().proposal.epoch));
}

std::optional<RolloutProof> UpgradeService::rollout_proof(
    const crypto::Ed25519PublicKey& genesis_public_key) const {
    const auto chain = driver_.authority_chain();
    if (!chain || !chain->has_base) return std::nullopt;
    RolloutProof out;
    out.genesis_public_key = genesis_public_key;
    for (const auto& [record, proof] : records_) {
        if (!proof.has_value() || proof->chain.empty()) return std::nullopt;
        out.records.push_back(encode_record_proof(record, *proof));
    }
    AuthorityChainPage base;
    base.has_base = true;
    base.base_certificate = chain->base_certificate;
    base.base_vote_keys = chain->base_vote_keys;
    out.base = encode_security_message(
        router_.compose(SecurityMessageKind::AuthorityChainPage, std::move(base), EpochId{}));
    for (const auto& link : chain->links) {
        out.links.push_back(encode_security_message(
            router_.compose(SecurityMessageKind::EpochHandoffProof, link, link.handoff.to_epoch)));
    }
    return out;
}

void UpgradeService::persist() {
    std::error_code ec;
    std::filesystem::create_directories(config_.directory, ec);
    nlohmann::json records = nlohmann::json::array();
    // The commit proofs are kept so that this server can still prove the
    // rollout after a restart (RolloutProof.hpp). Empty: no proof held.
    nlohmann::json proofs = nlohmann::json::array();
    for (const auto& [record, proof] : records_) {
        records.push_back(crypto::to_hex(encode_upgrade_record(record)));
        proofs.push_back(proof.has_value() && !proof->chain.empty()
                             ? crypto::to_hex(encode_record_proof(record, *proof))
                             : std::string());
    }
    const nlohmann::json root = {{"format_version", kRecordsFormatVersion},
                                 {"records", std::move(records)},
                                 {"proofs", std::move(proofs)}};
    if (ec || !write_durable(config_.directory / kRecordsFile, root.dump())) {
        spdlog::warn("[upgrade] cannot persist upgrade records");
    }
}

std::optional<CommitProof> UpgradeService::stored_proof(const std::string& hex,
                                                       const UpgradeRecord& record) const {
    if (hex.empty()) return std::nullopt;
    auto decoded = decode_security_message(crypto::from_hex(hex));
    const auto* message = std::get_if<SecurityMessage>(&decoded);
    const auto* body = message != nullptr ? std::get_if<UpgradeMsg>(&message->body) : nullptr;
    // A proof is kept only for the record it was stored with; a remote
    // verifier checks it again, so a damaged proof costs only provability.
    if (body == nullptr || body->topic != UpgradeTopic::RecordProof || !body->proof ||
        body->body != encode_upgrade_record(record)) {
        return std::nullopt;
    }
    return body->proof;
}

bool UpgradeService::load() {
    state_ = {};
    records_.clear();
    const auto path = config_.directory / kRecordsFile;
    std::error_code ec;
    if (!std::filesystem::exists(path, ec)) return !ec;
    std::ifstream stream(path, std::ios::binary);
    if (!stream) return false;
    try {
        const auto root = nlohmann::json::parse(stream);
        if (root.at("format_version").get<uint32_t>() != kRecordsFormatVersion) return false;
        // "proofs" is optional: a file written before it existed holds none.
        const auto proofs = root.value("proofs", nlohmann::json::array());
        for (const auto& entry : root.at("records")) {
            const auto bytes = crypto::from_hex(entry.get<std::string>());
            auto record = decode_upgrade_record(bytes);
            if (!record || record->network_id != config_.network_id) return false;
            // Stored records were checked when they finalized; the chaining is
            // what a restart re-proves.
            const bool first = records_.empty();
            if (first ? record->event != UpgradeEvent::Start
                      : (record->sequence != state_.sequence + 1 ||
                         record->previous != state_.head ||
                         record->event == UpgradeEvent::Start)) {
                return false;
            }
            apply_upgrade_record(state_, *record);
            std::optional<CommitProof> proof;
            if (const auto index = records_.size(); index < proofs.size()) {
                proof = stored_proof(proofs[index].get<std::string>(), *record);
            }
            records_.emplace_back(std::move(*record), std::move(proof));
        }
    } catch (const std::exception&) {
        return false;
    }
    return true;
}

}  // namespace nexus::security
