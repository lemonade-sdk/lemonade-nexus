#include <LemonadeNexus/Security/Storage/StorageKeyService.hpp>

#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Security/Attestation/AttestationProfileId.hpp>
#include <LemonadeNexus/Security/Attestation/VerifiedPlatformClaims.hpp>
#include <LemonadeNexus/Security/Consensus/CommitProof.hpp>
#include <LemonadeNexus/Security/Consensus/HotStuffService.hpp>
#include <LemonadeNexus/Security/DurableWrite.hpp>
#include <LemonadeNexus/Security/Lifecycle/SecurityDriver.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/SecurityRuntime.hpp>
#include <LemonadeNexus/Security/Storage/DataKeyService.hpp>
#include <LemonadeNexus/Security/Transport/PairwiseSeal.hpp>
#include <LemonadeNexus/Security/Transport/SecurityRouter.hpp>

#include <nlohmann/json.hpp>
#include <sodium.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <fstream>
#include <sstream>

namespace nexus::security {

namespace {

using json = nlohmann::json;

constexpr int kRecordsFormat = 1;
/// Verified epoch authorities kept for checking commit proofs of records
/// that committed in an earlier epoch than this node's current one.
constexpr std::size_t kAuthorityHistory = 8;

std::string short_hex(std::span<const uint8_t> bytes) {
    return crypto::to_hex(bytes.first(std::min<std::size_t>(bytes.size(), 6)));
}

bool storage_payload(const BlockPayload* payload) {
    return payload != nullptr && (payload->kind == BlockPayloadKind::StorageHolderPlan ||
                                  payload->kind == BlockPayloadKind::StorageKeyRotation);
}

const NetworkId& record_network(const StorageRecord& record) {
    return std::visit([](const auto& value) -> const NetworkId& { return value.network_id; },
                      record);
}

void wipe(crypto::StoragePeerBytesMap& map) {
    for (auto& [id, bytes] : map) {
        if (!bytes.empty()) {
            sodium_memzero(bytes.data(), bytes.size());
        }
    }
    map.clear();
}

}  // namespace

// --- Payload adapters --------------------------------------------------------

/// One registered handler per storage payload kind; both delegate to the
/// service, which decides on the one storage chain.
class StorageKeyService::PayloadAdapter final : public IBlockPayloadHandler {
public:
    PayloadAdapter(StorageKeyService& service, BlockPayloadKind kind)
        : service_(service), kind_(kind) {}

    [[nodiscard]] BlockPayloadKind kind() const override { return kind_; }
    [[nodiscard]] std::optional<ProposedPayload> propose(
        const HotStuffService& consensus) override {
        return service_.propose(consensus, kind_);
    }
    [[nodiscard]] bool validate(const HotStuffService& consensus, const Proposal& proposal,
                                const BlockPayload& payload) override {
        return payload.kind == kind_ && service_.validate(consensus, proposal, payload);
    }
    void on_committed(const CommittedPayload& committed) override {
        service_.on_committed(committed);
    }
    void on_consensus_reset() override {}

private:
    StorageKeyService& service_;
    BlockPayloadKind kind_;
};

// --- Session state -----------------------------------------------------------

struct StorageKeyService::Session {
    enum class Phase : uint8_t { Observing, Round1, Round2, Confirmed, Failed };

    StorageSelection selection;
    Digest id{};
    std::optional<StorageHolder> self;
    Phase phase = Phase::Observing;

    std::optional<crypto::StorageDkgRound1> dkg1;
    std::optional<crypto::StorageDkgRound2> dkg2;
    std::optional<crypto::StorageRefreshRound1> refresh1;
    std::optional<crypto::StorageRefreshRound2> refresh2;

    std::vector<uint8_t> own_round1;
    /// Sealed round-2 packages by recipient identifier, kept for re-sends.
    std::map<uint16_t, std::vector<uint8_t>> own_round2;
    std::vector<uint8_t> own_plan;
    crypto::Ed25519Signature own_confirmation{};

    /// One message per sender per round (design Part C). Round-2 entries
    /// stay sealed until this holder finishes.
    RoundInbox<uint16_t, std::vector<uint8_t>> round1;
    RoundInbox<uint16_t, std::vector<uint8_t>> round2;
    /// Holders whose round-1 package this node observed. A retry excludes the
    /// complement, and the holders that never confirmed (silent_holders()).
    std::set<NodeId> spoke;

    /// Confirmations by plan-bytes digest; one per holder.
    std::map<Digest, std::pair<std::vector<uint8_t>, std::map<NodeId, crypto::Ed25519Signature>>>
        confirmations;
    std::map<NodeId, Digest> confirmed_plan;

    ResendCadence resend{constants::kStorageResendMs};

    [[nodiscard]] const StorageHolder* holder_of(const NodeId& node) const {
        for (const auto& holder : selection.holders) {
            if (holder.node == node) return &holder;
        }
        return nullptr;
    }
    [[nodiscard]] const StorageHolder* holder_by_id(uint16_t id) const {
        for (const auto& holder : selection.holders) {
            if (holder.holder_id == id) return &holder;
        }
        return nullptr;
    }
    [[nodiscard]] std::size_t others() const { return selection.holders.size() - 1; }
};

// --- Construction and lifecycle ---------------------------------------------

StorageKeyService::StorageKeyService(StorageKeyServiceConfig config, SecurityDriver& driver,
                                     SecurityRouter& router, SecurityRuntime& runtime,
                                     PairwiseSealer& sealer, IStorageShareStore& shares,
                                     crypto::SodiumCryptoService& crypto)
    : config_(std::move(config)),
      driver_(driver),
      router_(router),
      runtime_(runtime),
      sealer_(sealer),
      share_store_(shares),
      crypto_(crypto),
      plan_handler_(std::make_unique<PayloadAdapter>(*this, BlockPayloadKind::StorageHolderPlan)),
      rotation_handler_(
          std::make_unique<PayloadAdapter>(*this, BlockPayloadKind::StorageKeyRotation)),
      data_keys_(std::make_unique<DataKeyService>(*this)) {}

StorageKeyService::~StorageKeyService() = default;

void StorageKeyService::attach() {
    driver_.register_payload_handler(*plan_handler_);
    driver_.register_payload_handler(*rotation_handler_);
    driver_.set_storage_sink([this](const SecurityMessage& message) { on_message(message); });
    driver_.set_storage_verdict_sink(
        [this](const AttestationVerdict& verdict) { on_verdict(verdict); });
    driver_.set_eligibility_finalized_callback(
        [this](const FinalizedEligibility& finalized, const Tier1Set& pool) {
            on_eligibility_finalized(finalized, pool);
        });
}

bool StorageKeyService::start(uint64_t now_ms) {
    now_ms_ = now_ms;
    if (!load_shares()) {
        spdlog::error("[storage] the sealed storage shares do not load; the storage key stays "
                      "inert on this server");
        healthy_ = false;
        return false;
    }
    if (!load_records()) {
        spdlog::error("[storage] the storage records do not load; the storage key stays inert "
                      "on this server");
        healthy_ = false;
        return false;
    }
    if (files_encrypted()) {
        // Encrypted files open only with the data key wrapped to an S that
        // these records name. Without them the service would prune this
        // holder's shares against an empty chain and later create a new data
        // key, and the files would never open again.
        std::string lost;
        const auto records = config_.directory / "records.json";
        if (!records_file_present_) {
            lost = records.string() + " is missing";
        } else if (!chain_.current.has_value()) {
            lost = records.string() + " holds no finalized storage plan";
        }
        std::error_code ec;
        const auto data_key = config_.directory / "data-key.json";
        if (!std::filesystem::exists(data_key, ec)) {
            lost += (lost.empty() ? "" : "; ") + data_key.string() + " is missing";
        }
        if (!lost.empty()) {
            halt("the files are encrypted under the data key, but the storage state that unlocks "
                 "them is lost: " +
                 lost +
                 ". Restore records.json and data-key.json in that directory from this "
                 "server's backup before it starts again. The server does not start fresh: that "
                 "would destroy its storage share and create a new data key, and the encrypted "
                 "files would never open.");
            healthy_ = false;
            return false;
        }
    }
    healthy_ = true;
    // Shares are pruned only after bind_chain() proves the records belong to
    // this node's epoch chain.
    return true;
}

std::string StorageKeyService::halt_reason() const {
    std::lock_guard lock(halt_mutex_);
    return halt_reason_;
}

void StorageKeyService::halt(std::string reason) {
    spdlog::error("[storage] {}", reason);
    std::lock_guard lock(halt_mutex_);
    halt_reason_ = std::move(reason);
}

bool StorageKeyService::files_encrypted() const {
    return config_.files_encrypted && config_.files_encrypted();
}

void StorageKeyService::bind_chain() {
    if (chain_bound_) {
        return;
    }
    // The chain identity is the Genesis certificate's signing digest, the
    // anchor of Epoch 1. Every epoch this node verified chains from it.
    const auto epoch_one = driver_.authority_for_epoch(EpochId{1});
    if (!epoch_one.has_value()) {
        return;
    }
    const Digest identity = epoch_one->anchor_digest;
    bool foreign = false;
    if (stored_chain_.has_value()) {
        foreign = *stored_chain_ != identity;
    } else {
        // Records written before the binding existed: each commit proof must
        // verify under this chain's authority for the epoch that committed it.
        for (const auto& [digest, proof] : proofs_) {
            if (proof.proof.chain.empty()) {
                foreign = true;
                break;
            }
            const EpochId epoch = proof.proof.chain.front().proposal.epoch;
            const auto authority = driver_.authority_for_epoch(epoch);
            if (!authority.has_value()) {
                return;  // decide once this node verified that epoch
            }
            const QcValidationContext context{constants::kConsensusRulesetVersion,
                                              config_.network_id, epoch,
                                              authority->consensus_quorum};
            if (verify_commit_proof(block_payload_digest(proof.payload), proof.proof, context,
                                    authority->vote_keys) != CommitProofFailure::None) {
                foreign = true;
                break;
            }
        }
    }
    if (foreign) {
        healthy_ = false;
        session_.reset();
        const std::string text =
            (config_.directory / "records.json").string() +
            " belongs to another epoch chain (for example a re-found mesh, or a backup from "
            "another network). Its records and this server's storage share and data key do not "
            "apply to this chain.";
        if (files_encrypted()) {
            halt(text +
                 " The files are encrypted under that chain's data key: restore records.json, "
                 "data-key.json, and the sealed share of the chain that encrypted them, or "
                 "restore the server's files from a backup of this chain.");
        } else {
            spdlog::error("[storage] {} The storage key stays inert on this server. Move "
                          "records.json and data-key.json in that directory aside to join this "
                          "chain's storage key.",
                          text);
        }
        return;
    }
    chain_identity_ = identity;
    chain_bound_ = true;
    if (records_file_present_ && stored_chain_ != identity) {
        persist_records();
    }
    prune_shares();
}

void StorageKeyService::tick(uint64_t now_ms) {
    now_ms_ = now_ms;
    if (!healthy_) {
        return;
    }
    capture_authority();
    bind_chain();
    if (!healthy_) {
        return;
    }
    sync_records(now_ms);
    resend(now_ms);
    prune_shares();
    for (auto it = pending_unlocks_.begin(); it != pending_unlocks_.end();) {
        it = now_ms >= it->second.expires_ms ? pending_unlocks_.erase(it) : std::next(it);
    }
    const EpochId epoch = current_epoch();
    if (epoch != seen_epoch_) {
        // A request names its epoch and must match the holder's, so a replay
        // from an earlier epoch is refused by the epoch check alone.
        seen_requests_.clear();
        seen_epoch_ = epoch;
        std::erase_if(unlock_counts_, [epoch](const auto& entry) {
            return entry.first.first < epoch;
        });
    }
    data_keys_->tick(now_ms);
}

EpochId StorageKeyService::current_epoch() const {
    if (const EpochManager* epochs = runtime_.epochs(); epochs != nullptr) {
        return epochs->current().id;
    }
    if (const VerifiedEpochAuthority* authority = driver_.verified_authority()) {
        return authority->epoch;
    }
    return EpochId{};
}

bool StorageKeyService::retiring_live() const {
    // Finalized block time and finalized claims only, so every server with
    // the same records agrees.
    return storage_retiring_live(chain_, chain_.last_block_time_ms);
}

uint64_t StorageKeyService::drops(StorageDrop reason) const {
    const auto it = drops_.find(reason);
    return it == drops_.end() ? 0 : it->second;
}

void StorageKeyService::drop(StorageDrop reason) {
    ++drops_[reason];
    spdlog::debug("[storage] dropped a message: reason {}", static_cast<uint16_t>(reason));
}

bool StorageKeyService::expects_unlock_challenge(const NodeId& holder,
                                                 const Digest& context) const {
    return healthy_ && data_keys_->expects_challenge(holder, context);
}

void StorageKeyService::on_eligibility_finalized(const FinalizedEligibility& finalized,
                                                 const Tier1Set& pool) {
    if (snapshot_.has_value() && snapshot_->target_epoch >= finalized.next_epoch) {
        return;
    }
    StorageEligibleSnapshot snapshot;
    snapshot.target_epoch = finalized.next_epoch;
    snapshot.eligibility_commitment = finalized.commitment;
    snapshot.checkpoint_seed = finalized.state_root;
    snapshot.pool = pool.members();
    snapshot_ = std::move(snapshot);
}

const StorageEligibleSnapshot* StorageKeyService::derivation_snapshot() const {
    return snapshot_.has_value() ? &*snapshot_ : nullptr;
}

// --- Inbound ------------------------------------------------------------------

void StorageKeyService::on_message(const SecurityMessage& message) {
    if (!healthy_) {
        return;
    }
    std::visit(
        [&](const auto& body) {
            using T = std::decay_t<decltype(body)>;
            if constexpr (std::is_same_v<T, StoragePlanProofMsg>) {
                on_plan_proof(body);
            } else if constexpr (std::is_same_v<T, StoragePlanRequestMsg>) {
                on_plan_request(body, message.sender);
            } else if constexpr (std::is_same_v<T, StorageKeyPackageMsg>) {
                on_package(body);
            } else if constexpr (std::is_same_v<T, StorageUnlockRequestMsg>) {
                on_unlock_request(body);
            } else if constexpr (std::is_same_v<T, StorageUnlockPartialMsg>) {
                on_unlock_partial(body);
            } else if constexpr (std::is_same_v<T, StorageWrapClaimMsg>) {
                on_wrap_claim(body);
            }
        },
        message.body);
}

// --- Records ------------------------------------------------------------------

void StorageKeyService::capture_authority() {
    if (const EpochManager* epochs = runtime_.epochs(); epochs != nullptr) {
        const EpochState& current = epochs->current();
        if (current.id != EpochId{}) {
            authorities_[current.id] = {current.consensus_quorum, epochs->current_vote_keys()};
        }
    }
    if (const VerifiedEpochAuthority* authority = driver_.verified_authority()) {
        authorities_[authority->epoch] = {authority->consensus_quorum, authority->vote_keys};
    }
    while (authorities_.size() > kAuthorityHistory) {
        authorities_.erase(authorities_.begin());
    }
}

void StorageKeyService::on_plan_proof(const StoragePlanProofMsg& message) {
    const auto record = storage_record_from_payload(message.payload);
    if (!record.has_value() || record_network(*record) != config_.network_id ||
        message.proof.chain.size() != 3) {
        drop(StorageDrop::Malformed);
        return;
    }
    // Cheap checks first: a record this node already holds verified, or one
    // older than its chain that is not the retiring plan or a wrap batch,
    // costs no signature work. An older batch can still carry claims this
    // node lacks.
    const Digest digest = storage_record_digest(*record);
    const bool batch = std::holds_alternative<StorageWrapBatch>(*record);
    const bool held = digest == chain_.pending_digest || digest == chain_.retiring_digest ||
                      (digest == chain_.current_digest && current_verified_) ||
                      (batch && proofs_.contains(digest));
    const bool wanted_retiring = chain_.current.has_value() && !chain_.retiring.has_value() &&
                                 digest == chain_.current->retiring_plan;
    if (held || (!batch && storage_record_sequence(*record) <= chain_.sequence &&
                 digest != chain_.current_digest && !wanted_retiring)) {
        return;
    }
    capture_authority();
    const EpochId epoch = message.proof.chain.front().proposal.epoch;
    const auto keys = authorities_.find(epoch);
    if (keys == authorities_.end()) {
        // Nothing to verify against yet; the proof arrives again on the next
        // sync once this node holds that epoch's authority.
        drop(StorageDrop::ProofInvalid);
        return;
    }
    const QcValidationContext context{constants::kConsensusRulesetVersion, config_.network_id,
                                      epoch, keys->second.quorum};
    const auto failure = verify_commit_proof(block_payload_digest(message.payload),
                                             message.proof, context, keys->second.vote_keys);
    if (failure != CommitProofFailure::None) {
        drop(StorageDrop::ProofInvalid);
        return;
    }
    if (const auto* plan = std::get_if<StorageFinalPlan>(&*record);
        plan != nullptr && plan->effective_epoch != epoch) {
        drop(StorageDrop::ProofInvalid);
        return;
    }
    apply_record(*record, message, true);
}

void StorageKeyService::on_plan_request(const StoragePlanRequestMsg& request,
                                        const NodeId& from) {
    if (from == config_.self) {
        return;
    }
    send_live_records(from, request.have_sequence);
}

void StorageKeyService::send_live_records(const NodeId& to, uint64_t after_sequence) {
    // proofs_ holds the live records only: the pending, current, and retiring
    // plans and the batches that carry a latest claim. Oldest first, so a
    // fresh server learns the retiring plan through the current one.
    const EpochId epoch = current_epoch();
    std::vector<std::pair<uint64_t, const StoragePlanProofMsg*>> live;
    for (const auto& [digest, proof] : proofs_) {
        const auto record = storage_record_from_payload(proof.payload);
        if (record.has_value() && storage_record_sequence(*record) > after_sequence) {
            live.emplace_back(storage_record_sequence(*record), &proof);
        }
    }
    std::sort(live.begin(), live.end(),
              [](const auto& a, const auto& b) { return a.first < b.first; });
    for (const auto& [sequence, proof] : live) {
        (void)router_.send(to, router_.compose(SecurityMessageKind::StoragePlanProof, *proof,
                                               epoch));
    }
}

std::vector<NodeId> StorageKeyService::tier1_members() const {
    std::vector<NodeId> members;
    if (const VerifiedEpochAuthority* authority = driver_.verified_authority()) {
        members = authority->members;
    } else if (const EpochManager* epochs = runtime_.epochs(); epochs != nullptr) {
        members = epochs->current().tier1_members.members();
    }
    return members;
}

void StorageKeyService::broadcast_proof(const Digest& record_digest) {
    const auto proof = proofs_.find(record_digest);
    if (proof == proofs_.end()) {
        return;
    }
    (void)router_.broadcast(router_.compose(SecurityMessageKind::StoragePlanProof, proof->second,
                                            current_epoch()));
}

void StorageKeyService::sync_records(uint64_t now_ms) {
    if (!record_sync_.due(now_ms)) {
        return;
    }
    std::vector<NodeId> members = tier1_members();
    std::erase(members, config_.self);
    if (members.empty()) {
        return;
    }
    const NodeId& target = members[sync_cursor_++ % members.size()];
    // A record read from disk is re-proved in this run before its S gets a
    // new wrap, so an unverified head asks for everything again. So does a
    // gap in the sequence: a missed wrap batch may still carry a live claim.
    const uint64_t have = current_verified_ && !record_gap_ ? chain_.sequence : 0;
    record_gap_ = false;
    (void)router_.send(target, router_.compose(SecurityMessageKind::StoragePlanRequest,
                                               StoragePlanRequestMsg{have}, current_epoch()));
}

bool StorageKeyService::live_batch(const StorageRecord& record) const {
    const auto* batch = std::get_if<StorageWrapBatch>(&record);
    if (batch == nullptr) {
        return false;
    }
    return std::any_of(batch->claims.begin(), batch->claims.end(), [this](const auto& claim) {
        const auto it = chain_.wrap_claims.find(claim.node);
        return it != chain_.wrap_claims.end() && it->second == claim;
    });
}

void StorageKeyService::apply_record(const StorageRecord& record,
                                     std::optional<StoragePlanProofMsg> proof, bool verified) {
    const Digest digest = storage_record_digest(record);
    if (storage_record_sequence(record) > chain_.sequence + 1) {
        record_gap_ = true;
    }
    if (std::holds_alternative<StorageWrapBatch>(record)) {
        const bool changed = apply_storage_record(chain_, record);
        if (proof.has_value() && !proofs_.contains(digest) && live_batch(record)) {
            proofs_.emplace(digest, std::move(*proof));
        } else if (!changed) {
            return;
        }
        std::erase_if(claim_pool_, [this](const auto& entry) {
            const auto it = chain_.wrap_claims.find(entry.first);
            return it != chain_.wrap_claims.end() && it->second.counter >= entry.second.counter;
        });
        std::erase_if(proofs_, [this](const auto& entry) {
            const auto stored = storage_record_from_payload(entry.second.payload);
            return stored.has_value() && std::holds_alternative<StorageWrapBatch>(*stored) &&
                   !live_batch(*stored);
        });
        persist_records();
        data_keys_->on_chain_changed();
        return;
    }
    const bool known = digest == chain_.current_digest || digest == chain_.pending_digest ||
                       digest == chain_.retiring_digest;
    if (known) {
        bool changed = false;
        if (verified && digest == chain_.current_digest && !current_verified_) {
            current_verified_ = true;
            changed = true;
        }
        if (proof.has_value() && !proofs_.contains(digest)) {
            proofs_.emplace(digest, std::move(*proof));
            persist_records();
        }
        if (changed) {
            data_keys_->on_chain_changed();
        }
        return;
    }
    if (!apply_storage_record(chain_, record)) {
        return;
    }
    if (proof.has_value()) {
        proofs_.insert_or_assign(digest, std::move(*proof));
    }
    if (const auto* selection = std::get_if<StorageSelection>(&record)) {
        open_session();
        spdlog::info("[storage] holder selection finalized: sequence {} operation {} holders {} "
                     "threshold {} attempt {} target epoch {}; this server {}",
                     selection->sequence, storage_operation_name(selection->operation),
                     selection->holders.size(), selection->threshold, selection->attempt,
                     selection->target_epoch.underlying(),
                     session_ != nullptr && session_->self.has_value()
                         ? "is holder " + std::to_string(session_->self->holder_id)
                         : std::string("observes"));
        if (session_ != nullptr && session_->self.has_value()) {
            start_round1(*session_);
        }
    } else if (chain_.current_digest == digest) {
        const auto& plan = std::get<StorageFinalPlan>(record);
        current_verified_ = verified;
        if (session_ != nullptr && session_->id == plan.selection) {
            adopt_session_share(session_->id, digest);
        }
        session_.reset();
        switch (plan.operation) {
            case StorageOperation::Create:
                spdlog::info("[storage] storage key created: epoch {} sequence {} holders {} "
                             "threshold {} S {}",
                             plan.effective_epoch.underlying(), plan.sequence,
                             plan.holders.size(), plan.threshold,
                             short_hex(plan.storage_public_key));
                break;
            case StorageOperation::Rotate:
                spdlog::info("[storage] storage key rotated: epoch {} sequence {} holders {} "
                             "threshold {} S {}; the previous S unwraps until every server "
                             "claims a rewrap, at most until block time {}",
                             plan.effective_epoch.underlying(), plan.sequence,
                             plan.holders.size(), plan.threshold,
                             short_hex(plan.storage_public_key), plan.retiring_until_ms);
                break;
            case StorageOperation::Refresh:
                spdlog::info("[storage] storage shares refreshed: epoch {} sequence {} holders "
                             "{} threshold {}",
                             plan.effective_epoch.underlying(), plan.sequence,
                             plan.holders.size(), plan.threshold);
                break;
        }
    }
    // Keep the proofs of the live records only.
    std::erase_if(proofs_, [this](const auto& entry) {
        if (entry.first == chain_.current_digest || entry.first == chain_.pending_digest ||
            entry.first == chain_.retiring_digest) {
            return false;
        }
        const auto stored = storage_record_from_payload(entry.second.payload);
        return !stored.has_value() || !live_batch(*stored);
    });
    prune_shares();
    persist_records();
    data_keys_->on_chain_changed();
}

void StorageKeyService::persist_records() {
    json records = json::array();
    std::vector<std::pair<uint64_t, Digest>> live;
    for (const auto& [digest, proof] : proofs_) {
        const auto record = storage_record_from_payload(proof.payload);
        if (record.has_value()) {
            live.emplace_back(storage_record_sequence(*record), digest);
        }
    }
    std::sort(live.begin(), live.end());
    for (const auto& [sequence, digest] : live) {
        const auto bytes = encode_security_message(
            router_.compose(SecurityMessageKind::StoragePlanProof, proofs_.at(digest), 0));
        if (!bytes.empty()) {
            records.push_back(crypto::to_base64(bytes));
        }
    }
    json document;
    document["format"] = kRecordsFormat;
    document["records"] = std::move(records);
    // The epoch chain these records belong to (see bind_chain()).
    if (const auto& chain = chain_identity_.has_value() ? chain_identity_ : stored_chain_) {
        document["chain"] = crypto::to_hex(*chain);
    }
    std::error_code ec;
    std::filesystem::create_directories(config_.directory, ec);
    if (!write_durable(config_.directory / "records.json", document.dump())) {
        spdlog::warn("[storage] the storage records could not be written");
    }
}

bool StorageKeyService::load_records() {
    std::ifstream in(config_.directory / "records.json", std::ios::binary);
    if (!in) {
        return true;  // nothing stored yet
    }
    records_file_present_ = true;
    std::ostringstream buffer;
    buffer << in.rdbuf();
    const json document = json::parse(buffer.str(), nullptr, false);
    if (!document.is_object() || !document.contains("format") ||
        document["format"] != kRecordsFormat || !document.contains("records") ||
        !document["records"].is_array() ||
        document["records"].size() > 3 + constants::kStorageMaxWrapOwners) {
        return false;
    }
    if (document.contains("chain")) {
        if (!document["chain"].is_string()) {
            return false;
        }
        const auto bytes = crypto::from_hex(document["chain"].get<std::string>());
        Digest chain{};
        if (bytes.size() != chain.size()) {
            return false;
        }
        std::copy(bytes.begin(), bytes.end(), chain.begin());
        stored_chain_ = chain;
    }
    for (const auto& entry : document["records"]) {
        if (!entry.is_string()) {
            return false;
        }
        const auto bytes = crypto::from_base64(entry.get<std::string>());
        const auto decoded = decode_security_message(bytes);
        const auto* message = std::get_if<SecurityMessage>(&decoded);
        if (message == nullptr) {
            return false;
        }
        const auto* proof = std::get_if<StoragePlanProofMsg>(&message->body);
        if (proof == nullptr) {
            return false;
        }
        const auto record = storage_record_from_payload(proof->payload);
        if (!record.has_value() || record_network(*record) != config_.network_id) {
            return false;
        }
        (void)apply_storage_record(chain_, *record);
        proofs_.insert_or_assign(storage_record_digest(*record), *proof);
    }
    // Records read from disk are this node's own earlier verification. They
    // serve unlock and holder duties, but no new wrap targets their S until
    // this run proves the current record again.
    current_verified_ = false;
    if (chain_.pending.has_value()) {
        // The session's library state died with the process: observe only. A
        // retry under a new session id runs without equivocation.
        open_session();
    }
    return true;
}

bool StorageKeyService::uncommitted_storage_ancestor(const HotStuffService& consensus,
                                                     const Digest& from) const {
    Digest cursor = from;
    while (cursor != consensus.genesis_digest()) {
        const Proposal* block = consensus.block(cursor);
        if (block == nullptr) {
            return true;
        }
        if (block->height <= consensus.last_committed_height()) {
            return false;
        }
        if (storage_payload(consensus.block_payload(cursor))) {
            return true;
        }
        cursor = block->parent_digest;
    }
    return false;
}

std::set<NodeId> StorageKeyService::silent_holders() const {
    std::set<NodeId> silent;
    if (!chain_.pending.has_value()) {
        return silent;
    }
    const bool observed = session_ != nullptr && session_->id == chain_.pending_digest;
    // Once one holder confirmed, the session got through round 2. A holder
    // that sent round 1 and never confirmed (for example one that cannot seal
    // its share) is then left out too; otherwise it stalls every retry.
    const bool confirmed = observed && !session_->confirmed_plan.empty();
    for (const auto& holder : chain_.pending->holders) {
        if (!observed || !session_->spoke.contains(holder.node) ||
            (confirmed && !session_->confirmed_plan.contains(holder.node))) {
            silent.insert(holder.node);
        }
    }
    return silent;
}

std::optional<ProposedPayload> StorageKeyService::propose(const HotStuffService& consensus,
                                                          BlockPayloadKind kind) {
    if (!healthy_ || !config_.wall_clock_ms) {
        return std::nullopt;
    }
    const Digest parent_digest = consensus.state().high_qc.proposal_digest;
    if (uncommitted_storage_ancestor(consensus, parent_digest)) {
        return std::nullopt;
    }
    const uint64_t now = config_.wall_clock_ms();
    const Proposal* parent = consensus.block(parent_digest);
    const uint64_t block_time =
        std::max({now, chain_.last_block_time_ms + 1,
                  parent != nullptr ? parent->timestamp_hint + 1 : uint64_t{0}});
    if (block_time > now + constants::kStorageBlockClockSkewMs) {
        return std::nullopt;
    }
    const EpochId epoch = driver_.current_epoch().value_or(EpochId{});
    std::optional<StorageRecord> record;
    if (chain_.pending.has_value()) {
        if (const auto complete = complete_confirmations()) {
            if (auto plan = make_storage_final(chain_, complete->first, complete->second, epoch,
                                               block_time)) {
                record = std::move(*plan);
            }
        }
    }
    if (!record.has_value()) {
        if (auto selection = derive_storage_selection(config_.network_id, chain_,
                                                      derivation_snapshot(), silent_holders(),
                                                      block_time)) {
            record = std::move(*selection);
        }
    }
    if (!record.has_value() && !claim_pool_.empty()) {
        // Claims that no longer pass (superseded, or naming an S that is no
        // longer live) leave the pool; their senders re-send current ones.
        std::erase_if(claim_pool_, [this, block_time](const auto& entry) {
            return !check_storage_wrap_claim(chain_, config_.network_id, entry.second,
                                             block_time);
        });
        if (auto batch =
                make_storage_wrap_batch(config_.network_id, chain_, claim_pool_, block_time)) {
            record = std::move(*batch);
        }
    }
    if (!record.has_value() || storage_record_kind(*record) != kind) {
        return std::nullopt;
    }
    ProposedPayload out;
    out.payload = storage_record_payload(*record);
    if (out.payload.body.empty()) {
        return std::nullopt;
    }
    out.previous_state_root = chain_.head;
    out.proposed_state_root = storage_record_digest(*record);
    out.timestamp_hint = block_time;
    return out;
}

bool StorageKeyService::validate(const HotStuffService& consensus, const Proposal& proposal,
                                 const BlockPayload& payload) {
    if (!healthy_ || !config_.wall_clock_ms) {
        return false;
    }
    const auto record = storage_record_from_payload(payload);
    if (!record.has_value() || record_network(*record) != config_.network_id) {
        spdlog::debug("[storage] vote withheld: the storage record does not decode");
        return false;
    }
    if (uncommitted_storage_ancestor(consensus, proposal.parent_digest)) {
        spdlog::debug("[storage] vote withheld: an earlier storage block is not committed");
        return false;
    }
    const uint64_t now = config_.wall_clock_ms();
    const uint64_t block_time = proposal.timestamp_hint;
    if (block_time != storage_record_block_time(*record) ||
        block_time > now + constants::kStorageBlockClockSkewMs ||
        block_time + constants::kStorageBlockClockSkewMs < now ||
        block_time <= chain_.last_block_time_ms) {
        spdlog::debug("[storage] vote withheld: block time {} is not binding here (clock {})",
                      block_time, now);
        return false;
    }
    if (const Proposal* parent = consensus.block(proposal.parent_digest);
        parent != nullptr && block_time <= parent->timestamp_hint) {
        return false;
    }
    if (proposal.previous_state_root != chain_.head ||
        proposal.proposed_state_root != storage_record_digest(*record)) {
        spdlog::debug("[storage] vote withheld: the record does not extend this node's chain");
        return false;
    }
    if (const auto* batch = std::get_if<StorageWrapBatch>(&*record)) {
        const auto failure = check_storage_wrap_batch(chain_, *batch);
        if (failure != StorageWrapFailure::None) {
            spdlog::debug("[storage] vote withheld: wrap batch refused ({})",
                          static_cast<uint16_t>(failure));
            return false;
        }
        return true;
    }
    if (const auto* selection = std::get_if<StorageSelection>(&*record)) {
        const auto expected = derive_storage_selection(
            config_.network_id, chain_, derivation_snapshot(), silent_holders(), block_time);
        if (!expected.has_value() ||
            encode_storage_record(StorageRecord{*expected}) != payload.body) {
            spdlog::debug("[storage] vote withheld: selection {} is not the one this node "
                          "derives",
                          selection->sequence);
            return false;
        }
        return true;
    }
    const auto failure =
        check_storage_final(chain_, std::get<StorageFinalPlan>(*record), proposal.epoch);
    if (failure != StorageFinalFailure::None) {
        spdlog::debug("[storage] vote withheld: final plan refused ({})",
                      static_cast<uint16_t>(failure));
        return false;
    }
    return true;
}

void StorageKeyService::on_committed(const CommittedPayload& committed) {
    if (!healthy_ || committed.payload == nullptr) {
        return;
    }
    const auto record = storage_record_from_payload(*committed.payload);
    if (!record.has_value()) {
        return;
    }
    std::optional<StoragePlanProofMsg> proof;
    if (committed.proof.has_value()) {
        proof = StoragePlanProofMsg{*committed.payload, *committed.proof};
    }
    const Digest digest = storage_record_digest(*record);
    apply_record(*record, std::move(proof), true);
    // The finalized record travels to every server with its proof, so holders
    // and requesters outside Tier 1 verify it themselves.
    broadcast_proof(digest);
}

// --- Sessions -------------------------------------------------------------------

void StorageKeyService::open_session() {
    session_.reset();
    if (!chain_.pending.has_value()) {
        prune_shares();
        return;
    }
    auto session = std::make_unique<Session>();
    session->selection = *chain_.pending;
    session->id = chain_.pending_digest;
    if (const StorageHolder* own = session->holder_of(config_.self)) {
        session->self = *own;
    }
    session_ = std::move(session);
    prune_shares();
}

void StorageKeyService::start_round1(Session& session) {
    const auto n = static_cast<uint16_t>(session.selection.holders.size());
    const uint16_t own = session.self->holder_id;
    std::vector<uint8_t> package;
    switch (session.selection.operation) {
        case StorageOperation::Create: {
            auto round = crypto::StorageThreshold::dkg_part1(own, n);
            if (round.ok()) {
                package = round.value->package();
                session.dkg1 = std::move(*round.value);
            }
            break;
        }
        case StorageOperation::Rotate: {
            auto round = crypto::StorageThreshold::dkg_rotation_part1(own, n);
            if (round.ok()) {
                package = round.value->package();
                session.dkg1 = std::move(*round.value);
            }
            break;
        }
        case StorageOperation::Refresh: {
            const auto* current = share_for(session.selection.base_plan);
            if (current == nullptr || session.selection.base_plan != chain_.current_digest) {
                spdlog::warn("[storage] no share for the plan this refresh starts from; this "
                             "holder cannot contribute");
                break;
            }
            auto round = crypto::StorageThreshold::refresh_part1(*current, n);
            if (round.ok()) {
                package = round.value->package();
                session.refresh1 = std::move(*round.value);
            }
            break;
        }
    }
    if (package.empty()) {
        session.phase = Session::Phase::Failed;
        return;
    }
    session.own_round1 = std::move(package);
    session.phase = Session::Phase::Round1;
    session.spoke.insert(config_.self);
    StorageKeyPackageMsg message;
    message.session = session.id;
    message.sender = config_.self;
    message.round = StorageRound::Round1;
    message.payload = session.own_round1;
    broadcast_package(message);
    session.resend.mark(now_ms_);
    maybe_round2(session);
}

void StorageKeyService::on_package(const StorageKeyPackageMsg& package) {
    if (session_ == nullptr || package.session != session_->id) {
        drop(StorageDrop::UnknownSession);
        return;
    }
    Session& session = *session_;
    const StorageHolder* sender = session.holder_of(package.sender);
    if (sender == nullptr || package.sender == config_.self || package.payload.empty()) {
        drop(StorageDrop::NotAHolder);
        return;
    }
    switch (package.round) {
        case StorageRound::Round1: {
            if (package.recipient != NodeId{}) {
                drop(StorageDrop::WrongRound);
                return;
            }
            const auto accepted = session.round1.accept(sender->holder_id, package.payload, false);
            if (accepted == RoundAccept::Equivocation) {
                drop(StorageDrop::Equivocation);
                return;
            }
            session.spoke.insert(package.sender);
            if (accepted == RoundAccept::Accepted) {
                maybe_round2(session);
            }
            return;
        }
        case StorageRound::Round2: {
            if (!session.self.has_value() || package.recipient != config_.self ||
                session.phase == Session::Phase::Observing ||
                session.phase == Session::Phase::Failed) {
                drop(StorageDrop::WrongRound);
                return;
            }
            const bool early = session.phase == Session::Phase::Round1;
            const auto accepted = session.round2.accept(sender->holder_id, package.payload, early);
            if (accepted == RoundAccept::Equivocation) {
                drop(StorageDrop::Equivocation);
                return;
            }
            if (accepted == RoundAccept::Accepted) {
                maybe_finish(session);
            }
            return;
        }
        case StorageRound::Confirm:
            on_confirm(session, package, *sender);
            return;
    }
}

void StorageKeyService::maybe_round2(Session& session) {
    if (session.phase != Session::Phase::Round1 || session.round1.size() != session.others()) {
        return;
    }
    crypto::StoragePeerBytesMap round1 = session.round1.messages();
    crypto::StoragePeerBytesMap outgoing;
    if (session.dkg1.has_value()) {
        auto next = crypto::StorageThreshold::dkg_part2(std::move(*session.dkg1), round1);
        session.dkg1.reset();
        if (next.ok()) {
            outgoing = next.value->packages_for_recipients();
            session.dkg2 = std::move(*next.value);
        }
    } else if (session.refresh1.has_value()) {
        auto next = crypto::StorageThreshold::refresh_part2(std::move(*session.refresh1), round1);
        session.refresh1.reset();
        if (next.ok()) {
            outgoing = next.value->packages_for_recipients();
            session.refresh2 = std::move(*next.value);
        }
    }
    if (outgoing.size() != session.others()) {
        wipe(outgoing);
        spdlog::warn("[storage] session {} failed in round 2", short_hex(session.id));
        session.phase = Session::Phase::Failed;
        return;
    }
    const uint16_t own = session.self->holder_id;
    for (auto& [recipient_id, bytes] : outgoing) {
        const StorageHolder* recipient = session.holder_by_id(recipient_id);
        if (recipient == nullptr) {
            session.phase = Session::Phase::Failed;
            break;
        }
        const Digest binding =
            storage_pairwise_binding(config_.network_id, session.id, own, recipient_id);
        auto sealed = sealer_.seal_bound_for(recipient->node, binding, bytes);
        if (!sealed.has_value()) {
            session.phase = Session::Phase::Failed;
            break;
        }
        session.own_round2.emplace(recipient_id, std::move(*sealed));
    }
    wipe(outgoing);
    if (session.phase == Session::Phase::Failed) {
        session.own_round2.clear();
        return;
    }
    session.phase = Session::Phase::Round2;
    session.round2.release_early();
    send_round2(session);
    maybe_finish(session);
}

void StorageKeyService::send_round2(const Session& session) {
    const EpochId epoch = current_epoch();
    for (const auto& [recipient_id, sealed] : session.own_round2) {
        const StorageHolder* recipient = session.holder_by_id(recipient_id);
        if (recipient == nullptr) {
            continue;
        }
        StorageKeyPackageMsg message;
        message.session = session.id;
        message.sender = config_.self;
        message.round = StorageRound::Round2;
        message.recipient = recipient->node;
        message.payload = sealed;
        (void)router_.send(recipient->node,
                           router_.compose(SecurityMessageKind::StorageKeyPackage, message, epoch));
    }
}

void StorageKeyService::maybe_finish(Session& session) {
    if (session.phase != Session::Phase::Round2 || session.round2.size() != session.others()) {
        return;
    }
    const uint16_t own = session.self->holder_id;
    crypto::StoragePeerBytesMap round2;
    for (const auto& [sender_id, sealed] : session.round2.messages()) {
        const Digest binding =
            storage_pairwise_binding(config_.network_id, session.id, sender_id, own);
        auto opened = sealer_.unseal_bound(binding, sealed);
        if (!opened.has_value()) {
            wipe(round2);
            spdlog::warn("[storage] session {}: a round-2 package from holder {} does not open",
                         short_hex(session.id), sender_id);
            session.phase = Session::Phase::Failed;
            return;
        }
        round2.emplace(sender_id, std::move(*opened));
    }
    const crypto::StoragePeerBytesMap round1 = session.round1.messages();
    std::optional<crypto::StorageKeyOutcome> outcome;
    if (session.dkg2.has_value()) {
        auto result =
            crypto::StorageThreshold::dkg_part3(std::move(*session.dkg2), round1, round2);
        session.dkg2.reset();
        if (result.ok()) outcome = std::move(*result.value);
    } else if (session.refresh2.has_value()) {
        const auto* current = share_for(session.selection.base_plan);
        if (current != nullptr && chain_.current.has_value()) {
            auto result = crypto::StorageThreshold::refresh_part3(
                std::move(*session.refresh2), round1, round2, *current, chain_.current->key_plan);
            if (result.ok()) outcome = std::move(*result.value);
        }
        session.refresh2.reset();
    }
    wipe(round2);
    if (!outcome.has_value()) {
        spdlog::warn("[storage] session {} failed in round 3", short_hex(session.id));
        session.phase = Session::Phase::Failed;
        return;
    }
    // The plan must be exactly the selected one before this holder vouches
    // for it.
    const auto info = crypto::StorageThreshold::validate_plan(outcome->plan);
    std::vector<uint16_t> ids;
    for (const auto& holder : session.selection.holders) ids.push_back(holder.holder_id);
    const bool refresh = session.selection.operation == StorageOperation::Refresh;
    if (!info.ok() || info.value->threshold != session.selection.threshold ||
        info.value->holders != ids ||
        (refresh && (!chain_.current.has_value() ||
                     outcome->storage_public_key != chain_.current->storage_public_key))) {
        spdlog::warn("[storage] session {} produced a plan that does not match its selection",
                     short_hex(session.id));
        session.phase = Session::Phase::Failed;
        return;
    }
    shares_.insert_or_assign(session.id, std::move(outcome->share));
    if (!persist_shares()) {
        // A share this holder cannot keep must not be vouched for.
        shares_.erase(session.id);
        session.phase = Session::Phase::Failed;
        return;
    }
    const Digest digest =
        storage_confirmation_digest(config_.network_id, session.id, outcome->plan, *session.self);
    crypto_sign_detached(session.own_confirmation.data(), nullptr, digest.data(), digest.size(),
                         config_.identity.private_key.data());
    session.own_plan = outcome->plan;
    session.phase = Session::Phase::Confirmed;

    Digest plan_digest{};
    crypto_hash_sha256(plan_digest.data(), session.own_plan.data(), session.own_plan.size());
    auto& entry = session.confirmations[plan_digest];
    entry.first = session.own_plan;
    entry.second[config_.self] = session.own_confirmation;
    session.confirmed_plan[config_.self] = plan_digest;

    StorageKeyPackageMsg message;
    message.session = session.id;
    message.sender = config_.self;
    message.round = StorageRound::Confirm;
    message.payload = session.own_plan;
    message.signature = session.own_confirmation;
    broadcast_package(message);
}

void StorageKeyService::on_confirm(Session& session, const StorageKeyPackageMsg& package,
                                   const StorageHolder& sender) {
    if (package.recipient != NodeId{} || package.payload.size() > constants::kMaxStoragePlanBytes) {
        drop(StorageDrop::WrongRound);
        return;
    }
    const Digest digest =
        storage_confirmation_digest(config_.network_id, session.id, package.payload, sender);
    if (crypto_sign_verify_detached(package.signature.data(), digest.data(), digest.size(),
                                    sender.node.bytes.data()) != 0) {
        drop(StorageDrop::BadSignature);
        return;
    }
    Digest plan_digest{};
    crypto_hash_sha256(plan_digest.data(), package.payload.data(), package.payload.size());
    const auto previous = session.confirmed_plan.find(sender.node);
    if (previous != session.confirmed_plan.end()) {
        if (previous->second != plan_digest) {
            // Two plans from one holder: neither counts toward a final plan.
            drop(StorageDrop::Equivocation);
        }
        return;
    }
    session.confirmed_plan.emplace(sender.node, plan_digest);
    auto& entry = session.confirmations[plan_digest];
    if (entry.first.empty()) {
        entry.first = package.payload;
    }
    entry.second.emplace(sender.node, package.signature);
}

std::optional<std::pair<std::vector<uint8_t>, std::map<NodeId, crypto::Ed25519Signature>>>
StorageKeyService::complete_confirmations() const {
    if (session_ == nullptr || session_->id != chain_.pending_digest) {
        return std::nullopt;
    }
    for (const auto& [digest, entry] : session_->confirmations) {
        if (entry.second.size() == session_->selection.holders.size()) {
            return entry;
        }
    }
    return std::nullopt;
}

void StorageKeyService::broadcast_package(const StorageKeyPackageMsg& package) {
    (void)router_.broadcast(
        router_.compose(SecurityMessageKind::StorageKeyPackage, package, current_epoch()));
}

void StorageKeyService::resend(uint64_t now_ms) {
    if (session_ == nullptr || !session_->self.has_value()) {
        return;
    }
    Session& session = *session_;
    if (session.phase == Session::Phase::Observing || session.phase == Session::Phase::Failed ||
        !session.resend.due(now_ms)) {
        return;
    }
    StorageKeyPackageMsg round1;
    round1.session = session.id;
    round1.sender = config_.self;
    round1.round = StorageRound::Round1;
    round1.payload = session.own_round1;
    broadcast_package(round1);
    if (session.phase == Session::Phase::Round2 || session.phase == Session::Phase::Confirmed) {
        send_round2(session);
    }
    if (session.phase == Session::Phase::Confirmed) {
        StorageKeyPackageMsg confirm;
        confirm.session = session.id;
        confirm.sender = config_.self;
        confirm.round = StorageRound::Confirm;
        confirm.payload = session.own_plan;
        confirm.signature = session.own_confirmation;
        broadcast_package(confirm);
    }
}

// --- Shares ---------------------------------------------------------------------

const crypto::StorageKeyShare* StorageKeyService::share_for(const Digest& plan_digest) const {
    const auto it = shares_.find(plan_digest);
    return it == shares_.end() ? nullptr : &it->second;
}

bool StorageKeyService::holds_share(const Digest& plan_digest) const {
    return share_for(plan_digest) != nullptr;
}

void StorageKeyService::adopt_session_share(const Digest& session_id, const Digest& plan_digest) {
    auto it = shares_.find(session_id);
    if (it == shares_.end()) {
        return;
    }
    crypto::StorageKeyShare share = std::move(it->second);
    shares_.erase(it);
    shares_.insert_or_assign(plan_digest, std::move(share));
    if (!persist_shares()) {
        spdlog::warn("[storage] the share for the finalized plan could not be resealed");
    }
}

void StorageKeyService::prune_shares() {
    // Never against an unbound or empty chain: lost or foreign records would
    // otherwise destroy a share that a live plan still needs.
    if (!chain_bound_ || !chain_.current.has_value()) {
        return;
    }
    std::set<Digest> keep{chain_.current_digest};
    if (retiring_live()) {
        keep.insert(chain_.retiring_digest);
    }
    if (session_ != nullptr) {
        keep.insert(session_->id);
    }
    // A removed share's handle zeroizes on destruction.
    const std::size_t before = shares_.size();
    std::erase_if(shares_, [&keep](const auto& entry) { return !keep.contains(entry.first); });
    if (shares_.size() != before) {
        if (!persist_shares()) {
            spdlog::warn("[storage] the storage shares could not be resealed after a prune");
        }
    }
}

bool StorageKeyService::persist_shares() {
    if (shares_.empty()) {
        return share_store_.remove(kStorageShareDomain);
    }
    StorageShareBundle bundle;
    for (const auto& [digest, share] : shares_) {
        auto bytes = crypto::StorageThreshold::serialize_share(share);
        if (!bytes.ok()) {
            return false;
        }
        bundle.emplace(digest, std::move(*bytes.value));
    }
    const auto encoded = encode_share_bundle(bundle);
    if (encoded.empty()) {
        return false;
    }
    return share_store_.seal(kStorageShareDomain, encoded.span()) == ShareStoreStatus::Ok;
}

bool StorageKeyService::load_shares() {
    auto unsealed = share_store_.unseal(kStorageShareDomain);
    if (unsealed.status == ShareStoreStatus::Missing) {
        return true;
    }
    if (unsealed.status != ShareStoreStatus::Ok) {
        return false;
    }
    auto bundle = decode_share_bundle(unsealed.plaintext.span());
    if (!bundle.has_value()) {
        return false;
    }
    for (auto& [digest, bytes] : *bundle) {
        auto share = crypto::StorageThreshold::deserialize_share(bytes.span());
        if (!share.ok()) {
            return false;
        }
        shares_.insert_or_assign(digest, std::move(*share.value));
    }
    return true;
}

// --- Unlock, holder side ------------------------------------------------------------

crypto::StorageUnlockContext StorageKeyService::unlock_context(
    const NetworkId& network_id, const StorageUnlockRequestMsg& request) {
    crypto::StorageUnlockContext context;
    context.network_id = network_id;
    context.epoch = request.epoch.underlying();
    context.plan_digest = request.plan_digest;
    context.request_nonce = request.nonce;
    return context;
}

const StorageFinalPlan* StorageKeyService::live_plan(const Digest& plan_digest) const {
    if (plan_digest == Digest{}) {
        return nullptr;
    }
    if (chain_.current.has_value() && plan_digest == chain_.current_digest) {
        return &*chain_.current;
    }
    if (retiring_live() && plan_digest == chain_.retiring_digest) {
        return &*chain_.retiring;
    }
    return nullptr;
}

std::optional<crypto::StoragePartial> StorageKeyService::own_partial(
    const StorageFinalPlan& plan, const Digest& plan_digest,
    const StorageUnlockRequestMsg& request) const {
    const auto* share = share_for(plan_digest);
    if (share == nullptr) {
        return std::nullopt;
    }
    auto partial = crypto::StorageThreshold::create_partial(
        *share, plan.key_plan, unlock_context(config_.network_id, request),
        request.ephemeral_point);
    if (!partial.ok()) {
        return std::nullopt;
    }
    return *partial.value;
}

void StorageKeyService::send_unlock_request(const NodeId& holder,
                                            const StorageUnlockRequestMsg& request) {
    (void)router_.send(holder, router_.compose(SecurityMessageKind::StorageUnlockRequest, request,
                                               request.epoch));
}

void StorageKeyService::submit_wrap_claim(const StorageWrapClaim& claim) {
    const EpochId epoch = current_epoch();
    for (const auto& member : tier1_members()) {
        if (member == config_.self) {
            on_wrap_claim(claim);
            continue;
        }
        (void)router_.send(member,
                           router_.compose(SecurityMessageKind::StorageWrapClaim, claim, epoch));
    }
}

void StorageKeyService::on_wrap_claim(const StorageWrapClaimMsg& claim) {
    // Only a Tier 1 member proposes wrap batches.
    if (!driver_.is_tier1_member() || !config_.wall_clock_ms) {
        return;
    }
    const uint64_t block_time = std::max(config_.wall_clock_ms(), chain_.last_block_time_ms + 1);
    if (!check_storage_wrap_claim(chain_, config_.network_id, claim, block_time)) {
        drop(StorageDrop::ClaimInvalid);
        return;
    }
    const auto it = claim_pool_.find(claim.node);
    if (it != claim_pool_.end() && it->second.counter >= claim.counter) {
        return;
    }
    if (it == claim_pool_.end() && claim_pool_.size() >= constants::kStorageMaxWrapOwners) {
        drop(StorageDrop::BudgetExceeded);
        return;
    }
    claim_pool_.insert_or_assign(claim.node, claim);
}

void StorageKeyService::on_unlock_request(const StorageUnlockRequestMsg& request) {
    if (request.requester == config_.self) {
        return;
    }
    const EpochId epoch = current_epoch();
    if (epoch == EpochId{} || request.epoch != epoch) {
        drop(StorageDrop::EpochMismatch);
        return;
    }
    const StorageFinalPlan* plan = live_plan(request.plan_digest);
    if (plan == nullptr) {
        // Not the current plan, and not the retiring plan inside its grace
        // period: an old S unwraps nothing here.
        drop(StorageDrop::UnknownPlan);
        return;
    }
    if (share_for(request.plan_digest) == nullptr) {
        drop(StorageDrop::NoShare);
        return;
    }
    // R must be one the requester's latest finalized claim names for this S.
    // An R that belongs to another server, or that nobody claimed, earns
    // nothing: s_i*R for another server's R would open that server's data key.
    if (!storage_wrap_claimed(chain_, request.requester,
                              StorageWrapRef{plan->storage_public_key, request.ephemeral_point})) {
        drop(StorageDrop::UnclaimedWrap);
        return;
    }
    const Digest request_digest = storage_unlock_request_digest(config_.network_id, request);
    if (seen_requests_.contains(request_digest)) {
        drop(StorageDrop::Replay);
        return;
    }
    if (const auto pending = pending_unlocks_.find(request.requester);
        pending != pending_unlocks_.end() && now_ms_ < pending->second.expires_ms) {
        drop(StorageDrop::PendingBusy);
        return;
    }
    auto& count = unlock_counts_[{epoch, request.requester}];
    if (count >= constants::kStorageUnlocksPerRequesterPerEpoch ||
        pending_unlocks_.size() >= constants::kStorageMaxPendingUnlocks ||
        seen_requests_.size() >= constants::kStorageMaxRememberedRequests) {
        // A full replay set refuses rather than forgets: forgetting would
        // reopen replays.
        drop(StorageDrop::BudgetExceeded);
        return;
    }
    const Digest context = storage_unlock_attestation_context(config_.network_id, epoch,
                                                              request.plan_digest, request_digest);
    const auto challenge = runtime_.attestation().create_challenge(
        request.requester, request.requester.bytes, IncarnationId(1), epoch,
        AttestationPurpose::StorageUnlock, context);
    if (!challenge.has_value()) {
        drop(StorageDrop::BudgetExceeded);
        return;
    }
    seen_requests_.insert(request_digest);
    ++count;
    pending_unlocks_.insert_or_assign(
        request.requester,
        PendingUnlock{request, request_digest, context,
                      now_ms_ + constants::kStorageUnlockPendingMs});
    (void)router_.send(request.requester,
                       router_.compose(SecurityMessageKind::AttestationChallenge, *challenge,
                                       epoch));
}

void StorageKeyService::on_verdict(const AttestationVerdict& verdict) {
    if (!healthy_ || verdict.purpose != AttestationPurpose::StorageUnlock) {
        return;
    }
    const auto it = pending_unlocks_.find(verdict.node_id);
    if (it == pending_unlocks_.end() || it->second.context != verdict.context_digest ||
        verdict.epoch != it->second.request.epoch) {
        return;
    }
    const PendingUnlock pending = it->second;
    pending_unlocks_.erase(it);
    // Fail closed: only a passing verdict that proved every platform claim of
    // the approved profile earns a partial.
    const bool approved = verdict.passed && verdict.failure == AttestationFailure::None &&
                          verdict.evidence_digest != Digest{} &&
                          platform_claims_are_consistent(verdict.claims) &&
                          all_platform_claims_proved(verdict.claims) &&
                          verdict.claims.profile_id == kTier1AttestationProfileId &&
                          verdict.claims.profile_ruleset == kAttestationProfileRulesetVersion;
    if (!approved) {
        drop(StorageDrop::AttestationFailed);
        return;
    }
    const StorageFinalPlan* plan = live_plan(pending.request.plan_digest);
    if (plan == nullptr) {
        drop(StorageDrop::UnknownPlan);
        return;
    }
    if (!storage_wrap_claimed(chain_, pending.request.requester,
                              StorageWrapRef{plan->storage_public_key,
                                             pending.request.ephemeral_point})) {
        drop(StorageDrop::UnclaimedWrap);
        return;
    }
    const auto own = std::find_if(plan->holders.begin(), plan->holders.end(),
                                  [this](const StorageHolder& h) { return h.node == config_.self; });
    const auto partial = own_partial(*plan, pending.request.plan_digest, pending.request);
    if (own == plan->holders.end() || !partial.has_value()) {
        drop(StorageDrop::NoShare);
        return;
    }
    auto sealed = sealer_.seal_bound_for(pending.request.requester, pending.request_digest,
                                         std::span<const uint8_t>(*partial));
    if (!sealed.has_value()) {
        return;
    }
    StorageUnlockPartialMsg message;
    message.holder = config_.self;
    message.request_digest = pending.request_digest;
    message.holder_id = own->holder_id;
    message.sealed_partial = std::move(*sealed);
    ++partials_sent_;
    (void)router_.send(pending.request.requester,
                       router_.compose(SecurityMessageKind::StorageUnlockPartial, message,
                                       pending.request.epoch));
}

void StorageKeyService::on_unlock_partial(const StorageUnlockPartialMsg& partial) {
    data_keys_->on_partial(partial);
}

}  // namespace nexus::security
