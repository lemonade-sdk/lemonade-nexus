#include <LemonadeNexus/Security/Lifecycle/SecurityDriver.hpp>

#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <sodium.h>
#include <spdlog/spdlog.h>

#include <algorithm>

namespace nexus::security {

namespace {

[[nodiscard]] const char* phase_name(DriverPhase p) {
    switch (p) {
        case DriverPhase::Failed:            return "Failed";
        case DriverPhase::Idle:              return "Idle";
        case DriverPhase::GenesisCollecting: return "GenesisCollecting";
        case DriverPhase::GenesisEligibility: return "GenesisEligibility";
        case DriverPhase::FoundingDkg:       return "FoundingDkg";
        case DriverPhase::AwaitingBootstrap: return "AwaitingBootstrap";
        case DriverPhase::Syncing:           return "Syncing";
        case DriverPhase::Active:            return "Active";
    }
    return "?";
}

[[nodiscard]] std::size_t sync_responses_needed(std::size_t members) {
    // One honest answer is enough to raise the floor; f + 1 distinct answers
    // guarantee one honest responder.
    const std::size_t needed = constants::max_byzantine_faults(members) + 1;
    const std::size_t reachable = members > 1 ? members - 1 : 1;
    return std::min(needed, reachable);
}

}  // namespace

SecurityDriver::SecurityDriver(SecurityDriverConfig config, SecurityRuntime& runtime,
                               SecurityRouter& router, EpochStore& store, GenesisService* genesis)
    : config_(std::move(config)),
      runtime_(runtime),
      router_(router),
      store_(store),
      genesis_(genesis),
      eligibility_(derive_network_id(config_.genesis_public_key,
                                     constants::kSecurityRulesetVersion,
                                     constants::kConsensusRulesetVersion),
                   config_.self, config_.identity, store.directory() / "eligibility") {
    eligibility_.set_certificate_source(config_.certificate_source);
}

bool SecurityDriver::genesis_node() const {
    return config_.identity.public_key == config_.genesis_public_key;
}

void SecurityDriver::set_phase(DriverPhase next, const char* reason) {
    if (phase_ == next) {
        return;
    }
    if (next == DriverPhase::Failed) {
        spdlog::warn("[security] phase {} -> {}: {}", phase_name(phase_), phase_name(next),
                     reason);
    } else {
        spdlog::info("[security] phase {} -> {}: {}", phase_name(phase_), phase_name(next),
                     reason);
    }
    phase_ = next;
}

NodeId SecurityDriver::genesis_id() const {
    NodeId id;
    id.bytes = config_.genesis_public_key;
    return id;
}

bool SecurityDriver::is_tier1_member() const {
    const EpochManager* epochs = runtime_.epochs();
    return epochs != nullptr && epochs->current().tier1_members.contains(config_.self);
}

std::optional<EpochId> SecurityDriver::current_epoch() const {
    const EpochManager* epochs = runtime_.epochs();
    if (epochs == nullptr) {
        return std::nullopt;
    }
    return epochs->current().id;
}

// --- Lifecycle ---------------------------------------------------------------

void SecurityDriver::start(uint64_t now_ms) {
    now_ms_ = now_ms;

    auto bootstrap = store_.load_bootstrap();
    auto epoch = store_.load_epoch();
    const auto corrupt = [](const auto& loaded) {
        const auto* result = std::get_if<EpochLoadResult>(&loaded);
        return result != nullptr && *result == EpochLoadResult::Corrupt;
    };
    // Corrupt durable state can hide an epoch this node already acted in.
    // Never continue as if fresh.
    if (corrupt(bootstrap) || corrupt(epoch)) {
        set_phase(DriverPhase::Failed, "durable security state is corrupt");
        return;
    }

    if (auto* stored = std::get_if<StoredEpoch>(&epoch)) {
        const EpochId id = stored->state.id;
        const bool member = stored->state.tier1_members.contains(config_.self);
        auto vote_key = store_.load_vote_key(id, config_.self);
        if (vote_key.has_value()) {
            vote_pubs_mine_[id] = vote_key->public_key;
        }
        if (!runtime_.restore_epoch(std::move(*stored), std::move(vote_key))) {
            set_phase(DriverPhase::Failed, "durable epoch state did not restore");
            return;
        }
        // Observations come back so the node can keep contributing, but the
        // finality that made them authoritative does not: it has to be reached
        // again through the mesh. That is what stops a rolled-back snapshot
        // from selecting the next epoch off its own disk.
        if (!enter_eligibility_epoch(id, runtime_.epochs()->current().tier1_members)) {
            set_phase(DriverPhase::Failed, "durable eligibility state is corrupt");
            return;
        }
        epoch_started_ms_ = now_ms;
        last_progress_ms_ = now_ms;
        if (member && runtime_.consensus() != nullptr && !runtime_.consensus()->synced()) {
            begin_sync(now_ms);
        } else {
            set_phase(DriverPhase::Active, "restored durable epoch");
        }
        return;
    }

    if (genesis_node() && genesis_ != nullptr) {
        set_phase(DriverPhase::GenesisCollecting, "this identity is the genesis anchor");
    } else {
        set_phase(DriverPhase::Idle, "no durable epoch; awaiting the mesh");
    }
}

bool SecurityDriver::enter_eligibility_epoch(EpochId epoch, const Tier1Set& members) {
    return eligibility_.enter_epoch(epoch, members.members()) != EligibilityRestore::Corrupt;
}

bool SecurityDriver::epoch_aged(uint64_t now_ms) const {
    return now_ms - epoch_started_ms_ >= constants::kTargetEpochSeconds * 1000;
}

void SecurityDriver::publish(const EligibilityObservation& observation, EpochId epoch) {
    (void)router_.broadcast(
        router_.compose(SecurityMessageKind::EligibilityObservation, observation, epoch));
}

void SecurityDriver::on_peer(const NodeId& peer, uint64_t now_ms) {
    now_ms_ = now_ms;
    if (phase_ == DriverPhase::GenesisCollecting && genesis_ != nullptr &&
        !genesis_->finalized()) {
        (void)genesis_->admit_candidate(peer);
        issue_genesis_challenge(peer);
    }
}

void SecurityDriver::issue_genesis_challenge(const NodeId& peer) {
    crypto::Ed25519PublicKey peer_key{};
    peer_key = peer.bytes;
    auto challenge = runtime_.attestation().create_challenge(peer, peer_key, 1, 1);
    if (!challenge.has_value()) {
        return;  // The attestation budget for this identity is spent.
    }
    spdlog::debug("[security] genesis challenge -> {}",
                  crypto::to_hex(std::span<const uint8_t>(peer.bytes.data(), 8)));
    (void)router_.send(peer,
                       router_.compose(SecurityMessageKind::AttestationChallenge, *challenge, 1));
}

void SecurityDriver::tick(uint64_t now_ms) {
    now_ms_ = now_ms;
    if (phase_ == DriverPhase::Failed) {
        return;
    }

    if (phase_ == DriverPhase::Syncing) {
        const bool window_over = now_ms - sync_started_ms_ >= config_.sync_window_ms;
        if (any_sync_response_ && window_over) {
            finish_sync();
        } else if (window_over) {
            // Nobody answered: ask again. Voting stays blocked until a
            // certified floor exists.
            sync_started_ms_ = now_ms;
            const EpochId epoch = current_epoch().value_or(0);
            (void)router_.broadcast(
                router_.compose(SecurityMessageKind::SyncRequest, SyncRequest{epoch}, epoch));
        }
        return;
    }

    HotStuffService* consensus = runtime_.consensus();
    if (phase_ == DriverPhase::Active && consensus != nullptr && consensus->synced()) {
        if (last_progress_ms_ == 0) {
            last_progress_ms_ = now_ms;
        }
        if (now_ms - last_progress_ms_ >=
            static_cast<uint64_t>(pacemaker_.timeout().count())) {
            const TimeoutVote timeout = consensus->make_timeout_vote();
            const EpochId epoch = current_epoch().value_or(0);
            auto message = router_.compose(SecurityMessageKind::HotStuffTimeout, timeout, epoch);
            (void)router_.broadcast(message);
            (void)router_.deliver_local(std::move(message));
            pacemaker_.on_timeout();
            last_progress_ms_ = now_ms;
        }
        maybe_propose(consensus->current_view());
    }

    if (phase_ == DriverPhase::Active && runtime_.epochs() != nullptr &&
        runtime_.epochs()->current().tier1_members.contains(config_.self)) {
        drain_objective_faults();
        run_epoch_cadence(now_ms);
    }
}

// --- Sync --------------------------------------------------------------------

void SecurityDriver::begin_sync(uint64_t now_ms) {
    set_phase(DriverPhase::Syncing, "member with unsynced chain; requesting the certified floor");
    sync_started_ms_ = now_ms;
    best_synced_view_ = 0;
    any_sync_response_ = false;
    sync_sources_.clear();
    const EpochId epoch = current_epoch().value_or(0);
    (void)router_.broadcast(
        router_.compose(SecurityMessageKind::SyncRequest, SyncRequest{epoch}, epoch));
}

void SecurityDriver::on_sync_certificate(const QuorumCertificate& certificate,
                                         const NodeId& from) {
    if (phase_ != DriverPhase::Syncing) {
        return;
    }
    any_sync_response_ = true;
    best_synced_view_ = std::max(best_synced_view_, certificate.view);
    sync_sources_.insert(from);
    const std::size_t members = runtime_.epochs()->current().tier1_members.size();
    if (sync_sources_.size() >= sync_responses_needed(members)) {
        finish_sync();
    }
}

void SecurityDriver::finish_sync() {
    HotStuffService* consensus = runtime_.consensus();
    if (consensus != nullptr) {
        consensus->sync_to_certified(best_synced_view_);
    }
    set_phase(DriverPhase::Active, "synced to the certified floor");
    epoch_started_ms_ = now_ms_;
    last_progress_ms_ = now_ms_;
}

// --- Genesis bootstrap -------------------------------------------------------

Digest SecurityDriver::genesis_attestation_root(const Tier1Set& founders) const {
    CanonicalEncoder encoder("lemonade-nexus/attestation-root:v1");
    encoder.add_u64(founders.size());
    for (const auto& node : founders.members()) {
        encoder.add_bytes(node.bytes);
        encoder.add_bytes(founder_evidence_digests_.at(node));
    }
    return encoder.digest();
}

void SecurityDriver::send_founding() {
    const auto founders = genesis_->founding_set();
    if (!founders.has_value()) {
        return;
    }
    GenesisFounding founding;
    founding.epoch = 1;
    for (const auto& node : founders->members()) {
        founding.members.emplace_back(node, founder_vote_keys_.at(node));
    }
    founding.attestation_root = genesis_attestation_root(*founders);
    spdlog::info("[security] genesis founding: {} attested founders", founders->size());
    for (const auto& node : founders->members()) {
        (void)router_.send(node,
                           router_.compose(SecurityMessageKind::GenesisFounding, founding, 1));
    }
    founding_sent_ = true;
}

void SecurityDriver::on_genesis_founding(const GenesisFounding& founding, const NodeId& from) {
    if (from != genesis_id() || phase_ != DriverPhase::Idle || runtime_.epochs() != nullptr) {
        return;
    }
    const auto self_entry =
        std::find_if(founding.members.begin(), founding.members.end(),
                     [this](const auto& entry) { return entry.first == config_.self; });
    if (self_entry == founding.members.end()) {
        return;
    }
    // The founding must echo the vote key this node's evidence bound.
    const auto own_key = vote_key_for_epoch(1);
    if (!own_key.has_value() || self_entry->second != *own_key) {
        return;
    }
    founding_ = founding;

    // The founding set observes itself before anything is generated. Genesis
    // names who was verified; it does not get to say who qualifies, so the
    // founders establish that among themselves first.
    std::vector<NodeId> founders;
    for (const auto& [node, key] : founding.members) {
        founders.push_back(node);
    }
    if (eligibility_.enter_genesis(std::move(founders)) == EligibilityRestore::Corrupt) {
        set_phase(DriverPhase::Failed, "durable eligibility state is corrupt");
        return;
    }
    set_phase(DriverPhase::GenesisEligibility,
              "founding received; running the mutual eligibility round");
    begin_founding_observations();
}

void SecurityDriver::begin_founding_observations() {
    // Continuity counts distinct attestations, so each founder is challenged
    // the compiled minimum number of times.
    //
    // These name epoch 0, the bootstrap window. The founding round is not
    // Epoch 1 work, and spending Epoch 1's per-node attestation budget here
    // would leave the first epoch's re-attestation cadence short of it.
    for (const auto& [node, key] : founding_->members) {
        if (node == config_.self) {
            continue;
        }
        for (std::size_t round = 0; round < constants::kMinContinuityObservations; ++round) {
            crypto::Ed25519PublicKey node_key{};
            node_key = node.bytes;
            auto challenge = runtime_.attestation().create_challenge(node, node_key, 1, 0);
            if (!challenge.has_value()) {
                break;
            }
            (void)router_.send(
                node, router_.compose(SecurityMessageKind::AttestationChallenge, *challenge, 0));
        }
    }
}

void SecurityDriver::record_founding_observation(const AttestationVerdict& verdict) {
    eligibility_.record_verdict(verdict);
    // Before Epoch 1 nothing is certified, so the round counter stands in for
    // the certified height an established epoch would supply.
    ++founding_round_;
    const Digest reference = founding_->attestation_root;
    if (auto observation =
            eligibility_.observe_attestation(verdict, founding_round_, reference)) {
        publish(*observation, 0);
    }
    // At Genesis the participation fact is the same exchange: the subject
    // answered an authenticated challenge bound to this network, this epoch and
    // the compiled rulesets. There is no consensus yet to speak on.
    if (verdict.passed) {
        ParticipationProof proof;
        proof.network_id = eligibility_.context().network_id;
        proof.epoch = 0;
        proof.consensus_ruleset = constants::kConsensusRulesetVersion;
        proof.subject = verdict.node_id;
        proof.incarnation = verdict.incarnation;
        proof.subject_height = founding_round_;
        if (auto observation =
                eligibility_.observe_participation(proof, founding_round_, reference)) {
            publish(*observation, 0);
        }
    }
    maybe_attest_founding_eligibility();
}

void SecurityDriver::maybe_attest_founding_eligibility() {
    if (phase_ != DriverPhase::GenesisEligibility || founding_eligibility_digest_ != Digest{}) {
        return;
    }
    if (!eligibility_.mutual_round_complete()) {
        return;
    }
    founding_eligibility_digest_ = eligibility_state_digest(eligibility_.compute_state(1));

    GenesisEligibilityAttest attest;
    attest.epoch = 1;
    attest.founding_state_digest = founding_eligibility_digest_;
    attest.node = config_.self;
    const Digest digest = genesis_eligibility_attest_digest(attest);
    crypto_sign_detached(attest.identity_signature.data(), nullptr, digest.data(), digest.size(),
                         config_.identity.private_key.data());

    founding_eligibility_attests_[config_.self] = founding_eligibility_digest_;
    (void)router_.broadcast(
        router_.compose(SecurityMessageKind::GenesisEligibilityAttest, attest, 1));
    (void)router_.send(genesis_id(),
                       router_.compose(SecurityMessageKind::GenesisEligibilityAttest, attest, 1));
    on_genesis_eligibility_attest(attest);
}

void SecurityDriver::on_genesis_eligibility_attest(const GenesisEligibilityAttest& attest) {
    if (genesis_ != nullptr && genesis_node() && !genesis_->finalized()) {
        (void)genesis_->record_eligibility_attest(attest);
        return;
    }
    if (phase_ != DriverPhase::GenesisEligibility || !founding_.has_value() || attest.epoch != 1) {
        return;
    }
    const bool founder =
        std::any_of(founding_->members.begin(), founding_->members.end(),
                    [&](const auto& entry) { return entry.first == attest.node; });
    if (!founder) {
        return;
    }
    const Digest digest = genesis_eligibility_attest_digest(attest);
    if (crypto_sign_verify_detached(attest.identity_signature.data(), digest.data(), digest.size(),
                                    attest.node.bytes.data()) != 0) {
        return;
    }
    founding_eligibility_attests_[attest.node] = attest.founding_state_digest;

    // Every founder, and the same transcript from each. One disagreement stops
    // the bootstrap: the threshold does not bend to reach a quorum.
    if (founding_eligibility_digest_ == Digest{} ||
        founding_eligibility_attests_.size() != founding_->members.size()) {
        return;
    }
    for (const auto& [node, value] : founding_eligibility_attests_) {
        if (value != founding_eligibility_digest_) {
            return;
        }
    }
    set_phase(DriverPhase::FoundingDkg, "founding eligibility agreed; starting the epoch-1 DKG");
    start_founding_dkg();
}

void SecurityDriver::start_founding_dkg() {
    std::vector<NodeId> ids;
    std::map<NodeId, IncarnationId> incarnations;
    for (const auto& [node, key] : founding_->members) {
        ids.push_back(node);
        incarnations[node] = 1;
    }
    auto set = Tier1Set::from_nodes(ids);
    if (!set.has_value()) {
        set_phase(DriverPhase::Idle, "founding set is not a valid Tier 1 set");
        return;
    }
    DkgConfiguration dkg;
    dkg.network_id = derive_network_id(config_.genesis_public_key,
                                       constants::kSecurityRulesetVersion,
                                       constants::kConsensusRulesetVersion);
    dkg.target_epoch = 1;
    dkg.participants = std::move(*set);
    dkg.incarnations = std::move(incarnations);
    dkg.threshold = constants::authority_threshold(founding_->members.size());
    dkg.self = config_.self;
    auto broadcast = runtime_.authority().start_dkg(std::move(dkg));
    if (!broadcast.has_value()) {
        set_phase(DriverPhase::Idle, "epoch-1 DKG refused to start");
        return;
    }
    (void)router_.broadcast(router_.compose(SecurityMessageKind::DkgBroadcast, *broadcast, 1));
}

void SecurityDriver::on_dkg_complete(EpochId target) {
    pending_dkg_ = runtime_.authority().take_dkg_result();
    if (!pending_dkg_.has_value()) {
        return;
    }
    if (target == 1 && phase_ == DriverPhase::FoundingDkg) {
        DkgTranscriptAttest attest;
        attest.epoch = 1;
        attest.participant_set_digest = pending_dkg_->participant_set_digest;
        attest.transcript_digest = pending_dkg_->transcript_digest;
        attest.group_public_key = pending_dkg_->group_public_key;
        attest.node = config_.self;
        const Digest digest = dkg_transcript_attest_digest(attest);
        crypto_sign_detached(attest.identity_signature.data(), nullptr, digest.data(),
                             digest.size(), config_.identity.private_key.data());
        (void)router_.send(genesis_id(),
                           router_.compose(SecurityMessageKind::DkgTranscriptAttest, attest, 1));
        set_phase(DriverPhase::AwaitingBootstrap,
                  "DKG transcript attested; awaiting the bootstrap certificate");
        return;
    }
    EpochManager* epochs = runtime_.epochs();
    if (epochs != nullptr && epochs->transition() != nullptr &&
        target == epochs->transition()->to_epoch) {
        (void)epochs->record_dkg_result(pending_dkg_->group_public_key,
                                        pending_dkg_->transcript_digest);
    }
}

void SecurityDriver::on_dkg_failed(DkgFailure, std::optional<NodeId> culprit) {
    runtime_.authority().abandon_dkg();
    if (phase_ == DriverPhase::GenesisEligibility || phase_ == DriverPhase::FoundingDkg ||
        phase_ == DriverPhase::AwaitingBootstrap) {
        // Await a fresh founding round; nothing was activated.
        founding_.reset();
        pending_dkg_.reset();
        founding_eligibility_digest_ = Digest{};
        founding_eligibility_attests_.clear();
        set_phase(DriverPhase::Idle, "founding DKG failed; awaiting a fresh round");
        return;
    }
    EpochManager* epochs = runtime_.epochs();
    if (epochs != nullptr && epochs->transition() != nullptr) {
        if (culprit.has_value()) {
            (void)epochs->replace_participant(*culprit, EpochTransitionFailure::DkgFailed);
        } else {
            epochs->abort_transition(EpochTransitionFailure::DkgFailed);
        }
        pending_dkg_.reset();
    }
}

void SecurityDriver::on_dkg_transcript_attest(const DkgTranscriptAttest& attest) {
    if (genesis_ == nullptr || !genesis_node() || genesis_->finalized()) {
        return;
    }
    if (!genesis_->record_transcript_attest(attest)) {
        return;
    }
    if (!genesis_->transcript_agreed()) {
        return;
    }
    const auto founders = genesis_->founding_set();
    const auto certificate = genesis_->finalize_epoch_one(
        attest.group_public_key, attest.transcript_digest, genesis_attestation_root(*founders),
        config_.identity.private_key);
    if (!certificate.has_value()) {
        return;
    }
    (void)store_.store_bootstrap(*certificate);
    (void)router_.broadcast(
        router_.compose(SecurityMessageKind::BootstrapCertificate, *certificate, 1));
    // Genesis unilateral authority ends here; this node continues as an
    // ordinary server.
    set_phase(DriverPhase::Idle, "bootstrap certificate issued; genesis authority ends");
}

void SecurityDriver::on_bootstrap_certificate(const BootstrapCertificate& certificate,
                                              const NodeId& from) {
    if (from != genesis_id() || phase_ != DriverPhase::AwaitingBootstrap ||
        !founding_.has_value() || !pending_dkg_.has_value() || runtime_.epochs() != nullptr) {
        return;
    }
    // Genesis may only certify the founding eligibility the founders computed.
    // A certificate naming anything else is refused rather than adopted.
    if (certificate.founding_eligibility_digest != founding_eligibility_digest_) {
        return;
    }
    std::vector<NodeId> ids;
    std::map<NodeId, crypto::Ed25519PublicKey> vote_keys;
    for (const auto& [node, key] : founding_->members) {
        ids.push_back(node);
        vote_keys[node] = key;
    }
    auto founders = Tier1Set::from_nodes(ids);
    if (!founders.has_value()) {
        return;
    }
    EpochVoteKey own_key = take_own_vote_key(1);
    if (!runtime_.adopt_epoch_one(certificate, config_.genesis_public_key, std::move(*founders),
                                  std::move(vote_keys), std::move(pending_dkg_),
                                  std::move(own_key))) {
        set_phase(DriverPhase::Idle, "epoch-1 adoption failed");
        return;
    }
    pending_dkg_.reset();
    const Digest checkpoint = bootstrap_certificate_signing_digest(certificate);
    (void)store_.store_bootstrap(certificate);
    persist_current_epoch(checkpoint);
    (void)store_.append_authority({1, certificate.authority_public_key,
                                   certificate.tier1_set_digest,
                                   certificate.dkg_transcript_digest});
    if (!enter_eligibility_epoch(1, runtime_.epochs()->current().tier1_members)) {
        set_phase(DriverPhase::Failed, "durable eligibility state is corrupt");
        return;
    }
    set_phase(DriverPhase::Active, "epoch 1 adopted and active");
    epoch_started_ms_ = now_ms_;
    last_progress_ms_ = now_ms_;
    announce_epoch(checkpoint);
}

// --- Vote keys ---------------------------------------------------------------

std::optional<crypto::Ed25519PublicKey> SecurityDriver::vote_key_for_epoch(EpochId epoch) {
    const auto known = vote_pubs_mine_.find(epoch);
    if (known != vote_pubs_mine_.end()) {
        return known->second;
    }
    EpochVoteKey key = make_epoch_vote_key(epoch, config_.self);
    vote_pubs_mine_[epoch] = key.public_key;
    (void)store_.store_vote_key(key);
    vote_keys_mine_.emplace(epoch, std::move(key));
    return vote_pubs_mine_.at(epoch);
}

EpochVoteKey SecurityDriver::take_own_vote_key(EpochId epoch) {
    (void)vote_key_for_epoch(epoch);
    auto it = vote_keys_mine_.find(epoch);
    EpochVoteKey key = std::move(it->second);
    vote_keys_mine_.erase(it);
    return key;
}

// --- Attestation and the epoch cadence --------------------------------------

void SecurityDriver::on_attestation_verdict(const AttestationVerdict& verdict,
                                            const AttestationEvidence& evidence) {
    if (phase_ == DriverPhase::GenesisCollecting && genesis_ != nullptr &&
        !genesis_->finalized()) {
        if (!genesis_->record_verdict(verdict)) {
            return;
        }
        spdlog::info("[security] genesis verdict for {}: {}",
                     crypto::to_hex(std::span<const uint8_t>(verdict.node_id.bytes.data(), 8)),
                     verdict.passed ? "PASSED" : "failed");
        if (verdict.passed) {
            founder_vote_keys_[verdict.node_id] = evidence.epoch_vote_key;
            founder_evidence_digests_[verdict.node_id] = verdict.evidence_digest;
        }
        if (genesis_->quorum_ready() && !founding_sent_) {
            send_founding();
        }
        return;
    }

    if (phase_ == DriverPhase::GenesisEligibility) {
        record_founding_observation(verdict);
        return;
    }

    EpochManager* epochs = runtime_.epochs();
    if (epochs == nullptr) {
        return;
    }
    if (verdict.epoch == epochs->current().id) {
        // Local re-attestation creates a candidate observation and nothing
        // more. One verifier's word is not a mesh fact: the statement is signed
        // and published, and a quorum of observers is what makes it count.
        eligibility_.record_verdict(verdict);
        if (auto observation = eligibility_.observe_attestation(verdict, last_committed_height_,
                                                                last_committed_root_)) {
            publish(*observation, epochs->current().id);
        }
        return;
    }
    const EpochTransition* transition = epochs->transition();
    if (transition != nullptr && verdict.epoch == transition->to_epoch) {
        (void)epochs->record_final_attestation(verdict);
        if (verdict.passed) {
            (void)epochs->record_vote_key(verdict.node_id, evidence.epoch_vote_key);
        }
        maybe_start_next_dkg();
    }
}

void SecurityDriver::run_epoch_cadence(uint64_t now_ms) {
    EpochManager* epochs = runtime_.epochs();
    const EpochState& current = epochs->current();

    if (epochs->transition() == nullptr &&
        now_ms - last_reattest_ms_ >= constants::kReattestIntervalSeconds * 1000) {
        last_reattest_ms_ = now_ms;
        for (const auto& member : current.tier1_members.members()) {
            if (member == config_.self) {
                continue;
            }
            crypto::Ed25519PublicKey member_key{};
            member_key = member.bytes;
            auto challenge =
                runtime_.attestation().create_challenge(member, member_key, 1, current.id);
            if (challenge.has_value()) {
                (void)router_.send(
                    member, router_.compose(SecurityMessageKind::AttestationChallenge,
                                            *challenge, current.id));
            }
        }
    }

    if (!epoch_aged(now_ms)) {
        return;
    }
    if (epochs->transition() == nullptr ||
        epochs->transition()->phase == EpochTransitionPhase::Aborted) {
        // The pool comes from the eligibility state a quorum finalized, never
        // from what this node happens to hold. Until that commitment commits
        // there is no pool, and selection simply waits.
        const auto pool = eligibility_.frozen_pool(current.id + 1);
        if (!pool.has_value() || !epochs->prepare_next_epoch(*pool, pool->size())) {
            return;
        }
        const EpochId target = epochs->transition()->to_epoch;
        for (const auto& member : epochs->transition()->selected_members) {
            if (member == config_.self) {
                attest_self_for(target);
                continue;
            }
            crypto::Ed25519PublicKey member_key{};
            member_key = member.bytes;
            auto challenge =
                runtime_.attestation().create_challenge(member, member_key, 1, target);
            if (challenge.has_value()) {
                (void)router_.send(member,
                                   router_.compose(SecurityMessageKind::AttestationChallenge,
                                                   *challenge, target));
            }
        }
    }
}

void SecurityDriver::attest_self_for(EpochId epoch) {
    auto challenge =
        runtime_.attestation().create_challenge(config_.self, config_.identity.public_key, 1,
                                                epoch);
    if (challenge.has_value()) {
        (void)router_.deliver_local(
            router_.compose(SecurityMessageKind::AttestationChallenge, *challenge, epoch));
    }
}

void SecurityDriver::maybe_start_next_dkg() {
    EpochManager* epochs = runtime_.epochs();
    const EpochTransition* transition = epochs->transition();
    if (transition == nullptr || transition->phase != EpochTransitionPhase::GeneratingAuthorityKey ||
        runtime_.authority().dkg() != nullptr || pending_dkg_.has_value()) {
        return;
    }
    auto set = Tier1Set::from_nodes(transition->selected_members);
    if (!set.has_value()) {
        return;
    }
    std::map<NodeId, IncarnationId> incarnations;
    for (const auto& node : transition->selected_members) {
        incarnations[node] = 1;
    }
    DkgConfiguration dkg;
    dkg.network_id = epochs->current().network_id;
    dkg.target_epoch = transition->to_epoch;
    dkg.participants = std::move(*set);
    dkg.incarnations = std::move(incarnations);
    dkg.threshold = transition->next_authority_threshold;
    dkg.self = config_.self;
    auto broadcast = runtime_.authority().start_dkg(std::move(dkg));
    if (broadcast.has_value()) {
        (void)router_.broadcast(router_.compose(SecurityMessageKind::DkgBroadcast, *broadcast,
                                                transition->to_epoch));
    }
}

// --- Consensus driving -------------------------------------------------------

void SecurityDriver::progress(uint64_t now_ms) { last_progress_ms_ = now_ms; }

void SecurityDriver::on_certificate(const QuorumCertificate&) { progress(now_ms_); }

void SecurityDriver::on_vote_accepted(const Vote& vote) {
    const EpochManager* epochs = runtime_.epochs();
    const HotStuffService* consensus = runtime_.consensus();
    // An observer that has not synced holds no floor to measure against, so it
    // cannot say whether anyone else is current.
    if (phase_ != DriverPhase::Active || epochs == nullptr || consensus == nullptr ||
        !consensus->synced()) {
        return;
    }
    ParticipationProof proof;
    proof.network_id = vote.network_id;
    proof.epoch = vote.epoch;
    proof.consensus_ruleset = vote.consensus_ruleset;
    proof.subject = vote.voter;
    proof.incarnation = 1;
    proof.subject_height = vote.height;
    if (auto observation = eligibility_.observe_participation(proof, last_committed_height_,
                                                              last_committed_root_)) {
        publish(*observation, epochs->current().id);
    }
}

void SecurityDriver::on_eligibility_observation(const EligibilityObservation& observation) {
    (void)eligibility_.accept(observation);
    maybe_attest_founding_eligibility();
}

void SecurityDriver::drain_objective_faults() {
    const HotStuffService* consensus = runtime_.consensus();
    if (consensus == nullptr) {
        return;
    }
    // Equivocation is two signed messages from one node for one view. It is
    // proved, so it is recorded; nothing here judges a peer.
    const auto& evidence = consensus->equivocation_evidence();
    for (std::size_t i = consumed_equivocations_; i < evidence.size(); ++i) {
        eligibility_.record_fault(evidence[i].node, ObjectiveFault::Equivocation);
    }
    consumed_equivocations_ = evidence.size();
}

void SecurityDriver::on_timeout_certificate(const TimeoutCertificate&) { progress(now_ms_); }

Digest SecurityDriver::pending_handoff_digest() const {
    const EpochManager* epochs = runtime_.epochs();
    if (epochs == nullptr || epochs->transition() == nullptr ||
        epochs->transition()->phase != EpochTransitionPhase::Ready) {
        return Digest{};
    }
    const EpochTransition& t = *epochs->transition();
    CanonicalEncoder encoder("lemonade-nexus/handoff:v1");
    encoder.add_u64(t.to_epoch);
    encoder.add_bytes(t.participant_set_digest);
    encoder.add_bytes(t.next_authority_key);
    encoder.add_bytes(t.dkg_transcript_digest);
    return encoder.digest();
}

Digest SecurityDriver::pending_eligibility_digest() const {
    const EpochManager* epochs = runtime_.epochs();
    if (phase_ != DriverPhase::Active || epochs == nullptr) {
        return Digest{};
    }
    // Only at a boundary, only before a transition exists, and only once. A
    // finalized state is not proposed again.
    if (!epoch_aged(now_ms_) || eligibility_.finalized() != nullptr) {
        return Digest{};
    }
    if (epochs->transition() != nullptr &&
        epochs->transition()->phase != EpochTransitionPhase::Aborted) {
        return Digest{};
    }
    return eligibility_commitment_digest(eligibility_.compute_state(epochs->current().id + 1));
}

bool SecurityDriver::accepts_transition(const Digest& transitions_digest) const {
    if (transitions_digest == Digest{}) {
        return true;
    }
    const Digest handoff = pending_handoff_digest();
    if (handoff != Digest{} && transitions_digest == handoff) {
        return true;
    }
    const Digest eligibility = pending_eligibility_digest();
    return eligibility != Digest{} && transitions_digest == eligibility;
}

void SecurityDriver::maybe_propose(View view) {
    HotStuffService* consensus = runtime_.consensus();
    if (consensus == nullptr || !consensus->synced() || view <= last_proposed_view_ ||
        consensus->current_view() != view || consensus->leader_of(view) != config_.self) {
        return;
    }
    // A boundary produces two transitions in order: the eligibility state that
    // decides who may serve, then the handoff that installs them.
    const Digest handoff = pending_handoff_digest();
    const Digest transitions = handoff != Digest{} ? handoff : pending_eligibility_digest();
    // The transition is inside the state root, so finalizing the block
    // finalizes the eligibility state it names.
    CanonicalEncoder root("lemonade-nexus/state-root:v1");
    root.add_bytes(last_committed_root_);
    root.add_bytes(transitions);
    auto made = consensus->make_proposal(last_committed_root_, root.digest(), transitions);
    if (!std::holds_alternative<Proposal>(made)) {
        return;
    }
    last_proposed_view_ = view;
    const EpochId epoch = current_epoch().value_or(0);
    ProposalMessage message{std::get<Proposal>(made), consensus->state().high_qc};
    auto envelope = router_.compose(SecurityMessageKind::HotStuffProposal, message, epoch);
    (void)router_.broadcast(envelope);
    (void)router_.deliver_local(std::move(envelope));
}

void SecurityDriver::on_commits(const std::vector<ConsensusCommit>& commits) {
    progress(now_ms_);
    for (const auto& commit : commits) {
        pacemaker_.on_committed_block();
        last_committed_root_ = commit.proposed_state_root;
        last_committed_height_ = commit.height;
        if (commit.transitions_digest == Digest{}) {
            continue;
        }
        EpochManager* epochs = runtime_.epochs();
        if (epochs == nullptr) {
            continue;
        }
        // A committed eligibility commitment is the finalized state. A node
        // that arrived at different facts recognizes nothing here, so it never
        // finalizes and never selects — availability, never authority.
        const Digest eligibility = pending_eligibility_digest();
        if (eligibility != Digest{} && commit.transitions_digest == eligibility) {
            eligibility_.finalize({commit.transitions_digest, commit.qc_digest, commit.height,
                                   epochs->current().id + 1});
            continue;
        }
        const Digest handoff = pending_handoff_digest();
        if (handoff != Digest{} && commit.transitions_digest == handoff) {
            if (epochs->record_handoff_authorization(commit.qc_digest)) {
                do_activate(commit.qc_digest);
            }
        }
    }
}

void SecurityDriver::do_activate(const Digest& checkpoint) {
    EpochManager* epochs = runtime_.epochs();
    const EpochTransition* transition = epochs->transition();
    if (transition == nullptr) {
        return;
    }
    const EpochId old_epoch = epochs->current().id;
    const EpochId to_epoch = transition->to_epoch;
    const Digest dkg_digest = transition->dkg_transcript_digest;
    const bool member = std::find(transition->selected_members.begin(),
                                  transition->selected_members.end(),
                                  config_.self) != transition->selected_members.end();

    std::optional<EpochVoteKey> own_key;
    if (member) {
        own_key = take_own_vote_key(to_epoch);
    }
    if (!runtime_.activate_next_epoch(std::move(pending_dkg_), std::move(own_key), checkpoint)) {
        return;
    }
    pending_dkg_.reset();
    persist_current_epoch(checkpoint);
    (void)store_.append_authority({to_epoch, epochs->current().authority_public_key,
                                   epochs->current().participant_set_digest, dkg_digest});
    store_.discard_vote_key(old_epoch);
    // Observations expire at the boundary: the new epoch's members are the new
    // observers, and continuity has to be re-established under them.
    if (!enter_eligibility_epoch(to_epoch, epochs->current().tier1_members)) {
        set_phase(DriverPhase::Failed, "durable eligibility state is corrupt");
        return;
    }
    epoch_started_ms_ = now_ms_;
    last_progress_ms_ = now_ms_;
    last_proposed_view_ = 0;
    last_committed_root_ = Digest{};
    last_committed_height_ = 0;
    announce_epoch(checkpoint);
}

void SecurityDriver::persist_current_epoch(const Digest& checkpoint) {
    const EpochManager* epochs = runtime_.epochs();
    StoredEpoch stored{epochs->current(), epochs->current_vote_keys(), checkpoint};
    (void)store_.store_epoch(stored);
}

void SecurityDriver::announce_epoch(const Digest& checkpoint) {
    const EpochState& current = runtime_.epochs()->current();
    EpochAnnouncement announcement;
    announcement.authority.network_id = current.network_id;
    announcement.authority.epoch = current.id;
    announcement.authority.key_generation = current.id;
    announcement.authority.security_ruleset = current.security_ruleset;
    announcement.authority.consensus_ruleset = current.consensus_ruleset;
    announcement.authority.tier1_set_digest = current.participant_set_digest;
    announcement.authority.consensus_quorum = current.consensus_quorum;
    announcement.authority.authority_threshold = current.authority_threshold;
    announcement.authority.frost_ciphersuite = std::string(constants::kFrostCiphersuite);
    announcement.authority.group_public_key = current.authority_public_key;
    announcement.authority.dkg_transcript_digest = Digest{};
    announcement.authority.attestation_root = current.attestation_root;
    announcement.authority.previous_checkpoint = checkpoint;
    announcement.handoff_certificate_digest = checkpoint;
    (void)router_.broadcast(router_.compose(SecurityMessageKind::EpochAnnouncement, announcement,
                                            current.id));
}

}  // namespace nexus::security
