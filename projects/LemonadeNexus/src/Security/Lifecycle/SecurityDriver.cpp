#include <LemonadeNexus/Security/Lifecycle/SecurityDriver.hpp>

#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Security/Consensus/QuorumValidation.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <sodium.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <limits>

namespace nexus::security {

namespace {

[[nodiscard]] const char* phase_name(DriverPhase p) {
    switch (p) {
        case DriverPhase::Failed:            return "Failed";
        case DriverPhase::Idle:              return "Idle";
        case DriverPhase::PendingNextEpoch:  return "PendingNextEpoch";
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

[[nodiscard]] bool bootstrap_valid_for(const BootstrapCertificate& certificate,
                                       const crypto::Ed25519PublicKey& genesis_public_key,
                                       const NetworkId& network_id) {
    return certificate.network_id == network_id && certificate.epoch == 1 &&
           certificate.security_ruleset == constants::kSecurityRulesetVersion &&
           certificate.consensus_ruleset == constants::kConsensusRulesetVersion &&
           certificate.authority_threshold ==
               constants::authority_threshold(constants::kBootstrapThreshold) &&
           verify_bootstrap_certificate(certificate, genesis_public_key);
}

[[nodiscard]] bool authority_cache_well_formed_for(const VerifiedEpochAuthority& authority,
                                                   const NetworkId& network_id) {
    const auto members = Tier1Set::from_nodes(authority.members);
    if (authority.network_id != network_id || authority.epoch < 1 || !members.has_value() ||
        members->members() != authority.members ||
        authority.members.size() < constants::kMinActiveTier1 ||
        authority.members.size() > constants::kMaxActiveTier1 ||
        authority.vote_keys.size() != authority.members.size() ||
        authority.incarnations.size() != authority.members.size() ||
        authority.consensus_quorum != constants::consensus_quorum(authority.members.size()) ||
        authority.authority_threshold != constants::authority_threshold(authority.members.size()) ||
        authority.security_ruleset != constants::kSecurityRulesetVersion ||
        authority.consensus_ruleset != constants::kConsensusRulesetVersion ||
        authority.key_generation != KeyGeneration(authority.epoch.underlying()) ||
        authority.checkpoint == Digest{} || authority.anchor_digest == Digest{}) {
        return false;
    }
    for (const auto& node : authority.members) {
        const auto incarnation = authority.incarnations.find(node);
        if (!authority.vote_keys.contains(node) || incarnation == authority.incarnations.end() ||
            incarnation->second == 0) {
            return false;
        }
    }
    return authority.epoch == 1
               ? authority.previous_anchor == Digest{} &&
                     authority.anchor_digest == authority.checkpoint
               : authority.previous_anchor != Digest{};
}

[[nodiscard]] bool epoch_valid_for(const StoredEpoch& epoch, const NetworkId& network_id) {
    if (epoch.state.id < 1 || epoch.state.network_id != network_id ||
        epoch.state.tier1_members.size() < constants::kMinActiveTier1 ||
        epoch.state.tier1_members.size() > constants::kMaxActiveTier1 ||
        epoch.vote_keys.size() != epoch.state.tier1_members.size() ||
        epoch.state.security_ruleset != constants::kSecurityRulesetVersion ||
        epoch.state.consensus_ruleset != constants::kConsensusRulesetVersion ||
        epoch.checkpoint == Digest{}) {
        return false;
    }
    return std::all_of(epoch.state.tier1_members.members().begin(),
                       epoch.state.tier1_members.members().end(),
                       [&epoch](const NodeId& node) { return epoch.vote_keys.contains(node); });
}

[[nodiscard]] bool authority_matches_epoch(const VerifiedEpochAuthority& authority,
                                           const StoredEpoch& epoch) {
    return authority.epoch == epoch.state.id &&
           authority.network_id == epoch.state.network_id &&
           authority.members == epoch.state.tier1_members.members() &&
           authority.vote_keys == epoch.vote_keys &&
           authority.group_public_key == epoch.state.authority_public_key &&
           authority.attestation_root == epoch.state.attestation_root &&
           authority.checkpoint == epoch.checkpoint;
}

[[nodiscard]] bool epoch_matches_bootstrap(const StoredEpoch& epoch,
                                           const BootstrapCertificate& certificate) {
    return epoch.state.id != 1 ||
           (epoch.state.network_id == certificate.network_id &&
            epoch.state.participant_set_digest == certificate.tier1_set_digest &&
            epoch.state.authority_public_key == certificate.authority_public_key &&
            epoch.state.attestation_root == certificate.attestation_root &&
            epoch.checkpoint == bootstrap_certificate_signing_digest(certificate));
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
    if (next == DriverPhase::Active && on_epoch_established_) on_epoch_established_();
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

std::optional<VerifiedEpochAuthority> SecurityDriver::authority_for_epoch(EpochId epoch) const {
    const auto it = authority_history_.find(epoch);
    if (it == authority_history_.end()) return std::nullopt;
    return it->second;
}

void SecurityDriver::install_authority(VerifiedEpochAuthority authority) {
    authority_history_[authority.epoch] = authority;
    authority_ = std::move(authority);
    (void)store_.store_authority_anchor(*authority_);
    if (genesis_node() && genesis_ != nullptr) {
        genesis_->restore_finalized();
    }
}

void SecurityDriver::start(uint64_t now_ms) {
    now_ms_ = now_ms;

    auto bootstrap = store_.load_bootstrap();
    auto epoch = store_.load_epoch();
    auto anchor = store_.load_authority_anchor();
    auto chain_base = store_.load_chain_base();
    auto chain_links = store_.load_chain_links();
    const auto corrupt = [](const auto& loaded) {
        const auto* result = std::get_if<EpochLoadResult>(&loaded);
        return result != nullptr && *result == EpochLoadResult::Corrupt;
    };
    const auto fail = [this](const char* reason) {
        if (genesis_node() && genesis_ != nullptr) {
            genesis_->restore_finalized();
        }
        set_phase(DriverPhase::Failed, reason);
    };
    if (corrupt(bootstrap) || corrupt(epoch) || corrupt(anchor) || corrupt(chain_base) ||
        corrupt(chain_links)) {
        fail("durable security state is corrupt");
        return;
    }

    const NetworkId network_id = derive_network_id(
        config_.genesis_public_key, constants::kSecurityRulesetVersion,
        constants::kConsensusRulesetVersion);
    const auto* certificate = std::get_if<BootstrapCertificate>(&bootstrap);
    const auto* cached = std::get_if<VerifiedEpochAuthority>(&anchor);
    const auto* stored_epoch = std::get_if<StoredEpoch>(&epoch);
    const auto* base = std::get_if<
        std::vector<std::pair<NodeId, crypto::Ed25519PublicKey>>>(&chain_base);
    const auto* links = std::get_if<std::vector<std::vector<uint8_t>>>(&chain_links);

    if ((certificate != nullptr &&
         !bootstrap_valid_for(*certificate, config_.genesis_public_key, network_id)) ||
        (cached != nullptr && !authority_cache_well_formed_for(*cached, network_id)) ||
        (stored_epoch != nullptr && !epoch_valid_for(*stored_epoch, network_id))) {
        fail("durable security state is invalid");
        return;
    }
    // Recovery fails closed unless the stored certificate's release commitment
    // is accepted: the same approval, or (with a release chain) a founding
    // approval that carries the pinned release signer for this network.
    if (certificate != nullptr &&
        !(config_.release_commitment
              ? config_.release_commitment(certificate->release_approval_digest)
              : certificate->release_approval_digest == config_.release_approval_digest)) {
        fail("epoch state commits a release approval this node cannot accept");
        return;
    }
    if (certificate != nullptr) {
        anchor_ = *certificate;
    }
    std::vector<VerifiedEpochAuthority> authenticated;
    if (base != nullptr) {
        if (certificate == nullptr) {
            chain_hint_epoch_ = std::max(chain_hint_epoch_, EpochId(1));
        } else {
            auto epoch_one = verify_epoch_one_authority(*certificate, config_.genesis_public_key,
                                                         *base);
            if (!epoch_one.has_value()) {
                fail("authority-chain base contradicts the bootstrap certificate");
                return;
            }
            authenticated.push_back(std::move(*epoch_one));
        }
    }

    if (stored_epoch != nullptr && certificate != nullptr &&
        !epoch_matches_bootstrap(*stored_epoch, *certificate)) {
        fail("stored epoch contradicts the bootstrap certificate");
        return;
    }
    if (authenticated.empty() && links != nullptr && !links->empty()) {
        fail("authority-chain history has no authenticated starting authority");
        return;
    }
    if (!authenticated.empty() && links != nullptr) {
        for (const auto& bytes : *links) {
            auto decoded = decode_security_message(bytes);
            const auto* message = std::get_if<SecurityMessage>(&decoded);
            const auto* link = message != nullptr
                                   ? std::get_if<EpochHandoffProofMsg>(&message->body)
                                   : nullptr;
            if (link == nullptr || link->handoff.from_epoch != authenticated.back().epoch) {
                fail("stored authority-chain history is invalid");
                return;
            }
            auto advanced =
                advance_epoch_authority(authenticated.back(), link->handoff, link->proof);
            auto* next = std::get_if<VerifiedEpochAuthority>(&advanced);
            if (next == nullptr) {
                fail("stored authority-chain history is invalid");
                return;
            }
            authenticated.push_back(std::move(*next));
        }
    }

    const auto authenticated_at = [&authenticated](EpochId epoch)
        -> const VerifiedEpochAuthority* {
        const auto match = std::find_if(
            authenticated.begin(), authenticated.end(),
            [epoch](const VerifiedEpochAuthority& authority) { return authority.epoch == epoch; });
        return match != authenticated.end() ? &*match : nullptr;
    };
    bool missing_proofs = false;
    if (cached != nullptr) {
        chain_hint_epoch_ = std::max(chain_hint_epoch_, cached->epoch);
        const auto* proved = authenticated_at(cached->epoch);
        if (proved == nullptr) {
            missing_proofs = true;
        } else if (verified_epoch_authority_digest(*cached) !=
                   verified_epoch_authority_digest(*proved)) {
            fail("cached authority contradicts authenticated authority");
            return;
        }
    }
    if (stored_epoch != nullptr) {
        chain_hint_epoch_ = std::max(chain_hint_epoch_, stored_epoch->state.id);
        const auto* proved = authenticated_at(stored_epoch->state.id);
        if (proved == nullptr) {
            missing_proofs = true;
        } else if (!authority_matches_epoch(*proved, *stored_epoch)) {
            fail("stored epoch contradicts authenticated authority");
            return;
        }
    }

    for (const auto& verified : authenticated) {
        authority_history_[verified.epoch] = verified;
    }
    if (!authenticated.empty()) {
        authority_ = authenticated.back();
    }
    const bool genesis_consumed = certificate != nullptr || cached != nullptr ||
                                  stored_epoch != nullptr || base != nullptr ||
                                  (links != nullptr && !links->empty());
    if (genesis_consumed && genesis_node() && genesis_ != nullptr) {
        genesis_->restore_finalized();
    }

    if (missing_proofs) {
        set_phase(DriverPhase::Idle,
                  "durable authority awaits its authenticated proof chain");
        return;
    }
    if (authority_.has_value() &&
        (cached == nullptr || cached->epoch != authority_->epoch)) {
        (void)store_.store_authority_anchor(*authority_);
    }

    if (stored_epoch != nullptr) {
        if (authority_.has_value() && authority_->epoch > stored_epoch->state.id) {
            // The verified chain has moved past the stored epoch: this node's
            // membership is history, and resuming it could only replay a
            // finished role. It continues as an ordinary Tier 2 server; the
            // stale state costs availability and grants nothing.
            set_phase(DriverPhase::Idle, "stored epoch superseded by the verified chain");
            return;
        }
        StoredEpoch stored = *stored_epoch;
        const EpochId id = stored.state.id;
        const bool member = stored.state.tier1_members.contains(config_.self);
        auto vote_key = store_.load_vote_key(id, config_.self);
        if (vote_key.has_value()) {
            vote_pubs_mine_[id] = vote_key->public_key;
        }
        if (!runtime_.restore_epoch(std::move(stored), std::move(vote_key))) {
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

    if (genesis_node() && genesis_ != nullptr && !genesis_->finalized()) {
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
    // The transport verified this peer's certificate. That makes it reachable
    // and nothing more; the cadence decides what to ask it for.
    certified_peers_.insert(peer);
    if (phase_ == DriverPhase::GenesisCollecting && genesis_ != nullptr &&
        !genesis_->finalized()) {
        (void)genesis_->admit_candidate(peer);
        issue_genesis_challenge(peer);
    }
}

void SecurityDriver::issue_genesis_challenge(const NodeId& peer) {
    crypto::Ed25519PublicKey peer_key{};
    peer_key = peer.bytes;
    auto challenge = runtime_.attestation().create_challenge(peer, peer_key, 1, 1,
                                                             AttestationPurpose::Eligibility);
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

    maybe_request_chain();
    run_bootstrap_liveness(now_ms);
    maybe_resend_dkg(now_ms);

    if (phase_ == DriverPhase::PendingNextEpoch && adoption_.has_value() &&
        !adoption_->state_synced &&
        now_ms - sync_started_ms_ >= config_.sync_window_ms) {
        // Recovery input can be lost; the ask repeats until certified state
        // answers it. Repeating costs nothing and authorizes nothing.
        sync_started_ms_ = now_ms;
        (void)router_.broadcast(router_.compose(SecurityMessageKind::SyncRequest,
                                                SyncRequest{adoption_->plan.current_epoch},
                                                adoption_->plan.current_epoch));
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
            (void)router_.deliver_local(std::move(message), now_ms);
            pacemaker_.on_timeout();
            last_progress_ms_ = now_ms;
        }
        maybe_propose(consensus->current_view());
    }

    if (phase_ == DriverPhase::Active && runtime_.epochs() != nullptr &&
        runtime_.epochs()->current().tier1_members.contains(config_.self)) {
        drain_objective_faults();
        maybe_fail_stalled_dkg(now_ms);
        maybe_renew_final_attestation();
        run_epoch_cadence(now_ms);
    }
}

void SecurityDriver::maybe_resend_dkg(uint64_t now_ms) {
    DkgSession* dkg = runtime_.authority().dkg();
    const bool live = dkg != nullptr && dkg->phase() != DkgPhase::Failed;
    if (live && phase_ == DriverPhase::FoundingDkg) {
        return;  // run_bootstrap_liveness re-emits the running founding session
    }
    if (!live && dkg_outbox_.has_value() &&
        now_ms - dkg_outbox_->kept_ms >= constants::kDkgStallSeconds * 2000) {
        dkg_outbox_.reset();  // nothing activated in time; stop talking
    }
    if (!live && !dkg_outbox_.has_value()) {
        return;
    }
    if (!dkg_resend_.due(now_ms)) {
        return;
    }
    const EpochId epoch = live ? dkg->target_epoch() : dkg_outbox_->epoch;
    const auto round1 = live ? dkg->own_round1() : dkg_outbox_->round1;
    const auto& round2 = live ? dkg->round2_cached() : dkg_outbox_->round2;
    if (round1.has_value()) {
        (void)router_.broadcast(router_.compose(SecurityMessageKind::DkgBroadcast, *round1, epoch));
    }
    for (const auto& package : round2) {
        (void)router_.send_sealed_dkg(package);
    }
}

std::optional<DkgResult> SecurityDriver::take_dkg_result_keeping_outbox() {
    if (DkgSession* dkg = runtime_.authority().dkg(); dkg != nullptr && dkg->complete()) {
        dkg_outbox_ = DkgOutbox{dkg->target_epoch(), dkg->own_round1(), dkg->round2_cached(),
                                now_ms_};
    }
    return runtime_.authority().take_dkg_result();
}

void SecurityDriver::maybe_fail_stalled_dkg(uint64_t now_ms) {
    EpochManager* epochs = runtime_.epochs();
    const EpochTransition* transition = epochs->transition();
    if (transition == nullptr ||
        transition->phase != EpochTransitionPhase::GeneratingAuthorityKey ||
        !readiness_.has_value() || dkg_authorized_ms_ == 0 ||
        now_ms - dkg_authorized_ms_ < constants::kDkgStallSeconds * 1000) {
        return;
    }
    // A participant that claimed readiness and then never spoke affects
    // liveness only: the attempt fails, its silence — observed identically by
    // every member from the broadcast traffic — excludes it, and the
    // deterministic replacement runs under a fresh plan and a fresh DKG.
    // Nothing of this attempt survives into the next one.
    const auto seen = runtime_.authority().round1_seen(transition->to_epoch);
    for (const auto& node : transition->selected_members) {
        if (node != config_.self && !seen.contains(node)) {
            boundary_failed_.insert(node);
        }
    }
    runtime_.authority().abandon_dkg();
    pending_dkg_.reset();
    abandon_boundary("DKG stalled past the compiled window; the attempt is replaced");
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
    founding.release_approval_digest = config_.release_approval_digest;
    spdlog::log(founding_sent_ ? spdlog::level::debug : spdlog::level::info,
                "[security] genesis founding: {} attested founders", founders->size());
    for (const auto& node : founders->members()) {
        (void)router_.send(node,
                           router_.compose(SecurityMessageKind::GenesisFounding, founding, 1));
    }
    founding_sent_ = true;
}

void SecurityDriver::run_bootstrap_liveness(uint64_t now_ms) {
    if (phase_ == DriverPhase::FoundingDkg && founding_dkg_started_ms_ != 0 &&
        now_ms - founding_dkg_started_ms_ >= constants::kDkgStallSeconds * 1000) {
        on_dkg_failed(DkgFailure::Stalled, std::nullopt);
        return;
    }
    const bool anchor_collecting = phase_ == DriverPhase::GenesisCollecting &&
                                   genesis_ != nullptr && !genesis_->finalized();
    const bool founder_round = phase_ == DriverPhase::GenesisEligibility && founding_.has_value();
    const bool founder_dkg = phase_ == DriverPhase::FoundingDkg && founding_.has_value();
    const bool founder_awaiting = phase_ == DriverPhase::AwaitingBootstrap &&
                                  pending_transcript_attest_.has_value();
    const bool certificate_tail =
        issued_certificate_.has_value() &&
        now_ms - certificate_issued_ms_ <= constants::kDkgStallSeconds * 2000;
    if (!anchor_collecting && !founder_round && !founder_dkg && !founder_awaiting &&
        !certificate_tail) {
        return;
    }
    const uint64_t jitter =
        (static_cast<uint64_t>(config_.self.bytes[0]) * 20) % constants::kBootstrapRetryJitterMs;
    if (now_ms - last_bootstrap_retry_ms_ < constants::kBootstrapRetryMs + jitter) {
        return;
    }
    last_bootstrap_retry_ms_ = now_ms;

    if (anchor_collecting) {
        if (founding_sent_) {
            send_founding();
            return;
        }
        for (const auto& peer : genesis_->unverdicted_candidates()) {
            runtime_.attestation().reset_attempts(1, peer);
            issue_genesis_challenge(peer);
        }
        return;
    }
    if (certificate_tail) {
        // A founder that missed the one certificate broadcast has no other
        // way to get it; repeat it for a bounded tail after issuance.
        (void)router_.broadcast(router_.compose(SecurityMessageKind::BootstrapCertificate,
                                                *issued_certificate_, 1));
        return;
    }
    if (founder_dkg) {
        // Re-attest so a straggler still assembling attests can finish.
        broadcast_eligibility_attest();
        // Datagrams are mortal: re-emit round-1 and produced round-2 packages.
        if (DkgSession* dkg = runtime_.authority().dkg();
            dkg != nullptr && !dkg->complete()) {
            if (const auto round1 = dkg->own_round1()) {
                (void)router_.broadcast(
                    router_.compose(SecurityMessageKind::DkgBroadcast, *round1, 1));
            }
            for (const auto& package : dkg->round2_cached()) {
                (void)router_.send_sealed_dkg(package);
            }
        }
        return;
    }
    if (founder_awaiting) {
        (void)router_.send(genesis_id(),
                           router_.compose(SecurityMessageKind::DkgTranscriptAttest,
                                           *pending_transcript_attest_, 1));
        return;
    }
    if (founding_eligibility_digest_ != Digest{}) {
        if (founding_eligibility_attests_.size() >= founding_->members.size()) {
            return;
        }
        broadcast_eligibility_attest();
        // No return: fresh observations at higher heights are the only way a
        // starved peer's round can finish.
    }
    for (const auto& [node, key] : founding_->members) {
        if (node != config_.self) {
            challenge_founding_edge(node);
        }
    }
}

void SecurityDriver::on_genesis_founding(const GenesisFounding& founding, const NodeId& from) {
    if (from != genesis_id() || runtime_.epochs() != nullptr) {
        return;
    }
    if (phase_ == DriverPhase::GenesisEligibility && founding_.has_value()) {
        // The root commits to every founder's evidence, vote key included, so
        // it alone identifies the round; an equal one is the anchor keep-alive.
        if (founding.attestation_root == founding_->attestation_root) {
            return;
        }
        // A different founding from the anchor supersedes a round that can no
        // longer complete (a founder restarted or the anchor re-collected).
        spdlog::info("[security] newer genesis founding received; restarting the mutual round");
        founding_eligibility_digest_ = Digest{};
        founding_eligibility_attests_.clear();
        // Stale ask times would suppress the fresh round's first challenges.
        founding_challenge_ms_.clear();
    } else if (phase_ != DriverPhase::Idle) {
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
    // One release selection per network: a founding naming a different (or no)
    // release approval than this node loaded is refused, not reconciled.
    if (founding.release_approval_digest != config_.release_approval_digest) {
        spdlog::warn("[security] genesis founding names a different release approval; refusing");
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
    // Heights are monotonic per record; a round counter behind the kept
    // ledger would publish nothing but rewinds.
    founding_round_ = std::max(founding_round_, eligibility_.max_observed_height());
    set_phase(DriverPhase::GenesisEligibility,
              "founding received; running the mutual eligibility round");
    begin_founding_observations();
}

bool SecurityDriver::is_founding_member(const NodeId& node) const {
    if (!founding_.has_value()) {
        return false;
    }
    return std::any_of(founding_->members.begin(), founding_->members.end(),
                       [&node](const auto& entry) { return entry.first == node; });
}

bool SecurityDriver::is_verified_authority_member(const NodeId& node) const {
    return authority_.has_value() &&
           std::find(authority_->members.begin(), authority_->members.end(), node) !=
               authority_->members.end();
}

void SecurityDriver::begin_founding_observations() {
    // One challenge per peer per pass: the service holds one pending challenge
    // per subject. The liveness cadence repeats the pass until continuity has
    // kMinContinuityObservations distinct attestations.
    spdlog::info("[security] founding round: observing {} founders",
                 founding_->members.size() - 1);
    for (const auto& [node, key] : founding_->members) {
        if (node != config_.self) {
            challenge_founding_edge(node);
        }
    }
}

void SecurityDriver::challenge_founding_edge(const NodeId& peer) {
    // Re-challenging over an outstanding ask orphans its answer; give each
    // edge two cadence periods before asking again.
    uint64_t& asked = founding_challenge_ms_[peer];
    if (asked != 0 && now_ms_ - asked < constants::kBootstrapRetryMs * 2) {
        return;
    }
    asked = now_ms_;
    // Epoch 0, the bootstrap window: the founding round is not Epoch 1 work,
    // and must not spend Epoch 1's per-node attestation budget.
    runtime_.attestation().reset_attempts(0, peer);
    crypto::Ed25519PublicKey peer_key{};
    peer_key = peer.bytes;
    auto challenge = runtime_.attestation().create_challenge(peer, peer_key, 1, 0,
                                                             AttestationPurpose::Eligibility);
    if (!challenge.has_value()) {
        return;
    }
    (void)router_.send(peer,
                       router_.compose(SecurityMessageKind::AttestationChallenge, *challenge, 0));
}

void SecurityDriver::record_founding_observation(const AttestationVerdict& verdict) {
    spdlog::info("[security] founding verdict for {}: {} (failure={})",
                 crypto::to_hex(std::span<const uint8_t>(verdict.node_id.bytes.data(), 8)),
                 verdict.passed ? "PASSED" : "failed",
                 static_cast<uint16_t>(verdict.failure));
    eligibility_.record_verdict(verdict);
    // Before Epoch 1 nothing is certified, so the round counter stands in for
    // the certified height an established epoch would supply.
    ++founding_round_;
    const Digest reference = founding_->attestation_root;
    if (auto observation =
            eligibility_.observe_attestation(verdict.node_id, founding_round_, reference)) {
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
    spdlog::info("[security] founding mutual round complete; attesting state {}",
                 crypto::to_hex(std::span<const uint8_t>(founding_eligibility_digest_.data(), 8)));
    founding_eligibility_attests_[config_.self] = founding_eligibility_digest_;
    broadcast_eligibility_attest();
}

void SecurityDriver::broadcast_eligibility_attest() {
    GenesisEligibilityAttest attest;
    attest.epoch = 1;
    attest.founding_state_digest = founding_eligibility_digest_;
    attest.node = config_.self;
    const Digest digest = genesis_eligibility_attest_digest(attest);
    crypto_sign_detached(attest.identity_signature.data(), nullptr, digest.data(), digest.size(),
                         config_.identity.private_key.data());
    (void)router_.broadcast(
        router_.compose(SecurityMessageKind::GenesisEligibilityAttest, attest, 1));
    (void)router_.send(genesis_id(),
                       router_.compose(SecurityMessageKind::GenesisEligibilityAttest, attest, 1));
    on_genesis_eligibility_attest(attest);
}

void SecurityDriver::on_genesis_eligibility_attest(const GenesisEligibilityAttest& attest) {
    if (genesis_ != nullptr && genesis_node() && !genesis_->finalized()) {
        if (genesis_->record_eligibility_attest(attest)) {
            spdlog::debug("[security] genesis: eligibility attest from {}",
                          crypto::to_hex(std::span<const uint8_t>(attest.node.bytes.data(), 8)));
        }
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
    if (!founding_eligibility_attests_.contains(attest.node)) {
        spdlog::info("[security] founding eligibility attest from {} ({}/{})",
                     crypto::to_hex(std::span<const uint8_t>(attest.node.bytes.data(), 8)),
                     founding_eligibility_attests_.size() + 1, founding_->members.size());
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
            spdlog::warn("[security] founding eligibility attest from {} disagrees: "
                         "theirs {} ours {}; the round cannot conclude",
                         crypto::to_hex(std::span<const uint8_t>(node.bytes.data(), 8)),
                         crypto::to_hex(std::span<const uint8_t>(value.data(), 8)),
                         crypto::to_hex(std::span<const uint8_t>(
                             founding_eligibility_digest_.data(), 8)));
            return;
        }
    }
    set_phase(DriverPhase::FoundingDkg, "founding eligibility agreed; starting the epoch-1 DKG");
    start_founding_dkg();
}

void SecurityDriver::start_founding_dkg() {
    founding_dkg_started_ms_ = now_ms_;
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
    runtime_.authority().observe_round1(*broadcast);
    (void)router_.broadcast(router_.compose(SecurityMessageKind::DkgBroadcast, *broadcast, 1));
}

void SecurityDriver::on_dkg_complete(EpochId target) {
    pending_dkg_ = take_dkg_result_keeping_outbox();
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
        pending_transcript_attest_ = attest;
        set_phase(DriverPhase::AwaitingBootstrap,
                  "DKG transcript attested; awaiting the bootstrap certificate");
        return;
    }
    if (phase_ == DriverPhase::PendingNextEpoch && adoption_.has_value() &&
        target == adoption_->plan.next_epoch) {
        // The share is prepared material and nothing more: it becomes usable
        // only at the finalized handoff. The attest travels so members outside
        // the ceremony can adopt the outcome the participants agree on.
        broadcast_transcript_attest(target);
        return;
    }
    EpochManager* epochs = runtime_.epochs();
    if (epochs != nullptr && epochs->transition() != nullptr &&
        target == epochs->transition()->to_epoch) {
        (void)epochs->record_dkg_result(pending_dkg_->group_public_key,
                                        pending_dkg_->transcript_digest);
        broadcast_transcript_attest(target);
    }
}

void SecurityDriver::broadcast_transcript_attest(EpochId target) {
    if (!pending_dkg_.has_value()) {
        return;
    }
    DkgTranscriptAttest attest;
    attest.epoch = target;
    attest.participant_set_digest = pending_dkg_->participant_set_digest;
    attest.transcript_digest = pending_dkg_->transcript_digest;
    attest.group_public_key = pending_dkg_->group_public_key;
    attest.node = config_.self;
    const Digest digest = dkg_transcript_attest_digest(attest);
    crypto_sign_detached(attest.identity_signature.data(), nullptr, digest.data(), digest.size(),
                         config_.identity.private_key.data());
    (void)router_.broadcast(
        router_.compose(SecurityMessageKind::DkgTranscriptAttest, attest, target));
}

void SecurityDriver::maybe_adopt_attested_transcript() {
    EpochManager* epochs = runtime_.epochs();
    const EpochTransition* transition = epochs != nullptr ? epochs->transition() : nullptr;
    if (transition == nullptr || transition->phase != EpochTransitionPhase::GeneratingAuthorityKey) {
        return;
    }
    // Every selected participant, and the same outcome from each — the Genesis
    // rule, applied to a transition. A member outside the ceremony adopts what
    // the whole ceremony signed, or nothing.
    const DkgTranscriptAttest* agreed = nullptr;
    for (const auto& node : transition->selected_members) {
        const auto it = transition_attests_.find(node);
        if (it == transition_attests_.end() ||
            it->second.participant_set_digest != transition->participant_set_digest) {
            return;
        }
        if (agreed == nullptr) {
            agreed = &it->second;
            continue;
        }
        if (it->second.transcript_digest != agreed->transcript_digest ||
            it->second.group_public_key != agreed->group_public_key) {
            return;
        }
    }
    if (agreed == nullptr) {
        return;
    }
    (void)epochs->record_dkg_result(agreed->group_public_key, agreed->transcript_digest);
}

void SecurityDriver::on_dkg_failed(DkgFailure, std::optional<NodeId> culprit) {
    runtime_.authority().abandon_dkg();
    if (phase_ == DriverPhase::GenesisEligibility || phase_ == DriverPhase::FoundingDkg ||
        phase_ == DriverPhase::AwaitingBootstrap) {
        // Await a fresh founding round; nothing was activated, and nothing of
        // this attempt may outlive it.
        founding_.reset();
        pending_dkg_.reset();
        pending_transcript_attest_.reset();
        founding_eligibility_digest_ = Digest{};
        founding_eligibility_attests_.clear();
        founding_challenge_ms_.clear();
        founding_dkg_started_ms_ = 0;
        issued_certificate_.reset();
        set_phase(DriverPhase::Idle, "founding DKG failed; awaiting a fresh round");
        return;
    }
    // A candidate's session failing resets it to pending; a fresh plan
    // renames or replaces it.
    if (phase_ == DriverPhase::PendingNextEpoch && adoption_.has_value()) {
        adoption_->dkg_authorized = false;
        pending_dkg_.reset();
        return;
    }
    EpochManager* epochs = runtime_.epochs();
    if (epochs != nullptr && epochs->transition() != nullptr) {
        // The selected set is a finalized plan now, so membership cannot change
        // under it. A failed participant means a NEW plan — next attempt, next
        // hash-ranked replacement, fresh DKG. Nothing of this attempt survives.
        if (culprit.has_value()) {
            boundary_failed_.insert(*culprit);
        }
        pending_dkg_.reset();
        abandon_boundary("DKG failed; a new plan replaces the attempt");
    }
}

void SecurityDriver::on_dkg_transcript_attest(const DkgTranscriptAttest& attest) {
    // The transition form: a ceremony participant attests the outcome so a
    // current member outside the ceremony can adopt it once every participant
    // signed the same one.
    EpochManager* epochs = runtime_.epochs();
    if (epochs != nullptr) {
        const EpochTransition* transition = epochs->transition();
        if (transition == nullptr || attest.epoch != transition->to_epoch ||
            !plan_.has_value()) {
            return;
        }
        const bool selected = std::find(transition->selected_members.begin(),
                                        transition->selected_members.end(),
                                        attest.node) != transition->selected_members.end();
        if (!selected) {
            return;
        }
        const Digest digest = dkg_transcript_attest_digest(attest);
        if (crypto_sign_verify_detached(attest.identity_signature.data(), digest.data(),
                                        digest.size(), attest.node.bytes.data()) != 0) {
            return;
        }
        transition_attests_[attest.node] = attest;
        maybe_adopt_attested_transcript();
        return;
    }
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
    std::map<NodeId, crypto::Ed25519PublicKey> founder_keys;
    for (const auto& node : founders->members()) {
        founder_keys[node] = founder_vote_keys_.at(node);
    }
    const auto certificate = genesis_->finalize_epoch_one(
        attest.group_public_key, attest.transcript_digest, genesis_attestation_root(*founders),
        vote_key_set_digest(founder_keys), config_.release_approval_digest,
        config_.identity.private_key);
    if (!certificate.has_value()) {
        return;
    }
    (void)store_.store_bootstrap(*certificate);
    issued_certificate_ = *certificate;
    certificate_issued_ms_ = now_ms_;
    (void)router_.broadcast(
        router_.compose(SecurityMessageKind::BootstrapCertificate, *certificate, 1));
    // Genesis unilateral authority ends here; this node continues as an
    // ordinary server.
    set_phase(DriverPhase::Idle, "bootstrap certificate issued; genesis authority ends");
    // The anchor never enters Active, but the certificate it just issued is
    // the same finalized authority.
    if (on_epoch_established_) on_epoch_established_();
}

void SecurityDriver::on_bootstrap_certificate(const BootstrapCertificate& certificate,
                                              const NodeId& from) {
    // Every node keeps the verified certificate as its trust anchor: the
    // pinned genesis signature is what a later candidate verifies a supplied
    // membership listing against. Storing it grants nothing.
    if (!anchor_.has_value() && bootstrap_valid_for(
                                    certificate, config_.genesis_public_key,
                                    derive_network_id(config_.genesis_public_key,
                                                      constants::kSecurityRulesetVersion,
                                                      constants::kConsensusRulesetVersion))) {
        anchor_ = certificate;
        if (genesis_node() && genesis_ != nullptr) {
            genesis_->restore_finalized();
            (void)store_.store_bootstrap(certificate);
            if (runtime_.epochs() == nullptr) {
                set_phase(DriverPhase::Idle,
                          "authenticated bootstrap certificate ends genesis authority");
            }
        }
    }
    if (from != genesis_id() || phase_ != DriverPhase::AwaitingBootstrap ||
        !founding_.has_value() || !pending_dkg_.has_value() || runtime_.epochs() != nullptr) {
        return;
    }
    // Genesis may only certify the founding eligibility the founders computed.
    // A certificate naming anything else is refused rather than adopted.
    if (certificate.founding_eligibility_digest != founding_eligibility_digest_) {
        return;
    }
    // And only the release selection this node bootstrapped under. After this
    // adoption the commitment is epoch state; Genesis cannot replace it.
    if (certificate.release_approval_digest != config_.release_approval_digest) {
        spdlog::warn("[security] bootstrap certificate commits a different release approval; "
                     "refusing adoption");
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
    // The verified chain starts here: Epoch 1 under the pinned signature. The
    // base listing persists beside it, so this node can serve the walk.
    if (auto epoch_one = verify_epoch_one_authority(certificate, config_.genesis_public_key,
                                                    founding_->members)) {
        (void)store_.store_chain_base(founding_->members);
        install_authority(std::move(*epoch_one));
    }
    if (!enter_eligibility_epoch(1, runtime_.epochs()->current().tier1_members)) {
        set_phase(DriverPhase::Failed, "durable eligibility state is corrupt");
        return;
    }
    dkg_outbox_.reset();
    set_phase(DriverPhase::Active, "epoch 1 adopted and active");
    epoch_started_ms_ = now_ms_;
    last_progress_ms_ = now_ms_;
    announce_epoch(checkpoint, certificate.dkg_transcript_digest);
}

// --- Vote keys ---------------------------------------------------------------

std::optional<crypto::Ed25519PublicKey> SecurityDriver::vote_key_for_epoch(EpochId epoch) {
    const auto known = vote_pubs_mine_.find(epoch);
    if (known != vote_pubs_mine_.end()) {
        return known->second;
    }
    // A candidate creates its next-epoch key only after the plan is verified
    // and the security state is synchronized. Before that there is nothing to
    // register a key against, and answering a final-attest challenge early
    // would bind a key to a preparation that was never authorized.
    if (adoption_.has_value() && epoch == adoption_->plan.next_epoch &&
        !adoption_->state_synced) {
        return std::nullopt;
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
    if (it == vote_keys_mine_.end()) {
        // The public half exists but the private half was already consumed, or
        // creation was refused. An empty key fails every later check closed
        // instead of erasing through an end iterator.
        return EpochVoteKey{};
    }
    EpochVoteKey key = std::move(it->second);
    vote_keys_mine_.erase(it);
    return key;
}

// --- Attestation and the epoch cadence --------------------------------------

bool SecurityDriver::eligibility_verdict_ok(const AttestationVerdict& verdict) const {
    // The verdict must have been produced for the ordinary eligibility purpose
    // and its canonical context. Final-readiness evidence relabelled as
    // eligibility names a different context and dies here. The network comes
    // from the pinned genesis key: it exists before any epoch does.
    const NetworkId network = derive_network_id(config_.genesis_public_key,
                                                constants::kSecurityRulesetVersion,
                                                constants::kConsensusRulesetVersion);
    return verdict.purpose == AttestationPurpose::Eligibility &&
           verdict.context_digest ==
               eligibility_attestation_context(network, verdict.epoch, verdict.node_id,
                                               verdict.incarnation);
}

void SecurityDriver::on_attestation_verdict(const AttestationVerdict& verdict,
                                            const AttestationEvidence& evidence) {
    if (verdict.purpose == AttestationPurpose::StorageUnlock) {
        // Unlock evidence answers one storage request. It confers no
        // eligibility and no readiness, so it never reaches either path.
        if (storage_verdict_sink_) {
            storage_verdict_sink_(verdict);
        }
        return;
    }
    if (verdict.purpose == AttestationPurpose::UpgradeHealth) {
        // Same rule: upgrade-health evidence answers one upgrade chain
        // position and confers nothing else.
        if (upgrade_verdict_sink_) {
            upgrade_verdict_sink_(verdict);
        }
        return;
    }
    if (phase_ == DriverPhase::GenesisCollecting && genesis_ != nullptr &&
        !genesis_->finalized()) {
        if (!eligibility_verdict_ok(verdict)) {
            return;
        }
        if (!genesis_->record_verdict(verdict)) {
            return;
        }
        spdlog::info("[security] genesis verdict for {}: {} (failure={})",
                     crypto::to_hex(std::span<const uint8_t>(verdict.node_id.bytes.data(), 8)),
                     verdict.passed ? "PASSED" : "failed",
                     static_cast<uint16_t>(verdict.failure));
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
        if (!eligibility_verdict_ok(verdict)) {
            return;
        }
        record_founding_observation(verdict);
        return;
    }

    EpochManager* epochs = runtime_.epochs();
    if (epochs == nullptr) {
        return;
    }
    if (verdict.epoch == epochs->current().id) {
        if (!eligibility_verdict_ok(verdict)) {
            return;
        }
        // Local re-attestation creates a candidate observation and nothing
        // more. One verifier's word is not a mesh fact: the statement is signed
        // and published, and a quorum of observers is what makes it count.
        eligibility_.record_verdict(verdict);
        if (auto observation = eligibility_.observe_attestation(
                verdict.node_id, last_committed_height_, last_committed_root_)) {
            publish(*observation, epochs->current().id);
        }
        return;
    }
    const EpochTransition* transition = epochs->transition();
    if (transition != nullptr && verdict.epoch == transition->to_epoch) {
        // Final readiness accepts only evidence produced for exactly this
        // plan, attempt and selected set. An ordinary eligibility verdict —
        // or one for a superseded plan — names a different context.
        if (verdict.purpose != AttestationPurpose::FinalEpochReadiness ||
            !plan_.has_value() ||
            verdict.context_digest != plan_attest_context(*plan_, verdict.node_id)) {
            return;
        }
        (void)epochs->record_final_attestation(verdict);
        if (verdict.passed) {
            final_verdict_ms_[verdict.node_id] = now_ms_;
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
        // Members and certified Tier 2 peers alike: a node must be able to
        // prove eligibility for Tier 1 without already being Tier 1.
        std::set<NodeId> subjects(certified_peers_.begin(), certified_peers_.end());
        for (const auto& member : current.tier1_members.members()) {
            subjects.insert(member);
        }
        for (const auto& subject : subjects) {
            if (subject == config_.self) {
                continue;
            }
            crypto::Ed25519PublicKey subject_key{};
            subject_key = subject.bytes;
            auto challenge = runtime_.attestation().create_challenge(
                subject, subject_key, 1, current.id, AttestationPurpose::Eligibility);
            if (challenge.has_value()) {
                (void)router_.send(
                    subject, router_.compose(SecurityMessageKind::AttestationChallenge,
                                             *challenge, current.id));
            }
            // A current member proves participation by voting. A candidate
            // holds no vote key, so it answers a challenge instead.
            if (!current.tier1_members.contains(subject)) {
                challenge_participation(subject);
            }
        }
    }

    // Selection now waits on two commitments in order: the finalized
    // eligibility state, then the finalized plan derived from it. Both travel
    // through maybe_propose; nothing here prepares anything locally.
}

Digest SecurityDriver::plan_attest_context(const NextEpochPlan& plan, const NodeId& node) {
    const auto set = Tier1Set::from_nodes(plan.selected);
    const auto incarnation = plan.incarnations.find(node);
    if (!set.has_value() || incarnation == plan.incarnations.end()) {
        // No canonical context exists; an empty digest fails every later
        // check closed, starting with challenge creation itself.
        return Digest{};
    }
    return final_readiness_attestation_context(plan.network_id, plan.next_epoch,
                                               next_epoch_plan_digest(plan), plan.attempt,
                                               set->digest(), node, incarnation->second);
}

void SecurityDriver::attest_self_for(EpochId epoch, const Digest& context) {
    auto challenge = runtime_.attestation().create_challenge(
        config_.self, config_.identity.public_key, 1, epoch,
        AttestationPurpose::FinalEpochReadiness, context);
    if (challenge.has_value()) {
        (void)router_.deliver_local(
            router_.compose(SecurityMessageKind::AttestationChallenge, *challenge, epoch), now_ms_);
    }
}

void SecurityDriver::maybe_start_next_dkg() {
    EpochManager* epochs = runtime_.epochs();
    const EpochTransition* transition = epochs->transition();
    if (transition == nullptr || transition->phase != EpochTransitionPhase::GeneratingAuthorityKey ||
        runtime_.authority().dkg() != nullptr || pending_dkg_.has_value()) {
        return;
    }
    // No readiness commit, no DKG. Current HotStuff authorizes the session;
    // one member deciding a candidate is ready authorizes nothing.
    if (!readiness_.has_value() || !plan_.has_value()) {
        return;
    }
    // Only a selected participant runs the ceremony. A current member outside
    // the next set follows it through the signed transcript attests instead —
    // a session it is not part of would only misread the traffic as failure.
    if (std::find(transition->selected_members.begin(), transition->selected_members.end(),
                  config_.self) == transition->selected_members.end()) {
        return;
    }
    auto set = Tier1Set::from_nodes(transition->selected_members);
    if (!set.has_value()) {
        return;
    }
    DkgConfiguration dkg;
    dkg.network_id = epochs->current().network_id;
    dkg.target_epoch = transition->to_epoch;
    dkg.participants = std::move(*set);
    dkg.incarnations = plan_->incarnations;
    dkg.threshold = transition->next_authority_threshold;
    dkg.self = config_.self;
    // The binding folds plan, attempt, selected set and registered keys into
    // every message: a replay from a failed attempt names a session nobody
    // is running.
    dkg.session_binding = candidate_readiness_digest(*readiness_);
    auto broadcast = runtime_.authority().start_dkg(std::move(dkg));
    if (broadcast.has_value()) {
        runtime_.authority().observe_round1(*broadcast);
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

void SecurityDriver::on_justify_quorum(const QuorumCertificate& certificate) {
    const EpochManager* epochs = runtime_.epochs();
    const HotStuffService* consensus = runtime_.consensus();
    if (phase_ != DriverPhase::Active || epochs == nullptr || consensus == nullptr ||
        !consensus->synced()) {
        return;
    }
    if (certificate.epoch != epochs->current().id) {
        return;
    }
    // Every signer of a validated certificate proved participation at its
    // height, and every replica holds the same certificate — so the witness
    // evidence cannot depend on which leader happened to collect the votes.
    for (const auto& signer : certificate.signers) {
        ParticipationProof proof;
        proof.network_id = certificate.network_id;
        proof.epoch = certificate.epoch;
        proof.consensus_ruleset = certificate.consensus_ruleset;
        proof.subject = signer.node_id;
        proof.incarnation = 1;
        proof.subject_height = certificate.height;
        if (auto observation = eligibility_.observe_participation(proof, last_committed_height_,
                                                                  last_committed_root_)) {
            publish(*observation, epochs->current().id);
        }
    }
}

void SecurityDriver::on_eligibility_observation(const EligibilityObservation& observation) {
    (void)eligibility_.accept(observation);
    maybe_attest_founding_eligibility();
}

void SecurityDriver::challenge_participation(const NodeId& candidate) {
    ParticipationChallenge challenge;
    challenge.network_id = runtime_.epochs()->current().network_id;
    challenge.epoch = runtime_.epochs()->current().id;
    challenge.security_ruleset = constants::kSecurityRulesetVersion;
    challenge.consensus_ruleset = constants::kConsensusRulesetVersion;
    challenge.node_id = candidate;
    challenge.incarnation = 1;
    randombytes_buf(challenge.nonce.data(), challenge.nonce.size());
    // The observer names the finalized state, so it knows the value the answer
    // is anchored to without taking the candidate's word for anything.
    challenge.anchor_height = last_committed_height_;
    challenge.anchor_state = last_committed_root_;
    challenge.observer = config_.self;

    pending_participation_[candidate] = challenge;
    (void)router_.send(candidate,
                       router_.compose(SecurityMessageKind::ParticipationChallenge, challenge,
                                       challenge.epoch));
}

void SecurityDriver::on_participation_challenge(const ParticipationChallenge& challenge,
                                                const NodeId& from) {
    // A node answers only a challenge naming itself, and only under its own
    // identity key. Answering grants nothing: it is evidence for an observer.
    if (challenge.node_id != config_.self || from == config_.self) {
        return;
    }
    if (challenge.security_ruleset != constants::kSecurityRulesetVersion ||
        challenge.consensus_ruleset != constants::kConsensusRulesetVersion) {
        return;
    }
    const ParticipationResponse response =
        answer_participation_challenge(challenge, config_.identity);
    (void)router_.send(from, router_.compose(SecurityMessageKind::ParticipationResponse, response,
                                             challenge.epoch));
}

void SecurityDriver::on_participation_response(const ParticipationResponse& response) {
    const EpochManager* epochs = runtime_.epochs();
    if (phase_ != DriverPhase::Active || epochs == nullptr) {
        return;
    }
    const auto pending = pending_participation_.find(response.node_id);
    if (pending == pending_participation_.end()) {
        return;
    }
    // Match before consume, so a replayed answer cannot spend the challenge a
    // live one is still coming for.
    if (response.challenge_digest != participation_challenge_digest(pending->second)) {
        return;
    }
    const ParticipationChallenge challenge = pending->second;
    pending_participation_.erase(pending);

    if (auto observation = eligibility_.observe_participation_response(
            response, challenge, challenge.anchor_height, challenge.anchor_state)) {
        publish(*observation, epochs->current().id);
    }
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
    const auto handoff = derive_handoff();
    return handoff.has_value() ? epoch_handoff_digest(*handoff) : Digest{};
}

std::optional<NextEpochPlan> SecurityDriver::derive_plan() const {
    const EpochManager* epochs = runtime_.epochs();
    const auto* finalized = eligibility_.finalized();
    if (epochs == nullptr || finalized == nullptr) {
        return std::nullopt;
    }
    const auto pool = eligibility_.frozen_pool(finalized->next_epoch);
    if (!pool.has_value()) {
        return std::nullopt;
    }
    const auto selected =
        epochs->preview_selection(*pool, pool->size(), boundary_failed_);
    if (selected.empty()) {
        return std::nullopt;
    }
    NextEpochPlan plan;
    plan.network_id = epochs->current().network_id;
    plan.current_epoch = epochs->current().id;
    plan.next_epoch = finalized->next_epoch;
    plan.attempt = plans_committed_;
    plan.checkpoint_height = finalized->height;
    plan.checkpoint_state_root = finalized->state_root;
    plan.eligibility_commitment = finalized->commitment;
    plan.selection_seed = epochs->current().authority_public_key;
    plan.selected = selected;
    for (const auto& node : selected) {
        plan.incarnations[node] = 1;
    }
    plan.security_ruleset = constants::kSecurityRulesetVersion;
    plan.consensus_ruleset = constants::kConsensusRulesetVersion;
    plan.profile_id = kTier1AttestationProfileId;
    plan.profile_ruleset = kAttestationProfileRulesetVersion;
    return plan;
}

std::optional<CandidateReadiness> SecurityDriver::derive_readiness() const {
    const EpochManager* epochs = runtime_.epochs();
    if (epochs == nullptr || !plan_.has_value() || epochs->transition() == nullptr ||
        epochs->transition()->phase != EpochTransitionPhase::GeneratingAuthorityKey) {
        return std::nullopt;
    }
    CandidateReadiness readiness;
    readiness.network_id = plan_->network_id;
    readiness.plan_digest = next_epoch_plan_digest(*plan_);
    readiness.next_epoch = plan_->next_epoch;
    const auto& verdicts = epochs->final_verdicts();
    const auto& keys = epochs->next_vote_keys();
    for (const auto& node : epochs->transition()->selected_members) {
        const auto verdict = verdicts.find(node);
        const auto key = keys.find(node);
        if (verdict == verdicts.end() || !verdict->second.passed || key == keys.end()) {
            return std::nullopt;
        }
        // The final attestation must have proved every required claim through
        // the provider-neutral path. A verdict that somehow passed without
        // them confers no readiness.
        if (!platform_claims_are_consistent(verdict->second.claims) ||
            !all_platform_claims_proved(verdict->second.claims)) {
            return std::nullopt;
        }
        // And it must have been produced for exactly this plan's context —
        // the second layer of the binding, checked where readiness forms.
        if (verdict->second.purpose != AttestationPurpose::FinalEpochReadiness ||
            verdict->second.context_digest != plan_attest_context(*plan_, node)) {
            return std::nullopt;
        }
        // Readiness rests on a FRESH final attestation. A verdict past the
        // compiled age names a platform state nobody has seen recently, so the
        // set is not proposable until re-attestation renews it.
        const auto seen = final_verdict_ms_.find(node);
        if (seen == final_verdict_ms_.end() ||
            now_ms_ - seen->second > constants::kFinalAttestMaxAgeSeconds * 1000) {
            return std::nullopt;
        }
        // A selected node from outside the current epoch must have proved it
        // acquired current certified state; a current member proves the same
        // fact continuously by voting.
        if (!epochs->current().tier1_members.contains(node) && node != config_.self &&
            !state_ready_.contains(node)) {
            return std::nullopt;
        }
        const auto incarnation = plan_->incarnations.find(node);
        if (incarnation == plan_->incarnations.end()) {
            // A selected node the plan does not name: the transition diverged
            // from its plan, so nothing here is proposable.
            return std::nullopt;
        }
        // The plan-bound context, not this member's evidence digest: each
        // member verified different evidence (its own nonce), and readiness
        // commits only when every voter derives the same record.
        readiness.entries.push_back({node, incarnation->second, verdict->second.context_digest,
                                     key->second});
    }
    std::sort(readiness.entries.begin(), readiness.entries.end());
    return readiness;
}

std::optional<EpochHandoff> SecurityDriver::derive_handoff() const {
    const EpochManager* epochs = runtime_.epochs();
    if (epochs == nullptr || !plan_.has_value() || epochs->transition() == nullptr ||
        epochs->transition()->phase != EpochTransitionPhase::Ready) {
        return std::nullopt;
    }
    // No verified anchor for the current epoch, no handoff: the record must
    // name its predecessor, and a guess would just fail every verifier.
    if (!authority_.has_value() || authority_->epoch != epochs->current().id) {
        return std::nullopt;
    }
    const EpochTransition& transition = *epochs->transition();
    EpochHandoff handoff;
    handoff.network_id = plan_->network_id;
    handoff.from_epoch = transition.from_epoch;
    handoff.to_epoch = transition.to_epoch;
    handoff.plan_digest = next_epoch_plan_digest(*plan_);
    handoff.previous_anchor = authority_->anchor_digest;
    handoff.members = transition.selected_members;
    for (const auto& node : transition.selected_members) {
        const auto incarnation = plan_->incarnations.find(node);
        handoff.incarnations[node] =
            incarnation != plan_->incarnations.end() ? incarnation->second : 1;
    }
    handoff.vote_keys = epochs->next_vote_keys();
    handoff.group_public_key = transition.next_authority_key;
    handoff.dkg_transcript_digest = transition.dkg_transcript_digest;
    handoff.key_generation = KeyGeneration(transition.to_epoch.underlying());
    handoff.attestation_root = transition.attestation_root;
    handoff.security_ruleset = constants::kSecurityRulesetVersion;
    handoff.consensus_ruleset = constants::kConsensusRulesetVersion;
    return handoff;
}

Digest SecurityDriver::pending_plan_digest() const {
    const EpochManager* epochs = runtime_.epochs();
    if (phase_ != DriverPhase::Active || epochs == nullptr || plan_.has_value()) {
        return Digest{};
    }
    if (!epoch_aged(now_ms_)) {
        return Digest{};
    }
    if (epochs->transition() != nullptr &&
        epochs->transition()->phase != EpochTransitionPhase::Aborted) {
        return Digest{};
    }
    const auto plan = derive_plan();
    return plan.has_value() ? next_epoch_plan_digest(*plan) : Digest{};
}

Digest SecurityDriver::pending_readiness_digest() const {
    if (readiness_.has_value()) {
        return Digest{};
    }
    const auto readiness = derive_readiness();
    return readiness.has_value() ? candidate_readiness_digest(*readiness) : Digest{};
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
    // One stage is pending at a time; a replica votes only for the stage it
    // independently arrived at.
    for (const Digest pending : {pending_handoff_digest(), pending_readiness_digest(),
                                 pending_plan_digest(), pending_eligibility_digest()}) {
        if (pending != Digest{} && transitions_digest == pending) {
            return true;
        }
    }
    return false;
}

void SecurityDriver::maybe_propose(View view) {
    HotStuffService* consensus = runtime_.consensus();
    if (consensus == nullptr || !consensus->synced() || view <= last_proposed_view_ ||
        consensus->current_view() != view || consensus->leader_of(view) != config_.self) {
        return;
    }
    // A boundary produces four transitions in order: the eligibility state,
    // the plan selected from it, the readiness set proved under the plan, and
    // the handoff that activates. Exactly one is pending at a time.
    Digest transitions = pending_handoff_digest();
    if (transitions == Digest{}) transitions = pending_readiness_digest();
    if (transitions == Digest{}) transitions = pending_plan_digest();
    if (transitions == Digest{}) transitions = pending_eligibility_digest();
    // Stages keep priority: a payload block is proposed only when no stage is
    // pending, so a block never carries both.
    std::optional<ProposedPayload> payload;
    if (transitions == Digest{}) {
        for (const auto& [kind, handler] : payload_handlers_) {
            payload = handler->propose(*consensus);
            if (payload.has_value()) break;
        }
    }
    const auto make = [&](const std::optional<ProposedPayload>& carried)
        -> std::optional<ProposalMessage> {
        Digest previous = last_committed_root_;
        Digest proposed{};
        Digest digest = transitions;
        if (carried.has_value()) {
            // The payload's handler defines its roots (a tree batch commits to
            // the tree state, design A5).
            digest = block_payload_digest(carried->payload);
            previous = carried->previous_state_root;
            proposed = carried->proposed_state_root;
        } else {
            // The transition is inside the state root, so finalizing the block
            // finalizes the eligibility state it names.
            CanonicalEncoder root("lemonade-nexus/state-root:v1");
            root.add_bytes(last_committed_root_);
            root.add_bytes(transitions);
            proposed = root.digest();
        }
        auto made = consensus->make_proposal(previous, proposed, digest);
        if (!std::holds_alternative<Proposal>(made)) {
            return std::nullopt;
        }
        ProposalMessage message{std::get<Proposal>(made), consensus->state().high_qc,
                                std::nullopt};
        if (carried.has_value()) {
            message.proposal.timestamp_hint = carried->timestamp_hint;
            message.payload = carried->payload;
        }
        return message;
    };
    const EpochId epoch = current_epoch().value_or(0);
    auto message = make(payload);
    if (message.has_value() && payload.has_value() &&
        encode_security_message(
            router_.compose(SecurityMessageKind::HotStuffProposal, *message, epoch))
            .empty()) {
        // A payload that does not fit the envelope would reach only this
        // node. Propose an ordinary block instead; the payload waits.
        spdlog::warn("[security] block payload does not fit a proposal message; "
                     "proposing without it");
        message = make(std::nullopt);
    }
    if (!message.has_value()) {
        return;
    }
    last_proposed_view_ = view;
    auto envelope = router_.compose(SecurityMessageKind::HotStuffProposal, *message, epoch);
    (void)router_.broadcast(envelope);
    (void)router_.deliver_local(std::move(envelope), now_ms_);
}

void SecurityDriver::register_payload_handler(IBlockPayloadHandler& handler) {
    payload_handlers_[handler.kind()] = &handler;
}

bool SecurityDriver::accepts_payload(const Proposal& proposal, const BlockPayload& payload) const {
    const auto handler = payload_handlers_.find(payload.kind);
    const HotStuffService* consensus = runtime_.consensus();
    if (handler == payload_handlers_.end() || consensus == nullptr) {
        return false;
    }
    return handler->second->validate(*consensus, proposal, payload);
}

void SecurityDriver::on_tree_op_submit(const TreeOpSubmitMsg& message, const NodeId& from) {
    if (tree_op_sink_) {
        tree_op_sink_(message, from);
    }
}

void SecurityDriver::on_storage_message(const SecurityMessage& message) {
    if (storage_sink_) {
        storage_sink_(message);
    }
}

void SecurityDriver::on_upgrade_message(const SecurityMessage& message) {
    if (upgrade_sink_) {
        upgrade_sink_(message);
    }
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
        // A payload block goes to its kind's handler, in commit order. Its
        // digest is domain-separated from every stage digest, so it can never
        // be mistaken for one.
        if (const HotStuffService* consensus = runtime_.consensus()) {
            if (const BlockPayload* payload = consensus->block_payload(commit.proposal_digest)) {
                const auto handler = payload_handlers_.find(payload->kind);
                const Proposal* proposal = consensus->block(commit.proposal_digest);
                if (handler != payload_handlers_.end() && proposal != nullptr) {
                    CommittedPayload committed;
                    committed.commit = commit;
                    committed.proposal = *proposal;
                    committed.payload = payload;
                    committed.proof = consensus->commit_proof(commit.proposal_digest);
                    handler->second->on_committed(committed);
                }
                continue;
            }
        }
        EpochManager* epochs = runtime_.epochs();
        if (epochs == nullptr) {
            continue;
        }
        // A committed stage is finalized state. A node that arrived at
        // different facts recognizes nothing here, so it never advances and
        // never selects — availability, never authority.
        const Digest eligibility = pending_eligibility_digest();
        if (eligibility != Digest{} && commit.transitions_digest == eligibility) {
            eligibility_.finalize({.commitment = commit.transitions_digest,
                                   .consensus_reference = commit.qc_digest,
                                   .height = commit.height,
                                   .state_root = commit.proposed_state_root,
                                   .next_epoch = epochs->current().id + 1});
            if (on_eligibility_finalized_) {
                if (const auto pool = eligibility_.frozen_pool(epochs->current().id + 1)) {
                    on_eligibility_finalized_(*eligibility_.finalized(), *pool);
                }
            }
            continue;
        }
        const Digest plan = pending_plan_digest();
        if (plan != Digest{} && commit.transitions_digest == plan) {
            on_plan_committed(commit);
            continue;
        }
        const Digest readiness = pending_readiness_digest();
        if (readiness != Digest{} && commit.transitions_digest == readiness) {
            on_readiness_committed(commit);
            continue;
        }
        const Digest handoff = pending_handoff_digest();
        if (handoff != Digest{} && commit.transitions_digest == handoff) {
            const auto record = derive_handoff();
            if (epochs->record_handoff_authorization(commit.qc_digest)) {
                // The newcomers activate from this exact proof; it goes out
                // before this member's own state moves on.
                const auto proof = runtime_.consensus() != nullptr
                                       ? runtime_.consensus()->commit_proof(commit.proposal_digest)
                                       : std::nullopt;
                if (record.has_value() && proof.has_value()) {
                    const auto message = router_.compose(
                        SecurityMessageKind::EpochHandoffProof,
                        EpochHandoffProofMsg{*record, *proof}, epochs->current().id);
                    (void)router_.broadcast(message);
                    // The finalized handoff is the next chain link. The same
                    // verification a stranger runs advances this member's own
                    // anchor — nothing here is taken on this node's word.
                    auto advanced = advance_epoch_authority(*authority_, *record, *proof);
                    if (auto* next = std::get_if<VerifiedEpochAuthority>(&advanced)) {
                        (void)store_.append_chain_link(encode_security_message(message));
                        install_authority(std::move(*next));
                    }
                }
                do_activate(commit.qc_digest);
            }
        }
    }
}

void SecurityDriver::on_plan_committed(const ConsensusCommit& commit) {
    EpochManager* epochs = runtime_.epochs();
    auto plan = derive_plan();
    if (!plan.has_value()) {
        return;
    }
    const auto pool = eligibility_.frozen_pool(plan->next_epoch);
    if (!pool.has_value() || !epochs->prepare_planned_epoch(*pool, plan->selected)) {
        return;
    }
    plan_ = std::move(plan);
    ++plans_committed_;
    state_ready_.clear();

    // The plan travels to the selected candidates with its commit proof, so a
    // node outside this epoch can verify the finality itself.
    if (HotStuffService* consensus = runtime_.consensus()) {
        if (auto proof = consensus->commit_proof(commit.proposal_digest)) {
            plan_proof_ = *proof;
            NextEpochPlanProof package;
            package.plan = *plan_;
            package.proof = *proof;
            for (const auto& [node, key] : epochs->current_vote_keys()) {
                package.current_vote_keys.emplace_back(node, key);
            }
            broadcast_proof(SecurityMessageKind::NextEpochPlanProof, package,
                            epochs->current().id);
        }
    }

    // Final-attestation challenges to every selected node, this one included.
    issue_final_challenges(false);
}

void SecurityDriver::issue_final_challenges(bool stale_only) {
    // Each challenge binds the plan context, so the answer commits to exactly
    // this plan, attempt and selected set — not merely to the target epoch.
    //
    // Readiness rests on FRESH attestations, and a boundary can outlive their
    // freshness — slow candidates, view recovery. The renewal pass re-asks
    // exactly the nodes whose proof aged out, at most once per freshness
    // window each. The budget is scoped to this attempt's context: when it
    // refuses a node the boundary still needs, the ATTEMPT is over — never
    // the boundary. The nodes that never fulfilled their part are excluded
    // for this boundary, and the replacement plan carries a fresh budget.
    const EpochId target = plan_->next_epoch;
    bool starved = false;
    for (const auto& member : plan_->selected) {
        if (stale_only) {
            const auto seen = final_verdict_ms_.find(member);
            const bool fresh =
                seen != final_verdict_ms_.end() &&
                now_ms_ - seen->second <= constants::kFinalAttestMaxAgeSeconds * 1000;
            if (fresh) {
                continue;
            }
            const auto asked = final_challenge_ms_.find(member);
            if (asked != final_challenge_ms_.end() &&
                now_ms_ - asked->second < constants::kFinalAttestMaxAgeSeconds * 1000) {
                continue;
            }
        }
        final_challenge_ms_[member] = now_ms_;
        const Digest context = plan_attest_context(*plan_, member);
        if (member == config_.self) {
            attest_self_for(target, context);
            continue;
        }
        crypto::Ed25519PublicKey member_key{};
        member_key = member.bytes;
        auto challenge = runtime_.attestation().create_challenge(
            member, member_key, 1, target, AttestationPurpose::FinalEpochReadiness, context);
        if (challenge.has_value()) {
            (void)router_.send(member,
                               router_.compose(SecurityMessageKind::AttestationChallenge,
                                               *challenge, target));
        } else if (stale_only) {
            starved = true;
        }
    }
    if (starved) {
        fail_starved_attempt();
    }
}

void SecurityDriver::fail_starved_attempt() {
    // The attempt's attestation budget ran dry with the readiness set still
    // incomplete. Exclude exactly the selected nodes that never fulfilled a
    // requirement this whole attempt — no verdict at all, or no state
    // possession statement — and let the deterministic replacement run. A
    // node that answered and merely went stale is selected again with a
    // fresh budget. Nothing here is a fault: exhaustion proves only that
    // this attempt is over.
    const EpochManager* epochs = runtime_.epochs();
    for (const auto& member : plan_->selected) {
        if (member == config_.self) {
            continue;
        }
        const bool attested = final_verdict_ms_.contains(member);
        const bool incumbent = epochs->current().tier1_members.contains(member);
        const bool possession = incumbent || state_ready_.contains(member);
        if (!attested || !possession) {
            boundary_failed_.insert(member);
        }
    }
    runtime_.authority().abandon_dkg();
    pending_dkg_.reset();
    abandon_boundary("final-attestation budget exhausted; the attempt is replaced");
}

void SecurityDriver::maybe_renew_final_attestation() {
    // Only while the readiness set is still forming. Once it committed, the
    // finalized record stands for a quorum of fresh verifications and
    // freshness no longer gates anything.
    const EpochManager* epochs = runtime_.epochs();
    const EpochTransition* transition = epochs->transition();
    if (transition == nullptr || readiness_.has_value() || !plan_.has_value() ||
        transition->phase == EpochTransitionPhase::Aborted ||
        transition->phase == EpochTransitionPhase::Ready) {
        return;
    }
    issue_final_challenges(true);
}

void SecurityDriver::on_readiness_committed(const ConsensusCommit& commit) {
    auto readiness = derive_readiness();
    if (!readiness.has_value()) {
        return;
    }
    readiness_ = std::move(readiness);
    dkg_authorized_ms_ = now_ms_;
    if (HotStuffService* consensus = runtime_.consensus()) {
        if (auto proof = consensus->commit_proof(commit.proposal_digest)) {
            readiness_proof_ = *proof;
            broadcast_proof(SecurityMessageKind::ReadinessProof,
                            ReadinessProofMsg{*readiness_, *proof},
                            runtime_.epochs()->current().id);
        }
    }
    maybe_start_next_dkg();
}

void SecurityDriver::broadcast_proof(SecurityMessageKind kind, SecurityBody body, EpochId epoch) {
    (void)router_.broadcast(router_.compose(kind, std::move(body), epoch));
}

void SecurityDriver::abandon_boundary(const char* reason) {
    spdlog::info("[security] boundary abandoned: {}", reason);
    dkg_outbox_.reset();
    plan_.reset();
    readiness_.reset();
    dkg_authorized_ms_ = 0;
    state_ready_.clear();
    final_verdict_ms_.clear();
    final_challenge_ms_.clear();
    transition_attests_.clear();
    EpochManager* epochs = runtime_.epochs();
    if (epochs != nullptr && epochs->transition() != nullptr) {
        epochs->abort_transition(EpochTransitionFailure::DkgFailed);
    }
}

void SecurityDriver::do_activate(const Digest& checkpoint) {
    EpochManager* epochs = runtime_.epochs();
    const EpochTransition* transition = epochs->transition();
    if (transition == nullptr) {
        return;
    }
    dkg_outbox_.reset();
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
    spdlog::info("[security] epoch {} activated", to_epoch.underlying());
    persist_current_epoch(checkpoint);
    (void)store_.append_authority({to_epoch, epochs->current().authority_public_key,
                                   epochs->current().participant_set_digest, dkg_digest});
    store_.discard_vote_key(old_epoch);
    clear_boundary_state();
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
    for (const auto& [kind, handler] : payload_handlers_) {
        handler->on_consensus_reset();
    }
    announce_epoch(checkpoint, dkg_digest);
}

void SecurityDriver::clear_boundary_state() {
    plan_.reset();
    readiness_.reset();
    state_ready_.clear();
    boundary_failed_.clear();
    final_verdict_ms_.clear();
    final_challenge_ms_.clear();
    transition_attests_.clear();
    plans_committed_ = 0;
    dkg_authorized_ms_ = 0;
}

bool SecurityDriver::follow_finalized_handoff(const EpochHandoffProofMsg& link) {
    EpochManager* epochs = runtime_.epochs();
    if (epochs == nullptr || !authority_.has_value() ||
        (phase_ != DriverPhase::Active && phase_ != DriverPhase::Syncing)) {
        return false;
    }
    const EpochHandoff& handoff = link.handoff;
    const EpochId old_epoch = epochs->current().id;
    if (authority_->epoch != old_epoch || handoff.from_epoch != old_epoch) {
        return false;
    }
    // The same chain-link verification a stranger runs: linkage, membership,
    // key hygiene, and the commit proof under this epoch's frozen vote keys.
    // The sender's word and this node's local boundary state count for
    // nothing; a link that does not verify changes nothing.
    auto advanced = advance_epoch_authority(*authority_, handoff, link.proof);
    auto* verified = std::get_if<VerifiedEpochAuthority>(&advanced);
    if (verified == nullptr) {
        return false;
    }
    VerifiedEpochAuthority next = std::move(*verified);
    const Digest checkpoint = next.checkpoint;

    // Serving the new epoch needs exactly what an activating newcomer needs:
    // the handoff names this node with the vote key it registered, and this
    // node holds the DKG outcome the handoff names.
    const bool named = std::find(handoff.members.begin(), handoff.members.end(), config_.self) !=
                       handoff.members.end();
    std::optional<DkgResult> dkg =
        pending_dkg_.has_value() ? std::move(pending_dkg_) : take_dkg_result_keeping_outbox();
    pending_dkg_.reset();
    if (named && !dkg.has_value()) {
        // A named participant whose own ceremony is still running waits for
        // its outcome. Waiting grants nothing, and it ends: the stall window
        // abandons the session, and the next verified link then finds none.
        const DkgSession* session = runtime_.authority().dkg();
        if (session != nullptr && session->target_epoch() == handoff.to_epoch &&
            session->phase() != DkgPhase::Failed) {
            return false;
        }
    }
    const auto own_key = vote_pubs_mine_.find(handoff.to_epoch);
    const auto listed_key = handoff.vote_keys.find(config_.self);
    const bool can_serve = named && dkg.has_value() &&
                           dkg->group_public_key == handoff.group_public_key &&
                           dkg->transcript_digest == handoff.dkg_transcript_digest &&
                           own_key != vote_pubs_mine_.end() &&
                           vote_keys_mine_.contains(handoff.to_epoch) &&
                           listed_key != handoff.vote_keys.end() &&
                           own_key->second == listed_key->second;
    if (!can_serve) {
        dkg.reset();
    }

    // The finished epoch ends here, before anything of the next one starts.
    (void)runtime_.leave_epoch();
    dkg_outbox_.reset();
    clear_boundary_state();
    store_.discard_vote_key(old_epoch);
    vote_keys_mine_.erase(old_epoch);
    vote_pubs_mine_.erase(old_epoch);
    for (const auto& [kind, handler] : payload_handlers_) {
        handler->on_consensus_reset();
    }
    (void)store_.append_chain_link(encode_security_message(
        router_.compose(SecurityMessageKind::EpochHandoffProof, link, handoff.to_epoch)));
    install_authority(std::move(next));
    epoch_started_ms_ = now_ms_;
    last_progress_ms_ = now_ms_;
    last_proposed_view_ = 0;
    last_committed_root_ = Digest{};
    last_committed_height_ = 0;
    behind_since_ms_.reset();

    if (!can_serve) {
        // The restart rule, applied live: a stored epoch that the verified
        // chain superseded is history, and the node continues as Tier 2.
        set_phase(DriverPhase::Idle,
                  named ? "a finalized handoff names this node, but it holds no matching DKG "
                          "outcome; it continues as Tier 2"
                        : "a finalized handoff ended this node's epoch without it; it continues "
                          "as Tier 2");
        return true;
    }
    EpochVoteKey vote_key = take_own_vote_key(handoff.to_epoch);
    if (!runtime_.adopt_epoch_from_handoff(handoff, std::move(dkg), std::move(vote_key),
                                           checkpoint)) {
        set_phase(DriverPhase::Failed, "verified handoff did not adopt");
        return true;
    }
    spdlog::info("[security] epoch {} adopted from its verified handoff",
                 handoff.to_epoch.underlying());
    persist_current_epoch(checkpoint);
    (void)store_.append_authority({handoff.to_epoch, handoff.group_public_key,
                                   runtime_.epochs()->current().participant_set_digest,
                                   handoff.dkg_transcript_digest});
    if (!enter_eligibility_epoch(handoff.to_epoch,
                                 runtime_.epochs()->current().tier1_members)) {
        set_phase(DriverPhase::Failed, "durable eligibility state is corrupt");
        return true;
    }
    set_phase(DriverPhase::Active, "finalized handoff verified; the new epoch role begins");
    return true;
}

void SecurityDriver::persist_current_epoch(const Digest& checkpoint) {
    const EpochManager* epochs = runtime_.epochs();
    StoredEpoch stored{epochs->current(), epochs->current_vote_keys(), checkpoint};
    (void)store_.store_epoch(stored);
}

void SecurityDriver::announce_epoch(const Digest& checkpoint, const Digest& dkg_transcript_digest) {
    const EpochState& current = runtime_.epochs()->current();
    EpochAnnouncement announcement;
    announcement.authority.network_id = current.network_id;
    announcement.authority.epoch = current.id;
    announcement.authority.key_generation = KeyGeneration(current.id.underlying());
    announcement.authority.security_ruleset = current.security_ruleset;
    announcement.authority.consensus_ruleset = current.consensus_ruleset;
    announcement.authority.tier1_set_digest = current.participant_set_digest;
    announcement.authority.consensus_quorum = current.consensus_quorum;
    announcement.authority.authority_threshold = current.authority_threshold;
    announcement.authority.frost_ciphersuite = std::string(constants::kFrostCiphersuite);
    announcement.authority.group_public_key = current.authority_public_key;
    announcement.authority.dkg_transcript_digest = dkg_transcript_digest;
    announcement.authority.attestation_root = current.attestation_root;
    announcement.authority.previous_checkpoint = checkpoint;
    announcement.handoff_certificate_digest = checkpoint;
    (void)router_.broadcast(router_.compose(SecurityMessageKind::EpochAnnouncement, announcement,
                                            current.id));
}

// --- The authority chain over the wire ---------------------------------------

void SecurityDriver::on_epoch_announcement(const EpochAnnouncement& announcement,
                                           const NodeId&) {
    // A hint and nothing more: it can prompt a question, never an answer.
    chain_hint_epoch_ = std::max(chain_hint_epoch_, announcement.authority.epoch);
}

void SecurityDriver::maybe_request_chain() {
    // An idle Tier 2 node walks toward the head; a member stuck in Syncing
    // asks too, because unanswered sync may mean the mesh moved past its
    // epoch. An active epoch holder is usually at the head, but it can miss
    // an activation: its own commit then never moves it. It asks once a hint
    // of a newer epoch outlived the sync window. Genesis is a one-shot
    // authority, not a walker.
    if (genesis_node() && (genesis_ == nullptr || !genesis_->finalized())) {
        return;
    }
    const EpochManager* epochs = runtime_.epochs();
    const bool idle_walker = epochs == nullptr && phase_ == DriverPhase::Idle;
    const bool stale_member = phase_ == DriverPhase::Syncing;
    const bool behind = epochs != nullptr && phase_ == DriverPhase::Active &&
                        chain_hint_epoch_ > epochs->current().id;
    if (!behind) {
        behind_since_ms_.reset();
    } else if (!behind_since_ms_.has_value()) {
        behind_since_ms_ = now_ms_;
    }
    const bool stale_holder = behind && now_ms_ - *behind_since_ms_ >= config_.sync_window_ms;
    if (!idle_walker && !stale_member && !stale_holder) {
        return;
    }
    const EpochId have = authority_.has_value() ? authority_->epoch : 0;
    // An idle walker with a verified authority and no hint of anything newer
    // has nothing to ask for. With none at all, the ask itself is the start.
    // A syncing member keeps asking: silence from its own epoch is the very
    // signal it is investigating.
    if (idle_walker && authority_.has_value() && chain_hint_epoch_ <= have) {
        return;
    }
    if (now_ms_ - chain_request_ms_ < config_.sync_window_ms) {
        return;
    }
    chain_request_ms_ = now_ms_;
    (void)router_.broadcast(router_.compose(SecurityMessageKind::AuthorityChainRequest,
                                            AuthorityChainRequest{have}, have));
}

std::optional<AuthorityChainPage> SecurityDriver::chain_page(EpochId have_epoch,
                                                            std::size_t max_links) const {
    // A bounded read of local records; it grants nothing and asserts nothing
    // the page's own proofs do not carry.
    AuthorityChainPage page;
    EpochId next_from = have_epoch;
    if (have_epoch == 0) {
        auto certificate = store_.load_bootstrap();
        auto base = store_.load_chain_base();
        const auto* cert = std::get_if<BootstrapCertificate>(&certificate);
        const auto* listing =
            std::get_if<std::vector<std::pair<NodeId, crypto::Ed25519PublicKey>>>(&base);
        if (cert == nullptr || listing == nullptr) {
            return std::nullopt;
        }
        page.has_base = true;
        page.base_certificate = *cert;
        page.base_vote_keys = *listing;
        next_from = 1;
    }
    auto links = store_.load_chain_links();
    if (const auto* stored = std::get_if<std::vector<std::vector<uint8_t>>>(&links)) {
        for (const auto& bytes : *stored) {
            if (page.links.size() >= max_links) {
                break;
            }
            auto decoded = decode_security_message(bytes);
            const auto* message = std::get_if<SecurityMessage>(&decoded);
            if (message == nullptr) {
                continue;
            }
            const auto* link = std::get_if<EpochHandoffProofMsg>(&message->body);
            if (link == nullptr || link->handoff.from_epoch != next_from) {
                continue;
            }
            page.links.push_back(*link);
            ++next_from;
        }
    }
    if (!page.has_base && page.links.empty()) {
        return std::nullopt;
    }
    return page;
}

std::optional<AuthorityChainPage> SecurityDriver::authority_chain_page(EpochId have_epoch) const {
    return chain_page(have_epoch, constants::kMaxHandoffChainLinks);
}

std::optional<AuthorityChainPage> SecurityDriver::authority_chain() const {
    return chain_page(0, std::numeric_limits<std::size_t>::max());
}

void SecurityDriver::on_authority_chain_request(const AuthorityChainRequest& request,
                                                const NodeId& from) {
    auto page = authority_chain_page(request.have_epoch);
    if (!page) {
        return;
    }
    (void)router_.send(from, router_.compose(SecurityMessageKind::AuthorityChainPage, *page,
                                             authority_.has_value() ? authority_->epoch : 0));
}

void SecurityDriver::on_authority_chain_page(const AuthorityChainPage& page, const NodeId& from) {
    // Candidate data from a peer. Everything is verified from the pinned
    // Genesis key and the advancing anchor; a page that proves nothing
    // changes nothing. A node that still holds an epoch the page proves
    // finished follows the verified link off it (follow_finalized_handoff)
    // and walks on from there like any Tier 2 node.
    if (runtime_.epochs() != nullptr && phase_ != DriverPhase::Syncing &&
        phase_ != DriverPhase::Active) {
        return;
    }
    const EpochId before = authority_.has_value() ? authority_->epoch : 0;
    if (!authority_.has_value() && page.has_base) {
        if (auto base = verify_epoch_one_authority(page.base_certificate,
                                                   config_.genesis_public_key,
                                                   page.base_vote_keys)) {
            anchor_ = page.base_certificate;
            (void)store_.store_bootstrap(page.base_certificate);
            (void)store_.store_chain_base(page.base_vote_keys);
            install_authority(std::move(*base));
        }
    }
    if (!authority_.has_value()) {
        return;
    }
    for (const auto& link : page.links) {
        if (link.handoff.from_epoch != authority_->epoch) {
            continue;
        }
        if (runtime_.epochs() != nullptr) {
            if (!follow_finalized_handoff(link)) {
                break;
            }
            continue;
        }
        auto advanced = advance_epoch_authority(*authority_, link.handoff, link.proof);
        auto* next = std::get_if<VerifiedEpochAuthority>(&advanced);
        if (next == nullptr) {
            break;
        }
        (void)store_.append_chain_link(encode_security_message(router_.compose(
            SecurityMessageKind::EpochHandoffProof, link, link.handoff.to_epoch)));
        install_authority(std::move(*next));
    }
    if (authority_->epoch > before) {
        if (genesis_node() && runtime_.epochs() == nullptr) {
            set_phase(DriverPhase::Idle, "authenticated authority chain ends genesis authority");
        }
        // Progress: ask for the next page right away, and ask everyone — the
        // server this page came from may itself be mid-walk and hold no more.
        // A server with nothing newer stays silent, which ends the walk.
        chain_request_ms_ = now_ms_;
        (void)router_.broadcast(router_.compose(SecurityMessageKind::AuthorityChainRequest,
                                                AuthorityChainRequest{authority_->epoch},
                                                authority_->epoch));
    }
}

// --- Candidate adoption ------------------------------------------------------

bool SecurityDriver::candidate_verify_proof(const Digest& transitions_digest,
                                            const CommitProof& proof) const {
    if (!adoption_.has_value()) {
        return false;
    }
    const QcValidationContext context{constants::kConsensusRulesetVersion,
                                      adoption_->plan.network_id, adoption_->plan.current_epoch,
                                      constants::consensus_quorum(
                                          adoption_->current_members.size())};
    return verify_commit_proof(transitions_digest, proof, context,
                               adoption_->current_vote_keys) == CommitProofFailure::None;
}

void SecurityDriver::on_next_epoch_plan(const NextEpochPlanProof& package) {
    // Members ignore this: their plan came from their own commit. Only a node
    // with no epoch state adopts, and only into the pending role.
    if (runtime_.epochs() != nullptr ||
        (phase_ != DriverPhase::Idle && phase_ != DriverPhase::PendingNextEpoch)) {
        return;
    }
    const NextEpochPlan& plan = package.plan;
    if (plan.network_id != derive_network_id(config_.genesis_public_key,
                                             constants::kSecurityRulesetVersion,
                                             constants::kConsensusRulesetVersion)) {
        return;
    }
    // Establish the verified authority for the plan's epoch. Epoch 1 derives
    // from the pinned Genesis certificate plus the supplied listing; every
    // later epoch must already have been reached through the verified
    // handoff chain. No listing, announcement, or plan invents an epoch.
    if (!authority_.has_value() && anchor_.has_value() && plan.current_epoch == anchor_->epoch) {
        if (auto epoch_one = verify_epoch_one_authority(*anchor_, config_.genesis_public_key,
                                                        package.current_vote_keys)) {
            (void)store_.store_chain_base(package.current_vote_keys);
            install_authority(std::move(*epoch_one));
        }
    }
    if (!authority_.has_value() || authority_->epoch != plan.current_epoch) {
        // Behind the chain: remember the hint so the walk starts. The plan
        // itself confers nothing and is dropped, not believed.
        chain_hint_epoch_ = std::max(chain_hint_epoch_, plan.current_epoch);
        return;
    }
    if (plan.security_ruleset != constants::kSecurityRulesetVersion ||
        plan.consensus_ruleset != constants::kConsensusRulesetVersion ||
        plan.profile_id != kTier1AttestationProfileId ||
        plan.profile_ruleset != kAttestationProfileRulesetVersion ||
        plan.next_epoch != plan.current_epoch + 1) {
        return;
    }
    // The plan must name this node at its live incarnation.
    const auto incarnation = plan.incarnations.find(config_.self);
    const bool named = std::find(plan.selected.begin(), plan.selected.end(), config_.self) !=
                       plan.selected.end();
    if (!named || incarnation == plan.incarnations.end() || incarnation->second != 1) {
        return;
    }
    // A later attempt for the same boundary replaces a held plan; anything
    // else that differs from the held plan is stale or hostile and ignored.
    if (adoption_.has_value() && plan.attempt <= adoption_->plan.attempt) {
        return;
    }

    // The supplied listing is a hint; the verified authority decides. It must
    // match exactly before a single certificate is judged.
    std::map<NodeId, crypto::Ed25519PublicKey> keys;
    for (const auto& [node, key] : package.current_vote_keys) {
        keys[node] = key;
    }
    if (keys != authority_->vote_keys) {
        return;
    }

    CandidateAdoption adoption;
    adoption.plan = plan;
    adoption.plan_digest = next_epoch_plan_digest(plan);
    adoption.current_members = authority_->members;
    adoption.current_vote_keys = authority_->vote_keys;
    const QcValidationContext context{constants::kConsensusRulesetVersion, plan.network_id,
                                      plan.current_epoch, authority_->consensus_quorum};
    if (verify_commit_proof(adoption.plan_digest, package.proof, context,
                            adoption.current_vote_keys) != CommitProofFailure::None) {
        return;
    }

    adoption_ = std::move(adoption);
    runtime_.authority().abandon_dkg();
    pending_dkg_.reset();
    sync_started_ms_ = now_ms_;
    set_phase(DriverPhase::PendingNextEpoch,
              "named in a finalized plan; preparing for the next epoch");
    // Recovery input comes from the mesh; finality stays the authority.
    (void)router_.broadcast(router_.compose(SecurityMessageKind::SyncRequest,
                                            SyncRequest{plan.current_epoch},
                                            plan.current_epoch));
}

void SecurityDriver::on_candidate_sync_response(const SyncResponse& response,
                                                const NodeId& from) {
    if (phase_ != DriverPhase::PendingNextEpoch || !adoption_.has_value() ||
        adoption_->state_synced) {
        return;
    }
    // The peer supplied bytes; the certificate decides. Valid signatures from
    // the anchored membership prove the chain reached this height.
    const QcValidationContext context{constants::kConsensusRulesetVersion,
                                      adoption_->plan.network_id, adoption_->plan.current_epoch,
                                      constants::consensus_quorum(
                                          adoption_->current_members.size())};
    if (validate_quorum_certificate(response.high_qc, context,
                                    adoption_->current_vote_keys).has_value()) {
        return;
    }
    if (response.high_qc.height < adoption_->plan.checkpoint_height) {
        return;  // Certified, but before the plan's checkpoint: keep syncing.
    }
    adoption_->state_synced = true;
    adoption_->verified_qc = response.high_qc;

    // The statement is narrow and stays narrow: this node verified a current
    // certified checkpoint and completed its sync procedure. It proves no
    // byte of local storage, and safety never rests on it — finality and the
    // fresh DKG do the deciding.
    CandidateStateReadyMsg ready;
    ready.network_id = adoption_->plan.network_id;
    ready.plan_digest = adoption_->plan_digest;
    ready.node = config_.self;
    const auto own_incarnation = adoption_->plan.incarnations.find(config_.self);
    if (own_incarnation == adoption_->plan.incarnations.end()) {
        return;
    }
    ready.incarnation = own_incarnation->second;
    ready.verified_qc = adoption_->verified_qc;
    const Digest digest = candidate_state_ready_digest(ready);
    crypto_sign_detached(ready.identity_signature.data(), nullptr, digest.data(), digest.size(),
                         config_.identity.private_key.data());
    (void)router_.broadcast(router_.compose(SecurityMessageKind::CandidateStateReady, ready,
                                            adoption_->plan.current_epoch));
}

void SecurityDriver::on_candidate_state_ready(const CandidateStateReadyMsg& message) {
    // Member side: record that a selected outside candidate proved it acquired
    // current certified state. One entry per candidate; the readiness commit is
    // what turns the set into authority to run a DKG.
    EpochManager* epochs = runtime_.epochs();
    if (phase_ != DriverPhase::Active || epochs == nullptr || !plan_.has_value()) {
        return;
    }
    if (message.network_id != plan_->network_id || message.plan_digest != next_epoch_plan_digest(*plan_)) {
        return;
    }
    const auto incarnation = plan_->incarnations.find(message.node);
    const bool selected = std::find(plan_->selected.begin(), plan_->selected.end(),
                                    message.node) != plan_->selected.end();
    if (!selected || incarnation == plan_->incarnations.end() ||
        incarnation->second != message.incarnation) {
        return;
    }
    const Digest digest = candidate_state_ready_digest(message);
    if (crypto_sign_verify_detached(message.identity_signature.data(), digest.data(),
                                    digest.size(), message.node.bytes.data()) != 0) {
        return;
    }
    // The presented certificate must be a real current-epoch certificate at or
    // above the plan's checkpoint, judged under this member's own frozen keys.
    const QcValidationContext context{constants::kConsensusRulesetVersion,
                                      epochs->current().network_id, epochs->current().id,
                                      epochs->current().consensus_quorum};
    if (validate_quorum_certificate(message.verified_qc, context,
                                    epochs->current_vote_keys()).has_value() ||
        message.verified_qc.height < plan_->checkpoint_height) {
        return;
    }
    state_ready_.insert(message.node);
}

void SecurityDriver::on_readiness_proof(const ReadinessProofMsg& message) {
    if (phase_ != DriverPhase::PendingNextEpoch || !adoption_.has_value() ||
        adoption_->dkg_authorized) {
        return;
    }
    const CandidateReadiness& readiness = message.readiness;
    if (readiness.network_id != adoption_->plan.network_id ||
        readiness.plan_digest != adoption_->plan_digest ||
        readiness.next_epoch != adoption_->plan.next_epoch) {
        return;
    }
    const Digest digest = candidate_readiness_digest(readiness);
    if (!candidate_verify_proof(digest, message.proof)) {
        return;
    }
    // The finalized set must name this node with the key it registered.
    const auto own_key = vote_pubs_mine_.find(adoption_->plan.next_epoch);
    const auto planned_incarnation = adoption_->plan.incarnations.find(config_.self);
    const auto self_entry =
        std::find_if(readiness.entries.begin(), readiness.entries.end(),
                     [this](const ReadinessEntry& entry) { return entry.node == config_.self; });
    if (self_entry == readiness.entries.end() || own_key == vote_pubs_mine_.end() ||
        planned_incarnation == adoption_->plan.incarnations.end() ||
        self_entry->vote_key != own_key->second ||
        self_entry->incarnation != planned_incarnation->second) {
        return;
    }

    adoption_->dkg_authorized = true;
    adoption_->readiness_digest = digest;

    // Current-epoch finality authorized exactly this preparation, so the
    // candidate now joins the future epoch's DKG. That makes it a participant
    // of a key ceremony, not a member of anything.
    auto set = Tier1Set::from_nodes(adoption_->plan.selected);
    if (!set.has_value()) {
        return;
    }
    DkgConfiguration dkg;
    dkg.network_id = adoption_->plan.network_id;
    dkg.target_epoch = adoption_->plan.next_epoch;
    dkg.participants = std::move(*set);
    dkg.incarnations = adoption_->plan.incarnations;
    dkg.threshold = constants::authority_threshold(adoption_->plan.selected.size());
    dkg.self = config_.self;
    dkg.session_binding = digest;
    auto broadcast = runtime_.authority().start_dkg(std::move(dkg));
    if (broadcast.has_value()) {
        runtime_.authority().observe_round1(*broadcast);
        (void)router_.broadcast(router_.compose(SecurityMessageKind::DkgBroadcast, *broadcast,
                                                adoption_->plan.next_epoch));
    }
}

void SecurityDriver::on_epoch_handoff_proof(const EpochHandoffProofMsg& message) {
    if (runtime_.epochs() != nullptr) {
        // A holder of the epoch this handoff ends. When it prepared exactly
        // this handoff, its own commit activates it. When it did not — it
        // missed a stage of the boundary, or it restarted inside it — its own
        // commit can never activate it, and the verified proof is the only
        // way off the finished epoch. The proof also counts as a hint, so a
        // node that cannot act on it yet keeps asking for the chain.
        const EpochId held = runtime_.epochs()->current().id;
        if (message.handoff.from_epoch == held) {
            chain_hint_epoch_ = std::max(chain_hint_epoch_, held + 1);
        }
        if (pending_handoff_digest() != epoch_handoff_digest(message.handoff)) {
            (void)follow_finalized_handoff(message);
        }
        return;
    }
    if (phase_ != DriverPhase::PendingNextEpoch || !adoption_.has_value()) {
        return;
    }
    const EpochHandoff& handoff = message.handoff;
    if (handoff.network_id != adoption_->plan.network_id ||
        handoff.from_epoch != adoption_->plan.current_epoch ||
        handoff.to_epoch != adoption_->plan.next_epoch ||
        handoff.plan_digest != adoption_->plan_digest) {
        return;
    }
    // Take the DKG result only when a completed session holds one; a handoff
    // arriving before the ceremony finished proves an epoch this node cannot
    // serve yet.
    if (!pending_dkg_.has_value()) {
        pending_dkg_ = take_dkg_result_keeping_outbox();
    }
    if (!pending_dkg_.has_value()) {
        return;
    }
    if (handoff.group_public_key != pending_dkg_->group_public_key ||
        handoff.dkg_transcript_digest != pending_dkg_->transcript_digest) {
        return;
    }
    // The finalized proof is the activation authority: the same chain-link
    // verification any stranger runs — linkage, membership, key hygiene, and
    // the commit proof under the old epoch's frozen keys. Announcements and
    // the sender's word count for nothing here.
    if (!authority_.has_value() || authority_->epoch != adoption_->plan.current_epoch) {
        return;
    }
    auto advanced = advance_epoch_authority(*authority_, handoff, message.proof);
    auto* next_authority = std::get_if<VerifiedEpochAuthority>(&advanced);
    if (next_authority == nullptr) {
        return;
    }

    EpochVoteKey own_key = take_own_vote_key(handoff.to_epoch);
    const Digest checkpoint = qc_digest(message.proof.chain[1].justify);
    if (!runtime_.adopt_epoch_from_handoff(handoff, std::move(pending_dkg_), std::move(own_key),
                                           checkpoint)) {
        set_phase(DriverPhase::Failed, "verified handoff did not adopt");
        return;
    }
    // The link that activated this node joins its chain record, so it can
    // serve the walk to the next stranger.
    (void)store_.append_chain_link(encode_security_message(
        router_.compose(SecurityMessageKind::EpochHandoffProof, message, handoff.to_epoch)));
    install_authority(std::move(*next_authority));
    pending_dkg_.reset();
    adoption_.reset();
    persist_current_epoch(checkpoint);
    (void)store_.append_authority({handoff.to_epoch, handoff.group_public_key,
                                   runtime_.epochs()->current().participant_set_digest,
                                   handoff.dkg_transcript_digest});
    if (!enter_eligibility_epoch(handoff.to_epoch,
                                 runtime_.epochs()->current().tier1_members)) {
        set_phase(DriverPhase::Failed, "durable eligibility state is corrupt");
        return;
    }
    dkg_outbox_.reset();
    set_phase(DriverPhase::Active, "finalized handoff verified; the new epoch role begins");
    epoch_started_ms_ = now_ms_;
    last_progress_ms_ = now_ms_;
    last_proposed_view_ = 0;
    last_committed_root_ = Digest{};
    last_committed_height_ = 0;
}

}  // namespace nexus::security
