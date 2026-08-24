#include <LemonadeNexus/Security/Transport/SecurityRouter.hpp>

#include <LemonadeNexus/Security/Consensus/QuorumValidation.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <sodium.h>

#include <algorithm>

namespace nexus::security {

namespace {

RouteResult drop(DropReason reason, std::optional<uint16_t> code = std::nullopt) {
    RouteResult result;
    result.dropped = reason;
    result.service_code = code;
    return result;
}

RouteResult delivered() {
    RouteResult result;
    result.delivered = true;
    return result;
}

DropReason from_codec(CodecError error) {
    switch (error) {
        case CodecError::Oversized:
            return DropReason::Oversized;
        case CodecError::UnknownKind:
            return DropReason::UnknownKind;
        default:
            return DropReason::Malformed;
    }
}

template <typename Enum>
uint16_t code(Enum value) {
    return static_cast<uint16_t>(value);
}

}  // namespace

SecurityRouter::SecurityRouter(SecurityRouterConfig config, SecurityRuntime& runtime,
                               ISecurityTransport& transport, ISecurityEvents& events,
                               PairwiseSealer& sealer, IEvidenceProducer* evidence_producer)
    : config_(config),
      runtime_(runtime),
      transport_(transport),
      events_(events),
      sealer_(sealer),
      evidence_producer_(evidence_producer),
      seen_ring_(constants::kSecurityDedupeWindow) {}

// --- Gates ------------------------------------------------------------------

bool SecurityRouter::within_budget(const NodeId& sender, uint64_t now_ms) {
    auto it = budgets_.find(sender);
    if (it == budgets_.end()) {
        if (budgets_.size() >= constants::kSecurityTrackedPeers) {
            // Evict the stalest window so a stream of new identities cannot
            // grow the table without limit.
            auto oldest = std::min_element(
                budgets_.begin(), budgets_.end(), [](const auto& a, const auto& b) {
                    return a.second.window_start_ms < b.second.window_start_ms;
                });
            budgets_.erase(oldest);
        }
        it = budgets_.emplace(sender, PeerBudget{now_ms, 0}).first;
    }
    PeerBudget& budget = it->second;
    if (now_ms - budget.window_start_ms >= constants::kSecurityFloodWindowMs) {
        budget.window_start_ms = now_ms;
        budget.count = 0;
    }
    if (budget.count >= constants::kSecurityPeerMessagesPerWindow) {
        return false;
    }
    ++budget.count;
    return true;
}

bool SecurityRouter::remember(std::span<const uint8_t> envelope) {
    Digest digest{};
    crypto_hash_sha256(digest.data(), envelope.data(), envelope.size());
    if (seen_.contains(digest)) {
        return false;
    }
    // Ring eviction keeps the window bounded; a replay older than the window
    // is caught by the services' own state (view, session, commitment).
    const Digest& evicted = seen_ring_[seen_next_];
    if (evicted != Digest{}) {
        seen_.erase(evicted);
    }
    seen_ring_[seen_next_] = digest;
    seen_next_ = (seen_next_ + 1) % seen_ring_.size();
    seen_.insert(digest);
    return true;
}

bool SecurityRouter::sender_bound(const SecurityMessage& message,
                                  const NodeId& authenticated_sender) const {
    if (message.sender != authenticated_sender) {
        return false;
    }
    // The body's own sender fields must name the same peer: a vote, share,
    // or package from A must never be attributed to B.
    return std::visit(
        [&](const auto& body) -> bool {
            using T = std::decay_t<decltype(body)>;
            if constexpr (std::is_same_v<T, ProposalMessage>) {
                return body.proposal.leader == authenticated_sender;
            } else if constexpr (std::is_same_v<T, Vote>) {
                return body.voter == authenticated_sender;
            } else if constexpr (std::is_same_v<T, TimeoutVote>) {
                return body.voter == authenticated_sender;
            } else if constexpr (std::is_same_v<T, DkgMessage>) {
                return body.sender == authenticated_sender;
            } else if constexpr (std::is_same_v<T, FrostCommitmentMessage>) {
                return body.header.sender == authenticated_sender;
            } else if constexpr (std::is_same_v<T, FrostShareMessage>) {
                return body.header.sender == authenticated_sender;
            } else if constexpr (std::is_same_v<T, AttestationEvidence>) {
                return body.node_id == authenticated_sender;
            } else if constexpr (std::is_same_v<T, DkgTranscriptAttest>) {
                return body.node == authenticated_sender;
            } else {
                return true;
            }
        },
        message.body);
}

bool SecurityRouter::epoch_in_window(const SecurityMessage& message) const {
    const EpochManager* epochs = runtime_.epochs();
    const bool bootstrap_kind = message.kind == SecurityMessageKind::GenesisFounding ||
                                message.kind == SecurityMessageKind::DkgTranscriptAttest ||
                                message.kind == SecurityMessageKind::BootstrapCertificate;
    if (epochs == nullptr) {
        // Before Epoch 1 only bootstrap traffic exists: challenges, evidence,
        // the Epoch 1 DKG, and the Genesis exchange.
        return message.epoch <= 1;
    }
    if (bootstrap_kind) {
        // Genesis authority ended at Epoch 1 activation.
        return false;
    }
    const EpochId current = epochs->current().id;
    if (message.epoch == current) {
        return true;
    }
    // Next-epoch preparation runs while the current epoch is authoritative.
    const bool preparation = message.kind == SecurityMessageKind::DkgBroadcast ||
                             message.kind == SecurityMessageKind::DkgPairwise ||
                             message.kind == SecurityMessageKind::AttestationChallenge ||
                             message.kind == SecurityMessageKind::AttestationEvidence ||
                             message.kind == SecurityMessageKind::EpochAnnouncement;
    return preparation && message.epoch == current + 1;
}

// --- Inbound ----------------------------------------------------------------

RouteResult SecurityRouter::receive(const NodeId& authenticated_sender,
                                    std::span<const uint8_t> envelope, uint64_t now_ms) {
    if (envelope.size() > constants::kMaxSecurityMessageBytes) {
        return drop(DropReason::Oversized);
    }
    if (!within_budget(authenticated_sender, now_ms)) {
        return drop(DropReason::Flooded);
    }

    auto decoded = decode_security_message(envelope);
    if (const auto* error = std::get_if<CodecError>(&decoded)) {
        return drop(from_codec(*error));
    }
    SecurityMessage message = std::move(std::get<SecurityMessage>(decoded));

    if (!sender_bound(message, authenticated_sender)) {
        return drop(DropReason::SenderMismatch);
    }
    if (message.security_ruleset != constants::kSecurityRulesetVersion ||
        message.consensus_ruleset != constants::kConsensusRulesetVersion) {
        return drop(DropReason::RulesetMismatch);
    }
    if (message.network_id != config_.network_id) {
        return drop(DropReason::NetworkMismatch);
    }
    if (!epoch_in_window(message)) {
        return drop(DropReason::EpochOutOfWindow);
    }
    if (!remember(envelope)) {
        return drop(DropReason::Duplicate);
    }
    return dispatch(message);
}

RouteResult SecurityRouter::deliver_local(SecurityMessage message) {
    if (message.sender != runtime_.self()) {
        return drop(DropReason::SenderMismatch);
    }
    return dispatch(message);
}

RouteResult SecurityRouter::dispatch(SecurityMessage& message) {
    switch (message.kind) {
        case SecurityMessageKind::AttestationChallenge:
            return route_challenge(std::get<AttestationChallenge>(message.body), message.sender);
        case SecurityMessageKind::AttestationEvidence:
            return route_evidence(std::get<AttestationEvidence>(message.body));
        case SecurityMessageKind::HotStuffProposal:
            return route_proposal(std::get<ProposalMessage>(message.body));
        case SecurityMessageKind::HotStuffVote:
            return route_vote(std::get<Vote>(message.body));
        case SecurityMessageKind::HotStuffTimeout:
            return route_timeout(std::get<TimeoutVote>(message.body));
        case SecurityMessageKind::DkgBroadcast:
        case SecurityMessageKind::DkgPairwise:
            return route_dkg(std::get<DkgMessage>(message.body));
        case SecurityMessageKind::FrostCommitment:
            return route_commitment(std::get<FrostCommitmentMessage>(message.body));
        case SecurityMessageKind::FrostSignatureShare:
            return route_share(std::get<FrostShareMessage>(message.body));
        case SecurityMessageKind::EpochAnnouncement:
            return route_announcement(std::get<EpochAnnouncement>(message.body), message.sender);
        case SecurityMessageKind::GenesisFounding:
            events_.on_genesis_founding(std::get<GenesisFounding>(message.body), message.sender);
            return delivered();
        case SecurityMessageKind::DkgTranscriptAttest:
            events_.on_dkg_transcript_attest(std::get<DkgTranscriptAttest>(message.body));
            return delivered();
        case SecurityMessageKind::BootstrapCertificate:
            events_.on_bootstrap_certificate(std::get<BootstrapCertificate>(message.body),
                                             message.sender);
            return delivered();
        case SecurityMessageKind::SyncRequest:
            return route_sync_request(std::get<SyncRequest>(message.body), message.sender);
        case SecurityMessageKind::SyncResponse:
            return route_sync_response(std::get<SyncResponse>(message.body), message.sender);
    }
    return drop(DropReason::UnknownKind);
}

RouteResult SecurityRouter::route_sync_request(const SyncRequest& request, const NodeId& from) {
    HotStuffService* consensus = runtime_.consensus();
    const EpochManager* epochs = runtime_.epochs();
    if (consensus == nullptr || epochs == nullptr || request.epoch != epochs->current().id) {
        return drop(DropReason::NoService);
    }
    SyncResponse response{consensus->state().high_qc};
    (void)send(from, compose(SecurityMessageKind::SyncResponse, response, request.epoch));
    return delivered();
}

RouteResult SecurityRouter::route_sync_response(const SyncResponse& response, const NodeId& from) {
    const EpochManager* epochs = runtime_.epochs();
    if (epochs == nullptr) {
        return drop(DropReason::NoService);
    }
    const EpochState& current = epochs->current();
    const QuorumCertificate& qc = response.high_qc;
    // A certificate is self-certifying: valid signatures from the frozen
    // membership prove the view. The genesis form proves only view 0.
    const bool genesis_form = qc.signers.empty() && qc.view == 0 && qc.height == 0 &&
                              qc.epoch == current.id && qc.network_id == current.network_id;
    if (!genesis_form) {
        const QcValidationContext context{constants::kConsensusRulesetVersion, current.network_id,
                                          current.id, current.consensus_quorum};
        const auto failure = validate_quorum_certificate(qc, context, epochs->current_vote_keys());
        if (failure.has_value()) {
            return drop(DropReason::ServiceRejected, code(*failure));
        }
    }
    events_.on_sync_certificate(qc, from);
    return delivered();
}

RouteResult SecurityRouter::route_proposal(const ProposalMessage& message) {
    HotStuffService* consensus = runtime_.consensus();
    if (consensus == nullptr) {
        return drop(DropReason::NoService);
    }
    const ProposalResult result = consensus->receive_proposal(message.proposal, message.justify);
    if (result.rejected.has_value()) {
        return drop(DropReason::ServiceRejected, code(*result.rejected));
    }
    if (!result.commits.empty()) {
        events_.on_commits(result.commits);
    }
    if (result.vote.has_value()) {
        // Chained HotStuff: the vote goes to the leader of the next view,
        // who forms the certificate and proposes on it.
        const NodeId next_leader = consensus->leader_of(result.vote->view + 1);
        const SecurityMessage vote =
            compose(SecurityMessageKind::HotStuffVote, *result.vote, result.vote->epoch);
        if (next_leader == runtime_.self()) {
            (void)route_vote(*result.vote);
        } else {
            (void)send(next_leader, vote);
        }
        events_.on_vote_sent(*result.vote, next_leader);
    }
    return delivered();
}

RouteResult SecurityRouter::route_vote(const Vote& vote) {
    HotStuffService* consensus = runtime_.consensus();
    if (consensus == nullptr) {
        return drop(DropReason::NoService);
    }
    auto outcome = consensus->receive_vote(vote);
    if (const auto* failure = std::get_if<ConsensusFailure>(&outcome)) {
        return drop(DropReason::ServiceRejected, code(*failure));
    }
    if (const auto* certificate = std::get_if<QuorumCertificate>(&outcome)) {
        events_.on_certificate(*certificate);
    }
    return delivered();
}

RouteResult SecurityRouter::route_timeout(const TimeoutVote& vote) {
    HotStuffService* consensus = runtime_.consensus();
    if (consensus == nullptr) {
        return drop(DropReason::NoService);
    }
    auto outcome = consensus->receive_timeout(vote);
    if (const auto* failure = std::get_if<ConsensusFailure>(&outcome)) {
        return drop(DropReason::ServiceRejected, code(*failure));
    }
    if (const auto* certificate = std::get_if<TimeoutCertificate>(&outcome)) {
        events_.on_timeout_certificate(*certificate);
    }
    return delivered();
}

RouteResult SecurityRouter::route_dkg(DkgMessage& message) {
    DkgSession* dkg = runtime_.authority().dkg();
    if (dkg == nullptr) {
        return drop(DropReason::NoService);
    }

    if (message.round == DkgRound::Round2Pairwise) {
        auto plaintext = sealer_.unseal(message.payload);
        if (!plaintext.has_value()) {
            return drop(DropReason::SealFailure);
        }
        message.payload = std::move(*plaintext);
        const DkgFailure failure = dkg->receive_pairwise(message);
        if (failure != DkgFailure::None && failure != DkgFailure::DuplicateMessage) {
            if (dkg->phase() == DkgPhase::Failed) {
                events_.on_dkg_failed(dkg->failure(), dkg->culprit());
            }
            return drop(DropReason::ServiceRejected, code(failure));
        }
        if (dkg->finish()) {
            events_.on_dkg_complete(message.target_epoch);
        } else if (dkg->phase() == DkgPhase::Failed) {
            events_.on_dkg_failed(dkg->failure(), dkg->culprit());
        }
        return delivered();
    }

    const DkgFailure failure = dkg->receive_broadcast(message);
    if (failure != DkgFailure::None && failure != DkgFailure::DuplicateMessage) {
        if (dkg->phase() == DkgPhase::Failed) {
            events_.on_dkg_failed(dkg->failure(), dkg->culprit());
        }
        return drop(DropReason::ServiceRejected, code(failure));
    }
    if (dkg->round1_complete() && dkg->phase() == DkgPhase::Round1) {
        const auto pairwise = dkg->round2_messages();
        if (dkg->phase() == DkgPhase::Failed) {
            events_.on_dkg_failed(dkg->failure(), dkg->culprit());
            return delivered();
        }
        events_.on_dkg_round1_complete(message.target_epoch);
        for (const auto& package : pairwise) {
            (void)send_sealed_dkg(package);
        }
    }
    return delivered();
}

RouteResult SecurityRouter::route_commitment(const FrostCommitmentMessage& message) {
    auto outcome = runtime_.authority().receive_commitment(message);
    if (const auto* failure = std::get_if<SigningFailure>(&outcome)) {
        return drop(DropReason::ServiceRejected, code(*failure));
    }
    if (const auto* share = std::get_if<FrostShareMessage>(&outcome)) {
        const SigningSession* session = runtime_.authority().session(share->header.session_id);
        if (session != nullptr) {
            const SecurityMessage out =
                compose(SecurityMessageKind::FrostSignatureShare, *share, share->header.epoch);
            for (const NodeId& signer : session->signer_set) {
                if (signer != runtime_.self()) {
                    (void)send(signer, out);
                }
            }
        }
    }
    return delivered();
}

RouteResult SecurityRouter::route_share(const FrostShareMessage& message) {
    auto outcome = runtime_.authority().receive_signature_share(message);
    if (const auto* failure = std::get_if<SigningFailure>(&outcome)) {
        return drop(DropReason::ServiceRejected, code(*failure));
    }
    if (const auto* signature = std::get_if<AuthoritySignature>(&outcome)) {
        events_.on_authority_signature(*signature);
    }
    return delivered();
}

RouteResult SecurityRouter::route_challenge(const AttestationChallenge& challenge,
                                            const NodeId& from) {
    if (challenge.node_id != runtime_.self()) {
        return drop(DropReason::SenderMismatch);
    }
    if (evidence_producer_ == nullptr) {
        return drop(DropReason::NoService);
    }
    auto evidence = evidence_producer_->produce(challenge);
    if (!evidence.has_value()) {
        return drop(DropReason::NoService);
    }
    const SecurityMessage out =
        compose(SecurityMessageKind::AttestationEvidence, *evidence, challenge.epoch);
    (void)send(from, out);
    return delivered();
}

RouteResult SecurityRouter::route_evidence(const AttestationEvidence& evidence) {
    const AttestationVerdict verdict = runtime_.attestation().receive_evidence(evidence);
    events_.on_attestation_verdict(verdict, evidence);
    return delivered();
}

RouteResult SecurityRouter::route_announcement(const EpochAnnouncement& announcement,
                                               const NodeId& from) {
    events_.on_epoch_announcement(announcement, from);
    return delivered();
}

// --- Outbound ---------------------------------------------------------------

SecurityMessage SecurityRouter::compose(SecurityMessageKind kind, SecurityBody body,
                                        EpochId epoch) const {
    SecurityMessage message;
    message.kind = kind;
    message.security_ruleset = constants::kSecurityRulesetVersion;
    message.consensus_ruleset = constants::kConsensusRulesetVersion;
    message.network_id = config_.network_id;
    message.epoch = epoch;
    message.sender = runtime_.self();
    message.body = std::move(body);
    return message;
}

bool SecurityRouter::send(const NodeId& to, const SecurityMessage& message) {
    const auto bytes = encode_security_message(message);
    if (bytes.empty()) {
        return false;
    }
    return transport_.send_to(to, bytes);
}

std::size_t SecurityRouter::broadcast(const SecurityMessage& message) {
    const auto bytes = encode_security_message(message);
    if (bytes.empty()) {
        return 0;
    }
    return transport_.broadcast(bytes);
}

bool SecurityRouter::send_sealed_dkg(const DkgMessage& message) {
    if (message.round != DkgRound::Round2Pairwise) {
        return false;
    }
    auto sealed = sealer_.seal_for(message.recipient, message.payload);
    if (!sealed.has_value()) {
        return false;
    }
    DkgMessage wire = message;
    wire.payload = std::move(*sealed);
    return send(message.recipient,
                compose(SecurityMessageKind::DkgPairwise, wire, message.target_epoch));
}

}  // namespace nexus::security
