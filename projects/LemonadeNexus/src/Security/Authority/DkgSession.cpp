#include <LemonadeNexus/Security/Authority/DkgSession.hpp>

#include <LemonadeNexus/Security/CanonicalEncoding.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

namespace nexus::security {

namespace {

constexpr std::string_view kMessageDomain = "lemonade-nexus/dkg-message:v1";
constexpr std::string_view kTranscriptDomain = "lemonade-nexus/dkg-transcript:v1";

Digest payload_digest(const std::vector<uint8_t>& payload) {
    CanonicalEncoder encoder(kMessageDomain);
    encoder.add_string("payload");
    encoder.add_bytes(payload);
    return encoder.digest();
}

}  // namespace

Digest dkg_message_digest(const DkgMessage& message) {
    CanonicalEncoder encoder(kMessageDomain);
    encoder.add_string("message");
    encoder.add_bytes(message.network_id);
    encoder.add_u64(message.target_epoch);
    encoder.add_bytes(message.participant_set_digest);
    encoder.add_bytes(message.sender.bytes);
    encoder.add_u64(message.sender_incarnation);
    encoder.add_u16(static_cast<uint16_t>(message.round));
    encoder.add_bytes(message.recipient.bytes);
    encoder.add_bytes(payload_digest(message.payload));
    return encoder.digest();
}

DkgSession::DkgSession(DkgConfiguration configuration) : config_(std::move(configuration)) {
    // FROST identifiers are the 1-based positions in the sorted participant
    // set, so every participant derives the same mapping.
    crypto::ParticipantIndex index = 1;
    for (const auto& node : config_.participants.members()) {
        index_of_[node] = index;
        node_of_[index] = node;
        ++index;
    }
    const auto self = index_of_.find(config_.self);
    if (self != index_of_.end()) {
        own_index_ = self->second;
    }
}

void DkgSession::fail(DkgFailure failure, std::optional<NodeId> culprit) {
    phase_ = DkgPhase::Failed;
    failure_ = failure;
    culprit_ = culprit;
}

DkgMessage DkgSession::make_message(DkgRound round, const NodeId& recipient,
                                    std::vector<uint8_t> payload) const {
    DkgMessage message;
    message.network_id = config_.network_id;
    message.target_epoch = config_.target_epoch;
    message.participant_set_digest = session_digest();
    message.sender = config_.self;
    message.sender_incarnation = config_.incarnations.at(config_.self);
    message.round = round;
    message.recipient = recipient;
    message.payload = std::move(payload);
    return message;
}

std::optional<DkgMessage> DkgSession::start() {
    if (phase_ != DkgPhase::Created) {
        fail(DkgFailure::WrongPhase);
        return std::nullopt;
    }
    const std::size_t n = config_.participants.size();
    if (n < constants::kMinActiveTier1 || n > constants::kMaxActiveTier1 ||
        own_index_ == 0 || config_.incarnations.size() != n) {
        fail(DkgFailure::ParticipantSetInvalid);
        return std::nullopt;
    }
    for (const auto& node : config_.participants.members()) {
        if (!config_.incarnations.contains(node)) {
            fail(DkgFailure::ParticipantSetInvalid);
            return std::nullopt;
        }
    }
    // The threshold is a compiled formula of the frozen population. A caller
    // cannot lower it, and a mismatch is a protocol error.
    if (config_.threshold != constants::authority_threshold(n)) {
        fail(DkgFailure::ThresholdInvalid);
        return std::nullopt;
    }

    auto round1 = crypto::FrostProvider::dkg_part1(
        own_index_, static_cast<uint16_t>(n), static_cast<uint16_t>(config_.threshold));
    if (!round1.ok()) {
        fail(DkgFailure::CryptoFailure);
        return std::nullopt;
    }
    round1_ = std::move(*round1.value);
    own_round1_payload_ = round1_.package();
    round1_payloads_[config_.self] = own_round1_payload_;
    phase_ = DkgPhase::Round1;
    return make_message(DkgRound::Round1Broadcast, NodeId{}, own_round1_payload_);
}

DkgFailure DkgSession::check_binding(const DkgMessage& message, DkgRound expected_round) {
    if (message.network_id != config_.network_id) {
        return DkgFailure::WrongNetwork;
    }
    if (message.target_epoch != config_.target_epoch) {
        return DkgFailure::WrongEpoch;
    }
    if (message.participant_set_digest != session_digest()) {
        return DkgFailure::WrongParticipantSet;
    }
    if (!index_of_.contains(message.sender)) {
        return DkgFailure::UnknownSender;
    }
    const auto incarnation = config_.incarnations.find(message.sender);
    if (incarnation == config_.incarnations.end() ||
        incarnation->second != message.sender_incarnation) {
        return DkgFailure::IncarnationMismatch;
    }
    if (message.round != expected_round) {
        return DkgFailure::WrongRound;
    }
    if (message.payload.empty()) {
        return DkgFailure::InvalidPackage;
    }
    return DkgFailure::None;
}

DkgFailure DkgSession::receive_broadcast(const DkgMessage& message) {
    if (phase_ != DkgPhase::Round1) {
        return DkgFailure::WrongPhase;
    }
    if (const auto failure = check_binding(message, DkgRound::Round1Broadcast);
        failure != DkgFailure::None) {
        return failure;
    }
    if (message.recipient != NodeId{}) {
        return DkgFailure::WrongRecipient;
    }

    const auto existing = round1_payloads_.find(message.sender);
    if (existing != round1_payloads_.end()) {
        if (existing->second == message.payload) {
            return DkgFailure::DuplicateMessage;
        }
        // Two different round-1 packages from one sender: the transcript is
        // ambiguous, and this participant is the provable cause.
        fail(DkgFailure::Equivocation, message.sender);
        return DkgFailure::Equivocation;
    }
    round1_payloads_[message.sender] = message.payload;
    return DkgFailure::None;
}

bool DkgSession::round1_complete() const {
    return phase_ != DkgPhase::Created && phase_ != DkgPhase::Failed &&
           round1_payloads_.size() == config_.participants.size();
}

std::optional<Digest> DkgSession::transcript_digest() const {
    if (!round1_complete()) {
        return std::nullopt;
    }
    CanonicalEncoder encoder(kTranscriptDomain);
    encoder.add_bytes(config_.network_id);
    encoder.add_u64(config_.target_epoch);
    encoder.add_bytes(config_.participants.digest());
    encoder.add_u64(config_.participants.size());
    for (const auto& [sender, payload] : round1_payloads_) {
        encoder.add_bytes(sender.bytes);
        encoder.add_bytes(payload_digest(payload));
    }
    return encoder.digest();
}

std::vector<DkgMessage> DkgSession::round2_messages() {
    if (phase_ != DkgPhase::Round1 || !round1_complete()) {
        return {};
    }

    crypto::FrostPeerBytesMap others;
    for (const auto& [sender, payload] : round1_payloads_) {
        if (sender != config_.self) {
            others[index_of_.at(sender)] = payload;
        }
    }

    auto round2 = crypto::FrostProvider::dkg_part2(std::move(round1_), others);
    if (!round2.ok()) {
        // FROST rejects a round-1 package with an invalid proof of knowledge
        // here. The FFI does not name the culprit yet, so the failure is
        // unattributed; the epoch layer restarts with the same set or times
        // the silent party out.
        fail(round2.status == crypto::FrostStatus::CryptoFailure ? DkgFailure::InvalidPackage
                                                                  : DkgFailure::CryptoFailure);
        return {};
    }
    round2_ = std::move(*round2.value);
    phase_ = DkgPhase::Round2;

    std::vector<DkgMessage> messages;
    for (const auto& [recipient_index, payload] : round2_.packages_for_recipients()) {
        messages.push_back(
            make_message(DkgRound::Round2Pairwise, node_of_.at(recipient_index), payload));
    }
    return messages;
}

DkgFailure DkgSession::receive_pairwise(const DkgMessage& message) {
    if (phase_ != DkgPhase::Round2) {
        return DkgFailure::WrongPhase;
    }
    if (const auto failure = check_binding(message, DkgRound::Round2Pairwise);
        failure != DkgFailure::None) {
        return failure;
    }
    if (message.recipient != config_.self) {
        return DkgFailure::WrongRecipient;
    }
    if (message.sender == config_.self) {
        return DkgFailure::UnknownSender;
    }
    const auto existing = round2_payloads_.find(message.sender);
    if (existing != round2_payloads_.end()) {
        if (existing->second == message.payload) {
            return DkgFailure::DuplicateMessage;
        }
        fail(DkgFailure::Equivocation, message.sender);
        return DkgFailure::Equivocation;
    }
    round2_payloads_[message.sender] = message.payload;
    return DkgFailure::None;
}

bool DkgSession::finish() {
    if (phase_ != DkgPhase::Round2 ||
        round2_payloads_.size() + 1 != config_.participants.size()) {
        return false;
    }

    crypto::FrostPeerBytesMap round1_others;
    for (const auto& [sender, payload] : round1_payloads_) {
        if (sender != config_.self) {
            round1_others[index_of_.at(sender)] = payload;
        }
    }
    crypto::FrostPeerBytesMap round2_for_me;
    for (const auto& [sender, payload] : round2_payloads_) {
        round2_for_me[index_of_.at(sender)] = payload;
    }

    auto outcome = crypto::FrostProvider::dkg_part3(std::move(round2_), round1_others,
                                                    round2_for_me);
    if (!outcome.ok()) {
        fail(outcome.status == crypto::FrostStatus::CryptoFailure ? DkgFailure::InvalidPackage
                                                                   : DkgFailure::CryptoFailure);
        return false;
    }

    DkgResult result;
    result.target_epoch = config_.target_epoch;
    result.participant_set_digest = session_digest();
    result.transcript_digest = *transcript_digest();
    result.group_public_key = outcome.value->group_public_key;
    result.public_key_package = std::move(outcome.value->public_key_package);
    result.key_share = std::move(outcome.value->key_share);
    result.own_index = own_index_;
    result.index_of = index_of_;
    result_ = std::move(result);
    phase_ = DkgPhase::Complete;
    return true;
}

std::optional<DkgResult> DkgSession::take_result() {
    if (phase_ != DkgPhase::Complete || !result_.has_value()) {
        return std::nullopt;
    }
    std::optional<DkgResult> out = std::move(result_);
    result_.reset();
    return out;
}

}  // namespace nexus::security
