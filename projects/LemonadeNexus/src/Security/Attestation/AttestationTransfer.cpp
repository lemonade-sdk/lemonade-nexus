#include <LemonadeNexus/Security/Attestation/AttestationTransfer.hpp>

#include <LemonadeNexus/Security/EvidenceSnpSvsmVtpm.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>

#include <algorithm>
#include <iterator>
#include <limits>

namespace nexus::security {

namespace {

std::size_t fixed_platform_bytes(const PlatformEvidence& platform) {
    return encode_platform_evidence(platform).size();
}

uint32_t chunk_count(std::size_t bytes) {
    return bytes == 0
               ? 0
               : static_cast<uint32_t>((bytes + constants::kMaxEvidenceChunkBytes - 1) /
                                       constants::kMaxEvidenceChunkBytes);
}

bool full_mode_fields_are_valid(const AttestationChallenge& challenge) {
    if (challenge.ima_mode == ImaEvidenceMode::Full) {
        return challenge.ima_checkpoint_digest == Digest{} &&
               challenge.ima_prior_event_count == 0 && challenge.ima_prior_pcr10 == Digest{} &&
               challenge.ima_checkpoint_paths.empty();
    }
    return challenge.ima_mode == ImaEvidenceMode::Resume &&
           challenge.ima_checkpoint_digest != Digest{} &&
           challenge.ima_prior_pcr10 != Digest{} &&
           !challenge.ima_checkpoint_paths.empty();
}

}  // namespace

std::optional<AttestationEvidenceTransfer> make_evidence_transfer(
    const AttestationEvidence& evidence) {
    const auto* full = std::get_if<SnpSvsmVtpmEvidence>(&evidence.platform);
    if (!full || evidence.profile_id != AttestationProfileId::SnpSvsmVtpm ||
        evidence.ima_bytes != full->ima_binary_log.size() ||
        evidence.ima_digest != raw_ima_digest(full->ima_binary_log)) {
        return std::nullopt;
    }

    AttestationEvidenceTransfer transfer;
    transfer.start.challenge_digest = evidence.challenge_digest;
    transfer.start.mode = evidence.ima_mode;
    transfer.start.ima_bytes = full->ima_binary_log.size();
    transfer.start.total_chunks = chunk_count(full->ima_binary_log.size());
    transfer.start.ima_digest = evidence.ima_digest;
    transfer.start.platform_digest = platform_evidence_digest(evidence.platform);
    transfer.start.evidence = evidence;
    svsm_evidence(transfer.start.evidence.platform).ima_binary_log.clear();
    const std::size_t fixed = fixed_platform_bytes(transfer.start.evidence.platform);
    if (fixed > std::numeric_limits<uint64_t>::max() - transfer.start.ima_bytes) {
        return std::nullopt;
    }
    transfer.start.total_transfer_bytes = fixed + transfer.start.ima_bytes;
    if (transfer.start.total_transfer_bytes > constants::kMaxFullEvidenceTransferBytes ||
        transfer.start.total_chunks > constants::kMaxEvidenceTransferChunks ||
        (evidence.ima_mode == ImaEvidenceMode::Resume &&
         evidence.ima_bytes > constants::kMaxResumeImaSuffixBytes)) {
        return std::nullopt;
    }
    transfer.start.transfer_id = evidence_transfer_id(transfer.start);

    for (std::size_t at = 0, index = 0; at < full->ima_binary_log.size();
         at += constants::kMaxEvidenceChunkBytes, ++index) {
        const std::size_t count = std::min(constants::kMaxEvidenceChunkBytes,
                                           full->ima_binary_log.size() - at);
        AttestationEvidenceChunk chunk;
        chunk.challenge_digest = evidence.challenge_digest;
        chunk.transfer_id = transfer.start.transfer_id;
        chunk.chunk_index = static_cast<uint32_t>(index);
        chunk.bytes.assign(full->ima_binary_log.begin() + static_cast<std::ptrdiff_t>(at),
                           full->ima_binary_log.begin() +
                               static_cast<std::ptrdiff_t>(at + count));
        transfer.chunks.push_back(std::move(chunk));
    }
    transfer.end.challenge_digest = evidence.challenge_digest;
    transfer.end.transfer_id = transfer.start.transfer_id;
    transfer.end.total_transfer_bytes = transfer.start.total_transfer_bytes;
    transfer.end.ima_bytes = transfer.start.ima_bytes;
    transfer.end.total_chunks = transfer.start.total_chunks;
    transfer.end.ima_digest = transfer.start.ima_digest;
    transfer.end.platform_digest = transfer.start.platform_digest;
    return transfer;
}

AttestationTransferReceiver::State* AttestationTransferReceiver::find(
    const NodeId& sender, const Digest& challenge, const Digest& transfer) {
    const auto it = live_.find(sender);
    if (it == live_.end() || it->second.start.challenge_digest != challenge ||
        it->second.start.transfer_id != transfer) {
        return nullptr;
    }
    return &it->second;
}

AttestationTransferReceiver::Early& AttestationTransferReceiver::early_slot(
    const NodeId& sender, const Digest& challenge, const Digest& transfer, uint64_t now_ms) {
    Early& slot = early_[sender];
    if (slot.challenge != challenge || slot.transfer != transfer) {
        slot = Early{};
        slot.challenge = challenge;
        slot.transfer = transfer;
        slot.deadline_ms = now_ms + constants::kEvidenceTransferDeadlineMs;
    }
    return slot;
}

EvidenceTransferFailure AttestationTransferReceiver::consume(
    State& state, const std::vector<uint8_t>& bytes) {
    if (state.next_chunk >= state.start.total_chunks) {
        return EvidenceTransferFailure::ExtraBytes;
    }
    if (bytes.empty() || bytes.size() > constants::kMaxEvidenceChunkBytes) {
        return EvidenceTransferFailure::ChunkTooLarge;
    }
    const std::size_t remaining =
        static_cast<std::size_t>(state.start.ima_bytes) - state.ima.size();
    if (bytes.size() != std::min(constants::kMaxEvidenceChunkBytes, remaining)) {
        return EvidenceTransferFailure::ExtraBytes;
    }
    state.ima.insert(state.ima.end(), bytes.begin(), bytes.end());
    ++state.next_chunk;
    return EvidenceTransferFailure::None;
}

EvidenceTransferResult AttestationTransferReceiver::try_finish(const NodeId& sender,
                                                               State& state) {
    while (!state.held.empty() && state.held.begin()->first == state.next_chunk) {
        auto held = state.held.extract(state.held.begin());
        const auto failure = consume(state, held.mapped());
        if (failure != EvidenceTransferFailure::None) {
            return {failure, std::nullopt};
        }
    }
    if (!state.pending_end.has_value() || state.next_chunk != state.start.total_chunks ||
        state.ima.size() != state.start.ima_bytes) {
        return {EvidenceTransferFailure::None, std::nullopt};
    }
    if (raw_ima_digest(state.ima) != state.start.ima_digest) {
        live_.erase(sender);
        return {EvidenceTransferFailure::WrongEvidenceHash, std::nullopt};
    }
    AttestationEvidence evidence = state.start.evidence;
    svsm_evidence(evidence.platform).ima_binary_log = std::move(state.ima);
    if (platform_evidence_digest(evidence.platform) != state.start.platform_digest) {
        live_.erase(sender);
        return {EvidenceTransferFailure::WrongEvidenceHash, std::nullopt};
    }
    live_.erase(sender);
    return {EvidenceTransferFailure::None, std::move(evidence)};
}

EvidenceTransferResult AttestationTransferReceiver::begin(
    const NodeId& sender, const AttestationEvidenceStart& start,
    const AttestationChallenge& live_challenge, uint64_t now_ms) {
    (void)expire(now_ms);
    if (const auto it = live_.find(sender); it != live_.end()) {
        // The sender repeats its burst; an identical Start is expected traffic.
        return {it->second.start.transfer_id == start.transfer_id
                    ? EvidenceTransferFailure::None
                    : EvidenceTransferFailure::DuplicateStart,
                std::nullopt};
    }
    if (live_.size() >= constants::kMaxConcurrentEvidenceTransfers) {
        return {EvidenceTransferFailure::ConcurrentLimit, std::nullopt};
    }
    if (sender != start.evidence.node_id) {
        return {EvidenceTransferFailure::WrongSender, std::nullopt};
    }
    if (start.challenge_digest != challenge_digest(live_challenge) ||
        start.evidence.challenge_digest != start.challenge_digest) {
        return {EvidenceTransferFailure::WrongChallenge, std::nullopt};
    }
    if (live_challenge.profile_id != AttestationProfileId::SnpSvsmVtpm ||
        start.evidence.profile_id != AttestationProfileId::SnpSvsmVtpm ||
        start.evidence.profile_ruleset != live_challenge.profile_ruleset) {
        return {EvidenceTransferFailure::WrongProfile, std::nullopt};
    }
    if (!full_mode_fields_are_valid(live_challenge) ||
        start.mode != live_challenge.ima_mode ||
        start.evidence.ima_mode != start.mode) {
        return {EvidenceTransferFailure::WrongMode, std::nullopt};
    }
    const auto* fixed = std::get_if<SnpSvsmVtpmEvidence>(&start.evidence.platform);
    if (!fixed || !fixed->ima_binary_log.empty() ||
        start.evidence.ima_bytes != start.ima_bytes ||
        start.evidence.ima_digest != start.ima_digest) {
        return {EvidenceTransferFailure::Malformed, std::nullopt};
    }
    const std::size_t fixed_bytes = fixed_platform_bytes(start.evidence.platform);
    if (start.ima_bytes > std::numeric_limits<std::size_t>::max() - fixed_bytes ||
        start.total_transfer_bytes != fixed_bytes + start.ima_bytes ||
        start.total_transfer_bytes > constants::kMaxFullEvidenceTransferBytes ||
        (start.mode == ImaEvidenceMode::Resume &&
         start.ima_bytes > constants::kMaxResumeImaSuffixBytes)) {
        return {EvidenceTransferFailure::DeclaredTotalTooLarge, std::nullopt};
    }
    if (start.total_chunks != chunk_count(static_cast<std::size_t>(start.ima_bytes)) ||
        start.total_chunks > constants::kMaxEvidenceTransferChunks) {
        return {EvidenceTransferFailure::TooManyChunks, std::nullopt};
    }
    if (start.transfer_id != evidence_transfer_id(start)) {
        return {EvidenceTransferFailure::BadTransferId, std::nullopt};
    }

    State state;
    state.start = start;
    state.sender = sender;
    state.deadline_ms = now_ms + constants::kEvidenceTransferDeadlineMs;
    // Allocation occurs only after every attacker-controlled declared size has
    // passed its mode-specific, total and chunk-count bounds.
    state.ima.reserve(static_cast<std::size_t>(start.ima_bytes));
    if (const auto it = early_.find(sender);
        it != early_.end() && it->second.challenge == start.challenge_digest &&
        it->second.transfer == start.transfer_id) {
        for (auto& [index, bytes] : it->second.chunks) {
            if (index < start.total_chunks) {
                state.held.emplace(index, std::move(bytes));
            }
        }
        state.pending_end = it->second.end;
        early_.erase(it);
    }
    State& live = live_.emplace(sender, std::move(state)).first->second;
    return try_finish(sender, live);
}

EvidenceTransferResult AttestationTransferReceiver::chunk(
    const NodeId& sender, const AttestationEvidenceChunk& chunk, uint64_t now_ms) {
    (void)expire(now_ms);
    if (chunk.bytes.empty() || chunk.bytes.size() > constants::kMaxEvidenceChunkBytes ||
        chunk.chunk_index >= constants::kMaxEvidenceTransferChunks) {
        return {EvidenceTransferFailure::ChunkTooLarge, std::nullopt};
    }
    State* state = find(sender, chunk.challenge_digest, chunk.transfer_id);
    if (!state) {
        if (early_.size() >= constants::kMaxConcurrentEvidenceTransfers &&
            !early_.contains(sender)) {
            return {EvidenceTransferFailure::ConcurrentLimit, std::nullopt};
        }
        early_slot(sender, chunk.challenge_digest, chunk.transfer_id, now_ms)
            .chunks[chunk.chunk_index] = chunk.bytes;
        return {EvidenceTransferFailure::None, std::nullopt};
    }
    if (chunk.chunk_index < state->next_chunk) {
        return {EvidenceTransferFailure::None, std::nullopt};
    }
    if (chunk.chunk_index >= state->start.total_chunks) {
        return {EvidenceTransferFailure::ExtraBytes, std::nullopt};
    }
    if (chunk.chunk_index > state->next_chunk) {
        state->held[chunk.chunk_index] = chunk.bytes;
        return {EvidenceTransferFailure::None, std::nullopt};
    }
    const auto failure = consume(*state, chunk.bytes);
    if (failure != EvidenceTransferFailure::None) {
        return {failure, std::nullopt};
    }
    return try_finish(sender, *state);
}

EvidenceTransferResult AttestationTransferReceiver::end(
    const NodeId& sender, const AttestationEvidenceEnd& end, uint64_t now_ms) {
    (void)expire(now_ms);
    State* state = find(sender, end.challenge_digest, end.transfer_id);
    if (!state) {
        if (early_.size() >= constants::kMaxConcurrentEvidenceTransfers &&
            !early_.contains(sender)) {
            return {EvidenceTransferFailure::ConcurrentLimit, std::nullopt};
        }
        early_slot(sender, end.challenge_digest, end.transfer_id, now_ms).end = end;
        return {EvidenceTransferFailure::None, std::nullopt};
    }
    if (end.total_transfer_bytes != state->start.total_transfer_bytes ||
        end.ima_bytes != state->start.ima_bytes ||
        end.total_chunks != state->start.total_chunks ||
        end.ima_digest != state->start.ima_digest ||
        end.platform_digest != state->start.platform_digest) {
        return {EvidenceTransferFailure::Malformed, std::nullopt};
    }
    state->pending_end = end;
    return try_finish(sender, *state);
}

std::size_t AttestationTransferReceiver::expire(uint64_t now_ms) {
    std::size_t removed = 0;
    for (auto it = live_.begin(); it != live_.end();) {
        if (now_ms >= it->second.deadline_ms) {
            it = live_.erase(it);
            ++removed;
        } else {
            ++it;
        }
    }
    for (auto it = early_.begin(); it != early_.end();) {
        it = now_ms >= it->second.deadline_ms ? early_.erase(it) : std::next(it);
    }
    return removed;
}

}  // namespace nexus::security
