#pragma once

// Bounded multi-message transfer of SVSM platform evidence.

#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <variant>
#include <vector>

namespace nexus::security {

struct AttestationEvidenceTransfer {
    AttestationEvidenceStart start;
    std::vector<AttestationEvidenceChunk> chunks;
    AttestationEvidenceEnd end;
};

/// Split an already signed complete SVSM bundle.  The log is carried only as
/// raw chunk bytes; the Start retains fixed evidence and the one signature over
/// the reconstructed complete bundle.
[[nodiscard]] std::optional<AttestationEvidenceTransfer> make_evidence_transfer(
    const AttestationEvidence& evidence);

enum class EvidenceTransferFailure : uint16_t {
    None,
    NoLiveChallenge,
    WrongSender,
    WrongChallenge,
    WrongProfile,
    WrongMode,
    DuplicateStart,
    ConcurrentLimit,
    DeclaredTotalTooLarge,
    TooManyChunks,
    BadTransferId,
    ChunkBeforeStart,  // reserved, not yet produced
    WrongChunkIndex,   // reserved, not yet produced
    DuplicateChunk,    // reserved, not yet produced
    ChunkTooLarge,
    ExtraBytes,
    MissingChunk,      // reserved, not yet produced
    WrongEvidenceHash,
    MultipleEnd,       // reserved, not yet produced
    TimedOut,          // reserved, not yet produced
    Malformed,
};

struct EvidenceTransferResult {
    EvidenceTransferFailure failure{EvidenceTransferFailure::None};
    std::optional<AttestationEvidence> evidence;

    [[nodiscard]] bool ok() const { return evidence.has_value(); }
};

/// Datagrams may arrive out of order, duplicated (the sender repeats the
/// burst), or ahead of their Start. Early pieces are held within the same
/// bounds a live transfer has; duplicates are ignored; any arrival order with
/// one surviving copy of each piece completes the transfer.
class AttestationTransferReceiver {
public:
    [[nodiscard]] EvidenceTransferResult begin(
        const NodeId& sender, const AttestationEvidenceStart& start,
        const AttestationChallenge& live_challenge, uint64_t now_ms);
    [[nodiscard]] EvidenceTransferResult chunk(
        const NodeId& sender, const AttestationEvidenceChunk& chunk, uint64_t now_ms);
    [[nodiscard]] EvidenceTransferResult end(
        const NodeId& sender, const AttestationEvidenceEnd& end, uint64_t now_ms);

    /// Clears expired partial transfers and held early pieces; no incomplete
    /// bytes survive the deadline.
    [[nodiscard]] std::size_t expire(uint64_t now_ms);
    [[nodiscard]] std::size_t live_transfers() const { return live_.size(); }

private:
    struct State {
        AttestationEvidenceStart start;
        NodeId sender{};
        uint64_t deadline_ms{};
        uint32_t next_chunk{};
        std::vector<uint8_t> ima;
        std::map<uint32_t, std::vector<uint8_t>> held;
        std::optional<AttestationEvidenceEnd> pending_end;
    };
    /// Pieces that arrived before their Start, one slot per sender.
    struct Early {
        Digest challenge{};
        Digest transfer{};
        std::map<uint32_t, std::vector<uint8_t>> chunks;
        std::optional<AttestationEvidenceEnd> end;
        uint64_t deadline_ms{};
    };

    [[nodiscard]] State* find(const NodeId& sender, const Digest& challenge,
                              const Digest& transfer);
    [[nodiscard]] EvidenceTransferFailure consume(State& state,
                                                  const std::vector<uint8_t>& bytes);
    [[nodiscard]] EvidenceTransferResult try_finish(const NodeId& sender, State& state);
    [[nodiscard]] Early& early_slot(const NodeId& sender, const Digest& challenge,
                                    const Digest& transfer, uint64_t now_ms);

    // One live transfer per sender on one observer.  Since a sender can have
    // only one live challenge here, this is also one per node/challenge.
    std::map<NodeId, State> live_;
    std::map<NodeId, Early> early_;
};

}  // namespace nexus::security
