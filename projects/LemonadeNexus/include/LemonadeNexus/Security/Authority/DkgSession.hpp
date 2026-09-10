#pragma once

// One dealerless DKG for one target epoch (architecture 20).
//
// The session binds every message to the network, the target epoch, the
// frozen participant set, the sender identity and incarnation, and the round.
// A message that fails any binding is rejected before any FROST work. The
// caller feeds round-1 broadcasts from the finalized transcript (HotStuff for
// epoch E+1, Genesis for epoch 1) and round-2 packages from the authenticated
// pairwise channel. The threshold is protocol-controlled: the session refuses
// a configuration whose threshold differs from the compiled formula.
//
// A new participant set is a new session. The old authority secret is never
// reshared.

#include <LemonadeNexus/Crypto/FrostProvider.hpp>
#include <LemonadeNexus/Security/Epoch/Tier1Set.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace nexus::security {

enum class DkgRound : uint16_t {
    Round1Broadcast = 1,
    Round2Pairwise = 2,
};

struct DkgMessage {
    NetworkId network_id{};
    EpochId target_epoch = 0;
    Digest participant_set_digest{};

    NodeId sender;
    IncarnationId sender_incarnation = 0;
    DkgRound round = DkgRound::Round1Broadcast;

    /// All-zero for a broadcast; the addressed participant for a pairwise
    /// package.
    NodeId recipient;

    std::vector<uint8_t> payload;
};

[[nodiscard]] Digest dkg_message_digest(const DkgMessage& message);

struct DkgConfiguration {
    NetworkId network_id{};
    EpochId target_epoch = 0;

    Tier1Set participants{*Tier1Set::from_nodes({})};
    std::map<NodeId, IncarnationId> incarnations;
    std::size_t threshold = 0;

    NodeId self;

    /// What every message of this session must carry in place of the bare
    /// participant-set digest. For an epoch transition this is the finalized
    /// readiness digest, which binds the plan, the attempt, the selected set
    /// and the registered vote keys all at once — so a replay from a failed
    /// attempt names a session nobody is running. Zero means the participant
    /// set digest itself, which is the Genesis form.
    Digest session_binding{};
};

enum class DkgPhase : uint16_t {
    Created,
    Round1,
    Round2,
    Complete,
    Failed,
};

enum class DkgFailure : uint16_t {
    None,
    NotStarted,
    ThresholdInvalid,
    ParticipantSetInvalid,
    WrongNetwork,
    WrongEpoch,
    WrongParticipantSet,
    UnknownSender,
    IncarnationMismatch,
    WrongRound,
    WrongRecipient,
    DuplicateMessage,
    Equivocation,
    InvalidPackage,
    CryptoFailure,
    WrongPhase,
};

struct DkgResult {
    EpochId target_epoch = 0;
    Digest participant_set_digest{};
    Digest transcript_digest{};

    crypto::Ed25519PublicKey group_public_key{};
    crypto::FrostBytes public_key_package;
    crypto::FrostKeyShare key_share;

    crypto::ParticipantIndex own_index = 0;
    std::map<NodeId, crypto::ParticipantIndex> index_of;
};

class DkgSession {
public:
    explicit DkgSession(DkgConfiguration configuration);

    /// The digest every message of this session carries: the configured
    /// session binding, or the bare participant-set digest at Genesis.
    [[nodiscard]] Digest session_digest() const {
        return config_.session_binding != Digest{} ? config_.session_binding
                                                   : config_.participants.digest();
    }

    /// Runs FROST part 1. Returns the own round-1 broadcast, or nullopt with
    /// failure() set.
    [[nodiscard]] std::optional<DkgMessage> start();

    /// Accepts one round-1 broadcast from the finalized transcript.
    [[nodiscard]] DkgFailure receive_broadcast(const DkgMessage& message);

    /// True once every participant's round-1 broadcast is present.
    [[nodiscard]] bool round1_complete() const;

    /// Runs FROST part 2 once round 1 is complete. Returns one pairwise
    /// message per other participant; empty with failure() set on error.
    [[nodiscard]] std::vector<DkgMessage> round2_messages();

    /// Accepts one round-2 package addressed to this participant.
    [[nodiscard]] DkgFailure receive_pairwise(const DkgMessage& message);

    /// Runs FROST part 3 once every round-2 package is present.
    [[nodiscard]] bool finish();

    [[nodiscard]] bool complete() const { return phase_ == DkgPhase::Complete; }
    [[nodiscard]] DkgPhase phase() const { return phase_; }
    [[nodiscard]] DkgFailure failure() const { return failure_; }

    /// The participant whose provably invalid message failed the session, when
    /// the failure is attributable. The current epoch records this evidence
    /// and replaces the participant (architecture 22).
    [[nodiscard]] std::optional<NodeId> culprit() const { return culprit_; }

    /// Digest of the finalized round-1 transcript. Valid once round 1 is
    /// complete; every participant must derive the same value.
    [[nodiscard]] std::optional<Digest> transcript_digest() const;

    /// Moves the result out exactly once. The key share leaves with it.
    [[nodiscard]] std::optional<DkgResult> take_result();

private:
    [[nodiscard]] DkgFailure check_binding(const DkgMessage& message, DkgRound expected_round);
    void fail(DkgFailure failure, std::optional<NodeId> culprit = std::nullopt);
    [[nodiscard]] DkgMessage make_message(DkgRound round, const NodeId& recipient,
                                          std::vector<uint8_t> payload) const;

    DkgConfiguration config_;
    std::map<NodeId, crypto::ParticipantIndex> index_of_;
    std::map<crypto::ParticipantIndex, NodeId> node_of_;
    crypto::ParticipantIndex own_index_ = 0;

    DkgPhase phase_ = DkgPhase::Created;
    DkgFailure failure_ = DkgFailure::None;
    std::optional<NodeId> culprit_;

    crypto::FrostDkgRound1 round1_;
    crypto::FrostDkgRound2 round2_;
    std::vector<uint8_t> own_round1_payload_;

    std::map<NodeId, std::vector<uint8_t>> round1_payloads_;
    std::map<NodeId, std::vector<uint8_t>> round2_payloads_;

    std::optional<DkgResult> result_;
};

}  // namespace nexus::security
