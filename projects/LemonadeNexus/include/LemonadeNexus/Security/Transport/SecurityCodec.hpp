#pragma once

// The wire codec for security protocol messages.
//
// Every message has a fixed, hand-written binary layout: little-endian
// integers, fixed-size digests and keys, and length-prefixed byte fields with
// an explicit maximum. There is no generic parser, no nesting, and no
// permissive mode: a byte stream either decodes to exactly one typed message
// with no bytes left over, or it is rejected. Digests and signatures are
// computed over the typed objects (CanonicalEncoding), never over these
// transport bytes.

#include <LemonadeNexus/Security/Attestation/AttestationTypes.hpp>
#include <LemonadeNexus/Security/Authority/AuthorityService.hpp>
#include <LemonadeNexus/Security/Authority/DkgSession.hpp>
#include <LemonadeNexus/Security/Consensus/CommitProof.hpp>
#include <LemonadeNexus/Security/Consensus/ConsensusTypes.hpp>
#include <LemonadeNexus/Security/Eligibility/EligibilityObservation.hpp>
#include <LemonadeNexus/Security/Eligibility/ParticipationProof.hpp>
#include <LemonadeNexus/Security/Epoch/EpochAuthority.hpp>
#include <LemonadeNexus/Security/Epoch/NextEpochPlan.hpp>
#include <LemonadeNexus/Security/Genesis/BootstrapCertificate.hpp>
#include <LemonadeNexus/Security/Genesis/GenesisMessages.hpp>
#include <LemonadeNexus/Security/Policy/SecurityTypes.hpp>

#include <cstdint>
#include <span>
#include <variant>
#include <vector>

namespace nexus::security {

enum class SecurityMessageKind : uint16_t {
    AttestationChallenge = 1,
    AttestationEvidence = 2,
    HotStuffProposal = 3,
    HotStuffVote = 4,
    HotStuffTimeout = 5,
    DkgBroadcast = 6,
    DkgPairwise = 7,
    FrostCommitment = 8,
    FrostSignatureShare = 9,
    EpochAnnouncement = 10,
    GenesisFounding = 11,
    DkgTranscriptAttest = 12,
    BootstrapCertificate = 13,
    SyncRequest = 14,
    SyncResponse = 15,
    EligibilityObservation = 16,
    GenesisEligibilityAttest = 17,
    ParticipationChallenge = 18,
    ParticipationResponse = 19,
    NextEpochPlanProof = 20,
    CandidateStateReady = 21,
    ReadinessProof = 22,
    EpochHandoffProof = 23,
    AuthorityChainRequest = 24,
    AuthorityChainPage = 25,
};

/// A restarted node asks for quorum-certified state; the answer carries the
/// responder's high certificate, which proves the view the network reached.
struct SyncRequest {
    EpochId epoch = 0;
};

struct SyncResponse;  // defined after ProposalMessage


/// A proposal always travels with the certificate it extends.
struct ProposalMessage {
    Proposal proposal;
    QuorumCertificate justify;
};

struct SyncResponse {
    QuorumCertificate high_qc;
    /// The responder's uncommitted chain, oldest first: block k is certified
    /// by block k+1's justify, the last block by high_qc. A restarted node
    /// rebuilds chain state from these certified facts.
    std::vector<ProposalMessage> chain;
};

/// The activated epoch, announced by its members. Receivers validate it
/// against their own finalized transition state; the announcement itself
/// grants nothing.
struct EpochAnnouncement {
    EpochAuthority authority;
    Digest handoff_certificate_digest{};
};

/// The finalized plan, delivered to a selected candidate with everything it
/// needs to verify the finality itself: the three-chain proof, and the current
/// membership's vote keys, checkable against the anchored set digests. A hint
/// wrapped around a proof — the proof decides.
struct NextEpochPlanProof {
    NextEpochPlan plan;
    CommitProof proof;
    /// The current epoch's frozen vote keys, one per member.
    std::vector<std::pair<NodeId, crypto::Ed25519PublicKey>> current_vote_keys;
};

/// A pending candidate's signed statement of exactly three facts: it
/// possesses and verified a current certified checkpoint at or above the
/// plan's, it completed its local verified sync procedure, and this is the
/// state it adopted. It does NOT prove physical possession of every state
/// object — a Byzantine candidate can lie about its local storage, and
/// nothing may depend on that assertion. Safety never does: current HotStuff
/// selected the candidate, finalizes its readiness, a fresh DKG must
/// complete, current HotStuff finalizes the handoff, and the new epoch
/// tolerates at most f Byzantine members like any other.
struct CandidateStateReadyMsg {
    NetworkId network_id{};
    Digest plan_digest{};
    NodeId node{};
    IncarnationId incarnation{};
    QuorumCertificate verified_qc;
    crypto::Ed25519Signature identity_signature{};
};

[[nodiscard]] Digest candidate_state_ready_digest(const CandidateStateReadyMsg& message);

/// The finalized readiness set with its commit proof. Receiving it authorizes
/// exactly one thing: joining the DKG session it names.
struct ReadinessProofMsg {
    CandidateReadiness readiness;
    CommitProof proof;
};

/// The finalized handoff with its commit proof. Verifying it is the one and
/// only activation path for a node that was not in the old epoch.
struct EpochHandoffProofMsg {
    EpochHandoff handoff;
    CommitProof proof;
};

/// Asks any peer for the handoff chain beyond the requester's verified
/// authority. Idempotent, nonce-free, answered from local records.
struct AuthorityChainRequest {
    /// The epoch the requester's verified authority already covers; zero for
    /// a fresh node holding only the pinned Genesis anchor.
    EpochId have_epoch = 0;
};

/// One bounded page of the handoff chain, oldest link first. Candidate data:
/// the receiver verifies the base against its pinned Genesis key and every
/// link against its own advancing authority. A peer supplies bytes, never
/// trust.
struct AuthorityChainPage {
    /// Present when the page starts at Genesis: the certificate plus the
    /// epoch-1 member and vote-key listing it commits to by digest.
    bool has_base = false;
    BootstrapCertificate base_certificate;
    std::vector<std::pair<NodeId, crypto::Ed25519PublicKey>> base_vote_keys;
    /// Consecutive links, at most kMaxHandoffChainLinks per page.
    std::vector<EpochHandoffProofMsg> links;
};

using SecurityBody = std::variant<AttestationChallenge,
                                  AttestationEvidence,
                                  ProposalMessage,
                                  Vote,
                                  TimeoutVote,
                                  DkgMessage,
                                  FrostCommitmentMessage,
                                  FrostShareMessage,
                                  EpochAnnouncement,
                                  GenesisFounding,
                                  DkgTranscriptAttest,
                                  BootstrapCertificate,
                                  SyncRequest,
                                  SyncResponse,
                                  EligibilityObservation,
                                  GenesisEligibilityAttest,
                                  ParticipationChallenge,
                                  ParticipationResponse,
                                  NextEpochPlanProof,
                                  CandidateStateReadyMsg,
                                  ReadinessProofMsg,
                                  EpochHandoffProofMsg,
                                  AuthorityChainRequest,
                                  AuthorityChainPage>;

struct SecurityMessage {
    SecurityMessageKind kind = SecurityMessageKind::AttestationChallenge;
    SecurityRulesetVersion security_ruleset = 0;
    ConsensusRulesetVersion consensus_ruleset = 0;
    NetworkId network_id{};
    EpochId epoch = 0;
    NodeId sender;
    SecurityBody body;
};

enum class CodecError : uint16_t {
    Truncated,
    Oversized,
    BadVersion,
    UnknownKind,
    KindMismatch,
    CountTooLarge,
    LengthTooLarge,
    TrailingBytes,
    BadValue,
};

/// The kind a body carries. A DkgMessage is broadcast or pairwise by its
/// round; an invalid round yields nullopt.
[[nodiscard]] std::optional<SecurityMessageKind> kind_of(const SecurityBody& body);

/// Encodes one envelope. Returns an empty vector when the message is not
/// encodable: kind and body disagree, or a field exceeds its wire bound.
[[nodiscard]] std::vector<uint8_t> encode_security_message(const SecurityMessage& message);

/// Decodes one complete envelope. Bounds are checked before any allocation
/// that depends on attacker-chosen lengths, and every byte must be consumed.
[[nodiscard]] std::variant<SecurityMessage, CodecError> decode_security_message(
    std::span<const uint8_t> bytes);

}  // namespace nexus::security
