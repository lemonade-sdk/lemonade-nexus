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
#include <LemonadeNexus/Security/Consensus/ConsensusTypes.hpp>
#include <LemonadeNexus/Security/Epoch/EpochAuthority.hpp>
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
};

/// A restarted node asks for quorum-certified state; the answer carries the
/// responder's high certificate, which proves the view the network reached.
struct SyncRequest {
    EpochId epoch = 0;
};

struct SyncResponse {
    QuorumCertificate high_qc;
};

/// A proposal always travels with the certificate it extends.
struct ProposalMessage {
    Proposal proposal;
    QuorumCertificate justify;
};

/// The activated epoch, announced by its members. Receivers validate it
/// against their own finalized transition state; the announcement itself
/// grants nothing.
struct EpochAnnouncement {
    EpochAuthority authority;
    Digest handoff_certificate_digest{};
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
                                  SyncResponse>;

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
