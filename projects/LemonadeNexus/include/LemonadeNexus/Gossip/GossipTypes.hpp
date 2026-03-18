#pragma once

#include <LemonadeNexus/Core/TrustTypes.hpp>

#include <array>
#include <cstdint>
#include <string>

namespace nexus::gossip {

static constexpr uint16_t kGossipMagic   = 0x4C47; // "LG"
static constexpr uint8_t  kGossipVersion = 0x01;
static constexpr uint16_t kDefaultGossipPort = 9102;

enum class GossipMsgType : uint8_t {
    Digest        = 0x01,  // "here's my latest state"
    DeltaRequest  = 0x02,  // "send me deltas since seq N"
    DeltaResponse = 0x03,  // "here are deltas"
    AntiEntropy   = 0x04,  // "let's compare full state"
    PeerExchange  = 0x05,  // "here are peers I know"
    ServerHello   = 0x06,  // "here's my server certificate"
    TeeChallenge  = 0x07,  // "prove you have TEE hardware" (nonce challenge)
    TeeResponse   = 0x08,  // "here's my TEE attestation report" (challenge response)
    EnrollmentVoteRequest = 0x09, // "new server presented cert, cast your vote"
    EnrollmentVote        = 0x0A, // "I approve/reject server X"
    RootKeyRotation       = 0x0B, // "root key rotated, here's the new chain entry"
    ShamirShareOffer      = 0x0C, // "here's your encrypted Shamir share of the root key"
    ShamirShareSubmit     = 0x0D, // "submitting my share for root key reconstruction"
    PeerHealthReport      = 0x0E, // "here's my view of peer uptime/health"
    GovernanceProposal    = 0x0F, // "I propose changing protocol parameter X to Y"
    GovernanceVote        = 0x10, // "I approve/reject governance proposal P"
    AclDelta              = 0x11, // "ACL grant/revoke — distributed permission sync"
    DnsRecordSync         = 0x12, // "DNS record add/remove — distributed authoritative DNS"
    BackboneIpamSync      = 0x13, // "backbone IP allocate/release — server mesh IPAM sync"
};

#pragma pack(push, 1)
struct GossipPacketHeader {
    uint16_t      magic;            // kGossipMagic
    uint8_t       version;          // kGossipVersion
    GossipMsgType msg_type;
    uint8_t       sender_pubkey[32]; // Ed25519 public key
    uint16_t      payload_length;
    // signature (64 bytes) appended AFTER payload
};
#pragma pack(pop)

static constexpr std::size_t kGossipHeaderSize    = sizeof(GossipPacketHeader);
static constexpr std::size_t kGossipSignatureSize = 64; // Ed25519 signature

struct GossipPeer {
    std::string pubkey;              // base64 Ed25519 public key
    std::string endpoint;            // "ip:port" (gossip port, public internet)
    std::string backbone_endpoint;   // "ip:port" (gossip port, over WG backbone — preferred when available)
    std::string wg_pubkey;           // base64 X25519 WireGuard public key
    std::string backbone_ip;         // "172.16.0.X" (empty until allocated)
    uint16_t    http_port{9100};     // HTTP control plane port
    uint64_t    last_seen{0};        // Unix timestamp
    float       reputation{1.0f};
    std::string certificate_json;    // serialized ServerCertificate (may be empty)
    core::TrustTier trust_tier{core::TrustTier::Untrusted};  // zero-trust tier
};

struct GossipDigest {
    uint64_t                 latest_seq{0};
    std::array<uint8_t, 32>  tree_hash{};  // merkle-like tree hash
    uint32_t                 peer_count{0};
    uint64_t                 timestamp{0};
};

// ---------------------------------------------------------------------------
// Quorum-based enrollment
// ---------------------------------------------------------------------------

/// A single signed vote for/against a server enrollment.
struct EnrollmentVoteData {
    std::string request_id;       // matches the enrollment request
    std::string candidate_pubkey; // pubkey of server being enrolled
    std::string voter_pubkey;     // pubkey of the voting server
    bool        approve{false};
    std::string reason;           // "certificate_valid", "cert_invalid", "revoked", etc.
    uint64_t    timestamp{0};
    std::string signature;        // Ed25519 over canonical vote JSON
};

/// Tracks a pending enrollment with collected votes.
struct EnrollmentBallot {
    enum class State : uint8_t {
        Collecting = 0,
        Approved   = 1,
        Rejected   = 2,
        TimedOut   = 3,
    };

    std::string    request_id;
    std::string    candidate_pubkey;
    std::string    candidate_server_id;
    std::string    certificate_json;     // full ServerCertificate JSON
    std::string    sponsor_pubkey;       // server that first received ServerHello
    uint64_t       created_at{0};
    uint64_t       timeout_at{0};
    State          state{State::Collecting};
    uint32_t       retries{0};
    std::vector<EnrollmentVoteData> votes;
};

// ---------------------------------------------------------------------------
// Democratic governance — Tier1 parameter changes
// ---------------------------------------------------------------------------

/// Goverable protocol parameters (the only ones that can change via vote).
enum class GovernableParam : uint8_t {
    RotationIntervalSec = 0x01,  // root key rotation interval
    ShamirQuorumRatio   = 0x02,  // Shamir K = ceil(N * ratio)
    MinTier1Uptime      = 0x03,  // minimum uptime for Tier1 authority
};

/// A governance proposal to change a protocol parameter.
struct GovernanceProposalData {
    std::string       proposal_id;       // unique ID (UUID or hash)
    std::string       proposer_pubkey;   // Tier1 peer that proposed the change
    GovernableParam   parameter;         // which parameter to change
    std::string       new_value;         // proposed new value (serialized)
    std::string       old_value;         // current value at proposal time (safety check)
    std::string       rationale;         // human-readable reason for the change
    uint64_t          created_at{0};     // Unix timestamp
    uint64_t          expires_at{0};     // vote window end
    std::string       signature;         // Ed25519 over canonical JSON (excludes this field)
};

/// A single signed vote on a governance proposal.
struct GovernanceVoteData {
    std::string proposal_id;      // matches the proposal
    std::string voter_pubkey;     // Tier1 peer casting the vote
    bool        approve{false};
    std::string reason;           // optional reason
    uint64_t    timestamp{0};
    std::string signature;        // Ed25519 over canonical vote JSON
};

/// Tracks a governance proposal with collected votes.
struct GovernanceBallot {
    enum class State : uint8_t {
        Collecting = 0,
        Approved   = 1,
        Rejected   = 2,
        TimedOut   = 3,
    };

    GovernanceProposalData          proposal;
    State                           state{State::Collecting};
    std::vector<GovernanceVoteData> votes;
};

// ---------------------------------------------------------------------------
// Distributed ACL sync
// ---------------------------------------------------------------------------

/// A signed ACL mutation that propagates via gossip.
struct AclDeltaData {
    std::string delta_id;          // unique ID for deduplication
    std::string operation;         // "grant" or "revoke"
    std::string user_id;
    std::string resource;
    uint32_t    permissions{0};    // bitmask to grant or revoke
    uint64_t    timestamp{0};
    std::string signer_pubkey;     // server that originated the change
    std::string signature;         // Ed25519 over canonical JSON (excludes this field)
};

// ---------------------------------------------------------------------------
// Distributed DNS record sync
// ---------------------------------------------------------------------------

/// A signed DNS record mutation that propagates via gossip.
struct DnsRecordDelta {
    std::string delta_id;          // unique ID for deduplication
    std::string operation;         // "set" or "remove"
    std::string fqdn;             // fully qualified domain name
    std::string record_type;      // "A", "AAAA", "TXT", "NS", "CNAME"
    std::string value;            // record value (IP, TXT content, etc.)
    uint32_t    ttl{60};          // TTL in seconds
    uint64_t    timestamp{0};
    std::string signer_pubkey;    // server that originated the change
    std::string signature;        // Ed25519 over canonical JSON (excludes this field)
};

} // namespace nexus::gossip
