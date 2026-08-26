#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace nexus::gossip {

static constexpr uint16_t kGossipMagic   = 0x4C47; // "LG"
static constexpr uint8_t  kGossipVersion = 0x01;
static constexpr uint16_t kDefaultGossipPort = 9102;

/// Cap on peers this node will track. Peer exchange takes entries from
/// unauthenticated senders, so without a cap a stranger can grow the table
/// until the process runs out of memory. A peer holding a root-signed
/// certificate is mesh membership and is never refused by this cap.
static constexpr std::size_t kMaxTrackedPeers = 512;

enum class GossipMsgType : uint8_t {
    Digest        = 0x01,  // "here's my latest state"
    DeltaRequest  = 0x02,  // "send me deltas since seq N"
    DeltaResponse = 0x03,  // "here are deltas"
    AntiEntropy   = 0x04,  // "let's compare full state"
    PeerExchange  = 0x05,  // "here are peers I know"
    ServerHello   = 0x06,  // "here's my server certificate"
    // 0x07-0x10 retired (old network-authority protocol: TEE challenge/response,
    // enrollment votes, root-key rotation, Shamir shares, peer health,
    // governance). Reserved forever — never reuse these values.
    AclDelta              = 0x11, // "ACL grant/revoke — distributed permission sync"
    DnsRecordSync         = 0x12, // "DNS record add/remove — distributed authoritative DNS"
    BackboneIpamSync      = 0x13, // "backbone IP allocate/release — server mesh IPAM sync"
    NsSlotClaim           = 0x14, // "democratic NS slot claim — ns1-ns9 bootstrap nameservers"
    MisbehaviorProofBroadcast = 0x15, // "proof a peer equivocated — verify and ban the accused"
    SecurityEnvelope      = 0x16,  // opaque security-protocol envelope; routed to SecurityRuntime, never relayed
};

// Compile-time pin on the retired range: a new enumerator inside [0x07, 0x10]
// would revive wire values the removed authority protocol used, and old peers
// would misparse it. Every live enumerator must stay outside the range.
namespace detail {
constexpr bool outside_retired_range(GossipMsgType t) {
    const auto v = static_cast<uint8_t>(t);
    return v < 0x07 || v > 0x10;
}
}  // namespace detail
static_assert(detail::outside_retired_range(GossipMsgType::Digest) &&
              detail::outside_retired_range(GossipMsgType::DeltaRequest) &&
              detail::outside_retired_range(GossipMsgType::DeltaResponse) &&
              detail::outside_retired_range(GossipMsgType::AntiEntropy) &&
              detail::outside_retired_range(GossipMsgType::PeerExchange) &&
              detail::outside_retired_range(GossipMsgType::ServerHello) &&
              detail::outside_retired_range(GossipMsgType::AclDelta) &&
              detail::outside_retired_range(GossipMsgType::DnsRecordSync) &&
              detail::outside_retired_range(GossipMsgType::BackboneIpamSync) &&
              detail::outside_retired_range(GossipMsgType::NsSlotClaim) &&
              detail::outside_retired_range(GossipMsgType::MisbehaviorProofBroadcast) &&
              detail::outside_retired_range(GossipMsgType::SecurityEnvelope),
              "gossip wire values 0x07-0x10 are retired and reserved forever");

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
    std::string endpoint;            // "ip:port" as observed (UDP source) — used for direct replies
    std::string advertised_endpoint; // "ip:port" the peer says it's reachable at — shared with third parties (the observed source can be a NAT/VPN artifact valid only from our vantage point)
    bool        advertised_confirmed{false}; // advertised_endpoint matched the observed UDP source at hello time — only then is it safe to relay/seed to third parties
    std::string backbone_endpoint;   // "ip:port" (gossip port, over WG backbone — preferred when available)
    std::string wg_pubkey;           // base64 X25519 mesh public key
    std::string backbone_ip;         // "172.16.0.X" (empty until allocated)
    std::string region;              // cloud region code (e.g. "us-east-1")
    uint16_t    http_port{9100};     // HTTP control plane port
    uint64_t    last_seen{0};        // Unix timestamp
    float       reputation{1.0f};
    std::string certificate_json;    // serialized ServerCertificate (may be empty)
};

struct GossipDigest {
    uint64_t                 latest_seq{0};
    std::array<uint8_t, 32>  tree_hash{};  // merkle-like tree hash
    uint32_t                 peer_count{0};
    uint64_t                 timestamp{0};
};

// ---------------------------------------------------------------------------
// Quorum-based enrollment — NO wire use any more (the vote message types are
// retired). Kept only because ServerAdmissionService still compiles against
// these; their reduction is a later stage.
// ---------------------------------------------------------------------------

/// A single signed vote for/against a server enrollment.
struct EnrollmentVoteData {
    std::string request_id;       // matches the enrollment request
    std::string candidate_pubkey; // pubkey of server being enrolled
    std::string voter_pubkey;     // pubkey of the voting server
    bool        approve{false};
    std::string reason;           // "certificate_valid", "cert_invalid", "revoked", etc.
    uint64_t    timestamp{0};
    std::string claim_hash;       // admission claim this vote is about ("" = enrollment)
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

    // Enrollment gates acceptance of an already-root-signed cert; Admission
    // decides whether to ISSUE a cert to a certless candidate (governed join).
    enum class Kind : uint8_t { Enrollment = 0, Admission = 1 };

    std::string    request_id;
    std::string    candidate_pubkey;
    std::string    candidate_server_id;
    std::string    certificate_json;     // full ServerCertificate JSON (Enrollment)
    std::string    admission_claim_json; // candidate's self-signed claim (Admission)
    // SHA-256 (hex) of the bytes the candidate signed (Admission). Recomputed
    // by each voter, never taken on the sponsor's word, and signed by each vote.
    std::string    claim_hash;
    std::string    sponsor_pubkey;       // server that first received ServerHello
    uint64_t       created_at{0};
    uint64_t       timeout_at{0};
    State          state{State::Collecting};
    Kind           kind{Kind::Enrollment};
    float          required_ratio{0.0f}; // 0 = use configured enrollment ratio
    uint32_t       retries{0};
    std::vector<EnrollmentVoteData> votes;
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

// ---------------------------------------------------------------------------
// Democratic NS slot claiming (ns1-ns9 bootstrap nameservers)
// ---------------------------------------------------------------------------

/// A signed NS slot claim that propagates via gossip.
/// The first 9 servers to join the mesh claim ns1-ns9 slots (LWW conflict resolution).
struct NsSlotClaimData {
    uint8_t     slot{0};           // 1-9
    std::string server_pubkey;     // base64 Ed25519
    std::string server_ip;         // public IP
    std::string region;            // cloud region code
    uint64_t    timestamp{0};      // LWW conflict resolution
    std::string signature;         // Ed25519 signature
};

} // namespace nexus::gossip
