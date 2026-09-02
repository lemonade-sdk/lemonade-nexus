#pragma once

// The compiled Nexus security rules.
//
// Every value here is protocol truth, not operator preference. The verified
// binary carries these constants; binary attestation is what protects them.
// Changing a value that alters deterministic security behavior requires a new
// ruleset version and a new verified release — never a configuration file.
//
// Architecture reference: Security Architecture Final Draft 1.1, sections 2,
// 13, 16, 17 and 20.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace nexus::security::constants {

// --- Ruleset identity -------------------------------------------------------

// Covers deterministic security behavior: Tier 1 prerequisites, selection
// rules, threshold formulas, DKG rules, and state-transition validity.
inline constexpr uint16_t kSecurityRulesetVersion = 1;

// Covers consensus safety and consensus validity. A safety-rule change MUST
// increment this value.
inline constexpr uint16_t kConsensusRulesetVersion = 1;

inline constexpr uint16_t kBftProtocolVersion = 1;
inline constexpr uint16_t kQcFormatVersion = 1;

// --- Domain-separation strings ----------------------------------------------

inline constexpr std::string_view kBftProtocolDomain = "LEMONADE-NEXUS-HOTSTUFF-V1";
inline constexpr std::string_view kFrostCiphersuite = "FROST(Ed25519, SHA-512)";
inline constexpr std::string_view kTier1AttestDomain = "LEMONADE-NEXUS-T1-ATTEST-V1";
inline constexpr std::string_view kTier1SelectDomain = "LEMONADE-NEXUS-T1-SELECT-V1";
inline constexpr std::string_view kLeaderOrderDomain = "LEMONADE-NEXUS-HOTSTUFF-LEADER-V1";

// --- Tier 1 population ------------------------------------------------------

inline constexpr std::size_t kBootstrapThreshold = 5;
inline constexpr std::size_t kMinActiveTier1 = 5;
inline constexpr std::size_t kPreferredMinActiveTier1 = 7;
inline constexpr std::size_t kMaxActiveTier1 = 31;
inline constexpr std::size_t kMinTier1Reserve = 2;

struct Tier1TargetStep {
    std::size_t min_admitted;
    std::size_t target;
};

// Compiled step table: admitted mesh servers -> desired active Tier 1 count.
// Below the first step the mesh is pre-quorum and the target is zero.
inline constexpr std::array<Tier1TargetStep, 10> kTier1TargetSteps{{
    {5, 5},
    {10, 7},
    {25, 10},
    {100, 13},
    {250, 16},
    {500, 19},
    {1000, 22},
    {2500, 25},
    {5000, 28},
    {10000, 31},
}};

// --- Quorum formulas --------------------------------------------------------

// f(N) = floor((N - 1) / 3). Zero is not a valid population; treat it as
// zero faults so the size_t subtraction cannot wrap.
[[nodiscard]] constexpr std::size_t max_byzantine_faults(std::size_t n) {
    return n == 0 ? 0 : (n - 1) / 3;
}

[[nodiscard]] constexpr std::size_t consensus_quorum(std::size_t n) {
    return n - max_byzantine_faults(n);
}

// The bootstrap threshold is a floor, never a ceiling: a larger active set
// always raises the authority threshold with it.
[[nodiscard]] constexpr std::size_t authority_threshold(std::size_t n) {
    const std::size_t quorum = consensus_quorum(n);
    return quorum < kBootstrapThreshold ? kBootstrapThreshold : quorum;
}

[[nodiscard]] constexpr std::size_t tier1_target_count(std::size_t admitted) {
    std::size_t target = 0;
    for (const auto& step : kTier1TargetSteps) {
        if (admitted >= step.min_admitted) {
            target = step.target;
        }
    }
    return target;
}

// --- Epoch and attestation cadence ------------------------------------------

inline constexpr uint64_t kTargetEpochSeconds = 3600;
inline constexpr uint64_t kReattestIntervalSeconds = 900;
inline constexpr uint64_t kFinalAttestMaxAgeSeconds = 300;

// How long an authorized next-epoch DKG may sit incomplete before the attempt
// fails and the deterministic replacement runs. Liveness only: a stall never
// activates anything, and the silent participants are excluded from the next
// attempt by their own observed silence. Wide enough that a run of view
// timeouts at the pacemaker's maximum backoff can never masquerade as one.
inline constexpr uint64_t kDkgStallSeconds = 300;

// Tier 1 attestation is expensive; the budget binds to node identity and
// epoch, never to an IP address (architecture 24). Initial value; a tuning
// item.
inline constexpr uint32_t kMaxTier1AttestAttemptsPerEpoch = 4;

// --- Mesh eligibility observations ------------------------------------------

// Distinct attestations one observer must have verified before it counts
// toward continuity. Two rounds, and because an observer only issues a
// challenge every kReattestIntervalSeconds, two of them span at least one
// interval without anyone trusting a peer's clock.
inline constexpr std::size_t kMinContinuityObservations = 2;

// Observations expire at the epoch boundary and affect the NEXT epoch's
// eligibility only. A node stays eligible while the mesh keeps seeing it, never
// because it was healthy once; and nothing here can shrink a frozen epoch.
inline constexpr uint64_t kObservationValidityEpochs = 1;

// Distinct attestations kept per observer per subject. Well above the rounds
// one epoch can hold, so it bounds memory against a flooding observer without
// ever being reached by honest cadence.
inline constexpr std::size_t kMaxContinuityAttestations = 8;

// --- HotStuff safety rules --------------------------------------------------

inline constexpr std::size_t kHotStuffChainLength = 3;

inline constexpr bool kVoteOncePerView = true;
inline constexpr bool kRequireParentQc = true;
inline constexpr bool kRequireSafeNodeRule = true;
inline constexpr bool kLockOnTwoChain = true;
inline constexpr bool kCommitOnThreeChain = true;

inline constexpr bool kEpochMembershipFrozen = true;
inline constexpr bool kAllowWeightedVotes = false;
inline constexpr bool kAllowMixedConsensusRulesets = false;

inline constexpr bool kQcUsesExplicitSignatures = true;
inline constexpr bool kQcDeduplicateByNodeId = true;

inline constexpr uint64_t kConsensusVoteKeyLifetimeEpochs = 1;

inline constexpr bool kMembershipChangesOnlyAtEpochBoundary = true;
inline constexpr bool kConsensusRuleChangesOnlyAtEpochBoundary = true;
inline constexpr bool kCheckpointEveryCommit = true;
inline constexpr bool kSignCanonicalDigestOnly = true;

// --- Pacemaker (liveness only; never part of message validity) --------------

inline constexpr uint64_t kViewTimeoutBaseMs = 2000;
inline constexpr uint64_t kViewTimeoutMaxMs = 30000;
inline constexpr uint64_t kViewTimeoutBackoffFactor = 2;
inline constexpr uint32_t kTimeoutResetAfterCommittedBlocks = 3;

// --- Consensus resource limits (applied before expensive work) --------------

inline constexpr std::size_t kMaxConsensusBlockBytes = 256 * 1024;
inline constexpr std::size_t kMaxTransitionsPerBlock = 128;
inline constexpr uint64_t kMaxFutureViewDistance = 64;
inline constexpr std::size_t kMaxPendingProposals = 128;
inline constexpr std::size_t kMaxQcSignatures = kMaxActiveTier1;

// --- Security transport bounds (applied before any parse or crypto work) ----

inline constexpr uint8_t kSecurityWireVersion = 1;
inline constexpr std::size_t kMaxSecurityMessageBytes = 60000;
inline constexpr std::size_t kMaxPlatformEvidenceWireBytes = 56 * 1024;
inline constexpr std::size_t kMaxDkgPayloadBytes = 4096;
inline constexpr std::size_t kMaxFrostPayloadBytes = 1024;
inline constexpr std::size_t kMaxCiphersuiteNameBytes = 64;

// Per-peer message budget: a member cannot drive the router faster than this.
inline constexpr uint32_t kSecurityPeerMessagesPerWindow = 256;
inline constexpr uint64_t kSecurityFloodWindowMs = 1000;
inline constexpr std::size_t kSecurityTrackedPeers = 512;
inline constexpr std::size_t kSecurityDedupeWindow = 4096;

// The uncommitted chain is at most a few blocks in chained HotStuff; the
// sync reply is bounded well above that and well below the envelope limit.
inline constexpr std::size_t kMaxSyncChainBlocks = 8;

// Handoff-chain links per page. A link at the largest population is under
// 10 KB on the wire, so four keep the page inside the envelope limit with the
// epoch-1 base beside them. A longer history is fetched page by page; nothing
// accepts one attacker-sized chain object.
inline constexpr std::size_t kMaxHandoffChainLinks = 4;

// --- Compile-time checks against the architecture tables --------------------

static_assert(max_byzantine_faults(5) == 1 && consensus_quorum(5) == 4);
static_assert(max_byzantine_faults(6) == 1 && consensus_quorum(6) == 5);
static_assert(max_byzantine_faults(7) == 2 && consensus_quorum(7) == 5);
static_assert(max_byzantine_faults(10) == 3 && consensus_quorum(10) == 7);
static_assert(max_byzantine_faults(31) == 10 && consensus_quorum(31) == 21);

static_assert(authority_threshold(5) == 5);
static_assert(authority_threshold(6) == 5);
static_assert(authority_threshold(7) == 5);
static_assert(authority_threshold(8) == 6);
static_assert(authority_threshold(31) == 21);

static_assert(tier1_target_count(4) == 0);
static_assert(tier1_target_count(5) == 5);
static_assert(tier1_target_count(24) == 7);
static_assert(tier1_target_count(25) == 10);
static_assert(tier1_target_count(10000) == 31);

}  // namespace nexus::security::constants
