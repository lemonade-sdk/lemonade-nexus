#pragma once

// The router between the mesh transport and the security services.
//
// Inbound: bound, budget, decode, bind the envelope to the authenticated
// peer, check the compiled rulesets, the network, and the epoch window,
// drop duplicates, then hand the typed message to exactly one service. Every
// check runs before any signature or FROST work. The router never decides
// eligibility, safety, quorum, DKG validity, or authorization; the services
// do, and the router only carries their answers back onto the wire.
//
// Outbound: the services tell the router what to send and to whom. The
// transport never fans out on its own.

#include <LemonadeNexus/Security/Attestation/EvidenceProducer.hpp>
#include <LemonadeNexus/Security/SecurityRuntime.hpp>
#include <LemonadeNexus/Security/Transport/PairwiseSeal.hpp>
#include <LemonadeNexus/Security/Transport/SecurityCodec.hpp>
#include <LemonadeNexus/Security/Transport/SecurityTransport.hpp>

#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <vector>

namespace nexus::security {

enum class DropReason : uint16_t {
    Oversized,
    Flooded,
    Malformed,
    UnknownKind,
    SenderMismatch,
    RulesetMismatch,
    NetworkMismatch,
    EpochOutOfWindow,
    Duplicate,
    NoService,
    SealFailure,
    ServiceRejected,
};

struct RouteResult {
    bool delivered = false;
    std::optional<DropReason> dropped;
    /// The service's typed failure when dropped == ServiceRejected.
    std::optional<uint16_t> service_code;
};

/// Protocol outcomes the lifecycle driver acts on. The router reports; it
/// does not decide what happens next.
class ISecurityEvents {
public:
    virtual ~ISecurityEvents() = default;
    virtual void on_vote_sent(const Vote&, const NodeId&) {}
    virtual void on_certificate(const QuorumCertificate&) {}
    virtual void on_timeout_certificate(const TimeoutCertificate&) {}
    virtual void on_commits(const std::vector<ConsensusCommit>&) {}
    virtual void on_dkg_round1_complete(EpochId) {}
    virtual void on_dkg_complete(EpochId) {}
    virtual void on_dkg_failed(DkgFailure, std::optional<NodeId>) {}
    virtual void on_authority_signature(const AuthoritySignature&) {}
    /// The evidence rides along: a passing verdict also carries the epoch
    /// vote key the node bound.
    virtual void on_attestation_verdict(const AttestationVerdict&, const AttestationEvidence&) {}
    virtual void on_epoch_announcement(const EpochAnnouncement&, const NodeId&) {}
    virtual void on_genesis_founding(const GenesisFounding&, const NodeId&) {}
    virtual void on_dkg_transcript_attest(const DkgTranscriptAttest&) {}
    virtual void on_bootstrap_certificate(const BootstrapCertificate&, const NodeId&) {}
    /// A validated certificate from a peer: proof the network reached its
    /// view. The driver derives the restart view floor from these.
    virtual void on_sync_certificate(const QuorumCertificate&, const NodeId&) {}
};

struct SecurityRouterConfig {
    NetworkId network_id{};
};

class SecurityRouter {
public:
    SecurityRouter(SecurityRouterConfig config, SecurityRuntime& runtime,
                   ISecurityTransport& transport, ISecurityEvents& events,
                   PairwiseSealer& sealer, IEvidenceProducer* evidence_producer);

    /// Inbound entry from the transport. `now_ms` drives the flood window.
    RouteResult receive(const NodeId& authenticated_sender, std::span<const uint8_t> envelope,
                        uint64_t now_ms);

    /// Fills the compiled rulesets, the network, and this node as sender.
    [[nodiscard]] SecurityMessage compose(SecurityMessageKind kind, SecurityBody body,
                                          EpochId epoch) const;

    /// Applies an own message through the same dispatch as inbound traffic.
    /// The gates do not run: the message never crossed the wire.
    RouteResult deliver_local(SecurityMessage message);

    [[nodiscard]] bool send(const NodeId& to, const SecurityMessage& message);
    std::size_t broadcast(const SecurityMessage& message);

    /// Sends a pairwise DKG message with its payload sealed to the recipient.
    [[nodiscard]] bool send_sealed_dkg(const DkgMessage& message);

private:
    [[nodiscard]] bool within_budget(const NodeId& sender, uint64_t now_ms);
    [[nodiscard]] bool remember(std::span<const uint8_t> envelope);
    [[nodiscard]] bool sender_bound(const SecurityMessage& message,
                                    const NodeId& authenticated_sender) const;
    [[nodiscard]] bool epoch_in_window(const SecurityMessage& message) const;

    RouteResult dispatch(SecurityMessage& message);
    RouteResult route_proposal(const ProposalMessage& message);
    RouteResult route_vote(const Vote& vote);
    RouteResult route_timeout(const TimeoutVote& vote);
    RouteResult route_dkg(DkgMessage& message);
    RouteResult route_commitment(const FrostCommitmentMessage& message);
    RouteResult route_share(const FrostShareMessage& message);
    RouteResult route_challenge(const AttestationChallenge& challenge, const NodeId& from);
    RouteResult route_evidence(const AttestationEvidence& evidence);
    RouteResult route_announcement(const EpochAnnouncement& announcement, const NodeId& from);
    RouteResult route_sync_request(const SyncRequest& request, const NodeId& from);
    RouteResult route_sync_response(const SyncResponse& response, const NodeId& from);

    struct PeerBudget {
        uint64_t window_start_ms = 0;
        uint32_t count = 0;
    };

    SecurityRouterConfig config_;
    SecurityRuntime& runtime_;
    ISecurityTransport& transport_;
    ISecurityEvents& events_;
    PairwiseSealer& sealer_;
    IEvidenceProducer* evidence_producer_;

    std::map<NodeId, PeerBudget> budgets_;
    std::vector<Digest> seen_ring_;
    std::set<Digest> seen_;
    std::size_t seen_next_ = 0;
};

}  // namespace nexus::security
