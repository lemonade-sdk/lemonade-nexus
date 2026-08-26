// The security protocol over encoded envelopes.
//
// Five runtimes talk only through SecurityRouter and an in-memory transport
// that queues envelopes and delivers them in order. Every DKG package, vote,
// commitment, and share crosses the codec. The attestation verifier's
// positive path needs a confidential VM, so verdicts are constructed.

#include <LemonadeNexus/Security/Consensus/VoteKey.hpp>
#include <LemonadeNexus/Security/Genesis/GenesisService.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Security/Transport/SecurityRouter.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <deque>
#include <filesystem>
#include <memory>
#include <unistd.h>
#include <vector>

using namespace nexus::security;
namespace constants = nexus::security::constants;
namespace fs = std::filesystem;

namespace {

constexpr std::size_t kFounders = 5;

struct RecordingEvents : ISecurityEvents {
    std::vector<QuorumCertificate> certificates;
    std::vector<ConsensusCommit> commits;
    std::vector<EpochId> dkg_complete;
    std::vector<DkgFailure> dkg_failed;
    std::vector<AuthoritySignature> signatures;
    std::vector<AttestationVerdict> verdicts;
    std::vector<std::pair<Vote, NodeId>> votes_sent;

    void on_certificate(const QuorumCertificate& qc) override { certificates.push_back(qc); }
    void on_commits(const std::vector<ConsensusCommit>& c) override {
        commits.insert(commits.end(), c.begin(), c.end());
    }
    void on_dkg_complete(EpochId epoch) override { dkg_complete.push_back(epoch); }
    void on_dkg_failed(DkgFailure failure, std::optional<NodeId>) override {
        dkg_failed.push_back(failure);
    }
    void on_authority_signature(const AuthoritySignature& s) override { signatures.push_back(s); }
    void on_attestation_verdict(const AttestationVerdict& v, const AttestationEvidence&) override {
        verdicts.push_back(v);
    }
    std::vector<QuorumCertificate> sync_certificates;
    void on_sync_certificate(const QuorumCertificate& qc, const NodeId&) override {
        sync_certificates.push_back(qc);
    }
    void on_vote_sent(const Vote& v, const NodeId& to) override { votes_sent.emplace_back(v, to); }
};

struct Node;

struct Queued {
    NodeId from;
    NodeId to;
    std::vector<uint8_t> bytes;
};

struct MemoryMesh {
    std::map<NodeId, Node*> nodes;
    std::deque<Queued> queue;
    uint64_t now_ms = 1000;
    void pump();
};

struct MemoryTransport : ISecurityTransport {
    MemoryTransport(MemoryMesh& mesh, NodeId self) : mesh(mesh), self(self) {}

    bool send_to(const NodeId& peer, std::span<const uint8_t> envelope) override {
        if (!mesh.nodes.contains(peer) || envelope.size() > constants::kMaxSecurityMessageBytes) {
            return false;
        }
        mesh.queue.push_back({self, peer, {envelope.begin(), envelope.end()}});
        return true;
    }

    std::size_t broadcast(std::span<const uint8_t> envelope) override {
        std::size_t count = 0;
        for (const auto& [peer, node] : mesh.nodes) {
            if (peer != self && send_to(peer, envelope)) ++count;
        }
        return count;
    }

    MemoryMesh& mesh;
    NodeId self;
};

struct Node {
    nexus::crypto::Ed25519PublicKey identity_pub{};
    nexus::crypto::Ed25519PrivateKey identity_priv{};
    NodeId id;
    fs::path dir;
    std::unique_ptr<SecurityRuntime> runtime;
    std::unique_ptr<PairwiseSealer> sealer;
    std::unique_ptr<MemoryTransport> transport;
    RecordingEvents events;
    std::unique_ptr<SecurityRouter> router;
    std::vector<RouteResult> results;

    RouteResult deliver(const NodeId& from, std::span<const uint8_t> bytes, uint64_t now) {
        results.push_back(router->receive(from, bytes, now));
        return results.back();
    }

    // Applies an own message locally: a leader must process its own proposal.
    RouteResult apply_local(const SecurityMessage& message, uint64_t now) {
        return deliver(id, encode_security_message(message), now);
    }
};

void MemoryMesh::pump() {
    while (!queue.empty()) {
        Queued item = std::move(queue.front());
        queue.pop_front();
        nodes.at(item.to)->deliver(item.from, item.bytes, now_ms);
    }
}


DkgTranscriptAttest signed_transcript_attest(const Node& node, const Tier1Set& founders,
                                             const Digest& transcript,
                                             const nexus::crypto::Ed25519PublicKey& group) {
    DkgTranscriptAttest attest;
    attest.epoch = 1;
    attest.participant_set_digest = founders.digest();
    attest.transcript_digest = transcript;
    attest.group_public_key = group;
    attest.node = node.id;
    const Digest digest = dkg_transcript_attest_digest(attest);
    crypto_sign_detached(attest.identity_signature.data(), nullptr, digest.data(), digest.size(),
                         node.identity_priv.data());
    return attest;
}

AttestationVerdict passing_verdict(const NodeId& id, EpochId epoch) {
    AttestationVerdict verdict;
    verdict.node_id = id;
    verdict.epoch = epoch;
    verdict.incarnation = 1;
    verdict.passed = true;
    verdict.evidence_digest.fill(id.bytes[0]);
    return verdict;
}

struct RouterMesh : ::testing::Test {
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        crypto_sign_keypair(genesis_pub.data(), genesis_priv.data());
        network = derive_network_id(genesis_pub, constants::kSecurityRulesetVersion,
                                    constants::kConsensusRulesetVersion);
        root = fs::temp_directory_path() / ("nexus_router_" + std::to_string(::getpid()));
        fs::create_directories(root);

        for (std::size_t i = 0; i < kFounders + 1; ++i) {
            auto node = std::make_unique<Node>();
            crypto_sign_keypair(node->identity_pub.data(), node->identity_priv.data());
            node->id.bytes = node->identity_pub;
            node->dir = root / ("node" + std::to_string(i));
            SecurityRuntimeConfig config;
            config.self = node->id;
            config.consensus_directory = node->dir;
            // These nodes model replicas that already arrived at whatever
            // transition a proposal carries, so transport is the only thing
            // under test here. The refusal rule has its own coverage in
            // hotstuff_safety.cpp; production installs the real pending handoff.
            config.transition_validator = [](const Digest&) { return true; };
            node->runtime = std::make_unique<SecurityRuntime>(config);
            node->sealer = std::make_unique<PairwiseSealer>(node->identity_priv);
            node->transport = std::make_unique<MemoryTransport>(mesh, node->id);
            node->router = std::make_unique<SecurityRouter>(
                SecurityRouterConfig{network}, *node->runtime, *node->transport, node->events,
                *node->sealer, nullptr);
            mesh.nodes[node->id] = node.get();
            nodes.push_back(std::move(node));
        }
        for (std::size_t i = 0; i < kFounders; ++i) founders.push_back(nodes[i].get());
        outsider = nodes[kFounders].get();
        std::vector<NodeId> ids;
        for (Node* node : founders) ids.push_back(node->id);
        founding_set.emplace(*Tier1Set::from_nodes(ids));
    }

    void TearDown() override { fs::remove_all(root); }

    // Runs one dealerless DKG for `target` entirely over the wire.
    std::vector<DkgResult> dkg_over_wire(EpochId target) {
        std::map<NodeId, IncarnationId> incarnations;
        for (Node* node : founders) incarnations[node->id] = 1;
        for (Node* node : founders) {
            DkgConfiguration config;
            config.network_id = network;
            config.target_epoch = target;
            config.participants = *founding_set;
            config.incarnations = incarnations;
            config.threshold = constants::authority_threshold(kFounders);
            config.self = node->id;
            auto broadcast = node->runtime->authority().start_dkg(config);
            EXPECT_TRUE(broadcast.has_value());
            node->router->broadcast(
                node->router->compose(SecurityMessageKind::DkgBroadcast, *broadcast, target));
        }
        mesh.pump();
        std::vector<DkgResult> results;
        for (Node* node : founders) {
            EXPECT_FALSE(node->events.dkg_complete.empty());
            if (!node->events.dkg_complete.empty()) {
                EXPECT_EQ(node->events.dkg_complete.back(), target);
            }
            auto result = node->runtime->authority().take_dkg_result();
            EXPECT_TRUE(result.has_value());
            results.push_back(std::move(*result));
        }
        return results;
    }

    void bootstrap_epoch_one() {
        GenesisService genesis(network);
        std::vector<AttestationVerdict> verdicts;
        for (Node* node : founders) {
            ASSERT_TRUE(genesis.admit_candidate(node->id));
            ASSERT_TRUE(genesis.record_verdict(passing_verdict(node->id, 0)));
        }
        std::vector<EpochVoteKey> own_keys;
        for (Node* node : founders) {
            own_keys.push_back(make_epoch_vote_key(1, node->id));
            vote_keys_1[node->id] = own_keys.back().public_key;
        }
        auto results = dkg_over_wire(1);
        ASSERT_EQ(results.size(), kFounders);
        Digest root_digest;
        root_digest.fill(0x01);
        for (Node* node : founders) {
            ASSERT_TRUE(genesis.record_transcript_attest(signed_transcript_attest(
                *node, *founding_set, results[0].transcript_digest,
                results[0].group_public_key)));
        }
        certificate = *genesis.finalize_epoch_one(results[0].group_public_key,
                                                  results[0].transcript_digest, root_digest,
                                                  genesis_priv);
        for (std::size_t i = 0; i < kFounders; ++i) {
            ASSERT_TRUE(founders[i]->runtime->adopt_epoch_one(certificate, genesis_pub,
                                                              *founding_set, vote_keys_1,
                                                              std::move(results[i]),
                                                              std::move(own_keys[i])));
        }
        ASSERT_TRUE(outsider->runtime->adopt_epoch_one(certificate, genesis_pub, *founding_set,
                                                       vote_keys_1, std::nullopt, std::nullopt));
    }

    Node* node_for(const NodeId& id) { return mesh.nodes.at(id); }

    // One HotStuff round over the wire: the leader of the next view proposes
    // on its high certificate; the next leader ends up holding the new one.
    // `leader` holds the newest certificate: it proposes at its current view.
    QuorumCertificate round_over_wire(Node*& leader, uint8_t state_byte) {
        const View view = leader->runtime->consensus()->current_view();
        EXPECT_EQ(leader->runtime->consensus()->leader_of(view), leader->id);
        Digest previous, proposed, transitions;
        previous.fill(static_cast<uint8_t>(state_byte - 1));
        proposed.fill(state_byte);
        transitions.fill(0xF0);
        auto made = leader->runtime->consensus()->make_proposal(previous, proposed, transitions);
        EXPECT_TRUE(std::holds_alternative<Proposal>(made));
        ProposalMessage message{std::get<Proposal>(made),
                                leader->runtime->consensus()->state().high_qc};
        const auto envelope =
            leader->router->compose(SecurityMessageKind::HotStuffProposal, message, 1);
        leader->router->broadcast(envelope);
        EXPECT_TRUE(leader->apply_local(envelope, mesh.now_ms).delivered);
        mesh.pump();

        Node* next = node_for(leader->runtime->consensus()->leader_of(view + 1));
        EXPECT_FALSE(next->events.certificates.empty());
        leader = next;
        return next->events.certificates.back();
    }

    nexus::crypto::Ed25519PublicKey genesis_pub{};
    nexus::crypto::Ed25519PrivateKey genesis_priv{};
    NetworkId network{};
    fs::path root;
    MemoryMesh mesh;
    std::vector<std::unique_ptr<Node>> nodes;
    std::vector<Node*> founders;
    Node* outsider = nullptr;
    std::optional<Tier1Set> founding_set;
    std::map<NodeId, nexus::crypto::Ed25519PublicKey> vote_keys_1;
    BootstrapCertificate certificate;
};

TEST_F(RouterMesh, ProtocolRunsOverEncodedEnvelopes) {
    bootstrap_epoch_one();

    // Four rounds commit the first block on every member.
    Node* proposer = node_for(founders[0]->runtime->consensus()->leader_of(
        founders[0]->runtime->consensus()->current_view()));
    QuorumCertificate qc1 = round_over_wire(proposer, 0x10);
    round_over_wire(proposer, 0x11);
    round_over_wire(proposer, 0x12);
    round_over_wire(proposer, 0x13);
    for (Node* node : founders) {
        ASSERT_FALSE(node->events.commits.empty()) << "no commit on a member";
        EXPECT_EQ(node->events.commits.front().height, 1u);
        EXPECT_EQ(node->events.commits.front().qc_digest, qc_digest(qc1));
    }
    // A non-member never gets a consensus service: proposals are dropped.
    EXPECT_TRUE(outsider->events.commits.empty());
    bool outsider_saw_no_service = false;
    for (const auto& result : outsider->results) {
        if (result.dropped == DropReason::NoService) outsider_saw_no_service = true;
    }
    EXPECT_TRUE(outsider_saw_no_service);

    // FROST signs the finalized object over the wire.
    Digest previous_state;
    previous_state.fill(0x0F);
    const AuthorityObject object =
        make_authority_object(founders[0]->events.commits.front(), network,
                              AuthorityOperation::EpochTransition, 1, previous_state);
    const std::vector<NodeId> signers = founding_set->members();
    auto start = founders[0]->runtime->authority().start_signing(object, qc1, signers);
    ASSERT_EQ(start.failure, SigningFailure::None);
    founders[0]->router->broadcast(
        founders[0]->router->compose(SecurityMessageKind::FrostCommitment, *start.commitment, 1));
    for (std::size_t i = 1; i < kFounders; ++i) {
        auto join = founders[i]->runtime->authority().join_signing(*start.session_id, object, qc1,
                                                                   signers);
        ASSERT_EQ(join.failure, SigningFailure::None);
        founders[i]->router->broadcast(founders[i]->router->compose(
            SecurityMessageKind::FrostCommitment, *join.commitment, 1));
    }
    mesh.pump();
    for (Node* node : founders) {
        ASSERT_EQ(node->events.signatures.size(), 1u);
        EXPECT_TRUE(nexus::crypto::FrostProvider::verify(certificate.authority_public_key,
                                                         authority_object_digest(object),
                                                         node->events.signatures[0].signature));
    }

    // Next-epoch DKG traffic passes the epoch window while Epoch 1 rules.
    auto epoch_two = dkg_over_wire(2);
    ASSERT_EQ(epoch_two.size(), kFounders);
    EXPECT_NE(epoch_two[0].group_public_key, certificate.authority_public_key);
}

TEST_F(RouterMesh, GatesRunBeforeAnyServiceWork) {
    bootstrap_epoch_one();
    Node* a = founders[0];
    Node* b = founders[1];

    Vote vote{};
    vote.consensus_ruleset = constants::kConsensusRulesetVersion;
    vote.network_id = network;
    vote.epoch = 1;
    vote.height = 1;
    vote.view = 1;
    vote.proposal_digest.fill(0x99);
    vote.voter = b->id;
    auto message = b->router->compose(SecurityMessageKind::HotStuffVote, vote, 1);
    auto bytes = encode_security_message(message);

    // Envelope sender must be the authenticated peer.
    EXPECT_EQ(a->deliver(founders[2]->id, bytes, mesh.now_ms).dropped, DropReason::SenderMismatch);

    // Body sender must be the authenticated peer too.
    auto forged = message;
    std::get<Vote>(forged.body).voter = founders[2]->id;
    EXPECT_EQ(a->deliver(b->id, encode_security_message(forged), mesh.now_ms).dropped,
              DropReason::SenderMismatch);

    auto wrong_ruleset = message;
    wrong_ruleset.consensus_ruleset = 2;
    EXPECT_EQ(a->deliver(b->id, encode_security_message(wrong_ruleset), mesh.now_ms).dropped,
              DropReason::RulesetMismatch);

    auto wrong_network = message;
    wrong_network.network_id.fill(0xEE);
    EXPECT_EQ(a->deliver(b->id, encode_security_message(wrong_network), mesh.now_ms).dropped,
              DropReason::NetworkMismatch);

    auto far_epoch = message;
    far_epoch.epoch = 5;
    EXPECT_EQ(a->deliver(b->id, encode_security_message(far_epoch), mesh.now_ms).dropped,
              DropReason::EpochOutOfWindow);

    // Votes in the current epoch reach the service; an unsigned vote is a
    // service rejection, not a transport drop.
    auto first = a->deliver(b->id, bytes, mesh.now_ms);
    EXPECT_EQ(first.dropped, DropReason::ServiceRejected);
    EXPECT_EQ(*first.service_code, static_cast<uint16_t>(ConsensusFailure::InvalidSignature));

    // The same bytes again are a duplicate before any signature work.
    EXPECT_EQ(a->deliver(b->id, bytes, mesh.now_ms).dropped, DropReason::Duplicate);

    std::vector<uint8_t> truncated(bytes.begin(), bytes.begin() + 40);
    EXPECT_EQ(a->deliver(b->id, truncated, mesh.now_ms).dropped, DropReason::Malformed);

    auto unknown = bytes;
    unknown[1] = 77;
    EXPECT_EQ(a->deliver(b->id, unknown, mesh.now_ms).dropped, DropReason::UnknownKind);

    std::vector<uint8_t> huge(constants::kMaxSecurityMessageBytes + 1, 0);
    EXPECT_EQ(a->deliver(b->id, huge, mesh.now_ms).dropped, DropReason::Oversized);
}

TEST_F(RouterMesh, FloodBudgetBindsToPeerAndWindow) {
    bootstrap_epoch_one();
    Node* a = founders[0];
    Node* b = founders[1];
    std::vector<uint8_t> junk(8, 0);
    // Bootstrap traffic used part of the current window; start a fresh one.
    mesh.now_ms += constants::kSecurityFloodWindowMs;

    for (uint32_t i = 0; i < constants::kSecurityPeerMessagesPerWindow; ++i) {
        junk[0] = static_cast<uint8_t>(i);
        EXPECT_NE(a->deliver(b->id, junk, mesh.now_ms).dropped, DropReason::Flooded);
    }
    EXPECT_EQ(a->deliver(b->id, junk, mesh.now_ms).dropped, DropReason::Flooded);

    // Another peer has its own budget; the next window resets.
    EXPECT_NE(a->deliver(founders[2]->id, junk, mesh.now_ms).dropped, DropReason::Flooded);
    EXPECT_NE(a->deliver(b->id, junk, mesh.now_ms + constants::kSecurityFloodWindowMs).dropped,
              DropReason::Flooded);
}

TEST_F(RouterMesh, PairwisePackageOpensOnlyForItsRecipient) {
    bootstrap_epoch_one();
    Node* a = founders[0];
    Node* b = founders[1];
    Node* c = founders[2];

    // Start a next-epoch DKG on every member so pairwise traffic is expected.
    std::map<NodeId, IncarnationId> incarnations;
    for (Node* node : founders) incarnations[node->id] = 1;
    for (Node* node : founders) {
        DkgConfiguration config;
        config.network_id = network;
        config.target_epoch = 2;
        config.participants = *founding_set;
        config.incarnations = incarnations;
        config.threshold = constants::authority_threshold(kFounders);
        config.self = node->id;
        ASSERT_TRUE(node->runtime->authority().start_dkg(config).has_value());
    }

    DkgMessage package;
    package.network_id = network;
    package.target_epoch = 2;
    package.participant_set_digest = founding_set->digest();
    package.sender = a->id;
    package.sender_incarnation = 1;
    package.round = DkgRound::Round2Pairwise;
    package.recipient = b->id;
    package.payload = std::vector<uint8_t>(37, 0x42);

    // Sealed for B, delivered to C: C cannot open it.
    auto sealed = a->sealer->seal_for(b->id, package.payload);
    ASSERT_TRUE(sealed.has_value());
    DkgMessage wire = package;
    wire.payload = *sealed;
    wire.recipient = c->id;
    const auto envelope = a->router->compose(SecurityMessageKind::DkgPairwise, wire, 2);
    EXPECT_EQ(c->deliver(a->id, encode_security_message(envelope), mesh.now_ms).dropped,
              DropReason::SealFailure);

    // Delivered to B it opens; the package content is then judged by the
    // session, not the transport.
    wire.recipient = b->id;
    const auto for_b = a->router->compose(SecurityMessageKind::DkgPairwise, wire, 2);
    const auto result = b->deliver(a->id, encode_security_message(for_b), mesh.now_ms);
    EXPECT_NE(result.dropped, DropReason::SealFailure);
}

TEST_F(RouterMesh, ChallengeWithoutProducerYieldsNoEvidence) {
    bootstrap_epoch_one();
    Node* a = founders[0];
    Node* b = founders[1];

    auto challenge = a->runtime->attestation().create_challenge(b->id, b->identity_pub, 1, 1);
    ASSERT_TRUE(challenge.has_value());
    const auto envelope = a->router->compose(SecurityMessageKind::AttestationChallenge, *challenge, 1);
    // No producer is wired: B cannot answer, and nothing is fabricated.
    EXPECT_EQ(b->deliver(a->id, encode_security_message(envelope), mesh.now_ms).dropped,
              DropReason::NoService);
    EXPECT_TRUE(mesh.queue.empty());

    // A challenge addressed to another node is refused outright.
    auto misaddressed = *challenge;
    misaddressed.node_id = founders[2]->id;
    const auto wrong = a->router->compose(SecurityMessageKind::AttestationChallenge, misaddressed, 1);
    EXPECT_EQ(b->deliver(a->id, encode_security_message(wrong), mesh.now_ms).dropped,
              DropReason::SenderMismatch);
}

TEST_F(RouterMesh, SyncResponseCarriesAValidatedCertificate) {
    bootstrap_epoch_one();
    Node* proposer = node_for(founders[0]->runtime->consensus()->leader_of(
        founders[0]->runtime->consensus()->current_view()));
    const QuorumCertificate qc1 = round_over_wire(proposer, 0x10);
    Node* holder = proposer;  // round_over_wire moved `proposer` to the certificate holder
    Node* asker = founders[0] == holder ? founders[1] : founders[0];

    // The holder answers a sync request with its high certificate; the
    // asker validates it under the epoch vote keys before it surfaces.
    const auto request = asker->router->compose(SecurityMessageKind::SyncRequest, SyncRequest{1}, 1);
    EXPECT_TRUE(holder->deliver(asker->id, encode_security_message(request), mesh.now_ms).delivered);
    mesh.pump();
    ASSERT_FALSE(asker->events.sync_certificates.empty());
    EXPECT_EQ(qc_digest(asker->events.sync_certificates.back()), qc_digest(qc1));

    // A forged certificate never surfaces.
    SyncResponse forged;
    forged.high_qc = qc1;
    forged.high_qc.signers[0].signature[0] ^= 0x01;
    const auto bad = holder->router->compose(SecurityMessageKind::SyncResponse, forged, 1);
    EXPECT_EQ(asker->deliver(holder->id, encode_security_message(bad), mesh.now_ms).dropped,
              DropReason::ServiceRejected);
    EXPECT_EQ(asker->events.sync_certificates.size(), 1u);
}

}  // namespace
