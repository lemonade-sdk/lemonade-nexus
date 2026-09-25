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

struct RecordingProducer : IEvidenceProducer {
    int calls = 0;
    std::optional<AttestationEvidence> answer = std::nullopt;

    std::optional<AttestationEvidence> produce(const AttestationChallenge&) override {
        ++calls;
        return answer;
    }
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
    RecordingProducer producer;
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

// The founding eligibility transcript each founder signs. Its value is opaque
// to Genesis, which only checks that all five signed the same one.
GenesisEligibilityAttest signed_eligibility_attest(const Node& node, const Digest& state) {
    GenesisEligibilityAttest attest;
    attest.epoch = 1;
    attest.founding_state_digest = state;
    attest.node = node.id;
    const Digest digest = genesis_eligibility_attest_digest(attest);
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

        NodeId anchor_id{};
        for (std::size_t i = 0; i < kFounders + 1; ++i) {
            auto node = std::make_unique<Node>();
            crypto_sign_keypair(node->identity_pub.data(), node->identity_priv.data());
            node->id.bytes = node->identity_pub;
            if (i == 0) anchor_id = node->id;  // node 0 is the pinned anchor
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
            // Node 0 is this fixture's pinned anchor, the same network state
            // the production config carries.
            SecurityRouterConfig router_config;
            router_config.network_id = network;
            router_config.genesis_anchor_id = anchor_id;
            node->router = std::make_unique<SecurityRouter>(
                router_config, *node->runtime, *node->transport, node->events,
                *node->sealer, &node->producer);
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
        Digest founding_eligibility;
        founding_eligibility.fill(0x3C);
        for (Node* node : founders) {
            ASSERT_TRUE(genesis.record_transcript_attest(signed_transcript_attest(
                *node, *founding_set, results[0].transcript_digest,
                results[0].group_public_key)));
            ASSERT_TRUE(genesis.record_eligibility_attest(
                signed_eligibility_attest(*node, founding_eligibility)));
        }
        certificate = *genesis.finalize_epoch_one(results[0].group_public_key,
                                                  results[0].transcript_digest, root_digest,
                                                  vote_key_set_digest(vote_keys_1),
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
    package.session_digest = founding_set->digest();
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

AttestationChallenge gate_passing_challenge(const NetworkId& network, const NodeId& target) {
    // A hand-built challenge with the mesh's rulesets and a fresh nonce: it
    // clears every router gate that does not concern the producer, and the
    // fresh nonce keeps the dedupe window from firing across repeats.
    AttestationChallenge challenge;
    challenge.network_id = network;
    randombytes_buf(challenge.nonce.data(), challenge.nonce.size());
    challenge.node_id = target;
    challenge.incarnation = 1;
    challenge.epoch = 1;
    challenge.security_ruleset = constants::kSecurityRulesetVersion;
    challenge.consensus_ruleset = constants::kConsensusRulesetVersion;
    return challenge;
}

TEST_F(RouterMesh, ChallengeWithoutProducerYieldsNoEvidence) {
    bootstrap_epoch_one();
    Node* a = founders[0];
    Node* b = founders[1];

    auto challenge = gate_passing_challenge(network, b->id);
    const auto envelope = a->router->compose(SecurityMessageKind::AttestationChallenge, challenge, 1);
    // The producer is wired but answers nothing: B cannot answer, and nothing
    // is fabricated.
    EXPECT_EQ(b->deliver(a->id, encode_security_message(envelope), mesh.now_ms).dropped,
              DropReason::NoService);
    EXPECT_EQ(b->producer.calls, 1);
    EXPECT_TRUE(mesh.queue.empty());

    // A challenge addressed to another node is refused outright, before any
    // production.
    const auto wrong = a->router->compose(SecurityMessageKind::AttestationChallenge,
                                          gate_passing_challenge(network, founders[2]->id), 1);
    EXPECT_EQ(b->deliver(a->id, encode_security_message(wrong), mesh.now_ms).dropped,
              DropReason::SenderMismatch);
    EXPECT_EQ(b->producer.calls, 1);
}

TEST_F(RouterMesh, RemoteNonMemberChallengeIsDroppedBeforeProduction) {
    bootstrap_epoch_one();
    Node* a = founders[0];

    // The mesh's only non-member is the outsider; it is not in Epoch 1's
    // frozen Tier 1 set.
    const auto challenge = gate_passing_challenge(network, a->id);
    const auto envelope = outsider->router->compose(SecurityMessageKind::AttestationChallenge,
                                                    challenge, 1);
    const auto result = a->deliver(outsider->id, encode_security_message(envelope), mesh.now_ms);
    EXPECT_EQ(result.dropped, DropReason::NotMember);
    // The expensive platform work never ran.
    EXPECT_EQ(a->producer.calls, 0);

    // A member's challenge to the same node is answered: the drop above was
    // membership, not a refusal of the request itself.
    const auto member_envelope =
        founders[1]->router->compose(SecurityMessageKind::AttestationChallenge,
                                     gate_passing_challenge(network, a->id), 1);
    // The fake producer answers nothing, so the drop is NoService — but the
    // production attempt itself happened, which is the point: the member was
    // let through the gate.
    const auto member_result =
        a->deliver(founders[1]->id, encode_security_message(member_envelope), mesh.now_ms);
    EXPECT_EQ(member_result.dropped, DropReason::NoService);
    EXPECT_EQ(a->producer.calls, 1);
}

TEST_F(RouterMesh, ChallengeProductionIsBoundedPerChallenger) {
    bootstrap_epoch_one();
    Node* a = founders[0];
    Node* b = founders[1];
    Node* c = founders[2];

    // A member's challenge is answered: the fake producer returns a bundle
    // named for B, so the sender-bound check on the evidence passes.
    a->producer.answer = AttestationEvidence{};
    a->producer.answer->node_id = a->id;

    for (uint32_t i = 0; i < constants::kChallengeProductionsPerWindow; ++i) {
        const auto envelope = b->router->compose(
            SecurityMessageKind::AttestationChallenge, gate_passing_challenge(network, a->id), 1);
        a->deliver(b->id, encode_security_message(envelope), mesh.now_ms);
    }
    EXPECT_EQ(a->producer.calls, constants::kChallengeProductionsPerWindow);

    // One more from the same challenger in the same window is dropped before
    // production.
    const auto excess = b->router->compose(
        SecurityMessageKind::AttestationChallenge, gate_passing_challenge(network, a->id), 1);
    EXPECT_EQ(a->deliver(b->id, encode_security_message(excess), mesh.now_ms).dropped,
              DropReason::BudgetExceeded);
    EXPECT_EQ(a->producer.calls, constants::kChallengeProductionsPerWindow);

    // A different challenger has its own budget and is still answered.
    const auto other = c->router->compose(
        SecurityMessageKind::AttestationChallenge, gate_passing_challenge(network, a->id), 1);
    const auto other_result = a->deliver(c->id, encode_security_message(other), mesh.now_ms);
    EXPECT_NE(other_result.dropped, DropReason::BudgetExceeded);
    EXPECT_EQ(a->producer.calls, constants::kChallengeProductionsPerWindow + 1);

    // The window rolls and B's budget resets.
    const auto rolled = b->router->compose(
        SecurityMessageKind::AttestationChallenge, gate_passing_challenge(network, a->id), 1);
    const auto rolled_result =
        a->deliver(b->id, encode_security_message(rolled),
                   mesh.now_ms + constants::kChallengeProductionWindowMs);
    EXPECT_NE(rolled_result.dropped, DropReason::BudgetExceeded);
    EXPECT_EQ(a->producer.calls, constants::kChallengeProductionsPerWindow + 2);
}

TEST_F(RouterMesh, LoopbackAttestationStillAnswersItself) {
    bootstrap_epoch_one();
    Node* a = founders[0];
    a->producer.answer = AttestationEvidence{};
    a->producer.answer->node_id = a->id;

    // Loopback: the node examines its own evidence. No membership check and
    // no per-challenger budget may block it.
    const auto envelope = a->router->compose(
        SecurityMessageKind::AttestationChallenge, gate_passing_challenge(network, a->id), 1);
    EXPECT_TRUE(a->apply_local(envelope, mesh.now_ms).delivered);
    EXPECT_EQ(a->producer.calls, 1);

    // And it is not one-shot: repeated loopback challenges keep answering
    // within the flood budget.
    const auto second = a->router->compose(
        SecurityMessageKind::AttestationChallenge, gate_passing_challenge(network, a->id), 1);
    EXPECT_TRUE(a->apply_local(second, mesh.now_ms).delivered);
    EXPECT_EQ(a->producer.calls, 2);
}

// --- Pre-quorum (Genesis window) challenge authorization ----------------
//
// No epoch is active in these tests: epochs() is null on every node, so the
// router is in the bootstrap window. The only identity authorized to issue a
// remote challenge there is the pinned genesis anchor; every other identity
// is a stranger, however well-formed and freshly signed its envelope is.

NodeId fresh_stranger_id() {
    NodeId id{};
    randombytes_buf(id.bytes.data(), id.bytes.size());
    return id;
}

TEST_F(RouterMesh, PreQuorumStrangerChallengeIsDroppedBeforeProduction) {
    Node* a = founders[0];

    // A correctly formed, correctly signed (at the transport seam) challenge
    // from an identity that is neither the anchor nor any member, naming A as
    // the subject, with a fresh nonce: it must die before the expensive
    // platform work runs.
    const auto challenge = gate_passing_challenge(network, a->id);
    const SecurityMessage message = outsider->router->compose(
        SecurityMessageKind::AttestationChallenge, challenge, 1);
    const auto result = a->deliver(outsider->id, encode_security_message(message), mesh.now_ms);
    EXPECT_EQ(result.dropped, DropReason::NotMember);
    EXPECT_EQ(a->producer.calls, 0);
}

TEST_F(RouterMesh, PreQuorumIdentityRotationCannotProduceEvidence) {
    Node* a = founders[0];

    // A stream of freshly generated identities, each inside its own (reset)
    // per-challenger budget. If authorization were "no epoch yet, anyone",
    // rotating NodeIds would keep the production rate at the per-identity
    // budget forever. Count actual producer invocations, not drop codes.
    constexpr std::size_t kStrangers = 12;
    for (std::size_t i = 0; i < kStrangers; ++i) {
        const NodeId stranger = fresh_stranger_id();
        for (uint32_t c = 0; c < constants::kChallengeProductionsPerWindow; ++c) {
            const auto challenge = gate_passing_challenge(network, a->id);
            SecurityMessage message =
                a->router->compose(SecurityMessageKind::AttestationChallenge, challenge, 1);
            message.sender = stranger;
            (void)a->deliver(stranger, encode_security_message(message), mesh.now_ms);
        }
    }
    EXPECT_EQ(a->producer.calls, 0);
}

TEST_F(RouterMesh, PreQuorumAnchorChallengeIsAnswered) {
    // founders[0] is this fixture's pinned anchor. Its challenge to a second
    // node is the founding flow itself and must reach the producer even with
    // no epoch active.
    Node* anchor = founders[0];
    Node* b = founders[1];
    b->producer.answer = AttestationEvidence{};
    b->producer.answer->node_id = b->id;

    const auto challenge = gate_passing_challenge(network, b->id);
    const auto envelope = anchor->router->compose(SecurityMessageKind::AttestationChallenge,
                                                  challenge, 1);
    const auto result = b->deliver(anchor->id, encode_security_message(envelope), mesh.now_ms);
    EXPECT_TRUE(result.delivered);
    EXPECT_EQ(b->producer.calls, 1);
}

TEST_F(RouterMesh, PreQuorumAnchorChallengeIsBoundedPerWindow) {
    Node* anchor = founders[0];
    Node* b = founders[1];
    b->producer.answer = AttestationEvidence{};
    b->producer.answer->node_id = b->id;

    for (uint32_t i = 0; i < constants::kChallengeProductionsPerWindow; ++i) {
        const auto challenge = gate_passing_challenge(network, b->id);
        const auto envelope = anchor->router->compose(SecurityMessageKind::AttestationChallenge,
                                                      challenge, 1);
        (void)b->deliver(anchor->id, encode_security_message(envelope), mesh.now_ms);
    }
    EXPECT_EQ(b->producer.calls, constants::kChallengeProductionsPerWindow);

    // The anchor is authorized, not unbounded: the next one in the same
    // window is dropped before production.
    const auto excess = gate_passing_challenge(network, b->id);
    const auto excess_envelope = anchor->router->compose(
        SecurityMessageKind::AttestationChallenge, excess, 1);
    EXPECT_EQ(b->deliver(anchor->id, encode_security_message(excess_envelope), mesh.now_ms)
                  .dropped,
              DropReason::BudgetExceeded);
    EXPECT_EQ(b->producer.calls, constants::kChallengeProductionsPerWindow);
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
