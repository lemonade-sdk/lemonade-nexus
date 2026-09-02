#pragma once

// The memory mesh the lifecycle tests run on: one Genesis server, five
// founders, and two Tier 2 reserves, exchanging only encoded envelopes and
// paced only by tick().
//
// The attestation verifier's positive path needs a confidential VM, so verdicts
// are injected through the driver's own event entry point; every other step —
// founding, the mutual eligibility round, DKG, certificates, consensus,
// observations, the finalized eligibility state, the handoff — runs the real
// code over the wire.

#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Security/Lifecycle/SecurityDriver.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <algorithm>
#include <deque>
#include <filesystem>
#include <fstream>
#include <memory>
#include <set>
#include <unistd.h>
#include <vector>

namespace lifecycle_test {

using namespace nexus::security;
namespace constants = nexus::security::constants;
namespace fs = std::filesystem;

constexpr std::size_t kFounders = 5;
/// Tier 2 servers: authenticated mesh members that hold no epoch role. They
/// exist to prove a node can qualify for Tier 1 without already being Tier 1.
constexpr std::size_t kReserves = 2;

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
    /// Decoded copies of adoption traffic, so a hostile test can mutate a
    /// genuine package instead of guessing at one.
    std::vector<NextEpochPlanProof> captured_plans;
    std::vector<ReadinessProofMsg> captured_readiness;
    std::vector<EpochHandoffProofMsg> captured_handoffs;
    // Unreachable nodes: nothing is delivered to or from them. Offline is a
    // transport fact, not a protocol one.
    std::set<NodeId> offline;
    void capture(std::span<const uint8_t> bytes);
    // Nodes whose transport certificate no longer verifies against the root.
    // The mesh knows this, not the platform, so it lives here. The per-observer
    // map lets one node see the answer differently, which is what a
    // pre-consensus disagreement looks like.
    std::set<NodeId> uncertified;
    std::map<NodeId, std::set<NodeId>> uncertified_for;
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

// The router needs its events sink at construction; the driver needs the
// router. The proxy breaks the cycle.
struct EventsProxy : ISecurityEvents {
    ISecurityEvents* target = nullptr;
    void on_vote_sent(const Vote& v, const NodeId& n) override {
        if (target) target->on_vote_sent(v, n);
    }
    void on_certificate(const QuorumCertificate& q) override {
        if (target) target->on_certificate(q);
    }
    void on_justify_quorum(const QuorumCertificate& q) override {
        if (target) target->on_justify_quorum(q);
    }
    void on_timeout_certificate(const TimeoutCertificate& t) override {
        if (target) target->on_timeout_certificate(t);
    }
    void on_commits(const std::vector<ConsensusCommit>& c) override {
        if (target) target->on_commits(c);
    }
    void on_dkg_round1_complete(EpochId e) override {
        if (target) target->on_dkg_round1_complete(e);
    }
    void on_dkg_complete(EpochId e) override {
        if (target) target->on_dkg_complete(e);
    }
    void on_dkg_failed(DkgFailure f, std::optional<NodeId> c) override {
        if (target) target->on_dkg_failed(f, c);
    }
    void on_authority_signature(const AuthoritySignature& s) override {
        if (target) target->on_authority_signature(s);
    }
    void on_attestation_verdict(const AttestationVerdict& v,
                                const AttestationEvidence& e) override {
        if (target) target->on_attestation_verdict(v, e);
    }
    void on_epoch_announcement(const EpochAnnouncement& a, const NodeId& n) override {
        if (target) target->on_epoch_announcement(a, n);
    }
    void on_genesis_founding(const GenesisFounding& f, const NodeId& n) override {
        if (target) target->on_genesis_founding(f, n);
    }
    void on_dkg_transcript_attest(const DkgTranscriptAttest& a) override {
        if (target) target->on_dkg_transcript_attest(a);
    }
    void on_bootstrap_certificate(const BootstrapCertificate& c, const NodeId& n) override {
        if (target) target->on_bootstrap_certificate(c, n);
    }
    void on_sync_certificate(const QuorumCertificate& q, const NodeId& n) override {
        if (target) target->on_sync_certificate(q, n);
    }
    void on_vote_accepted(const Vote& v) override {
        if (target) target->on_vote_accepted(v);
    }
    void on_eligibility_observation(const EligibilityObservation& o) override {
        if (target) target->on_eligibility_observation(o);
    }
    void on_genesis_eligibility_attest(const GenesisEligibilityAttest& a) override {
        if (target) target->on_genesis_eligibility_attest(a);
    }
    void on_participation_challenge(const ParticipationChallenge& c, const NodeId& n) override {
        if (target) target->on_participation_challenge(c, n);
    }
    void on_participation_response(const ParticipationResponse& r) override {
        if (target) target->on_participation_response(r);
    }
    void on_next_epoch_plan(const NextEpochPlanProof& p) override {
        if (target) target->on_next_epoch_plan(p);
    }
    void on_candidate_state_ready(const CandidateStateReadyMsg& m) override {
        if (target) target->on_candidate_state_ready(m);
    }
    void on_readiness_proof(const ReadinessProofMsg& m) override {
        if (target) target->on_readiness_proof(m);
    }
    void on_epoch_handoff_proof(const EpochHandoffProofMsg& m) override {
        if (target) target->on_epoch_handoff_proof(m);
    }
    void on_candidate_sync_response(const SyncResponse& s, const NodeId& n) override {
        if (target) target->on_candidate_sync_response(s, n);
    }
    void on_authority_chain_request(const AuthorityChainRequest& r, const NodeId& n) override {
        if (target) target->on_authority_chain_request(r, n);
    }
    void on_authority_chain_page(const AuthorityChainPage& p, const NodeId& n) override {
        if (target) target->on_authority_chain_page(p, n);
    }
};

struct Node {
    nexus::crypto::Ed25519Keypair identity;
    NodeId id;
    fs::path dir;
    // The wrapping stack persists the epoch vote key at rest, so a restarted
    // node can resume voting after its certified sync.
    std::unique_ptr<nexus::crypto::SodiumCryptoService> crypto;
    std::unique_ptr<nexus::storage::FileStorageService> file_storage;
    std::unique_ptr<nexus::crypto::KeyWrappingService> wrapping;
    std::unique_ptr<SecurityRuntime> runtime;
    std::unique_ptr<PairwiseSealer> sealer;
    std::unique_ptr<MemoryTransport> transport;
    EventsProxy events;
    std::unique_ptr<SecurityRouter> router;
    std::unique_ptr<GenesisService> genesis;
    std::unique_ptr<EpochStore> store;
    std::unique_ptr<SecurityDriver> driver;

    void deliver(const NodeId& from, std::span<const uint8_t> bytes, uint64_t now) {
        (void)router->receive(from, bytes, now);
    }
};

inline void MemoryMesh::capture(std::span<const uint8_t> bytes) {
    const auto decoded = decode_security_message(bytes);
    if (!std::holds_alternative<SecurityMessage>(decoded)) {
        return;
    }
    const auto& message = std::get<SecurityMessage>(decoded);
    if (const auto* plan = std::get_if<NextEpochPlanProof>(&message.body)) {
        captured_plans.push_back(*plan);
    } else if (const auto* readiness = std::get_if<ReadinessProofMsg>(&message.body)) {
        captured_readiness.push_back(*readiness);
    } else if (const auto* handoff = std::get_if<EpochHandoffProofMsg>(&message.body)) {
        captured_handoffs.push_back(*handoff);
    }
}

inline void MemoryMesh::pump() {
    while (!queue.empty()) {
        Queued item = std::move(queue.front());
        queue.pop_front();
        if (offline.contains(item.from) || offline.contains(item.to)) {
            continue;
        }
        capture(item.bytes);
        nodes.at(item.to)->deliver(item.from, item.bytes, now_ms);
    }
}

// What a provider proves on a good confidential host. Tier 1 reads the claims,
// not `passed`, so a verdict without them confers nothing.
inline VerifiedPlatformClaims complete_claims() {
    VerifiedPlatformClaims claims;
    claims.profile_id = kTier1AttestationProfileId;
    claims.profile_ruleset = kAttestationProfileRulesetVersion;
    claims.hardware_confidentiality_valid = true;
    claims.platform_identity_valid = true;
    claims.evidence_freshness_valid = true;
    claims.node_identity_binding_valid = true;
    claims.incarnation_binding_valid = true;
    claims.epoch_binding_valid = true;
    claims.security_ruleset_binding_valid = true;
    claims.boot_integrity_valid = true;
    claims.tcb_valid = true;
    claims.attestation_profile_valid = true;
    claims.ima_anchored = true;
    claims.binary_approved = true;
    claims.runtime_profile_enforced = true;
    claims.runtime_integrity_valid = true;
    return claims;
}

// `round` distinguishes two verifications of the same node. Continuity counts
// distinct attestations, so the digests must differ between rounds. The
// verdict carries no context; the fixture helpers bind one, because the
// driver refuses a verdict whose purpose or context does not match.
inline AttestationVerdict passing_verdict(const NodeId& id, EpochId epoch, uint8_t round = 0,
                                          IncarnationId incarnation = 1) {
    AttestationVerdict verdict;
    verdict.node_id = id;
    verdict.epoch = epoch;
    verdict.incarnation = incarnation;
    verdict.passed = true;
    verdict.claims = complete_claims();
    // Distinct per node, epoch and round, and never all-zero: an empty
    // evidence digest proves no attestation ran and is refused as such.
    verdict.evidence_digest.fill(id.bytes[0]);
    verdict.evidence_digest[0] = static_cast<uint8_t>(0xA0 + round);
    verdict.evidence_digest[1] = static_cast<uint8_t>(epoch + 1);
    verdict.evidence_digest[2] = static_cast<uint8_t>(incarnation);
    return verdict;
}

// What the real service would produce for an ordinary eligibility exchange.
inline AttestationVerdict eligibility_verdict(const NetworkId& network, const NodeId& id,
                                              EpochId epoch, uint8_t round = 0,
                                              IncarnationId incarnation = 1) {
    AttestationVerdict verdict = passing_verdict(id, epoch, round, incarnation);
    verdict.context_digest = eligibility_attestation_context(network, epoch, id, incarnation);
    return verdict;
}

// What the real service would produce for one plan's final attestation.
inline AttestationVerdict final_verdict(const NextEpochPlan& plan, const NodeId& id,
                                        uint8_t round = 0) {
    const auto incarnation = plan.incarnations.find(id);
    AttestationVerdict verdict = passing_verdict(
        id, plan.next_epoch, round,
        incarnation != plan.incarnations.end() ? incarnation->second : 1);
    verdict.purpose = AttestationPurpose::FinalEpochReadiness;
    verdict.context_digest = SecurityDriver::plan_attest_context(plan, id);
    return verdict;
}

inline AttestationEvidence evidence_for(const NodeId& id, const nexus::crypto::Ed25519PublicKey& vote_key) {
    AttestationEvidence evidence;
    evidence.node_id = id;
    evidence.incarnation = 1;
    evidence.epoch_vote_key = vote_key;
    return evidence;
}

struct DriverMeshBase : ::testing::Test {
    explicit DriverMeshBase(std::size_t reserve_count = kReserves)
        : reserve_count_(reserve_count) {}

    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        root = fs::temp_directory_path() / ("nexus_driver_" + std::to_string(::getpid()) + "_" +
                                            std::to_string(reserve_count_));
        fs::remove_all(root);
        fs::create_directories(root);

        // Node 0 is Genesis: its identity IS the pinned genesis key.
        for (std::size_t i = 0; i < kFounders + reserve_count_ + 1; ++i) {
            auto node = std::make_unique<Node>();
            crypto_sign_keypair(node->identity.public_key.data(),
                                node->identity.private_key.data());
            node->id.bytes = node->identity.public_key;
            nodes.push_back(std::move(node));
        }
        genesis_node = nodes[0].get();
        for (std::size_t i = 1; i <= kFounders; ++i) founders.push_back(nodes[i].get());
        for (std::size_t i = kFounders + 1; i < nodes.size(); ++i) {
            reserves.push_back(nodes[i].get());
        }
        network = derive_network_id(genesis_node->identity.public_key,
                                    constants::kSecurityRulesetVersion,
                                    constants::kConsensusRulesetVersion);

        for (std::size_t i = 0; i < nodes.size(); ++i) {
            Node* node = nodes[i].get();
            node->dir = root / ("node" + std::to_string(i));
            node->crypto = std::make_unique<nexus::crypto::SodiumCryptoService>();
            node->crypto->start();
            node->file_storage = std::make_unique<nexus::storage::FileStorageService>(
                (node->dir / "data").string());
            node->file_storage->start();
            node->wrapping = std::make_unique<nexus::crypto::KeyWrappingService>(
                *node->crypto, *node->file_storage);
            node->wrapping->start();
            build_node(*node);
            mesh.nodes[node->id] = node;
        }
    }

    // Rebuilds the runtime-side objects from the node's directories, as a
    // process restart would.
    void restart_node(Node& node) {
        node.driver.reset();
        node.router.reset();
        node.store.reset();
        node.runtime.reset();
        node.sealer.reset();
        node.transport.reset();
        build_node(node);
    }

    void build_node(Node& node) {
        SecurityRuntimeConfig runtime_config;
        runtime_config.self = node.id;
        runtime_config.network_id = network;
        runtime_config.consensus_directory = node.dir / "consensus";
        // Mirrors production: a replica votes for a handoff only when it has
        // independently arrived at the same one. Node addresses are stable, and
        // the driver exists long before consensus runs.
        runtime_config.transition_validator = [&node](const Digest& transitions_digest) {
            return node.driver && node.driver->accepts_transition(transitions_digest);
        };
        node.runtime = std::make_unique<SecurityRuntime>(runtime_config);
        node.sealer = std::make_unique<PairwiseSealer>(node.identity.private_key);
        node.transport = std::make_unique<MemoryTransport>(mesh, node.id);
        node.router = std::make_unique<SecurityRouter>(SecurityRouterConfig{network},
                                                       *node.runtime, *node.transport,
                                                       node.events, *node.sealer, nullptr);
        if (&node == genesis_node) {
            node.genesis = std::make_unique<GenesisService>(network);
        }
        node.store = std::make_unique<EpochStore>(node.dir / "security", node.wrapping.get());
        SecurityDriverConfig driver_config;
        driver_config.self = node.id;
        driver_config.identity = node.identity;
        driver_config.genesis_public_key = genesis_node->identity.public_key;
        // Stands in for the gossip layer's root-signature check.
        driver_config.certificate_source = [this, self = node.id](const NodeId& peer) {
            const auto view = mesh.uncertified_for.find(self);
            if (view != mesh.uncertified_for.end() && view->second.contains(peer)) {
                return false;
            }
            return !mesh.uncertified.contains(peer);
        };
        node.driver = std::make_unique<SecurityDriver>(driver_config, *node.runtime,
                                                       *node.router, *node.store,
                                                       node.genesis.get());
        node.events.target = node.driver.get();
    }

    void TearDown() override {
        for (auto& node : nodes) {
            if (node->wrapping) node->wrapping->stop();
            if (node->file_storage) node->file_storage->stop();
            if (node->crypto) node->crypto->stop();
        }
        fs::remove_all(root);
    }

    // Before Epoch 1 the founding set observes itself: every founder verifies
    // every other one often enough for continuity, and every founder must sign
    // the same founding eligibility transcript before any DKG starts.
    void run_founding_eligibility() {
        for (std::size_t round = 0; round < constants::kMinContinuityObservations; ++round) {
            for (Node* observer : founders) {
                for (Node* subject : founders) {
                    if (observer == subject) continue;
                    // Epoch 0 is the bootstrap window: the founding round is
                    // not Epoch 1 work and does not spend its budget.
                    observer->driver->on_attestation_verdict(
                        eligibility_verdict(network, subject->id, 0,
                                            static_cast<uint8_t>(round + 1)),
                        evidence_for(subject->id, *subject->driver->vote_key_for_epoch(1)));
                }
            }
            mesh.pump();
        }
    }

    // Everything up to the founding message: Genesis verifies the candidates
    // and names the founders. No assertions, so a negative path can use it.
    void collect_founding() {
        for (auto& node : nodes) node->driver->start(mesh.now_ms);
        for (Node* founder : founders) {
            genesis_node->driver->on_peer(founder->id, mesh.now_ms);
        }
        mesh.pump();  // Challenges reach the founders; no producer, no answer.

        // Injected verdicts stand in for the confidential-VM positive path.
        for (Node* founder : founders) {
            genesis_node->driver->on_attestation_verdict(
                eligibility_verdict(network, founder->id, 1),
                evidence_for(founder->id, *founder->driver->vote_key_for_epoch(1)));
        }
        mesh.pump();  // The founding reaches the founders; the mutual round starts.
    }

    void bootstrap() {
        collect_founding();
        ASSERT_EQ(genesis_node->driver->phase(), DriverPhase::GenesisCollecting);
        for (Node* founder : founders) {
            ASSERT_EQ(founder->driver->phase(), DriverPhase::GenesisEligibility);
        }

        // Mutual observation -> agreed transcript -> DKG -> certificate.
        run_founding_eligibility();

        for (Node* founder : founders) {
            ASSERT_EQ(founder->driver->phase(), DriverPhase::Active);
            ASSERT_EQ(founder->driver->current_epoch(), 1u);
            ASSERT_NE(founder->runtime->consensus(), nullptr);
            ASSERT_TRUE(founder->runtime->consensus()->usable());
            ASSERT_TRUE(founder->runtime->consensus()->synced());
        }
        EXPECT_EQ(genesis_node->driver->phase(), DriverPhase::Idle);
        EXPECT_EQ(genesis_node->runtime->epochs(), nullptr);
    }

    void step(int count) { step(count, founders); }

    void step(int count, const std::vector<Node*>& online) {
        for (int i = 0; i < count; ++i) {
            mesh.now_ms += 200;
            for (Node* node : online) node->driver->tick(mesh.now_ms);
            mesh.pump();
        }
    }

    /// Steps until the chain commits again. Continuity counts statements at
    /// strictly newer certified heights, so a round that lands at the height
    /// the last one used says nothing new; with a member offline the next
    /// commit waits on a view timeout, which no fixed step count can promise.
    void advance_commit(const std::vector<Node*>& online, int max_steps = 400) {
        const Height start = online.front()->driver->last_committed_height();
        for (int i = 0; i < max_steps; ++i) {
            step(1, online);
            if (online.front()->driver->last_committed_height() > start) return;
        }
    }

    // Advances time in tick steps until every founder committed `height`.
    void run_until_committed(Height height, int max_steps = 200) {
        for (int i = 0; i < max_steps; ++i) {
            step(1);
            const bool done = std::all_of(founders.begin(), founders.end(), [&](Node* f) {
                return f->driver->last_committed_height() >= height;
            });
            if (done) return;
        }
        FAIL() << "no commit at height " << height << " within " << max_steps << " steps";
    }

    // One re-attestation round: every member verifies every other one and
    // signs an observation about it. One verifier's word is not a fact; the
    // quorum forms from the published statements.
    void reattest_round(uint8_t round, EpochId epoch = 1, IncarnationId incarnation = 1) {
        attest_subjects(round, founders, epoch, incarnation);
    }

    /// Injects the verdicts a confidential host would produce, into every
    /// current member, for each named subject.
    void attest_subjects(uint8_t round, const std::vector<Node*>& subjects,
                         const std::vector<Node*>& observers, EpochId epoch = 1,
                         IncarnationId incarnation = 1) {
        for (Node* observer : observers) {
            for (Node* subject : subjects) {
                if (subject == observer) continue;
                observer->driver->on_attestation_verdict(
                    eligibility_verdict(network, subject->id, epoch, round, incarnation),
                    evidence_for(subject->id, *subject->driver->vote_key_for_epoch(epoch)));
            }
        }
        mesh.pump();
    }

    void attest_subjects(uint8_t round, const std::vector<Node*>& subjects, EpochId epoch = 1,
                         IncarnationId incarnation = 1) {
        attest_subjects(round, subjects, founders, epoch, incarnation);
    }

    /// The plan the members most recently committed and broadcast. Final
    /// attestation binds to it, so the injected verdicts must name it too.
    /// A missing plan is a recorded failure and an empty plan, never UB.
    [[nodiscard]] const NextEpochPlan& latest_plan() const {
        static const NextEpochPlan kNone{};
        if (mesh.captured_plans.empty()) {
            ADD_FAILURE() << "no plan was captured";
            return kNone;
        }
        return mesh.captured_plans.back().plan;
    }

    /// Injects the fresh final-attestation verdicts for the committed plan
    /// into each observer, bound to that plan's exact context. Every observer
    /// also holds a verdict for itself: the production path loops evidence
    /// back through the local verifier.
    void final_attest_subjects(uint8_t round, const std::vector<Node*>& subjects,
                               const std::vector<Node*>& observers) {
        const NextEpochPlan plan = latest_plan();
        for (Node* observer : observers) {
            for (Node* subject : subjects) {
                const auto vote_key = subject->driver->vote_key_for_epoch(plan.next_epoch);
                if (!vote_key.has_value()) {
                    ADD_FAILURE() << "selected node holds no next-epoch key";
                    continue;
                }
                observer->driver->on_attestation_verdict(
                    final_verdict(plan, subject->id, round),
                    evidence_for(subject->id, *vote_key));
            }
        }
        mesh.pump();
    }

    /// The reserves become reachable to the current members. Reachability is
    /// not eligibility: the cadence decides what to ask them for.
    void introduce_reserves() {
        for (Node* founder : founders) {
            for (Node* reserve : reserves) {
                founder->driver->on_peer(reserve->id, mesh.now_ms);
            }
        }
    }

    /// Advances past the re-attestation interval so the cadence fires: an
    /// attestation challenge to every certified peer, and a participation
    /// challenge to the ones that hold no epoch vote key. The reserves answer
    /// over the wire; the verdicts are injected because the positive
    /// attestation path needs a confidential VM.
    void run_reattest_cadence(uint8_t round, const std::vector<Node*>& subjects,
                              const std::vector<Node*>& online = {}, EpochId epoch = 1) {
        const std::vector<Node*>& members = online.empty() ? founders : online;
        mesh.now_ms += constants::kReattestIntervalSeconds * 1000;
        for (Node* node : members) node->driver->tick(mesh.now_ms);
        for (Node* reserve : reserves) reserve->driver->tick(mesh.now_ms);
        mesh.pump();
        attest_subjects(round, subjects, members, epoch);
        advance_commit(members);
    }

    // One member re-attests under a second incarnation inside a frozen epoch.
    // Two identity-signed bundles naming different incarnations is proved
    // misbehavior, so every observer records the fault independently.
    void reattest_one(Node& subject, uint8_t round, IncarnationId incarnation,
                      EpochId epoch = 1) {
        for (Node* founder : founders) {
            if (founder == &subject) continue;
            founder->driver->on_attestation_verdict(
                eligibility_verdict(network, subject.id, epoch, round, incarnation),
                evidence_for(subject.id, *subject.driver->vote_key_for_epoch(epoch)));
        }
        mesh.pump();
    }

    [[nodiscard]] const EligibilityService& eligibility_of(const Node& node) const {
        return node.driver->eligibility();
    }

    [[nodiscard]] Digest commitment_of(const Node& node, EpochId next) const {
        return eligibility_commitment_digest(eligibility_of(node).compute_state(next));
    }

    [[nodiscard]] bool eligible_in(const Node& node, const NodeId& subject, EpochId next) const {
        const auto nodes_in = eligible_nodes(eligibility_of(node).compute_state(next));
        return std::find(nodes_in.begin(), nodes_in.end(), subject) != nodes_in.end();
    }

    // Runs the live eligibility path to the point where a transition exists:
    // continuity from repeated mesh-observed attestations, participation from
    // the consensus votes themselves, then the finalized eligibility
    // commitment that releases the pool.
    void prepare_handoff(int max_steps = 120) {
        for (uint8_t round = 1; round <= constants::kMinContinuityObservations; ++round) {
            reattest_round(round);
            advance_commit(founders);
        }
        mesh.now_ms += constants::kTargetEpochSeconds * 1000;
        for (int i = 0; i < max_steps; ++i) {
            step(1);
            const bool prepared = std::all_of(founders.begin(), founders.end(), [](Node* f) {
                return f->runtime->epochs() != nullptr &&
                       f->runtime->epochs()->transition() != nullptr;
            });
            if (prepared) return;
        }
    }

    fs::path root;
    NetworkId network{};
    MemoryMesh mesh;
    std::vector<std::unique_ptr<Node>> nodes;
    Node* genesis_node = nullptr;
    std::vector<Node*> founders;
    std::vector<Node*> reserves;
    std::size_t reserve_count_ = kReserves;
};

/// The default mesh: five founders, two reserves.
struct DriverMesh : DriverMeshBase {};

}  // namespace lifecycle_test
