#pragma once

// The six-node memory mesh the lifecycle tests run on: one Genesis server and
// five founders, exchanging only encoded envelopes, paced only by tick().
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

inline void MemoryMesh::pump() {
    while (!queue.empty()) {
        Queued item = std::move(queue.front());
        queue.pop_front();
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
// distinct attestations, so the digests must differ between rounds.
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

inline AttestationEvidence evidence_for(const NodeId& id, const nexus::crypto::Ed25519PublicKey& vote_key) {
    AttestationEvidence evidence;
    evidence.node_id = id;
    evidence.incarnation = 1;
    evidence.epoch_vote_key = vote_key;
    return evidence;
}

struct DriverMesh : ::testing::Test {
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        root = fs::temp_directory_path() / ("nexus_driver_" + std::to_string(::getpid()));
        fs::create_directories(root);

        // Node 0 is Genesis: its identity IS the pinned genesis key.
        for (std::size_t i = 0; i < kFounders + 1; ++i) {
            auto node = std::make_unique<Node>();
            crypto_sign_keypair(node->identity.public_key.data(),
                                node->identity.private_key.data());
            node->id.bytes = node->identity.public_key;
            nodes.push_back(std::move(node));
        }
        genesis_node = nodes[0].get();
        for (std::size_t i = 1; i < nodes.size(); ++i) founders.push_back(nodes[i].get());
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
                        passing_verdict(subject->id, 0, static_cast<uint8_t>(round + 1)),
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
                passing_verdict(founder->id, 1),
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

    void step(int count) {
        for (int i = 0; i < count; ++i) {
            mesh.now_ms += 200;
            for (Node* founder : founders) founder->driver->tick(mesh.now_ms);
            mesh.pump();
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
        for (Node* founder : founders) {
            for (Node* member : founders) {
                if (member == founder) continue;
                founder->driver->on_attestation_verdict(
                    passing_verdict(member->id, epoch, round, incarnation),
                    evidence_for(member->id, *member->driver->vote_key_for_epoch(epoch)));
            }
        }
        mesh.pump();
    }

    // One member re-attests under a second incarnation inside a frozen epoch.
    // Two identity-signed bundles naming different incarnations is proved
    // misbehavior, so every observer records the fault independently.
    void reattest_one(Node& subject, uint8_t round, IncarnationId incarnation,
                      EpochId epoch = 1) {
        for (Node* founder : founders) {
            if (founder == &subject) continue;
            founder->driver->on_attestation_verdict(
                passing_verdict(subject.id, epoch, round, incarnation),
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
            step(6);
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
};

}  // namespace lifecycle_test
