// The lifecycle driver on a six-node memory mesh: one Genesis server and five
// founders, exchanging only encoded envelopes, paced only by tick().
//
// The attestation verifier's positive path needs a confidential VM, so
// verdicts are injected through the driver's own event entry point; every
// other step — founding, DKG, certificates, consensus, handoff — runs the
// real code over the wire.

#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Security/Lifecycle/SecurityDriver.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <deque>
#include <fstream>
#include <filesystem>
#include <memory>
#include <unistd.h>
#include <vector>

using namespace nexus::security;
namespace constants = nexus::security::constants;
namespace fs = std::filesystem;

namespace {

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

void MemoryMesh::pump() {
    while (!queue.empty()) {
        Queued item = std::move(queue.front());
        queue.pop_front();
        nodes.at(item.to)->deliver(item.from, item.bytes, now_ms);
    }
}

AttestationVerdict passing_verdict(const NodeId& id, EpochId epoch) {
    AttestationVerdict verdict;
    verdict.node_id = id;
    verdict.epoch = epoch;
    verdict.incarnation = 1;
    verdict.passed = true;
    verdict.evidence_digest.fill(id.bytes[0] ^ static_cast<uint8_t>(epoch));
    return verdict;
}

AttestationEvidence evidence_for(const NodeId& id, const nexus::crypto::Ed25519PublicKey& vote_key) {
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

    void bootstrap() {
        for (auto& node : nodes) node->driver->start(mesh.now_ms);
        ASSERT_EQ(genesis_node->driver->phase(), DriverPhase::GenesisCollecting);

        for (Node* founder : founders) {
            genesis_node->driver->on_peer(founder->id, mesh.now_ms);
        }
        mesh.pump();  // Challenges reach the founders; no producer, no answer.

        // Injected verdicts stand in for the confidential-VM positive path.
        for (Node* founder : founders) {
            const auto vote_key = founder->driver->vote_key_for_epoch(1);
            ASSERT_TRUE(vote_key.has_value());
            genesis_node->driver->on_attestation_verdict(passing_verdict(founder->id, 1),
                                                         evidence_for(founder->id, *vote_key));
        }
        mesh.pump();  // Founding -> DKG -> attests -> certificate -> adoption.

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

    // Advances time in tick steps until every founder committed `height`.
    void run_until_committed(Height height, int max_steps = 200) {
        for (int step = 0; step < max_steps; ++step) {
            mesh.now_ms += 200;
            for (Node* founder : founders) founder->driver->tick(mesh.now_ms);
            mesh.pump();
            const bool done = std::all_of(founders.begin(), founders.end(), [&](Node* f) {
                return f->driver->last_committed_height() >= height;
            });
            if (done) return;
        }
        FAIL() << "no commit at height " << height << " within " << max_steps << " steps";
    }

    fs::path root;
    NetworkId network{};
    MemoryMesh mesh;
    std::vector<std::unique_ptr<Node>> nodes;
    Node* genesis_node = nullptr;
    std::vector<Node*> founders;
};

TEST_F(DriverMesh, GenesisToEpochOneOverTheWire) {
    bootstrap();

    // The bootstrap certificate is durable on every founder and on Genesis.
    for (Node* founder : founders) {
        EXPECT_TRUE(std::holds_alternative<BootstrapCertificate>(
            founder->store->load_bootstrap()));
        EXPECT_TRUE(std::holds_alternative<StoredEpoch>(founder->store->load_epoch()));
        const auto history = founder->store->load_authority_history();
        ASSERT_TRUE(std::holds_alternative<std::vector<EpochAuthorityRecord>>(history));
        EXPECT_EQ(std::get<std::vector<EpochAuthorityRecord>>(history).size(), 1u);
    }
    EXPECT_TRUE(std::holds_alternative<BootstrapCertificate>(
        genesis_node->store->load_bootstrap()));

    // Every founder holds the same group key and a live share.
    const auto group = founders[0]->runtime->authority().group_public_key();
    ASSERT_TRUE(group.has_value());
    for (Node* founder : founders) {
        EXPECT_EQ(*founder->runtime->authority().group_public_key(), *group);
        EXPECT_EQ(*founder->runtime->authority().key_epoch(), 1u);
    }
}

TEST_F(DriverMesh, TickPacedConsensusCommits) {
    bootstrap();
    run_until_committed(3);
    for (Node* founder : founders) {
        EXPECT_GE(founder->driver->last_committed_height(), 3u);
    }
}

TEST_F(DriverMesh, TimedHandoffRotatesToEpochTwo) {
    bootstrap();
    run_until_committed(1);
    const auto epoch_one_group = *founders[0]->runtime->authority().group_public_key();

    // The epoch ages past the compiled target; every member's local pool has
    // every other member passing its re-attestation.
    mesh.now_ms += constants::kTargetEpochSeconds * 1000;
    for (Node* founder : founders) {
        for (Node* member : founders) {
            if (member == founder) continue;
            founder->driver->on_attestation_verdict(
                passing_verdict(member->id, 1),
                evidence_for(member->id, *member->driver->vote_key_for_epoch(1)));
        }
    }
    for (Node* founder : founders) founder->driver->tick(mesh.now_ms);
    mesh.pump();  // Final challenges go out; nobody can answer without a VM.
    for (Node* founder : founders) {
        ASSERT_NE(founder->runtime->epochs()->transition(), nullptr);
        ASSERT_EQ(founder->runtime->epochs()->transition()->to_epoch, 2u);
    }

    // Injected final verdicts for the target epoch, binding epoch-2 vote keys.
    for (Node* member : founders) {
        const auto vote_key = member->driver->vote_key_for_epoch(2);
        ASSERT_TRUE(vote_key.has_value());
        for (Node* founder : founders) {
            founder->driver->on_attestation_verdict(passing_verdict(member->id, 2),
                                                    evidence_for(member->id, *vote_key));
        }
    }
    mesh.pump();  // The epoch-2 DKG runs over the wire.
    for (Node* founder : founders) {
        ASSERT_NE(founder->runtime->epochs()->transition(), nullptr);
        EXPECT_EQ(founder->runtime->epochs()->transition()->phase, EpochTransitionPhase::Ready);
    }

    // The next committed block carries the handoff and activates Epoch 2.
    for (int step = 0; step < 200; ++step) {
        mesh.now_ms += 200;
        for (Node* founder : founders) founder->driver->tick(mesh.now_ms);
        mesh.pump();
        const bool rotated = std::all_of(founders.begin(), founders.end(), [](Node* f) {
            return f->driver->current_epoch() == 2u;
        });
        if (rotated) break;
    }
    for (Node* founder : founders) {
        ASSERT_EQ(founder->driver->current_epoch(), 2u);
        EXPECT_EQ(*founder->runtime->authority().key_epoch(), 2u);
        EXPECT_NE(*founder->runtime->authority().group_public_key(), epoch_one_group);
        ASSERT_NE(founder->runtime->consensus(), nullptr);
        EXPECT_TRUE(founder->runtime->consensus()->usable());
        const auto history = founder->store->load_authority_history();
        ASSERT_TRUE(std::holds_alternative<std::vector<EpochAuthorityRecord>>(history));
        EXPECT_EQ(std::get<std::vector<EpochAuthorityRecord>>(history).size(), 2u);
    }

    // Epoch 2 keeps committing under the new vote keys.
    const Height before = founders[0]->driver->last_committed_height();
    run_until_committed(before + 1);
}

TEST_F(DriverMesh, RestartSyncsToACertifiedFloorBeforeVoting) {
    bootstrap();
    run_until_committed(2);
    Node* victim = founders[0];
    const Height committed_before = victim->driver->last_committed_height();

    restart_node(*victim);
    victim->driver->start(mesh.now_ms);

    // The stored epoch and safety state came back; voting stays blocked
    // until quorum-certified state sets the view floor.
    ASSERT_EQ(victim->driver->phase(), DriverPhase::Syncing);
    ASSERT_NE(victim->runtime->consensus(), nullptr);
    EXPECT_TRUE(victim->runtime->consensus()->usable());
    EXPECT_FALSE(victim->runtime->consensus()->synced());
    EXPECT_EQ(victim->driver->current_epoch(), 1u);

    // The sync request went out during start; the answers carry validated
    // certificates and finish the sync.
    mesh.pump();
    EXPECT_EQ(victim->driver->phase(), DriverPhase::Active);
    EXPECT_TRUE(victim->runtime->consensus()->synced());

    // The mesh keeps committing with the restarted member voting again.
    run_until_committed(committed_before + 2);
    EXPECT_GE(victim->driver->last_committed_height(), committed_before + 2);
}

TEST_F(DriverMesh, CorruptEpochStateFailsClosed) {
    bootstrap();
    Node* victim = founders[0];
    restart_node(*victim);
    {
        std::ofstream out(victim->store->directory() / "epoch-current.json");
        out << "{corrupt";
    }
    victim->driver->start(mesh.now_ms);
    EXPECT_EQ(victim->driver->phase(), DriverPhase::Failed);
    EXPECT_EQ(victim->runtime->epochs(), nullptr);

    // A failed driver does nothing on tick and answers no protocol traffic.
    victim->driver->tick(mesh.now_ms + 1000);
    EXPECT_EQ(victim->driver->phase(), DriverPhase::Failed);
}

}  // namespace
