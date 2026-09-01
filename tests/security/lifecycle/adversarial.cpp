// Adversarial behavior on the in-process mesh.
//
// The harness is the DriverMesh pattern from driver.cpp with three additions:
// a partition model, a hold buffer that parks selected envelopes, and an
// in-flight corrupter. Everything else is the real code over the wire.
//
// driver.cpp pins the happy paths: genesis bootstrap, the epoch-1 DKG, tick
// paced finality, the timed handoff to epoch 2, restart sync, and corrupt
// epoch state. This file attacks them. Every negative case carries a positive
// control, so no assertion here can pass because the mesh simply stopped.

#include <LemonadeNexus/Crypto/FrostProvider.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Security/Lifecycle/SecurityDriver.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <gtest/gtest.h>
#include <sodium.h>

#include <algorithm>
#include <deque>
#include <fstream>
#include <filesystem>
#include <memory>
#include <optional>
#include <set>
#include <string>
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

[[nodiscard]] std::optional<SecurityMessageKind> envelope_kind(std::span<const uint8_t> bytes) {
    auto decoded = decode_security_message(bytes);
    if (const auto* message = std::get_if<SecurityMessage>(&decoded)) {
        return message->kind;
    }
    return std::nullopt;
}

// Flips one byte of a DKG payload without touching any binding field, so the
// message still passes every transport and session binding check and fails
// only inside FROST.
[[nodiscard]] std::vector<uint8_t> corrupt_dkg_payload(std::span<const uint8_t> bytes) {
    auto decoded = decode_security_message(bytes);
    auto* message = std::get_if<SecurityMessage>(&decoded);
    if (message == nullptr) {
        return {bytes.begin(), bytes.end()};
    }
    auto* dkg = std::get_if<DkgMessage>(&message->body);
    if (dkg == nullptr || dkg->payload.empty()) {
        return {bytes.begin(), bytes.end()};
    }
    dkg->payload[0] ^= 0x01;
    auto encoded = encode_security_message(*message);
    return encoded.empty() ? std::vector<uint8_t>(bytes.begin(), bytes.end()) : encoded;
}

struct MemoryMesh {
    std::map<NodeId, Node*> nodes;
    std::deque<Queued> queue;
    uint64_t now_ms = 1000;

    // Partition side per node; nodes on different sides exchange nothing.
    std::map<NodeId, int> side;
    // Envelopes matched here are parked instead of queued.
    std::map<NodeId, std::set<SecurityMessageKind>> hold_rules;
    std::deque<Queued> held;
    // Envelopes matched here have one payload byte flipped in flight.
    std::map<NodeId, std::set<SecurityMessageKind>> corrupt_rules;
    // Envelopes that actually left each node, by kind.
    std::map<NodeId, std::map<SecurityMessageKind, std::size_t>> sent;
    // Nodes whose transport certificate no longer verifies against the root.
    // The mesh knows this, not the platform, so it lives here.
    std::set<NodeId> uncertified;

    [[nodiscard]] bool reachable(const NodeId& from, const NodeId& to) const {
        const auto a = side.find(from);
        const auto b = side.find(to);
        const int left = a == side.end() ? 0 : a->second;
        const int right = b == side.end() ? 0 : b->second;
        return left == right;
    }

    [[nodiscard]] static bool matches(
        const std::map<NodeId, std::set<SecurityMessageKind>>& rules, const NodeId& from,
        SecurityMessageKind kind) {
        const auto it = rules.find(from);
        return it != rules.end() && it->second.contains(kind);
    }

    void enqueue(const NodeId& from, const NodeId& to, std::span<const uint8_t> envelope) {
        if (!reachable(from, to)) {
            return;
        }
        std::vector<uint8_t> bytes(envelope.begin(), envelope.end());
        const auto kind = envelope_kind(bytes);
        if (kind.has_value()) {
            if (matches(corrupt_rules, from, *kind)) {
                bytes = corrupt_dkg_payload(bytes);
            }
            if (matches(hold_rules, from, *kind)) {
                held.push_back({from, to, std::move(bytes)});
                return;
            }
            ++sent[from][*kind];
        }
        queue.push_back({from, to, std::move(bytes)});
    }

    void release_held() {
        hold_rules.clear();
        while (!held.empty()) {
            Queued item = std::move(held.front());
            held.pop_front();
            const auto kind = envelope_kind(item.bytes);
            if (kind.has_value()) {
                ++sent[item.from][*kind];
            }
            queue.push_back(std::move(item));
        }
    }

    void heal() { side.clear(); }

    void pump();
};

struct MemoryTransport : ISecurityTransport {
    MemoryTransport(MemoryMesh& mesh, NodeId self) : mesh(mesh), self(self) {}

    bool send_to(const NodeId& peer, std::span<const uint8_t> envelope) override {
        if (!mesh.nodes.contains(peer) || envelope.size() > constants::kMaxSecurityMessageBytes) {
            return false;
        }
        // A partitioned send still looks accepted to the sender: a node never
        // learns from the transport that a peer is unreachable.
        mesh.enqueue(self, peer, envelope);
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
// router. The proxy breaks the cycle and records what crossed it.
struct EventsProxy : ISecurityEvents {
    ISecurityEvents* target = nullptr;

    std::vector<std::pair<Vote, NodeId>> votes_sent;
    std::vector<QuorumCertificate> certificates;
    std::vector<std::pair<EpochId, std::pair<Height, Digest>>> commits;
    std::vector<std::pair<DkgFailure, std::optional<NodeId>>> dkg_failures;
    std::vector<EpochId> dkg_complete;
    std::vector<AuthoritySignature> signatures;
    std::vector<AttestationVerdict> verdicts;
    std::vector<QuorumCertificate> sync_certificates;

    void clear() {
        votes_sent.clear();
        certificates.clear();
        commits.clear();
        dkg_failures.clear();
        dkg_complete.clear();
        signatures.clear();
        verdicts.clear();
        sync_certificates.clear();
    }

    void on_vote_sent(const Vote& v, const NodeId& n) override {
        votes_sent.emplace_back(v, n);
        if (target) target->on_vote_sent(v, n);
    }
    void on_certificate(const QuorumCertificate& q) override {
        certificates.push_back(q);
        if (target) target->on_certificate(q);
    }
    void on_timeout_certificate(const TimeoutCertificate& t) override {
        if (target) target->on_timeout_certificate(t);
    }
    void on_commits(const std::vector<ConsensusCommit>& c) override {
        for (const auto& commit : c) {
            commits.emplace_back(commit.epoch,
                                 std::pair{commit.height, commit.proposal_digest});
        }
        if (target) target->on_commits(c);
    }
    void on_dkg_round1_complete(EpochId e) override {
        if (target) target->on_dkg_round1_complete(e);
    }
    void on_dkg_complete(EpochId e) override {
        dkg_complete.push_back(e);
        if (target) target->on_dkg_complete(e);
    }
    void on_dkg_failed(DkgFailure f, std::optional<NodeId> c) override {
        dkg_failures.emplace_back(f, c);
        if (target) target->on_dkg_failed(f, c);
    }
    void on_authority_signature(const AuthoritySignature& s) override {
        signatures.push_back(s);
        if (target) target->on_authority_signature(s);
    }
    void on_attestation_verdict(const AttestationVerdict& v,
                                const AttestationEvidence& e) override {
        verdicts.push_back(v);
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
        sync_certificates.push_back(q);
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
};

struct Node {
    nexus::crypto::Ed25519Keypair identity;
    NodeId id;
    fs::path dir;
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

    // Drops seen on the inbound path, by reason. A test that expects an
    // attack to be stopped at the transport reads its evidence here.
    std::map<DropReason, std::size_t> drops;

    RouteResult deliver(const NodeId& from, std::span<const uint8_t> bytes, uint64_t now) {
        const RouteResult result = router->receive(from, bytes, now);
        if (result.dropped.has_value()) ++drops[*result.dropped];
        return result;
    }
};

void MemoryMesh::pump() {
    while (!queue.empty()) {
        Queued item = std::move(queue.front());
        queue.pop_front();
        nodes.at(item.to)->deliver(item.from, item.bytes, now_ms);
    }
}

// What a provider proves on a good confidential host. Tier 1 reads the claims,
// not `passed`, so a verdict without them confers nothing.
VerifiedPlatformClaims complete_claims() {
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
AttestationVerdict passing_verdict(const NodeId& id, EpochId epoch, uint8_t round = 0) {
    AttestationVerdict verdict;
    verdict.node_id = id;
    verdict.epoch = epoch;
    verdict.incarnation = 1;
    verdict.passed = true;
    verdict.claims = complete_claims();
    // Distinct per node, epoch and round, and never all-zero: an empty
    // evidence digest proves no attestation ran and is refused as such.
    verdict.evidence_digest.fill(id.bytes[0]);
    verdict.evidence_digest[0] = static_cast<uint8_t>(0xA0 + round);
    verdict.evidence_digest[1] = static_cast<uint8_t>(epoch + 1);
    return verdict;
}

AttestationEvidence evidence_for(const NodeId& id, const nexus::crypto::Ed25519PublicKey& vote_key) {
    AttestationEvidence evidence;
    evidence.node_id = id;
    evidence.incarnation = 1;
    evidence.epoch_vote_key = vote_key;
    return evidence;
}

Digest filled(uint8_t byte) {
    Digest digest{};
    digest.fill(byte);
    return digest;
}

// Step 0 of the verifier refuses every candidate under an incomplete profile,
// so the attestation tests need a profile that pins everything.
LinuxAttestationProfile complete_profile() {
    LinuxAttestationProfile profile = linux_attestation_profile_v1();
    profile.snp.min_tcb = {2, 0, 6, 55};
    profile.snp.expected_measurement_hex = std::string(96, 'a');
    profile.ima_policy_digest = filled(0x60);
    profile.approved_binary_sha256 = {std::string(64, 'b')};
    return profile;
}

struct AdversarialMesh : ::testing::Test {
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        ASSERT_TRUE(profile_is_complete(complete_profile()));
        root = fs::temp_directory_path() / ("nexus_adversarial_" + std::to_string(::getpid()));
        fs::remove_all(root);
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

    void TearDown() override {
        for (auto& node : nodes) {
            if (node->wrapping) node->wrapping->stop();
            if (node->file_storage) node->file_storage->stop();
            if (node->crypto) node->crypto->stop();
        }
        fs::remove_all(root);
    }

    void build_node(Node& node) {
        SecurityRuntimeConfig runtime_config;
        runtime_config.self = node.id;
        runtime_config.network_id = network;
        runtime_config.consensus_directory = node.dir / "consensus";
        runtime_config.profile = complete_profile();
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
        driver_config.certificate_source = [this](const NodeId& peer) {
            return !mesh.uncertified.contains(peer);
        };
        node.driver = std::make_unique<SecurityDriver>(driver_config, *node.runtime,
                                                       *node.router, *node.store,
                                                       node.genesis.get());
        node.events.target = node.driver.get();
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
        mesh.pump();  // The founding reaches the founders; the mutual round starts.
        run_founding_eligibility();  // -> agreed transcript -> DKG -> certificate.

        for (Node* founder : founders) {
            ASSERT_EQ(founder->driver->phase(), DriverPhase::Active);
            ASSERT_EQ(founder->driver->current_epoch(), 1u);
            ASSERT_NE(founder->runtime->consensus(), nullptr);
            ASSERT_TRUE(founder->runtime->consensus()->synced());
        }
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
    void reattest_round(uint8_t round, EpochId epoch = 1) {
        for (Node* founder : founders) {
            for (Node* member : founders) {
                if (member == founder) continue;
                founder->driver->on_attestation_verdict(
                    passing_verdict(member->id, epoch, round),
                    evidence_for(member->id, *member->driver->vote_key_for_epoch(epoch)));
            }
        }
        mesh.pump();
    }

    // Runs the live eligibility path to the point where a transition exists:
    // continuity from repeated mesh-observed attestations, participation from
    // the consensus votes themselves, then the finalized eligibility
    // commitment that releases the pool.
    void prepare_handoff(int max_steps = 120) {
        for (uint8_t round = 1; round <= constants::kMinContinuityObservations; ++round) {
            reattest_round(round);
            // Commits between rounds so every observer's certified height moves.
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

    // Final verdicts for the target epoch; these start the epoch-2 DKG.
    void inject_final_verdicts() {
        for (Node* member : founders) {
            const auto vote_key = member->driver->vote_key_for_epoch(2);
            EXPECT_TRUE(vote_key.has_value());
            for (Node* founder : founders) {
                founder->driver->on_attestation_verdict(passing_verdict(member->id, 2),
                                                        evidence_for(member->id, *vote_key));
            }
        }
        mesh.pump();
    }

    // True when any member formed a quorum certificate since the recorded
    // certificates were last cleared.
    [[nodiscard]] bool any_new_certificate() const {
        return std::any_of(founders.begin(), founders.end(),
                           [](Node* f) { return !f->events.certificates.empty(); });
    }

    [[nodiscard]] bool all_at_epoch(EpochId epoch) const {
        return std::all_of(founders.begin(), founders.end(), [&](Node* f) {
            return f->driver->current_epoch() == epoch;
        });
    }

    void advance_to_epoch_two(int max_steps = 300) {
        prepare_handoff();
        inject_final_verdicts();
        for (int i = 0; i < max_steps; ++i) {
            step(1);
            if (all_at_epoch(2)) return;
        }
        FAIL() << "epoch 2 did not activate within " << max_steps << " steps";
    }

    // Two nodes committing different blocks at one (epoch, height) is the
    // safety violation every partition test is really looking for.
    void expect_no_conflicting_commits() const {
        std::map<std::pair<EpochId, Height>, Digest> seen;
        for (Node* founder : founders) {
            for (const auto& [epoch, entry] : founder->events.commits) {
                const auto key = std::pair{epoch, entry.first};
                const auto it = seen.find(key);
                if (it == seen.end()) {
                    seen.emplace(key, entry.second);
                } else {
                    EXPECT_EQ(it->second, entry.second)
                        << "conflicting commit at epoch " << epoch << " height " << entry.first;
                }
            }
        }
    }

    [[nodiscard]] Vote signed_vote(Node& signer, EpochId epoch, Height height, View view,
                                   const Digest& digest) const {
        auto key = signer.store->load_vote_key(epoch, signer.id);
        EXPECT_TRUE(key.has_value()) << "epoch vote key is not on disk";
        Vote vote{};
        vote.consensus_ruleset = constants::kConsensusRulesetVersion;
        vote.network_id = network;
        vote.epoch = epoch;
        vote.height = height;
        vote.view = view;
        vote.proposal_digest = digest;
        vote.voter = signer.id;
        vote.signature = sign_digest(*key, vote_signing_digest(vote));
        return vote;
    }

    [[nodiscard]] QuorumCertificate signed_qc(const std::vector<Node*>& signers, EpochId epoch,
                                              Height height, View view,
                                              const Digest& digest) const {
        QuorumCertificate certificate{};
        certificate.qc_format_version = constants::kQcFormatVersion;
        certificate.consensus_ruleset = constants::kConsensusRulesetVersion;
        certificate.network_id = network;
        certificate.epoch = epoch;
        certificate.height = height;
        certificate.view = view;
        certificate.proposal_digest = digest;
        for (Node* signer : signers) {
            auto key = signer->store->load_vote_key(epoch, signer->id);
            EXPECT_TRUE(key.has_value());
            const Digest preimage = vote_signing_digest(
                certificate.consensus_ruleset, certificate.network_id, certificate.epoch,
                certificate.height, certificate.view, certificate.proposal_digest, signer->id);
            certificate.signers.push_back(QcSigner{signer->id, sign_digest(*key, preimage)});
        }
        return certificate;
    }

    RouteResult send_envelope(Node& from, Node& to, const SecurityMessage& message) {
        return to.deliver(from.id, encode_security_message(message), mesh.now_ms);
    }

    [[nodiscard]] std::size_t sent_count(const Node& node, SecurityMessageKind kind) {
        return mesh.sent[node.id][kind];
    }

    fs::path root;
    NetworkId network{};
    MemoryMesh mesh;
    std::vector<std::unique_ptr<Node>> nodes;
    Node* genesis_node = nullptr;
    std::vector<Node*> founders;
};

// --- 1. Restart -------------------------------------------------------------

// driver.cpp already pins the happy restart (RestartSyncsToACertifiedFloor...)
// and corrupt epoch state (CorruptEpochStateFailsClosed). What is missing is
// the window in between: a restarted node whose sync never completes.
TEST_F(AdversarialMesh, RestartedNodeCastsNoVoteBeforeItsFloorIsCertified) {
    bootstrap();
    run_until_committed(2);

    Node* victim = founders[0];
    const View stored_view = victim->runtime->consensus()->state().last_voted_view;
    ASSERT_GT(stored_view, 0u);

    restart_node(*victim);
    // No peer may answer, so the sync window never closes on a real floor.
    mesh.hold_rules[victim->id] = {SecurityMessageKind::SyncRequest};
    victim->events.clear();
    victim->driver->start(mesh.now_ms);

    ASSERT_EQ(victim->driver->phase(), DriverPhase::Syncing);
    ASSERT_NE(victim->runtime->consensus(), nullptr);
    EXPECT_TRUE(victim->runtime->consensus()->usable());
    EXPECT_FALSE(victim->runtime->consensus()->synced());
    EXPECT_EQ(victim->runtime->consensus()->state().last_voted_view, stored_view);

    // The mesh keeps proposing at the victim for many views. Not one vote may
    // leave, and the stored floor may not move.
    step(40);
    EXPECT_TRUE(victim->events.votes_sent.empty());
    EXPECT_EQ(victim->driver->phase(), DriverPhase::Syncing);
    EXPECT_FALSE(victim->runtime->consensus()->synced());
    EXPECT_EQ(victim->runtime->consensus()->state().last_voted_view, stored_view);

    // Positive control: released, the same requests are answered, the floor
    // rises to certified state, and the node votes again.
    mesh.release_held();
    mesh.pump();
    ASSERT_EQ(victim->driver->phase(), DriverPhase::Active);
    EXPECT_TRUE(victim->runtime->consensus()->synced());
    EXPECT_GE(victim->runtime->consensus()->state().last_voted_view, stored_view);

    const Height before = victim->driver->last_committed_height();
    run_until_committed(before + 2);
    EXPECT_FALSE(victim->events.votes_sent.empty());
    expect_no_conflicting_commits();
}

TEST_F(AdversarialMesh, CorruptConsensusSafetyStateIsPermanentlyUnusable) {
    bootstrap();
    run_until_committed(2);

    Node* victim = founders[0];
    Node* control = founders[1];
    restart_node(*victim);
    restart_node(*control);
    {
        // The safety file is the only record of what this node already voted.
        std::ofstream out(victim->dir / "consensus" / "hotstuff-safety-1.json");
        out << "{not-json";
    }

    victim->events.clear();
    control->events.clear();
    victim->driver->start(mesh.now_ms);
    control->driver->start(mesh.now_ms);

    EXPECT_EQ(victim->driver->phase(), DriverPhase::Failed);
    ASSERT_NE(victim->runtime->consensus(), nullptr);
    EXPECT_FALSE(victim->runtime->consensus()->usable());
    // Corrupt state is never a fresh epoch: an unusable service is not synced.
    EXPECT_FALSE(victim->runtime->consensus()->synced());

    // Positive control: the same restart with intact state recovers.
    mesh.pump();
    EXPECT_EQ(control->driver->phase(), DriverPhase::Active);
    EXPECT_TRUE(control->runtime->consensus()->synced());

    // One envelope, both nodes: the failed service refuses it as unsynced, the
    // restored one counts it. The mechanism is live; only the corrupt node is
    // out of the protocol.
    Node* peer = founders[2];
    const Vote probe = signed_vote(*peer, 1, 1,
                                   control->runtime->consensus()->current_view(), filled(0x6B));
    const auto probe_message = peer->router->compose(SecurityMessageKind::HotStuffVote, probe, 1);

    const RouteResult refused = send_envelope(*peer, *victim, probe_message);
    EXPECT_EQ(refused.dropped, DropReason::ServiceRejected);
    ASSERT_TRUE(refused.service_code.has_value());
    EXPECT_EQ(*refused.service_code, static_cast<uint16_t>(ConsensusFailure::NotSynced));
    EXPECT_TRUE(send_envelope(*peer, *control, probe_message).delivered);

    // The failed node answers nothing, however long the mesh runs at it.
    step(40);
    EXPECT_EQ(victim->driver->phase(), DriverPhase::Failed);
    EXPECT_TRUE(victim->events.votes_sent.empty());
    EXPECT_FALSE(victim->runtime->consensus()->usable());
    EXPECT_FALSE(victim->runtime->consensus()->synced());
}

// --- 2. Partitions ----------------------------------------------------------

TEST_F(AdversarialMesh, NoPartitionSideBelowQuorumMakesProgress) {
    bootstrap();
    run_until_committed(2);
    // Five members need four votes. Neither a 2/5 nor a 3/5 side is a quorum,
    // so a "majority" of three must be as powerless as the minority of two.
    ASSERT_EQ(founders[0]->runtime->epochs()->current().consensus_quorum, 4u);

    // Positive control, taken with the same harness and the same step count
    // that the split then gets: whole, this mesh certifies immediately.
    for (Node* founder : founders) founder->events.certificates.clear();
    step(8);
    EXPECT_TRUE(any_new_certificate()) << "the whole mesh formed no certificate";

    // A node may still finalize blocks the whole mesh certified before the
    // split, so the property under test is "no side certifies anything new".
    Height certified = 0;
    for (Node* founder : founders) {
        certified = std::max(certified, founder->runtime->consensus()->state().high_qc.height);
        founder->events.certificates.clear();
    }
    for (std::size_t i = 0; i < kFounders; ++i) {
        mesh.side[founders[i]->id] = i < 2 ? 0 : 1;
    }

    step(80);
    for (Node* founder : founders) {
        EXPECT_TRUE(founder->events.certificates.empty())
            << "a side below quorum formed a certificate";
        EXPECT_LE(founder->driver->last_committed_height(), certified)
            << "a side below quorum finalized an uncertified block";
    }
    expect_no_conflicting_commits();

    // KNOWN GAP, documented rather than asserted away: healing the network is
    // not enough. A replica times out only in its own current view, a timeout
    // certificate is never relayed, and a proposal lost during the split is
    // never re-sent, so the members stay stranded in different views and no
    // single view can gather a quorum again. Recovery needs a restart, which
    // IsolatedMemberNeverForksAndRejoinsTheCertifiedChain exercises.
    mesh.heal();
    step(200);
    EXPECT_FALSE(any_new_certificate())
        << "the mesh now recovers from a heal by itself; tighten this test";
    expect_no_conflicting_commits();
}

TEST_F(AdversarialMesh, IsolatedMemberNeverForksAndRejoinsTheCertifiedChain) {
    bootstrap();
    run_until_committed(2);

    Node* isolated = founders[4];
    const Height isolated_before = isolated->driver->last_committed_height();
    const Height isolated_certified =
        isolated->runtime->consensus()->state().high_qc.height;
    isolated->events.certificates.clear();
    mesh.side[isolated->id] = 1;

    // Four of five is exactly the quorum, so the majority side must finalize
    // even while one leader slot never proposes. That is this test's positive
    // control: the isolated member's silence is measured against real progress.
    Height majority = 0;
    for (int i = 0; i < 400; ++i) {
        step(1);
        majority = founders[0]->driver->last_committed_height();
        if (majority >= isolated_before + 3) break;
    }
    EXPECT_GE(majority, isolated_before + 3) << "the quorum side made no progress";

    // The isolated member certifies nothing. It may still finalize blocks the
    // quorum had already certified before the split; it never goes past them.
    EXPECT_TRUE(isolated->events.certificates.empty())
        << "the isolated member formed a certificate alone";
    EXPECT_LE(isolated->driver->last_committed_height(), isolated_certified)
        << "the isolated member finalized an uncertified block";
    expect_no_conflicting_commits();

    // Healing alone does not put the isolated node back on the chain: the
    // proposals it now receives mostly name parents it never saw. Whatever it
    // does accept, it never runs ahead of the quorum and never builds a branch
    // of its own.
    mesh.heal();
    isolated->events.clear();
    step(40);
    EXPECT_LE(isolated->driver->last_committed_height(),
              founders[0]->driver->last_committed_height());
    expect_no_conflicting_commits();

    // A restart is the certified catch-up path: the node takes the chain the
    // quorum finalized instead of continuing its own, and votes again on it.
    View certified_view = 0;
    for (Node* founder : founders) {
        if (founder == isolated) continue;
        certified_view =
            std::max(certified_view, founder->runtime->consensus()->state().high_qc.view);
    }
    restart_node(*isolated);
    isolated->events.clear();
    isolated->driver->start(mesh.now_ms);
    ASSERT_EQ(isolated->driver->phase(), DriverPhase::Syncing);
    mesh.pump();
    ASSERT_EQ(isolated->driver->phase(), DriverPhase::Active);
    EXPECT_GE(isolated->runtime->consensus()->state().last_voted_view, certified_view);

    for (int i = 0; i < 200 && isolated->events.votes_sent.empty(); ++i) step(1);
    EXPECT_FALSE(isolated->events.votes_sent.empty())
        << "the rejoining member never voted on the certified chain";
    for (const auto& [vote, to] : isolated->events.votes_sent) {
        EXPECT_GT(vote.view, certified_view) << "a rejoining vote fell below the floor";
    }
    expect_no_conflicting_commits();
}

// --- 3. Duplicate node identity ---------------------------------------------

// A clone holding a member's epoch vote key is the strongest form of a shared
// identity: it can sign anything the member can. It must still weigh once.
TEST_F(AdversarialMesh, ClonedIdentityVotesCountOnceTowardQuorum) {
    bootstrap();
    run_until_committed(1);

    Node* victim = founders[4];
    ASSERT_TRUE(victim->runtime->consensus()->synced());
    const View view = victim->runtime->consensus()->current_view();
    const Digest target = filled(0x5A);
    const auto certifies_target = [&](const QuorumCertificate& qc) {
        return qc.proposal_digest == target;
    };

    victim->events.clear();
    const std::size_t equivocations_before =
        victim->runtime->consensus()->equivocation_evidence().size();

    for (std::size_t i = 0; i < 3; ++i) {
        const Vote vote = signed_vote(*founders[i], 1, 1, view, target);
        const auto message =
            founders[i]->router->compose(SecurityMessageKind::HotStuffVote, vote, 1);
        EXPECT_TRUE(send_envelope(*founders[i], *victim, message).delivered);
    }
    ASSERT_FALSE(std::any_of(victim->events.certificates.begin(),
                             victim->events.certificates.end(), certifies_target))
        << "three votes formed a certificate";

    // The clone signs the same block again at another height: fresh bytes, a
    // fresh envelope, and a signature that verifies.
    const Vote clone = signed_vote(*founders[0], 1, 2, view, target);
    const auto clone_message =
        founders[0]->router->compose(SecurityMessageKind::HotStuffVote, clone, 1);
    EXPECT_TRUE(send_envelope(*founders[0], *victim, clone_message).delivered);
    EXPECT_FALSE(std::any_of(victim->events.certificates.begin(),
                             victim->events.certificates.end(), certifies_target))
        << "a cloned identity supplied the fourth vote";

    // The clone signs a different block in the same view: objective evidence,
    // and still no second vote counted.
    const Vote conflicting = signed_vote(*founders[0], 1, 1, view, filled(0x5B));
    const auto conflicting_message =
        founders[0]->router->compose(SecurityMessageKind::HotStuffVote, conflicting, 1);
    const RouteResult result = send_envelope(*founders[0], *victim, conflicting_message);
    EXPECT_EQ(result.dropped, DropReason::ServiceRejected);
    ASSERT_TRUE(result.service_code.has_value());
    EXPECT_EQ(*result.service_code, static_cast<uint16_t>(ConsensusFailure::DuplicateSigner));
    EXPECT_GT(victim->runtime->consensus()->equivocation_evidence().size(),
              equivocations_before);

    // Positive control: a fourth distinct member forms the certificate at
    // exactly the quorum, with four distinct signers.
    const Vote fourth = signed_vote(*founders[3], 1, 1, view, target);
    const auto fourth_message =
        founders[3]->router->compose(SecurityMessageKind::HotStuffVote, fourth, 1);
    EXPECT_TRUE(send_envelope(*founders[3], *victim, fourth_message).delivered);
    const auto formed = std::find_if(victim->events.certificates.begin(),
                                     victim->events.certificates.end(), certifies_target);
    ASSERT_NE(formed, victim->events.certificates.end());
    std::set<NodeId> distinct;
    for (const auto& signer : formed->signers) distinct.insert(signer.node_id);
    EXPECT_EQ(distinct.size(), 4u);
    EXPECT_EQ(formed->signers.size(), 4u);
}

// --- 4. Stale epochs --------------------------------------------------------

TEST_F(AdversarialMesh, StaleEpochTrafficNeverReachesCurrentState) {
    bootstrap();
    run_until_committed(1);

    Node* victim = founders[0];
    Node* peer = founders[1];

    // Bootstrap authority ends at epoch 1: the genuine, correctly signed
    // certificate that founded the mesh is refused when replayed.
    auto stored = genesis_node->store->load_bootstrap();
    ASSERT_TRUE(std::holds_alternative<BootstrapCertificate>(stored));
    const auto replay = genesis_node->router->compose(
        SecurityMessageKind::BootstrapCertificate, std::get<BootstrapCertificate>(stored), 1);
    EXPECT_EQ(send_envelope(*genesis_node, *victim, replay).dropped,
              DropReason::EpochOutOfWindow);

    // An epoch-0 message is outside the window in the other direction.
    const Vote below = signed_vote(*peer, 1, 1, victim->runtime->consensus()->current_view(),
                                   filled(0x11));
    auto below_message = peer->router->compose(SecurityMessageKind::HotStuffVote, below, 0);
    EXPECT_EQ(send_envelope(*peer, *victim, below_message).dropped,
              DropReason::EpochOutOfWindow);

    // The epoch-1 material has to be captured now: activation destroys the
    // epoch-1 vote key on disk.
    const Vote stale = signed_vote(*peer, 1, 1, 1, filled(0x22));
    SyncResponse old_state;
    old_state.high_qc = signed_qc({founders[0], founders[1], founders[2], founders[3]}, 1, 1, 1,
                                  filled(0x33));

    advance_to_epoch_two();
    ASSERT_EQ(victim->driver->current_epoch(), 2u);
    EXPECT_FALSE(peer->store->load_vote_key(1, peer->id).has_value())
        << "the retired epoch vote key survived activation";
    const Height height_before = victim->driver->last_committed_height();
    const View view_before = victim->runtime->consensus()->current_view();
    const Digest high_qc_before = qc_digest(victim->runtime->consensus()->state().high_qc);

    // An epoch-1 vote, correctly signed by an epoch-1 vote key, in epoch 2.
    const auto stale_message = peer->router->compose(SecurityMessageKind::HotStuffVote, stale, 1);
    EXPECT_EQ(send_envelope(*peer, *victim, stale_message).dropped,
              DropReason::EpochOutOfWindow);

    // A whole epoch-1 sync response carrying a real epoch-1 certificate.
    const auto old_sync = peer->router->compose(SecurityMessageKind::SyncResponse, old_state, 1);
    EXPECT_EQ(send_envelope(*peer, *victim, old_sync).dropped, DropReason::EpochOutOfWindow);

    EXPECT_EQ(victim->driver->current_epoch(), 2u);
    EXPECT_EQ(victim->driver->last_committed_height(), height_before);
    EXPECT_EQ(victim->runtime->consensus()->current_view(), view_before);
    EXPECT_EQ(qc_digest(victim->runtime->consensus()->state().high_qc), high_qc_before);

    // Positive control: the same shape in the current epoch is not dropped by
    // the epoch gate; it reaches the consensus service.
    const Vote current = signed_vote(*peer, 2, 1, view_before, filled(0x44));
    const auto current_message =
        peer->router->compose(SecurityMessageKind::HotStuffVote, current, 2);
    EXPECT_TRUE(send_envelope(*peer, *victim, current_message).delivered);
}

// --- 5. Invalid quorum certificates -----------------------------------------

TEST_F(AdversarialMesh, InvalidCertificatesNeverFinishARestartSync) {
    bootstrap();
    run_until_committed(2);

    Node* victim = founders[4];
    Node* peer = founders[0];
    const QuorumCertificate genuine = peer->runtime->consensus()->state().high_qc;
    ASSERT_FALSE(genuine.signers.empty());

    restart_node(*victim);
    mesh.hold_rules[victim->id] = {SecurityMessageKind::SyncRequest};
    victim->events.clear();
    victim->driver->start(mesh.now_ms);
    ASSERT_EQ(victim->driver->phase(), DriverPhase::Syncing);

    const auto offer = [&](const QuorumCertificate& certificate, Node& from) {
        SyncResponse response;
        response.high_qc = certificate;
        return send_envelope(from, *victim,
                             from.router->compose(SecurityMessageKind::SyncResponse, response, 1));
    };
    const auto expect_refused = [&](const RouteResult& result, ConsensusFailure failure,
                                    const char* label) {
        EXPECT_EQ(result.dropped, DropReason::ServiceRejected) << label;
        ASSERT_TRUE(result.service_code.has_value()) << label;
        EXPECT_EQ(*result.service_code, static_cast<uint16_t>(failure)) << label;
    };

    QuorumCertificate forged = genuine;
    forged.signers[0].signature[0] ^= 0x01;
    expect_refused(offer(forged, *peer), ConsensusFailure::InvalidSignature, "forged signature");

    QuorumCertificate wrong_epoch = genuine;
    wrong_epoch.epoch = 2;
    expect_refused(offer(wrong_epoch, *peer), ConsensusFailure::EpochMismatch, "other epoch");

    QuorumCertificate wrong_ruleset = genuine;
    wrong_ruleset.consensus_ruleset =
        static_cast<ConsensusRulesetVersion>(constants::kConsensusRulesetVersion + 1);
    expect_refused(offer(wrong_ruleset, *peer), ConsensusFailure::RulesetMismatch,
                   "other ruleset");

    QuorumCertificate wrong_format = genuine;
    wrong_format.qc_format_version = constants::kQcFormatVersion + 1;
    expect_refused(offer(wrong_format, *peer), ConsensusFailure::FormatVersion, "other format");

    // A certificate for a view the chain never reached, signed by fewer than
    // the quorum. A far view buys nothing without the signatures.
    const QuorumCertificate thin_future =
        signed_qc({founders[0], founders[1], founders[2]}, 1, genuine.height + 1000,
                  genuine.view + 1000, filled(0x77));
    expect_refused(offer(thin_future, *peer), ConsensusFailure::InsufficientQuorum,
                   "future view below quorum");

    // Not one of them counted as an answer: the node is still unsynced.
    EXPECT_EQ(victim->driver->phase(), DriverPhase::Syncing);
    EXPECT_FALSE(victim->runtime->consensus()->synced());
    EXPECT_TRUE(victim->events.sync_certificates.empty());
    EXPECT_TRUE(victim->events.votes_sent.empty());

    // Positive control: the genuine certificate from two distinct members
    // finishes the sync through the very same path.
    EXPECT_TRUE(offer(genuine, *peer).delivered);
    EXPECT_TRUE(offer(genuine, *founders[1]).delivered);
    EXPECT_EQ(victim->driver->phase(), DriverPhase::Active);
    EXPECT_TRUE(victim->runtime->consensus()->synced());
    EXPECT_GE(victim->runtime->consensus()->state().last_voted_view, genuine.view);
}

TEST_F(AdversarialMesh, TheCertifiedFloorOnlyEverRises) {
    bootstrap();
    run_until_committed(2);

    Node* victim = founders[4];
    const QuorumCertificate genuine = founders[0]->runtime->consensus()->state().high_qc;
    ASSERT_GT(genuine.view, 1u);
    const View stored_view = victim->runtime->consensus()->state().last_voted_view;

    restart_node(*victim);
    mesh.hold_rules[victim->id] = {SecurityMessageKind::SyncRequest};
    victim->events.clear();
    victim->driver->start(mesh.now_ms);
    ASSERT_EQ(victim->driver->phase(), DriverPhase::Syncing);

    const auto offer = [&](const QuorumCertificate& certificate, Node& from) {
        SyncResponse response;
        response.high_qc = certificate;
        return send_envelope(from, *victim,
                             from.router->compose(SecurityMessageKind::SyncResponse, response, 1));
    };

    // A genuine but old certificate: valid, so it is accepted as an answer.
    const QuorumCertificate old_certificate =
        signed_qc({founders[0], founders[1], founders[2], founders[3]}, 1, 1, 1, filled(0x88));
    EXPECT_TRUE(offer(old_certificate, *founders[0]).delivered);
    EXPECT_TRUE(offer(genuine, *founders[1]).delivered);

    ASSERT_EQ(victim->driver->phase(), DriverPhase::Active);
    // The floor is the highest certified view seen, never the last one seen,
    // and never below what this node already voted.
    EXPECT_GE(victim->runtime->consensus()->state().last_voted_view, genuine.view);
    EXPECT_GE(victim->runtime->consensus()->state().last_voted_view, stored_view);
    EXPECT_GT(victim->runtime->consensus()->current_view(), old_certificate.view);
}

// --- 6. DKG participant failure ---------------------------------------------

TEST_F(AdversarialMesh, SilentDkgParticipantBlocksActivationUntilItSpeaks) {
    bootstrap();
    run_until_committed(1);
    const auto epoch_one_group = *founders[0]->runtime->authority().group_public_key();

    Node* silent = founders[4];
    mesh.hold_rules[silent->id] = {SecurityMessageKind::DkgBroadcast,
                                   SecurityMessageKind::DkgPairwise};

    prepare_handoff();
    for (Node* founder : founders) {
        ASSERT_NE(founder->runtime->epochs()->transition(), nullptr);
        ASSERT_EQ(founder->runtime->epochs()->transition()->to_epoch, 2u);
    }
    inject_final_verdicts();

    const auto finished_epoch_two = [](Node* node) {
        return std::find(node->events.dkg_complete.begin(), node->events.dkg_complete.end(),
                         EpochId{2}) != node->events.dkg_complete.end();
    };

    // Every other member is generating the authority key and waiting.
    step(60);
    for (Node* founder : founders) {
        const EpochTransition* transition = founder->runtime->epochs()->transition();
        ASSERT_NE(transition, nullptr);
        EXPECT_NE(transition->phase, EpochTransitionPhase::Ready)
            << "a half-formed epoch reached Ready";
        EXPECT_EQ(founder->driver->current_epoch(), 1u);
        EXPECT_EQ(*founder->runtime->authority().key_epoch(), 1u);
        EXPECT_EQ(*founder->runtime->authority().group_public_key(), epoch_one_group);
        EXPECT_FALSE(finished_epoch_two(founder));
    }
    // Positive control for liveness: epoch 1 keeps finalizing throughout.
    const Height committed = founders[0]->driver->last_committed_height();
    run_until_committed(committed + 1);
    EXPECT_EQ(founders[0]->driver->current_epoch(), 1u);

    // Positive control for the mechanism: the withheld packages alone complete
    // the DKG and the handoff activates.
    mesh.release_held();
    mesh.pump();
    for (Node* founder : founders) {
        EXPECT_TRUE(finished_epoch_two(founder));
        ASSERT_NE(founder->runtime->epochs()->transition(), nullptr);
        EXPECT_EQ(founder->runtime->epochs()->transition()->phase,
                  EpochTransitionPhase::Ready);
    }
    for (int i = 0; i < 300 && !all_at_epoch(2); ++i) step(1);
    ASSERT_TRUE(all_at_epoch(2));
    for (Node* founder : founders) {
        EXPECT_EQ(*founder->runtime->authority().key_epoch(), 2u);
        EXPECT_NE(*founder->runtime->authority().group_public_key(), epoch_one_group);
    }
    expect_no_conflicting_commits();
}

TEST_F(AdversarialMesh, InvalidDkgRoundOneDataNeverActivatesAnEpoch) {
    bootstrap();
    run_until_committed(1);
    const auto epoch_one_group = *founders[0]->runtime->authority().group_public_key();

    // One byte of the round-1 package, with every binding field intact: the
    // message passes the transport and the session and fails inside FROST.
    mesh.corrupt_rules[founders[4]->id] = {SecurityMessageKind::DkgBroadcast};

    prepare_handoff();
    inject_final_verdicts();
    step(20);

    bool reported = false;
    bool named_culprit = false;
    for (Node* founder : founders) {
        if (founder == founders[4]) continue;
        for (const auto& [failure, culprit] : founder->events.dkg_failures) {
            if (failure != DkgFailure::InvalidPackage && failure != DkgFailure::CryptoFailure) {
                continue;
            }
            reported = true;
            if (culprit.has_value()) named_culprit = true;
        }
    }
    EXPECT_TRUE(reported) << "an invalid round-1 package was not reported at all";
    // KNOWN GAP, documented rather than asserted away: FROST rejects the bad
    // package but does not say whose it was, so the driver aborts the whole
    // transition instead of replacing the one member that sent it.
    EXPECT_FALSE(named_culprit) << "the DKG now names a culprit; tighten this test";

    for (Node* founder : founders) {
        const EpochTransition* transition = founder->runtime->epochs()->transition();
        if (transition != nullptr) {
            EXPECT_NE(transition->phase, EpochTransitionPhase::Ready);
        }
        EXPECT_EQ(founder->driver->current_epoch(), 1u);
        EXPECT_EQ(*founder->runtime->authority().key_epoch(), 1u);
        EXPECT_EQ(*founder->runtime->authority().group_public_key(), epoch_one_group);
    }

    // Positive control: the current epoch is unharmed and keeps finalizing.
    const Height committed = founders[0]->driver->last_committed_height();
    run_until_committed(committed + 1);
    EXPECT_EQ(founders[0]->driver->current_epoch(), 1u);
    expect_no_conflicting_commits();
}

TEST_F(AdversarialMesh, TamperedDkgRoundTwoPackageNeverSplitsTheEpoch) {
    bootstrap();
    run_until_committed(1);
    const auto epoch_one_group = *founders[0]->runtime->authority().group_public_key();

    // The round-2 payload is sealed to its recipient, so tampering shows up as
    // a seal failure at the transport rather than as a DKG verdict. Only the
    // packages leaving this member are touched, so its own DKG still finishes
    // while nobody else's can.
    Node* tamperer = founders[4];
    mesh.corrupt_rules[tamperer->id] = {SecurityMessageKind::DkgPairwise};

    prepare_handoff();
    inject_final_verdicts();
    step(60);

    std::size_t seal_failures = 0;
    for (Node* founder : founders) seal_failures += founder->drops[DropReason::SealFailure];
    ASSERT_GT(seal_failures, 0u) << "the tampered packages never reached a participant";

    // The required property holds for the honest members: none of them adopts
    // a half-formed epoch, and each keeps the epoch-1 authority key.
    for (Node* founder : founders) {
        if (founder == tamperer) continue;
        const EpochTransition* transition = founder->runtime->epochs()->transition();
        ASSERT_NE(transition, nullptr);
        EXPECT_NE(transition->phase, EpochTransitionPhase::Ready);
        EXPECT_EQ(founder->driver->current_epoch(), 1u);
        EXPECT_EQ(*founder->runtime->authority().key_epoch(), 1u);
        EXPECT_EQ(*founder->runtime->authority().group_public_key(), epoch_one_group);
    }

    // Only the tamperer's own DKG could finish: it received every genuine
    // package while none of its own arrived intact.
    const auto finished_epoch_two = [](Node* node) {
        return std::find(node->events.dkg_complete.begin(), node->events.dkg_complete.end(),
                         EpochId{2}) != node->events.dkg_complete.end();
    };
    EXPECT_TRUE(finished_epoch_two(tamperer));
    for (Node* founder : founders) {
        if (founder != tamperer) EXPECT_FALSE(finished_epoch_two(founder));
    }

    // The member whose own DKG finished reaches Ready alone. It must NOT be
    // able to rotate on that: a proposal carries its handoff as an opaque
    // digest, and a replica that cannot match it against a transition of its
    // own refuses to vote. Without that rule the honest four would authorize a
    // handoff only the proposer understood, and the mesh would split across two
    // epochs. Run well past the point where a lone rotation used to happen.
    for (int i = 0; i < 200; ++i) step(1);
    EXPECT_EQ(tamperer->driver->current_epoch(), 1u)
        << "a lone Ready member rotated by itself and split the mesh";
    EXPECT_EQ(*tamperer->runtime->authority().key_epoch(), 1u);
    EXPECT_EQ(*tamperer->runtime->authority().group_public_key(), epoch_one_group);

    // Every member is still in the same epoch under the same authority key.
    for (Node* founder : founders) {
        EXPECT_EQ(founder->driver->current_epoch(), 1u);
        EXPECT_EQ(*founder->runtime->authority().key_epoch(), 1u);
        EXPECT_EQ(*founder->runtime->authority().group_public_key(), epoch_one_group);
    }
    expect_no_conflicting_commits();

    // Positive control: the four members left in epoch 1 are exactly a quorum
    // and keep finalizing under the epoch-1 authority key.
    std::vector<Node*> remaining;
    for (Node* founder : founders) {
        if (founder != tamperer) remaining.push_back(founder);
    }
    const Height committed = remaining[0]->driver->last_committed_height();
    bool advanced = false;
    for (int i = 0; i < 400 && !advanced; ++i) {
        step(1);
        advanced = std::all_of(remaining.begin(), remaining.end(), [&](Node* f) {
            return f->driver->last_committed_height() > committed;
        });
    }
    EXPECT_TRUE(advanced) << "the epoch-1 quorum stopped finalizing";
    expect_no_conflicting_commits();
}

// --- 7. FROST commitment replay ---------------------------------------------

// Helper state for a signing round driven over the wire.
struct SigningRound {
    SigningSessionId id = 0;
    std::vector<FrostCommitmentMessage> commitments;
};

TEST_F(AdversarialMesh, ReplayedNonceCommitmentProducesNoSecondShare) {
    bootstrap();
    run_until_committed(2);

    const QuorumCertificate certificate = founders[0]->runtime->consensus()->state().high_qc;
    ASSERT_FALSE(certificate.signers.empty());

    ConsensusCommit commit{};
    commit.epoch = 1;
    commit.height = certificate.height;
    commit.view = certificate.view;
    commit.proposal_digest = certificate.proposal_digest;
    commit.proposed_state_root = filled(0x42);
    commit.qc_digest = qc_digest(certificate);
    const AuthorityObject object =
        make_authority_object(commit, network, AuthorityOperation::EpochTransition, 1,
                              filled(0x41));
    std::vector<NodeId> signers;
    for (Node* founder : founders) signers.push_back(founder->id);
    std::sort(signers.begin(), signers.end());

    const auto open_round = [&]() {
        SigningRound round;
        auto start = founders[0]->runtime->authority().start_signing(object, certificate, signers);
        EXPECT_EQ(start.failure, SigningFailure::None);
        EXPECT_TRUE(start.session_id.has_value());
        round.id = start.session_id.value_or(0);
        round.commitments.push_back(*start.commitment);
        for (std::size_t i = 1; i < kFounders; ++i) {
            auto join = founders[i]->runtime->authority().join_signing(round.id, object,
                                                                       certificate, signers);
            EXPECT_EQ(join.failure, SigningFailure::None);
            round.commitments.push_back(*join.commitment);
        }
        return round;
    };

    // Round one runs to completion over the wire: this is the shape a replay
    // has to be measured against.
    const SigningRound first = open_round();
    for (std::size_t i = 0; i < kFounders; ++i) {
        founders[i]->router->broadcast(founders[i]->router->compose(
            SecurityMessageKind::FrostCommitment, first.commitments[i], 1));
    }
    mesh.pump();
    for (Node* founder : founders) {
        ASSERT_EQ(founder->events.signatures.size(), 1u);
        EXPECT_TRUE(nexus::crypto::FrostProvider::verify(
            *founder->runtime->authority().group_public_key(),
            authority_object_digest(object), founder->events.signatures[0].signature));
    }

    const SigningRound second = open_round();
    Node* honest = founders[1];
    Node* attacked = founders[3];
    const std::size_t honest_before =
        sent_count(*honest, SecurityMessageKind::FrostSignatureShare);
    const std::size_t attacked_before =
        sent_count(*attacked, SecurityMessageKind::FrostSignatureShare);

    // Positive control: a full set of fresh commitments yields exactly one
    // share, sent to every other signer.
    for (std::size_t i = 0; i < kFounders; ++i) {
        if (founders[i] == honest) continue;
        const auto message = founders[i]->router->compose(SecurityMessageKind::FrostCommitment,
                                                          second.commitments[i], 1);
        EXPECT_TRUE(send_envelope(*founders[i], *honest, message).delivered);
    }
    EXPECT_EQ(sent_count(*honest, SecurityMessageKind::FrostSignatureShare) - honest_before,
              kFounders - 1);

    // The attacked node gets three fresh commitments and then, in place of the
    // fourth, the commitment its owner already used in the completed round.
    for (std::size_t i = 0; i < kFounders; ++i) {
        if (founders[i] == attacked || founders[i] == founders[2]) continue;
        const auto message = founders[i]->router->compose(SecurityMessageKind::FrostCommitment,
                                                          second.commitments[i], 1);
        EXPECT_TRUE(send_envelope(*founders[i], *attacked, message).delivered);
    }
    EXPECT_EQ(sent_count(*attacked, SecurityMessageKind::FrostSignatureShare), attacked_before);

    FrostCommitmentMessage replayed = first.commitments[2];
    replayed.header.session_id = second.id;
    const auto replay_message =
        founders[2]->router->compose(SecurityMessageKind::FrostCommitment, replayed, 1);
    const RouteResult result = send_envelope(*founders[2], *attacked, replay_message);
    EXPECT_EQ(result.dropped, DropReason::ServiceRejected);
    ASSERT_TRUE(result.service_code.has_value());
    EXPECT_EQ(*result.service_code, static_cast<uint16_t>(SigningFailure::CommitmentReplayed));

    // No share left the node under the reused nonce.
    EXPECT_EQ(sent_count(*attacked, SecurityMessageKind::FrostSignatureShare), attacked_before);
    EXPECT_TRUE(attacked->runtime->commitments().commitment_exists(1, 1,
                                                                    replayed.commitment));
}

// --- 8. Retired epoch authority ---------------------------------------------

TEST_F(AdversarialMesh, RetiredEpochAuthorityCannotAuthorizeCurrentState) {
    bootstrap();
    run_until_committed(2);

    const auto epoch_one_group = *founders[0]->runtime->authority().group_public_key();
    const QuorumCertificate epoch_one_qc = founders[0]->runtime->consensus()->state().high_qc;
    ASSERT_FALSE(epoch_one_qc.signers.empty());

    ConsensusCommit commit{};
    commit.epoch = 1;
    commit.height = epoch_one_qc.height;
    commit.view = epoch_one_qc.view;
    commit.proposal_digest = epoch_one_qc.proposal_digest;
    commit.proposed_state_root = filled(0x12);
    commit.qc_digest = qc_digest(epoch_one_qc);
    const AuthorityObject epoch_one_object =
        make_authority_object(commit, network, AuthorityOperation::EpochTransition, 1,
                              filled(0x11));

    std::vector<NodeId> signers;
    for (Node* founder : founders) signers.push_back(founder->id);
    std::sort(signers.begin(), signers.end());

    auto start = founders[0]->runtime->authority().start_signing(epoch_one_object, epoch_one_qc,
                                                                  signers);
    ASSERT_EQ(start.failure, SigningFailure::None);
    std::vector<FrostCommitmentMessage> commitments{*start.commitment};
    for (std::size_t i = 1; i < kFounders; ++i) {
        auto join = founders[i]->runtime->authority().join_signing(*start.session_id,
                                                                    epoch_one_object,
                                                                    epoch_one_qc, signers);
        ASSERT_EQ(join.failure, SigningFailure::None);
        commitments.push_back(*join.commitment);
    }
    for (std::size_t i = 0; i < kFounders; ++i) {
        founders[i]->router->broadcast(founders[i]->router->compose(
            SecurityMessageKind::FrostCommitment, commitments[i], 1));
    }
    mesh.pump();
    ASSERT_EQ(founders[0]->events.signatures.size(), 1u);
    const auto epoch_one_signature = founders[0]->events.signatures[0].signature;
    const Digest epoch_one_digest = authority_object_digest(epoch_one_object);
    ASSERT_TRUE(nexus::crypto::FrostProvider::verify(epoch_one_group, epoch_one_digest,
                                                     epoch_one_signature));

    advance_to_epoch_two();
    const auto epoch_two_group = *founders[0]->runtime->authority().group_public_key();
    EXPECT_EQ(*founders[0]->runtime->authority().key_epoch(), 2u);
    EXPECT_NE(epoch_two_group, epoch_one_group);

    // The old signature still proves what it always proved, and nothing more:
    // it does not verify under the epoch now in force.
    EXPECT_TRUE(nexus::crypto::FrostProvider::verify(epoch_one_group, epoch_one_digest,
                                                     epoch_one_signature));
    EXPECT_FALSE(nexus::crypto::FrostProvider::verify(epoch_two_group, epoch_one_digest,
                                                      epoch_one_signature));

    // The epoch-2 key refuses to sign an epoch-1 object at all.
    EXPECT_EQ(founders[0]
                  ->runtime->authority()
                  .start_signing(epoch_one_object, epoch_one_qc, signers)
                  .failure,
              SigningFailure::WrongEpoch);

    // And an epoch-2 object justified by the retired epoch-1 certificate is
    // refused on the certificate, not merely on the object header.
    run_until_committed(founders[0]->driver->last_committed_height() + 2, 400);
    const QuorumCertificate epoch_two_qc = founders[0]->runtime->consensus()->state().high_qc;
    ASSERT_EQ(epoch_two_qc.epoch, 2u);
    ASSERT_FALSE(epoch_two_qc.signers.empty());

    AuthorityObject stale_certificate_object = epoch_one_object;
    stale_certificate_object.epoch = 2;
    stale_certificate_object.key_generation = 2;
    EXPECT_EQ(founders[0]
                  ->runtime->authority()
                  .start_signing(stale_certificate_object, epoch_one_qc, signers)
                  .failure,
              SigningFailure::CertificateInvalid);

    // Positive control: the epoch-2 key signs epoch-2 state through the very
    // same entry point.
    ConsensusCommit next{};
    next.epoch = 2;
    next.height = epoch_two_qc.height;
    next.view = epoch_two_qc.view;
    next.proposal_digest = epoch_two_qc.proposal_digest;
    next.proposed_state_root = filled(0x22);
    next.qc_digest = qc_digest(epoch_two_qc);
    const AuthorityObject epoch_two_object =
        make_authority_object(next, network, AuthorityOperation::EpochTransition, 2,
                              filled(0x21));
    EXPECT_EQ(founders[0]
                  ->runtime->authority()
                  .start_signing(epoch_two_object, epoch_two_qc, signers)
                  .failure,
              SigningFailure::None);

    // Both authority keys are on record, one per epoch.
    const auto history = founders[0]->store->load_authority_history();
    ASSERT_TRUE(std::holds_alternative<std::vector<EpochAuthorityRecord>>(history));
    const auto& records = std::get<std::vector<EpochAuthorityRecord>>(history);
    ASSERT_EQ(records.size(), 2u);
    EXPECT_EQ(records[0].group_public_key, epoch_one_group);
    EXPECT_EQ(records[1].group_public_key, epoch_two_group);
}

// --- 9. Attestation replay --------------------------------------------------

TEST_F(AdversarialMesh, AttestationEvidenceAnswersOneChallengeForOneNode) {
    bootstrap();
    run_until_committed(1);

    Node* verifier = founders[0];
    Node* prover = founders[1];
    Node* other_verifier = founders[2];

    const auto build_evidence = [&](const AttestationChallenge& challenge, Node& signer) {
        AttestationEvidence evidence;
        evidence.network_id = challenge.network_id;
        evidence.challenge_digest = challenge_digest(challenge);
        evidence.node_id = challenge.node_id;
        evidence.incarnation = challenge.incarnation;
        evidence.epoch = challenge.epoch;
        evidence.security_ruleset = constants::kSecurityRulesetVersion;
        evidence.consensus_ruleset = constants::kConsensusRulesetVersion;
        evidence.profile_id = challenge.profile_id;
        evidence.profile_ruleset = challenge.profile_ruleset;
        evidence.epoch_vote_key = *signer.driver->vote_key_for_epoch(1);
        evidence.platform.hcl_blob.assign(64, 0xA5);
        evidence.platform.tpms_attest.assign(48, 0x5A);
        evidence.platform.tpm_signature.assign(32, 0x3C);
        evidence.platform.pcr_values.assign(32, 0xC3);
        evidence.platform.ima_log = "10 aa ima-ng sha256:bb /opt/nexus\n";
        evidence.platform.binary_path = "/opt/nexus";
        evidence.platform.binary_sha256 = std::string(64, 'b');
        const Digest digest = evidence_signing_digest(evidence);
        crypto_sign_detached(evidence.identity_signature.data(), nullptr, digest.data(),
                             digest.size(), signer.identity.private_key.data());
        return evidence;
    };

    auto first = verifier->runtime->attestation().create_challenge(
        prover->id, prover->identity.public_key, 1, 1);
    ASSERT_TRUE(first.has_value());
    const AttestationEvidence answer = build_evidence(*first, *prover);

    // Positive control: the bundle clears the challenge, identity, incarnation
    // and identity-signature checks. A non-empty evidence digest is only ever
    // produced past all four; only the platform chain is left to fail.
    const AttestationVerdict accepted =
        verifier->runtime->attestation().receive_evidence(answer);
    EXPECT_EQ(accepted.node_id, prover->id);
    EXPECT_EQ(accepted.epoch, 1u);
    EXPECT_NE(accepted.evidence_digest, Digest{});
    EXPECT_NE(accepted.failure, AttestationFailure::ChallengeMismatch);
    EXPECT_NE(accepted.failure, AttestationFailure::IdentityMismatch);
    EXPECT_NE(accepted.failure, AttestationFailure::IdentitySignatureInvalid);
    EXPECT_NE(accepted.failure, AttestationFailure::ProfileIncomplete);

    // The same bundle a second time: the challenge it answered is spent.
    const AttestationVerdict replayed =
        verifier->runtime->attestation().receive_evidence(answer);
    EXPECT_FALSE(replayed.passed);
    EXPECT_EQ(replayed.failure, AttestationFailure::ChallengeMismatch);
    EXPECT_EQ(replayed.evidence_digest, Digest{});

    // Another verifier that never issued this challenge cannot be answered.
    const AttestationVerdict elsewhere =
        other_verifier->runtime->attestation().receive_evidence(answer);
    EXPECT_FALSE(elsewhere.passed);
    EXPECT_EQ(elsewhere.failure, AttestationFailure::ChallengeMismatch);

    // A later challenge carries a fresh nonce, so the old bundle cannot answer
    // it either.
    auto second = verifier->runtime->attestation().create_challenge(
        prover->id, prover->identity.public_key, 1, 1);
    ASSERT_TRUE(second.has_value());
    ASSERT_NE(challenge_digest(*second), challenge_digest(*first));
    const AttestationVerdict stale = verifier->runtime->attestation().receive_evidence(answer);
    EXPECT_FALSE(stale.passed);
    EXPECT_EQ(stale.failure, AttestationFailure::ChallengeMismatch);
    EXPECT_EQ(stale.evidence_digest, Digest{});

    // The replay above answered nothing, so it consumed nothing. The honest
    // answer to the live challenge still finds it outstanding — otherwise any
    // peer that knows a node ID could deny that node attestation by replaying
    // one stale bundle per challenge.
    const AttestationEvidence honest_late = build_evidence(*second, *prover);
    const AttestationVerdict survived =
        verifier->runtime->attestation().receive_evidence(honest_late);
    EXPECT_NE(survived.failure, AttestationFailure::ChallengeMismatch);
    EXPECT_NE(survived.evidence_digest, Digest{});

    // Positive control: a bundle built for a challenge that no replay touched
    // clears the challenge, identity, incarnation and signature checks again.
    auto third = verifier->runtime->attestation().create_challenge(
        prover->id, prover->identity.public_key, 1, 1);
    ASSERT_TRUE(third.has_value());
    const AttestationVerdict current =
        verifier->runtime->attestation().receive_evidence(build_evidence(*third, *prover));
    EXPECT_NE(current.evidence_digest, Digest{});
    EXPECT_NE(current.failure, AttestationFailure::ChallengeMismatch);
    EXPECT_NE(current.failure, AttestationFailure::IdentityMismatch);
    EXPECT_NE(current.failure, AttestationFailure::IdentitySignatureInvalid);

    // Over the wire, evidence claiming another node never reaches the verifier.
    // A fresh prover keeps this clear of the per-epoch challenge budget.
    Node* second_prover = founders[3];
    auto wire_challenge = verifier->runtime->attestation().create_challenge(
        second_prover->id, second_prover->identity.public_key, 1, 1);
    ASSERT_TRUE(wire_challenge.has_value());
    AttestationEvidence relabelled = build_evidence(*wire_challenge, *second_prover);
    relabelled.node_id = founders[2]->id;
    const auto relabelled_message =
        second_prover->router->compose(SecurityMessageKind::AttestationEvidence, relabelled, 1);
    verifier->events.clear();
    EXPECT_EQ(send_envelope(*second_prover, *verifier, relabelled_message).dropped,
              DropReason::SenderMismatch);
    EXPECT_TRUE(verifier->events.verdicts.empty());

    // Positive control: the identical envelope naming its own sender is
    // delivered and produces a verdict for that sender.
    const AttestationEvidence own = build_evidence(*wire_challenge, *second_prover);
    const auto own_message =
        second_prover->router->compose(SecurityMessageKind::AttestationEvidence, own, 1);
    EXPECT_TRUE(send_envelope(*second_prover, *verifier, own_message).delivered);
    ASSERT_EQ(verifier->events.verdicts.size(), 1u);
    EXPECT_EQ(verifier->events.verdicts[0].node_id, second_prover->id);
    EXPECT_NE(verifier->events.verdicts[0].evidence_digest, Digest{});
}

}  // namespace
