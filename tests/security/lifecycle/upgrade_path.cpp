// In-place release updates on the memory mesh (Design-Auto-Update Phases 2,
// 3 and 5).
//
// Every server runs the real driver, router, HotStuff, release chain, and
// upgrade service over encoded envelopes. A process restart rebuilds a node
// from its directories with a different packaged approval, as an updater swap
// would. The positive attestation path needs a confidential VM, so the
// UpgradeHealth verdicts are injected into the challenging witness, with the
// measured hashes of the release the subject runs.

#include "support/lifecycle_mesh.hpp"
#include "support/release_fixture.hpp"

#include <LemonadeNexus/Security/Attestation/AttestationVerifier.hpp>
#include <LemonadeNexus/Security/Attestation/ReleaseChain.hpp>
#include <LemonadeNexus/Security/Upgrade/RolloutProof.hpp>
#include <LemonadeNexus/Security/Upgrade/UpgradeService.hpp>

#include <fstream>

namespace lifecycle_test {
namespace {

using nexus_test::release_hash;
using nexus_test::ReleaseSigner;

constexpr uint64_t kWallBase = 1'800'000'000'000ULL;
constexpr uint64_t kN = 2026102401;
constexpr uint64_t kN1 = 2026102501;

struct UpgradeStack {
    std::optional<ReleaseApprovalBundleV1> installed;
    std::unique_ptr<ReleaseChain> chain;
    std::unique_ptr<UpgradeService> service;
};

class UpgradePath : public DriverMeshBase {
protected:
    void SetUp() override {
        DriverMeshBase::SetUp();
        signer.emplace(genesis_node->identity.public_key, genesis_node->identity.private_key);
        ready_ = true;
        for (Node* node : servers()) {
            stacks[node->id].installed = initial_installed();
            node->release_approval_digest = founding_digest();
            node->release_commitment = [this, id = node->id](const Digest& committed) {
                const auto it = stacks.find(id);
                return it != stacks.end() && it->second.chain &&
                       it->second.chain->bind_commitment(committed);
            };
            restart_node(*node);
        }
        // Genesis composes the founding, so it names the same approval.
        genesis_node->release_approval_digest = founding_digest();
        restart_node(*genesis_node);
    }

    void TearDown() override {
        for (auto& [id, stack] : stacks) stack.service.reset();
        DriverMeshBase::TearDown();
    }

    /// The first server that holds a complete rollout proof.
    std::optional<RolloutProof> rollout_proof_from_any() {
        for (Node* node : servers()) {
            if (auto proof = upgrade(node).rollout_proof(genesis_node->identity.public_key)) {
                return proof;
            }
        }
        return std::nullopt;
    }

    /// The packaged approval every server starts with, and the approval the
    /// founding commits. A fixture variant overrides both.
    virtual std::optional<ReleaseApprovalBundleV1> initial_installed() {
        return signer->approval(kN);
    }
    virtual Digest founding_digest() {
        return release_approval_digest(signer->approval(kN).approval);
    }

    void on_node_built(Node& node) override {
        if (!ready_ || &node == genesis_node) return;
        build_stack(node);
    }

    /// (Re)builds the release chain and the upgrade service from the node's
    /// directories and its packaged approval.
    void build_stack(Node& node) {
        auto& stack = stacks[node.id];
        stack.service.reset();
        stack.chain = std::make_unique<ReleaseChain>(node.dir / "release",
                                                     genesis_node->identity.public_key, network);
        (void)stack.chain->load(stack.installed);
        install_profile(node);
        UpgradeServiceConfig config;
        config.self = node.id;
        config.identity = node.identity;
        config.network_id = network;
        config.directory = node.dir / "upgrade";
        config.wall_clock_ms = [this] { return kWallBase + mesh.now_ms; };
        config.running_release = stack.installed ? stack.installed->approval.release_number : 0;
        config.attestable = [] { return true; };
        stack.service = std::make_unique<UpgradeService>(std::move(config), *node.driver,
                                                         *node.router, *node.runtime,
                                                         stack.chain.get());
        stack.service->set_release_adopted_callback(
            [this, &node](const ReleaseApprovalBundleV1&) { install_profile(node); });
        stack.service->set_release_floor_callback([this, &node] { install_profile(node); });
        stack.service->attach();
        EXPECT_TRUE(stack.service->start(mesh.now_ms));
    }

    void install_profile(Node& node) {
        const auto& chain = *stacks.at(node.id).chain;
        node.runtime->attestation().replace_profile(
            chain.current() ? profile_from_release_approval(chain.current()->approval)
                            : linux_attestation_profile_v3_svsm_release());
    }

    void on_tick(Node& node) override {
        if (auto it = stacks.find(node.id); it != stacks.end() && it->second.service) {
            it->second.service->tick(mesh.now_ms);
        }
    }

    [[nodiscard]] std::vector<Node*> servers() const {
        std::vector<Node*> out(founders.begin(), founders.end());
        out.insert(out.end(), reserves.begin(), reserves.end());
        return out;
    }

    [[nodiscard]] std::vector<Node*> online_servers() const {
        std::vector<Node*> out;
        for (Node* node : servers()) {
            if (!mesh.offline.contains(node->id)) out.push_back(node);
        }
        return out;
    }

    UpgradeService& upgrade(const Node* node) { return *stacks.at(node->id).service; }
    ReleaseChain& chain(const Node* node) { return *stacks.at(node->id).chain; }

    /// The hashes the node's packaged release measures as.
    [[nodiscard]] std::vector<ImaCheckpointPath> measured(const Node& node) const {
        const auto number = stacks.at(node.id).installed->approval.release_number;
        return {{"/usr/bin/lemonade-nexus", release_hash(number, 'n')},
                {"/usr/bin/nexus-attestd", release_hash(number, 'a')}};
    }

    /// Answers every captured UpgradeHealth challenge the way the subject's
    /// collector and the witness's verifier would.
    void answer_upgrade_challenges() {
        auto pending = std::move(mesh.captured_upgrade_challenges);
        mesh.captured_upgrade_challenges.clear();
        for (const auto& [witness, challenge] : pending) {
            if (mesh.offline.contains(challenge.node_id) || mesh.offline.contains(witness)) {
                continue;
            }
            AttestationVerdict verdict = passing_verdict(challenge.node_id, challenge.epoch,
                                                         upgrade_round_++, challenge.incarnation);
            verdict.purpose = challenge.purpose;
            verdict.context_digest = challenge.context_digest;
            verdict.measured_paths = measured(*mesh.nodes.at(challenge.node_id));
            mesh.nodes.at(witness)->driver->on_attestation_verdict(
                verdict, evidence_for(challenge.node_id, {}));
        }
        mesh.pump();
    }

    void upgrade_step(int count = 1) {
        for (int i = 0; i < count; ++i) {
            mesh.now_ms += 200;
            for (Node* node : online_servers()) {
                node->driver->tick(mesh.now_ms);
                on_tick(*node);
            }
            mesh.pump();
            answer_upgrade_challenges();
        }
    }

    bool run_until(const std::function<bool()>& done, int max_steps = 1500) {
        for (int i = 0; i < max_steps; ++i) {
            if (done()) return true;
            upgrade_step();
        }
        return done();
    }

    /// The updater's swap: the node restarts with release `number` packaged.
    void restart_with(Node& node, uint64_t number, uint64_t previous) {
        stacks.at(node.id).installed = signer->approval(number, previous);
        restart_node(node);
        node.driver->start(mesh.now_ms);
    }

    /// The updater's swap for a Tier 1 member, restarting the release chain
    /// and the upgrade service but not consensus. Sequential full restarts are
    /// covered by DriverMesh.SequentialRestartsKeepEveryMemberCommitting, and
    /// ARestartWithANewerApprovalKeepsTheEpochChainAndTheTier1Role covers the
    /// full restart of one member.
    void swap_upgrade_stack(Node& node, uint64_t number, uint64_t previous) {
        stacks.at(node.id).installed = signer->approval(number, previous);
        build_stack(node);
    }

    [[nodiscard]] const UpgradeChainState& finalized() { return upgrade(founders.front()).state(); }

    std::optional<ReleaseSigner> signer;
    std::map<NodeId, UpgradeStack> stacks;
    bool ready_ = false;
    uint8_t upgrade_round_ = 0x60;
};

TEST_F(UpgradePath, ARestartWithANewerApprovalKeepsTheEpochChainAndTheTier1Role) {
    bootstrap();
    ASSERT_FALSE(HasFatalFailure());
    Node* node = founders.front();
    const auto key_before = node->runtime->epochs()->current().authority_public_key;

    restart_with(*node, kN1, kN);
    EXPECT_NE(node->driver->phase(), DriverPhase::Failed);
    EXPECT_EQ(chain(node).highest_release_number(), kN1);
    ASSERT_TRUE(run_until([&] { return node->driver->phase() == DriverPhase::Active; }));
    EXPECT_EQ(node->driver->current_epoch(), 1u);
    EXPECT_TRUE(node->driver->is_tier1_member());
    EXPECT_EQ(node->runtime->epochs()->current().authority_public_key, key_before);

    // The restarted member votes again: the chain keeps committing with it.
    const Height before = node->driver->last_committed_height();
    advance_commit(founders);
    advance_commit(founders);
    EXPECT_GT(node->driver->last_committed_height(), before);

    // A second restart on the same release still binds the founding
    // commitment; the release number never drops back to N.
    restart_with(*node, kN1, kN);
    EXPECT_NE(node->driver->phase(), DriverPhase::Failed);
    EXPECT_EQ(chain(node).highest_release_number(), kN1);
}

TEST_F(UpgradePath, NodesOnNAndNPlusOneAttestEachOther) {
    bootstrap();
    ASSERT_FALSE(HasFatalFailure());
    // Let the reserves walk to the verified authority so they report status.
    ASSERT_TRUE(run_until([&] {
        return std::all_of(reserves.begin(), reserves.end(),
                           [](Node* r) { return r->driver->verified_authority() != nullptr; });
    }));
    restart_with(*founders.front(), kN1, kN);
    const auto all = servers();
    ASSERT_TRUE(run_until([&] {
        return std::all_of(all.begin(), all.end(), [&](Node* node) {
            return chain(node).highest_release_number() == kN1;
        });
    })) << "the newer approval did not spread over the backbone";

    for (Node* node : servers()) {
        const auto& profile = node->runtime->attestation().profile();
        for (const char tag : {'n', 'a'}) {
            const std::string path =
                tag == 'n' ? "/usr/bin/lemonade-nexus" : "/usr/bin/nexus-attestd";
            EXPECT_TRUE(path_approved(profile, path, release_hash(kN1, tag)));
            EXPECT_TRUE(path_approved(profile, path, release_hash(kN, tag)));
            EXPECT_FALSE(path_approved(profile, path, release_hash(kN - 100, tag)));
        }
    }
}

TEST_F(UpgradePath, TurnsRunOneAtATimeTier2FirstAndOnlyAfterWitnesses) {
    bootstrap();
    ASSERT_FALSE(HasFatalFailure());
    ASSERT_TRUE(run_until([&] {
        return std::all_of(reserves.begin(), reserves.end(),
                           [](Node* r) { return r->driver->verified_authority() != nullptr; });
    }));
    ASSERT_EQ(upgrade(founders.front()).offer_approval(
                  release_approval_bundle_json(signer->approval(kN1, kN))),
              ReleaseOfferResult::Adopted);
    ASSERT_TRUE(run_until([&] { return finalized().release_number == kN1; }))
        << "no rollout started";
    // The release guard sees the rollout open.
    {
        const auto proof = rollout_proof_from_any();
        ASSERT_TRUE(proof) << "no server holds a rollout proof";
        std::string error;
        const auto rollout = verify_rollout_proof(*proof, network, error);
        ASSERT_TRUE(rollout) << error;
        std::string reason;
        EXPECT_FALSE(rollout_complete(*rollout, kN1, reason));
        EXPECT_NE(reason.find("open"), std::string::npos) << reason;
    }
    const auto order = finalized().order;
    ASSERT_EQ(order.size(), servers().size());
    EXPECT_FALSE(order[0].tier1);
    EXPECT_FALSE(order[1].tier1);
    EXPECT_TRUE(order[2].tier1);

    // Every updater stages at once: two (in fact seven) servers ask to
    // restart at the same time. Only the finalized next one may.
    for (Node* node : servers()) upgrade(node).stage(kN1);
    std::vector<NodeId> restarted;
    ASSERT_TRUE(run_until(
        [&] {
            // A server that already restarted can still read Go from its own
            // lagging copy of the records until the Upgraded record reaches
            // it; its updater has nothing left to install. Count the others.
            std::vector<Node*> go;
            for (Node* node : servers()) {
                if (upgrade(node).gate(kN1) == UpgradeGate::Go &&
                    std::find(restarted.begin(), restarted.end(), node->id) ==
                        restarted.end()) {
                    go.push_back(node);
                }
            }
            EXPECT_LE(go.size(), 1u) << "two servers held a turn at once";
            for (Node* node : go) {
                restarted.push_back(node->id);
                if (node->driver->is_tier1_member()) {
                    swap_upgrade_stack(*node, kN1, kN);
                } else {
                    restart_with(*node, kN1, kN);
                }
                upgrade(node).stage(kN1);
            }
            return finalized().complete();
        },
        6000))
        << "rollout incomplete: " << finalized().upgraded.size() << " of " << order.size();
    ASSERT_EQ(restarted.size(), order.size());
    for (std::size_t i = 0; i < order.size(); ++i) {
        EXPECT_EQ(restarted[i], order[i].node) << "turn " << i << " out of order";
    }
    for (Node* node : servers()) {
        EXPECT_EQ(upgrade(node).gate(kN1), UpgradeGate::Done);
        EXPECT_NE(node->driver->phase(), DriverPhase::Failed);
    }
    // The Tier 1 set and epoch survived the rollout.
    for (Node* node : founders) EXPECT_TRUE(node->driver->is_tier1_member());

    // The release guard: a proof from finalized state shows the rollout
    // complete, verified from the network id alone.
    const auto proof = rollout_proof_from_any();
    ASSERT_TRUE(proof);
    std::string error;
    const auto rollout = verify_rollout_proof(*proof, network, error);
    ASSERT_TRUE(rollout) << error;
    std::string reason;
    EXPECT_TRUE(rollout_complete(*rollout, kN1, reason)) << reason;
    EXPECT_FALSE(rollout_complete(*rollout, kN1 + 1, reason)) << "another release";
    // After a completed rollout the next approval overlaps with N+1 only.
    const auto completed = signer->approval(kN1, kN);
    EXPECT_EQ(previous_rollout_state(*rollout, kN1, &completed, reason),
              PreviousRollout::Complete)
        << reason;
    EXPECT_TRUE(release_follows_rollout(*rollout, kN1, completed,
                                        signer->approval(kN1 + 1, kN1).approval, reason))
        << reason;
    EXPECT_FALSE(release_follows_rollout(
        *rollout, kN1, completed,
        signer->approval(kN1 + 1, std::vector<uint64_t>{kN1, kN}).approval, reason))
        << "a completed rollout drops N";
    // The JSON form round-trips.
    const auto parsed = parse_rollout_proof(rollout_proof_json(*proof), error);
    ASSERT_TRUE(parsed) << error;
    EXPECT_TRUE(verify_rollout_proof(*parsed, network, error)) << error;
    // A restarted server kept its commit proofs on disk and can still prove it.
    ASSERT_TRUE(run_until([&] {
        Node* restarted_tier2 = mesh.nodes.at(order.front().node);
        const auto own = upgrade(restarted_tier2).rollout_proof(genesis_node->identity.public_key);
        std::string why;
        const auto verified = own ? verify_rollout_proof(*own, network, why) : std::nullopt;
        std::string done;
        return verified && rollout_complete(*verified, kN1, done);
    }));

    // Rejections: each altered proof fails closed.
    {   // Another network.
        NetworkId other = network;
        other[0] ^= 1;
        EXPECT_FALSE(verify_rollout_proof(*proof, other, error));
    }
    {   // A Genesis key that does not derive the network id.
        auto forged = *proof;
        forged.genesis_public_key[0] ^= 1;
        EXPECT_FALSE(verify_rollout_proof(forged, network, error));
    }
    {   // A record byte changed after finalization.
        auto forged = *proof;
        forged.records.back().back() ^= 1;
        EXPECT_FALSE(verify_rollout_proof(forged, network, error));
    }
    {   // A record removed: the chain no longer links, or no longer completes.
        auto forged = *proof;
        forged.records.erase(forged.records.begin() + 1);
        const auto gapped = verify_rollout_proof(forged, network, error);
        EXPECT_TRUE(!gapped || !rollout_complete(*gapped, kN1, reason));
    }
    {   // The records cut short of completion.
        auto forged = *proof;
        forged.records.pop_back();
        const auto cut = verify_rollout_proof(forged, network, error);
        ASSERT_TRUE(cut) << error;
        EXPECT_FALSE(rollout_complete(*cut, kN1, reason));
    }
    {   // No Genesis base.
        auto forged = *proof;
        forged.base.clear();
        EXPECT_FALSE(verify_rollout_proof(forged, network, error));
    }
}

TEST_F(UpgradePath, AServerThatIsDownBlocksTheNextTurn) {
    bootstrap();
    ASSERT_FALSE(HasFatalFailure());
    ASSERT_TRUE(run_until([&] {
        return std::all_of(reserves.begin(), reserves.end(),
                           [](Node* r) { return r->driver->verified_authority() != nullptr; });
    }));
    ASSERT_EQ(upgrade(founders.front()).offer_approval(
                  release_approval_bundle_json(signer->approval(kN1, kN))),
              ReleaseOfferResult::Adopted);
    ASSERT_TRUE(run_until([&] { return finalized().release_number == kN1; }));
    const NodeId first = finalized().order.front().node;
    // A participant that is not next goes down before anyone asks.
    Node* down = mesh.nodes.at(finalized().order.back().node);
    mesh.offline.insert(down->id);
    mesh.now_ms += constants::kUpgradeLivenessWindowMs + 1000;
    for (Node* node : online_servers()) upgrade(node).stage(kN1);
    upgrade_step(400);
    EXPECT_FALSE(finalized().in_turn.has_value()) << "a turn opened while a server was down";
    EXPECT_EQ(upgrade(mesh.nodes.at(first)).gate(kN1), UpgradeGate::Wait);

    // Back up: its status is fresh again and the first turn opens.
    mesh.offline.erase(down->id);
    upgrade(down).stage(kN1);
    ASSERT_TRUE(run_until([&] { return finalized().in_turn == first; }));
}

TEST_F(UpgradePath, AFailedReportHaltsTheRelease) {
    bootstrap();
    ASSERT_FALSE(HasFatalFailure());
    ASSERT_TRUE(run_until([&] {
        return std::all_of(reserves.begin(), reserves.end(),
                           [](Node* r) { return r->driver->verified_authority() != nullptr; });
    }));
    ASSERT_EQ(upgrade(founders.front()).offer_approval(
                  release_approval_bundle_json(signer->approval(kN1, kN))),
              ReleaseOfferResult::Adopted);
    ASSERT_TRUE(run_until([&] { return finalized().release_number == kN1; }));
    for (Node* node : servers()) upgrade(node).stage(kN1);
    ASSERT_TRUE(run_until([&] { return finalized().in_turn.has_value(); }));
    Node* subject = mesh.nodes.at(*finalized().in_turn);
    // The updater's health gate failed and it rolled back to N.
    restart_with(*subject, kN, 0);
    upgrade(subject).report_failed(kN1);
    ASSERT_TRUE(run_until([&] { return finalized().halted; })) << "no halt finalized";
    upgrade_step(50);
    for (Node* node : servers()) {
        EXPECT_EQ(upgrade(node).gate(kN1), UpgradeGate::Halted)
            << "node " << nexus::crypto::to_hex(node->id.bytes).substr(0, 8);
    }
    EXPECT_TRUE(finalized().upgraded.empty());
    // The release guard refuses a halted rollout.
    const auto proof = rollout_proof_from_any();
    ASSERT_TRUE(proof);
    std::string error;
    const auto rollout = verify_rollout_proof(*proof, network, error);
    ASSERT_TRUE(rollout) << error;
    std::string reason;
    EXPECT_FALSE(rollout_complete(*rollout, kN1, reason));
    EXPECT_NE(reason.find("halted"), std::string::npos) << reason;
}

// The fix after a halt. One server upgraded to N+1 before the next one failed,
// so servers run N+1 or N, and the finalized records prove which. The release
// that fixes the halt lists both in its overlap; the release guard accepts it
// only then, and servers on either release adopt and attest it.
TEST_F(UpgradePath, AHaltedRolloutIsFixedByAReleaseThatCoversBothReleases) {
    constexpr uint64_t kFix = kN1 + 1;
    bootstrap();
    ASSERT_FALSE(HasFatalFailure());
    ASSERT_TRUE(run_until([&] {
        return std::all_of(reserves.begin(), reserves.end(),
                           [](Node* r) { return r->driver->verified_authority() != nullptr; });
    }));
    const auto halted_approval = signer->approval(kN1, kN);
    ASSERT_EQ(upgrade(founders.front()).offer_approval(release_approval_bundle_json(halted_approval)),
              ReleaseOfferResult::Adopted);
    ASSERT_TRUE(run_until([&] { return finalized().release_number == kN1; }));
    for (Node* node : servers()) upgrade(node).stage(kN1);

    // The first server in the order upgrades; the second one fails its health
    // gate, rolls back to N, and reports it.
    std::vector<NodeId> went;
    ASSERT_TRUE(run_until(
        [&] {
            for (Node* node : servers()) {
                if (upgrade(node).gate(kN1) != UpgradeGate::Go ||
                    std::find(went.begin(), went.end(), node->id) != went.end()) {
                    continue;
                }
                went.push_back(node->id);
                if (went.size() == 1) {
                    restart_with(*node, kN1, kN);
                    upgrade(node).stage(kN1);
                } else {
                    restart_with(*node, kN, 0);
                    upgrade(node).report_failed(kN1);
                }
                break;
            }
            return finalized().halted;
        },
        4000))
        << "no halt finalized";
    ASSERT_EQ(went.size(), 2u);
    ASSERT_EQ(finalized().upgraded.size(), 1u);
    EXPECT_TRUE(finalized().upgraded.contains(went[0]));
    Node* on_halted = mesh.nodes.at(went[0]);
    EXPECT_EQ(stacks.at(on_halted->id).installed->approval.release_number, kN1);

    // The release guard: the proof shows the halt, bound to the approval its
    // Start record names.
    const auto proof = rollout_proof_from_any();
    ASSERT_TRUE(proof);
    std::string error;
    const auto rollout = verify_rollout_proof(*proof, network, error);
    ASSERT_TRUE(rollout) << error;
    std::string reason;
    EXPECT_FALSE(rollout_complete(*rollout, kN1, reason));
    EXPECT_FALSE(previous_rollout_state(*rollout, kN1, nullptr, reason)) << "a halt needs its approval";
    EXPECT_EQ(previous_rollout_state(*rollout, kN1, &halted_approval, reason),
              PreviousRollout::Halted)
        << reason;
    EXPECT_NE(reason.find("1 of"), std::string::npos) << reason;
    // Another approval with the same number is not the finalized one.
    const auto other = signer->approval(kN1, kN - 100);
    EXPECT_FALSE(previous_rollout_state(*rollout, kN1, &other, reason));

    const auto fix = signer->approval(kFix, std::vector<uint64_t>{kN1, kN});
    EXPECT_TRUE(release_follows_rollout(*rollout, kN1, halted_approval, fix.approval, reason))
        << reason;
    // A fix that omits either release's hashes is refused.
    EXPECT_FALSE(release_follows_rollout(*rollout, kN1, halted_approval,
                                         signer->approval(kFix, kN1).approval, reason));
    EXPECT_NE(reason.find("halted release and the release before it"), std::string::npos)
        << reason;
    EXPECT_FALSE(release_follows_rollout(*rollout, kN1, halted_approval,
                                         signer->approval(kFix, kN).approval, reason));
    // A fix whose number does not rise, or another release key, is refused.
    EXPECT_FALSE(release_follows_rollout(*rollout, kN1, halted_approval,
                                         signer->approval(kN1, std::vector<uint64_t>{kN1, kN})
                                             .approval,
                                         reason));
    {
        ReleaseSigner other_key(genesis_node->identity.public_key,
                                genesis_node->identity.private_key);
        EXPECT_FALSE(release_follows_rollout(
            *rollout, kN1, halted_approval,
            other_key.approval(kFix, std::vector<uint64_t>{kN1, kN}).approval, reason));
    }

    // Servers on N+1 and on N adopt the fix, and each one attests the fix and
    // both earlier releases, so the next rollout can run.
    ASSERT_EQ(upgrade(founders.front()).offer_approval(release_approval_bundle_json(fix)),
              ReleaseOfferResult::Adopted);
    const auto all = servers();
    ASSERT_TRUE(run_until([&] {
        return std::all_of(all.begin(), all.end(), [&](Node* node) {
            return chain(node).highest_release_number() == kFix;
        });
    })) << "the fix did not spread";
    for (Node* node : servers()) {
        const auto& profile = node->runtime->attestation().profile();
        for (const char tag : {'n', 'a'}) {
            const std::string path =
                tag == 'n' ? "/usr/bin/lemonade-nexus" : "/usr/bin/nexus-attestd";
            EXPECT_TRUE(path_approved(profile, path, release_hash(kFix, tag)));
            EXPECT_TRUE(path_approved(profile, path, release_hash(kN1, tag)));
            EXPECT_TRUE(path_approved(profile, path, release_hash(kN, tag)));
            EXPECT_FALSE(path_approved(profile, path, release_hash(kN - 100, tag)));
        }
    }
    ASSERT_TRUE(run_until([&] {
        return finalized().release_number == kFix && !finalized().halted;
    })) << "the rollout of the fix did not start after the halt";
}

// Rollback protection for the highest accepted release. The finalized Start
// record of N+1 is the network floor. A server whose release record was
// rolled back refuses to use the old approval until a peer hands it N+1, and
// a fresh server learns the floor from Tier 1 and catches up to it. Both
// servers here are Tier 2: they hold no consensus state of their own.
TEST_F(UpgradePath, ARolledBackReleaseRecordIsRefusedAndAFreshServerCatchesUpToTheFloor) {
    bootstrap();
    ASSERT_FALSE(HasFatalFailure());
    ASSERT_TRUE(run_until([&] {
        return std::all_of(reserves.begin(), reserves.end(),
                           [](Node* r) { return r->driver->verified_authority() != nullptr; });
    }));
    ASSERT_GE(reserves.size(), 2u);
    Node* rolled = reserves.front();
    Node* fresh = reserves.back();
    const auto record_path = rolled->dir / "release" / kReleaseChainFile;
    std::string before_n1;
    {
        std::ifstream in(record_path);
        ASSERT_TRUE(in) << "no release record";
        before_n1.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    ASSERT_EQ(upgrade(founders.front()).offer_approval(
                  release_approval_bundle_json(signer->approval(kN1, kN))),
              ReleaseOfferResult::Adopted);
    const auto all = servers();
    ASSERT_TRUE(run_until([&] {
        return finalized().release_number == kN1 &&
               std::all_of(all.begin(), all.end(), [&](Node* node) {
                   return chain(node).floor() == kN1 &&
                          chain(node).highest_release_number() == kN1;
               });
    })) << "the floor did not reach every server";

    const auto approves = [](const Node* node, uint64_t release) {
        return path_approved(node->runtime->attestation().profile(), "/usr/bin/lemonade-nexus",
                             release_hash(release, 'n'));
    };

    // The record from before N+1 comes back, and the server restarts on N.
    std::ofstream(record_path, std::ios::trunc) << before_n1;
    restart_with(*rolled, kN, 0);
    EXPECT_EQ(chain(rolled).highest_release_number(), kN);
    EXPECT_EQ(chain(rolled).floor(), kN1);
    EXPECT_TRUE(chain(rolled).below_floor());
    EXPECT_FALSE(chain(rolled).current().has_value());
    EXPECT_FALSE(upgrade(rolled).accepted_approval().has_value());
    EXPECT_FALSE(approves(rolled, kN)) << "the rolled-back approval must not attest";
    ASSERT_TRUE(run_until([&] {
        return chain(rolled).highest_release_number() == kN1 && !chain(rolled).below_floor();
    })) << "no peer handed the rolled-back server N+1";
    EXPECT_TRUE(approves(rolled, kN1));
    EXPECT_TRUE(approves(rolled, kN));

    // A fresh server: no release record and no upgrade records, packaged N.
    std::filesystem::remove_all(fresh->dir / "release");
    std::filesystem::remove_all(fresh->dir / "upgrade");
    restart_with(*fresh, kN, 0);
    EXPECT_EQ(chain(fresh).floor(), 0u);
    EXPECT_EQ(chain(fresh).highest_release_number(), kN);
    ASSERT_TRUE(run_until([&] {
        return chain(fresh).floor() == kN1 && chain(fresh).highest_release_number() == kN1 &&
               chain(fresh).current().has_value();
    })) << "the fresh server did not catch up to the floor";
    EXPECT_TRUE(approves(fresh, kN1));
}

/// The r21 network: founded on a format-2 approval, before any server kept a
/// release chain.
class UpgradeFromR21 : public UpgradePath {
protected:
    std::optional<ReleaseApprovalBundleV1> initial_installed() override { return std::nullopt; }
    Digest founding_digest() override { return release_approval_digest(r21().approval); }
    ReleaseApprovalBundleV1 r21() { return signer->approval(21, 0, kReleaseApprovalFormatV2); }
};

TEST_F(UpgradeFromR21, TheFirstReleaseNeedsTheFoundingApprovalAndThenKeepsTheEpoch) {
    bootstrap();
    ASSERT_FALSE(HasFatalFailure());
    Node* node = founders.front();
    // Without the founding approval the new release cannot tie the
    // commitment to its pinned signer: it fails closed.
    restart_with(*node, kN, 0);
    EXPECT_EQ(node->driver->phase(), DriverPhase::Failed);

    // The migration step copies the r21 approval into the release directory.
    std::ofstream(node->dir / "release" / kFoundingApprovalFile)
        << release_approval_bundle_json(r21());
    restart_with(*node, kN, 0);
    EXPECT_NE(node->driver->phase(), DriverPhase::Failed);
    ASSERT_TRUE(run_until([&] { return node->driver->phase() == DriverPhase::Active; }));
    EXPECT_EQ(node->driver->current_epoch(), 1u);
    EXPECT_TRUE(node->driver->is_tier1_member());
}

}  // namespace
}  // namespace lifecycle_test
