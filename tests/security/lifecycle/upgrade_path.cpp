// In-place release updates on the memory mesh (Design-Auto-Update Phases 2,
// 3 and 5).
//
// Every server runs the real driver, router, HotStuff, release chain, and
// upgrade service over encoded envelopes. A process restart rebuilds a node
// from its directories with a different packaged approval, as an updater swap
// would. The positive attestation path needs a confidential VM, so the
// UpgradeHealth verdicts are injected into the challenging witness, with the
// measured hashes of the release the subject runs.

#include "support/release_fixture.hpp"
#include "support/rotation.hpp"

#include <LemonadeNexus/Security/Attestation/AttestationVerifier.hpp>
#include <LemonadeNexus/Security/Attestation/ReleaseChain.hpp>
#include <LemonadeNexus/Security/Upgrade/RolloutProof.hpp>
#include <LemonadeNexus/Security/Upgrade/UpgradeService.hpp>

#include <nlohmann/json.hpp>

#include <filesystem>
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

class UpgradePath : public RotatingMeshBase {
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
        config.updater_wake = wake_marker(node);
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

    /// Where the node's service touches the nexus-updater wake marker.
    [[nodiscard]] static std::filesystem::path wake_marker(const Node& node) {
        return node.dir / "updater-wake";
    }
    [[nodiscard]] static bool woken(const Node& node) {
        std::error_code ec;
        return std::filesystem::exists(wake_marker(node), ec);
    }
    static void clear_wake(const Node& node) {
        std::error_code ec;
        std::filesystem::remove(wake_marker(node), ec);
    }
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

    /// The finalized chain as a current Tier 1 member holds it. After a
    /// rotation the first founder may be Tier 2; its copy then only follows.
    [[nodiscard]] const UpgradeChainState& finalized() {
        for (Node* node : servers()) {
            if (node->driver->is_tier1_member()) return upgrade(node).state();
        }
        return upgrade(founders.front()).state();
    }

    /// Adopts N+1 and runs until every server holds the Start record and the
    /// record that opens the first turn. Returns that record's sequence.
    uint64_t open_first_turn() {
        EXPECT_TRUE(run_until([&] {
            return std::all_of(reserves.begin(), reserves.end(), [](Node* r) {
                return r->driver->verified_authority() != nullptr;
            });
        }));
        EXPECT_EQ(upgrade(founders.front())
                      .offer_approval(release_approval_bundle_json(signer->approval(kN1, kN))),
                  ReleaseOfferResult::Adopted);
        EXPECT_TRUE(run_until([&] { return finalized().release_number == kN1; }));
        for (Node* node : servers()) upgrade(node).stage(kN1);
        EXPECT_TRUE(run_until([&] {
            const auto all = servers();
            return finalized().in_turn.has_value() &&
                   std::all_of(all.begin(), all.end(), [&](Node* node) {
                       return upgrade(node).state().sequence == finalized().sequence;
                   });
        }));
        return finalized().sequence;
    }

    /// Rewrites the node's upgrade records the way the earlier release left
    /// them on the fleet: the proof of record `unproven` is empty, and only
    /// the first `keep` records remain when `keep` is set.
    void rewrite_records(const Node& node, std::size_t unproven,
                         std::optional<std::size_t> keep = std::nullopt) {
        const auto path = node.dir / "upgrade" / "upgrade-records.json";
        nlohmann::json root;
        {
            std::ifstream in(path);
            ASSERT_TRUE(in) << "no upgrade records";
            root = nlohmann::json::parse(in);
        }
        auto& records = root.at("records");
        auto& proofs = root.at("proofs");
        ASSERT_GT(proofs.size(), unproven);
        proofs[unproven] = "";
        if (keep) {
            records.erase(records.begin() + static_cast<std::ptrdiff_t>(*keep), records.end());
            proofs.erase(proofs.begin() + static_cast<std::ptrdiff_t>(*keep), proofs.end());
        }
        std::ofstream(path, std::ios::trunc) << root.dump();
    }

    /// The node's own rollout proof, verified, or nullopt.
    std::optional<VerifiedRollout> verified_own_proof(const Node* node) {
        const auto proof = upgrade(node).rollout_proof(genesis_node->identity.public_key);
        if (!proof) return std::nullopt;
        std::string error;
        return verify_rollout_proof(*proof, network, error);
    }

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

// Production incident: the first rollout with a Tier 2 participant in the
// order, in Epoch 3. The participant had been a member until the finalized
// handoff ended its epoch without it; it continued as Tier 2 in place, with
// the verified authority of Epoch 3 and no epoch state. Its router dropped
// every Upgrade message of that epoch as EpochOutOfWindow, so the Start and
// Turn records that opened its turn never reached it. Its gate stayed
// NotStarted, and the rollout stood still on an open turn.
TEST_F(UpgradePath, TheUpdaterIsWokenByAStartItTakesPartInAndByItsOwnTurn) {
    bootstrap();
    ASSERT_FALSE(HasFatalFailure());
    ASSERT_TRUE(run_until([&] {
        return std::all_of(reserves.begin(), reserves.end(),
                           [](Node* r) { return r->driver->verified_authority() != nullptr; });
    }));
    for (Node* node : servers()) ASSERT_FALSE(woken(*node));

    // A Tier 2 server that is down when the Start is composed is left out of
    // the order. It learns the Start from its peers once it is back.
    Node* absent = reserves.back();
    mesh.offline.insert(absent->id);
    mesh.now_ms += constants::kUpgradeLivenessWindowMs + 1000;
    ASSERT_EQ(upgrade(founders.front()).offer_approval(
                  release_approval_bundle_json(signer->approval(kN1, kN))),
              ReleaseOfferResult::Adopted);
    ASSERT_TRUE(run_until([&] { return finalized().release_number == kN1; }))
        << "no rollout started";
    ASSERT_FALSE(finalized().participant(absent->id));
    mesh.offline.erase(absent->id);
    ASSERT_TRUE(run_until([&] {
        const auto all = servers();
        return std::all_of(all.begin(), all.end(), [&](Node* node) {
            return upgrade(node).state().release_number == kN1;
        });
    })) << "a server did not learn the Start";

    // The Start woke every participant and nobody else.
    for (Node* node : servers()) {
        EXPECT_EQ(woken(*node), finalized().participant(node->id))
            << (node == absent ? "the absent server" : "a participant");
        clear_wake(*node);
    }

    // The first Turn wakes its subject only.
    for (Node* node : servers()) upgrade(node).stage(kN1);
    ASSERT_TRUE(run_until([&] {
        const auto all = servers();
        return finalized().in_turn.has_value() &&
               std::all_of(all.begin(), all.end(), [&](Node* node) {
                   return upgrade(node).state().sequence == finalized().sequence;
               });
    })) << "no turn opened";
    const NodeId subject = *finalized().in_turn;
    for (Node* node : servers()) {
        EXPECT_EQ(woken(*node), node->id == subject)
            << (node->id == subject ? "the subject" : "another server");
    }
}

TEST_F(UpgradePath, ADemotedMemberTakesItsTier2TurnInALaterEpoch) {
    bootstrap();
    ASSERT_FALSE(HasFatalFailure());
    run_until_committed(1);
    introduce_reserves();
    ASSERT_TRUE(run_until([&] {
        return std::all_of(reserves.begin(), reserves.end(),
                           [](Node* r) { return r->driver->verified_authority() != nullptr; });
    }));

    // Epoch 1 -> 2 with one founder absent from the observed pool: it is not
    // eligible, so not selected. It restarts inside the boundary, as the
    // production server had, so its own commit of the handoff cannot move
    // it: the members' broadcast proof, verified under its own epoch's keys,
    // ends its epoch in place (follow_finalized_handoff).
    Node* demoted = founders.back();
    std::vector<Node*> pool(founders.begin(), founders.end() - 1);
    pool.push_back(reserves.front());
    observe(founders, pool, 1);
    run_to_plan(founders);
    ASSERT_FALSE(HasFatalFailure());
    const auto members = selected_nodes(*founders.front());
    ASSERT_EQ(ids_of(members), ids_of(pool));
    wait_for_keys(founders, members, 2);
    ASSERT_FALSE(HasFatalFailure());
    restart_node(*demoted);
    demoted->driver->start(mesh.now_ms);
    run_to_activation(founders, members, 2);
    ASSERT_FALSE(HasFatalFailure());
    ASSERT_TRUE(run_until([&] { return demoted->runtime->epochs() == nullptr; }))
        << "the excluded member never left its finished epoch";
    EXPECT_EQ(demoted->driver->phase(), DriverPhase::Idle);
    EXPECT_FALSE(demoted->driver->is_tier1_member());
    ASSERT_NE(demoted->driver->verified_authority(), nullptr);
    EXPECT_EQ(demoted->driver->verified_authority()->epoch, 2u);
    // Every server places itself in Epoch 2, then reports a status there
    // once, so the Start orders all of them.
    ASSERT_TRUE(run_until([&] {
        const auto all = servers();
        return std::all_of(all.begin(), all.end(), [](Node* node) {
            return node->driver->current_epoch() == 2u ||
                   (node->driver->verified_authority() != nullptr &&
                    node->driver->verified_authority()->epoch == 2u);
        });
    }));
    upgrade_step(static_cast<int>(constants::kUpgradeStatusIntervalMs / 200) + 5);

    ASSERT_EQ(upgrade(members.front())
                  .offer_approval(release_approval_bundle_json(signer->approval(kN1, kN))),
              ReleaseOfferResult::Adopted);
    ASSERT_TRUE(run_until([&] { return finalized().release_number == kN1; }))
        << "no rollout started";
    const auto order = finalized().order;
    for (Node* node : servers()) {
        EXPECT_TRUE(finalized().participant(node->id))
            << "server " << (node == demoted ? "demoted" : "other") << " "
            << nexus::crypto::to_hex(std::span<const uint8_t>(node->id.bytes.data(), 4))
            << " is not in the order";
    }
    ASSERT_EQ(order.size(), servers().size());
    ASSERT_TRUE(finalized().participant(demoted->id));
    EXPECT_FALSE(order.front().tier1) << "Tier 2 goes first";
    const auto position_of = [&](const NodeId& node) {
        return static_cast<std::size_t>(std::distance(
            order.begin(), std::find_if(order.begin(), order.end(),
                                        [&](const UpgradeParticipant& e) { return e.node == node; })));
    };
    for (Node* member : members) {
        EXPECT_LT(position_of(demoted->id), position_of(member->id))
            << "the demoted server is ordered with Tier 2, before every member";
    }

    // The finalized records reach the demoted server although it holds no
    // epoch state: its copy follows the members' chain.
    for (Node* node : servers()) upgrade(node).stage(kN1);
    ASSERT_TRUE(run_until([&] {
        return upgrade(demoted).state().sequence == finalized().sequence &&
               finalized().in_turn.has_value();
    })) << "the demoted Tier 2 server never received the Start and Turn records";
    EXPECT_NE(upgrade(demoted).gate(kN1), UpgradeGate::NotStarted);

    std::vector<NodeId> restarted;
    ASSERT_TRUE(run_until(
        [&] {
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
    EXPECT_EQ(upgrade(demoted).gate(kN1), UpgradeGate::Done);
    // The rollout changed no role: the demoted server is still Tier 2 on the
    // verified chain, and Epoch 2 keeps its members.
    EXPECT_EQ(demoted->driver->phase(), DriverPhase::Idle);
    EXPECT_EQ(demoted->runtime->epochs(), nullptr);
    ASSERT_NE(demoted->driver->verified_authority(), nullptr);
    EXPECT_EQ(demoted->driver->verified_authority()->epoch, 2u);
    for (Node* member : members) {
        EXPECT_TRUE(member->driver->is_tier1_member());
        EXPECT_EQ(member->driver->current_epoch(), 2u);
    }
}

// Production incident: the updater installs on its own timer, up to about 17
// minutes after its turn opens, but the witnesses challenged the subject at
// once and spent their whole per-position attempt budget (8 attempts, 10 s
// apart) on the release it still ran. When it finally upgraded, no witness
// could challenge it again and the turn never closed. A witness now waits
// for the subject's signed status to name the release.
TEST_F(UpgradePath, ATurnClosesWhenTheSubjectInstallsLongAfterItOpened) {
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
    ASSERT_FALSE(subject->driver->is_tier1_member()) << "Tier 2 goes first";

    // The subject's turn is open, but its updater has not run yet.
    const uint64_t budget_ms = (constants::kMaxUpgradeHealthAttemptsPerPosition + 2) *
                               constants::kUpgradeWitnessIntervalMs;
    const uint64_t installs_at = mesh.now_ms + budget_ms;
    while (mesh.now_ms < installs_at) upgrade_step();
    ASSERT_EQ(finalized().in_turn, subject->id);
    EXPECT_FALSE(finalized().upgraded.contains(subject->id));

    restart_with(*subject, kN1, kN);
    upgrade(subject).stage(kN1);
    EXPECT_TRUE(run_until([&] { return finalized().upgraded.contains(subject->id); }))
        << "the turn never closed after a late install";
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

// Production incident (release 2026102601): one Tier 1 member was down when a
// record committed, and the commit produced no proof on any live member
// (HotStuffSafety.ACommitProofSkipsAChildThatNoCertificateExtends). No server
// could serve a complete rollout proof, so the release guard refused the next
// release. The members still held the finalizing blocks in consensus, and the
// proof comes back from that certified chain, including on a member that
// restarted after the commit and holds none of those blocks itself.
TEST_F(UpgradePath, ARecordFinalizedWithoutItsProofGetsTheProofBackFromTheCertifiedChain) {
    bootstrap();
    ASSERT_FALSE(HasFatalFailure());
    const uint64_t sequence = open_first_turn();
    ASSERT_FALSE(HasFatalFailure());
    ASSERT_GE(sequence, 2u);
    ASSERT_TRUE(rollout_proof_from_any()) << "the commits produced the proofs";

    // Every server holds record 2 without its proof, as on the fleet.
    Node* restarted = founders[1];
    for (Node* node : servers()) {
        rewrite_records(*node, 1);
        ASSERT_FALSE(HasFatalFailure());
        if (node == restarted) {
            restart_node(*node);
            node->driver->start(mesh.now_ms);
        } else {
            build_stack(*node);
        }
    }
    for (Node* node : servers()) {
        EXPECT_EQ(upgrade(node).state().sequence, sequence);
    }
    ASSERT_FALSE(rollout_proof_from_any()) << "a server still held the lost proof";

    const auto all = servers();
    ASSERT_TRUE(run_until([&] {
        return std::all_of(all.begin(), all.end(), [&](Node* node) {
            const auto rollout = verified_own_proof(node);
            return rollout && rollout->state.sequence == sequence;
        });
    })) << "a server never got the lost commit proof back";

    // The proof the release guard reads, from the member that restarted.
    const auto proof = upgrade(restarted).rollout_proof(genesis_node->identity.public_key);
    ASSERT_TRUE(proof);
    std::string error;
    const auto rollout = verify_rollout_proof(*proof, network, error);
    ASSERT_TRUE(rollout) << error;
    EXPECT_EQ(rollout->state.release_number, kN1);
    EXPECT_EQ(rollout->state.in_turn, finalized().in_turn);
    // The recovered proof was kept on disk.
    build_stack(*restarted);
    EXPECT_TRUE(verified_own_proof(restarted));
}

// Production incident (release 2026102601): a member that restarted while a
// record committed never received it or any later record. Its peers held that
// record without a proof, so none could send it, and the member stayed at the
// Start record. Once the peers rebuild the proof, the record sync delivers
// the record and every later one.
TEST_F(UpgradePath, AMemberThatMissedLaterRecordsCatchesUpWhenNoPeerHeldTheirProof) {
    bootstrap();
    ASSERT_FALSE(HasFatalFailure());
    const uint64_t sequence = open_first_turn();
    ASSERT_FALSE(HasFatalFailure());
    ASSERT_GE(sequence, 2u);

    // The member holds the Start record only; every other server holds
    // record 2 without its proof.
    Node* behind = founders[2];
    for (Node* node : servers()) {
        if (node == behind) {
            rewrite_records(*node, 1, 1);
        } else {
            rewrite_records(*node, 1);
        }
        ASSERT_FALSE(HasFatalFailure());
        build_stack(*node);
    }
    ASSERT_EQ(upgrade(behind).state().sequence, 1u);
    {
        // The member proves only an open rollout with no turn, as on the fleet.
        const auto rollout = verified_own_proof(behind);
        ASSERT_TRUE(rollout);
        EXPECT_EQ(rollout->state.sequence, 1u);
        std::string reason;
        EXPECT_FALSE(rollout_complete(*rollout, kN1, reason));
    }

    ASSERT_TRUE(run_until([&] {
        const auto rollout = verified_own_proof(behind);
        return upgrade(behind).state().sequence == sequence && rollout &&
               rollout->state.sequence == sequence;
    })) << "the member stayed at sequence " << upgrade(behind).state().sequence;
    EXPECT_EQ(upgrade(behind).state().in_turn, finalized().in_turn);
    EXPECT_EQ(upgrade(behind).state().head, finalized().head);
}

// Production incident (release 2026102604): two of five Tier 1 members held
// the Start record of the previous rollout only. Its first Upgraded record had
// finalized without a commit proof on any member, and after an epoch change
// and a restart of every member no consensus served its block any more, so
// no peer could ever send it. The later records arrived with their proofs but
// did not extend the two members' chains. Every member judged a Start of the
// next release against its own head only, so no Start got a quorum of four,
// and every updater waited on "not_started" forever. A member now judges a
// Start against the newest finalized record it verified, even one it cannot
// apply.
TEST_F(UpgradePath, ASplitCommitteeStartsTheNextReleaseFromAVerifiedRecord) {
    constexpr uint64_t kNext = kN1 + 1;
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

    // Only the first server in the order upgrades: Start, Turn, Upgraded.
    Node* first = mesh.nodes.at(finalized().order.front().node);
    upgrade(first).stage(kN1);
    ASSERT_TRUE(run_until([&] { return upgrade(first).gate(kN1) == UpgradeGate::Go; }));
    restart_with(*first, kN1, kN);
    upgrade(first).stage(kN1);
    const auto all = servers();
    ASSERT_TRUE(run_until([&] {
        return finalized().upgraded.contains(first->id) &&
               std::all_of(all.begin(), all.end(), [&](Node* node) {
                   return upgrade(node).state().sequence == finalized().sequence;
               });
    })) << "the first server did not upgrade";
    const uint64_t sequence = finalized().sequence;
    ASSERT_EQ(sequence, 3u);

    // Two members hold the Start record only; every other server holds the
    // Turn record without its proof. The sync pages that would rebuild that
    // proof are lost, as on the fleet, so the Turn record never reaches the
    // two members and the Upgraded record cannot extend their chains.
    const std::vector<Node*> behind{founders[1], founders[2]};
    for (Node* node : servers()) {
        if (std::find(behind.begin(), behind.end(), node) != behind.end()) {
            rewrite_records(*node, 1, 1);
        } else {
            rewrite_records(*node, 1);
        }
        ASSERT_FALSE(HasFatalFailure());
    }
    mesh.drop_if = [](const Queued&, const SecurityMessage& message) {
        return std::holds_alternative<SyncResponse>(message.body);
    };
    for (Node* node : servers()) build_stack(*node);
    for (Node* node : behind) ASSERT_EQ(upgrade(node).state().sequence, 1u);
    EXPECT_FALSE(run_until(
        [&] { return upgrade(behind[0]).state().sequence > 1; }, 300))
        << "the lost record came back; the split did not hold";

    // The next release starts on every server, chained to the finalized
    // Upgraded record that the two members verified but could not apply.
    ASSERT_EQ(upgrade(founders.front()).offer_approval(
                  release_approval_bundle_json(signer->approval(kNext, kN1))),
              ReleaseOfferResult::Adopted);
    ASSERT_TRUE(run_until([&] {
        return std::all_of(all.begin(), all.end(), [&](Node* node) {
            return upgrade(node).state().release_number == kNext;
        });
    })) << "the next release did not start; finalized release "
        << finalized().release_number << " at sequence " << finalized().sequence;
    for (Node* node : servers()) {
        EXPECT_EQ(upgrade(node).state().sequence, sequence + 1);
        EXPECT_EQ(upgrade(node).state().head, finalized().head);
        EXPECT_FALSE(upgrade(node).state().in_turn.has_value());
        // Every server is in the new order; its updater waits for a Turn.
        EXPECT_EQ(upgrade(node).gate(kNext), UpgradeGate::Wait);
    }
    // The new rollout proves itself: every record since its Start has a proof.
    for (Node* node : behind) EXPECT_TRUE(verified_own_proof(node));
}

// A proof rebuilt from a peer's certified chain is candidate data: it is kept
// only when it verifies under the epoch's vote keys and quorum and commits the
// held record's exact bytes.
TEST_F(UpgradePath, ARebuiltProofIsKeptOnlyWhenItVerifies) {
    bootstrap();
    ASSERT_FALSE(HasFatalFailure());
    const uint64_t sequence = open_first_turn();
    ASSERT_FALSE(HasFatalFailure());
    ASSERT_GE(sequence, 2u);
    Node* member = founders[3];
    Node* peer = founders[0];

    // The finalizing block of record 2 in the peer's certified chain.
    nlohmann::json root;
    {
        std::ifstream in(member->dir / "upgrade" / "upgrade-records.json");
        ASSERT_TRUE(in);
        root = nlohmann::json::parse(in);
    }
    const auto body = nexus::crypto::from_hex(root.at("records").at(1).get<std::string>());
    const Digest wanted = block_payload_digest(BlockPayload{BlockPayloadKind::UpgradeProgress, body});
    const HotStuffService* consensus = peer->runtime->consensus();
    ASSERT_NE(consensus, nullptr);
    std::optional<SyncResponse> genuine;
    for (uint64_t after = 0; after < consensus->last_committed_height().underlying() && !genuine;
         ++after) {
        const auto page = consensus->certified_page_after(Height{after});
        if (!page || page->chain.size() < 3 ||
            page->chain.front().first.transitions_digest != wanted) {
            continue;
        }
        SyncResponse response;
        response.high_qc = page->certifying;
        for (const auto& [proposal, justify] : page->chain) {
            response.chain.push_back(ProposalMessage{proposal, justify, std::nullopt});
        }
        genuine = std::move(response);
    }
    ASSERT_TRUE(genuine) << "no page starts at the record's block";

    rewrite_records(*member, 1);
    ASSERT_FALSE(HasFatalFailure());
    build_stack(*member);
    ASSERT_FALSE(verified_own_proof(member));

    {   // A certificate over the record's block with forged signatures.
        auto forged = *genuine;
        for (auto& signer : forged.chain[1].justify.signers) signer.signature[0] ^= 1;
        upgrade(member).on_certified_chain(forged, peer->id);
        EXPECT_FALSE(verified_own_proof(member)) << "a forged certificate was kept";
    }
    {   // The child removed: the three blocks no longer link.
        auto forged = *genuine;
        forged.chain.erase(forged.chain.begin() + 1);
        upgrade(member).on_certified_chain(forged, peer->id);
        EXPECT_FALSE(verified_own_proof(member)) << "a broken chain was kept";
    }
    {   // The closing certificate covers the child, not the grandchild.
        auto forged = *genuine;
        forged.chain.resize(3);
        forged.high_qc = forged.chain[1].justify;
        upgrade(member).on_certified_chain(forged, peer->id);
        EXPECT_FALSE(verified_own_proof(member)) << "an unclosed three-chain was kept";
    }
    upgrade(member).on_certified_chain(*genuine, peer->id);
    const auto rollout = verified_own_proof(member);
    ASSERT_TRUE(rollout) << "the genuine chain did not rebuild the proof";
    EXPECT_EQ(rollout->state.sequence, sequence);
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
