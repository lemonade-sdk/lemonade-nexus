// Tree operations through Tier 1 consensus on the memory mesh (design A2 to
// A6). Five founders run the real driver, router, and HotStuff over encoded
// envelopes. An op submitted at one founder is forwarded to the others,
// proposed by whichever founder leads, committed, and applied on every
// founder in the same order, to the same tree digest. A rebuilt tree stack
// replays its log to the same state and keeps following the chain.
//
// Replication (design A7): a Tier 2 server and a Tier 1 member that missed
// blocks receive committed entries from a founder's log and verify each one
// against their own verified authority chain, across an epoch change.

#include "support/lifecycle_mesh.hpp"
#include "support/rotation.hpp"

#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeConsensus.hpp>
#include <LemonadeNexus/Tree/TreeOpSubmitter.hpp>

#include <chrono>
#include <functional>
#include <set>

namespace lifecycle_test {
namespace {

using nexus::tree::TreeOp;
using nexus::tree::TreeOpKind;
using nexus::tree::TreeOpSource;

uint64_t wall_clock_ms() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::system_clock::now().time_since_epoch())
                                     .count());
}

struct TreeStack {
    std::unique_ptr<nexus::tree::PermissionTreeService> tree;
    std::unique_ptr<nexus::tree::TreeConsensus> consensus;
    std::unique_ptr<nexus::tree::TreeOpSubmitter> submitter;
};

class TreeConsensusPath : public RotatingMeshBase {
protected:
    void SetUp() override {
        nexus::crypto::Ed25519Keypair root{};
        crypto_sign_keypair(root.public_key.data(), root.private_key.data());
        root_key = "ed25519:" + nexus::crypto::to_base64(std::span<const uint8_t>(
                                    root.public_key.data(), root.public_key.size()));
        DriverMeshBase::SetUp();
    }

    void TearDown() override {
        for (auto& [id, stack] : stacks) {
            stack.submitter.reset();
            stack.consensus.reset();
            if (stack.tree) stack.tree->stop();
        }
        stacks.clear();
        DriverMeshBase::TearDown();
    }

    // Every founder and reserve gets a tree stack, except a node the test
    // detaches; it is rebuilt with the driver.
    void on_node_built(Node& node) override {
        const bool server = std::find(founders.begin(), founders.end(), &node) != founders.end() ||
                            std::find(reserves.begin(), reserves.end(), &node) != reserves.end();
        if (server && !detached.contains(node.id)) build_stack(node);
    }

    void build_stack(Node& node) {
        auto& stack = stacks[node.id];
        stack.submitter.reset();
        stack.consensus.reset();
        if (!stack.tree) {
            stack.tree = std::make_unique<nexus::tree::PermissionTreeService>(*node.file_storage,
                                                                              *node.crypto);
            stack.tree->start();
        }
        nexus::tree::TreeConsensusConfig config;
        config.self = node.id;
        config.network_id = network;
        config.root_key = root_key;
        config.wall_clock_ms = wall_clock_ms;
        stack.consensus = std::make_unique<nexus::tree::TreeConsensus>(
            std::move(config), *stack.tree, *node.crypto, node.dir / "data" / "tree" / "log");
        EXPECT_TRUE(stack.consensus->start()) << stack.consensus->halt_reason();
        auto* consensus = stack.consensus.get();
        consensus->set_authority_source(
            [&node](EpochId epoch) { return node.driver->authority_for_epoch(epoch); });
        consensus->set_epoch_hint([&node](EpochId epoch) { node.driver->note_epoch_hint(epoch); });
        stack.submitter = std::make_unique<nexus::tree::TreeOpSubmitter>(
            *stack.tree, *node.crypto, network, node.identity,
            [consensus](TreeOp op) { return consensus->submit(std::move(op)); },
            std::chrono::milliseconds(0));
        consensus->set_broadcast([&node](TreeOpSubmitMsg message) {
            const EpochId epoch = node.driver->current_epoch().value_or(0);
            (void)node.router->broadcast(
                node.router->compose(SecurityMessageKind::TreeOpSubmit, std::move(message), epoch));
        });
        node.driver->register_payload_handler(*consensus);
        node.driver->set_tree_op_sink(
            [consensus](const TreeOpSubmitMsg& message, const NodeId& from) {
                consensus->receive_forwarded(message, from);
            });
        if (node.runtime->epochs() != nullptr) {
            consensus->set_members(node.runtime->epochs()->current().tier1_members.members());
        }
    }

    void refresh_members() {
        for (Node* founder : founders) {
            if (!stacks.contains(founder->id)) continue;
            stacks.at(founder->id).consensus->set_members(
                founder->runtime->epochs()->current().tier1_members.members());
        }
    }

    /// Delivers every entry `from` holds above `to`'s height, through the
    /// wire form the sync stream carries, and returns each result.
    std::vector<nexus::tree::ReplicaResult> replicate(const Node* from, const Node* to) {
        std::vector<nexus::tree::ReplicaResult> results;
        auto& source = stack_of(from);
        auto& target = stack_of(to);
        for (uint64_t h = target.consensus->log().height() + 1;
             h <= source.consensus->log().height(); ++h) {
            const auto bytes = source.consensus->encoded_entry(h);
            EXPECT_TRUE(bytes.has_value()) << "height " << h;
            if (!bytes) break;
            const auto entry = nexus::tree::decode_replicated_entry(*bytes);
            EXPECT_TRUE(entry.has_value());
            if (!entry) break;
            results.push_back(target.consensus->receive_replicated(*entry));
        }
        return results;
    }

    /// Ticks founders and reserves until every reserve verified `epoch`.
    bool reserves_reach(EpochId epoch, int max_steps = 400) {
        std::vector<Node*> everyone = founders;
        everyone.insert(everyone.end(), reserves.begin(), reserves.end());
        for (int i = 0; i < max_steps; ++i) {
            if (std::all_of(reserves.begin(), reserves.end(), [&](Node* r) {
                    return r->driver->authority_for_epoch(epoch).has_value();
                })) {
                return true;
            }
            step(1, everyone);
        }
        return false;
    }

    TreeStack& stack_of(const Node* node) { return stacks.at(node->id); }

    /// Steps the mesh until `done` holds on every founder with a tree stack.
    bool run_until(const std::function<bool(TreeStack&)>& done, int max_steps = 400) {
        for (int i = 0; i < max_steps; ++i) {
            if (std::all_of(founders.begin(), founders.end(), [&](Node* f) {
                    return !stacks.contains(f->id) || done(stack_of(f));
                })) {
                return true;
            }
            step(1);
        }
        return false;
    }

    TreeOp root_op() const {
        TreeOp op;
        op.kind = TreeOpKind::EstablishRoot;
        op.target = "root";
        op.principal = root_key;
        op.body.source = TreeOpSource::Session;
        return op;
    }

    TreeOp create_customer(const std::string& id) const {
        nexus::tree::TreeNode node;
        node.id = id;
        node.parent_id = "root";
        node.type = nexus::tree::NodeType::Customer;
        node.mgmt_pubkey = root_key;
        node.assignments = {{root_key, {"admin"}}};
        TreeOp op;
        op.kind = TreeOpKind::CreateNode;
        op.target = id;
        op.principal = root_key;
        op.body.source = TreeOpSource::Session;
        op.body.node = node;
        return op;
    }

    /// Every founder's tree, log root, and log height agree.
    void expect_founders_agree() {
        const auto& first = stack_of(founders.front());
        for (Node* founder : founders) {
            auto& stack = stack_of(founder);
            EXPECT_TRUE(stack.consensus->healthy()) << stack.consensus->halt_reason();
            EXPECT_EQ(stack.tree->tree_digest(), first.tree->tree_digest());
            EXPECT_EQ(stack.consensus->log().state().root, first.consensus->log().state().root);
            EXPECT_EQ(stack.consensus->log().height(), first.consensus->log().height());
        }
    }

    std::string root_key;
    std::map<NodeId, TreeStack> stacks;
    std::set<NodeId> detached;
};

TEST_F(TreeConsensusPath, OpsCommitOnEveryTier1MemberToTheSameDigest) {
    bootstrap();
    refresh_members();

    // The root op, submitted at one founder, commits everywhere.
    const auto root = stack_of(founders[0]).submitter->submit_async(root_op());
    ASSERT_TRUE(root.verdict.ok()) << root.verdict.reason;
    ASSERT_TRUE(run_until([](TreeStack& s) { return s.tree->get_node("root").has_value(); }));
    EXPECT_EQ(root.ticket->current().status, nexus::tree::TreeOpStatus::Committed);

    // Two ops submitted at two other founders: forwarded, ordered, applied.
    const auto acme = stack_of(founders[1]).submitter->submit_async(create_customer("acme"));
    const auto beta = stack_of(founders[2]).submitter->submit_async(create_customer("beta"));
    ASSERT_TRUE(acme.verdict.ok()) << acme.verdict.reason;
    ASSERT_TRUE(beta.verdict.ok()) << beta.verdict.reason;
    ASSERT_TRUE(run_until([](TreeStack& s) {
        return s.tree->get_node("acme").has_value() && s.tree->get_node("beta").has_value();
    }));
    EXPECT_EQ(acme.ticket->current().status, nexus::tree::TreeOpStatus::Committed);
    EXPECT_EQ(beta.ticket->current().status, nexus::tree::TreeOpStatus::Committed);
    expect_founders_agree();
    EXPECT_GE(stack_of(founders[0]).consensus->log().height(), 2u);

    // The same op again is refused at submission: it is committed.
    TreeOp replay = create_customer("acme");
    EXPECT_FALSE(stack_of(founders[3]).submitter->submit_async(replay).verdict.ok());
}

TEST_F(TreeConsensusPath, ARebuiltTreeStackReplaysItsLogAndKeepsFollowing) {
    bootstrap();
    refresh_members();
    ASSERT_TRUE(stack_of(founders[0]).submitter->submit_async(root_op()).verdict.ok());
    // Submission pre-checks against the committed tree, so the child waits
    // for the root's commit.
    ASSERT_TRUE(run_until([](TreeStack& s) { return s.tree->get_node("root").has_value(); }));
    ASSERT_TRUE(stack_of(founders[1]).submitter->submit_async(create_customer("acme"))
                    .verdict.ok());
    ASSERT_TRUE(run_until([](TreeStack& s) { return s.tree->get_node("acme").has_value(); }));

    // Rebuild one founder's tree stack from disk, as a process restart would.
    Node* restarted = founders[3];
    auto& stack = stack_of(restarted);
    const auto digest = stack.tree->tree_digest();
    const auto height = stack.consensus->log().height();
    stack.submitter.reset();
    stack.consensus.reset();
    stack.tree->stop();
    stack.tree.reset();
    build_stack(*restarted);
    EXPECT_EQ(stack_of(restarted).tree->tree_digest(), digest);
    EXPECT_EQ(stack_of(restarted).consensus->log().height(), height);

    // It keeps applying the chain with everyone else.
    ASSERT_TRUE(stack_of(founders[2]).submitter->submit_async(create_customer("gamma"))
                    .verdict.ok());
    ASSERT_TRUE(run_until([](TreeStack& s) { return s.tree->get_node("gamma").has_value(); }));
    expect_founders_agree();
}

TEST_F(TreeConsensusPath, TheLogHeightContinuesAcrossAnEpochChange) {
    bootstrap();
    refresh_members();
    ASSERT_TRUE(stack_of(founders[0]).submitter->submit_async(root_op()).verdict.ok());
    ASSERT_TRUE(run_until([](TreeStack& s) { return s.tree->get_node("root").has_value(); }));

    // A full boundary on the production path. Activation resets consensus;
    // the tree log does not reset with it.
    const auto members = rotate(founders, founders, 1);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    ASSERT_EQ(ids_of(members), ids_of(founders));
    for (Node* founder : founders) ASSERT_EQ(founder->driver->current_epoch(), 2u);
    refresh_members();

    ASSERT_TRUE(stack_of(founders[4]).submitter->submit_async(create_customer("acme"))
                    .verdict.ok());
    ASSERT_TRUE(run_until([](TreeStack& s) { return s.tree->get_node("acme").has_value(); }));
    expect_founders_agree();
    const auto& log = stack_of(founders[0]).consensus->log();
    ASSERT_EQ(log.height(), 2u);
    EXPECT_EQ(log.read_entry(1)->commit.value("epoch", 0u), 1u);
    EXPECT_EQ(log.read_entry(2)->commit.value("epoch", 0u), 2u);
    EXPECT_EQ(log.read_entry(2)->previous_root, log.read_entry(1)->state_root);
}

TEST_F(TreeConsensusPath, AServerOutsideTier1RefusesTreeWrites) {
    bootstrap();
    refresh_members();
    // A Tier 2 server cannot sign an op any replica trusts, and no finalized
    // list of admitted submitters exists, so it refuses instead of
    // forwarding.
    auto& stack = stack_of(founders[0]);
    stack.consensus->set_members({founders[1]->id, founders[2]->id, founders[3]->id,
                                  founders[4]->id});
    const auto refused = stack.submitter->submit_async(root_op());
    EXPECT_EQ(refused.verdict.refusal, nexus::tree::TreeOpRefusal::Unavailable);
}


TEST_F(TreeConsensusPath, ATier2ServerAppliesAndServesTheSameTree) {
    bootstrap();
    refresh_members();
    ASSERT_TRUE(stack_of(founders[0]).submitter->submit_async(root_op()).verdict.ok());
    ASSERT_TRUE(run_until([](TreeStack& s) { return s.tree->get_node("root").has_value(); }));
    ASSERT_TRUE(stack_of(founders[1]).submitter->submit_async(create_customer("acme"))
                    .verdict.ok());
    ASSERT_TRUE(run_until([](TreeStack& s) { return s.tree->get_node("acme").has_value(); }));

    // The reserve never votes and receives no commit. It walks the authority
    // chain from the pinned Genesis certificate, then verifies each entry's
    // commit proof under that epoch's vote keys.
    Node* reserve = reserves[0];
    ASSERT_EQ(reserve->runtime->consensus(), nullptr);
    ASSERT_TRUE(reserves_reach(1));
    for (const auto result : replicate(founders[2], reserve)) {
        EXPECT_EQ(result, nexus::tree::ReplicaResult::Applied);
    }
    auto& tier2 = stack_of(reserve);
    const auto& founder = stack_of(founders[2]);
    EXPECT_TRUE(tier2.consensus->healthy()) << tier2.consensus->halt_reason();
    EXPECT_EQ(tier2.consensus->log().height(), founder.consensus->log().height());
    EXPECT_EQ(tier2.consensus->log().state().root, founder.consensus->log().state().root);
    EXPECT_EQ(tier2.tree->tree_digest(), founder.tree->tree_digest());
    EXPECT_TRUE(tier2.tree->get_node("acme").has_value());

    // It serves the same entries onward, to the next Tier 2 server.
    for (const auto result : replicate(reserve, reserves[1])) {
        EXPECT_EQ(result, nexus::tree::ReplicaResult::Applied);
    }
    EXPECT_EQ(stack_of(reserves[1]).tree->tree_digest(), founder.tree->tree_digest());

    // And it still refuses writes: it orders nothing and cannot forward.
    refresh_members();
    tier2.consensus->set_members(founders[0]->runtime->epochs()->current().tier1_members.members());
    EXPECT_EQ(tier2.submitter->submit_async(create_customer("beta")).verdict.refusal,
              nexus::tree::TreeOpRefusal::Unavailable);
}

TEST_F(TreeConsensusPath, ALaggingTier1MemberCatchesUpAcrossAnEpochChange) {
    // One founder runs no tree stack while blocks commit in two epochs.
    Node* lagging = founders[4];
    detached.insert(lagging->id);
    {
        auto& stack = stack_of(lagging);
        stack.submitter.reset();
        stack.consensus.reset();
        stack.tree->stop();
        stacks.erase(lagging->id);
    }
    restart_node(*lagging);  // a driver with no tree handler registered
    bootstrap();
    refresh_members();
    ASSERT_TRUE(stack_of(founders[0]).submitter->submit_async(root_op()).verdict.ok());
    ASSERT_TRUE(run_until([](TreeStack& s) { return s.tree->get_node("root").has_value(); }));

    const auto members = rotate(founders, founders, 1);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    ASSERT_EQ(ids_of(members), ids_of(founders));
    for (Node* founder : founders) ASSERT_EQ(founder->driver->current_epoch(), 2u);
    refresh_members();
    ASSERT_TRUE(stack_of(founders[1]).submitter->submit_async(create_customer("acme"))
                    .verdict.ok());
    ASSERT_TRUE(run_until([](TreeStack& s) { return s.tree->get_node("acme").has_value(); }));
    ASSERT_EQ(stack_of(founders[0]).consensus->log().height(), 2u);

    // The member comes back with an empty log: the next committed block does
    // not follow it, so it applies nothing and waits for replication.
    detached.erase(lagging->id);
    build_stack(*lagging);
    refresh_members();
    ASSERT_TRUE(stack_of(founders[2]).submitter->submit_async(create_customer("beta"))
                    .verdict.ok());
    ASSERT_TRUE(run_until([](TreeStack& s) {
        return s.tree->get_node("beta").has_value() || s.consensus->status_summary().behind;
    }));
    auto& late = stack_of(lagging);
    EXPECT_TRUE(late.consensus->healthy()) << late.consensus->halt_reason();
    EXPECT_TRUE(late.consensus->status_summary().behind);
    EXPECT_EQ(late.consensus->log().height(), 0u);

    // Replication: entry 1 verifies under epoch 1's vote keys, entries 2 and
    // 3 under epoch 2's, from this member's own verified chain.
    ASSERT_TRUE(lagging->driver->authority_for_epoch(1).has_value());
    ASSERT_TRUE(lagging->driver->authority_for_epoch(2).has_value());
    const auto results = replicate(founders[0], lagging);
    ASSERT_EQ(results.size(), 3u);
    for (const auto result : results) EXPECT_EQ(result, nexus::tree::ReplicaResult::Applied);
    EXPECT_EQ(late.consensus->log().read_entry(1)->commit.value("epoch", 0u), 1u);
    EXPECT_EQ(late.consensus->log().read_entry(3)->commit.value("epoch", 0u), 2u);

    // It resumes from consensus: the next block applies through its own commit.
    ASSERT_TRUE(stack_of(founders[3]).submitter->submit_async(create_customer("gamma"))
                    .verdict.ok());
    ASSERT_TRUE(run_until([](TreeStack& s) { return s.tree->get_node("gamma").has_value(); }));
    EXPECT_FALSE(late.consensus->status_summary().behind);
    expect_founders_agree();
    EXPECT_EQ(late.consensus->log().height(), 4u);
}

}  // namespace
}  // namespace lifecycle_test
