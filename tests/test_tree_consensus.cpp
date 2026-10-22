// Tree operations through Tier 1 consensus (docs/Design-Tree-Consensus-and-
// Storage-Key.md, A2 to A6): the batch wire form, the deterministic batch
// rules, state roots, the tree log, the pending pool, the submitter's wait,
// and the payload handler voting and applying against a real HotStuff
// replica.

#include "security/consensus/hotstuff_harness.hpp"

#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Security/Consensus/BlockPayload.hpp>
#include <LemonadeNexus/Security/Consensus/HotStuffService.hpp>
#include <LemonadeNexus/Security/Consensus/VoteKey.hpp>
#include <LemonadeNexus/Security/Policy/SecurityConstants.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeBatch.hpp>
#include <LemonadeNexus/Tree/TreeChain.hpp>
#include <LemonadeNexus/Tree/TreeConsensus.hpp>
#include <LemonadeNexus/Tree/TreeLog.hpp>
#include <LemonadeNexus/Tree/TreeOpPool.hpp>
#include <LemonadeNexus/Tree/TreeOpSubmitter.hpp>
#include <LemonadeNexus/Tree/TreeOps.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <thread>
#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

using namespace nexus;
namespace fs = std::filesystem;
namespace sec = nexus::security;
using tree::TreeBatch;
using tree::TreeOp;
using tree::TreeOpKind;
using tree::TreeOpRefusal;
using tree::TreeOpSource;

namespace {

/// A fixed wall clock in 2023. Block times and signed times sit near it.
constexpr uint64_t kNowMs = 1'700'000'000'000;
constexpr uint64_t kNowSec = kNowMs / 1000;
constexpr sec::EpochId kEpoch = 7;

std::string principal_of(const crypto::Ed25519Keypair& kp) {
    return "ed25519:" +
           crypto::to_base64(std::span<const uint8_t>(kp.public_key.data(), kp.public_key.size()));
}

sec::Digest filled(uint8_t value) {
    sec::Digest d{};
    d.fill(value);
    return d;
}

sec::BlockPayload payload_of(const TreeBatch& batch) {
    sec::BlockPayload payload;
    payload.kind = sec::BlockPayloadKind::TreeBatch;
    payload.body = *tree::encode_tree_batch(batch);
    return payload;
}

struct TestBlock {
    sec::Proposal proposal;
    sec::QuorumCertificate justify;
    sec::Digest digest{};
    std::optional<sec::BlockPayload> payload;
};

}  // namespace

class TreeConsensusTest : public ::testing::Test {
protected:
    fs::path dir;
    std::unique_ptr<crypto::SodiumCryptoService> crypto_svc;
    std::unique_ptr<storage::FileStorageService> storage_svc;
    std::unique_ptr<tree::PermissionTreeService> tree_svc;
    std::unique_ptr<tree::TreeConsensus> tc;

    std::vector<crypto::Ed25519Keypair> member_keys;
    std::vector<sec::NodeId> members;
    std::vector<sec::EpochVoteKey> vote_keys;
    std::map<sec::NodeId, crypto::Ed25519PublicKey> vote_pubs;
    crypto::Ed25519Keypair root_kp;
    crypto::Ed25519Keypair stranger_kp;
    std::string root_key;
    sec::NetworkId network{};
    uint64_t now_ms = kNowMs;

    hotstuff_test::RecordingStore store;
    std::unique_ptr<sec::HotStuffService> service;

    void SetUp() override {
        dir = fs::temp_directory_path() / ("nexus_test_tree_consensus_" + std::to_string(getpid()));
        fs::remove_all(dir);
        fs::create_directories(dir);
        crypto_svc = std::make_unique<crypto::SodiumCryptoService>();
        crypto_svc->start();
        for (int i = 0; i < 4; ++i) {
            member_keys.push_back(crypto_svc->ed25519_keygen());
            sec::NodeId node{};
            node.bytes = member_keys.back().public_key;
            members.push_back(node);
        }
        // Leader order and vote-key maps are sorted by node id in production.
        std::sort(members.begin(), members.end());
        std::sort(member_keys.begin(), member_keys.end(), [](const auto& a, const auto& b) {
            return a.public_key < b.public_key;
        });
        for (const auto& node : members) {
            vote_keys.push_back(sec::make_epoch_vote_key(kEpoch, node));
            vote_pubs[node] = vote_keys.back().public_key;
        }
        root_kp = crypto_svc->ed25519_keygen();
        stranger_kp = crypto_svc->ed25519_keygen();
        root_key = principal_of(root_kp);
        network.fill(0x42);
        open_tree();
        open_consensus();
        make_service();
    }

    void TearDown() override {
        service.reset();
        tc.reset();
        if (tree_svc) tree_svc->stop();
        if (storage_svc) storage_svc->stop();
        crypto_svc->stop();
        fs::remove_all(dir);
    }

    void open_tree() {
        storage_svc = std::make_unique<storage::FileStorageService>(dir / "data");
        storage_svc->start();
        tree_svc = std::make_unique<tree::PermissionTreeService>(*storage_svc, *crypto_svc);
        tree_svc->start();
    }

    void close_tree() {
        tc.reset();
        tree_svc->stop();
        tree_svc.reset();
        storage_svc->stop();
        storage_svc.reset();
    }

    /// The handler for member 0. `start` opens the log.
    bool open_consensus(bool start = true) {
        tree::TreeConsensusConfig config;
        config.self = members[0];
        config.network_id = network;
        config.root_key = root_key;
        config.wall_clock_ms = [this] { return now_ms; };
        tc = std::make_unique<tree::TreeConsensus>(std::move(config), *tree_svc, *crypto_svc,
                                                   dir / "data" / "tree" / "log");
        tc->set_members(members);
        return start ? tc->start() : true;
    }

    void make_service() {
        sec::HotStuffConfig config{};
        config.security_ruleset = sec::constants::kSecurityRulesetVersion;
        config.consensus_ruleset = sec::constants::kConsensusRulesetVersion;
        config.network_id = network;
        config.epoch = kEpoch;
        config.genesis_digest = filled(0x11);
        config.leader_order = members;
        config.vote_keys = vote_pubs;
        config.quorum = sec::constants::consensus_quorum(members.size());
        config.self = members[0];
        config.payload_validator = [this](const sec::Proposal& proposal,
                                          const sec::BlockPayload& payload) {
            return tc && tc->validate(*service, proposal, payload);
        };
        service = std::make_unique<sec::HotStuffService>(
            std::move(config), hotstuff_test::clone_key(vote_keys[0]), store);
    }

    // --- Ops ------------------------------------------------------------------

    TreeOp seal(TreeOp op, const crypto::Ed25519Keypair* author = nullptr,
                uint64_t signed_at = kNowSec) {
        op.network_id = network;
        op.signed_at = signed_at;
        crypto_svc->random_bytes(std::span<uint8_t>(op.nonce));
        tree::sign_tree_op(*crypto_svc, op, author ? *author : member_keys[1]);
        return op;
    }

    TreeOp root_op() {
        TreeOp op;
        op.kind = TreeOpKind::EstablishRoot;
        op.target = "root";
        op.principal = root_key;
        op.body.source = TreeOpSource::Session;
        return op;
    }

    static tree::TreeNode customer(const std::string& id, const std::string& owner) {
        tree::TreeNode n;
        n.id = id;
        n.parent_id = "root";
        n.type = tree::NodeType::Customer;
        n.mgmt_pubkey = owner;
        n.assignments = {{owner, {"admin"}}};
        return n;
    }

    TreeOp create_op(const tree::TreeNode& node, const std::string& principal) {
        TreeOp op;
        op.kind = TreeOpKind::CreateNode;
        op.target = node.id;
        op.principal = principal;
        op.body.source = TreeOpSource::Session;
        op.body.node = node;
        return op;
    }

    TreeOp update_op(const tree::TreeNode& node, uint64_t base_version) {
        TreeOp op;
        op.kind = TreeOpKind::UpdateFields;
        op.target = node.id;
        op.base_version = base_version;
        op.principal = root_key;
        op.body.source = TreeOpSource::Session;
        op.body.node = node;
        return op;
    }

    TreeOp assign_op(const std::string& target, uint64_t base_version,
                     const std::string& principal, const std::vector<std::string>& perms) {
        TreeOp op;
        op.kind = TreeOpKind::SetAssignment;
        op.target = target;
        op.base_version = base_version;
        op.principal = root_key;
        op.body.source = TreeOpSource::Session;
        op.body.assignment_principal = principal;
        op.body.assignment_permissions = perms;
        return op;
    }

    // --- Blocks ---------------------------------------------------------------

    [[nodiscard]] sec::QuorumCertificate genesis_qc() const {
        sec::QuorumCertificate qc{};
        qc.qc_format_version = sec::constants::kQcFormatVersion;
        qc.consensus_ruleset = sec::constants::kConsensusRulesetVersion;
        qc.network_id = network;
        qc.epoch = kEpoch;
        qc.proposal_digest = filled(0x11);
        return qc;
    }

    [[nodiscard]] sec::QuorumCertificate qc_for(const sec::Proposal& proposal) const {
        sec::QuorumCertificate qc{};
        qc.qc_format_version = sec::constants::kQcFormatVersion;
        qc.consensus_ruleset = sec::constants::kConsensusRulesetVersion;
        qc.network_id = network;
        qc.epoch = kEpoch;
        qc.height = proposal.height;
        qc.view = proposal.view;
        qc.proposal_digest = sec::proposal_digest(proposal);
        for (const auto& key : vote_keys) {
            sec::QcSigner signer{};
            signer.node_id = key.node_id;
            signer.signature = sec::sign_digest(
                key, sec::vote_signing_digest(sec::constants::kConsensusRulesetVersion, network,
                                              kEpoch, proposal.height, proposal.view,
                                              qc.proposal_digest, key.node_id));
            qc.signers.push_back(signer);
        }
        return qc;
    }

    /// A block at `view` on `parent` (genesis when null).
    TestBlock block(const TestBlock* parent, uint64_t view,
                    std::optional<sec::BlockPayload> payload = std::nullopt,
                    sec::Digest previous_root = {}, sec::Digest proposed_root = {},
                    uint64_t hint = 0) {
        TestBlock b;
        auto& p = b.proposal;
        p.security_ruleset = sec::constants::kSecurityRulesetVersion;
        p.consensus_ruleset = sec::constants::kConsensusRulesetVersion;
        p.network_id = network;
        p.epoch = kEpoch;
        p.height = parent ? parent->proposal.height + 1 : 1;
        p.view = view;
        p.leader = members[view % members.size()];
        p.parent_digest = parent ? parent->digest : filled(0x11);
        b.justify = parent ? qc_for(parent->proposal) : genesis_qc();
        p.justify_qc_digest = sec::qc_digest(b.justify);
        p.previous_state_root = previous_root;
        p.proposed_state_root = proposed_root;
        p.transitions_digest = payload ? sec::block_payload_digest(*payload) : sec::Digest{};
        p.timestamp_hint = hint;
        b.payload = std::move(payload);
        b.digest = sec::proposal_digest(p);
        return b;
    }

    /// A correctly rooted tree block over `mirror`, which advances with it.
    TestBlock tree_block(const TestBlock* parent, uint64_t view, const TreeBatch& batch,
                         uint64_t hint, tree::TreeChainState& mirror) {
        auto payload = payload_of(batch);
        const auto previous = mirror.root;
        const auto result =
            tree::apply_certified_batch(mirror, batch, hint, sec::block_payload_digest(payload));
        EXPECT_TRUE(result.verdict.ok()) << result.verdict.reason;
        return block(parent, view, std::move(payload), previous, result.root, hint);
    }

    /// The log's base: the empty tree this fixture starts from.
    [[nodiscard]] tree::TreeChainState base_state() const {
        tree::TreeChainState state;
        state.root = tree::base_state_root(tree::compute_tree_digest(state.nodes));
        return state;
    }

    /// Deliver a block to the replica; hand every committed payload block to
    /// the handler, as SecurityDriver::on_commits does.
    sec::ProposalResult deliver(const TestBlock& b) {
        auto result = service->receive_proposal(b.proposal, b.justify,
                                                b.payload ? &*b.payload : nullptr);
        for (const auto& commit : result.commits) {
            const auto* payload = service->block_payload(commit.proposal_digest);
            const auto* proposal = service->block(commit.proposal_digest);
            if (payload == nullptr || proposal == nullptr) continue;
            sec::CommittedPayload committed;
            committed.commit = commit;
            committed.proposal = *proposal;
            committed.payload = payload;
            committed.proof = service->commit_proof(commit.proposal_digest);
            tc->on_committed(committed);
        }
        return result;
    }

    /// A first tree block holding only `ops` (sealed by member 1), and whether
    /// the replica voted for it.
    bool votes_for_first_block(std::vector<TreeOp> ops) {
        auto mirror = base_state();
        TreeBatch batch{std::move(ops)};
        auto payload = payload_of(batch);
        // Roots computed without validation, so an invalid op still yields a
        // well-formed block whose only defect is the op.
        auto copy = mirror;
        const auto result = tree::apply_certified_batch(copy, batch, now_ms,
                                                        sec::block_payload_digest(payload));
        const auto root = result.verdict.ok() ? result.root : filled(0x77);
        const auto b = block(nullptr, 1, std::move(payload), mirror.root, root, now_ms);
        return deliver(b).vote.has_value();
    }
};

// =========================================================================
// Wire form
// =========================================================================

TEST_F(TreeConsensusTest, BatchWireFormIsCanonical) {
    TreeBatch batch{{seal(root_op()), seal(create_op(customer("acme", root_key), root_key)),
                     seal(assign_op("acme", 1, root_key, {"read"}))}};
    const auto bytes = tree::encode_tree_batch(batch);
    ASSERT_TRUE(bytes.has_value());
    const auto decoded = tree::decode_tree_batch(*bytes);
    ASSERT_TRUE(decoded.has_value());
    ASSERT_EQ(decoded->ops.size(), 3u);
    for (std::size_t i = 0; i < 3; ++i) {
        EXPECT_EQ(decoded->ops[i].op_id, batch.ops[i].op_id);
        EXPECT_EQ(decoded->ops[i].signature, batch.ops[i].signature);
    }
    EXPECT_EQ(*tree::encode_tree_batch(*decoded), *bytes);

    auto trailing = *bytes;
    trailing.push_back(0);
    EXPECT_FALSE(tree::decode_tree_batch(trailing).has_value());
    auto short_count = *bytes;
    short_count[0] = 2;
    EXPECT_FALSE(tree::decode_tree_batch(short_count).has_value());
    auto tampered = *bytes;
    tampered[10] ^= 0x01;  // inside the first op's domain field
    EXPECT_FALSE(tree::decode_tree_batch(tampered).has_value());
    EXPECT_FALSE(tree::encode_tree_batch(TreeBatch{}).has_value());
    const std::vector<uint8_t> zero_count{0, 0};
    EXPECT_FALSE(tree::decode_tree_batch(zero_count).has_value());
}

TEST_F(TreeConsensusTest, EveryOpKindRoundTrips) {
    tree::TreeNode endpoint = customer("dev", root_key);
    endpoint.reputation_score = 0.3f;
    endpoint.version = 9;
    TreeOp endpoint_op;
    endpoint_op.kind = TreeOpKind::SetEndpoint;
    endpoint_op.target = "dev";
    endpoint_op.principal = root_key;
    endpoint_op.body.source = TreeOpSource::Session;
    endpoint_op.body.listen_endpoint = "203.0.113.5:51940";
    TreeOp join;
    join.kind = TreeOpKind::Join;
    join.target = "abc";
    join.principal = root_key;
    join.body.source = TreeOpSource::Device;
    join.body.join.device_pubkey = root_key;
    join.body.join.hostname_present = true;
    join.body.join.hostname = "laptop";
    join.body.join.is_inference = true;
    TreeOp delta;
    delta.kind = TreeOpKind::UpdateFields;
    delta.target = "dev";
    delta.principal = root_key;
    delta.body.source = TreeOpSource::Delta;
    delta.body.delta.operation = "update_node";
    delta.body.delta.node_data = endpoint;
    for (const auto& op : {seal(root_op()), seal(create_op(endpoint, root_key)),
                           seal(update_op(endpoint, 1)), seal(assign_op("dev", 1, root_key, {})),
                           seal(endpoint_op), seal(join), seal(delta)}) {
        const auto encoded = tree::encode_tree_op(op);
        const auto signature = *tree::tree_op_signature_bytes(op);
        const auto decoded = tree::decode_tree_op(encoded, signature);
        ASSERT_TRUE(decoded.has_value()) << static_cast<int>(op.kind);
        EXPECT_EQ(decoded->op_id, op.op_id);
        EXPECT_EQ(tree::encode_tree_op(*decoded), encoded);
        auto extra = encoded;
        extra.push_back(0);
        EXPECT_FALSE(tree::decode_tree_op(extra, signature).has_value());
    }
}

// =========================================================================
// Batch rules (design A4), against a chain state
// =========================================================================

TEST_F(TreeConsensusTest, OversizeBatchesAreRefused) {
    auto state = base_state();
    const auto policy = tc->policy_for(members);
    TreeBatch many;
    for (std::size_t i = 0; i <= tree::kMaxTreeBatchOps; ++i) {
        many.ops.push_back(seal(create_op(customer("c" + std::to_string(i), root_key), root_key)));
    }
    EXPECT_FALSE(tree::encode_tree_batch(many).has_value());
    EXPECT_EQ(tree::check_batch(*crypto_svc, state, many, now_ms, {}, policy).verdict.refusal,
              TreeOpRefusal::Oversize);

    // Two ops that each fit alone but not together.
    auto big = customer("big", root_key);
    big.hostname = std::string(30000, 'h');
    auto big2 = customer("big2", root_key);
    big2.hostname = std::string(30000, 'h');
    TreeBatch heavy{{seal(create_op(big, root_key)), seal(create_op(big2, root_key))}};
    EXPECT_FALSE(tree::encode_tree_batch(heavy).has_value());
    EXPECT_EQ(tree::check_batch(*crypto_svc, state, heavy, now_ms, {}, policy).verdict.refusal,
              TreeOpRefusal::Oversize);
    EXPECT_EQ(state.root, base_state().root);  // a refused batch changes nothing
}

TEST_F(TreeConsensusTest, BlockTimeMustAdvancePastTheLastTreeBlock) {
    auto state = base_state();
    const auto policy = tc->policy_for(members);
    TreeBatch first{{seal(root_op())}};
    ASSERT_TRUE(tree::check_batch(*crypto_svc, state, first, now_ms, {}, policy).verdict.ok());
    TreeBatch second{{seal(create_op(customer("acme", root_key), root_key))}};
    EXPECT_EQ(tree::check_batch(*crypto_svc, state, second, now_ms, {}, policy).verdict.refusal,
              TreeOpRefusal::Stale);
    EXPECT_EQ(
        tree::check_batch(*crypto_svc, state, second, now_ms - 1, {}, policy).verdict.refusal,
        TreeOpRefusal::Stale);
    EXPECT_TRUE(
        tree::check_batch(*crypto_svc, state, second, now_ms + 1, {}, policy).verdict.ok());
}

TEST_F(TreeConsensusTest, TwoServersApplyingTheSameBatchesReachTheSameDigest) {
    const auto policy = tc->policy_for(members);
    std::vector<TreeBatch> batches = {
        {{seal(root_op())}},
        {{seal(create_op(customer("acme", root_key), root_key)),
          seal(create_op(customer("beta", root_key), root_key))}},
        {{seal(create_op(customer("gamma", root_key), root_key)),
          seal(update_op([this] {
              auto n = customer("beta", root_key);
              n.hostname = "renamed";
              return n;
          }(), 1))}},
    };
    // Server A validates every batch; server B applies them as certified, from
    // a node map filled in another order.
    auto a = base_state();
    auto b = base_state();
    uint64_t t = now_ms;
    for (const auto& batch : batches) {
        const auto ops = sec::block_payload_digest(payload_of(batch));
        const auto ra = tree::check_batch(*crypto_svc, a, batch, ++t, ops, policy);
        ASSERT_TRUE(ra.verdict.ok()) << ra.verdict.reason;
        tree::rules::NodeMap reordered;
        for (auto it = b.nodes.begin(); it != b.nodes.end(); ++it) reordered.insert(*it);
        b.nodes = std::move(reordered);
        const auto rb = tree::apply_certified_batch(b, batch, t, ops);
        ASSERT_TRUE(rb.verdict.ok());
        EXPECT_EQ(ra.tree_digest, rb.tree_digest);
        EXPECT_EQ(ra.root, rb.root);
    }
    EXPECT_EQ(a.root, b.root);
    EXPECT_EQ(a.committed.sorted(), b.committed.sorted());
}

// =========================================================================
// Votes (design A4, A5): the handler against a HotStuff replica
// =========================================================================

TEST_F(TreeConsensusTest, AValidTreeBlockEarnsTheVote) {
    EXPECT_TRUE(votes_for_first_block({seal(root_op())}));
}

TEST_F(TreeConsensusTest, WrongNetworkWithholdsTheVote) {
    auto op = root_op();
    op.network_id = network;
    op.network_id[0] ^= 0xFF;
    op.signed_at = kNowSec;
    tree::sign_tree_op(*crypto_svc, op, member_keys[1]);
    EXPECT_FALSE(votes_for_first_block({op}));
}

TEST_F(TreeConsensusTest, BadSignatureWithholdsTheVote) {
    auto op = seal(root_op());
    auto signature = *tree::tree_op_signature_bytes(op);
    signature[5] ^= 0x01;
    op.signature = crypto::to_base64(std::span<const uint8_t>(signature.data(), signature.size()));
    EXPECT_FALSE(votes_for_first_block({op}));
}

TEST_F(TreeConsensusTest, AnAuthorOutsideTier1WithholdsTheVote) {
    // Identity is not authority: a valid signature by a non-member key is not
    // a trusted submission.
    EXPECT_FALSE(votes_for_first_block({seal(root_op(), &stranger_kp)}));
}

TEST_F(TreeConsensusTest, ARootForAnotherKeyWithholdsTheVote) {
    auto op = root_op();
    op.principal = principal_of(stranger_kp);
    EXPECT_FALSE(votes_for_first_block({seal(op)}));
}

TEST_F(TreeConsensusTest, AStaleOpWithholdsTheVote) {
    EXPECT_FALSE(votes_for_first_block(
        {seal(root_op(), nullptr, kNowSec - tree::kTreeOpMaxAgeSec - 1)}));
}

TEST_F(TreeConsensusTest, AReplayedOpInTheSameBatchWithholdsTheVote) {
    const auto op = seal(root_op());
    const auto acme = seal(create_op(customer("acme", root_key), root_key));
    EXPECT_FALSE(votes_for_first_block({op, acme, acme}));
}

/// Builds b1 = {root, acme} (voted), then returns whether the replica votes
/// for b2 = `second` on top of it.
class TreeConsensusChainTest : public TreeConsensusTest {
protected:
    bool votes_for_second_block(std::vector<TreeOp> second, uint64_t hint_offset_ms = 1,
                                std::optional<sec::Digest> forced_root = std::nullopt) {
        mirror = base_state();
        b1 = tree_block(nullptr, 1,
                        TreeBatch{{seal(root_op()),
                                   seal(create_op(customer("acme", root_key), root_key))}},
                        now_ms, mirror);
        if (!deliver(b1).vote.has_value()) {
            ADD_FAILURE() << "the first block earned no vote";
            return false;
        }
        TreeBatch batch{std::move(second)};
        auto payload = payload_of(batch);
        auto copy = mirror;
        const uint64_t hint = now_ms + hint_offset_ms;
        const auto result = tree::apply_certified_batch(copy, batch, hint,
                                                        sec::block_payload_digest(payload));
        const auto root = forced_root.value_or(result.verdict.ok() ? result.root : filled(0x77));
        const auto b2 = block(&b1, 2, std::move(payload), mirror.root, root, hint);
        return deliver(b2).vote.has_value();
    }

    tree::TreeChainState mirror;
    TestBlock b1;
};

TEST_F(TreeConsensusChainTest, AValidChildBlockEarnsTheVote) {
    EXPECT_TRUE(votes_for_second_block({seal(create_op(customer("beta", root_key), root_key))}));
}

TEST_F(TreeConsensusChainTest, AnOpReplayedFromAnUncommittedAncestorWithholdsTheVote) {
    mirror = base_state();
    const auto acme = seal(create_op(customer("acme", root_key), root_key));
    b1 = tree_block(nullptr, 1, TreeBatch{{seal(root_op()), acme}}, now_ms, mirror);
    ASSERT_TRUE(deliver(b1).vote.has_value());
    TreeBatch replay{{acme}};
    auto payload = payload_of(replay);
    const auto b2 = block(&b1, 2, std::move(payload), mirror.root, filled(0x55), now_ms + 1);
    EXPECT_FALSE(deliver(b2).vote.has_value());
}

TEST_F(TreeConsensusChainTest, AStaleBaseVersionWithholdsTheVote) {
    auto renamed = customer("acme", root_key);
    renamed.hostname = "renamed";
    EXPECT_FALSE(votes_for_second_block({seal(update_op(renamed, 0))}));
}

TEST_F(TreeConsensusChainTest, AnAuthorWithoutPermissionWithholdsTheVote) {
    const auto stranger = principal_of(stranger_kp);
    EXPECT_FALSE(votes_for_second_block({seal(create_op(customer("evil", stranger), stranger))}));
}

TEST_F(TreeConsensusChainTest, AnAdminChangingItsOwnAnchorEntryWithholdsTheVote) {
    EXPECT_FALSE(votes_for_second_block({seal(assign_op("root", 1, root_key, {"read"}))}));
}

TEST_F(TreeConsensusChainTest, AnUnjoinedPrincipalWithholdsTheVote) {
    EXPECT_FALSE(votes_for_second_block(
        {seal(assign_op("acme", 1, principal_of(stranger_kp), {"read"}))}));
}

TEST_F(TreeConsensusChainTest, AStateRootMismatchWithholdsTheVote) {
    EXPECT_FALSE(votes_for_second_block({seal(create_op(customer("beta", root_key), root_key))}, 1,
                                        filled(0x99)));
}

TEST_F(TreeConsensusChainTest, ABlockTimeBehindItsParentWithholdsTheVote) {
    EXPECT_FALSE(votes_for_second_block({seal(create_op(customer("beta", root_key), root_key))}, 0));
}

TEST_F(TreeConsensusChainTest, ABlockTimeTooFarAheadWithholdsTheVote) {
    EXPECT_FALSE(votes_for_second_block({seal(create_op(customer("beta", root_key), root_key))},
                                        tree::kTreeBlockClockSkewMs + 1));
}

TEST_F(TreeConsensusTest, ABlockTimeTooFarBehindTheClockWithholdsTheVote) {
    now_ms = kNowMs + tree::kTreeBlockClockSkewMs + 1;  // the replica's clock moved on
    auto mirror = base_state();
    const auto b = tree_block(nullptr, 1, TreeBatch{{seal(root_op())}}, kNowMs, mirror);
    EXPECT_FALSE(deliver(b).vote.has_value());
}

TEST_F(TreeConsensusTest, APreviousRootThatIsNotTheLogHeadWithholdsTheVote) {
    TreeBatch batch{{seal(root_op())}};
    auto mirror = base_state();
    auto payload = payload_of(batch);
    auto copy = mirror;
    const auto result =
        tree::apply_certified_batch(copy, batch, now_ms, sec::block_payload_digest(payload));
    const auto b = block(nullptr, 1, std::move(payload), filled(0x31), result.root, now_ms);
    EXPECT_FALSE(deliver(b).vote.has_value());
}

TEST_F(TreeConsensusTest, APayloadThatMissesTheHeaderDigestIsNotStored) {
    auto mirror = base_state();
    auto b = tree_block(nullptr, 1, TreeBatch{{seal(root_op())}}, now_ms, mirror);
    b.payload = payload_of(TreeBatch{{seal(root_op())}});  // other bytes, same header
    const auto result = deliver(b);
    EXPECT_FALSE(result.vote.has_value());
    EXPECT_TRUE(result.transition_refused);
    EXPECT_EQ(service->block_payload(b.digest), nullptr);
}

TEST_F(TreeConsensusTest, AHaltedHandlerVotesForNothing) {
    // Write the tree outside the log, then restart: the handler halts.
    ASSERT_TRUE(tree_svc->bootstrap_root(tree::make_root_node(root_key)));
    ASSERT_FALSE(open_consensus());
    EXPECT_FALSE(tc->healthy());
    EXPECT_FALSE(votes_for_first_block({seal(create_op(customer("acme", root_key), root_key))}));
    EXPECT_EQ(tc->submit(seal(root_op())).verdict.refusal, TreeOpRefusal::Unavailable);
}

// =========================================================================
// Commit, then apply (design A6), and the tree log
// =========================================================================

/// Commits b1 = {root, acme} and b2 = {beta} through the replica.
class TreeConsensusCommitTest : public TreeConsensusTest {
protected:
    void commit_two_blocks() {
        mirror = base_state();
        root = seal(root_op());
        acme = seal(create_op(customer("acme", root_key), root_key));
        blocks.push_back(tree_block(nullptr, 1, TreeBatch{{root, acme}}, now_ms, mirror));
        blocks.push_back(tree_block(&blocks[0], 2,
                                    TreeBatch{{seal(create_op(customer("beta", root_key),
                                                              root_key))}},
                                    now_ms + 1, mirror));
        blocks.push_back(block(&blocks[1], 3));
        blocks.push_back(block(&blocks[2], 4));
        blocks.push_back(block(&blocks[3], 5));
        for (const auto& b : blocks) ASSERT_FALSE(deliver(b).rejected.has_value());
    }

    tree::TreeChainState mirror;
    TreeOp root;
    TreeOp acme;
    std::vector<TestBlock> blocks;
};

TEST_F(TreeConsensusCommitTest, CommittedBlocksAreLoggedThenApplied) {
    commit_two_blocks();
    EXPECT_TRUE(tc->healthy()) << tc->halt_reason();
    EXPECT_EQ(tc->log().height(), 2u);
    EXPECT_EQ(tc->log().applied_height(), 2u);
    EXPECT_EQ(tc->log().state().root, mirror.root);
    EXPECT_EQ(tree_svc->tree_digest(), tree::compute_tree_digest(mirror.nodes));
    ASSERT_TRUE(tree_svc->get_node("beta").has_value());
    EXPECT_EQ(tree_svc->get_node("acme")->version, 1u);

    const auto entry = tc->log().read_entry(1);
    ASSERT_TRUE(entry.has_value());
    EXPECT_EQ(entry->ops_digest, blocks[0].proposal.transitions_digest);
    EXPECT_EQ(entry->state_root, blocks[0].proposal.proposed_state_root);
    EXPECT_EQ(entry->commit.value("consensus_height", 0u), 1u);
    EXPECT_TRUE(entry->commit.contains("proof"));
    // The stored proof verifies against the epoch's vote keys.
    const auto proof = sec::commit_proof_from_json(entry->commit["proof"]);
    ASSERT_TRUE(proof.has_value());
    const sec::QcValidationContext context{sec::constants::kConsensusRulesetVersion, network,
                                           kEpoch,
                                           sec::constants::consensus_quorum(members.size())};
    EXPECT_EQ(sec::verify_commit_proof(entry->ops_digest, *proof, context, vote_pubs),
              sec::CommitProofFailure::None);
}

TEST_F(TreeConsensusCommitTest, RestartReplaysTheLogToTheSameStateAndRefusesReplay) {
    commit_two_blocks();
    const auto digest = tree_svc->tree_digest();
    const auto root_hash = tc->log().state().root;
    close_tree();

    open_tree();
    ASSERT_TRUE(open_consensus()) << tc->halt_reason();
    EXPECT_EQ(tc->log().height(), 2u);
    EXPECT_EQ(tc->log().state().root, root_hash);
    EXPECT_EQ(tree_svc->tree_digest(), digest);

    // Replay after the restart: the committed ids came back with the log.
    EXPECT_EQ(tc->submit(acme).verdict.refusal, TreeOpRefusal::Replayed);
    auto state = tc->log().state();
    TreeBatch replay{{acme}};
    EXPECT_EQ(tree::check_batch(*crypto_svc, state, replay, now_ms + 10, {},
                                tc->policy_for(members))
                  .verdict.refusal,
              TreeOpRefusal::Replayed);
}

TEST_F(TreeConsensusCommitTest, AnInterruptedApplyIsRestoredFromTheLog) {
    commit_two_blocks();
    const auto digest = tree_svc->tree_digest();
    // A crash after the log write and before the apply: the tree is one block
    // behind and applied.json says so.
    ASSERT_TRUE(tree_svc->replace_all([&] {
        auto nodes = tree_svc->nodes_snapshot();
        nodes.erase("beta");
        return nodes;
    }(), tc->log().state().committed));
    nlohmann::json applied{{"format", 1}, {"height", 1}};
    std::ofstream(dir / "data" / "tree" / "log" / "applied.json") << applied.dump();
    close_tree();

    open_tree();
    ASSERT_TRUE(open_consensus()) << tc->halt_reason();
    EXPECT_EQ(tree_svc->tree_digest(), digest);
    EXPECT_TRUE(tree_svc->get_node("beta").has_value());
    EXPECT_EQ(tc->log().applied_height(), 2u);
}

TEST_F(TreeConsensusCommitTest, ATamperedLogEntryHalts) {
    commit_two_blocks();
    close_tree();
    const auto path = dir / "data" / "tree" / "log" / "2.json";
    auto doc = nlohmann::json::parse(std::ifstream(path));
    doc["block_time_ms"] = doc["block_time_ms"].get<uint64_t>() + 1;
    std::ofstream(path) << doc.dump();

    open_tree();
    EXPECT_FALSE(open_consensus());
    EXPECT_FALSE(tc->healthy());
}

TEST_F(TreeConsensusCommitTest, AMissedBlockHaltsInsteadOfApplying) {
    commit_two_blocks();
    const auto digest = tree_svc->tree_digest();
    // A committed tree block whose previous root is not this log's head: the
    // block before it never reached this server.
    auto other = mirror;
    other.root = filled(0x13);
    const auto gap = tree_block(&blocks[4], 6,
                                TreeBatch{{seal(create_op(customer("gamma", root_key), root_key))}},
                                now_ms + 5, other);
    sec::CommittedPayload committed;
    committed.proposal = gap.proposal;
    committed.payload = &*gap.payload;
    tc->on_committed(committed);
    EXPECT_FALSE(tc->healthy());
    EXPECT_EQ(tree_svc->tree_digest(), digest);
    EXPECT_EQ(tc->log().height(), 2u);
}

// =========================================================================
// Submission (design A2)
// =========================================================================

TEST_F(TreeConsensusTest, SubmitRequiresTier1MembershipAndPrechecks) {
    tc->set_members({members[1], members[2], members[3]});
    EXPECT_EQ(tc->submit(seal(root_op())).verdict.refusal, TreeOpRefusal::Unavailable);
    tc->set_members(members);
    EXPECT_EQ(tc->submit(seal(create_op(customer("acme", root_key), root_key))).verdict.refusal,
              TreeOpRefusal::NotFound);
    std::vector<sec::TreeOpSubmitMsg> forwarded;
    tc->set_broadcast([&](sec::TreeOpSubmitMsg m) { forwarded.push_back(std::move(m)); });
    const auto op = seal(root_op());
    const auto admission = tc->submit(op);
    ASSERT_TRUE(admission.verdict.ok()) << admission.verdict.reason;
    ASSERT_TRUE(admission.ticket);
    ASSERT_EQ(forwarded.size(), 1u);
    EXPECT_EQ(forwarded[0].encoded_op, tree::encode_tree_op(op));
    EXPECT_EQ(tc->status(tree::op_id_hex(op))->status, tree::TreeOpStatus::Pending);
}

TEST_F(TreeConsensusTest, TheLeaderProposesABatchItsReplicaAccepts) {
    const auto root = seal(root_op());
    const auto acme = seal(create_op(customer("acme", root_key), root_key));
    auto r1 = tc->submit(root);
    ASSERT_TRUE(r1.verdict.ok());
    // A forwarded op from another member joins the pool too.
    tc->receive_forwarded(sec::TreeOpSubmitMsg{tree::encode_tree_op(acme),
                                               *tree::tree_op_signature_bytes(acme)},
                          members[2]);
    // acme is refused against the committed tree (no root yet), so only the
    // root op is pooled.
    EXPECT_EQ(tc->status(tree::op_id_hex(acme)), std::nullopt);

    const auto proposed = tc->propose(*service);
    ASSERT_TRUE(proposed.has_value());
    EXPECT_EQ(proposed->timestamp_hint, now_ms);
    const auto batch = tree::decode_tree_batch(proposed->payload.body);
    ASSERT_TRUE(batch.has_value());
    ASSERT_EQ(batch->ops.size(), 1u);
    EXPECT_EQ(batch->ops[0].op_id, root.op_id);
    const auto b = block(nullptr, 1, proposed->payload, proposed->previous_state_root,
                         proposed->proposed_state_root, proposed->timestamp_hint);
    EXPECT_TRUE(deliver(b).vote.has_value());
}

TEST_F(TreeConsensusCommitTest, CommitSettlesTicketsAndRefusesWhatNoLongerValidates) {
    // A queued update of acme at base 1, and a competing one that commits
    // first: the loser is refused with StaleBaseVersion once the winner
    // commits.
    mirror = base_state();
    auto b1 = tree_block(nullptr, 1,
                         TreeBatch{{seal(root_op()),
                                    seal(create_op(customer("acme", root_key), root_key))}},
                         now_ms, mirror);
    auto renamed = customer("acme", root_key);
    renamed.hostname = "winner";
    const auto winner = seal(update_op(renamed, 1));
    renamed.hostname = "loser";
    const auto loser = seal(update_op(renamed, 1));
    ASSERT_TRUE(deliver(b1).vote.has_value());

    // b1 <- c2 <- c3 with a QC over c3 (carried by c4) commits b1.
    auto c2 = block(&b1, 2);
    auto c3 = block(&c2, 3);
    auto c4 = block(&c3, 4);
    for (const auto* b : {&c2, &c3, &c4}) ASSERT_FALSE(deliver(*b).rejected.has_value());
    ASSERT_EQ(tc->log().height(), 1u) << tc->halt_reason();

    // Both updates pass the pre-check against the committed tree.
    const auto win_ticket = tc->submit(winner).ticket;
    const auto lose_ticket = tc->submit(loser).ticket;
    ASSERT_TRUE(win_ticket);
    ASSERT_TRUE(lose_ticket);

    auto mirror2 = tc->log().state();
    auto w = tree_block(&c4, 5, TreeBatch{{winner}}, now_ms + 2, mirror2);
    auto x6 = block(&w, 6);
    auto x7 = block(&x6, 7);
    auto x8 = block(&x7, 8);
    for (const auto* b : {&w, &x6, &x7, &x8}) ASSERT_FALSE(deliver(*b).rejected.has_value());
    ASSERT_EQ(tc->log().height(), 2u) << tc->halt_reason();
    EXPECT_EQ(win_ticket->current().status, tree::TreeOpStatus::Committed);
    EXPECT_EQ(win_ticket->current().log_height, 2u);
    EXPECT_EQ(lose_ticket->current().status, tree::TreeOpStatus::Refused);
    EXPECT_EQ(lose_ticket->current().verdict.refusal, TreeOpRefusal::StaleBaseVersion);
    EXPECT_EQ(tree_svc->get_node("acme")->hostname, "winner");
}

TEST_F(TreeConsensusTest, TheSubmitterWaitsForTheCommitThenReportsPending) {
    tree::TreeOpPool pool;
    std::shared_ptr<tree::TreeOpTicket> last;
    auto gateway = [&](TreeOp op) {
        tree::TreeOpAdmission admission;
        admission.ticket = std::make_shared<tree::TreeOpTicket>(tree::op_id_hex(op));
        last = admission.ticket;
        (void)pool.add(std::move(op), admission.ticket);
        return admission;
    };
    tree::TreeOpSubmitter submitter(*tree_svc, *crypto_svc, network, member_keys[1], gateway,
                                    std::chrono::milliseconds(50));
    EXPECT_TRUE(submitter.ordered());

    // Nobody commits: pending after the wait, nothing applied.
    const auto pending = submitter.submit(root_op());
    EXPECT_TRUE(pending.pending);
    EXPECT_TRUE(pending.verdict.ok());
    EXPECT_FALSE(tree_svc->get_node("root").has_value());

    // A commit that arrives during the wait answers at once.
    tree::TreeOpSubmitter patient(*tree_svc, *crypto_svc, network, member_keys[1], gateway,
                                  std::chrono::milliseconds(5000));
    std::thread committer([&] {
        while (pool.size() < 2) std::this_thread::sleep_for(std::chrono::milliseconds(1));
        pool.settle(last->op_id(), {tree::TreeOpStatus::Committed, {}, 4});
    });
    const auto committed = patient.submit(root_op());
    committer.join();
    EXPECT_FALSE(committed.pending);
    EXPECT_TRUE(committed.verdict.ok());

    // A refusal is reported with its reason.
    const auto refused_gateway = [](TreeOp) {
        return tree::TreeOpAdmission{{TreeOpRefusal::Unavailable, "not Tier 1"}, nullptr};
    };
    tree::TreeOpSubmitter refusing(*tree_svc, *crypto_svc, network, member_keys[1],
                                   refused_gateway, std::chrono::milliseconds(50));
    EXPECT_EQ(refusing.submit(root_op()).verdict.refusal, TreeOpRefusal::Unavailable);
}

TEST(TreeOpPoolTest, LimitsAndOutcomes) {
    tree::TreeOpPool pool(tree::TreeOpPoolLimits{.total = 3, .per_author = 2,
                                                 .per_principal = 2, .remembered_outcomes = 2});
    auto op = [](const std::string& author, const std::string& principal, uint8_t n) {
        TreeOp o;
        o.author = author;
        o.principal = principal;
        o.op_id.fill(n);
        return o;
    };
    EXPECT_EQ(pool.add(op("a", "p", 1), nullptr), tree::TreeOpPool::Admit::Added);
    EXPECT_EQ(pool.add(op("a", "p", 1), nullptr), tree::TreeOpPool::Admit::Duplicate);
    EXPECT_EQ(pool.add(op("a", "q", 2), nullptr), tree::TreeOpPool::Admit::Added);
    EXPECT_EQ(pool.add(op("a", "r", 3), nullptr), tree::TreeOpPool::Admit::AuthorLimit);
    EXPECT_EQ(pool.add(op("b", "p", 4), nullptr), tree::TreeOpPool::Admit::Added);
    EXPECT_EQ(pool.add(op("c", "p", 5), nullptr), tree::TreeOpPool::Admit::Full);

    const auto id1 = tree::op_id_hex(op("a", "p", 1));
    auto ticket = std::make_shared<tree::TreeOpTicket>(id1);
    bool continued = false;
    ticket->on_settled([&](const tree::TreeOpOutcome& o) {
        continued = o.status == tree::TreeOpStatus::Refused;
    });
    pool.settle(id1, {tree::TreeOpStatus::Refused, {TreeOpRefusal::Stale, "old"}, 0});
    ticket->settle({tree::TreeOpStatus::Refused, {TreeOpRefusal::Stale, "old"}, 0});
    ticket->settle({tree::TreeOpStatus::Committed, {}, 1});  // first settle wins
    EXPECT_TRUE(continued);
    EXPECT_EQ(ticket->current().status, tree::TreeOpStatus::Refused);
    EXPECT_EQ(pool.status(id1)->status, tree::TreeOpStatus::Refused);
    EXPECT_EQ(pool.size(), 2u);
    // A settled op id is not admitted again.
    EXPECT_EQ(pool.add(op("a", "p", 1), nullptr), tree::TreeOpPool::Admit::Duplicate);
}

// =========================================================================
// Closed Phase 1 gaps: tunnel addresses, root, heartbeat, committed ids
// =========================================================================

TEST_F(TreeConsensusTest, TunnelAddressesAreAFunctionOfTheTree) {
    tree::rules::NodeMap nodes;
    const auto a = tree::derive_tunnel_address(nodes, "node-a");
    EXPECT_EQ(a, tree::derive_tunnel_address(nodes, "node-a"));
    ASSERT_TRUE(a.ends_with("/32"));
    // Inside the tree range, above the IPAM range 10.64.0.0/16.
    EXPECT_FALSE(a.starts_with("10.64."));
    EXPECT_TRUE(a.starts_with("10."));

    // A taken address moves the next node with the same start onward, and is
    // free again once its node is gone.
    tree::TreeNode holder;
    holder.id = "holder";
    holder.tunnel_ip = a;
    nodes["holder"] = holder;
    const auto b = tree::derive_tunnel_address(nodes, "node-a");
    EXPECT_NE(a, b);
    nodes.erase("holder");
    EXPECT_EQ(tree::derive_tunnel_address(nodes, "node-a"), a);
}

TEST_F(TreeConsensusTest, OnlyTheConfiguredKeyEstablishesTheRootOnce) {
    tree::TreeOpPolicy policy = tc->policy_for(members);
    tree::rules::NodeMap nodes;
    tree::CommittedOpIds none;
    const tree::TreeState state(nodes, policy);
    EXPECT_TRUE(tree::validate_op(*crypto_svc, seal(root_op()), state, kNowSec, none).ok());
    auto other = root_op();
    other.principal = principal_of(stranger_kp);
    EXPECT_EQ(tree::validate_op(*crypto_svc, seal(other), state, kNowSec, none).refusal,
              TreeOpRefusal::Forbidden);
    tree::TreeOpPolicy no_root = policy;
    no_root.root_key.clear();
    EXPECT_EQ(tree::validate_op(*crypto_svc, seal(root_op()), tree::TreeState(nodes, no_root),
                                kNowSec, none)
                  .refusal,
              TreeOpRefusal::Forbidden);
    nodes["root"] = tree::make_root_node(root_key);
    EXPECT_EQ(tree::validate_op(*crypto_svc, seal(root_op()), state, kNowSec, none).refusal,
              TreeOpRefusal::AlreadyExists);
}

TEST_F(TreeConsensusTest, OnlyANodesOwnKeySetsItsEndpoint) {
    tree::TreeOpPolicy policy = tc->policy_for(members);
    tree::rules::NodeMap nodes;
    nodes["root"] = tree::make_root_node(root_key);
    auto dev = customer("dev", principal_of(stranger_kp));
    dev.version = 3;
    nodes["dev"] = dev;
    tree::CommittedOpIds none;
    const tree::TreeState state(nodes, policy);
    TreeOp op;
    op.kind = TreeOpKind::SetEndpoint;
    op.target = "dev";
    op.base_version = 3;
    op.principal = principal_of(stranger_kp);
    op.body.source = TreeOpSource::Session;
    op.body.listen_endpoint = "198.51.100.7:51940";
    EXPECT_TRUE(tree::validate_op(*crypto_svc, seal(op), state, kNowSec, none).ok());
    auto foreign = op;
    foreign.principal = root_key;  // even the root admin does not speak for the device
    EXPECT_EQ(tree::validate_op(*crypto_svc, seal(foreign), state, kNowSec, none).refusal,
              TreeOpRefusal::Forbidden);
    auto garbage = op;
    garbage.body.listen_endpoint = "not an endpoint";
    EXPECT_EQ(tree::validate_op(*crypto_svc, seal(garbage), state, kNowSec, none).refusal,
              TreeOpRefusal::Malformed);
    tree::TreeOpEffect effect;
    ASSERT_TRUE(tree::plan_op(seal(op), nodes, effect).ok());
    ASSERT_EQ(effect.writes.size(), 1u);
    EXPECT_EQ(effect.writes[0].listen_endpoint, "198.51.100.7:51940");
    EXPECT_EQ(effect.writes[0].version, 4u);
}

TEST_F(TreeConsensusTest, LocallyCommittedIdsSurviveARestart) {
    tree::TreeOpPolicy policy;
    policy.network_id = network;
    policy.trusted_submitters = {principal_of(member_keys[1])};
    policy.root_key = root_key;
    const auto op = seal(root_op());
    ASSERT_TRUE(tree_svc->submit_local_op(op, policy, kNowSec).ok());
    close_tree();
    open_tree();
    // Replay is checked before target existence, so Replayed (not
    // AlreadyExists) proves the committed id came back from disk.
    EXPECT_EQ(tree_svc->validate_local_op(op, policy, kNowSec).refusal, TreeOpRefusal::Replayed);

    // An unreadable record fails closed instead of forgetting every id.
    close_tree();
    std::ofstream(dir / "data" / "tree" / "committed-ops.json") << "{not json";
    open_tree();
    EXPECT_EQ(tree_svc->validate_local_op(seal(root_op()), policy, kNowSec).refusal,
              TreeOpRefusal::StorageError);
}
