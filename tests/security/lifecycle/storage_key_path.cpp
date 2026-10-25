// The threshold storage key on the memory mesh (design Part B, Phase 5).
//
// Founders and reserves run the real driver, router, HotStuff, and storage
// key service over encoded envelopes. The first boundary's finalized
// eligibility pool selects the holders; Tier 1 finalizes the selection and
// the plan; the holders run the storage-threshold key generation over the
// security transport; every server wraps a data key to S and unlocks it
// through attested holders. The attestation verifier's positive path needs a
// confidential VM, so StorageUnlock verdicts are injected into the challenging
// holder, exactly like the other lifecycle tests inject eligibility verdicts.

#include "support/lifecycle_mesh.hpp"
#include "support/rotation.hpp"

#include <LemonadeNexus/Crypto/StorageThreshold.hpp>
#include <LemonadeNexus/Security/Storage/DataKeyService.hpp>
#include <LemonadeNexus/Security/Storage/StorageKeyService.hpp>
#include <LemonadeNexus/Security/Storage/StorageShareStore.hpp>
#include <LemonadeNexus/Security/Storage/StorageVault.hpp>

#include <nlohmann/json.hpp>

#include <fstream>
#include <functional>
#include <iterator>

namespace lifecycle_test {
namespace {

using nexus::crypto::StorageThreshold;

/// Unix milliseconds of mesh time zero. The storage wall clock is this plus
/// mesh time plus a test-controlled offset, so a test can move block time a
/// day forward without aging the epoch the driver measures.
constexpr uint64_t kWallBase = 1'800'000'000'000ULL;
constexpr uint64_t kDayMs = 24ULL * 3600 * 1000;

struct StorageStack {
    std::unique_ptr<FileStorageShareStore> shares;
    std::unique_ptr<StorageKeyService> service;
};

class StorageKeyPath : public RotatingMeshBase {
protected:
    void TearDown() override {
        vaults.clear();
        for (auto& [id, stack] : stacks) {
            stack.service.reset();
        }
        stacks.clear();
        DriverMeshBase::TearDown();
    }

    void on_node_built(Node& node) override {
        if (&node != genesis_node) {
            build_storage(node);
        }
    }

    void on_tick(Node& node) override {
        if (auto it = stacks.find(node.id); it != stacks.end() && it->second.service) {
            it->second.service->tick(mesh.now_ms);
        }
        if (auto it = vaults.find(node.id); it != vaults.end()) {
            it->second->tick(kWallBase + mesh.now_ms + wall_offset_ms);
        }
    }

    /// (Re)builds a node's storage service from its directories, as a process
    /// restart of the storage side would: the data key leaves memory. Returns
    /// what start() returned; `expect_start` makes a refusal a test failure.
    bool build_storage(Node& node, bool expect_start = true) {
        auto& stack = stacks[node.id];
        if (auto it = vaults.find(node.id); it != vaults.end()) it->second->attach(nullptr);
        stack.service.reset();
        stack.shares = std::make_unique<FileStorageShareStore>(
            node.dir / "storage" / "sealed", node.crypto.get(), node.wrapping.get(),
            node.identity.public_key);
        StorageKeyServiceConfig config;
        config.self = node.id;
        config.identity = node.identity;
        config.network_id = network;
        config.directory = node.dir / "storage";
        config.wall_clock_ms = [this] { return kWallBase + mesh.now_ms + wall_offset_ms; };
        config.files_encrypted = [this, id = node.id] {
            const auto it = vaults.find(id);
            return it != vaults.end() && it->second != nullptr &&
                   it->second->mode() == VaultMode::Encrypted;
        };
        stack.service = std::make_unique<StorageKeyService>(
            std::move(config), *node.driver, *node.router, *node.runtime, *node.sealer,
            *stack.shares, *node.crypto);
        stack.service->attach();
        auto* service = stack.service.get();
        node.storage_gate = [service](const NodeId& holder, const Digest& context) {
            return service->expects_unlock_challenge(holder, context);
        };
        const bool started = stack.service->start(mesh.now_ms);
        if (expect_start) {
            EXPECT_TRUE(started) << stack.service->halt_reason();
        }
        if (auto it = vaults.find(node.id); it != vaults.end()) {
            it->second->attach(&stack.service->data_keys());
        }
        return started;
    }

    /// The node's file vault (Phase 7) over <dir>/files, rebuilt from disk
    /// like a process restart. `seed` writes plaintext files first.
    StorageVault& build_vault(Node& node, bool seed) {
        const auto root = node.dir / "files";
        if (seed) {
            for (const auto& [rel, text] : vault_files) {
                std::filesystem::create_directories((root / rel).parent_path());
                std::ofstream(root / rel, std::ios::binary | std::ios::trunc) << text;
            }
        }
        auto& vault = vaults[node.id];
        vault.reset();
        vault = std::make_unique<StorageVault>(root, node.dir / "storage", *node.crypto);
        vault->load();
        vault->attach(&storage(&node).data_keys());
        return *vault;
    }

    static std::string raw_file(const std::filesystem::path& path) {
        std::ifstream in(path, std::ios::binary);
        return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    }

    static void write_file(const std::filesystem::path& path, const std::string& text) {
        std::ofstream(path, std::ios::binary | std::ios::trunc) << text;
    }

    /// The R of `node`'s first wrap in its finalized claim, as `observer` holds it.
    StoragePointBytes claimed_point(const Node* observer, const Node* node) {
        return storage(observer).chain().wrap_claims.at(node->id).wraps.front().ephemeral_point;
    }

    /// Steps until the current plan is a finished rotation away from `from`
    /// that every online server holds.
    bool run_until_rotated_from(const Digest& from) {
        return run_storage_until([&] {
            const auto& chain = storage(founders.front()).chain();
            return chain.current.has_value() && chain.current_digest != from &&
                   chain.current->operation == StorageOperation::Rotate &&
                   !chain.pending.has_value() &&
                   all_current(online(storage_nodes()), chain.current_digest);
        });
    }

    void expect_vault_files(Node& node) {
        for (const auto& [rel, text] : vault_files) {
            const auto read = vaults.at(node.id)->read(node.dir / "files" / rel);
            ASSERT_EQ(read.status, VaultReadStatus::Ok) << rel;
            EXPECT_EQ(read.bytes, text) << rel;
            EXPECT_TRUE(raw_file(node.dir / "files" / rel).starts_with("LNXVAULT")) << rel;
        }
    }

    bool vault_done(Node& node) {
        const auto& vault = *vaults.at(node.id);
        return vault.mode() == VaultMode::Encrypted && vault.phase() == VaultPhase::Idle &&
               !vault.rotation_requested();
    }

    StorageKeyService& storage(const Node* node) { return *stacks.at(node->id).service; }

    std::vector<Node*> storage_nodes() const {
        std::vector<Node*> out(founders.begin(), founders.end());
        out.insert(out.end(), reserves.begin(), reserves.end());
        return out;
    }

    std::vector<Node*> online(const std::vector<Node*>& nodes_in) const {
        std::vector<Node*> out;
        for (Node* node : nodes_in) {
            if (!mesh.offline.contains(node->id)) out.push_back(node);
        }
        return out;
    }

    /// Answers every captured StorageUnlock challenge the way a producer and
    /// a verifier would: a verdict for exactly that challenge, injected into
    /// the challenging holder. Subjects in `refuse_attestation` fail.
    void answer_storage_challenges() {
        if (mesh.captured_storage_challenges.empty()) {
            return;
        }
        auto pending = std::move(mesh.captured_storage_challenges);
        mesh.captured_storage_challenges.clear();
        for (const auto& [challenger, challenge] : pending) {
            if (mesh.offline.contains(challenge.node_id) || mesh.offline.contains(challenger)) {
                continue;
            }
            AttestationVerdict verdict = passing_verdict(challenge.node_id, challenge.epoch,
                                                         storage_round_++, challenge.incarnation);
            verdict.purpose = challenge.purpose;
            verdict.context_digest = challenge.context_digest;
            if (refuse_attestation.contains(challenge.node_id)) {
                verdict.passed = false;
                verdict.failure = AttestationFailure::SnpInvalid;
                verdict.claims = VerifiedPlatformClaims{};
            }
            mesh.nodes.at(challenger)
                ->driver->on_attestation_verdict(verdict, evidence_for(challenge.node_id, {}));
        }
        mesh.pump();
    }

    /// One tick for every online founder and reserve: driver, storage, and
    /// the injected attestation answers.
    void storage_step(int count = 1) {
        for (int i = 0; i < count; ++i) {
            mesh.now_ms += 200;
            for (Node* node : online(storage_nodes())) {
                node->driver->tick(mesh.now_ms);
                on_tick(*node);
            }
            mesh.pump();
            answer_storage_challenges();
        }
    }

    bool run_storage_until(const std::function<bool()>& done, int max_steps = 1500) {
        for (int i = 0; i < max_steps; ++i) {
            if (done()) return true;
            storage_step();
        }
        return done();
    }

    /// True when every node in `nodes_in` holds `digest` as its current plan.
    bool all_current(const std::vector<Node*>& nodes_in, const Digest& digest) {
        return std::all_of(nodes_in.begin(), nodes_in.end(), [&](Node* node) {
            return storage(node).chain().current_digest == digest;
        });
    }

    bool all_unlocked(const std::vector<Node*>& nodes_in) {
        return std::all_of(nodes_in.begin(), nodes_in.end(), [&](Node* node) {
            const auto& keys = storage(node).data_keys();
            return keys.state() == DataKeyState::Unlocked && keys.unlock_verified();
        });
    }

    /// Bootstrap, one production boundary over `pool`, then step until every
    /// founder holds the same finalized first plan and every server's data
    /// key is created and verified through the holders.
    void create_key(const std::vector<Node*>& pool) {
        bootstrap();
        ASSERT_FALSE(::testing::Test::HasFatalFailure());
        members = rotate(founders, pool, 1);
        ASSERT_FALSE(::testing::Test::HasFatalFailure());
        if (pool.size() == founders.size()) {
            ASSERT_EQ(ids_of(members), ids_of(founders));
        }
        ASSERT_TRUE(run_storage_until([&] {
            const auto& first = storage(founders.front()).chain();
            return first.current.has_value() && first.pending == std::nullopt &&
                   all_current(storage_nodes(), first.current_digest) &&
                   all_unlocked(storage_nodes());
        })) << "no storage key and verified data keys on every server";
    }

    const StorageFinalPlan& current_plan() {
        return *storage(founders.front()).chain().current;
    }

    std::vector<Node*> holders_of(const StorageFinalPlan& plan) {
        std::vector<Node*> out;
        for (const auto& holder : plan.holders) out.push_back(mesh.nodes.at(holder.node));
        return out;
    }

    /// The share a holder keeps for `plan_digest`, read from its share store
    /// the way the service reads it at start.
    std::optional<nexus::crypto::StorageKeyShare> share_of(const Node* node,
                                                           const Digest& plan_digest) {
        auto unsealed = stacks.at(node->id).shares->unseal(kStorageShareDomain);
        if (unsealed.status != ShareStoreStatus::Ok) return std::nullopt;
        auto bundle = decode_share_bundle(unsealed.plaintext.span());
        if (!bundle.has_value() || !bundle->contains(plan_digest)) return std::nullopt;
        auto share = StorageThreshold::deserialize_share(bundle->at(plan_digest).span());
        if (!share.ok()) return std::nullopt;
        return std::move(*share.value);
    }

    std::vector<uint8_t> data_key_bytes(const Node* node) {
        const auto key = storage(node).data_keys().data_key();
        if (!key.has_value()) return {};
        return {key->data(), key->data() + key->size()};
    }

    /// Mutes one node's storage session packages (an unreachable holder) while
    /// it keeps voting.
    void mute_storage_packages(const std::set<NodeId>& muted) {
        mesh.drop_if = [muted](const Queued& item, const SecurityMessage& message) {
            return message.kind == SecurityMessageKind::StorageKeyPackage &&
                   muted.contains(item.from);
        };
    }

    /// Records every unlock request `requester` sends, then applies the
    /// optional storage-package mute.
    void capture_requests(const Node* requester, std::set<NodeId> muted = {}) {
        const NodeId who = requester->id;
        mesh.drop_if = [this, who, muted](const Queued& item, const SecurityMessage& message) {
            if (const auto* request = std::get_if<StorageUnlockRequestMsg>(&message.body);
                request != nullptr && item.from == who) {
                captured_requests.push_back(*request);
            }
            return message.kind == SecurityMessageKind::StorageKeyPackage &&
                   muted.contains(item.from);
        };
    }

    /// The captured request the requester's live attempt sent.
    std::optional<StorageUnlockRequestMsg> live_request_of(const Node* requester) {
        const auto live = storage(requester).data_keys().live_request();
        if (!live.has_value()) return std::nullopt;
        for (const auto& request : captured_requests) {
            if (storage_unlock_request_digest(network, request) == *live) return request;
        }
        return std::nullopt;
    }

    /// A partial from `holder` for `request`, built from the holder's sealed
    /// share for `plan` and delivered straight to the requester's storage
    /// service. `mutate` changes the 96 bytes before sealing; `other_point`
    /// computes it for another R.
    void deliver_partial(const Node* holder, const Node* requester,
                         const StorageUnlockRequestMsg& request, const StorageFinalPlan& plan,
                         const Digest& plan_digest,
                         const std::function<void(nexus::crypto::StoragePartial&)>& mutate,
                         std::optional<StoragePointBytes> other_point = std::nullopt) {
        auto share = share_of(holder, plan_digest);
        ASSERT_TRUE(share.has_value());
        const auto context = StorageKeyService::unlock_context(network, request);
        const StoragePointBytes point = other_point.value_or(request.ephemeral_point);
        auto partial = StorageThreshold::create_partial(*share, plan.key_plan, context, point);
        ASSERT_TRUE(partial.ok());
        if (mutate) mutate(*partial.value);
        const Digest request_digest = storage_unlock_request_digest(network, request);
        auto sealed = holder->sealer->seal_bound_for(requester->id, request_digest,
                                                     std::span<const uint8_t>(*partial.value));
        ASSERT_TRUE(sealed.has_value());
        uint16_t holder_id = 0;
        for (const auto& h : plan.holders) {
            if (h.node == holder->id) holder_id = h.holder_id;
        }
        StorageUnlockPartialMsg message;
        message.holder = holder->id;
        message.request_digest = request_digest;
        message.holder_id = holder_id;
        message.sealed_partial = std::move(*sealed);
        storage(requester).on_message(holder->router->compose(
            SecurityMessageKind::StorageUnlockPartial, message, request.epoch));
    }

    /// Lets in-flight answers from earlier attempts settle, so a counter read
    /// afterwards measures only what follows.
    void settle() {
        for (int i = 0; i < 100; ++i) storage_step();
    }

    /// The current Tier 1 members (after create_key, the epoch-2 set).
    std::vector<Node*> members;
    std::map<NodeId, StorageStack> stacks;
    std::map<NodeId, std::unique_ptr<StorageVault>> vaults;
    const std::map<std::string, std::string> vault_files = {
        {"identity/keypair.enc", "v2:1:0011:2233"},
        {"identity/jwt_secret.hex", "abcdef0123456789"},
        {"tree/nodes/root.json", "{\"id\":\"root\"}"},
        {"tree/log/1.json", "{\"height\":1}"},
    };
    std::vector<StorageUnlockRequestMsg> captured_requests;
    std::set<NodeId> refuse_attestation;
    uint64_t wall_offset_ms = 0;
    uint8_t storage_round_ = 0x80;
};

// --- Key creation and plan agreement ---------------------------------------------

TEST_F(StorageKeyPath, KeyIsCreatedAtTheBoundaryAndEveryReplicaHoldsTheSamePlan) {
    create_key(founders);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    const auto& plan = current_plan();
    EXPECT_EQ(plan.operation, StorageOperation::Create);
    EXPECT_EQ(plan.holders.size(), founders.size());
    EXPECT_EQ(plan.threshold, 4);
    EXPECT_EQ(plan.effective_epoch, 2u);
    // Byte-for-byte: every server holds the same record, plan bytes, and S.
    const Digest digest = storage(founders.front()).chain().current_digest;
    for (Node* node : storage_nodes()) {
        const auto& chain = storage(node).chain();
        ASSERT_TRUE(chain.current.has_value());
        EXPECT_EQ(chain.current_digest, digest);
        EXPECT_EQ(chain.current->key_plan, plan.key_plan);
        EXPECT_EQ(chain.current->storage_public_key, plan.storage_public_key);
    }
    for (Node* holder : holders_of(plan)) {
        EXPECT_TRUE(storage(holder).holds_share(digest));
    }
    // Every server wrapped its data key to S and proved it opens.
    for (Node* node : storage_nodes()) {
        EXPECT_EQ(storage(node).data_keys().wrapped_to(), plan.storage_public_key);
    }
}

// --- Unlock (B7) and cold start (B8) ------------------------------------------------

TEST_F(StorageKeyPath, ColdStartUnlocksWithExactlyTHoldersAndNotWithTMinusOne) {
    create_key(founders);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    ASSERT_EQ(current_plan().threshold, 4);
    Node* requester = founders[0];
    const auto data_key = data_key_bytes(requester);
    ASSERT_EQ(data_key.size(), 32u);

    // Exactly t: the requester (a holder) and three other holders are up.
    mesh.offline.insert(founders[4]->id);
    build_storage(*requester);
    // After the restart the data key is not in memory; only the holders can
    // give it back.
    EXPECT_FALSE(storage(requester).data_keys().data_key().has_value());
    ASSERT_TRUE(run_storage_until(
        [&] { return storage(requester).data_keys().state() == DataKeyState::Unlocked; }));
    EXPECT_EQ(data_key_bytes(requester), data_key);

    // t - 1: one more holder down. The requester retries with backoff and
    // stays locked; nothing hands it the data key.
    mesh.offline.insert(founders[3]->id);
    build_storage(*requester);
    for (int i = 0; i < 600; ++i) storage_step();
    EXPECT_EQ(storage(requester).data_keys().state(), DataKeyState::Locked);
    EXPECT_FALSE(storage(requester).data_keys().data_key().has_value());
    EXPECT_GE(storage(requester).data_keys().attempts(), 2u);

    // The holder returns; the next attempt unlocks.
    mesh.offline.erase(founders[3]->id);
    ASSERT_TRUE(run_storage_until(
        [&] { return storage(requester).data_keys().state() == DataKeyState::Unlocked; }));
    EXPECT_EQ(data_key_bytes(requester), data_key);
}

TEST_F(StorageKeyPath, RequesterRejectsBadPartialsAndCountsOnlyVerifiedOnes) {
    create_key(founders);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    const StorageFinalPlan plan = current_plan();
    const Digest plan_digest = storage(founders.front()).chain().current_digest;
    Node* requester = founders[0];
    Node* forger = founders[3];
    const auto data_key = data_key_bytes(requester);

    // Only the requester and two holders answer: one partial short of t.
    mesh.offline.insert(founders[3]->id);
    mesh.offline.insert(founders[4]->id);
    capture_requests(requester);
    build_storage(*requester);
    ASSERT_TRUE(run_storage_until([&] { return live_request_of(requester).has_value(); }, 50));
    for (int i = 0; i < 5; ++i) storage_step();
    const auto request = live_request_of(requester);
    ASSERT_TRUE(request.has_value());
    ASSERT_EQ(storage(requester).data_keys().state(), DataKeyState::Locked);

    // A partial with an invalid DLEQ proof does not count.
    deliver_partial(forger, requester, *request, plan, plan_digest,
                    [](nexus::crypto::StoragePartial& p) { p[40] ^= 0x01; });
    EXPECT_EQ(storage(requester).data_keys().state(), DataKeyState::Locked);

    // A valid partial for a different R does not count.
    auto other = StorageThreshold::wrap_data_key(*requester->crypto, plan.storage_public_key,
                                                 std::vector<uint8_t>(32, 7),
                                                 std::vector<uint8_t>{'x'});
    ASSERT_TRUE(other.ok());
    deliver_partial(forger, requester, *request, plan, plan_digest, {},
                    other.value->ephemeral_point);
    EXPECT_EQ(storage(requester).data_keys().state(), DataKeyState::Locked);

    // The genuine partial is the t-th and unlocks.
    deliver_partial(forger, requester, *request, plan, plan_digest, {});
    EXPECT_EQ(storage(requester).data_keys().state(), DataKeyState::Unlocked);
    EXPECT_EQ(data_key_bytes(requester), data_key);
}

TEST_F(StorageKeyPath, HolderRefusesARequesterWithoutAPassingAttestation) {
    create_key(founders);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    Node* requester = founders[1];
    settle();
    // The other holders' partial counts; the requester's own service restarts.
    uint64_t sent_before = 0;
    for (Node* holder : founders) {
        if (holder != requester) sent_before += storage(holder).partials_sent();
    }

    refuse_attestation.insert(requester->id);
    build_storage(*requester);
    for (int i = 0; i < 300; ++i) storage_step();
    EXPECT_EQ(storage(requester).data_keys().state(), DataKeyState::Locked);
    uint64_t sent_after = 0;
    uint64_t refused = 0;
    for (Node* holder : founders) {
        if (holder == requester) continue;
        sent_after += storage(holder).partials_sent();
        refused += storage(holder).drops(StorageDrop::AttestationFailed);
    }
    EXPECT_EQ(sent_after, sent_before);
    EXPECT_GT(refused, 0u);

    refuse_attestation.clear();
    ASSERT_TRUE(run_storage_until(
        [&] { return storage(requester).data_keys().state() == DataKeyState::Unlocked; }));
}

TEST_F(StorageKeyPath, ReplayedUnlockRequestIsRefused) {
    create_key(founders);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    Node* requester = founders[0];
    Node* holder = founders[2];
    capture_requests(requester);
    build_storage(*requester);
    ASSERT_TRUE(run_storage_until(
        [&] { return storage(requester).data_keys().state() == DataKeyState::Unlocked; }));
    // The request the holder answered.
    std::optional<StorageUnlockRequestMsg> request;
    for (const auto& sent : captured_requests) {
        if (sent.requester == requester->id) request = sent;
    }
    ASSERT_TRUE(request.has_value());

    // The identical envelope again: the router's replay window drops it.
    const auto envelope = encode_security_message(requester->router->compose(
        SecurityMessageKind::StorageUnlockRequest, *request, request->epoch));
    const auto routed = holder->router->receive(requester->id, envelope, mesh.now_ms);
    EXPECT_EQ(routed.dropped, DropReason::Duplicate);
    // Past the router, the holder's record of answered requests refuses it.
    const uint64_t before = storage(holder).drops(StorageDrop::Replay);
    storage(holder).on_message(requester->router->compose(
        SecurityMessageKind::StorageUnlockRequest, *request, request->epoch));
    EXPECT_EQ(storage(holder).drops(StorageDrop::Replay), before + 1);
}

TEST_F(StorageKeyPath, UnlockAndSessionBudgetsBind) {
    create_key(founders);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    Node* requester = founders[0];
    Node* holder = founders[1];
    const Digest plan_digest = storage(holder).chain().current_digest;
    const StoragePointBytes point = claimed_point(holder, requester);
    const auto make = [&](uint8_t seed) {
        StorageUnlockRequestMsg request;
        request.requester = requester->id;
        request.epoch = storage(holder).current_epoch();
        request.plan_digest = plan_digest;
        request.ephemeral_point = point;
        request.nonce.fill(seed);
        return requester->router->compose(SecurityMessageKind::StorageUnlockRequest, request,
                                          request.epoch);
    };
    // One pending request per requester at a holder: a second one waits.
    storage(holder).on_message(make(1));
    const uint64_t busy = storage(holder).drops(StorageDrop::PendingBusy);
    storage(holder).on_message(make(2));
    EXPECT_EQ(storage(holder).drops(StorageDrop::PendingBusy), busy + 1);

    // Each accepted request spends the per-epoch budget until it runs out.
    int accepted = 1;
    for (uint8_t seed = 3; seed < 40; ++seed) {
        mesh.now_ms += constants::kStorageUnlockPendingMs;
        storage(holder).tick(mesh.now_ms);
        const uint64_t exceeded = storage(holder).drops(StorageDrop::BudgetExceeded);
        storage(holder).on_message(make(seed));
        if (storage(holder).drops(StorageDrop::BudgetExceeded) != exceeded) break;
        ++accepted;
    }
    EXPECT_LE(accepted, static_cast<int>(constants::kStorageUnlocksPerRequesterPerEpoch));
    EXPECT_GT(storage(holder).drops(StorageDrop::BudgetExceeded), 0u);

    // A request for a plan the holder does not hold is refused outright.
    StorageUnlockRequestMsg unknown;
    unknown.requester = requester->id;
    unknown.epoch = storage(holder).current_epoch();
    unknown.plan_digest.fill(0x42);
    const uint64_t before = storage(holder).drops(StorageDrop::UnknownPlan);
    storage(holder).on_message(requester->router->compose(
        SecurityMessageKind::StorageUnlockRequest, unknown, unknown.epoch));
    EXPECT_EQ(storage(holder).drops(StorageDrop::UnknownPlan), before + 1);

    // A session package for a session nobody runs is dropped before any
    // library call: one session per finalized selection.
    StorageKeyPackageMsg stray;
    stray.session.fill(0x33);
    stray.sender = requester->id;
    stray.payload = {1, 2, 3};
    const uint64_t unknown_session = storage(holder).drops(StorageDrop::UnknownSession);
    storage(holder).on_message(
        requester->router->compose(SecurityMessageKind::StorageKeyPackage, stray, 2));
    EXPECT_EQ(storage(holder).drops(StorageDrop::UnknownSession), unknown_session + 1);
}

// --- Re-sharing (B5) -------------------------------------------------------------------

TEST_F(StorageKeyPath, PerEpochRefreshKeepsSAndRetiresPreRefreshShares) {
    create_key(founders);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    const StorageFinalPlan before = current_plan();
    const Digest before_digest = storage(founders.front()).chain().current_digest;
    auto stale = share_of(founders[0], before_digest);
    ASSERT_TRUE(stale.has_value());
    const auto data_key = data_key_bytes(founders[1]);

    // The next boundary refreshes the shares: same holders, same t, same S.
    members = rotate(members, founders, 2);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    ASSERT_TRUE(run_storage_until([&] {
        const auto& chain = storage(founders.front()).chain();
        return chain.current_digest != before_digest && !chain.pending.has_value() &&
               all_current(storage_nodes(), chain.current_digest);
    }));
    const StorageFinalPlan after = current_plan();
    const Digest after_digest = storage(founders.front()).chain().current_digest;
    EXPECT_EQ(after.operation, StorageOperation::Refresh);
    EXPECT_EQ(after.effective_epoch, 3u);
    EXPECT_EQ(after.storage_public_key, before.storage_public_key);
    EXPECT_EQ(after.threshold, before.threshold);
    EXPECT_EQ(after.holders, before.holders);
    EXPECT_NE(after.key_plan, before.key_plan);
    for (Node* holder : founders) {
        EXPECT_TRUE(storage(holder).holds_share(after_digest));
        EXPECT_FALSE(storage(holder).holds_share(before_digest));
        EXPECT_FALSE(share_of(holder, before_digest).has_value());
    }
    // Data keys need no rewrap: S did not change.
    for (Node* node : storage_nodes()) {
        EXPECT_EQ(storage(node).data_keys().wrapped_to(), after.storage_public_key);
    }

    // A pre-refresh share combined with post-refresh shares does not unwrap.
    const std::vector<uint8_t> secret(32, 0x5C);
    const std::vector<uint8_t> server{'t'};
    auto wrapped = StorageThreshold::wrap_data_key(*founders[0]->crypto,
                                                   after.storage_public_key, secret, server);
    ASSERT_TRUE(wrapped.ok());
    nexus::crypto::StorageUnlockContext context;
    context.network_id = network;
    context.epoch = 3;
    context.plan_digest = after_digest;
    context.request_nonce.fill(9);
    const auto partial_of = [&](const nexus::crypto::StorageKeyShare& share,
                                const StorageFinalPlan& plan) {
        auto p = StorageThreshold::create_partial(share, plan.key_plan, context,
                                                  wrapped.value->ephemeral_point);
        EXPECT_TRUE(p.ok());
        return p.ok() ? nexus::crypto::StorageBytes(p.value->begin(), p.value->end())
                      : nexus::crypto::StorageBytes{};
    };
    // Holder identifiers follow the plan, not the founder order.
    uint16_t stale_id = 0;
    std::size_t others = 0;
    nexus::crypto::StoragePeerBytesMap partials;
    for (const auto& holder : after.holders) {
        if (holder.node == founders[0]->id) {
            stale_id = holder.holder_id;
            partials[holder.holder_id] = partial_of(*stale, before);
        } else if (others + 1 < after.threshold) {
            ++others;
            partials[holder.holder_id] =
                partial_of(*share_of(mesh.nodes.at(holder.node), after_digest), after);
        }
    }
    ASSERT_NE(stale_id, 0);
    ASSERT_EQ(partials.size(), after.threshold);
    EXPECT_EQ(StorageThreshold::unwrap_data_key(*founders[0]->crypto, *wrapped.value,
                                                after.key_plan, context, partials, server)
                  .status,
              nexus::crypto::StorageStatus::InvalidProof);
    partials[stale_id] = partial_of(*share_of(founders[0], after_digest), after);
    EXPECT_TRUE(StorageThreshold::unwrap_data_key(*founders[0]->crypto, *wrapped.value,
                                                  after.key_plan, context, partials, server)
                    .ok());

    // A cold start after the refresh unlocks under the refreshed plan.
    build_storage(*founders[1]);
    ASSERT_TRUE(run_storage_until(
        [&] { return storage(founders[1]).data_keys().state() == DataKeyState::Unlocked; }));
    EXPECT_EQ(data_key_bytes(founders[1]), data_key);
}

TEST_F(StorageKeyPath, RemovedHolderShareStopsCountingAfterTheReshare) {
    // Six eligible servers (the five founders and one reserve) hold the first
    // key: 6 holders, t = 4. Tier 1 has five members, so one holder is a
    // Tier 2 server that holds a share and answers unlocks outside Tier 1.
    std::vector<Node*> pool(founders.begin(), founders.end());
    pool.push_back(reserves[0]);
    create_key(pool);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    const StorageFinalPlan before = current_plan();
    const Digest before_digest = storage(founders.front()).chain().current_digest;
    ASSERT_EQ(before.holders.size(), 6u);
    ASSERT_EQ(before.threshold, 4);
    Node* removed = nullptr;
    for (Node* node : pool) {
        if (std::find(members.begin(), members.end(), node) == members.end()) removed = node;
    }
    ASSERT_NE(removed, nullptr);
    ASSERT_FALSE(removed->driver->is_tier1_member());
    ASSERT_TRUE(storage(removed).holds_share(before_digest));
    EXPECT_GT(storage(removed).partials_sent(), 0u);
    auto removed_share = share_of(removed, before_digest);
    ASSERT_TRUE(removed_share.has_value());

    // At the next boundary the Tier 2 holder stops answering. Either the
    // boundary already leaves it out, or the 6-holder refresh times out and
    // runs again without it. 5 holders keep t = 4, so it stays a refresh and
    // S stays.
    mute_storage_packages({removed->id});
    members = rotate(members, pool, 2);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    // A current member other than the removed holder: a founder left out of
    // Tier 1 may lag on records.
    Node* lead = members.front() != removed ? members.front() : members.back();
    const auto refreshed_without = [&] {
        const auto& chain = storage(lead).chain();
        return chain.current_digest != before_digest && !chain.pending.has_value() &&
               chain.current->operation == StorageOperation::Refresh &&
               std::none_of(chain.current->holders.begin(), chain.current->holders.end(),
                            [&](const StorageHolder& h) { return h.node == removed->id; });
    };
    for (int round = 0; round < 3 && !refreshed_without(); ++round) {
        (void)run_storage_until([&] {
            return refreshed_without() || storage(lead).chain().pending.has_value();
        });
        if (refreshed_without()) break;
        for (int i = 0; i < 20; ++i) storage_step();
        wall_offset_ms += constants::kStorageSessionTimeoutMs;
        (void)run_storage_until(refreshed_without, 400);
    }
    ASSERT_TRUE(refreshed_without());
    ASSERT_TRUE(run_storage_until([&] {
        return all_current(members, storage(lead).chain().current_digest);
    }));
    const StorageFinalPlan after = *storage(lead).chain().current;
    const Digest after_digest = storage(lead).chain().current_digest;
    EXPECT_EQ(after.holders.size(), 5u);
    EXPECT_EQ(after.threshold, 4);
    EXPECT_EQ(after.storage_public_key, before.storage_public_key);
    // The removed holder keeps no share of the new plan, and its old share is
    // gone once it learns the new plan.
    EXPECT_FALSE(storage(removed).holds_share(after_digest));

    // Its old share's partial does not verify under the new plan.
    uint16_t removed_id = 0;
    for (const auto& h : before.holders) {
        if (h.node == removed->id) removed_id = h.holder_id;
    }
    nexus::crypto::StorageUnlockContext context;
    context.network_id = network;
    context.epoch = 3;
    context.plan_digest = after_digest;
    context.request_nonce.fill(4);
    auto wrapped = StorageThreshold::wrap_data_key(*founders[0]->crypto,
                                                   after.storage_public_key,
                                                   std::vector<uint8_t>(32, 1),
                                                   std::vector<uint8_t>{'r'});
    ASSERT_TRUE(wrapped.ok());
    auto old_partial = StorageThreshold::create_partial(*removed_share, before.key_plan, context,
                                                        wrapped.value->ephemeral_point);
    ASSERT_TRUE(old_partial.ok());
    EXPECT_EQ(StorageThreshold::verify_partial(after.key_plan, context,
                                               wrapped.value->ephemeral_point, removed_id,
                                               *old_partial.value),
              nexus::crypto::StorageStatus::InvalidProof);
    // It answers no request for the new plan.
    StorageUnlockRequestMsg request;
    request.requester = lead->id;
    request.epoch = storage(removed).current_epoch();
    request.plan_digest = after_digest;
    request.ephemeral_point = wrapped.value->ephemeral_point;
    request.nonce.fill(5);
    const auto refusals = [&] {
        return storage(removed).drops(StorageDrop::NoShare) +
               storage(removed).drops(StorageDrop::UnknownPlan) +
               storage(removed).drops(StorageDrop::EpochMismatch);
    };
    const uint64_t refused = refusals();
    const uint64_t sent = storage(removed).partials_sent();
    storage(removed).on_message(lead->router->compose(
        SecurityMessageKind::StorageUnlockRequest, request, request.epoch));
    EXPECT_EQ(refusals(), refused + 1);
    EXPECT_EQ(storage(removed).partials_sent(), sent);
}

// --- Rotation (B5a) ---------------------------------------------------------------------

TEST_F(StorageKeyPath, AServerStoppedForTwoRotationIntervalsRecoversItsDataKey) {
    create_key(founders);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    const StorageFinalPlan first = current_plan();
    const Digest first_digest = storage(founders.front()).chain().current_digest;
    Node* away = reserves[0];
    const auto away_key = data_key_bytes(away);
    ASSERT_EQ(away_key.size(), 32u);

    // The server stops. A day of block time later Tier 1 rotates.
    mesh.offline.insert(away->id);
    wall_offset_ms += kDayMs;
    ASSERT_TRUE(run_until_rotated_from(first_digest));
    const StorageFinalPlan rotated = current_plan();
    const Digest rotated_digest = storage(founders.front()).chain().current_digest;
    EXPECT_NE(rotated.storage_public_key, first.storage_public_key);
    EXPECT_EQ(rotated.retiring_plan, first_digest);
    EXPECT_EQ(rotated.retiring_until_ms,
              rotated.block_time_ms + constants::kStorageRetiringCapMs);
    // Every running server moves its data key to the new S through the holders.
    ASSERT_TRUE(run_storage_until([&] {
        return std::all_of(founders.begin(), founders.end(), [&](Node* n) {
            return storage(n).data_keys().wrapped_to() == rotated.storage_public_key;
        });
    }));

    // The stopped server's finalized claim still names the old S, so the old
    // plan stays live and its holders keep their shares.
    EXPECT_TRUE(storage(founders[1]).retiring_live());
    for (Node* holder : founders) {
        EXPECT_TRUE(storage(holder).holds_share(first_digest));
    }
    // A second day: the next rotation is due, and it waits for that server.
    wall_offset_ms += kDayMs;
    for (int i = 0; i < 300; ++i) storage_step();
    EXPECT_EQ(storage(founders.front()).chain().current_digest, rotated_digest);
    EXPECT_TRUE(storage(founders[1]).retiring_live());

    // The server starts again after two rotation intervals. Its data key is
    // not in memory; it unlocks under the old S and moves to the new one.
    mesh.offline.erase(away->id);
    build_storage(*away);
    ASSERT_TRUE(run_storage_until([&] {
        const auto& keys = storage(away).data_keys();
        return keys.state() == DataKeyState::Unlocked && keys.wrapped_to().has_value() &&
               *keys.wrapped_to() != first.storage_public_key;
    }));
    EXPECT_EQ(data_key_bytes(away), away_key);

    // Its rewrap was the last one: the old plan ends, its holders destroy the
    // old shares, and the deferred rotation runs.
    ASSERT_TRUE(run_storage_until([&] {
        return std::none_of(founders.begin(), founders.end(),
                            [&](Node* n) { return storage(n).holds_share(first_digest); });
    }));
    ASSERT_TRUE(run_until_rotated_from(rotated_digest));
    const auto latest = current_plan().storage_public_key;
    ASSERT_TRUE(run_storage_until(
        [&] { return storage(away).data_keys().wrapped_to() == latest; }));
    EXPECT_EQ(data_key_bytes(away), away_key);
}

TEST_F(StorageKeyPath, TheOldKeyStopsUnwrappingAtTheHardCap) {
    create_key(founders);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    const StorageFinalPlan first = current_plan();
    const Digest first_digest = storage(founders.front()).chain().current_digest;
    Node* away = reserves[0];

    mesh.offline.insert(away->id);
    wall_offset_ms += kDayMs;
    ASSERT_TRUE(run_until_rotated_from(first_digest));
    const Digest rotated_digest = storage(founders.front()).chain().current_digest;

    // The server stays away past the hard cap. Then the old plan ends without
    // its rewrap: the holders destroy the old shares and the next rotation
    // runs.
    wall_offset_ms += constants::kStorageRetiringCapMs;
    ASSERT_TRUE(run_until_rotated_from(rotated_digest));
    ASSERT_TRUE(run_storage_until([&] {
        return std::none_of(founders.begin(), founders.end(),
                            [&](Node* n) { return storage(n).holds_share(first_digest); });
    }));

    // Back after the cap, the server's key wrapped to the old S opens nothing.
    mesh.offline.erase(away->id);
    build_storage(*away);
    for (int i = 0; i < 400; ++i) storage_step();
    EXPECT_NE(storage(away).data_keys().state(), DataKeyState::Unlocked);
    EXPECT_FALSE(storage(away).data_keys().data_key().has_value());
    EXPECT_EQ(storage(away).data_keys().wrapped_to(), first.storage_public_key);

    StorageUnlockRequestMsg request;
    request.requester = away->id;
    request.epoch = storage(founders[1]).current_epoch();
    request.plan_digest = first_digest;
    request.nonce.fill(8);
    const uint64_t refused = storage(founders[1]).drops(StorageDrop::UnknownPlan);
    storage(founders[1]).on_message(away->router->compose(
        SecurityMessageKind::StorageUnlockRequest, request, request.epoch));
    EXPECT_EQ(storage(founders[1]).drops(StorageDrop::UnknownPlan), refused + 1);
}

TEST_F(StorageKeyPath, ARewrapReplacesTheStoredKeyOnlyAfterTheNewHoldersReproduceIt) {
    create_key(founders);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    const Digest first_digest = storage(founders.front()).chain().current_digest;
    const auto first_key = current_plan().storage_public_key;
    Node* server = reserves[1];
    const auto key = data_key_bytes(server);
    const auto next_file = server->dir / "storage" / "data-key.next.json";

    // The holders refuse this server's attestation, so its staged wrap cannot
    // verify: a verification that never passes.
    refuse_attestation.insert(server->id);
    wall_offset_ms += kDayMs;
    ASSERT_TRUE(run_until_rotated_from(first_digest));
    const auto rotated_key = current_plan().storage_public_key;
    ASSERT_TRUE(run_storage_until(
        [&] { return storage(server).data_keys().staged_to() == rotated_key; }));
    for (int i = 0; i < 200; ++i) storage_step();
    // The new wrap waits in data-key.next.json; data-key.json keeps the old S.
    EXPECT_EQ(storage(server).data_keys().wrapped_to(), first_key);
    EXPECT_EQ(storage(server).data_keys().staged_to(), rotated_key);
    EXPECT_TRUE(std::filesystem::exists(next_file));
    EXPECT_EQ(data_key_bytes(server), key);

    // A crash between the rewrap and its verification: the staged file is
    // discarded, and the stored key still names the old S.
    build_storage(*server);
    storage_step();
    EXPECT_FALSE(std::filesystem::exists(next_file));
    EXPECT_EQ(storage(server).data_keys().wrapped_to(), first_key);
    for (int i = 0; i < 100; ++i) storage_step();
    EXPECT_EQ(storage(server).data_keys().state(), DataKeyState::Locked);

    // Once the holders answer, the server unlocks under the old plan, stages
    // the rewrap again, verifies it, and only then swaps the stored key.
    refuse_attestation.clear();
    ASSERT_TRUE(run_storage_until([&] {
        const auto& keys = storage(server).data_keys();
        return keys.state() == DataKeyState::Unlocked && keys.wrapped_to() == rotated_key &&
               !keys.staged_to().has_value();
    }));
    EXPECT_EQ(data_key_bytes(server), key);
    EXPECT_FALSE(std::filesystem::exists(next_file));
    build_storage(*server);
    ASSERT_TRUE(run_storage_until(
        [&] { return storage(server).data_keys().state() == DataKeyState::Unlocked; }));
    EXPECT_EQ(data_key_bytes(server), key);
}

TEST_F(StorageKeyPath, ARetryLeavesOutAHolderThatSentRoundOneButNeverConfirmed) {
    create_key(founders);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    const Digest first_digest = storage(founders.front()).chain().current_digest;
    // One holder cannot seal: a file stands where its share directory was. It
    // sends both rounds, then cannot keep its new share, so it never confirms.
    Node* stuck = founders[4];
    const NodeId stuck_id = stuck->id;
    const auto sealed = stuck->dir / "storage" / "sealed";
    std::filesystem::remove_all(sealed);
    write_file(sealed, "not a directory");
    wall_offset_ms += kDayMs;
    ASSERT_TRUE(
        run_storage_until([&] { return storage(founders.front()).chain().pending.has_value(); }));
    for (int i = 0; i < 40; ++i) storage_step();
    wall_offset_ms += constants::kStorageSessionTimeoutMs;
    ASSERT_TRUE(run_until_rotated_from(first_digest));
    const auto& plan = current_plan();
    EXPECT_EQ(plan.holders.size(), 4u);
    EXPECT_EQ(plan.threshold, 3);
    EXPECT_TRUE(std::none_of(plan.holders.begin(), plan.holders.end(),
                             [&](const StorageHolder& h) { return h.node == stuck_id; }));
}

TEST_F(StorageKeyPath, AHolderServesOnlyTheRequestersOwnClaimedR) {
    create_key(founders);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    settle();
    Node* requester = reserves[0];
    Node* victim = reserves[1];
    Node* holder = founders[1];
    const Digest plan_digest = storage(holder).chain().current_digest;
    const auto request_for = [&](const StoragePointBytes& point, uint8_t seed) {
        StorageUnlockRequestMsg request;
        request.requester = requester->id;
        request.epoch = storage(holder).current_epoch();
        request.plan_digest = plan_digest;
        request.ephemeral_point = point;
        request.nonce.fill(seed);
        return requester->router->compose(SecurityMessageKind::StorageUnlockRequest, request,
                                          request.epoch);
    };
    const uint64_t sent = storage(holder).partials_sent();

    // The victim's R: it belongs to another server and earns nothing.
    const uint64_t unclaimed = storage(holder).drops(StorageDrop::UnclaimedWrap);
    storage(holder).on_message(request_for(claimed_point(holder, victim), 1));
    EXPECT_EQ(storage(holder).drops(StorageDrop::UnclaimedWrap), unclaimed + 1);
    // An R that nobody claimed earns nothing either.
    StoragePointBytes stray{};
    stray.fill(0x5A);
    storage(holder).on_message(request_for(stray, 2));
    EXPECT_EQ(storage(holder).drops(StorageDrop::UnclaimedWrap), unclaimed + 2);
    storage_step();
    EXPECT_EQ(storage(holder).partials_sent(), sent);

    // The requester's own R passes the claim check, is challenged, and is
    // answered after the attestation.
    storage(holder).on_message(request_for(claimed_point(holder, requester), 3));
    EXPECT_EQ(storage(holder).drops(StorageDrop::UnclaimedWrap), unclaimed + 2);
    const uint64_t busy = storage(holder).drops(StorageDrop::PendingBusy);
    storage(holder).on_message(request_for(claimed_point(holder, requester), 4));
    EXPECT_EQ(storage(holder).drops(StorageDrop::PendingBusy), busy + 1);
    ASSERT_TRUE(run_storage_until([&] { return storage(holder).partials_sent() > sent; }, 50));
}

// --- Lost or foreign storage state -------------------------------------------------------

TEST_F(StorageKeyPath, LostStorageStateWithEncryptedFilesStopsInsteadOfStartingFresh) {
    create_key(founders);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    Node* server = founders[0];  // a holder with encrypted files
    build_vault(*server, /*seed=*/true);
    ASSERT_TRUE(run_storage_until([&] { return vault_done(*server); }));
    const Digest plan_digest = storage(server).chain().current_digest;
    ASSERT_TRUE(share_of(server, plan_digest).has_value());
    const auto dir = server->dir / "storage";
    const auto records = raw_file(dir / "records.json");
    const auto data_key = raw_file(dir / "data-key.json");
    ASSERT_FALSE(records.empty());
    ASSERT_FALSE(data_key.empty());

    const auto expect_refused = [&](std::string_view file) {
        EXPECT_FALSE(build_storage(*server, /*expect_start=*/false));
        const auto reason = storage(server).halt_reason();
        EXPECT_NE(reason.find(file), std::string::npos) << reason;
        for (int i = 0; i < 50; ++i) storage_step();
        // The share survives, and no new data key takes the lost one's place.
        EXPECT_TRUE(share_of(server, plan_digest).has_value());
        EXPECT_FALSE(storage(server).data_keys().data_key().has_value());
        EXPECT_FALSE(vaults.at(server->id)->files_ready());
    };

    // records.json is gone: the chain was moved aside.
    std::filesystem::remove(dir / "records.json");
    expect_refused("records.json");
    EXPECT_FALSE(std::filesystem::exists(dir / "records.json"));
    EXPECT_EQ(raw_file(dir / "data-key.json"), data_key);

    // data-key.json is gone.
    write_file(dir / "records.json", records);
    std::filesystem::remove(dir / "data-key.json");
    expect_refused("data-key.json");
    EXPECT_FALSE(std::filesystem::exists(dir / "data-key.json"));

    // records.json holds a fresh, empty chain.
    write_file(dir / "data-key.json", data_key);
    write_file(dir / "records.json", R"({"format":1,"records":[]})");
    expect_refused("records.json");

    // With the state restored, the server unlocks and reads its files.
    write_file(dir / "records.json", records);
    build_storage(*server);
    auto& vault = build_vault(*server, /*seed=*/false);
    ASSERT_TRUE(run_storage_until([&] { return vault.files_ready(); }));
    expect_vault_files(*server);
    EXPECT_TRUE(storage(server).halt_reason().empty());
}

TEST_F(StorageKeyPath, RecordsFromAnotherEpochChainAreRefused) {
    create_key(founders);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    Node* server = founders[1];
    build_vault(*server, /*seed=*/true);
    ASSERT_TRUE(run_storage_until([&] { return vault_done(*server); }));
    ASSERT_TRUE(storage(server).chain_bound());
    const Digest plan_digest = storage(server).chain().current_digest;
    const auto file = server->dir / "storage" / "records.json";
    auto document = nlohmann::json::parse(raw_file(file));
    ASSERT_TRUE(document.contains("chain"));
    const std::string chain = document["chain"].get<std::string>();

    // A file from before the binding: its proofs verify under this chain, so
    // the records bind and the binding is written back.
    document.erase("chain");
    write_file(file, document.dump());
    build_storage(*server);
    auto& unbound = build_vault(*server, /*seed=*/false);
    ASSERT_TRUE(run_storage_until([&] { return storage(server).chain_bound(); }));
    EXPECT_EQ(nlohmann::json::parse(raw_file(file))["chain"].get<std::string>(), chain);
    ASSERT_TRUE(run_storage_until([&] { return unbound.files_ready(); }));

    // The same records bound to another chain, as after a re-found: refused,
    // and with encrypted files the server must not run.
    document["chain"] = std::string(64, 'a');
    write_file(file, document.dump());
    build_storage(*server);
    auto& foreign = build_vault(*server, /*seed=*/false);
    ASSERT_TRUE(
        run_storage_until([&] { return !storage(server).halt_reason().empty(); }, 100));
    EXPECT_NE(storage(server).halt_reason().find("another epoch chain"), std::string::npos);
    EXPECT_FALSE(storage(server).healthy());
    EXPECT_FALSE(storage(server).chain_bound());
    for (int i = 0; i < 50; ++i) storage_step();
    EXPECT_FALSE(foreign.files_ready());
    EXPECT_TRUE(share_of(server, plan_digest).has_value());
}

TEST_F(StorageKeyPath, HolderLossShrinksToFourAndThreeAndStopsBelowThree) {
    create_key(founders);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    // A day of block time starts a rotation among the current holders. The
    // muted holders stay silent, so the session times out; the block-time
    // offset then jumps past the timeout so the retry runs without them.
    const auto rotate_without = [&](std::set<NodeId> muted, std::size_t holders,
                                    uint16_t threshold) {
        mute_storage_packages(muted);
        wall_offset_ms += kDayMs;
        if (!run_storage_until([&] {
                return storage(founders.front()).chain().pending.has_value();
            })) {
            return false;
        }
        for (int i = 0; i < 20; ++i) storage_step();
        wall_offset_ms += constants::kStorageSessionTimeoutMs;
        return run_storage_until([&] {
            const auto& chain = storage(founders.front()).chain();
            return chain.current.has_value() && chain.current->holders.size() == holders &&
                   chain.current->threshold == threshold && !chain.pending.has_value() &&
                   all_current(storage_nodes(), chain.current_digest);
        });
    };
    // One holder stops answering: the rotation retries without it. 4 holders
    // give t = 3, so the key rotates (a refresh cannot change t).
    ASSERT_TRUE(rotate_without({founders[4]->id}, 4, 3));
    EXPECT_EQ(current_plan().operation, StorageOperation::Rotate);
    // A second loss: 3 holders, t = 2.
    ASSERT_TRUE(rotate_without({founders[4]->id, founders[3]->id}, 3, 2));
    EXPECT_EQ(current_plan().operation, StorageOperation::Rotate);
    const Digest three = storage(founders.front()).chain().current_digest;
    // The data keys followed every rotation.
    ASSERT_TRUE(run_storage_until([&] { return all_unlocked(storage_nodes()); }));

    // A third loss would leave 2: the last plan stays.
    mute_storage_packages({founders[4]->id, founders[3]->id, founders[2]->id});
    wall_offset_ms += kDayMs;
    for (uint32_t attempt = 0; attempt <= constants::kStorageMaxSessionAttempts; ++attempt) {
        for (int i = 0; i < 100; ++i) storage_step();
        wall_offset_ms += constants::kStorageSessionTimeoutMs;
    }
    for (int i = 0; i < 100; ++i) storage_step();
    EXPECT_EQ(storage(founders.front()).chain().current_digest, three);
    EXPECT_EQ(current_plan().holders.size(), 3u);

    // The 3-holder plan still unlocks with t = 2.
    mesh.drop_if = {};
    build_storage(*founders[0]);
    ASSERT_TRUE(run_storage_until(
        [&] { return storage(founders[0]).data_keys().state() == DataKeyState::Unlocked; }));
}

// --- Records outside Tier 1 -------------------------------------------------------------

TEST_F(StorageKeyPath, AServerOutsideTier1AcceptsOnlyAProvedRecord) {
    create_key(founders);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    const Digest current = storage(founders.front()).chain().current_digest;
    StoragePlanProofMsg proof;
    bool found = false;
    mesh.drop_if = [&](const Queued&, const SecurityMessage& message) {
        if (const auto* p = std::get_if<StoragePlanProofMsg>(&message.body); p && !found) {
            const auto record = storage_record_from_payload(p->payload);
            if (record.has_value() && storage_record_digest(*record) == current) {
                proof = *p;
                found = true;
            }
        }
        return false;
    };
    // A member answers a record request with the live records and proofs.
    Node* fresh = reserves[0];
    storage(founders[0]).on_message(fresh->router->compose(
        SecurityMessageKind::StoragePlanRequest, StoragePlanRequestMsg{0}, 2));
    mesh.pump();
    mesh.drop_if = {};
    ASSERT_TRUE(found);
    ASSERT_EQ(storage_record_digest(*storage_record_from_payload(proof.payload)), current);

    // A server that holds no storage state yet.
    stacks.at(fresh->id).service.reset();
    std::filesystem::remove_all(fresh->dir / "storage");
    build_storage(*fresh);
    ASSERT_FALSE(storage(fresh).chain().current.has_value());
    const auto deliver = [&](const StoragePlanProofMsg& message) {
        storage(fresh).on_message(
            founders[0]->router->compose(SecurityMessageKind::StoragePlanProof, message, 2));
    };

    // A forged certificate signature: the commit proof does not verify.
    auto forged = proof;
    forged.proof.certifying.signers.front().signature[0] ^= 0x01;
    const uint64_t invalid = storage(fresh).drops(StorageDrop::ProofInvalid);
    deliver(forged);
    EXPECT_EQ(storage(fresh).drops(StorageDrop::ProofInvalid), invalid + 1);
    EXPECT_FALSE(storage(fresh).chain().current.has_value());

    // One changed byte of the record: the proof no longer covers it.
    auto edited = proof;
    edited.payload.body[edited.payload.body.size() / 2] ^= 0x01;
    const auto refusals = [&] {
        return storage(fresh).drops(StorageDrop::ProofInvalid) +
               storage(fresh).drops(StorageDrop::Malformed);
    };
    const uint64_t before = refusals();
    deliver(edited);
    EXPECT_EQ(refusals(), before + 1);
    EXPECT_FALSE(storage(fresh).chain().current.has_value());

    // The genuine proof is accepted, and the record is marked verified.
    deliver(proof);
    EXPECT_EQ(storage(fresh).chain().current_digest, current);
    EXPECT_TRUE(storage(fresh).current_verified());
}

// --- Files under the data key (Phase 7, B9, B10, B5a) --------------------------------

TEST_F(StorageKeyPath, FilesMigrateAfterAHolderRoundTripAndColdStartNeedsTHolders) {
    create_key(founders);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    ASSERT_EQ(current_plan().threshold, 4);
    Node* server = founders[0];
    build_vault(*server, /*seed=*/true);
    ASSERT_TRUE(run_storage_until([&] { return vault_done(*server); }));
    expect_vault_files(*server);

    // Restart with exactly t holders: services that need the files wait for
    // the unlock, then read them.
    mesh.offline.insert(founders[4]->id);
    build_storage(*server);
    auto& vault = build_vault(*server, /*seed=*/false);
    EXPECT_FALSE(vault.files_ready());
    EXPECT_EQ(vault.read(server->dir / "files/tree/nodes/root.json").status,
              VaultReadStatus::Locked);
    ASSERT_TRUE(run_storage_until([&] { return vault.files_ready(); }));
    expect_vault_files(*server);

    // Restart with t - 1 holders: the data key never arrives, nothing is
    // readable, and no plaintext is accepted in its place.
    mesh.offline.insert(founders[3]->id);
    build_storage(*server);
    auto& locked = build_vault(*server, /*seed=*/false);
    for (int i = 0; i < 600; ++i) storage_step();
    EXPECT_FALSE(locked.files_ready());
    EXPECT_EQ(locked.read(server->dir / "files/identity/jwt_secret.hex").status,
              VaultReadStatus::Locked);
    EXPECT_FALSE(locked.write(server->dir / "files/identity/jwt_secret.hex", "replaced"));
}

TEST_F(StorageKeyPath, DataKeyRotationRewrapsThroughTheHoldersAndSurvivesARestart) {
    create_key(founders);
    ASSERT_FALSE(::testing::Test::HasFatalFailure());
    Node* server = founders[1];
    auto& vault = build_vault(*server, /*seed=*/true);
    ASSERT_TRUE(run_storage_until([&] { return vault_done(*server); }));
    const auto first = data_key_bytes(server);
    ASSERT_EQ(first.size(), 32u);

    ASSERT_TRUE(vault.request_rotation());
    ASSERT_TRUE(run_storage_until([&] { return vault_done(*server); }));
    const auto second = data_key_bytes(server);
    EXPECT_NE(second, first);
    EXPECT_EQ(storage(server).data_keys().wrapped_to(), current_plan().storage_public_key);
    EXPECT_FALSE(std::filesystem::exists(server->dir / "storage" / "data-key.next.json"));
    expect_vault_files(*server);

    // After a restart the holders return the new key, and it opens the files.
    build_storage(*server);
    auto& restarted = build_vault(*server, /*seed=*/false);
    ASSERT_TRUE(run_storage_until([&] { return restarted.files_ready(); }));
    EXPECT_EQ(data_key_bytes(server), second);
    expect_vault_files(*server);
}

}  // namespace
}  // namespace lifecycle_test
