#include <LemonadeNexus/Account/AccountDataStore.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

using namespace nexus;
namespace fs = std::filesystem;
using json = nlohmann::json;

namespace {

std::string b64(const crypto::Ed25519PublicKey& pk) {
    return crypto::to_base64(std::span<const uint8_t>(pk.data(), pk.size()));
}
std::string prefixed(const crypto::Ed25519PublicKey& pk) { return "ed25519:" + b64(pk); }

json chat_blob(const std::string& marker) {
    return {{"key_id", "gk1"}, {"nonce", "bm9uY2U"}, {"ciphertext", marker}};
}

} // namespace

class AccountDataTest : public ::testing::Test {
protected:
    fs::path temp_dir;
    std::unique_ptr<crypto::SodiumCryptoService> crypto_svc;
    std::unique_ptr<storage::FileStorageService> storage;
    std::unique_ptr<tree::PermissionTreeService> tree;
    std::unique_ptr<account::AccountDataStore> store;

    crypto::Ed25519Keypair root_kp, a_kp, b_kp, c_kp;

    void write_node(const std::string& id, const std::string& parent, tree::NodeType type,
                    const std::string& mgmt_prefixed,
                    const std::vector<tree::Assignment>& assignments) {
        tree::TreeNode n;
        n.id = id;
        n.parent_id = parent;
        n.type = type;
        n.mgmt_pubkey = mgmt_prefixed;
        n.assignments = assignments;
        storage::SignedEnvelope env;
        env.version = 1;
        env.type = "tree_node";
        env.data = json(n).dump();
        env.signer_pubkey = mgmt_prefixed;
        (void)storage->write_node(id, env);
    }

    void build_tree() {
        // root
        write_node("root", "", tree::NodeType::Root, prefixed(root_kp.public_key),
                   {{prefixed(root_kp.public_key), {"admin"}}});
        // Group 1: owner A (read+write), linked device B (read only)
        write_node("customer-g1", "root", tree::NodeType::Customer, prefixed(a_kp.public_key),
                   {{prefixed(a_kp.public_key), {"read", "write", "add_child", "edit_node", "delete_node"}},
                    {prefixed(b_kp.public_key), {"read"}}});
        write_node("endpointA", "customer-g1", tree::NodeType::Endpoint, prefixed(a_kp.public_key),
                   {{prefixed(a_kp.public_key), {"read", "write", "edit_node"}}});
        write_node("endpointB", "customer-g1", tree::NodeType::Endpoint, prefixed(b_kp.public_key),
                   {{prefixed(b_kp.public_key), {"read", "write", "edit_node"}}});
        // Group 2: owner C
        write_node("customer-g2", "root", tree::NodeType::Customer, prefixed(c_kp.public_key),
                   {{prefixed(c_kp.public_key), {"read", "write", "add_child", "edit_node", "delete_node"}}});
        write_node("endpointC", "customer-g2", tree::NodeType::Endpoint, prefixed(c_kp.public_key),
                   {{prefixed(c_kp.public_key), {"read", "write", "edit_node"}}});
    }

    void bring_up() {
        crypto_svc = std::make_unique<crypto::SodiumCryptoService>(); crypto_svc->start();
        storage = std::make_unique<storage::FileStorageService>(temp_dir); storage->start();
    }

    void start_tree_and_store() {
        tree = std::make_unique<tree::PermissionTreeService>(*storage, *crypto_svc); tree->start();
        store = std::make_unique<account::AccountDataStore>(*crypto_svc, *tree, *storage);
    }

    void SetUp() override {
        temp_dir = fs::temp_directory_path() / ("nexus_test_acctdata_" + std::to_string(getpid()));
        fs::remove_all(temp_dir);
        fs::create_directories(temp_dir);
        bring_up();
        root_kp = crypto_svc->ed25519_keygen();
        a_kp = crypto_svc->ed25519_keygen();
        b_kp = crypto_svc->ed25519_keygen();
        c_kp = crypto_svc->ed25519_keygen();
        build_tree();
        start_tree_and_store();
    }

    void TearDown() override {
        if (store) store.reset();
        if (tree) tree->stop();
        if (storage) storage->stop();
        if (crypto_svc) crypto_svc->stop();
        fs::remove_all(temp_dir);
    }

    // A = owner of g1, B = linked (read-only) device in g1, C = owner of g2.
    std::string a_pub() const { return b64(a_kp.public_key); }
    std::string b_pub() const { return b64(b_kp.public_key); }
    std::string c_pub() const { return b64(c_kp.public_key); }
};

// --- Free helpers ---

TEST_F(AccountDataTest, IsHexIdValidation) {
    EXPECT_TRUE(account::is_hex_id("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"));
    EXPECT_FALSE(account::is_hex_id(""));
    EXPECT_FALSE(account::is_hex_id("../../identity/keypair"));
    EXPECT_FALSE(account::is_hex_id("has/slash"));
    EXPECT_FALSE(account::is_hex_id("ABCDEF"));  // uppercase not produced by to_hex
    EXPECT_FALSE(account::is_hex_id(std::string(65, 'a')));
}

// --- Chat CRUD round-trip (owner A) ---

TEST_F(AccountDataTest, ChatCrudRoundTrip) {
    auto blob = chat_blob("CIPHERTEXT-ONE");
    auto created = store->create_chat("endpointA", a_pub(), blob, blob.dump().size());
    ASSERT_EQ(created.status, 201) << created.body.dump();
    auto chat_id = created.body.at("chat_id").get<std::string>();
    EXPECT_TRUE(account::is_hex_id(chat_id));

    auto listed = store->list_chats("endpointA", a_pub());
    ASSERT_EQ(listed.status, 200);
    ASSERT_EQ(listed.body.at("chats").size(), 1u);
    EXPECT_EQ(listed.body["chats"][0]["chat_id"], chat_id);

    auto got = store->get_chat("endpointA", a_pub(), chat_id);
    ASSERT_EQ(got.status, 200);
    EXPECT_EQ(got.body.at("ciphertext"), "CIPHERTEXT-ONE");

    auto blob2 = chat_blob("CIPHERTEXT-TWO");
    auto updated = store->update_chat("endpointA", a_pub(), chat_id, blob2, blob2.dump().size());
    ASSERT_EQ(updated.status, 200);
    EXPECT_EQ(store->get_chat("endpointA", a_pub(), chat_id).body.at("ciphertext"), "CIPHERTEXT-TWO");

    EXPECT_EQ(store->delete_chat("endpointA", a_pub(), chat_id).status, 200);
    EXPECT_EQ(store->get_chat("endpointA", a_pub(), chat_id).status, 404);
    EXPECT_EQ(store->list_chats("endpointA", a_pub()).body.at("chats").size(), 0u);
}

TEST_F(AccountDataTest, UpdateOrDeleteMissingChatIs404) {
    EXPECT_EQ(store->get_chat("endpointA", a_pub(), "deadbeef").status, 404);
    EXPECT_EQ(store->delete_chat("endpointA", a_pub(), "deadbeef").status, 404);
    EXPECT_EQ(store->update_chat("endpointA", a_pub(), "deadbeef",
                                 chat_blob("x"), 10).status, 404);
}

// --- Opacity: the server stores the client blob verbatim, adds no plaintext ---

TEST_F(AccountDataTest, StoredBlobIsOpaqueOnDisk) {
    auto blob = chat_blob("OPAQUE-MARKER-XYZ");
    auto created = store->create_chat("endpointA", a_pub(), blob, blob.dump().size());
    ASSERT_EQ(created.status, 201);
    auto chat_id = created.body.at("chat_id").get<std::string>();

    // Category is derived from the group id via sha256 — locate it the same way.
    auto gh = crypto::to_hex(crypto_svc->sha256(std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(std::string("customer-g1").data()), 11)));
    auto path = temp_dir / ("chat-" + gh) / (chat_id + ".json");
    ASSERT_TRUE(fs::exists(path)) << path.string();

    std::ifstream ifs(path);
    std::stringstream ss; ss << ifs.rdbuf();
    auto on_disk = json::parse(ss.str());
    EXPECT_EQ(on_disk.at("type"), "chat_blob");
    // Only the opaque client fields are present under data — the server never
    // decrypted or added a plaintext title.
    EXPECT_EQ(on_disk.at("data").at("ciphertext"), "OPAQUE-MARKER-XYZ");
    EXPECT_FALSE(on_disk.at("data").contains("title"));
    EXPECT_FALSE(on_disk.at("data").contains("plaintext"));
}

// --- Strict isolation: another account cannot see or touch a group's chats ---

TEST_F(AccountDataTest, CrossAccountIsolation) {
    auto created = store->create_chat("endpointA", a_pub(), chat_blob("A-SECRET"), 40);
    ASSERT_EQ(created.status, 201);
    auto chat_id = created.body.at("chat_id").get<std::string>();

    // C is in a different Customer group — sees nothing, every op is 404.
    EXPECT_EQ(store->list_chats("endpointC", c_pub()).body.at("chats").size(), 0u);
    EXPECT_EQ(store->get_chat("endpointC", c_pub(), chat_id).status, 404);
    EXPECT_EQ(store->delete_chat("endpointC", c_pub(), chat_id).status, 404);
    EXPECT_EQ(store->update_chat("endpointC", c_pub(), chat_id, chat_blob("evil"), 20).status, 404);

    // A's chat is still intact and readable by its owner.
    EXPECT_EQ(store->get_chat("endpointA", a_pub(), chat_id).status, 200);
}

// --- Multi-device: a group's read-capable device sees the chats; no write ---

TEST_F(AccountDataTest, LinkedDeviceReadsButCannotWrite) {
    auto created = store->create_chat("endpointA", a_pub(), chat_blob("SHARED"), 30);
    ASSERT_EQ(created.status, 201);
    auto chat_id = created.body.at("chat_id").get<std::string>();

    // B (linked, read-only on the group) can list + read the same account's chats.
    EXPECT_EQ(store->list_chats("endpointB", b_pub()).body.at("chats").size(), 1u);
    EXPECT_EQ(store->get_chat("endpointB", b_pub(), chat_id).status, 200);

    // But cannot create, update, or delete (no Write on the Customer node) -> 404.
    EXPECT_EQ(store->create_chat("endpointB", b_pub(), chat_blob("x"), 20).status, 404);
    EXPECT_EQ(store->update_chat("endpointB", b_pub(), chat_id, chat_blob("x"), 20).status, 404);
    EXPECT_EQ(store->delete_chat("endpointB", b_pub(), chat_id).status, 404);
}

TEST_F(AccountDataTest, NoGroupForToplessCaller) {
    // The root node has no parent -> no account group.
    EXPECT_EQ(store->create_chat("root", b64(root_kp.public_key), chat_blob("x"), 10).status, 403);
    EXPECT_EQ(store->list_chats("root", b64(root_kp.public_key)).status, 403);
    // Unknown caller node -> no group.
    EXPECT_EQ(store->list_chats("nobody", a_pub()).status, 403);
}

TEST_F(AccountDataTest, OversizeBlobRejected) {
    auto r = store->create_chat("endpointA", a_pub(), chat_blob("x"),
                                account::AccountDataStore::kMaxBlobBytes + 1);
    EXPECT_EQ(r.status, 413);
}

// --- Group-key envelopes ---

TEST_F(AccountDataTest, EnvelopeProvisionFetchAndMembership) {
    json env_body = {{"target_pubkey", b_pub()}, {"key_id", "gk1"},
                     {"ephemeral_pubkey", "ephem"}, {"wrapped_key", "WRAPPED-FOR-B"}};

    // No envelope yet for B.
    EXPECT_EQ(store->get_envelope("endpointB", b_pub()).status, 404);

    // A (owner, write) provisions the group key to member B.
    auto put = store->put_envelope("endpointA", a_pub(), env_body, env_body.dump().size());
    ASSERT_EQ(put.status, 200) << put.body.dump();

    // B fetches its own envelope and gets the wrapped key back verbatim.
    auto got = store->get_envelope("endpointB", b_pub());
    ASSERT_EQ(got.status, 200);
    EXPECT_EQ(got.body.at("wrapped_key"), "WRAPPED-FOR-B");

    // Provisioning to a NON-member (C's key) is refused.
    json bad = {{"target_pubkey", c_pub()}, {"wrapped_key", "leak"}};
    EXPECT_EQ(store->put_envelope("endpointA", a_pub(), bad, bad.dump().size()).status, 404);

    // A device in another group cannot fetch g1's envelope material.
    EXPECT_EQ(store->get_envelope("endpointC", c_pub()).status, 404);
}

TEST_F(AccountDataTest, PendingEnvelopesTracksProvisioning) {
    // Before provisioning, both A and B lack an envelope.
    auto pend0 = store->pending_envelopes("endpointA", a_pub());
    ASSERT_EQ(pend0.status, 200);
    EXPECT_EQ(pend0.body.at("pending").size(), 2u);

    json for_a = {{"target_pubkey", a_pub()}, {"wrapped_key", "wa"}};
    json for_b = {{"target_pubkey", b_pub()}, {"wrapped_key", "wb"}};
    store->put_envelope("endpointA", a_pub(), for_a, for_a.dump().size());
    store->put_envelope("endpointA", a_pub(), for_b, for_b.dump().size());

    EXPECT_EQ(store->pending_envelopes("endpointA", a_pub()).body.at("pending").size(), 0u);
}

// --- Persistence across a full restart (the demo flow) ---

TEST_F(AccountDataTest, SurvivesRestart) {
    auto created = store->create_chat("endpointA", a_pub(), chat_blob("PERSISTED"), 40);
    ASSERT_EQ(created.status, 201);
    auto chat_id = created.body.at("chat_id").get<std::string>();
    json for_b = {{"target_pubkey", b_pub()}, {"wrapped_key", "WK-B"}};
    ASSERT_EQ(store->put_envelope("endpointA", a_pub(), for_b, for_b.dump().size()).status, 200);
    store->create_chat("endpointC", c_pub(), chat_blob("G2-CHAT"), 30);

    // Tear the store + tree + storage down and rebuild from the same data root.
    store.reset();
    tree->stop(); tree.reset();
    storage->stop();
    storage = std::make_unique<storage::FileStorageService>(temp_dir); storage->start();
    start_tree_and_store();

    // A's chat reloads and decrypts (opaque round-trips); only its own group.
    auto listed = store->list_chats("endpointA", a_pub());
    ASSERT_EQ(listed.status, 200);
    ASSERT_EQ(listed.body.at("chats").size(), 1u);
    EXPECT_EQ(store->get_chat("endpointA", a_pub(), chat_id).body.at("ciphertext"), "PERSISTED");

    // B still reads its envelope after restart.
    EXPECT_EQ(store->get_envelope("endpointB", b_pub()).body.at("wrapped_key"), "WK-B");

    // Isolation still holds; C sees only its own group's one chat.
    EXPECT_EQ(store->list_chats("endpointC", c_pub()).body.at("chats").size(), 1u);
    EXPECT_EQ(store->get_chat("endpointC", c_pub(), chat_id).status, 404);
}
