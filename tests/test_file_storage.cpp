#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <gtest/gtest.h>

#include <filesystem>
#include <string>
#include <unistd.h>

using namespace nexus::storage;
namespace fs = std::filesystem;

class FileStorageTest : public ::testing::Test {
protected:
    fs::path temp_dir;
    std::unique_ptr<FileStorageService> storage;

    void SetUp() override {
        temp_dir = fs::temp_directory_path() / ("nexus_test_fs_" + std::to_string(getpid()));
        fs::create_directories(temp_dir);
        storage = std::make_unique<FileStorageService>(temp_dir);
        storage->start();
    }

    void TearDown() override {
        storage->stop();
        fs::remove_all(temp_dir);
    }

    SignedEnvelope make_envelope(const std::string& type, const std::string& data) {
        SignedEnvelope env;
        env.version = 1;
        env.type = type;
        env.data = data;
        env.signer_pubkey = "ed25519:testkey";
        env.signature = "testsig";
        env.timestamp = 1000;
        return env;
    }
};

// --- Node CRUD ---

TEST_F(FileStorageTest, WriteAndReadNode) {
    auto env = make_envelope("tree_node", R"({"id":"node1"})");
    ASSERT_TRUE(storage->write_node("node1", env));

    auto read = storage->read_node("node1");
    ASSERT_TRUE(read.has_value());
    EXPECT_EQ(read->type, "tree_node");
    EXPECT_EQ(read->signer_pubkey, "ed25519:testkey");
}

TEST_F(FileStorageTest, ReadNonExistentNodeReturnsNullopt) {
    auto read = storage->read_node("nonexistent");
    EXPECT_FALSE(read.has_value());
}

TEST_F(FileStorageTest, DeleteNode) {
    auto env = make_envelope("tree_node", R"({"id":"node1"})");
    storage->write_node("node1", env);
    EXPECT_TRUE(storage->delete_node("node1"));
    EXPECT_FALSE(storage->read_node("node1").has_value());
}

TEST_F(FileStorageTest, DeleteNonExistentNodeReturnsFalse) {
    EXPECT_FALSE(storage->delete_node("nonexistent"));
}

TEST_F(FileStorageTest, ListNodes) {
    storage->write_node("alpha", make_envelope("tree_node", R"({"id":"alpha"})"));
    storage->write_node("beta", make_envelope("tree_node", R"({"id":"beta"})"));
    storage->write_node("gamma", make_envelope("tree_node", R"({"id":"gamma"})"));

    auto nodes = storage->list_nodes();
    ASSERT_EQ(nodes.size(), 3u);
    EXPECT_EQ(nodes[0], "alpha");
    EXPECT_EQ(nodes[1], "beta");
    EXPECT_EQ(nodes[2], "gamma");
}

TEST_F(FileStorageTest, ListNodesEmpty) {
    auto nodes = storage->list_nodes();
    EXPECT_TRUE(nodes.empty());
}

TEST_F(FileStorageTest, OverwriteNode) {
    auto env1 = make_envelope("tree_node", R"({"id":"node1","v":1})");
    auto env2 = make_envelope("tree_node", R"({"id":"node1","v":2})");
    storage->write_node("node1", env1);
    storage->write_node("node1", env2);

    auto read = storage->read_node("node1");
    ASSERT_TRUE(read.has_value());
    // The data should contain v:2
    EXPECT_NE(read->data.find("2"), std::string::npos);
}

// --- Delta log ---

TEST_F(FileStorageTest, AppendAndReadDelta) {
    SignedDelta delta;
    delta.operation = "create_node";
    delta.target_node_id = "node1";
    delta.data = R"({"id":"node1"})";
    delta.signer_pubkey = "ed25519:test";
    delta.signature = "sig123";
    delta.timestamp = 1000;

    auto seq = storage->append_delta(delta);
    EXPECT_GT(seq, 0u);

    auto read = storage->read_delta(seq);
    ASSERT_TRUE(read.has_value());
    EXPECT_EQ(read->operation, "create_node");
    EXPECT_EQ(read->target_node_id, "node1");
    EXPECT_EQ(read->sequence, seq);
}

TEST_F(FileStorageTest, DeltaSequenceAutoIncrements) {
    SignedDelta delta;
    delta.operation = "create_node";
    delta.data = R"({})";

    auto seq1 = storage->append_delta(delta);
    auto seq2 = storage->append_delta(delta);
    auto seq3 = storage->append_delta(delta);

    EXPECT_EQ(seq2, seq1 + 1);
    EXPECT_EQ(seq3, seq2 + 1);
}

TEST_F(FileStorageTest, LatestDeltaSeq) {
    EXPECT_EQ(storage->latest_delta_seq(), 0u);

    SignedDelta delta;
    delta.operation = "create_node";
    delta.data = R"({})";

    storage->append_delta(delta);
    EXPECT_EQ(storage->latest_delta_seq(), 1u);

    storage->append_delta(delta);
    EXPECT_EQ(storage->latest_delta_seq(), 2u);
}

TEST_F(FileStorageTest, ReadDeltasSince) {
    SignedDelta delta;
    delta.data = R"({})";

    delta.operation = "op1";
    storage->append_delta(delta);
    delta.operation = "op2";
    storage->append_delta(delta);
    delta.operation = "op3";
    storage->append_delta(delta);

    auto deltas = storage->read_deltas_since(1);
    ASSERT_EQ(deltas.size(), 2u);
    EXPECT_EQ(deltas[0].operation, "op2");
    EXPECT_EQ(deltas[1].operation, "op3");
}

TEST_F(FileStorageTest, ReadNonExistentDelta) {
    auto read = storage->read_delta(999);
    EXPECT_FALSE(read.has_value());
}

// --- Generic file storage ---

TEST_F(FileStorageTest, WriteAndReadFile) {
    auto env = make_envelope("credential", R"({"user":"bob"})");
    ASSERT_TRUE(storage->write_file("credentials", "bob.json", env));

    auto read = storage->read_file("credentials", "bob.json");
    ASSERT_TRUE(read.has_value());
    EXPECT_EQ(read->type, "credential");
}

TEST_F(FileStorageTest, ReadNonExistentFile) {
    auto read = storage->read_file("credentials", "nonexistent.json");
    EXPECT_FALSE(read.has_value());
}

// --- Path traversal protection ---

TEST_F(FileStorageTest, PathTraversalNodeIdRejected) {
    auto env = make_envelope("tree_node", R"({})");
    EXPECT_FALSE(storage->write_node("../evil", env));
    EXPECT_FALSE(storage->write_node("foo/bar", env));
    EXPECT_FALSE(storage->write_node("", env));
}

TEST_F(FileStorageTest, PathTraversalFileRejected) {
    auto env = make_envelope("test", R"({})");
    EXPECT_FALSE(storage->write_file("../evil", "file.json", env));
    EXPECT_FALSE(storage->write_file("creds", "../evil.json", env));
}

// --- Ensure directories ---

TEST_F(FileStorageTest, EnsureDirectoriesCreatesAll) {
    storage->ensure_directories();
    EXPECT_TRUE(fs::exists(temp_dir / "tree" / "nodes"));
    EXPECT_TRUE(fs::exists(temp_dir / "tree" / "deltas"));
    EXPECT_TRUE(fs::exists(temp_dir / "identity"));
    EXPECT_TRUE(fs::exists(temp_dir / "credentials"));
    EXPECT_TRUE(fs::exists(temp_dir / "ipam"));
    EXPECT_TRUE(fs::exists(temp_dir / "certs"));
}

// --- Service interface ---

TEST_F(FileStorageTest, ServiceName) {
    EXPECT_EQ(storage->service_name(), "FileStorageService");
}

// --- Delta persistence across restart ---

TEST_F(FileStorageTest, DeltaSequenceRestoredOnRestart) {
    SignedDelta delta;
    delta.operation = "create_node";
    delta.data = R"({})";

    storage->append_delta(delta);
    storage->append_delta(delta);
    storage->append_delta(delta);
    EXPECT_EQ(storage->latest_delta_seq(), 3u);

    // Stop and recreate (simulating server restart)
    storage->stop();
    storage = std::make_unique<FileStorageService>(temp_dir);
    storage->start();

    // Next delta should get seq 4
    auto seq = storage->append_delta(delta);
    EXPECT_EQ(seq, 4u);
}
