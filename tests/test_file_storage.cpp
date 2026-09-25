#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <string>
#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

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

TEST_F(FileStorageTest, DeleteFile) {
    auto env = make_envelope("chat_blob", R"({"c":"x"})");
    storage->write_file("chat-abc", "id1.json", env);
    EXPECT_TRUE(storage->read_file("chat-abc", "id1.json").has_value());
    EXPECT_TRUE(storage->delete_file("chat-abc", "id1.json"));
    EXPECT_FALSE(storage->read_file("chat-abc", "id1.json").has_value());
}

TEST_F(FileStorageTest, DeleteNonExistentFileReturnsFalse) {
    EXPECT_FALSE(storage->delete_file("chat-abc", "missing.json"));
}

TEST_F(FileStorageTest, ListFilesPerCategory) {
    storage->write_file("chat-g1", "b.json", make_envelope("chat_blob", R"({})"));
    storage->write_file("chat-g1", "a.json", make_envelope("chat_blob", R"({})"));
    storage->write_file("chat-g2", "z.json", make_envelope("chat_blob", R"({})"));

    auto g1 = storage->list_files("chat-g1");
    ASSERT_EQ(g1.size(), 2u);
    EXPECT_EQ(g1[0], "a");   // stems, sorted, no ".json"
    EXPECT_EQ(g1[1], "b");

    // Isolation: a different category never sees another's files.
    auto g2 = storage->list_files("chat-g2");
    ASSERT_EQ(g2.size(), 1u);
    EXPECT_EQ(g2[0], "z");
}

TEST_F(FileStorageTest, ListFilesEmptyCategory) {
    EXPECT_TRUE(storage->list_files("chat-does-not-exist").empty());
}

TEST_F(FileStorageTest, DeleteAndListFileTraversalRejected) {
    // The path guard throws inside; delete/list convert that to false/empty,
    // never touching anything outside the category.
    EXPECT_FALSE(storage->delete_file("chat-g1", "../../identity/keypair"));
    EXPECT_FALSE(storage->delete_file("../evil", "x.json"));
    EXPECT_TRUE(storage->list_files("../evil").empty());
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

// --- Delta transfer pool primitives ---

namespace {
// A valid 64-character lowercase hex identifier.
const std::string kHash =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
}

TEST_F(FileStorageTest, PoolGenerationRoundTripAndRefusal) {
    FileStorageService::PoolMetaRead meta = FileStorageService::PoolMetaRead::Ok;
    EXPECT_FALSE(storage->read_pool_generation(meta).has_value());
    EXPECT_EQ(meta, FileStorageService::PoolMetaRead::Absent);
    ASSERT_TRUE(storage->write_pool_generation("gen-1"));
    ASSERT_TRUE(storage->read_pool_generation(meta).has_value());
    EXPECT_EQ(meta, FileStorageService::PoolMetaRead::Ok);
    EXPECT_EQ(*storage->read_pool_generation(meta), "gen-1");
    EXPECT_FALSE(storage->write_pool_generation(""));
    ASSERT_TRUE(storage->read_pool_generation(meta).has_value());
    EXPECT_EQ(*storage->read_pool_generation(meta), "gen-1");  // unchanged
}

TEST_F(FileStorageTest, PoolRecordWriteReadRoundTripAndBoundedRead) {
    const auto text = R"({"position":1,"operation":"create_node"})";
    ASSERT_EQ(storage->write_pool_record(kHash, text),
              FileStorageService::PoolWrite::Ok);
    EXPECT_TRUE(storage->pool_record_exists(kHash));

    FileStorageService::PoolRead result = FileStorageService::PoolRead::Ok;
    auto read = storage->read_pool_record(kHash, 4096, result);
    ASSERT_TRUE(read.has_value());
    EXPECT_EQ(result, FileStorageService::PoolRead::Ok);
    EXPECT_EQ(*read, text);

    // The bound is applied before any read: a small cap reports Oversized
    // without returning content.
    auto big = storage->read_pool_record(kHash, 5, result);
    EXPECT_FALSE(big.has_value());
    EXPECT_EQ(result, FileStorageService::PoolRead::Oversized);

    const std::string other =
        "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
    EXPECT_FALSE(storage->pool_record_exists(other));
    auto absent = storage->read_pool_record(other, 4096, result);
    EXPECT_FALSE(absent.has_value());
    EXPECT_EQ(result, FileStorageService::PoolRead::Absent);
}

TEST_F(FileStorageTest, PoolListReportsRecordsTempFilesAndExcludesMeta) {
    ASSERT_TRUE(storage->write_pool_generation("gen-x"));
    ASSERT_EQ(storage->write_pool_record(kHash, "{}"),
              FileStorageService::PoolWrite::Ok);

    // A leftover in-flight temp file (e.g. from a crashed write) must be
    // listed so it counts toward storage bounds, and never indexed.
    std::ofstream(storage->pool_dir() / (kHash + ".json.tmp")) << "partial";
    // Unrecognized physical entries also occupy the bounded directory.
    std::ofstream(storage->pool_dir() / "orphan.bin") << std::string(17, 'o');

    const auto listing = storage->list_pool_entries();
    EXPECT_FALSE(listing.error);
    EXPECT_FALSE(listing.truncated);
    const auto& entries = listing.entries;
    ASSERT_EQ(entries.size(), 3u);
    bool saw_record = false, saw_tmp = false, saw_excluded = false;
    for (const auto& e : entries) {
        if (e.hash == kHash && e.record) {
            saw_record = true;
            EXPECT_EQ(e.size_bytes, 2u);  // "{}"
        }
        if (e.hash == kHash && e.temporary) saw_tmp = true;
        if (e.hash == "orphan.bin" && !e.record && !e.temporary) {
            saw_excluded = true;
            EXPECT_EQ(e.size_bytes, 17u);
        }
        EXPECT_NE(e.hash, "_meta");
    }
    EXPECT_TRUE(saw_record);
    EXPECT_TRUE(saw_tmp);
    EXPECT_TRUE(saw_excluded);
}

TEST_F(FileStorageTest, PoolRecordIdentifierRefusesNonHexAndTraversal) {
    EXPECT_EQ(storage->write_pool_record("not-hex", "{}"),
              FileStorageService::PoolWrite::Failed);
    EXPECT_EQ(storage->write_pool_record(kHash.substr(0, 10), "{}"),
              FileStorageService::PoolWrite::Failed);
    EXPECT_FALSE(storage->pool_record_exists("not-hex"));

    FileStorageService::PoolRead result = FileStorageService::PoolRead::Ok;
    EXPECT_FALSE(storage->read_pool_record("../etc", 100, result).has_value());
}

// The uncertain outcome is produced at the real boundary: the rename
// succeeds, the post-rename directory sync fails. The destination exists,
// and the caller is told the durability is unconfirmed — not Ok, not a
// clean Failed.
TEST_F(FileStorageTest, PoolWriteUncertainLeavesDestinationAndReportsUncertain) {
    storage->test_arm_pool_dirsync_failure();
    const auto result = storage->write_pool_record(kHash, "{}");
    EXPECT_EQ(result, FileStorageService::PoolWrite::Uncertain);
    // The renamed destination exists even though the outcome is uncertain.
    EXPECT_TRUE(storage->pool_record_exists(kHash));
    // The seam is one-shot: the next write is a normal durable write.
    EXPECT_EQ(storage->write_pool_record(kHash, "{}"),
              FileStorageService::PoolWrite::Ok);
}

// Generation metadata: absence and filesystem error are distinct states,
// and the read is bounded before any allocation.
TEST_F(FileStorageTest, PoolMetaReadBoundedAndDistinguishesAbsentFromError) {
    FileStorageService::PoolMetaRead meta = FileStorageService::PoolMetaRead::Ok;
    EXPECT_FALSE(storage->read_pool_generation(meta).has_value());
    EXPECT_EQ(meta, FileStorageService::PoolMetaRead::Absent);

    // A well-formed meta file reads back.
    ASSERT_TRUE(storage->write_pool_generation("gen-1"));
    EXPECT_EQ(*storage->read_pool_generation(meta), "gen-1");
    EXPECT_EQ(meta, FileStorageService::PoolMetaRead::Ok);

    // Malformed content is an error, not an absence.
    std::ofstream(storage->pool_dir() / "_meta.json", std::ios::trunc) << "not json";
    EXPECT_FALSE(storage->read_pool_generation(meta).has_value());
    EXPECT_EQ(meta, FileStorageService::PoolMetaRead::IoError);

    // An oversized meta file is refused before its content is read.
    std::ofstream big(storage->pool_dir() / "_meta.json", std::ios::trunc);
    big << std::string(8192, 'x');
    big.close();
    EXPECT_FALSE(storage->read_pool_generation(meta).has_value());
    EXPECT_EQ(meta, FileStorageService::PoolMetaRead::IoError);
}

// The directory enumeration is bounded while collecting, not after the
// vector is built: with a cap below the file count, collection stops at
// the cap.
TEST_F(FileStorageTest, PoolListEnumerationIsBoundedWhileCollecting) {
    auto make_hash = [](int i) {
        return kHash.substr(0, 60) + std::to_string(i % 10) +
               std::to_string((i * 7) % 10) + std::to_string((i * 13) % 10) +
               std::to_string((i * 29) % 10);
    };
    // Six distinct record files.
    for (int i = 0; i < 6; ++i) {
        ASSERT_EQ(storage->write_pool_record(make_hash(i), "{}"),
                  FileStorageService::PoolWrite::Ok);
    }
    auto full = storage->list_pool_entries();
    EXPECT_FALSE(full.error);
    EXPECT_FALSE(full.truncated);
    EXPECT_EQ(full.entries.size(), 6u);

    // A scan that stops at the cap is incomplete: it must say so, not
    // present a partial inventory as complete.
    storage->test_set_pool_list_cap(4);
    const auto capped = storage->list_pool_entries();
    EXPECT_FALSE(capped.error);
    EXPECT_TRUE(capped.truncated);
    EXPECT_EQ(capped.entries.size(), 4u);
    storage->test_set_pool_list_cap(0);  // production bound
    EXPECT_EQ(storage->list_pool_entries().entries.size(), 6u);
}

// A file that grows between the size inspection and the read must not be
// read unbounded: the limit is enforced during the read, and the stale
// inspection is reported as an I/O error, not absence or oversize.
TEST_F(FileStorageTest, RecordGrowthBetweenInspectionAndReadIsAnIoError) {
    // The file is exactly at the read limit, so the size inspection passes.
    ASSERT_EQ(storage->write_pool_record(kHash, std::string(100, 'r')),
              FileStorageService::PoolWrite::Ok);
    storage->test_arm_pool_record_growth(kHash);  // appends one byte in between

    FileStorageService::PoolRead result = FileStorageService::PoolRead::Ok;
    auto text = storage->read_pool_record(kHash, 100, result);
    EXPECT_EQ(result, FileStorageService::PoolRead::IoError)
        << "growth past the inspected size must fail closed, unbounded reads must not happen";
    EXPECT_FALSE(text.has_value());

    // The file is preserved, not truncated or repaired.
    std::error_code ec;
    EXPECT_EQ(fs::file_size(storage->pool_dir() / (kHash + ".json"), ec), 101u);
    EXPECT_FALSE(ec);

    // The same file reads fine within a limit that fits it.
    auto text2 = storage->read_pool_record(kHash, 200, result);
    EXPECT_EQ(result, FileStorageService::PoolRead::Ok);
    ASSERT_TRUE(text2.has_value());
    EXPECT_EQ(text2->size(), 101u);
}

// An existing record file that cannot be read is an I/O error, never
// absence: the identifier is still occupied by evidence.
TEST_F(FileStorageTest, UnreadableRecordFileIsIoErrorNotAbsent) {
    ASSERT_EQ(storage->write_pool_record(kHash, "{}"),
              FileStorageService::PoolWrite::Ok);
    const auto path = storage->pool_dir() / (kHash + ".json");
    ASSERT_EQ(::chmod(path.c_str(), 0), 0);

    FileStorageService::PoolRead result = FileStorageService::PoolRead::Ok;
    auto text = storage->read_pool_record(kHash, 1000, result);
    ::chmod(path.c_str(), 0600);
    EXPECT_EQ(result, FileStorageService::PoolRead::IoError)
        << "an unreadable existing file must not be reported as absent";
    EXPECT_FALSE(text.has_value());
    EXPECT_TRUE(storage->pool_record_exists(kHash));
}

TEST_F(FileStorageTest, PoolRecordStateDistinguishesIoErrorFromAbsence) {
    const std::string other = kHash.substr(1) + "0";
    EXPECT_EQ(storage->pool_record_state(other),
              FileStorageService::PoolFileState::Absent);

    storage->test_arm_pool_record_state_failure(other);
    EXPECT_EQ(storage->pool_record_state(other),
              FileStorageService::PoolFileState::IoError);
    EXPECT_EQ(storage->pool_record_state(other),
              FileStorageService::PoolFileState::Absent)
        << "the injected inspection failure is one-shot, not absence";
}

// A broken symlink posing as a record file makes the entry size
// indeterminate: the scan reports the error instead of a zero size or an
// empty inventory.
TEST_F(FileStorageTest, BrokenSymlinkMakesTheInventoryIncomplete) {
    ASSERT_EQ(storage->write_pool_record(kHash, "{}"),
              FileStorageService::PoolWrite::Ok);
    const std::string other = kHash.substr(1) + "0";
    ::symlink((temp_dir / "missing-target").c_str(),
              (storage->pool_dir() / (other + ".json")).c_str());

    EXPECT_EQ(storage->pool_record_state(other),
              FileStorageService::PoolFileState::Present)
        << "a broken symlink is an occupied path, never absence";
    FileStorageService::PoolRead read_result = FileStorageService::PoolRead::Ok;
    EXPECT_FALSE(storage->read_pool_record(other, 1000, read_result).has_value());
    EXPECT_EQ(read_result, FileStorageService::PoolRead::IoError);

    const auto listing = storage->list_pool_entries();
    EXPECT_TRUE(listing.error)
        << "an entry whose size cannot be determined must fail the scan";
    EXPECT_FALSE(listing.truncated);

    ::remove((storage->pool_dir() / (other + ".json")).c_str());
    const auto clean = storage->list_pool_entries();
    EXPECT_FALSE(clean.error);
    EXPECT_EQ(clean.entries.size(), 1u);
}

// A directory that cannot be opened is a scan error, never a complete
// empty pool.
TEST_F(FileStorageTest, UnscannablePoolDirectoryIsAnErrorNotAnEmptyPool) {
    ASSERT_EQ(storage->write_pool_record(kHash, "{}"),
              FileStorageService::PoolWrite::Ok);
    ASSERT_EQ(::chmod(storage->pool_dir().c_str(), 0), 0);
    const auto blocked = storage->list_pool_entries();
    ASSERT_EQ(::chmod(storage->pool_dir().c_str(), 0755), 0);
    EXPECT_TRUE(blocked.error)
        << "a failed scan must not be presented as an empty pool";
    EXPECT_EQ(blocked.entries.size(), 0u);
}

// The pool directory is derived from the constructor argument. A moved-from
// or default argument would make it CWD-relative, so two instances with
// different roots would share one pool. This pins the derivation and proves
// isolation between two roots.
TEST_F(FileStorageTest, PoolsOfDifferentRootsAreIsolated) {
    // The pool dir resolves under THIS instance's root, not the CWD.
    EXPECT_EQ(storage->pool_dir(), temp_dir / "tree" / "retained_deltas");
    EXPECT_TRUE(storage->pool_dir().is_absolute());

    const fs::path other_root = temp_dir / "other";
    FileStorageService other(other_root);
    other.start();
    EXPECT_EQ(other.pool_dir(), other_root / "tree" / "retained_deltas");
    EXPECT_TRUE(other.pool_dir().is_absolute());

    // Each root writes its own generation and record.
    const std::string hash_a = kHash;
    const std::string hash_b = kHash.substr(1) + "0";  // distinct 64-hex id
    ASSERT_TRUE(storage->write_pool_generation("gen-a"));
    ASSERT_EQ(storage->write_pool_record(hash_a, "{}"),
              FileStorageService::PoolWrite::Ok);
    ASSERT_TRUE(other.write_pool_generation("gen-b"));
    ASSERT_EQ(other.write_pool_record(hash_b, "{}"),
              FileStorageService::PoolWrite::Ok);

    // Neither instance sees the other's pool contents.
    auto entries_a = storage->list_pool_entries().entries;
    auto entries_b = other.list_pool_entries().entries;
    ASSERT_EQ(entries_a.size(), 1u);
    EXPECT_EQ(entries_a[0].hash, hash_a);
    ASSERT_EQ(entries_b.size(), 1u);
    EXPECT_EQ(entries_b[0].hash, hash_b);
    FileStorageService::PoolMetaRead meta = FileStorageService::PoolMetaRead::Ok;
    EXPECT_EQ(*storage->read_pool_generation(meta), "gen-a");
    EXPECT_EQ(*other.read_pool_generation(meta), "gen-b");
    EXPECT_FALSE(storage->pool_record_exists(hash_b));
    EXPECT_FALSE(other.pool_record_exists(hash_a));

    // A write through one instance does not appear under the other's root.
    const std::string hash_c = kHash.substr(2) + "11";
    ASSERT_EQ(other.write_pool_record(hash_c, "{}"),
              FileStorageService::PoolWrite::Ok);
    EXPECT_EQ(other.list_pool_entries().entries.size(), 2u);
    EXPECT_EQ(storage->list_pool_entries().entries.size(), 1u);

    other.stop();
}

TEST_F(FileStorageTest, RetainedDeltaJsonRoundTrip) {
    FileStorageService::RetainedDelta r;
    r.position = 7;
    r.record_hash = kHash;
    r.operation = "update_node";
    r.target_node_id = "node-1";
    r.data = R"({"id":"node-1","parent_id":"root"})";
    r.signer_pubkey = "ed25519:AAAA";
    r.signature = "BBBB";
    r.timestamp = 1234;

    auto parsed = FileStorageService::RetainedDelta::from_json(r.to_json());
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->position, 7u);
    EXPECT_EQ(parsed->record_hash, kHash);
    EXPECT_EQ(parsed->operation, "update_node");
    EXPECT_EQ(parsed->target_node_id, "node-1");
    EXPECT_EQ(parsed->data, r.data);
    EXPECT_EQ(parsed->signer_pubkey, "ed25519:AAAA");
    EXPECT_EQ(parsed->signature, "BBBB");
    EXPECT_EQ(parsed->timestamp, 1234u);

    // Malformed structures are refused, not half-parsed.
    EXPECT_FALSE(FileStorageService::RetainedDelta::from_json("not json").has_value());
    EXPECT_FALSE(FileStorageService::RetainedDelta::from_json(
        R"({"operation":"update_node"})").has_value());
}
