// Unit tests for AclStore — the sqlite persistence layer behind ACLService.
//
// The store owns the connection, the schema, and every raw SQL statement.
// These tests exercise its whole surface directly: open and schema, the
// perms blob round-trip, delete, counting, seen-delta de-duplication, and
// persistence across close/reopen on the same path.

#include <gtest/gtest.h>

#include <LemonadeNexus/ACL/AclStore.hpp>

#include <filesystem>
#include <optional>
#include <cstdlib>

namespace fs = std::filesystem;
using nexus::acl::AclStore;

namespace {

class AclStoreTest : public ::testing::Test {
protected:
    void SetUp() override {
        // Unique per test case AND per process: the random seed is shared by
        // every test in a run, and under parallel ctest a fixed seed path would
        // collide across processes. mkdtemp gives an exclusive directory.
        auto tmpl = fs::temp_directory_path() / "acl-store-test-XXXXXX";
        auto tmp = tmpl.string();
        if (const char* created = ::mkdtemp(tmp.data())) {
            dir_ = created;
        } else {
            GTEST_FAIL() << "mkdtemp failed for the AclStore test directory";
        }
    }

    void TearDown() override {
        fs::remove_all(dir_);
    }

    fs::path dir_;
    fs::path db_path() const { return dir_ / "acl.db"; }
};

TEST_F(AclStoreTest, OpenIsRefusedUntilReadyAndCountsEmptySchema) {
    AclStore store{db_path()};
    EXPECT_FALSE(store.ready());
    EXPECT_EQ(store.count(), 0);

    store.open();
    EXPECT_TRUE(store.ready());
    EXPECT_EQ(store.count(), 0);

    // Reopening an open store is a no-op, not an error.
    store.open();
    EXPECT_TRUE(store.ready());
}

TEST_F(AclStoreTest, PermsBlobRoundTripsAndMissingRowIsAbsent) {
    AclStore store{db_path()};
    store.open();

    EXPECT_FALSE(store.load_perms("alice", "res-1").has_value());

    const std::vector<uint8_t> blob{0x01, 0x02, 0x03, 0x04, 0x05};
    ASSERT_TRUE(store.store_perms("alice", "res-1", std::span<const uint8_t>{blob}, 42));

    auto loaded = store.load_perms("alice", "res-1");
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(loaded->size(), blob.size());
    EXPECT_EQ(*loaded, blob);

    // A different (user_id, resource) pair never sees the row.
    EXPECT_FALSE(store.load_perms("bob", "res-1").has_value());
    EXPECT_FALSE(store.load_perms("alice", "res-2").has_value());

    // Upsert overwrites the blob in place.
    const std::vector<uint8_t> updated{0x09, 0x08};
    ASSERT_TRUE(store.store_perms("alice", "res-1", std::span<const uint8_t>{updated}, 77));
    auto reloaded = store.load_perms("alice", "res-1");
    ASSERT_TRUE(reloaded.has_value());
    EXPECT_EQ(*reloaded, updated);
}

TEST_F(AclStoreTest, DeleteRemovesTheRow) {
    AclStore store{db_path()};
    store.open();

    const std::vector<uint8_t> blob{1, 2, 3};
    ASSERT_TRUE(store.store_perms("alice", "res-1", std::span<const uint8_t>{blob}, 1));
    EXPECT_EQ(store.count(), 1);

    ASSERT_TRUE(store.delete_perms("alice", "res-1"));
    EXPECT_EQ(store.count(), 0);
    EXPECT_FALSE(store.load_perms("alice", "res-1").has_value());

    // Deleting an absent row is still success (SQL DELETE matches nothing).
    EXPECT_TRUE(store.delete_perms("alice", "res-1"));
}

TEST_F(AclStoreTest, SeenDeltasDeDuplicate) {
    AclStore store{db_path()};
    store.open();

    EXPECT_FALSE(store.is_delta_seen("delta-1"));
    ASSERT_TRUE(store.mark_delta_seen("delta-1"));
    EXPECT_TRUE(store.is_delta_seen("delta-1"));

    // Idempotent: marking the same delta again succeeds and changes nothing.
    EXPECT_TRUE(store.mark_delta_seen("delta-1"));
    EXPECT_TRUE(store.is_delta_seen("delta-1"));

    EXPECT_FALSE(store.is_delta_seen("delta-2"));
}

TEST_F(AclStoreTest, AStoreOverTheSamePathReloadsPriorData) {
    {
        AclStore store{db_path()};
        store.open();

        const std::vector<uint8_t> blob{0xDE, 0xAD, 0xBE, 0xEF};
        ASSERT_TRUE(store.store_perms("carol", "res-9", std::span<const uint8_t>{blob}, 123));
        ASSERT_TRUE(store.mark_delta_seen("delta-persist"));
        EXPECT_EQ(store.count(), 1);
    }  // store destroyed: connection closed

    AclStore reopened{db_path()};
    reopened.open();
    EXPECT_TRUE(reopened.ready());

    EXPECT_EQ(reopened.count(), 1);
    auto loaded = reopened.load_perms("carol", "res-9");
    ASSERT_TRUE(loaded.has_value());
    const std::vector<uint8_t> expected{0xDE, 0xAD, 0xBE, 0xEF};
    EXPECT_EQ(*loaded, expected);
    EXPECT_TRUE(reopened.is_delta_seen("delta-persist"));
    EXPECT_FALSE(reopened.is_delta_seen("delta-other"));
}

TEST_F(AclStoreTest, CloseReleasesTheConnectionAndReopenRestoresIt) {
    AclStore store{db_path()};
    store.open();

    const std::vector<uint8_t> blob{7, 7, 7};
    ASSERT_TRUE(store.store_perms("dave", "res-1", std::span<const uint8_t>{blob}, 5));

    store.close();
    EXPECT_FALSE(store.ready());
    EXPECT_EQ(store.count(), 0);
    EXPECT_FALSE(store.load_perms("dave", "res-1").has_value());
    EXPECT_FALSE(store.is_delta_seen("delta-1"));

    store.open();
    EXPECT_TRUE(store.ready());
    auto loaded = store.load_perms("dave", "res-1");
    ASSERT_TRUE(loaded.has_value());
    EXPECT_EQ(*loaded, blob);
}

} // namespace
