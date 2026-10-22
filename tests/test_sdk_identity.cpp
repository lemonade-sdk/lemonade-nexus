// lnsdk::Identity key file storage.
//
// The key file holds the device's Ed25519 secret key. Identity::save must
// create it readable by its owner only, with no point at which another user
// can read it, and must replace an older file of any mode.

#include <gtest/gtest.h>

#include <LemonadeNexusSDK/Identity.hpp>

#include <sodium.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>

#ifndef _WIN32
#include <sys/stat.h>
#include <sys/types.h>
#endif

namespace fs = std::filesystem;
using lnsdk::Identity;

namespace {

class SdkIdentityFileTest : public ::testing::Test {
protected:
    fs::path dir;

    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        dir = fs::temp_directory_path() /
              ("nexus_sdk_identity_" +
               std::to_string(::testing::UnitTest::GetInstance()->random_seed()) + "_" +
               std::to_string(reinterpret_cast<uintptr_t>(this)));
        fs::create_directories(dir);
    }

    void TearDown() override {
        std::error_code ec;
        fs::remove_all(dir, ec);
    }

    static Identity generated() {
        Identity id;
        id.generate();
        return id;
    }
};

#ifndef _WIN32
/// Restores the process umask when the test ends.
struct ScopedUmask {
    mode_t previous;
    explicit ScopedUmask(mode_t mask) : previous(::umask(mask)) {}
    ~ScopedUmask() { ::umask(previous); }
};

mode_t mode_of(const fs::path& path) {
    struct stat st {};
    EXPECT_EQ(::stat(path.c_str(), &st), 0);
    return st.st_mode & 0777;
}
#endif

}  // namespace

TEST_F(SdkIdentityFileTest, SaveThenLoadRoundTrips) {
    const auto id = generated();
    const auto path = dir / "nested" / "identity.json";
    ASSERT_TRUE(id.save(path));

    Identity loaded;
    ASSERT_TRUE(loaded.load(path));
    EXPECT_EQ(loaded.pubkey_string(), id.pubkey_string());
    EXPECT_EQ(loaded.private_key(), id.private_key());

    // Only the key file remains; the temporary file was renamed into place.
    std::size_t entries = 0;
    for ([[maybe_unused]] const auto& e : fs::directory_iterator(path.parent_path())) ++entries;
    EXPECT_EQ(entries, 1u);
}

TEST_F(SdkIdentityFileTest, InvalidIdentityIsNotSaved) {
    Identity empty;
    const auto path = dir / "identity.json";
    EXPECT_FALSE(empty.save(path));
    EXPECT_FALSE(fs::exists(path));
}

#ifndef _WIN32
// With an open umask, a file created with default permissions is
// world-readable. The key file must still be 0600.
TEST_F(SdkIdentityFileTest, KeyFileIsOwnerOnlyUnderAnOpenUmask) {
    ScopedUmask open_umask(0);
    const auto path = dir / "identity.json";
    ASSERT_TRUE(generated().save(path));
    EXPECT_EQ(mode_of(path), static_cast<mode_t>(0600));
}

// A key file left world-readable by an older client becomes 0600 when the
// key is saved again.
TEST_F(SdkIdentityFileTest, SaveReplacesAWorldReadableFile) {
    ScopedUmask open_umask(0);
    const auto path = dir / "identity.json";
    { std::ofstream(path) << "{}"; }
    fs::permissions(path, fs::perms::all, fs::perm_options::replace);
    ASSERT_EQ(mode_of(path), static_cast<mode_t>(0777));

    const auto id = generated();
    ASSERT_TRUE(id.save(path));
    EXPECT_EQ(mode_of(path), static_cast<mode_t>(0600));
    Identity loaded;
    ASSERT_TRUE(loaded.load(path));
    EXPECT_EQ(loaded.pubkey_string(), id.pubkey_string());
}

// A symbolic link at the temporary path must not redirect the key elsewhere.
// save() uses a fresh random temporary name and refuses an existing one, so a
// link at the target itself is replaced, not followed.
TEST_F(SdkIdentityFileTest, SaveReplacesASymlinkAtTheTarget) {
    const auto elsewhere = dir / "elsewhere.json";
    { std::ofstream(elsewhere) << "unchanged"; }
    const auto path = dir / "identity.json";
    fs::create_symlink(elsewhere, path);

    ASSERT_TRUE(generated().save(path));
    EXPECT_FALSE(fs::is_symlink(path));
    std::ifstream in(elsewhere);
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    EXPECT_EQ(content, "unchanged");
}
#endif
