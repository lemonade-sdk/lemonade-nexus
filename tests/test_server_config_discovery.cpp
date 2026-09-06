// Config discovery must not abort the process.
//
// The default config path is relative, so load_config() stats the CURRENT
// directory. Started from a directory the user cannot read, the throwing
// filesystem overload terminated the process before any configuration was
// applied — observed on the Azure host as:
//   terminate called after throwing an instance of 'std::filesystem_error'
//     what(): filesystem error: status: Permission denied [lemonade-nexus.json]
// An unreadable directory means "no config file here", not a fatal error.

#include <LemonadeNexus/Core/ServerConfig.hpp>

#include <gtest/gtest.h>
#include <unistd.h>

#include <filesystem>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

struct ConfigDiscovery : ::testing::Test {
    void SetUp() override {
        original = fs::current_path();
        dir = fs::temp_directory_path() /
              ("nexus_cfg_disc_" + std::to_string(::getpid()) + "_" +
               ::testing::UnitTest::GetInstance()->current_test_info()->name());
        fs::remove_all(dir);
        fs::create_directories(dir);
    }

    void TearDown() override {
        std::error_code ec;
        fs::current_path(original, ec);
        fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace, ec);
        fs::remove_all(dir, ec);
    }

    fs::path original;
    fs::path dir;
};

/// load_config with the minimum required values, so it returns rather than
/// exiting on a missing key.
nexus::core::ServerConfig load_from_cwd() {
    std::string a0 = "lemonade-nexus";
    std::string a1 = "--root-pubkey";
    std::string a2 = std::string(64, 'a');
    std::string a3 = "--release-signing-pubkey";
    std::string a4 = std::string(64, 'b');
    std::vector<char*> argv{a0.data(), a1.data(), a2.data(), a3.data(), a4.data()};
    return nexus::core::load_config(static_cast<int>(argv.size()), argv.data());
}

}  // namespace

TEST_F(ConfigDiscovery, AnUnreadableWorkingDirectoryDoesNotTerminate) {
    if (::geteuid() == 0) {
        GTEST_SKIP() << "root bypasses directory permissions, so this cannot be exercised";
    }
    fs::current_path(dir);

    // Strip every permission: statting a relative path now fails with EACCES.
    std::error_code ec;
    fs::permissions(dir, fs::perms::none, fs::perm_options::replace, ec);
    ASSERT_FALSE(ec) << ec.message();

    // The throwing overload would abort here. This must simply return.
    EXPECT_NO_THROW({
        const auto config = load_from_cwd();
        EXPECT_FALSE(config.data_root.empty());
    });
}

TEST_F(ConfigDiscovery, AReadableDirectoryWithNoConfigStillLoadsDefaults) {
    fs::current_path(dir);
    EXPECT_NO_THROW({
        const auto config = load_from_cwd();
        EXPECT_FALSE(config.data_root.empty());
    });
}
