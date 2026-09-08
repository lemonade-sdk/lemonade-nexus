#include <LemonadeNexus/Core/ServerConfig.hpp>

#include <gtest/gtest.h>
#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

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

#ifndef _WIN32
TEST_F(ConfigDiscovery, AnUnreadableWorkingDirectoryDoesNotTerminate) {
    if (::geteuid() == 0) {
        GTEST_SKIP() << "root bypasses directory permissions, so this cannot be exercised";
    }
    fs::current_path(dir);

    std::error_code ec;
    fs::permissions(dir, fs::perms::none, fs::perm_options::replace, ec);
    ASSERT_FALSE(ec) << ec.message();

    EXPECT_NO_THROW({
        const auto config = load_from_cwd();
        EXPECT_FALSE(config.data_root.empty());
    });
}

#endif

TEST_F(ConfigDiscovery, AReadableDirectoryWithNoConfigStillLoadsDefaults) {
    fs::current_path(dir);
    EXPECT_NO_THROW({
        const auto config = load_from_cwd();
        EXPECT_FALSE(config.data_root.empty());
    });
}
