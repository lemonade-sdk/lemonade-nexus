#include <LemonadeNexus/Core/ServerConfig.hpp>

#include <gtest/gtest.h>
#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
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

TEST(ServerConfigJson, MeshInterfaceReadsCurrentName) {
    nexus::core::ServerConfig current;
    nexus::core::from_json(nlohmann::json{{"mesh_interface", "mesh0"}}, current);
    EXPECT_EQ(current.mesh_interface, "mesh0");
}

// The storage key and file encryption are not configurable settings: the old
// `storage_key_enabled` / `storage_files_enabled` JSON keys were removed. A
// stale config that still names one is ignored, not an error.
TEST(ServerConfigJson, StaleStorageFlagJsonKeysAreIgnored) {
    nexus::core::ServerConfig config;
    nexus::core::from_json(
        nlohmann::json{{"storage_key_enabled", true}, {"storage_files_enabled", true}},
        config);
    EXPECT_FALSE(config.ddns_enabled);
}

// Tree operations, open registration, onboarding, and DNS seed discovery
// always run. A config file that still names one of the removed keys, with any
// value, loads like one without it.
TEST_F(ConfigDiscovery, RemovedSwitchesInTheConfigFileAreIgnored) {
    fs::current_path(dir);
    {
        std::ofstream out(dir / "lemonade-nexus.json");
        out << R"({"tree_ops_enabled": false, "tree_log_enabled": "yes",
                   "open_registration": false, "onboard_enabled": false,
                   "dns_seed_discovery": 0, "http_port": 9200})";
    }
    const auto config = load_from_cwd();
    EXPECT_EQ(config.http_port, 9200);
    EXPECT_FALSE(config.data_root.empty());
}

#ifndef _WIN32
// The removed variables and command-line switches are accepted and ignored.
TEST_F(ConfigDiscovery, RemovedSwitchesInTheEnvironmentAndCommandLineAreIgnored) {
    fs::current_path(dir);
    const char* variables[] = {"SP_TREE_OPS", "SP_TREE_LOG", "SP_CLOSED_REGISTRATION",
                               "SP_DNS_SEED_DISCOVERY"};
    for (const char* name : variables) ::setenv(name, "maybe", 1);
    std::vector<std::string> args = {"lemonade-nexus",        "--tree-ops",
                                     "--tree-log",            "--closed-registration",
                                     "--no-onboard",          "--no-dns-seed-discovery",
                                     "--http-port",           "9300"};
    std::vector<char*> argv;
    for (auto& a : args) argv.push_back(a.data());
    const auto config = nexus::core::load_config(static_cast<int>(argv.size()), argv.data());
    EXPECT_EQ(config.http_port, 9300);
    for (const char* name : variables) ::unsetenv(name);
}
#endif

TEST(ServerConfigEnv, ParseBoolFlagAcceptsOnlyBooleanWords) {
    using nexus::core::parse_bool_flag;
    for (const char* yes : {"1", "true", "TRUE", "Yes", "on"}) {
        EXPECT_EQ(parse_bool_flag(yes), std::optional<bool>(true)) << yes;
    }
    for (const char* no : {"0", "false", "False", "NO", "off"}) {
        EXPECT_EQ(parse_bool_flag(no), std::optional<bool>(false)) << no;
    }
    for (const char* other : {"", "2", "enable", "true ", " 1"}) {
        EXPECT_FALSE(parse_bool_flag(other).has_value()) << "'" << other << "'";
    }
}

#ifndef _WIN32
// A boolean SP_* variable reads its value: "0" is off, not "set".
TEST_F(ConfigDiscovery, BooleanEnvironmentVariablesReadTheirValue) {
    fs::current_path(dir);
    ::setenv("SP_DDNS_ENABLED", "0", 1);
    EXPECT_FALSE(load_from_cwd().ddns_enabled);
    ::setenv("SP_DDNS_ENABLED", "1", 1);
    EXPECT_TRUE(load_from_cwd().ddns_enabled);
    // An unreadable value turns the feature off.
    ::setenv("SP_DDNS_ENABLED", "maybe", 1);
    EXPECT_FALSE(load_from_cwd().ddns_enabled);
    ::unsetenv("SP_DDNS_ENABLED");
}
#endif
