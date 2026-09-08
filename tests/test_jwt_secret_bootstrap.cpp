#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Core/ServerIdentity.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>

#include <gtest/gtest.h>
#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

#include <filesystem>
#include <string>

namespace fs = std::filesystem;

namespace {

struct JwtSecretBootstrap : ::testing::Test {
    void SetUp() override {
        crypto.start();
        dir = fs::temp_directory_path() /
              ("nexus_jwt_" + std::to_string(::getpid()) + "_" +
               ::testing::UnitTest::GetInstance()->current_test_info()->name());
        fs::remove_all(dir);
        fs::create_directories(dir);
    }
    void TearDown() override {
        crypto.stop();
        std::error_code ec;
        fs::remove_all(dir, ec);
    }
    nexus::crypto::SodiumCryptoService crypto;
    fs::path dir;
};

}  // namespace

TEST_F(JwtSecretBootstrap, AConfiguredSecretIsUsedVerbatimAndNothingIsGenerated) {
    nexus::core::ServerConfig config;
    config.jwt_secret = "CHANGE_ME";

    const auto resolved = nexus::core::resolve_jwt_secret(config, dir, crypto);
    EXPECT_EQ(resolved, "CHANGE_ME") << "a configured secret is taken as-is";
    EXPECT_FALSE(fs::exists(dir / "identity" / "jwt_secret.hex"))
        << "no secret is generated while one is configured";
}

TEST_F(JwtSecretBootstrap, AnUnsetSecretIsGeneratedAndPersisted) {
    nexus::core::ServerConfig config;
    ASSERT_TRUE(config.jwt_secret.empty()) << "the default must be empty";

    const auto first = nexus::core::resolve_jwt_secret(config, dir, crypto);
    EXPECT_EQ(first.size(), 64u) << "32 random bytes, hex encoded";
    EXPECT_NE(first, "CHANGE_ME");
    EXPECT_TRUE(fs::exists(dir / "identity" / "jwt_secret.hex"));

    const auto second = nexus::core::resolve_jwt_secret(config, dir, crypto);
    EXPECT_EQ(second, first);
}

TEST_F(JwtSecretBootstrap, GeneratedSecretsDifferBetweenInstalls) {
    nexus::core::ServerConfig config;
    const auto a = nexus::core::resolve_jwt_secret(config, dir / "a", crypto);
    const auto b = nexus::core::resolve_jwt_secret(config, dir / "b", crypto);
    EXPECT_NE(a, b);
}
