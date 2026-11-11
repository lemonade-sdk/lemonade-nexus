// The root certificates the SDK verifies servers against come from an
// explicit PEM bundle (set_ca_bundle_path / ln_set_ca_bundle_path), not only
// from the platform's default trust. A mobile host has no default trust:
// iOS and Android ship no OpenSSL certificate directory, and an Android app
// process runs with AT_SECURE set, so OpenSSL ignores SSL_CERT_FILE there.

#include <LemonadeNexusSDK/LemonadeNexusClient.hpp>
#include <LemonadeNexusSDK/lemonade_nexus.h>

#include "support/localhost_cert.hpp"

#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <cstdlib>
#include <filesystem>
#include <memory>
#include <string>
#include <thread>

namespace fs = std::filesystem;

namespace {

using test_support::make_localhost_cert;

class SdkCaBundleTest : public ::testing::Test {
protected:
    fs::path dir;
    fs::path cert;
    fs::path other_cert;
    std::unique_ptr<httplib::SSLServer> server;
    std::thread server_thread;
    int port = 0;

    void SetUp() override {
        dir = fs::temp_directory_path() /
              ("nexus_sdk_ca_bundle_" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()) +
               "_" + std::to_string(reinterpret_cast<uintptr_t>(this)));
        fs::create_directories(dir);
        cert = dir / "cert.pem";
        other_cert = dir / "other_cert.pem";
        const auto key = dir / "key.pem";
        const auto other_key = dir / "other_key.pem";
        ASSERT_TRUE(make_localhost_cert(cert, key));
        ASSERT_TRUE(make_localhost_cert(other_cert, other_key));
        // The default trust must not know the server: the bundle is the only
        // way to it.
#ifdef _WIN32
        (void)_putenv_s("SSL_CERT_FILE", other_cert.string().c_str());
#else
        ::setenv("SSL_CERT_FILE", other_cert.string().c_str(), 1);
#endif
        server = std::make_unique<httplib::SSLServer>(cert.string().c_str(), key.string().c_str());
        ASSERT_TRUE(server->is_valid());
        server->Get("/api/health", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(R"({"status":"ok","service":"lemonade-nexus","rp_id":"lemonade-nexus.local"})",
                            "application/json");
        });
        port = server->bind_to_any_port("127.0.0.1");
        ASSERT_GT(port, 0);
        server_thread = std::thread([this] { server->listen_after_bind(); });
        server->wait_until_ready();
    }

    void TearDown() override {
        lnsdk::set_ca_bundle_path("");
        server->stop();
        if (server_thread.joinable()) server_thread.join();
        std::error_code ec;
        fs::remove_all(dir, ec);
    }

    /// ln_health through the C ABI against the test server: ok, or the
    /// transport error the SDK reports.
    static std::pair<bool, std::string> health(int port) {
        ln_client_t* client = ln_create_tls("localhost", static_cast<uint16_t>(port));
        EXPECT_NE(client, nullptr);
        char* out = nullptr;
        const ln_error_t err = ln_health(client, &out);
        EXPECT_NE(out, nullptr);
        const auto j = nlohmann::json::parse(out);
        ln_free(out);
        ln_destroy(client);
        return {err == LN_OK && j.value("ok", false), j.value("error", std::string{})};
    }
};

}  // namespace

TEST_F(SdkCaBundleTest, TheBundleIsTheTrustForEveryClientOpenedAfterIt) {
    ASSERT_EQ(ln_set_ca_bundle_path(cert.string().c_str()), LN_OK);
    EXPECT_EQ(lnsdk::ca_bundle_path(), cert.string());
    const auto [ok, error] = health(port);
    EXPECT_TRUE(ok) << error;
}

TEST_F(SdkCaBundleTest, ABundleWithoutTheServersRootRefusesTheServer) {
    ASSERT_EQ(ln_set_ca_bundle_path(other_cert.string().c_str()), LN_OK);
    const auto [ok, error] = health(port);
    EXPECT_FALSE(ok);
    EXPECT_FALSE(error.empty());
}

TEST_F(SdkCaBundleTest, AnEmptyPathReturnsToTheDefaultTrust) {
    ASSERT_EQ(ln_set_ca_bundle_path(cert.string().c_str()), LN_OK);
    ASSERT_EQ(ln_set_ca_bundle_path(""), LN_OK);
    EXPECT_TRUE(lnsdk::ca_bundle_path().empty());
    // The default trust follows SSL_CERT_FILE on Linux (the other
    // certificate), and ignores it on macOS (the keychain): either way the
    // test server is not trusted.
    const auto [ok, error] = health(port);
    EXPECT_FALSE(ok);
}

TEST_F(SdkCaBundleTest, ANullPathIsRefused) {
    EXPECT_EQ(ln_set_ca_bundle_path(nullptr), LN_ERR_NULL_ARG);
}
