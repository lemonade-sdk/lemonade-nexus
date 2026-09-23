// SDK-side coverage for the passkey challenge: the C ABI symbol's argument
// validation and the C++ client's error handling when the server is
// unreachable. Full request/response behavior is covered by
// test_passkey_challenge_http.cpp against a live server.

#include <LemonadeNexusSDK/LemonadeNexusClient.hpp>
#include <LemonadeNexusSDK/lemonade_nexus.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <memory>
#include <string>

namespace {

using lnsdk::LemonadeNexusClient;
using lnsdk::ServerConfig;

// A port nothing listens on in this environment.
constexpr uint16_t kDeadPort = 1;

}  // namespace

class SdkPasskeyChallengeTest : public ::testing::Test {
protected:
    ln_client_t* c_api_client = nullptr;
    std::unique_ptr<LemonadeNexusClient> client;

    void SetUp() override {
        c_api_client = ln_create("127.0.0.1", kDeadPort);
        ASSERT_NE(c_api_client, nullptr);

        ServerConfig cfg;
        cfg.servers = {lnsdk::ServerEndpoint{"127.0.0.1", kDeadPort, false}};
        cfg.auto_discover = false;
        client = std::make_unique<LemonadeNexusClient>(cfg);
    }

    void TearDown() override {
        client.reset();
        if (c_api_client) ln_destroy(c_api_client);
        c_api_client = nullptr;
    }
};

TEST_F(SdkPasskeyChallengeTest, CApiValidatesNullArguments) {
    char* out = nullptr;

    EXPECT_EQ(ln_auth_passkey_challenge(nullptr, "alice", &out), LN_ERR_NULL_ARG);
    EXPECT_EQ(out, nullptr);

    EXPECT_EQ(ln_auth_passkey_challenge(c_api_client, nullptr, &out), LN_ERR_NULL_ARG);
    EXPECT_EQ(out, nullptr);

    EXPECT_EQ(ln_auth_passkey_challenge(c_api_client, "alice", nullptr), LN_ERR_NULL_ARG);
}

TEST_F(SdkPasskeyChallengeTest, CApiUnreachableServerFailsWithoutOutput) {
    char* out = nullptr;
    const auto err = ln_auth_passkey_challenge(c_api_client, "alice", &out);
    EXPECT_NE(err, LN_OK);
    EXPECT_EQ(err, LN_ERR_CONNECT);
    // Error responses carry an error string the client can surface.
    ASSERT_NE(out, nullptr);
    std::string json_str(out);
    free(out);
    EXPECT_NE(json_str.find("error"), std::string::npos);
}

TEST_F(SdkPasskeyChallengeTest, CppClientIssueFailsCleanlyWhenUnreachable) {
    auto result = client->issue_passkey_challenge("alice");
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.http_status, 0);
    EXPECT_FALSE(result.error.empty());
    EXPECT_TRUE(result.value.empty());
}

TEST_F(SdkPasskeyChallengeTest, CppClientAuthPasskeyFailsCleanlyWhenUnreachable) {
    nlohmann::json body;
    body["method"] = "passkey";
    auto result = client->authenticate_passkey(body);
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.http_status, 0);
    EXPECT_FALSE(result.error.empty());
}
