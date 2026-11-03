// The public request budget: a valid session spends its node's bucket, an
// unauthenticated request the address bucket, and the authority chain walk
// its own. See Api/RequestBudget.hpp.

#include <LemonadeNexus/Api/RequestBudget.hpp>
#include <LemonadeNexus/Api/Tier1ApiHandler.hpp>
#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <span>
#include <string>

using namespace nexus;
using json = nlohmann::json;

namespace {

class RequestBudgetTest : public ::testing::Test {
protected:
    void SetUp() override {
        temp_dir_ = std::filesystem::temp_directory_path() /
                    ("nexus_request_budget_" + std::to_string(::getpid()));
        std::filesystem::create_directories(temp_dir_);
        crypto_.start();
        storage_ = std::make_unique<storage::FileStorageService>(temp_dir_);
        storage_->start();
        auth_ = std::make_unique<auth::AuthService>(*storage_, crypto_, "lemonade-nexus.local",
                                                    "request-budget-test-secret");
        auth_->start();
    }

    void TearDown() override {
        auth_->stop();
        storage_->stop();
        crypto_.stop();
        std::filesystem::remove_all(temp_dir_);
    }

    /// A session token for a fresh Ed25519 identity, through the same
    /// challenge round-trip a device performs.
    std::string session_token() {
        const auto kp = crypto_.ed25519_keygen();
        const auto bare = crypto::to_base64(
            std::span<const uint8_t>(kp.public_key.data(), kp.public_key.size()));
        const auto challenge_b64 =
            auth_->issue_ed25519_challenge(bare).value("challenge", std::string{});
        const auto challenge = crypto::from_base64(challenge_b64);
        const auto sig = crypto_.ed25519_sign(kp.private_key, std::span<const uint8_t>(challenge));
        const auto result = auth_->authenticate({
            {"method", "ed25519"},
            {"pubkey", bare},
            {"public_key", "ed25519:" + bare},
            {"challenge", challenge_b64},
            {"signature", crypto::to_base64(sig)},
        });
        EXPECT_TRUE(result.authenticated) << result.error_message;
        return result.session_token;
    }

    static httplib::Request request(const std::string& path, const std::string& addr,
                                    const std::string& token = {}) {
        httplib::Request req;
        req.method = "GET";
        req.path = path;
        req.remote_addr = addr;
        if (!token.empty()) req.set_header("Authorization", "Bearer " + token);
        return req;
    }

    std::filesystem::path temp_dir_;
    crypto::SodiumCryptoService crypto_;
    std::unique_ptr<storage::FileStorageService> storage_;
    std::unique_ptr<auth::AuthService> auth_;
};

constexpr network::RateLimitConfig kSmallAddressBudget{60, 2};

}  // namespace

TEST_F(RequestBudgetTest, UnauthenticatedRequestsSpendTheAddressBucket) {
    api::RequestBudget budget{kSmallAddressBudget, *auth_};
    const auto charge = budget.charge_for(request("/api/devices", "203.0.113.7"));
    EXPECT_EQ(charge.bucket, api::RequestBucket::Address);
    EXPECT_EQ(charge.key, "203.0.113.7");

    EXPECT_TRUE(budget.allow(request("/api/devices", "203.0.113.7")));
    EXPECT_TRUE(budget.allow(request("/api/devices", "203.0.113.7")));
    EXPECT_FALSE(budget.allow(request("/api/devices", "203.0.113.7")))
        << "the address burst is spent";
    EXPECT_TRUE(budget.allow(request("/api/devices", "203.0.113.8")))
        << "another address has its own bucket";
}

TEST_F(RequestBudgetTest, ASessionSpendsItsNodeBucketNotTheAddress) {
    api::RequestBudget budget{kSmallAddressBudget, *auth_};
    const std::string token = session_token();
    ASSERT_FALSE(token.empty());

    const auto charge = budget.charge_for(request("/api/devices", "203.0.113.7", token));
    EXPECT_EQ(charge.bucket, api::RequestBucket::Node);
    EXPECT_FALSE(charge.key.empty());
    EXPECT_NE(charge.key, "203.0.113.7");

    // A join burst behind a carrier NAT: far more than the address burst,
    // and the address bucket is untouched by it.
    for (int i = 0; i < 40; ++i) {
        EXPECT_TRUE(budget.allow(request("/api/devices", "203.0.113.7", token))) << i;
    }
    EXPECT_TRUE(budget.allow(request("/api/devices", "203.0.113.7")));
    EXPECT_TRUE(budget.allow(request("/api/devices", "203.0.113.7")));
    EXPECT_FALSE(budget.allow(request("/api/devices", "203.0.113.7")));

    // The node bucket is bounded too.
    int allowed = 0;
    for (int i = 0; i < static_cast<int>(api::kNodeRequestBurst) + 10; ++i) {
        if (budget.allow(request("/api/devices", "203.0.113.9", token))) ++allowed;
    }
    EXPECT_LE(allowed, static_cast<int>(api::kNodeRequestBurst) - 40 + 1);
}

TEST_F(RequestBudgetTest, AForgedOrMalformedTokenBuysNothing) {
    api::RequestBudget budget{kSmallAddressBudget, *auth_};
    const std::string token = session_token();
    const std::string forged = token.substr(0, token.size() - 4) + "AAAA";

    EXPECT_EQ(budget.charge_for(request("/api/devices", "203.0.113.7", forged)).bucket,
              api::RequestBucket::Address);
    httplib::Request bare = request("/api/devices", "203.0.113.7");
    bare.set_header("Authorization", "Token " + token);
    EXPECT_EQ(budget.charge_for(bare).bucket, api::RequestBucket::Address);

    EXPECT_TRUE(budget.allow(request("/api/devices", "203.0.113.7", forged)));
    EXPECT_TRUE(budget.allow(request("/api/devices", "203.0.113.7", forged)));
    EXPECT_FALSE(budget.allow(request("/api/devices", "203.0.113.7", forged)))
        << "a forged token still spends the address bucket";
}

TEST_F(RequestBudgetTest, TheAuthorityChainWalkKeepsItsOwnAddressBucket) {
    api::RequestBudget budget{kSmallAddressBudget, *auth_};
    const std::string token = session_token();

    EXPECT_EQ(budget.charge_for(request("/api/tier1/authority", "203.0.113.7")).bucket,
              api::RequestBucket::Authority);
    EXPECT_EQ(budget.charge_for(request("/api/tier1/authority", "203.0.113.7", token)).bucket,
              api::RequestBucket::Authority)
        << "the walk happens before a session exists; a session changes nothing";

    for (uint32_t i = 0; i < api::kAuthorityPageBurst; ++i) {
        ASSERT_TRUE(budget.allow(request("/api/tier1/authority", "203.0.113.7"))) << i;
    }
    EXPECT_FALSE(budget.allow(request("/api/tier1/authority", "203.0.113.7")));
    EXPECT_TRUE(budget.allow(request("/api/health", "203.0.113.7")))
        << "the address bucket is separate from the authority bucket";
}
