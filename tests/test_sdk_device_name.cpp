// The C ABI of the device-name check (ln_check_device_name): argument checks,
// the JSON shape of the answer, the request it sends, and the error mapping,
// against a stand-in Tier 1 server. The route is a public tree route, so the
// client sends it only to a server it verified from the pinned Genesis key.

#include <LemonadeNexusSDK/lemonade_nexus.h>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Security/Epoch/Tier1Membership.hpp>
#include <LemonadeNexus/Security/Transport/AuthorityChainCodec.hpp>

#include "support/localhost_cert.hpp"
#include "support/tier1_chain.hpp"

#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;
using nlohmann::json;

namespace {

struct Client {
    ln_client_t* c = ln_create("localhost", 9);
    ~Client() { if (c) ln_destroy(c); }
};

json take_json(char* out) {
    auto parsed = json::parse(out ? out : "null", nullptr, false);
    ln_free(out);
    return parsed;
}

/// One reachable Tier 1 member of a five-member epoch that answers the
/// device-name check with whatever the test sets.
class SdkDeviceNameMockTest : public ::testing::Test {
protected:
    fs::path dir;
    std::unique_ptr<httplib::SSLServer> server;
    std::thread server_thread;
    int port = 0;
    nexus::crypto::Ed25519Keypair identity{};
    tier1_chain_test::Chain chain;

    std::mutex mtx;
    std::vector<json> bodies;  // every check request body, in order
    int reply_status = 200;
    json reply_body = json::object();

    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        dir = fs::temp_directory_path() /
              ("nexus_sdk_device_name_" +
               std::to_string(::testing::UnitTest::GetInstance()->random_seed()) + "_" +
               std::to_string(reinterpret_cast<uintptr_t>(this)));
        fs::create_directories(dir);
        const auto cert = dir / "cert.pem";
        const auto key = dir / "key.pem";
        ASSERT_TRUE(test_support::make_localhost_cert(cert, key));
#ifdef _WIN32
        (void)_putenv_s("SSL_CERT_FILE", cert.string().c_str());
#else
        ::setenv("SSL_CERT_FILE", cert.string().c_str(), 1);
#endif
        identity = tier1_chain_test::new_identity();
        std::vector<nexus::crypto::Ed25519Keypair> epoch1 = {identity};
        for (int i = 0; i < 4; ++i) epoch1.push_back(tier1_chain_test::new_identity());
        chain = tier1_chain_test::Chain::make({epoch1});

        server = std::make_unique<httplib::SSLServer>(cert.string().c_str(), key.string().c_str());
        ASSERT_TRUE(server->is_valid());
        server->Get("/api/tier1/authority", [this](const httplib::Request& req,
                                                   httplib::Response& res) {
            const auto page = chain.page_after(std::stoull(req.get_param_value("have_epoch")), 1);
            if (!page) {
                res.status = 404;
                return;
            }
            const auto bytes = nexus::security::encode_authority_chain_page(*page);
            res.set_content(json{{"page", nexus::crypto::to_base64(bytes)}}.dump(),
                            "application/json");
        });
        server->Get("/api/servers", [](const httplib::Request&, httplib::Response& res) {
            res.set_content("[]", "application/json");
        });
        server->Get("/api/tier1/proof", [this](const httplib::Request& req,
                                               httplib::Response& res) {
            const auto nonce = nexus::crypto::from_hex(req.get_param_value("nonce"));
            const auto proof = nexus::security::sign_tier1_endpoint_proof(
                chain.network, nexus::security::EpochId{1}, "localhost",
                static_cast<uint16_t>(port), nonce, identity);
            res.set_content(json{{"node_id", nexus::crypto::to_base64(proof.node.bytes)},
                                 {"epoch", 1},
                                 {"host", proof.host},
                                 {"port", proof.port},
                                 {"signature", nexus::crypto::to_base64(proof.signature)}}
                                .dump(),
                            "application/json");
        });
        server->Post("/api/tree/device-name/check", [this](const httplib::Request& req,
                                                            httplib::Response& res) {
            std::lock_guard lock(mtx);
            bodies.push_back(json::parse(req.body, nullptr, false));
            res.status = reply_status;
            res.set_content(reply_body.dump(), "application/json");
        });
        port = server->bind_to_any_port("127.0.0.1");
        ASSERT_GT(port, 0);
        server_thread = std::thread([this] { server->listen_after_bind(); });
        server->wait_until_ready();
    }

    void TearDown() override {
        if (server) server->stop();
        if (server_thread.joinable()) server_thread.join();
        std::error_code ec;
        fs::remove_all(dir, ec);
    }

    /// True when the platform's default TLS trust follows SSL_CERT_FILE.
    bool default_trust_reaches_server() {
        httplib::Client probe("https://localhost:" + std::to_string(port));
        probe.set_connection_timeout(3);
        auto res = probe.Get("/api/servers");
        return res && res->status == 200;
    }

    void answer(int status, json body) {
        std::lock_guard lock(mtx);
        reply_status = status;
        reply_body = std::move(body);
    }

    std::vector<json> requests() {
        std::lock_guard lock(mtx);
        return bodies;
    }

    /// A client that verified this server from the network's Genesis key.
    ln_client_t* verified_client() {
        ln_client_t* c = ln_create_tls("localhost", static_cast<uint16_t>(port));
        EXPECT_NE(c, nullptr);
        if (!c) return nullptr;
        EXPECT_EQ(ln_set_genesis_key(c, nexus::crypto::to_base64(chain.genesis.public_key).c_str(),
                                     0),
                  LN_OK);
        return c;
    }
};

}  // namespace

#ifdef __linux__
#define LN_REQUIRE_TEST_TRUST()                                                   \
    if (!default_trust_reaches_server())                                          \
    FAIL() << "default TLS trust cannot reach the test server; SSL_CERT_FILE is " \
              "deterministic on Linux"
#else
#define LN_REQUIRE_TEST_TRUST()                                                   \
    if (!default_trust_reaches_server())                                          \
    GTEST_SKIP() << "default TLS trust here ignores SSL_CERT_FILE (macOS keychain)"
#endif

TEST(SdkDeviceNameCApi, ArgumentsAreCheckedAndNothingIsSentWithoutATier1Server) {
    char* out = nullptr;
    EXPECT_EQ(ln_check_device_name(nullptr, "Work PC", "grp", nullptr, &out), LN_ERR_NULL_ARG);
    Client client;
    ASSERT_NE(client.c, nullptr);
    EXPECT_EQ(ln_check_device_name(client.c, nullptr, "grp", nullptr, &out), LN_ERR_NULL_ARG);
    EXPECT_EQ(ln_check_device_name(client.c, "Work PC", "grp", nullptr, nullptr),
              LN_ERR_NULL_ARG);
    // One scope is required: a group or an invite.
    EXPECT_EQ(ln_check_device_name(client.c, "Work PC", nullptr, nullptr, &out), LN_ERR_NULL_ARG);
    EXPECT_EQ(ln_check_device_name(client.c, "Work PC", "", "", &out), LN_ERR_NULL_ARG);
    EXPECT_EQ(out, nullptr);

    // Without a pinned Genesis key no server is a verified Tier 1 member, so
    // the check is not sent and the answer names the problem.
    EXPECT_EQ(ln_check_device_name(client.c, "Work PC", "grp", nullptr, &out), LN_ERR_CONNECT);
    ASSERT_NE(out, nullptr);
    const auto j = take_json(out);
    ASSERT_TRUE(j.is_object());
    EXPECT_FALSE(j.value("error", std::string{}).empty());
    EXPECT_FALSE(j.contains("label"));
}

TEST_F(SdkDeviceNameMockTest, TheAnswerKeepsTheServersShapeAndRefusalsMapToErrorCodes) {
    LN_REQUIRE_TEST_TRUST();
    ln_client_t* c = verified_client();
    ASSERT_NE(c, nullptr);

    // A taken name: label, conflicts, and suggestion come through unchanged.
    answer(200, {{"label", "work-pc"},
                 {"available", false},
                 {"conflicts", json::array({{{"node_id", "dev-1"}, {"device_name", "Work PC"}}})},
                 {"suggestion", "work-pc-2"}});
    char* out = nullptr;
    ASSERT_EQ(ln_check_device_name(c, "work pc", "grp-1", nullptr, &out), LN_OK);
    ASSERT_NE(out, nullptr);
    auto j = take_json(out);
    EXPECT_EQ(j["label"], "work-pc");
    EXPECT_EQ(j["available"], false);
    ASSERT_EQ(j["conflicts"].size(), 1u);
    EXPECT_EQ(j["conflicts"][0]["node_id"], "dev-1");
    EXPECT_EQ(j["conflicts"][0]["device_name"], "Work PC");
    EXPECT_EQ(j["suggestion"], "work-pc-2");
    EXPECT_FALSE(j.contains("error"));
    auto sent = requests();
    ASSERT_EQ(sent.size(), 1u);
    EXPECT_EQ(sent[0]["name"], "work pc");
    EXPECT_EQ(sent[0]["group_node_id"], "grp-1");
    EXPECT_FALSE(sent[0].contains("link_token"));

    // The invite form sends the token and no group; a free name round-trips.
    answer(200, {{"label", "printer"},
                 {"available", true},
                 {"conflicts", json::array()},
                 {"suggestion", "printer"}});
    ASSERT_EQ(ln_check_device_name(c, "Printer", "", "invite-code", &out), LN_OK);
    j = take_json(out);
    EXPECT_EQ(j["label"], "printer");
    EXPECT_EQ(j["available"], true);
    EXPECT_TRUE(j["conflicts"].empty());
    EXPECT_EQ(j["suggestion"], "printer");
    sent = requests();
    ASSERT_EQ(sent.size(), 2u);
    EXPECT_EQ(sent[1]["name"], "Printer");
    EXPECT_EQ(sent[1]["link_token"], "invite-code");
    EXPECT_FALSE(sent[1].contains("group_node_id"));

    // Refusals keep the server's reason and map to the error class.
    answer(403, {{"error", "no read permission"}});
    EXPECT_EQ(ln_check_device_name(c, "Printer", "grp-1", nullptr, &out), LN_ERR_AUTH);
    j = take_json(out);
    EXPECT_EQ(j["error"], "no read permission");
    EXPECT_FALSE(j.contains("label"));
    answer(404, {{"error", "group not found"}});
    EXPECT_EQ(ln_check_device_name(c, "Printer", "grp-2", nullptr, &out), LN_ERR_NOT_FOUND);
    EXPECT_EQ(take_json(out)["error"], "group not found");
    answer(400, {{"error", "name required"}});
    EXPECT_EQ(ln_check_device_name(c, "", "grp-1", nullptr, &out), LN_ERR_REJECTED);
    EXPECT_EQ(take_json(out)["error"], "name required");

    ln_destroy(c);
}
