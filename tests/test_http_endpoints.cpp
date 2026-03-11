#include <LemonadeNexus/Network/HttpServer.hpp>
#include <LemonadeNexus/Network/RateLimiter.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>
#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>

#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <filesystem>
#include <string>
#include <thread>

using namespace nexus;
namespace fs = std::filesystem;
using json = nlohmann::json;

/// Integration test that spins up the HTTP server with real services
/// and tests endpoints via httplib::Client.
class HttpEndpointTest : public ::testing::Test {
protected:
    static constexpr uint16_t kTestPort = 19100; // use non-standard port for tests

    fs::path temp_dir;
    std::unique_ptr<crypto::SodiumCryptoService> crypto;
    std::unique_ptr<storage::FileStorageService> storage;
    std::unique_ptr<crypto::KeyWrappingService> key_wrapping;
    std::unique_ptr<tree::PermissionTreeService> tree;
    std::unique_ptr<auth::AuthService> auth;
    std::unique_ptr<ipam::IPAMService> ipam;
    std::unique_ptr<network::HttpServer> http;
    std::unique_ptr<network::RateLimiter> rate_limiter;

    crypto::Ed25519Keypair root_keypair;
    std::string root_pubkey_str;
    std::string jwt_secret;

    void SetUp() override {
        temp_dir = fs::temp_directory_path() / ("nexus_test_http_" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()));
        fs::create_directories(temp_dir);

        // Start services
        crypto = std::make_unique<crypto::SodiumCryptoService>();
        crypto->start();

        storage = std::make_unique<storage::FileStorageService>(temp_dir);
        storage->start();

        key_wrapping = std::make_unique<crypto::KeyWrappingService>(*crypto, *storage);
        key_wrapping->start();

        // Generate root keypair
        root_keypair = crypto->ed25519_keygen();
        root_pubkey_str = "ed25519:" + crypto::to_base64(root_keypair.public_key);

        // Bootstrap root node
        bootstrap_root_node();

        tree = std::make_unique<tree::PermissionTreeService>(*storage, *crypto);
        tree->start();

        std::array<uint8_t, 32> secret_bytes{};
        crypto->random_bytes(std::span<uint8_t>(secret_bytes));
        jwt_secret = crypto::to_hex(std::span<const uint8_t>(secret_bytes));

        auth = std::make_unique<auth::AuthService>(*storage, *crypto, "lemonade-nexus.local", jwt_secret);
        auth->start();

        ipam = std::make_unique<ipam::IPAMService>(*storage);
        ipam->start();

        // Set up HTTP server with routes
        http = std::make_unique<network::HttpServer>(kTestPort);
        rate_limiter = std::make_unique<network::RateLimiter>(
            network::RateLimitConfig{.requests_per_minute = 1000, .burst_size = 100});

        register_routes();
        http->start();

        // Brief pause to let the server thread bind
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    void TearDown() override {
        http->stop();
        ipam->stop();
        auth->stop();
        tree->stop();
        key_wrapping->stop();
        storage->stop();
        crypto->stop();
        fs::remove_all(temp_dir);
    }

    void bootstrap_root_node() {
        tree::TreeNode root;
        root.id = "root";
        root.parent_id = "";
        root.type = tree::NodeType::Root;
        root.mgmt_pubkey = root_pubkey_str;
        root.assignments = {{root_pubkey_str, {"admin"}}};

        auto canonical = tree::canonical_node_json(root);
        auto msg = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
        auto sig = crypto->ed25519_sign(root_keypair.private_key, msg);
        root.signature = crypto::to_base64(sig);

        storage::SignedEnvelope env;
        env.version = 1;
        env.type = "tree_node";
        env.data = json(root).dump();
        env.signer_pubkey = root_pubkey_str;
        env.signature = root.signature;
        storage->write_node("root", env);
    }

    void register_routes() {
        auto& srv = http->server();

        // Health
        srv.Get("/api/health", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(R"({"status":"ok","service":"lemonade-nexus"})", "application/json");
        });

        // Auth
        srv.Post("/api/auth", [this](const httplib::Request& req, httplib::Response& res) {
            auto body = json::parse(req.body, nullptr, false);
            if (body.is_discarded()) {
                res.status = 400;
                res.set_content(R"({"error":"invalid json"})", "application/json");
                return;
            }
            auto result = auth->authenticate(body);
            json resp = {
                {"authenticated", result.authenticated},
                {"user_id", result.user_id},
                {"session_token", result.session_token},
                {"error", result.error_message},
            };
            res.status = result.authenticated ? 200 : 401;
            res.set_content(resp.dump(), "application/json");
        });

        // Auth register
        srv.Post("/api/auth/register", [this](const httplib::Request& req, httplib::Response& res) {
            auto body = json::parse(req.body, nullptr, false);
            if (body.is_discarded()) {
                res.status = 400;
                res.set_content(R"({"error":"invalid json"})", "application/json");
                return;
            }
            auto result = auth->register_passkey(body);
            json resp = {
                {"authenticated", result.authenticated},
                {"user_id", result.user_id},
                {"session_token", result.session_token},
                {"error", result.error_message},
            };
            res.status = result.authenticated ? 200 : 400;
            res.set_content(resp.dump(), "application/json");
        });

        // Tree: get node
        srv.Get(R"(/api/tree/node/(.+))", [this](const httplib::Request& req, httplib::Response& res) {
            auto node_id = req.matches[1].str();
            auto node = tree->get_node(node_id);
            if (!node) {
                res.status = 404;
                res.set_content(R"({"error":"node not found"})", "application/json");
                return;
            }
            json resp = *node;
            res.set_content(resp.dump(), "application/json");
        });

        // Tree: submit delta
        srv.Post("/api/tree/delta", [this](const httplib::Request& req, httplib::Response& res) {
            auto body = json::parse(req.body, nullptr, false);
            if (body.is_discarded()) {
                res.status = 400;
                res.set_content(R"({"error":"invalid json"})", "application/json");
                return;
            }
            tree::TreeDelta delta;
            try {
                delta = body.get<tree::TreeDelta>();
            } catch (...) {
                res.status = 400;
                res.set_content(R"({"error":"invalid delta"})", "application/json");
                return;
            }
            bool ok = tree->apply_delta(delta);
            res.status = ok ? 200 : 403;
            json resp = {{"success", ok}};
            if (!ok) resp["error"] = "delta rejected";
            res.set_content(resp.dump(), "application/json");
        });

        // Tree: get children
        srv.Get(R"(/api/tree/children/(.+))", [this](const httplib::Request& req, httplib::Response& res) {
            auto parent_id = req.matches[1].str();
            auto children = tree->get_children(parent_id);
            json arr = json::array();
            for (const auto& child : children) {
                arr.push_back(json(child));
            }
            res.set_content(arr.dump(), "application/json");
        });

        // IPAM: allocate
        srv.Post("/api/ipam/allocate", [this](const httplib::Request& req, httplib::Response& res) {
            auto body = json::parse(req.body, nullptr, false);
            if (body.is_discarded()) {
                res.status = 400;
                res.set_content(R"({"error":"invalid json"})", "application/json");
                return;
            }
            auto node_id = body.value("node_id", "");
            auto block_type = body.value("block_type", "tunnel");

            ipam::Allocation alloc;
            if (block_type == "tunnel") {
                alloc = ipam->allocate_tunnel_ip(node_id);
            } else if (block_type == "private") {
                auto prefix = body.value("prefix_len", 30);
                alloc = ipam->allocate_private_subnet(node_id, static_cast<uint8_t>(prefix));
            } else if (block_type == "shared") {
                auto prefix = body.value("prefix_len", 30);
                alloc = ipam->allocate_shared_block(node_id, static_cast<uint8_t>(prefix));
            } else {
                res.status = 400;
                res.set_content(R"({"error":"invalid block_type"})", "application/json");
                return;
            }

            json resp = {
                {"success", !alloc.base_network.empty()},
                {"network", alloc.base_network},
                {"node_id", alloc.customer_node_id},
            };
            res.set_content(resp.dump(), "application/json");
        });
    }

    httplib::Client make_client() {
        return httplib::Client("localhost", kTestPort);
    }

    tree::TreeDelta make_signed_delta(const std::string& operation,
                                       const std::string& target_node_id,
                                       const tree::TreeNode& node_data) {
        tree::TreeDelta delta;
        delta.operation = operation;
        delta.target_node_id = target_node_id;
        delta.node_data = node_data;
        delta.signer_pubkey = root_pubkey_str;
        delta.timestamp = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());

        auto canonical = tree::canonical_delta_json(delta);
        auto msg = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
        auto sig = crypto->ed25519_sign(root_keypair.private_key, msg);
        delta.signature = crypto::to_base64(sig);
        return delta;
    }
};

// --- Health endpoint ---

TEST_F(HttpEndpointTest, HealthEndpoint) {
    auto cli = make_client();
    auto res = cli.Get("/api/health");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 200);

    auto body = json::parse(res->body);
    EXPECT_EQ(body["status"], "ok");
    EXPECT_EQ(body["service"], "lemonade-nexus");
}

// --- Auth endpoints ---

TEST_F(HttpEndpointTest, AuthUnknownMethod) {
    auto cli = make_client();
    auto res = cli.Post("/api/auth", R"({"method":"unknown"})", "application/json");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 401);
}

TEST_F(HttpEndpointTest, AuthInvalidJson) {
    auto cli = make_client();
    auto res = cli.Post("/api/auth", "not json", "application/json");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 400);
}

TEST_F(HttpEndpointTest, AuthRegisterInvalidJson) {
    auto cli = make_client();
    auto res = cli.Post("/api/auth/register", "not json", "application/json");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 400);
}

// --- Tree endpoints ---

TEST_F(HttpEndpointTest, GetRootNode) {
    auto cli = make_client();
    auto res = cli.Get("/api/tree/node/root");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 200);

    auto body = json::parse(res->body);
    EXPECT_EQ(body["id"], "root");
    EXPECT_EQ(body["type"], "root");
}

TEST_F(HttpEndpointTest, GetNonExistentNode) {
    auto cli = make_client();
    auto res = cli.Get("/api/tree/node/nonexistent");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 404);
}

TEST_F(HttpEndpointTest, CreateNodeViaDelta) {
    auto cli = make_client();

    tree::TreeNode child;
    child.id = "http_child1";
    child.parent_id = "root";
    child.type = tree::NodeType::Customer;
    child.mgmt_pubkey = root_pubkey_str;

    auto delta = make_signed_delta("create_node", "http_child1", child);
    json delta_json = delta;

    auto res = cli.Post("/api/tree/delta", delta_json.dump(), "application/json");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 200);

    auto body = json::parse(res->body);
    EXPECT_TRUE(body["success"].get<bool>());

    // Verify node was created
    auto get_res = cli.Get("/api/tree/node/http_child1");
    ASSERT_NE(get_res, nullptr);
    EXPECT_EQ(get_res->status, 200);
}

TEST_F(HttpEndpointTest, GetChildren) {
    auto cli = make_client();

    // Create two children
    for (const auto& name : {"child_a", "child_b"}) {
        tree::TreeNode child;
        child.id = name;
        child.parent_id = "root";
        child.type = tree::NodeType::Customer;
        child.mgmt_pubkey = root_pubkey_str;

        auto delta = make_signed_delta("create_node", name, child);
        cli.Post("/api/tree/delta", json(delta).dump(), "application/json");
    }

    auto res = cli.Get("/api/tree/children/root");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 200);

    auto body = json::parse(res->body);
    EXPECT_GE(body.size(), 2u);
}

// --- IPAM endpoint ---

TEST_F(HttpEndpointTest, AllocateTunnelIP) {
    auto cli = make_client();
    json req = {{"node_id", "ipam_node1"}, {"block_type", "tunnel"}};
    auto res = cli.Post("/api/ipam/allocate", req.dump(), "application/json");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 200);

    auto body = json::parse(res->body);
    EXPECT_TRUE(body["success"].get<bool>());
    EXPECT_FALSE(body["network"].get<std::string>().empty());
}

TEST_F(HttpEndpointTest, AllocateInvalidBlockType) {
    auto cli = make_client();
    json req = {{"node_id", "n1"}, {"block_type", "invalid"}};
    auto res = cli.Post("/api/ipam/allocate", req.dump(), "application/json");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 400);
}

// --- Full endpoint creation flow ---

TEST_F(HttpEndpointTest, CreateCustomerThenEndpoint) {
    auto cli = make_client();

    // 1. Create customer
    tree::TreeNode customer;
    customer.id = "acme_corp";
    customer.parent_id = "root";
    customer.type = tree::NodeType::Customer;
    customer.mgmt_pubkey = root_pubkey_str;
    customer.assignments = {{root_pubkey_str, {"admin"}}};

    auto delta1 = make_signed_delta("create_node", "acme_corp", customer);
    auto res1 = cli.Post("/api/tree/delta", json(delta1).dump(), "application/json");
    ASSERT_NE(res1, nullptr);
    EXPECT_EQ(res1->status, 200);

    // 2. Allocate tunnel IP for the customer
    json ipam_req = {{"node_id", "acme_corp"}, {"block_type", "tunnel"}};
    auto ipam_res = cli.Post("/api/ipam/allocate", ipam_req.dump(), "application/json");
    ASSERT_NE(ipam_res, nullptr);
    auto tunnel_ip = json::parse(ipam_res->body)["network"].get<std::string>();
    EXPECT_FALSE(tunnel_ip.empty());

    // 3. Create an endpoint under the customer
    tree::TreeNode endpoint;
    endpoint.id = "acme_ep1";
    endpoint.parent_id = "acme_corp";
    endpoint.type = tree::NodeType::Endpoint;
    endpoint.mgmt_pubkey = root_pubkey_str;
    endpoint.tunnel_ip = tunnel_ip;
    endpoint.wg_pubkey = "wg_test_key";

    auto delta2 = make_signed_delta("create_node", "acme_ep1", endpoint);
    auto res2 = cli.Post("/api/tree/delta", json(delta2).dump(), "application/json");
    ASSERT_NE(res2, nullptr);
    EXPECT_EQ(res2->status, 200);

    // 4. Verify endpoint exists
    auto get_res = cli.Get("/api/tree/node/acme_ep1");
    ASSERT_NE(get_res, nullptr);
    EXPECT_EQ(get_res->status, 200);

    auto ep = json::parse(get_res->body);
    EXPECT_EQ(ep["id"], "acme_ep1");
    EXPECT_EQ(ep["type"], "endpoint");
    EXPECT_EQ(ep["tunnel_ip"], tunnel_ip);

    // 5. Verify customer's children includes the endpoint
    auto children_res = cli.Get("/api/tree/children/acme_corp");
    ASSERT_NE(children_res, nullptr);
    auto children = json::parse(children_res->body);
    EXPECT_EQ(children.size(), 1u);
    EXPECT_EQ(children[0]["id"], "acme_ep1");
}

// --- Delta with invalid JSON ---

TEST_F(HttpEndpointTest, DeltaInvalidJson) {
    auto cli = make_client();
    auto res = cli.Post("/api/tree/delta", "not json", "application/json");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 400);
}
