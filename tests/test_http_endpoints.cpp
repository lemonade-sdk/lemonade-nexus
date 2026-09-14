#include <LemonadeNexus/Network/HttpServer.hpp>
#include <LemonadeNexus/Network/RateLimiter.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/KeyWrappingService.hpp>
#include <LemonadeNexus/Storage/FileStorageService.hpp>
#include <LemonadeNexus/Tree/PermissionTreeService.hpp>
#include <LemonadeNexus/Tree/TreeTypes.hpp>
#include <LemonadeNexus/Auth/AuthService.hpp>
#include <LemonadeNexus/Auth/AuthMiddleware.hpp>
#include <LemonadeNexus/ACL/Permission.hpp>
#include <LemonadeNexus/IPAM/IPAMService.hpp>
#include <LemonadeNexus/Gossip/GossipService.hpp>
#include <LemonadeNexus/Relay/RelayService.hpp>
#include <LemonadeNexus/Relay/RelayDiscoveryService.hpp>
#include <LemonadeNexus/Routing/RoutingCoordinationService.hpp>
#include <LemonadeNexus/Core/BinaryAttestation.hpp>
#include <LemonadeNexus/Core/ServerAdmissionService.hpp>
#include <LemonadeNexus/Network/DdnsService.hpp>
#include <LemonadeNexus/Acme/AcmeService.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Api/IRequestHandler.hpp>
#include <LemonadeNexus/Api/TreeApiHandler.hpp>
#include <LemonadeNexus/Api/RoutingApiHandler.hpp>
#include <LemonadeNexus/Api/MeshRekey.hpp>
#include <LemonadeNexus/Routing/IdentifierDerivation.hpp>

#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <jwt-cpp/jwt.h>

#include <chrono>
#include <filesystem>
#include <string>
#include <thread>
#include <asio.hpp>
#ifdef _WIN32
#  include <process.h>
#  define getpid _getpid
#else
#  include <unistd.h>
#endif

using namespace nexus;
namespace fs = std::filesystem;
using json = nlohmann::json;

// ---------------------------------------------------------------------------
// Test-only process-lifetime ApiContext + TreeApiHandler storage.
//
// ApiContext is non-default-constructible (reference members), so we heap-
// allocate it once and keep it for the process lifetime. This is safe because
// the test fixture runs sequentially in a single gtest process.
// ---------------------------------------------------------------------------
namespace test_api {

struct Storage {
    core::ServerConfig* config = nullptr;
    api::ApiContext*    ctx    = nullptr;
    api::TreeApiHandler* handler = nullptr;
    api::RoutingApiHandler* routing_handler = nullptr;

    void release() {
        delete routing_handler;
        delete handler;
        delete ctx;
        delete config;
        routing_handler = nullptr;
        handler = nullptr;
        ctx = nullptr;
        config = nullptr;
    }
};

// Per-fixture storage — reset each test.
inline Storage& current() {
    static Storage s;
    return s;
}

inline void reset() { current().release(); }

inline void install(core::ServerConfig& cfg,
                    auth::AuthService& auth,
                    tree::PermissionTreeService& tree,
                    ipam::IPAMService& ipam,
                    gossip::GossipService& gossip,
                    crypto::SodiumCryptoService& crypto,
                    crypto::KeyWrappingService& kw,
                    storage::FileStorageService& store,
                    acme::AcmeService& acme,
                    network::HttpServer& http,
                    network::DdnsService& ddns,
                    relay::RelayService& relay,
                    relay::RelayDiscoveryService& rd,
                    routing::RoutingCoordinationService& routing,
                    core::BinaryAttestationService& att,
                    core::ServerAdmissionService& adm) {
    auto& s = current();
    if (s.ctx) return; // already installed this test
    s.config = new core::ServerConfig(cfg);
    s.ctx = new api::ApiContext{
        .config           = *s.config,
        .auth             = auth,
        .tree             = tree,
        .ipam             = ipam,
        .gossip           = gossip,
        .crypto           = crypto,
        .key_wrapping     = kw,
        .storage          = store,
        .acme             = acme,
        .http_server      = http,
        .ddns             = ddns,
        .relay            = relay,
        .relay_discovery  = rd,
        .routing          = routing,
        .attestation      = att,
        .admission        = adm,
        .boringtun        = nullptr,
        .dns              = nullptr,
        .server_fqdn      = "test.local",
        .server_seip_fqdn = "",
        .server_private_fqdn = "",
        .server_public_ip = "",
        .tunnel_bind_ip   = "",
    };
    s.handler = new api::TreeApiHandler(*s.ctx);
    s.routing_handler = new api::RoutingApiHandler(*s.ctx);
}

inline api::TreeApiHandler& handler() { return *current().handler; }
inline api::RoutingApiHandler& routing_handler() { return *current().routing_handler; }

} // namespace test_api

/// Integration test that spins up the HTTP server with real services
/// and tests endpoints via httplib::Client.
class HttpEndpointTest : public ::testing::Test {
protected:
    uint16_t test_port_{0};

    fs::path temp_dir;
    asio::io_context io;
    std::unique_ptr<crypto::SodiumCryptoService> crypto;
    std::unique_ptr<storage::FileStorageService> storage;
    std::unique_ptr<crypto::KeyWrappingService> key_wrapping;
    std::unique_ptr<tree::PermissionTreeService> tree;
    std::unique_ptr<auth::AuthService> auth;
    std::unique_ptr<ipam::IPAMService> ipam;
    std::unique_ptr<network::HttpServer> http;
    std::unique_ptr<network::RateLimiter> rate_limiter;

    // Services required by the real TreeApiHandler (ApiContext stand-ins)
    std::unique_ptr<relay::RelayService> relay;
    std::unique_ptr<relay::RelayDiscoveryService> relay_discovery;
    std::unique_ptr<gossip::GossipService> gossip;
    std::unique_ptr<routing::RoutingCoordinationService> routing;
    std::unique_ptr<core::BinaryAttestationService> attestation;
    std::unique_ptr<core::ServerAdmissionService> admission;
    std::unique_ptr<network::DdnsService> ddns;
    std::unique_ptr<acme::AcmeService> acme;
    core::ServerConfig config;

    crypto::Ed25519Keypair root_keypair;
    std::string root_pubkey_str;
    std::string jwt_secret;

    void SetUp() override {
        test_port_ = static_cast<uint16_t>(19100 + (getpid() % 10000));
        temp_dir = fs::temp_directory_path() / ("nexus_test_http_" + std::to_string(getpid()));
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
        http = std::make_unique<network::HttpServer>(test_port_);
        rate_limiter = std::make_unique<network::RateLimiter>(
            network::RateLimitConfig{.requests_per_minute = 1000, .burst_size = 100});

        // Dummy services referenced by ApiContext. The delta route only touches
        // auth + tree, so unstarted stand-ins are never used.
        relay = std::make_unique<relay::RelayService>(io, 0, *crypto, root_keypair.public_key);
        relay_discovery = std::make_unique<relay::RelayDiscoveryService>(*storage);
        gossip = std::make_unique<gossip::GossipService>(io, 0, *storage, *crypto);
        routing = std::make_unique<routing::RoutingCoordinationService>(*crypto, *gossip);
        attestation = std::make_unique<core::BinaryAttestationService>(*crypto, *storage);
        admission = std::make_unique<core::ServerAdmissionService>(
            config, *crypto, *key_wrapping, *storage, *gossip);
        ddns = std::make_unique<network::DdnsService>(
            io, *crypto, *storage, *attestation, *gossip);
        acme = std::make_unique<acme::AcmeService>(*storage);

        test_api::install(config, *auth, *tree, *ipam, *gossip, *crypto,
                          *key_wrapping, *storage, *acme, *http, *ddns,
                          *relay, *relay_discovery, *routing, *attestation,
                          *admission);
        register_routes();
        test_api::handler().register_routes(http->server(), http->server());
        test_api::routing_handler().register_routes(http->server(), http->server());
        http->start();

        // Brief pause to let the server thread bind
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    void TearDown() override {
        test_api::reset();
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

        // Mesh: peers (auth required)
        srv.Get(R"(/api/mesh/peers/([a-zA-Z0-9_-]+))", auth::require_auth(*auth,
            [this](const httplib::Request& req, httplib::Response& res,
                   const auth::SessionClaims& claims) {

            std::string node_id = req.matches[1];
            if (node_id.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"node_id required"})", "application/json");
                return;
            }

            auto node_opt = tree->get_node(node_id);
            if (!node_opt) {
                res.status = 404;
                res.set_content(R"({"error":"node not found"})", "application/json");
                return;
            }

            // Verify Read permission — normalize pubkey (add ed25519: prefix if missing)
            auto caller = claims.user_id;
            if (!caller.starts_with("ed25519:")) caller = "ed25519:" + caller;
            bool has_perm = tree->check_permission(caller, node_id, acl::Permission::Read);
            if (!has_perm) {
                res.status = 403;
                res.set_content(R"({"error":"insufficient permissions"})", "application/json");
                return;
            }

            // Get siblings
            const auto& node = *node_opt;
            json peers = json::array();
            if (!node.parent_id.empty()) {
                auto siblings = tree->get_children(node.parent_id);
                for (const auto& s : siblings) {
                    if (s.id == node_id) continue;
                    if (s.type != tree::NodeType::Endpoint) continue;
                    // Check Read permission on sibling too
                    bool can_read = tree->check_permission(caller, s.id, acl::Permission::Read);
                    if (!can_read) continue;
                    json p;
                    p["node_id"] = s.id;
                    p["hostname"] = s.hostname;
                    p["mesh_pubkey"] = s.mesh_pubkey;
                    p["tunnel_ip"] = s.tunnel_ip;
                    p["endpoint"] = s.listen_endpoint;
                    peers.push_back(std::move(p));
                }
            }

            json j;
            j["node_id"] = node_id;
            j["peers"] = std::move(peers);
            res.set_content(j.dump(), "application/json");
        }));

        // Mesh: heartbeat (auth required)
        srv.Post("/api/mesh/heartbeat", auth::require_auth(*auth,
            [this](const httplib::Request& req, httplib::Response& res,
                   const auth::SessionClaims& claims) {

            auto body = json::parse(req.body, nullptr, false);
            if (body.is_discarded()) {
                res.status = 400;
                res.set_content(R"({"error":"invalid json"})", "application/json");
                return;
            }

            auto hb_node_id = body.value("node_id", "");
            if (hb_node_id.empty()) {
                res.status = 400;
                res.set_content(R"({"error":"node_id required"})", "application/json");
                return;
            }

            auto node_opt = tree->get_node(hb_node_id);
            if (!node_opt) {
                res.status = 404;
                res.set_content(R"({"error":"node not found"})", "application/json");
                return;
            }

            // Verify caller owns this node via mgmt_pubkey (defense in depth)
            auto caller = claims.user_id;
            if (!caller.starts_with("ed25519:")) caller = "ed25519:" + caller;
            if (node_opt->mgmt_pubkey != caller) {
                res.status = 403;
                res.set_content(R"({"error":"insufficient permissions"})", "application/json");
                return;
            }

            // Also verify EditNode permission
            bool has_perm = tree->check_permission(caller, hb_node_id, acl::Permission::EditNode);
            if (!has_perm) {
                res.status = 403;
                res.set_content(R"({"error":"insufficient permissions"})", "application/json");
                return;
            }

            // Validate endpoint format
            auto ep = body.value("endpoint", "");
            if (!ep.empty()) {
                // Basic ip:port format check
                auto colon = ep.rfind(':');
                if (colon == std::string::npos || colon == 0 || colon == ep.size() - 1) {
                    res.status = 400;
                    res.set_content(R"({"error":"invalid endpoint format"})", "application/json");
                    return;
                }
            }

            // Use atomic endpoint update to avoid TOCTOU
            tree->update_node_endpoint(hb_node_id, ep);

            json j;
            j["success"] = true;
            j["node_id"] = hb_node_id;
            j["endpoint"] = ep;
            res.set_content(j.dump(), "application/json");
        }));

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

    /// Generate a valid JWT for testing auth-protected endpoints.
    /// Sets the `pubkey` claim (the session identity used by tree authorization).
    std::string make_jwt(const std::string& user_id) {
        auto now = std::chrono::system_clock::now();
        return jwt::create()
            .set_issuer("lemonade-nexus")
            .set_subject(user_id)
            .set_issued_at(now)
            .set_expires_at(now + std::chrono::hours{1})
            .set_payload_claim("pubkey", jwt::claim(user_id))
            .sign(jwt::algorithm::hs256{jwt_secret});
    }

    /// POST a delta with an auth header matching the root key identity.
    httplib::Result post_auth_delta(
        httplib::Client& cli, const std::string& body) {
        httplib::Headers h = {{"Authorization",
                               "Bearer " + make_jwt(root_pubkey_str)}};
        return cli.Post("/api/tree/delta", h, body, "application/json");
    }

    httplib::Client make_client() {
        return httplib::Client("localhost", test_port_);
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

    auto res = post_auth_delta(cli, delta_json.dump());
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
        post_auth_delta(cli, json(delta).dump());
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
    auto res1 = post_auth_delta(cli, json(delta1).dump());
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
    endpoint.mesh_pubkey = "mesh_test_key";

    auto delta2 = make_signed_delta("create_node", "acme_ep1", endpoint);
    auto res2 = post_auth_delta(cli, json(delta2).dump());
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
    auto res = post_auth_delta(cli, "not json");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 400);
}

// =========================================================================
// Mesh API security tests
// =========================================================================

TEST_F(HttpEndpointTest, MeshPeersNoAuth) {
    auto cli = make_client();
    // No Authorization header → 401
    auto res = cli.Get("/api/mesh/peers/root");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 401);
}

TEST_F(HttpEndpointTest, MeshPeersInvalidToken) {
    auto cli = make_client();
    httplib::Headers h = {{"Authorization", "Bearer invalid_token_here"}};
    auto res = cli.Get("/api/mesh/peers/root", h);
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 401);
}

TEST_F(HttpEndpointTest, MeshPeersMalformedAuthHeader) {
    auto cli = make_client();
    // No "Bearer " prefix
    httplib::Headers h = {{"Authorization", "Basic dXNlcjpwYXNz"}};
    auto res = cli.Get("/api/mesh/peers/root", h);
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 401);
}

TEST_F(HttpEndpointTest, MeshHeartbeatNoAuth) {
    auto cli = make_client();
    json body = {{"node_id", "root"}, {"endpoint", "1.2.3.4:51820"}};
    auto res = cli.Post("/api/mesh/heartbeat", body.dump(), "application/json");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 401);
}

TEST_F(HttpEndpointTest, MeshPeersValidAuthRootNode) {
    auto cli = make_client();
    // Create a valid JWT with root's pubkey as user_id
    auto token = make_jwt(root_pubkey_str);
    httplib::Headers h = {{"Authorization", "Bearer " + token}};
    auto res = cli.Get("/api/mesh/peers/root", h);
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 200);

    auto body = json::parse(res->body);
    EXPECT_EQ(body["node_id"], "root");
    // Root has no siblings, so peers should be empty
    EXPECT_TRUE(body["peers"].empty());
}

TEST_F(HttpEndpointTest, MeshPeersNodeNotFound) {
    auto cli = make_client();
    auto token = make_jwt(root_pubkey_str);
    httplib::Headers h = {{"Authorization", "Bearer " + token}};
    auto res = cli.Get("/api/mesh/peers/nonexistent_node", h);
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 404);
}

TEST_F(HttpEndpointTest, MeshPeersUnauthorizedUser) {
    auto cli = make_client();
    // Create a JWT with a different user_id that has no permissions
    auto other_kp = crypto->ed25519_keygen();
    auto other_pubkey = "ed25519:" + crypto::to_base64(other_kp.public_key);
    auto token = make_jwt(other_pubkey);
    httplib::Headers h = {{"Authorization", "Bearer " + token}};
    auto res = cli.Get("/api/mesh/peers/root", h);
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 403);
}

TEST_F(HttpEndpointTest, MeshPeersSiblingDiscovery) {
    auto cli = make_client();

    // Create a customer group with two endpoint children
    tree::TreeNode group;
    group.id = "mesh_group";
    group.parent_id = "root";
    group.type = tree::NodeType::Customer;
    group.mgmt_pubkey = root_pubkey_str;
    group.assignments = {{root_pubkey_str, {"admin"}}};
    auto d1 = make_signed_delta("create_node", "mesh_group", group);
    post_auth_delta(cli, json(d1).dump());

    tree::TreeNode ep1;
    ep1.id = "mesh_ep1";
    ep1.parent_id = "mesh_group";
    ep1.type = tree::NodeType::Endpoint;
    ep1.mgmt_pubkey = root_pubkey_str;
    ep1.assignments = {{root_pubkey_str, {"admin"}}};
    ep1.mesh_pubkey = "mesh_pubkey_ep1";
    ep1.tunnel_ip = "10.0.0.2";
    ep1.hostname = "peer-alpha";
    auto d2 = make_signed_delta("create_node", "mesh_ep1", ep1);
    post_auth_delta(cli, json(d2).dump());

    tree::TreeNode ep2;
    ep2.id = "mesh_ep2";
    ep2.parent_id = "mesh_group";
    ep2.type = tree::NodeType::Endpoint;
    ep2.mgmt_pubkey = root_pubkey_str;
    ep2.assignments = {{root_pubkey_str, {"admin"}}};
    ep2.mesh_pubkey = "mesh_pubkey_ep2";
    ep2.tunnel_ip = "10.0.0.3";
    ep2.hostname = "peer-beta";
    auto d3 = make_signed_delta("create_node", "mesh_ep2", ep2);
    post_auth_delta(cli, json(d3).dump());

    // Request peers for ep1 — should see ep2 but not itself
    auto token = make_jwt(root_pubkey_str);
    httplib::Headers h = {{"Authorization", "Bearer " + token}};
    auto res = cli.Get("/api/mesh/peers/mesh_ep1", h);
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 200);

    auto body = json::parse(res->body);
    EXPECT_EQ(body["node_id"], "mesh_ep1");
    auto peers = body["peers"];
    EXPECT_EQ(peers.size(), 1u);
    EXPECT_EQ(peers[0]["node_id"], "mesh_ep2");
    EXPECT_EQ(peers[0]["hostname"], "peer-beta");
    EXPECT_EQ(peers[0]["mesh_pubkey"], "mesh_pubkey_ep2");
    EXPECT_EQ(peers[0]["tunnel_ip"], "10.0.0.3");
}

TEST_F(HttpEndpointTest, MeshPeersIDORPrevention) {
    auto cli = make_client();

    // Create two separate groups with endpoints — endpoint in group A
    // should NOT see endpoints in group B
    tree::TreeNode groupA;
    groupA.id = "idor_groupA";
    groupA.parent_id = "root";
    groupA.type = tree::NodeType::Customer;
    groupA.mgmt_pubkey = root_pubkey_str;
    groupA.assignments = {{root_pubkey_str, {"admin"}}};
    auto dA = make_signed_delta("create_node", "idor_groupA", groupA);
    post_auth_delta(cli, json(dA).dump());

    tree::TreeNode groupB;
    groupB.id = "idor_groupB";
    groupB.parent_id = "root";
    groupB.type = tree::NodeType::Customer;
    groupB.mgmt_pubkey = root_pubkey_str;
    groupB.assignments = {{root_pubkey_str, {"admin"}}};
    auto dB = make_signed_delta("create_node", "idor_groupB", groupB);
    post_auth_delta(cli, json(dB).dump());

    tree::TreeNode epA;
    epA.id = "idor_epA";
    epA.parent_id = "idor_groupA";
    epA.type = tree::NodeType::Endpoint;
    epA.mgmt_pubkey = root_pubkey_str;
    epA.assignments = {{root_pubkey_str, {"admin"}}};
    epA.mesh_pubkey = "mesh_A";
    auto dEpA = make_signed_delta("create_node", "idor_epA", epA);
    post_auth_delta(cli, json(dEpA).dump());

    tree::TreeNode epB;
    epB.id = "idor_epB";
    epB.parent_id = "idor_groupB";
    epB.type = tree::NodeType::Endpoint;
    epB.mgmt_pubkey = root_pubkey_str;
    epB.assignments = {{root_pubkey_str, {"admin"}}};
    epB.mesh_pubkey = "mesh_B";
    auto dEpB = make_signed_delta("create_node", "idor_epB", epB);
    post_auth_delta(cli, json(dEpB).dump());

    // Querying peers for epA should NOT include epB (different group)
    auto token = make_jwt(root_pubkey_str);
    httplib::Headers h = {{"Authorization", "Bearer " + token}};
    auto res = cli.Get("/api/mesh/peers/idor_epA", h);
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 200);

    auto body = json::parse(res->body);
    auto peers = body["peers"];
    // epA is the only endpoint in groupA, so peers should be empty
    EXPECT_TRUE(peers.empty());

    // epB should NOT appear in epA's peer list
    for (const auto& p : peers) {
        EXPECT_NE(p["node_id"], "idor_epB") << "Cross-group peer leak detected!";
    }
}

TEST_F(HttpEndpointTest, MeshHeartbeatUnauthorizedNode) {
    auto cli = make_client();

    // Create a node owned by root
    tree::TreeNode node;
    node.id = "hb_node";
    node.parent_id = "root";
    node.type = tree::NodeType::Endpoint;
    node.mgmt_pubkey = root_pubkey_str;
    auto d = make_signed_delta("create_node", "hb_node", node);
    post_auth_delta(cli, json(d).dump());

    // Try heartbeat with a different user (no EditNode permission)
    auto other_kp = crypto->ed25519_keygen();
    auto other_pubkey = "ed25519:" + crypto::to_base64(other_kp.public_key);
    auto token = make_jwt(other_pubkey);
    httplib::Headers h = {{"Authorization", "Bearer " + token}};
    json body = {{"node_id", "hb_node"}, {"endpoint", "1.2.3.4:51820"}};
    auto res = cli.Post("/api/mesh/heartbeat", h, body.dump(), "application/json");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 403);
}

TEST_F(HttpEndpointTest, MeshHeartbeatNonexistentNode) {
    auto cli = make_client();
    auto token = make_jwt(root_pubkey_str);
    httplib::Headers h = {{"Authorization", "Bearer " + token}};
    json body = {{"node_id", "ghost_node"}, {"endpoint", "1.2.3.4:51820"}};
    auto res = cli.Post("/api/mesh/heartbeat", h, body.dump(), "application/json");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 404);
}

TEST_F(HttpEndpointTest, MeshHeartbeatMissingNodeId) {
    auto cli = make_client();
    auto token = make_jwt(root_pubkey_str);
    httplib::Headers h = {{"Authorization", "Bearer " + token}};
    json body = {{"endpoint", "1.2.3.4:51820"}};
    auto res = cli.Post("/api/mesh/heartbeat", h, body.dump(), "application/json");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 400);
}

TEST_F(HttpEndpointTest, MeshHeartbeatInvalidEndpointFormat) {
    auto cli = make_client();

    // Create a node owned by root
    tree::TreeNode node;
    node.id = "hb_validate_node";
    node.parent_id = "root";
    node.type = tree::NodeType::Endpoint;
    node.mgmt_pubkey = root_pubkey_str;
    node.assignments = {{root_pubkey_str, {"admin"}}};
    auto d = make_signed_delta("create_node", "hb_validate_node", node);
    post_auth_delta(cli, json(d).dump());

    auto token = make_jwt(root_pubkey_str);
    httplib::Headers h = {{"Authorization", "Bearer " + token}};

    // Malformed: no port
    json body1 = {{"node_id", "hb_validate_node"}, {"endpoint", "just-a-string"}};
    auto res1 = cli.Post("/api/mesh/heartbeat", h, body1.dump(), "application/json");
    ASSERT_NE(res1, nullptr);
    EXPECT_EQ(res1->status, 400) << "Endpoint with no port should be rejected";

    // Malformed: shell injection attempt
    json body2 = {{"node_id", "hb_validate_node"}, {"endpoint", "1.2.3.4; rm -rf /"}};
    auto res2 = cli.Post("/api/mesh/heartbeat", h, body2.dump(), "application/json");
    ASSERT_NE(res2, nullptr);
    EXPECT_EQ(res2->status, 400) << "Shell injection in endpoint should be rejected";

    // Valid endpoint should succeed
    json body3 = {{"node_id", "hb_validate_node"}, {"endpoint", "203.0.113.1:51820"}};
    auto res3 = cli.Post("/api/mesh/heartbeat", h, body3.dump(), "application/json");
    ASSERT_NE(res3, nullptr);
    EXPECT_EQ(res3->status, 200) << "Valid ip:port endpoint should be accepted";

    // Empty endpoint should succeed (clearing endpoint)
    json body4 = {{"node_id", "hb_validate_node"}, {"endpoint", ""}};
    auto res4 = cli.Post("/api/mesh/heartbeat", h, body4.dump(), "application/json");
    ASSERT_NE(res4, nullptr);
    EXPECT_EQ(res4->status, 200) << "Empty endpoint (clear) should be accepted";
}

// --- Two-plane agreement on POST /api/tree/delta ---
//
// The delta handler is auth-gated, but apply_delta authorizes purely on
// delta.signer_pubkey's tree assignments plus a signature the caller claims to
// possess. The handler must additionally require the authenticated session
// identity (claims.pubkey) to BE the delta signer, or any session holder could
// submit deltas signed with another principal's captured management key.

TEST_F(HttpEndpointTest, DeltaSignerMatchesSessionIsApplied) {
    auto cli = make_client();

    // Session for the root key (same key that signs the delta below)
    auto token = make_jwt(root_pubkey_str);
    httplib::Headers h = {{"Authorization", "Bearer " + token}};

    tree::TreeNode child;
    child.id = "p14_match_child";
    child.parent_id = "root";
    child.type = tree::NodeType::Customer;
    child.mgmt_pubkey = root_pubkey_str;

    // Signed by root_keypair — the same identity the session authenticates
    auto delta = make_signed_delta("create_node", "p14_match_child", child);
    auto res = cli.Post("/api/tree/delta", h, json(delta).dump(), "application/json");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 200) << res->body;
    auto body = json::parse(res->body);
    EXPECT_TRUE(body.value("success", false));
    EXPECT_TRUE(tree->get_node("p14_match_child").has_value());
}

TEST_F(HttpEndpointTest, DeltaSignerMismatchWithSessionIsRejected) {
    auto cli = make_client();

    // A second principal with full permission on root (so apply_delta alone
    // WOULD authorize it) but whose key differs from the session identity.
    auto other_kp = crypto->ed25519_keygen();
    auto other_pubkey = "ed25519:" + crypto::to_base64(other_kp.public_key);
    tree->grant_assignment("root", {.management_pubkey = other_pubkey,
                                    .permissions = {"read", "write",
                                                    "add_child", "delete_node",
                                                    "edit_node", "admin"}});

    // Session authenticates as a DIFFERENT key (root), delta signs as other
    auto token = make_jwt(root_pubkey_str);
    httplib::Headers h = {{"Authorization", "Bearer " + token}};

    tree::TreeNode child;
    child.id = "p14_mismatch_child";
    child.parent_id = "root";
    child.type = tree::NodeType::Customer;
    child.mgmt_pubkey = other_pubkey;

    // Build the delta with the other principal as signer
    tree::TreeDelta delta;
    delta.operation      = "create_node";
    delta.target_node_id = "p14_mismatch_child";
    delta.node_data      = child;
    delta.signer_pubkey  = other_pubkey;
    delta.timestamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    auto canonical = tree::canonical_delta_json(delta);
    auto msg = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
    delta.signature = crypto::to_base64(
        crypto->ed25519_sign(other_kp.private_key, msg));

    auto res = cli.Post("/api/tree/delta", h, json(delta).dump(), "application/json");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 403) << res->body;
    // The tree must be unmutated
    EXPECT_FALSE(tree->get_node("p14_mismatch_child").has_value());
}

// --- P2-17: POST /api/routing/endpoint/register must not accept a
// caller-supplied mesh key as authoritative. The node's mesh public key is
// established at join/onboarding (tree->mesh_pubkey); a body override with a
// different key must be rejected and must NOT overwrite the trusted key,
// or an authenticated principal could MITM another node's mesh routing.

TEST_F(HttpEndpointTest, RoutingRegisterUsesTrustedMeshKey) {
    // Endpoint node whose mesh key is the identity-bound (X25519) form of the
    // session's Ed25519 key — the normal onboarding shape.
    auto ep_kp = crypto->ed25519_keygen();
    const std::string ep_pubkey = "ed25519:" + crypto::to_base64(ep_kp.public_key);
    const std::string trusted =
        api::identity_mesh_pubkey(ep_pubkey);
    ASSERT_FALSE(trusted.empty());

    tree::TreeNode node;
    node.id = "p17_ep1";
    node.parent_id = "root";
    node.type = tree::NodeType::Endpoint;
    node.mgmt_pubkey = root_pubkey_str;
    node.region = "us-east";
    node.cpu_id = "cpu-p17-1";
    node.net_mac = "aa:bb:cc:dd:ee:01";
    node.is_inference = true;
    node.mesh_pubkey = trusted;
    node.endpoint_identifier = routing::derive_endpoint_identifier(
        node.id, node.region, node.cpu_id, node.net_mac, node.is_inference);

    tree::TreeDelta delta;
    delta.operation = "create_node";
    delta.target_node_id = node.id;
    delta.node_data = node;
    delta.signer_pubkey = root_pubkey_str;
    delta.timestamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    auto canonical = tree::canonical_delta_json(delta);
    auto msg = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
    delta.signature = crypto::to_base64(
        crypto->ed25519_sign(root_keypair.private_key, msg));
    ASSERT_TRUE(tree->apply_delta(delta));

    auto cli = make_client();
    httplib::Headers h = {{"Authorization", "Bearer " + make_jwt("p17_ep1")}};
    json body = {{"cpu_id", node.cpu_id}, {"net_mac", node.net_mac},
                 {"mesh_pubkey", trusted}};  // matches the trusted key
    auto res = cli.Post("/api/routing/endpoint/register", h, body.dump(),
                        "application/json");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 200) << res->body;
    auto resp = json::parse(res->body);
    EXPECT_TRUE(resp.value("success", false));
    EXPECT_EQ(resp["endpoint_identifier"].get<std::string>(),
              node.endpoint_identifier);

    // The node's registered mesh key must be the trusted one.
    const auto stored = tree->get_node("p17_ep1");
    ASSERT_TRUE(stored.has_value());
    EXPECT_EQ(stored->mesh_pubkey, trusted);
}

TEST_F(HttpEndpointTest, RoutingRegisterRejectsForeignMeshKey) {
    auto ep_kp = crypto->ed25519_keygen();
    const std::string ep_pubkey = "ed25519:" + crypto::to_base64(ep_kp.public_key);
    const std::string trusted = api::identity_mesh_pubkey(ep_pubkey);
    ASSERT_FALSE(trusted.empty());

    tree::TreeNode node;
    node.id = "p17_ep2";
    node.parent_id = "root";
    node.type = tree::NodeType::Endpoint;
    node.mgmt_pubkey = root_pubkey_str;
    node.region = "us-east";
    node.cpu_id = "cpu-p17-2";
    node.net_mac = "aa:bb:cc:dd:ee:02";
    node.is_inference = true;
    node.mesh_pubkey = trusted;
    node.endpoint_identifier = routing::derive_endpoint_identifier(
        node.id, node.region, node.cpu_id, node.net_mac, node.is_inference);

    tree::TreeDelta delta;
    delta.operation = "create_node";
    delta.target_node_id = node.id;
    delta.node_data = node;
    delta.signer_pubkey = root_pubkey_str;
    delta.timestamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    auto canonical = tree::canonical_delta_json(delta);
    auto msg = std::span<const uint8_t>(
        reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
    delta.signature = crypto::to_base64(
        crypto->ed25519_sign(root_keypair.private_key, msg));
    ASSERT_TRUE(tree->apply_delta(delta));

    auto cli = make_client();
    httplib::Headers h = {{"Authorization", "Bearer " + make_jwt("p17_ep2")}};
    // Attacker-controlled mesh key in the body — must be refused.
    json body = {{"cpu_id", node.cpu_id}, {"net_mac", node.net_mac},
                 {"mesh_pubkey", "attacker-controlled-mesh-key"}};
    auto res = cli.Post("/api/routing/endpoint/register", h, body.dump(),
                        "application/json");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 409) << res->body;

    // The node's registered mesh key must remain the trusted one.
    const auto stored = tree->get_node("p17_ep2");
    ASSERT_TRUE(stored.has_value());
    EXPECT_EQ(stored->mesh_pubkey, trusted);
}
