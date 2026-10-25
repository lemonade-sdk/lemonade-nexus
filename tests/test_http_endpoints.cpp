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
#include <LemonadeNexus/Network/DnsService.hpp>
#include <LemonadeNexus/Core/ServerIdentity.hpp>
#include <LemonadeNexus/Acme/AcmeService.hpp>
#include <LemonadeNexus/Core/ServerConfig.hpp>
#include <LemonadeNexus/Api/IRequestHandler.hpp>
#include <LemonadeNexus/Api/TreeApiHandler.hpp>
#include <LemonadeNexus/Api/MeshApiHandler.hpp>
#include <LemonadeNexus/Api/RoutingApiHandler.hpp>
#include <LemonadeNexus/Api/MeshApiHandler.hpp>
#include <LemonadeNexus/Api/MeshRekey.hpp>
#include <LemonadeNexus/Routing/IdentifierDerivation.hpp>

#include <gtest/gtest.h>
#include "test_http_ready.hpp"
#include "support/tree_ops_mode.hpp"
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <jwt-cpp/jwt.h>
#include <openssl/evp.h>
#include <openssl/bn.h>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <set>
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
                    network::DnsService& dns,
                    relay::RelayService& relay,
                    relay::RelayDiscoveryService& rd,
                    routing::RoutingCoordinationService& routing,
                    core::BinaryAttestationService& att,
                    core::ServerAdmissionService& adm,
                    tree::TreeOpSubmitter* tree_ops) {
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
        .dns              = &dns,
        .server_fqdn      = "test.local",
        .server_seip_fqdn = "",
        .server_private_fqdn = "",
        .server_public_ip = "",
        .tunnel_bind_ip   = "",
        .tree_ops         = tree_ops,
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
    // Dedicated reactor for the DNS listener: the shared `io` above is never
    // run in this fixture, and DnsService answers queries asynchronously.
    asio::io_context dns_io;
    std::thread dns_io_thread;
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
    std::unique_ptr<network::DnsService> dns;
    std::unique_ptr<acme::AcmeService> acme;
    core::ServerConfig config;
    test_support::TreeOpsMode tree_ops_mode;

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

        // Real, running DNS service on an ephemeral port so the issue #22
        // assertions query the zone over UDP exactly like a client would.
        for (int attempt = 0; attempt < 8 && !dns; ++attempt) {
            try {
                dns = std::make_unique<network::DnsService>(
                    dns_io, 0, *tree, config.dns_base_domain);
                dns->start();
            } catch (const std::exception&) {
                if (dns) {
                    dns->stop();
                    dns.reset();
                }
            }
        }
        ASSERT_TRUE(dns) << "could not bind the DNS service on an ephemeral port";
        dns_io_thread = std::thread([this] {
            auto guard = asio::make_work_guard(dns_io);
            dns_io.run();
        });

        auto* tree_ops = tree_ops_mode.enable(config, *tree, *crypto);
        test_api::install(config, *auth, *tree, *ipam, *gossip, *crypto,
                          *key_wrapping, *storage, *acme, *http, *ddns, *dns,
                          *relay, *relay_discovery, *routing, *attestation,
                          *admission, tree_ops);
        register_routes();
        test_api::handler().register_routes(http->server(), http->server());
        test_api::routing_handler().register_routes(http->server(), http->server());
        http->start();

        // Wait until the server thread actually accepts connections; a fixed
        // sleep races on loaded CI runners (first request refused, 10-14).
        ASSERT_TRUE(wait_http_ready(test_port_))
            << "HTTP server not accepting on port " << test_port_;
    }

    void TearDown() override {
        test_api::reset();
        if (dns) dns->stop();
        dns_io.stop();
        if (dns_io_thread.joinable()) dns_io_thread.join();
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

    /// Full Ed25519 challenge-response join; returns the /api/join response.
    /// Uses the same AuthService instance the handler authenticates against,
    /// so the challenge round-trip is exactly what the join route performs.
    httplib::Result join_node(const crypto::Ed25519Keypair& kp,
                              const std::string& link_token = {}) {
        const auto bare = crypto::to_base64(
            std::span<const uint8_t>(kp.public_key.data(),
                                     kp.public_key.size()));
        const auto challenge_b64 =
            auth->issue_ed25519_challenge(bare).value("challenge", std::string{});
        auto challenge = crypto::from_base64(challenge_b64);
        auto sig = crypto->ed25519_sign(kp.private_key,
                                        std::span<const uint8_t>(challenge));
        json body = {
            {"method", "ed25519"},
            {"pubkey", bare},
            {"public_key", "ed25519:" + bare},
            {"challenge", challenge_b64},
            {"signature", crypto::to_base64(sig)},
        };
        if (!link_token.empty()) body["link_token"] = link_token;
        return make_client().Post("/api/join", body.dump(), "application/json");
    }

    /// Raw UDP A query for `fqdn` against the fixture's DNS service.
    /// Returns the response bytes; empty on a transport or encode error.
    std::vector<uint8_t> dns_a_query(const std::string& fqdn) {
        const auto query = nexus::core::build_dns_query(fqdn, 1, 0x1234);
        if (query.empty() || !dns || dns->local_port() == 0) return {};
        asio::io_context client;
        asio::ip::udp::socket sock(client,
                                   asio::ip::udp::endpoint(asio::ip::udp::v4(), 0));
        asio::error_code ec;
        sock.send_to(asio::buffer(query),
                     {asio::ip::make_address("127.0.0.1"), dns->local_port()});
        if (ec) return {};
        std::vector<uint8_t> reply(512);
        asio::ip::udp::endpoint from;
        const std::size_t n = sock.receive_from(asio::buffer(reply), from, 0, ec);
        if (ec) return {};
        reply.resize(n);
        return reply;
    }

    /// True when an A query for `fqdn` answers exactly one record whose
    /// RDATA is `ip`.
    bool dns_a_resolves_to(const std::string& fqdn, const std::string& ip) {
        const auto reply = dns_a_query(fqdn);
        if (reply.size() < 12 ||
            static_cast<std::size_t>(reply[6]) * 256u + reply[7] != 1u) {
            return false;
        }
        unsigned a = 0, b = 0, c = 0, d = 0;
        if (std::sscanf(ip.c_str(), "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
            return false;
        }
        const uint8_t want[4] = {static_cast<uint8_t>(a), static_cast<uint8_t>(b),
                                 static_cast<uint8_t>(c), static_cast<uint8_t>(d)};
        for (std::size_t i = 0; i + 4 <= reply.size(); ++i) {
            if (reply[i] == want[0] && reply[i + 1] == want[1] &&
                reply[i + 2] == want[2] && reply[i + 3] == want[3]) {
                return true;
            }
        }
        return false;
    }

    /// Number of answer records for an A query of `fqdn` (0 = NXDOMAIN or
    /// unresolvable name).
    std::size_t dns_a_answer_count(const std::string& fqdn) {
        const auto reply = dns_a_query(fqdn);
        if (reply.size() < 12) return 0;
        return static_cast<std::size_t>(reply[6]) * 256u + reply[7];
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

    /// Same as above but signed by an arbitrary identity (e.g. a device key
    /// that holds its own node's delete_node grant).
    tree::TreeDelta make_signed_delta(const std::string& operation,
                                       const std::string& target_node_id,
                                       const tree::TreeNode& node_data,
                                       const crypto::Ed25519Keypair& signer_kp,
                                       const std::string& signer_pubkey) {
        tree::TreeDelta delta;
        delta.operation = operation;
        delta.target_node_id = target_node_id;
        delta.node_data = node_data;
        delta.signer_pubkey = signer_pubkey;
        delta.timestamp = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::seconds>(
                std::chrono::system_clock::now().time_since_epoch()).count());

        auto canonical = tree::canonical_delta_json(delta);
        auto msg = std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(canonical.data()), canonical.size());
        auto sig = crypto->ed25519_sign(signer_kp.private_key, msg);
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

// --- Delete cascade via signed delta (issue #17: revocation bypass) ---
//
// The delta route must run the same post-delete cascade as the direct route:
// credential revocation (owner-protected), IPAM release, mesh peer removal.
// (boringtun is nullptr in this fixture, so only the first two are asserted.)

TEST_F(HttpEndpointTest, DeltaDeleteRevokesKeyAndReleasesIpam) {
    auto cli = make_client();

    // Linked device holds its own Ed25519 key as the node's mgmt_pubkey.
    auto device_kp = crypto->ed25519_keygen();
    const auto device_b64 = crypto::to_base64(
        std::span<const uint8_t>(device_kp.public_key.data(),
                                 device_kp.public_key.size()));
    const auto device_pubkey = "ed25519:" + device_b64;

    // Baseline: an unrevoked device key passes session validation.
    ASSERT_TRUE(auth->validate_session_claims(make_jwt(device_b64)).has_value());

    // Create the node via delta: owned by the device key, deletable by root.
    tree::TreeNode node;
    node.id = "cascade_node1";
    node.parent_id = "root";
    node.type = tree::NodeType::Endpoint;
    node.mgmt_pubkey = device_pubkey;
    node.assignments = {{root_pubkey_str, {"admin"}}};
    auto create = make_signed_delta("create_node", node.id, node);
    auto res = post_auth_delta(cli, json(create).dump());
    ASSERT_NE(res, nullptr);
    ASSERT_EQ(res->status, 200);

    // Allocate a tunnel IP; the delete cascade must release it.
    auto alloc = ipam->allocate_tunnel_ip(node.id);
    ASSERT_FALSE(alloc.base_network.empty());
    ASSERT_TRUE(ipam->get_allocation(node.id)->tunnel.has_value());

    // Delete via the signed-delta route.
    auto del = make_signed_delta("delete_node", node.id, tree::TreeNode{});
    auto del_res = post_auth_delta(cli, json(del).dump());
    ASSERT_NE(del_res, nullptr);
    ASSERT_EQ(del_res->status, 200);

    // Node is gone.
    auto get_res = cli.Get("/api/tree/node/" + node.id);
    ASSERT_NE(get_res, nullptr);
    EXPECT_EQ(get_res->status, 404);

    // The device key was the only holder → revoked: sessions invalidate.
    EXPECT_FALSE(auth->validate_session_claims(make_jwt(device_b64)).has_value());

    // IPAM allocation released back to the pool.
    EXPECT_FALSE(ipam->get_allocation(node.id).has_value());
}

TEST_F(HttpEndpointTest, DeltaDeleteKeepsSharedKey) {
    auto cli = make_client();

    // Owner-protection: two nodes share one mgmt key (an owner's own devices
    // hold the same key as their group). Deleting one via delta must NOT
    // revoke a key a surviving node still owns.
    auto owner_kp = crypto->ed25519_keygen();
    const auto owner_b64 = crypto::to_base64(
        std::span<const uint8_t>(owner_kp.public_key.data(),
                                 owner_kp.public_key.size()));
    const auto owner_pubkey = "ed25519:" + owner_b64;

    for (const auto& id : {"cascade_shared_a", "cascade_shared_b"}) {
        tree::TreeNode node;
        node.id = id;
        node.parent_id = "root";
        node.type = tree::NodeType::Endpoint;
        node.mgmt_pubkey = owner_pubkey;
        node.assignments = {{root_pubkey_str, {"admin"}}};
        auto create = make_signed_delta("create_node", id, node);
        auto res = post_auth_delta(cli, json(create).dump());
        ASSERT_NE(res, nullptr);
        ASSERT_EQ(res->status, 200);
    }

    // Delete one of the two via the signed-delta route.
    auto del = make_signed_delta("delete_node", "cascade_shared_a", tree::TreeNode{});
    auto del_res = post_auth_delta(cli, json(del).dump());
    ASSERT_NE(del_res, nullptr);
    ASSERT_EQ(del_res->status, 200);

    // The surviving node still holds the key → it must NOT be revoked.
    EXPECT_TRUE(auth->validate_session_claims(make_jwt(owner_b64)).has_value());

    // Surviving node is intact.
    auto get_res = cli.Get("/api/tree/node/cascade_shared_b");
    ASSERT_NE(get_res, nullptr);
    EXPECT_EQ(get_res->status, 200);
}

// --- Private EP DNS record removal (issue #22: stale A record after delete) ---
//
// Join registers a dynamic A record private.<node_id>.ep.<domain> -> tunnel
// IP. Both delete routes must remove it through cascade_node_cleanup, or the
// stale record keeps resolving to a tunnel IP IPAM has already recycled
// (which may now belong to a different, live node).

TEST_F(HttpEndpointTest, DirectDeleteRemovesPrivateEpDnsRecord) {
    auto cli = make_client();

    // Node joins; the join route registers its private EP A record.
    auto device_kp = crypto->ed25519_keygen();
    const auto device_b64 = crypto::to_base64(
        std::span<const uint8_t>(device_kp.public_key.data(),
                                 device_kp.public_key.size()));
    auto join_res = join_node(device_kp);
    ASSERT_NE(join_res, nullptr);
    ASSERT_EQ(join_res->status, 200);
    auto join = json::parse(join_res->body);
    const auto node_id = join.value("node_id", std::string{});
    const auto fqdn = join.value("client_private_fqdn", std::string{});
    const auto tunnel_ip = join.value("tunnel_ip", std::string{});
    ASSERT_FALSE(node_id.empty());
    ASSERT_FALSE(fqdn.empty());
    // The FQDN matches the documented private EP format byte-for-byte.
    EXPECT_EQ(fqdn, "private." + node_id + ".ep." + config.dns_base_domain);
    const auto ip = tunnel_ip.substr(0, tunnel_ip.find('/'));
    ASSERT_FALSE(ip.empty());

    // The A record is present after join (served over UDP like a client query).
    ASSERT_TRUE(dns_a_resolves_to(fqdn, ip));

    // Delete via the DIRECT route; the owner holds delete_node on their own
    // endpoint.
    httplib::Headers h = {{"Authorization", "Bearer " + make_jwt(device_b64)}};
    auto del_res = cli.Post("/api/tree/node/delete/" + node_id, h);
    ASSERT_NE(del_res, nullptr);
    ASSERT_EQ(del_res->status, 200);

    // Node is gone and its A record no longer answers over UDP.
    auto get_res = cli.Get("/api/tree/node/" + node_id);
    ASSERT_NE(get_res, nullptr);
    EXPECT_EQ(get_res->status, 404);
    EXPECT_EQ(dns_a_answer_count(fqdn), 0u);
}

TEST_F(HttpEndpointTest, DeltaDeleteRemovesPrivateEpDnsRecord) {
    auto cli = make_client();

    // Node joins; the join route registers its private EP A record.
    auto device_kp = crypto->ed25519_keygen();
    const auto device_b64 = crypto::to_base64(
        std::span<const uint8_t>(device_kp.public_key.data(),
                                 device_kp.public_key.size()));
    auto join_res = join_node(device_kp);
    ASSERT_NE(join_res, nullptr);
    ASSERT_EQ(join_res->status, 200);
    auto join = json::parse(join_res->body);
    const auto node_id = join.value("node_id", std::string{});
    const auto fqdn = join.value("client_private_fqdn", std::string{});
    ASSERT_FALSE(node_id.empty());
    ASSERT_FALSE(fqdn.empty());
    EXPECT_EQ(fqdn, "private." + node_id + ".ep." + config.dns_base_domain);
    ASSERT_NE(dns_a_answer_count(fqdn), 0u);

    // Delete via the SIGNED-DELTA route. The device holds delete_node on its
    // own endpoint, so it signs the delta and authenticates as itself.
    auto del = make_signed_delta("delete_node", node_id, tree::TreeNode{},
                                 device_kp, "ed25519:" + device_b64);
    httplib::Headers h = {{"Authorization", "Bearer " + make_jwt(device_b64)}};
    auto del_res = cli.Post("/api/tree/delta", h, json(del).dump(),
                            "application/json");
    ASSERT_NE(del_res, nullptr);
    ASSERT_EQ(del_res->status, 200);

    // Node is gone and its A record no longer answers over UDP.
    auto get_res = cli.Get("/api/tree/node/" + node_id);
    ASSERT_NE(get_res, nullptr);
    EXPECT_EQ(get_res->status, 404);
    EXPECT_EQ(dns_a_answer_count(fqdn), 0u);
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

// --- Fail-closed delta body parsing ---
//
// The legacy manual fallback re-parsed operation/target_node_id/node_data/
// signer_pubkey/signature by hand, silently zero-filling whatever was missing
// and deferring rejection to apply_delta. The typed TreeDelta parse is now the
// single source of truth: a body it rejects must get a 400 here and must not
// reach the tree.

TEST_F(HttpEndpointTest, DeltaMalformedBodyIsRejectedFailClosed) {
    auto cli = make_client();

    // Seed a live node so the malformed delta has a real target and we can
    // prove the tree is unmutated.
    tree::TreeNode child;
    child.id = "p18_badbody_child";
    child.parent_id = "root";
    child.type = tree::NodeType::Customer;
    child.mgmt_pubkey = root_pubkey_str;
    auto create = make_signed_delta("create_node", child.id, child);
    auto create_res = post_auth_delta(cli, json(create).dump());
    ASSERT_NE(create_res, nullptr);
    ASSERT_EQ(create_res->status, 200) << create_res->body;

    // Fallback-shaped body: no node_data, no timestamp — the old manual
    // parse accepted this (zero-filled node_data) and only apply_delta
    // rejected it. The typed parse must reject it at the boundary.
    json body = {
        {"operation", "update_node"},
        {"target_node_id", child.id},
        {"signer_pubkey", root_pubkey_str},
        {"signature", ""},
    };
    auto res = post_auth_delta(cli, body.dump());
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 400) << res->body;
    EXPECT_EQ(json::parse(res->body).value("error", std::string{}),
              "invalid delta body");

    // Node unchanged: still present with its original identity.
    auto stored = tree->get_node(child.id);
    ASSERT_TRUE(stored.has_value());
    EXPECT_EQ(stored->mgmt_pubkey, root_pubkey_str);
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

// --- Assignment administration endpoint ---

TEST_F(HttpEndpointTest, AssignmentEndpointAppliesTheAdminRules) {
    auto cli = make_client();
    auto bare_of = [](const crypto::Ed25519Keypair& kp) {
        return crypto::to_base64(std::span<const uint8_t>(kp.public_key.data(),
                                                          kp.public_key.size()));
    };
    auto owner_kp = crypto->ed25519_keygen();
    auto other_kp = crypto->ed25519_keygen();
    const auto owner_b64 = bare_of(owner_kp);
    const auto other_b64 = bare_of(other_kp);

    auto owner_join = join_node(owner_kp);
    ASSERT_NE(owner_join, nullptr);
    ASSERT_EQ(owner_join->status, 200) << owner_join->body;
    const auto owner_node = json::parse(owner_join->body).value("node_id", std::string{});
    const auto group = tree->get_node(owner_node)->parent_id;
    auto other_join = join_node(other_kp);
    ASSERT_NE(other_join, nullptr);
    ASSERT_EQ(other_join->status, 200) << other_join->body;

    auto post = [&](const std::string& as_b64, const std::string& node, json body) {
        httplib::Headers h = {{"Authorization", "Bearer " + make_jwt(as_b64)}};
        return cli.Post("/api/tree/node/assignments/" + node, h, body.dump(),
                        "application/json");
    };

    // The group owner administers its own device: node-level access applies.
    auto ok = post(owner_b64, owner_node,
                   {{"pubkey", owner_b64}, {"permissions", {"read", "connect_private"}}});
    ASSERT_NE(ok, nullptr);
    EXPECT_EQ(ok->status, 200) << ok->body;
    EXPECT_TRUE(tree->check_permission("ed25519:" + owner_b64, owner_node,
                                       acl::Permission::ConnectPrivate));

    // Someone from another group is not an admin here...
    auto not_admin = post(other_b64, owner_node,
                          {{"pubkey", other_b64}, {"permissions", {"admin"}}});
    ASSERT_NE(not_admin, nullptr);
    EXPECT_EQ(not_admin->status, 403);
    // ...and has not joined this group, so the owner cannot grant it either.
    auto not_joined = post(owner_b64, group,
                           {{"pubkey", other_b64}, {"permissions", {"read"}}});
    ASSERT_NE(not_joined, nullptr);
    EXPECT_EQ(not_joined->status, 403);
    EXPECT_FALSE(tree->check_permission("ed25519:" + other_b64, group,
                                        acl::Permission::Read));

    auto bad = post(owner_b64, owner_node, {{"pubkey", owner_b64}});
    ASSERT_NE(bad, nullptr);
    EXPECT_EQ(bad->status, 400);
}

// --- Tree write routes with and without tree operations ---
//
// test_http_endpoints_tree_ops builds this file with NEXUS_TEST_TREE_OPS, so
// each case here and above also runs with ServerConfig::tree_ops_enabled.
// Only the version counter and a joined endpoint's tunnel address (derived
// from the tree instead of allocated by IPAM) may differ between the builds.

TEST_F(HttpEndpointTest, NodeRoutesAnswerTheSameInBothModes) {
    auto cli = make_client();
    // POST /api/tree/node names the node "node-" + the first 16 characters of
    // the caller's key in the URL-safe base64 alphabet. Pick a key whose
    // standard spelling has a '/' there: that once made the node file
    // unwritable and the route answer 409.
    crypto::Ed25519Keypair owner_kp;
    std::string owner_b64;
    do {
        owner_kp = crypto->ed25519_keygen();
        owner_b64 = crypto::to_base64(std::span<const uint8_t>(
            owner_kp.public_key.data(), owner_kp.public_key.size()));
    } while (owner_b64.substr(0, 16).find('/') == std::string::npos);
    std::string owner_id_part = owner_b64.substr(0, 16);
    for (auto& c : owner_id_part) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }
    auto stranger_kp = crypto->ed25519_keygen();
    const auto stranger_b64 = crypto::to_base64(std::span<const uint8_t>(
        stranger_kp.public_key.data(), stranger_kp.public_key.size()));
    auto join_res = join_node(owner_kp);
    ASSERT_NE(join_res, nullptr);
    ASSERT_EQ(join_res->status, 200) << join_res->body;
    const auto ep = json::parse(join_res->body).value("node_id", std::string{});
    const auto group = tree->get_node(ep)->parent_id;
    const httplib::Headers owner = {{"Authorization", "Bearer " + make_jwt(owner_b64)}};
    const httplib::Headers stranger = {{"Authorization", "Bearer " + make_jwt(stranger_b64)}};

    // Create under the owner's group; repeating it is idempotent.
    const json create = {{"parent_id", group}, {"type", "endpoint"}, {"hostname", "laptop-2"}};
    auto c1 = cli.Post("/api/tree/node", owner, create.dump(), "application/json");
    ASSERT_NE(c1, nullptr);
    ASSERT_EQ(c1->status, 200) << c1->body;
    const auto created = json::parse(c1->body).value("node_id", std::string{});
    EXPECT_EQ(created, "node-" + owner_id_part);
    ASSERT_TRUE(tree->get_node(created).has_value());
    EXPECT_EQ(tree->get_node(created)->hostname, "laptop-2");
    auto c2 = cli.Post("/api/tree/node", owner, create.dump(), "application/json");
    ASSERT_NE(c2, nullptr);
    EXPECT_EQ(c2->status, 200) << c2->body;
    auto bad_type = cli.Post("/api/tree/node", owner,
                             json{{"parent_id", group}, {"type", "planet"}}.dump(),
                             "application/json");
    ASSERT_NE(bad_type, nullptr);
    EXPECT_EQ(bad_type->status, 400);
    auto no_add_child = cli.Post("/api/tree/node", stranger, create.dump(), "application/json");
    ASSERT_NE(no_add_child, nullptr);
    EXPECT_EQ(no_add_child->status, 403);

    // Update the owner's own endpoint.
    auto u1 = cli.Post("/api/tree/node/update/" + ep, owner,
                       json{{"hostname", "renamed"}, {"region", "eu-west"}}.dump(),
                       "application/json");
    ASSERT_NE(u1, nullptr);
    ASSERT_EQ(u1->status, 200) << u1->body;
    EXPECT_EQ(tree->get_node(ep)->hostname, "renamed");
    EXPECT_EQ(tree->get_node(ep)->region, "eu-west");
    auto u2 = cli.Post("/api/tree/node/update/" + ep, stranger,
                       json{{"hostname", "hijacked"}}.dump(), "application/json");
    ASSERT_NE(u2, nullptr);
    EXPECT_EQ(u2->status, 403);
    EXPECT_EQ(tree->get_node(ep)->hostname, "renamed");

    // Assignment refusals keep their status codes and reasons.
    auto bad_perm = cli.Post("/api/tree/node/assignments/" + ep, owner,
                             json{{"pubkey", owner_b64}, {"permissions", {"fly"}}}.dump(),
                             "application/json");
    ASSERT_NE(bad_perm, nullptr);
    EXPECT_EQ(bad_perm->status, 400);
    EXPECT_EQ(json::parse(bad_perm->body).value("error", std::string{}),
              "unknown permission 'fly'");
    auto missing = cli.Post("/api/tree/node/assignments/no-such-node", owner,
                            json{{"pubkey", owner_b64}, {"permissions", {"read"}}}.dump(),
                            "application/json");
    ASSERT_NE(missing, nullptr);
    EXPECT_EQ(missing->status, 404);
    EXPECT_EQ(json::parse(missing->body).value("error", std::string{}), "node not found");

    // Delete the owner's endpoint; it is gone and cannot be deleted twice.
    auto d1 = cli.Post("/api/tree/node/delete/" + ep, owner);
    ASSERT_NE(d1, nullptr);
    ASSERT_EQ(d1->status, 200) << d1->body;
    EXPECT_FALSE(tree->get_node(ep).has_value());
    EXPECT_FALSE(ipam->get_allocation(ep).has_value());
    auto d2 = cli.Post("/api/tree/node/delete/" + ep, owner);
    ASSERT_NE(d2, nullptr);
    EXPECT_EQ(d2->status, 403);
}

TEST_F(HttpEndpointTest, NodeVersionsAdvanceOnlyWithTreeOperations) {
    auto cli = make_client();
    auto owner_kp = crypto->ed25519_keygen();
    const auto owner_b64 = crypto::to_base64(std::span<const uint8_t>(
        owner_kp.public_key.data(), owner_kp.public_key.size()));
    auto join_res = join_node(owner_kp);
    ASSERT_NE(join_res, nullptr);
    ASSERT_EQ(join_res->status, 200) << join_res->body;
    const auto ep = json::parse(join_res->body).value("node_id", std::string{});
    const httplib::Headers owner = {{"Authorization", "Bearer " + make_jwt(owner_b64)}};
    auto u = cli.Post("/api/tree/node/update/" + ep, owner,
                      json{{"hostname", "v2"}}.dump(), "application/json");
    ASSERT_NE(u, nullptr);
    ASSERT_EQ(u->status, 200) << u->body;

    const auto stored = tree->get_node(ep);
    ASSERT_TRUE(stored.has_value());
    // Join wrote version 1 and the update version 2; the direct paths keep 0,
    // and at 0 the stored JSON has no "version" field at all.
    EXPECT_EQ(stored->version, test_support::kTreeOpsBuild ? 2u : 0u);
    EXPECT_EQ(json(*stored).contains("version"), test_support::kTreeOpsBuild);
}

TEST_F(HttpEndpointTest, TreeOpsWithoutSubmitterFailClosed) {
    // The flag on with no submitter wired must not fall back to direct writes.
    auto cli = make_client();
    test_api::current().config->tree_ops_enabled = true;
    test_api::current().ctx->tree_ops = nullptr;

    tree::TreeNode child;
    child.id = "failclosed_child";
    child.parent_id = "root";
    child.type = tree::NodeType::Customer;
    child.mgmt_pubkey = root_pubkey_str;
    auto res = post_auth_delta(cli, json(make_signed_delta("create_node", child.id, child)).dump());
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 500);
    EXPECT_FALSE(tree->get_node(child.id).has_value());

    auto device_kp = crypto->ed25519_keygen();
    auto join_res = join_node(device_kp);
    ASSERT_NE(join_res, nullptr);
    EXPECT_EQ(join_res->status, 500);
    EXPECT_TRUE(tree->get_children("root").empty());
}

// The production heartbeat route (MeshApiHandler). With tree operations on,
// a changed endpoint is a SetEndpoint operation that only the node's own key
// may submit, and an unchanged endpoint writes nothing.
TEST_F(HttpEndpointTest, HeartbeatEndpointWritesFollowTheTreeOperationRules) {
    auto device_kp = crypto->ed25519_keygen();
    auto join_res = join_node(device_kp);
    ASSERT_NE(join_res, nullptr);
    ASSERT_EQ(join_res->status, 200) << join_res->body;
    const auto node_id = json::parse(join_res->body).value("node_id", std::string{});
    const auto version_before = tree->get_node(node_id)->version;

    httplib::Server mesh_srv;
    api::MeshApiHandler mesh(*test_api::current().ctx);
    mesh.register_routes(mesh_srv, mesh_srv);
    // An ephemeral port, so parallel test processes never collide.
    const int bound = mesh_srv.bind_to_any_port("127.0.0.1");
    ASSERT_GT(bound, 0);
    const auto mesh_port = static_cast<uint16_t>(bound);
    std::thread mesh_thread([&] { mesh_srv.listen_after_bind(); });
    ASSERT_TRUE(wait_http_ready(mesh_port));
    httplib::Client mesh_cli("127.0.0.1", mesh_port);

    auto session = [&](const crypto::Ed25519Keypair& kp) {
        const auto bare = crypto::to_base64(
            std::span<const uint8_t>(kp.public_key.data(), kp.public_key.size()));
        auto now = std::chrono::system_clock::now();
        const auto token = jwt::create()
                               .set_issuer("lemonade-nexus")
                               .set_subject(node_id)
                               .set_issued_at(now)
                               .set_expires_at(now + std::chrono::hours{1})
                               .set_payload_claim("pubkey", jwt::claim(bare))
                               .sign(jwt::algorithm::hs256{jwt_secret});
        return httplib::Headers{{"Authorization", "Bearer " + token}};
    };
    const json body = {{"node_id", node_id}, {"endpoint", "203.0.113.9:51940"}};

    auto res = mesh_cli.Post("/api/mesh/heartbeat", session(device_kp), body.dump(),
                             "application/json");
    ASSERT_NE(res, nullptr);
    ASSERT_EQ(res->status, 200) << res->body;
    EXPECT_EQ(tree->get_node(node_id)->listen_endpoint, "203.0.113.9:51940");
    if (test_support::kTreeOpsBuild) {
        EXPECT_EQ(json::parse(res->body).value("status", std::string{}), "committed");
        EXPECT_EQ(tree->get_node(node_id)->version, version_before + 1);

        // The same endpoint again: no operation, no version change.
        res = mesh_cli.Post("/api/mesh/heartbeat", session(device_kp), body.dump(),
                            "application/json");
        ASSERT_NE(res, nullptr);
        EXPECT_EQ(json::parse(res->body).value("status", std::string{}), "unchanged");
        EXPECT_EQ(tree->get_node(node_id)->version, version_before + 1);

        // A session naming the node but holding another key is refused by the
        // operation's ownership rule.
        const auto other_kp = crypto->ed25519_keygen();
        const json moved = {{"node_id", node_id}, {"endpoint", "203.0.113.10:51940"}};
        res = mesh_cli.Post("/api/mesh/heartbeat", session(other_kp), moved.dump(),
                            "application/json");
        ASSERT_NE(res, nullptr);
        EXPECT_EQ(res->status, 403);
        EXPECT_EQ(tree->get_node(node_id)->listen_endpoint, "203.0.113.9:51940");
    }
    mesh_srv.stop();
    mesh_thread.join();
}

// Under consensus a write that does not commit within the wait answers 202
// with its op id, and the op's status is polled (design A2). A server that
// cannot order tree operations answers 503. Nothing is applied before commit.
TEST_F(HttpEndpointTest, AnUncommittedTreeWriteAnswersPendingWithItsOpId) {
    auto cli = make_client();
    tree::TreeOpPool pool;
    const auto submitter_key = crypto->ed25519_keygen();
    tree::TreeOpSubmitter ordered(
        *tree, *crypto, security::NetworkId{}, submitter_key,
        [&pool](tree::TreeOp op) {
            tree::TreeOpAdmission admission;
            admission.ticket = std::make_shared<tree::TreeOpTicket>(tree::op_id_hex(op));
            (void)pool.add(std::move(op), admission.ticket);
            return admission;
        },
        std::chrono::milliseconds(20));
    test_api::current().config->tree_ops_enabled = true;
    test_api::current().ctx->tree_ops = &ordered;
    test_api::current().ctx->tree_op_status = [&pool](const std::string& id) {
        return pool.status(id);
    };

    tree::TreeNode child;
    child.id = "pending_child";
    child.parent_id = "root";
    child.type = tree::NodeType::Customer;
    child.mgmt_pubkey = root_pubkey_str;
    auto res = post_auth_delta(cli, json(make_signed_delta("create_node", child.id, child)).dump());
    ASSERT_NE(res, nullptr);
    ASSERT_EQ(res->status, 202) << res->body;
    const auto body = json::parse(res->body);
    EXPECT_EQ(body.value("status", std::string{}), "pending");
    const auto op_id = body.value("op_id", std::string{});
    ASSERT_EQ(op_id.size(), 64u);
    EXPECT_FALSE(tree->get_node(child.id).has_value());

    const httplib::Headers h = {{"Authorization", "Bearer " + make_jwt(root_pubkey_str)}};
    auto poll = cli.Get("/api/tree/op/" + op_id, h);
    ASSERT_NE(poll, nullptr);
    ASSERT_EQ(poll->status, 200) << poll->body;
    EXPECT_EQ(json::parse(poll->body).value("status", std::string{}), "pending");

    pool.settle(op_id, {tree::TreeOpStatus::Committed, {}, 7});
    poll = cli.Get("/api/tree/op/" + op_id, h);
    ASSERT_NE(poll, nullptr);
    EXPECT_EQ(json::parse(poll->body).value("status", std::string{}), "committed");
    EXPECT_EQ(json::parse(poll->body).value("log_height", 0), 7);
    poll = cli.Get("/api/tree/op/" + std::string(64, 'a'), h);
    ASSERT_NE(poll, nullptr);
    EXPECT_EQ(poll->status, 404);
    poll = cli.Get("/api/tree/op/" + op_id);
    ASSERT_NE(poll, nullptr);
    EXPECT_EQ(poll->status, 401);

    tree::TreeOpSubmitter unavailable(
        *tree, *crypto, security::NetworkId{}, submitter_key,
        [](tree::TreeOp) {
            return tree::TreeOpAdmission{
                {tree::TreeOpRefusal::Unavailable, "not a Tier 1 member"}, nullptr};
        },
        std::chrono::milliseconds(20));
    test_api::current().ctx->tree_ops = &unavailable;
    res = post_auth_delta(cli, json(make_signed_delta("create_node", child.id, child)).dump());
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 503);
    test_api::current().ctx->tree_ops = nullptr;
    test_api::current().ctx->tree_op_status = nullptr;
}

// A group admin administers the group's devices even without an entry on the
// device itself: it reads the device's full assignments and removes it. A
// member without admin does neither, and the root is never removed.
TEST_F(HttpEndpointTest, GroupAdminReadsAndRemovesTheGroupsDevices) {
    auto cli = make_client();
    auto bare_of = [](const crypto::Ed25519Keypair& kp) {
        return crypto::to_base64(std::span<const uint8_t>(kp.public_key.data(),
                                                          kp.public_key.size()));
    };
    auto owner_kp = crypto->ed25519_keygen();
    auto device_kp = crypto->ed25519_keygen();
    const auto owner_b64 = bare_of(owner_kp);
    const auto device_b64 = bare_of(device_kp);
    auto owner_join = join_node(owner_kp);
    ASSERT_NE(owner_join, nullptr);
    ASSERT_EQ(owner_join->status, 200) << owner_join->body;
    const auto owner_node = json::parse(owner_join->body).value("node_id", std::string{});
    const auto group = tree->get_node(owner_node)->parent_id;

    // A device in the group whose own node names only itself.
    tree::TreeNode device;
    device.id = "grp-device";
    device.parent_id = group;
    device.type = tree::NodeType::Endpoint;
    device.mgmt_pubkey = "ed25519:" + device_b64;
    device.assignments = {{"ed25519:" + device_b64, {"read", "write", "edit_node"}}};
    ASSERT_TRUE(tree->insert_join_node(device));
    ASSERT_FALSE(tree->check_permission("ed25519:" + owner_b64, "grp-device",
                                        acl::Permission::Read));

    httplib::Headers owner_h = {{"Authorization", "Bearer " + make_jwt(owner_b64)}};
    auto read = cli.Get("/api/tree/node/grp-device", owner_h);
    ASSERT_NE(read, nullptr);
    ASSERT_EQ(read->status, 200) << read->body;
    EXPECT_EQ(json::parse(read->body)["assignments"].size(), 1u);  // full list, not redacted away

    // The device itself is not an admin of the group's other nodes.
    httplib::Headers device_h = {{"Authorization", "Bearer " + make_jwt(device_b64)}};
    auto refused = cli.Post("/api/tree/node/delete/" + owner_node, device_h);
    ASSERT_NE(refused, nullptr);
    EXPECT_EQ(refused->status, 403);

    auto removed = cli.Post("/api/tree/node/delete/grp-device", owner_h);
    ASSERT_NE(removed, nullptr);
    EXPECT_EQ(removed->status, 200) << removed->body;
    EXPECT_FALSE(tree->get_node("grp-device").has_value());

    httplib::Headers root_h = {{"Authorization", "Bearer " + make_jwt(root_pubkey_str)}};
    auto root_delete = cli.Post("/api/tree/node/delete/root", root_h);
    ASSERT_NE(root_delete, nullptr);
    EXPECT_EQ(root_delete->status, 403);
    EXPECT_TRUE(tree->get_node("root").has_value());
}

namespace join_proof {

// A real WebAuthn assertion, so the join below authenticates with a valid
// passkey and only the device-key proof is missing.
EVP_PKEY* p256_key() {
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    EVP_PKEY_keygen_init(pctx);
    char group[] = "P-256";
    OSSL_PARAM params[] = {OSSL_PARAM_construct_utf8_string("group", group, 0),
                           OSSL_PARAM_construct_end()};
    EVP_PKEY_CTX_set_params(pctx, params);
    EVP_PKEY_keygen(pctx, &pkey);
    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

std::string hex_coordinate(EVP_PKEY* pkey, const char* name) {
    BIGNUM* bn = nullptr;
    EVP_PKEY_get_bn_param(pkey, name, &bn);
    std::vector<uint8_t> out(32, 0);
    BN_bn2binpad(bn, out.data(), 32);
    BN_free(bn);
    return crypto::to_hex(std::span<const uint8_t>(out));
}

std::string b64url(const std::vector<uint8_t>& bytes) {
    std::string out = crypto::to_base64(std::span<const uint8_t>(bytes));
    for (auto& ch : out) {
        if (ch == '+') ch = '-';
        else if (ch == '/') ch = '_';
    }
    out.erase(std::remove(out.begin(), out.end(), '='), out.end());
    return out;
}

json passkey_assertion(crypto::SodiumCryptoService& c, const std::string& rp_id,
                       EVP_PKEY* pkey, const std::string& credential_id,
                       const std::string& challenge) {
    auto sha = [&](std::string_view in) {
        auto h = c.sha256(std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(in.data()), in.size()));
        return std::vector<uint8_t>(h.begin(), h.end());
    };
    std::vector<uint8_t> auth_data = sha(rp_id);
    auth_data.insert(auth_data.end(), {0x01, 0, 0, 0, 1});
    const std::string cdj =
        json{{"type", "webauthn.get"}, {"origin", rp_id}, {"challenge", challenge}}.dump();
    std::vector<uint8_t> signed_data = auth_data;
    const auto cdj_hash = sha(cdj);
    signed_data.insert(signed_data.end(), cdj_hash.begin(), cdj_hash.end());
    size_t sig_len = 0;
    EVP_MD_CTX* mctx = EVP_MD_CTX_new();
    EVP_DigestSignInit(mctx, nullptr, EVP_sha256(), nullptr, pkey);
    EVP_DigestSign(mctx, nullptr, &sig_len, signed_data.data(), signed_data.size());
    std::vector<uint8_t> sig(sig_len);
    EVP_DigestSign(mctx, sig.data(), &sig_len, signed_data.data(), signed_data.size());
    EVP_MD_CTX_free(mctx);
    sig.resize(sig_len);
    return {{"method", "passkey"},
            {"assertion",
             {{"credential_id", credential_id},
              {"authenticator_data", b64url(auth_data)},
              {"client_data_json", b64url({cdj.begin(), cdj.end()})},
              {"signature", b64url(sig)}}}};
}

}  // namespace join_proof

// The joining device's key becomes its management key and every permission
// principal, so a join must prove possession. Only the ed25519 method verifies
// body.pubkey. A valid passkey login could otherwise join under someone
// else's device key, taking their identity in the tree.
TEST_F(HttpEndpointTest, JoinRefusesMethodsThatDoNotProveTheDeviceKey) {
    auto victim = crypto->ed25519_keygen();
    const auto victim_b64 = crypto::to_base64(
        std::span<const uint8_t>(victim.public_key.data(), victim.public_key.size()));

    // Mallory holds a genuine passkey account.
    auto* pkey = join_proof::p256_key();
    const std::string mallory = "mallory";
    ASSERT_TRUE(auth->register_passkey(json{{"user_id", mallory},
                                            {"credential_id", "cred_mallory"},
                                            {"public_key_x", join_proof::hex_coordinate(pkey, "qx")},
                                            {"public_key_y", join_proof::hex_coordinate(pkey, "qy")}})
                    .authenticated);
    const auto challenge = auth->issue_passkey_challenge(mallory);
    ASSERT_TRUE(challenge.has_value());
    json body = join_proof::passkey_assertion(*crypto, "lemonade-nexus.local", pkey,
                                              "cred_mallory",
                                              challenge->at("challenge").get<std::string>());
    EVP_PKEY_free(pkey);

    body["pubkey"] = victim_b64;
    body["public_key"] = "ed25519:" + victim_b64;
    auto res = make_client().Post("/api/join", body.dump(), "application/json");
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->status, 403) << res->body;
    for (const char* method : {"password", "token-link", ""}) {
        json other = {{"pubkey", victim_b64}, {"public_key", "ed25519:" + victim_b64},
                      {"username", "someone"}, {"password", "anything"}};
        if (*method) other["method"] = method;
        auto r = make_client().Post("/api/join", other.dump(), "application/json");
        ASSERT_NE(r, nullptr);
        EXPECT_EQ(r->status, 403) << method << ": " << r->body;
    }
    for (const auto& child : tree->get_children("root")) {
        EXPECT_NE(child.mgmt_pubkey, "ed25519:" + victim_b64);
    }
    // The ed25519 path still joins.
    auto ok = join_node(victim);
    ASSERT_NE(ok, nullptr);
    EXPECT_EQ(ok->status, 200) << ok->body;
}

// ---------------------------------------------------------------------------
// GET /api/mesh/peers through the real MeshApiHandler.
//
// The client adds every listed peer to its dataplane, so the list must hold
// only peers the requester may connect to: ConnectPrivate or ConnectShared on
// the peer node, as in PermissionTreeService::resolve_authorized. Read alone
// must not list an endpoint. The routes in register_routes() above are a
// stand-in, so this fixture serves the real handler on its own server.
// ---------------------------------------------------------------------------
class MeshPeersConnectTest : public HttpEndpointTest {
protected:
    httplib::Server mesh_srv;
    std::thread mesh_thread;
    int mesh_port = 0;
    std::unique_ptr<api::MeshApiHandler> mesh_handler;
    std::string caller;  // the requesting device's principal

    void SetUp() override {
        HttpEndpointTest::SetUp();
        if (HasFatalFailure()) return;
        mesh_handler = std::make_unique<api::MeshApiHandler>(*test_api::current().ctx);
        mesh_handler->register_routes(mesh_srv, mesh_srv);
        mesh_port = mesh_srv.bind_to_any_port("127.0.0.1");
        ASSERT_GT(mesh_port, 0);
        mesh_thread = std::thread([this] { mesh_srv.listen_after_bind(); });
        mesh_srv.wait_until_ready();

        caller = principal();
        add("mc_group", "root", tree::NodeType::Customer, {});
        add("mc_self", "mc_group", tree::NodeType::Endpoint, {{caller, {"read"}}});
    }

    void TearDown() override {
        mesh_srv.stop();
        if (mesh_thread.joinable()) mesh_thread.join();
        mesh_handler.reset();
        HttpEndpointTest::TearDown();
    }

    std::string principal() {
        return "ed25519:" + crypto::to_base64(crypto->ed25519_keygen().public_key);
    }

    void add(const std::string& id, const std::string& parent, tree::NodeType type,
             std::vector<tree::Assignment> assignments) {
        tree::TreeNode n;
        n.id = id;
        n.parent_id = parent;
        n.type = type;
        n.mgmt_pubkey = root_pubkey_str;
        n.assignments = std::move(assignments);
        if (type == tree::NodeType::Endpoint || type == tree::NodeType::Relay) {
            n.mesh_pubkey = "mesh-" + id;
            n.tunnel_ip = "10.64.9." + std::to_string(tree->get_children(parent).size() + 2) + "/32";
        }
        ASSERT_TRUE(tree->insert_join_node(n)) << id;
    }

    /// Node ids in the requester's peer list, and the full response body.
    std::set<std::string> listed(json* body_out = nullptr) {
        httplib::Client cli("127.0.0.1", mesh_port);
        httplib::Headers h = {{"Authorization", "Bearer " + make_jwt(caller)}};
        auto res = cli.Get("/api/mesh/peers/mc_self", h);
        EXPECT_NE(res, nullptr);
        if (!res) return {};
        EXPECT_EQ(res->status, 200) << res->body;
        auto body = json::parse(res->body);
        std::set<std::string> ids;
        for (const auto& p : body["peers"]) ids.insert(p["node_id"].get<std::string>());
        if (body_out) *body_out = body;
        return ids;
    }

    uint32_t status_peer_count() {
        httplib::Client cli("127.0.0.1", mesh_port);
        httplib::Headers h = {{"Authorization", "Bearer " + make_jwt(caller)}};
        auto res = cli.Get("/api/mesh/status/mc_self", h);
        EXPECT_NE(res, nullptr);
        if (!res) return 0;
        EXPECT_EQ(res->status, 200) << res->body;
        return json::parse(res->body)["peer_count"].get<uint32_t>();
    }
};

TEST_F(MeshPeersConnectTest, ReadOnlyEndpointIsNotListed) {
    add("mc_seen", "mc_group", tree::NodeType::Endpoint, {{caller, {"read"}}});
    const auto ids = listed();
    EXPECT_FALSE(ids.count("mc_seen")) << "Read alone put a peer in the dataplane list";
    EXPECT_EQ(status_peer_count(), 0u);
}

TEST_F(MeshPeersConnectTest, ConnectGrantIsListed) {
    add("mc_private", "mc_group", tree::NodeType::Endpoint,
        {{caller, {"read", "connect_private"}}});
    add("mc_shared", "mc_group", tree::NodeType::Endpoint, {{caller, {"connect_shared"}}});
    add("mc_other_key", "mc_group", tree::NodeType::Endpoint,
        {{principal(), {"read", "connect_private"}}});
    const auto ids = listed();
    EXPECT_TRUE(ids.count("mc_private"));
    EXPECT_TRUE(ids.count("mc_shared"));
    EXPECT_FALSE(ids.count("mc_other_key")) << "a grant to another principal counted";
    EXPECT_EQ(status_peer_count(), 2u);
}

// An admin grant holds every permission bit, so it lists the node it is on.
// Permissions are not inherited: admin on the group does not list a device in
// that group on which the caller holds only Read.
TEST_F(MeshPeersConnectTest, GroupAdminNeedsAGrantOnEachDevice) {
    auto group = tree->get_node("mc_group");
    ASSERT_TRUE(group.has_value());
    group->assignments = {{caller, {"admin"}}};
    ASSERT_TRUE(tree->update_node_direct("mc_group", *group));
    add("mc_admin_dev", "mc_group", tree::NodeType::Endpoint, {{caller, {"admin"}}});
    add("mc_read_dev", "mc_group", tree::NodeType::Endpoint, {{caller, {"read"}}});
    const auto ids = listed();
    EXPECT_TRUE(ids.count("mc_admin_dev"));
    EXPECT_FALSE(ids.count("mc_read_dev"));
}

// Infrastructure entries keep their rules: the server peer is always present,
// and a relay in scope is listed with Read.
TEST_F(MeshPeersConnectTest, ServerPeerAndRelayAreUnchanged) {
    add("mc_relay", "mc_group", tree::NodeType::Relay, {{caller, {"read"}}});
    json body;
    const auto ids = listed(&body);
    EXPECT_TRUE(ids.count("mc_relay"));
    ASSERT_TRUE(body.contains("server_peer"));
    EXPECT_EQ(body["server_peer"]["node_id"], "server");
    EXPECT_EQ(body["server_peer"]["is_server"], true);
    EXPECT_EQ(status_peer_count(), 1u);
}

// --- Review fixes: server-assigned fields, delete cleanup, link tokens, IPAM ---

// A joined device holds add_child and edit_node on its endpoint and owns its
// group, yet tunnel addresses, private subnets, and relays stay
// server-assigned: the direct routes refuse them as tree operations do.
TEST_F(HttpEndpointTest, NodeRoutesKeepAddressesServerAssigned) {
    auto cli = make_client();
    auto device_kp = crypto->ed25519_keygen();
    const auto device_b64 = crypto::to_base64(std::span<const uint8_t>(
        device_kp.public_key.data(), device_kp.public_key.size()));
    auto join_res = join_node(device_kp);
    ASSERT_NE(join_res, nullptr);
    ASSERT_EQ(join_res->status, 200) << join_res->body;
    const auto ep = json::parse(join_res->body).value("node_id", std::string{});
    const auto stored_ip = tree->get_node(ep)->tunnel_ip;
    ASSERT_FALSE(stored_ip.empty());
    const httplib::Headers device = {{"Authorization", "Bearer " + make_jwt(device_b64)}};

    auto relay = cli.Post("/api/tree/node", device,
                          json{{"parent_id", ep}, {"type", "relay"}}.dump(), "application/json");
    ASSERT_NE(relay, nullptr);
    EXPECT_EQ(relay->status, 403) << relay->body;

    auto move = cli.Post("/api/tree/node/update/" + ep, device,
                         json{{"tunnel_ip", "10.65.0.9/32"}}.dump(), "application/json");
    ASSERT_NE(move, nullptr);
    EXPECT_EQ(move->status, 403) << move->body;
    auto widen = cli.Post("/api/tree/node/update/" + ep, device,
                          json{{"private_subnet", "10.64.0.0/10"}}.dump(), "application/json");
    ASSERT_NE(widen, nullptr);
    EXPECT_EQ(widen->status, 403) << widen->body;
    EXPECT_EQ(tree->get_node(ep)->tunnel_ip, stored_ip);
    EXPECT_TRUE(tree->get_node(ep)->private_subnet.empty());

    // Sending the stored value back is not a change.
    auto same = cli.Post("/api/tree/node/update/" + ep, device,
                         json{{"tunnel_ip", stored_ip}, {"hostname", "kept"}}.dump(),
                         "application/json");
    ASSERT_NE(same, nullptr);
    EXPECT_EQ(same->status, 200) << same->body;
    EXPECT_EQ(tree->get_node(ep)->hostname, "kept");
}

// A delete that another server took reaches this server as a committed
// operation, with no request here. The cleanup must still run here: the
// credential is revoked, the IPAM record released, and the DNS record removed.
TEST_F(HttpEndpointTest, ACommittedDeleteRunsTheCleanupOnThisServer) {
    auto cli = make_client();
    auto apply_delete = [&](const std::string& node_id, const std::string& principal) {
        tree::TreeOp op;
        op.kind = tree::TreeOpKind::DeleteNode;
        op.target = node_id;
        op.principal = principal;
        op.base_version = tree->get_node(node_id)->version;
        op.body.source = tree::TreeOpSource::Session;
        const auto now = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
        return tree->apply_committed_ops({op}, now);
    };

    // A device key that only this node holds, with an IPAM record.
    auto device_kp = crypto->ed25519_keygen();
    const auto device_b64 = crypto::to_base64(std::span<const uint8_t>(
        device_kp.public_key.data(), device_kp.public_key.size()));
    tree::TreeNode node;
    node.id = "replicated_delete";
    node.parent_id = "root";
    node.type = tree::NodeType::Endpoint;
    node.mgmt_pubkey = "ed25519:" + device_b64;
    node.assignments = {{root_pubkey_str, {"admin"}}};
    auto create = post_auth_delta(cli, json(make_signed_delta("create_node", node.id, node)).dump());
    ASSERT_NE(create, nullptr);
    ASSERT_EQ(create->status, 200) << create->body;
    ASSERT_FALSE(ipam->allocate_tunnel_ip(node.id).base_network.empty());
    ASSERT_TRUE(auth->validate_session_claims(make_jwt(device_b64)).has_value());

    ASSERT_TRUE(apply_delete(node.id, root_pubkey_str).ok());
    EXPECT_FALSE(tree->get_node(node.id).has_value());
    EXPECT_FALSE(auth->validate_session_claims(make_jwt(device_b64)).has_value());
    EXPECT_FALSE(ipam->get_allocation(node.id).has_value());

    // A joined device's private DNS record goes too.
    auto joined_kp = crypto->ed25519_keygen();
    auto join_res = join_node(joined_kp);
    ASSERT_NE(join_res, nullptr);
    ASSERT_EQ(join_res->status, 200) << join_res->body;
    const auto join = json::parse(join_res->body);
    const auto joined_id = join.value("node_id", std::string{});
    const auto fqdn = join.value("client_private_fqdn", std::string{});
    const auto ip = join.value("tunnel_ip", std::string{});
    ASSERT_TRUE(dns_a_resolves_to(fqdn, ip.substr(0, ip.find('/'))));
    ASSERT_TRUE(apply_delete(joined_id, root_pubkey_str).ok());
    EXPECT_EQ(dns_a_answer_count(fqdn), 0u);
}

// A link token is spent only by a join that places a device with it. A join
// refused before placement leaves the token usable, and a join that placed a
// device spends it.
TEST_F(HttpEndpointTest, ARefusedJoinDoesNotSpendTheLinkToken) {
    const auto minted = auth->mint_link_token("owner", root_pubkey_str, "grp_later",
                                              std::chrono::seconds{600});
    ASSERT_TRUE(minted.has_value());
    const auto& token = minted->first;

    // The token's group does not exist yet: the join is refused.
    auto first_kp = crypto->ed25519_keygen();
    auto refused = join_node(first_kp, token);
    ASSERT_NE(refused, nullptr);
    EXPECT_EQ(refused->status, 409) << refused->body;

    tree::TreeNode group;
    group.id = "grp_later";
    group.parent_id = "root";
    group.type = tree::NodeType::Customer;
    group.mgmt_pubkey = root_pubkey_str;
    group.assignments = {{root_pubkey_str, {"admin"}}};
    ASSERT_TRUE(tree->insert_join_node(group));

    auto placed = join_node(first_kp, token);
    ASSERT_NE(placed, nullptr);
    ASSERT_EQ(placed->status, 200) << placed->body;
    const auto node_id = json::parse(placed->body).value("node_id", std::string{});
    EXPECT_EQ(tree->get_node(node_id)->parent_id, "grp_later");

    auto second_kp = crypto->ed25519_keygen();
    auto spent = join_node(second_kp, token);
    ASSERT_NE(spent, nullptr);
    EXPECT_EQ(spent->status, 403) << spent->body;
}

// With tree operations on, the Join operation assigns tunnel addresses on
// every replica, so POST /api/ipam/allocate refuses a local tunnel address.
// The fixture shadows that route with a stand-in, so this test serves the
// production route on its own server.
TEST_F(HttpEndpointTest, TunnelAllocationIsRefusedWithTreeOperations) {
    httplib::Server srv;
    test_api::handler().register_routes(srv, srv);
    const int port = srv.bind_to_any_port("127.0.0.1");
    ASSERT_GT(port, 0);
    std::thread server_thread([&srv] { srv.listen_after_bind(); });
    ASSERT_TRUE(wait_http_ready(static_cast<uint16_t>(port)));

    auto& cfg = *test_api::current().config;
    const bool original = cfg.tree_ops_enabled;
    httplib::Client cli("127.0.0.1", port);
    const httplib::Headers root = {{"Authorization", "Bearer " + make_jwt(root_pubkey_str)}};
    auto allocate = [&](const std::string& block) {
        json body = {{"node_id", "root"}, {"block_type", block}, {"prefix_len", 30}};
        return cli.Post("/api/ipam/allocate", root, body.dump(), "application/json");
    };

    cfg.tree_ops_enabled = true;
    auto tunnel = allocate("tunnel");
    ASSERT_NE(tunnel, nullptr);
    EXPECT_EQ(tunnel->status, 409) << tunnel->body;
    EXPECT_FALSE(ipam->get_allocation("root").has_value());
    auto priv = allocate("private");
    ASSERT_NE(priv, nullptr);
    EXPECT_EQ(priv->status, 200) << priv->body;

    cfg.tree_ops_enabled = false;
    auto direct = allocate("tunnel");
    ASSERT_NE(direct, nullptr);
    EXPECT_EQ(direct->status, 200) << direct->body;

    cfg.tree_ops_enabled = original;
    srv.stop();
    server_thread.join();
}
