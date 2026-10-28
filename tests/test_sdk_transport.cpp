// SDK public transport: one kept-alive connection per server, safe to use from
// several threads at once.
//
// The Flutter client calls the SDK from worker isolates, so requests and
// session-token updates arrive concurrently. The client must not tear its
// shared state, and it must reuse its HTTPS connection instead of paying a TCP
// and TLS handshake on every call.

#include <LemonadeNexusSDK/BoringtunMesh.hpp>
#include <LemonadeNexusSDK/LemonadeNexusClient.hpp>

#include <LemonadeNexus/Crypto/CryptoTypes.hpp>
#include <LemonadeNexus/Crypto/SodiumCryptoService.hpp>
#include <LemonadeNexus/Network/StunService.hpp>
#include <LemonadeNexus/Security/Epoch/Tier1Membership.hpp>
#include <LemonadeNexus/Security/Transport/AuthorityChainCodec.hpp>

#include "support/localhost_cert.hpp"
#include "support/tier1_chain.hpp"

#include <gtest/gtest.h>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <future>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

namespace {

using test_support::make_localhost_cert;

class SdkTransportTest : public ::testing::Test {
protected:
    fs::path dir;
    std::unique_ptr<httplib::SSLServer> server;
    std::thread server_thread;
    int port = 0;

    std::mutex seen_mutex;
    std::set<int> client_ports;        // one per TCP connection
    std::set<std::string> auth_values;  // every Authorization header received

    void SetUp() override {
        dir = fs::temp_directory_path() /
              ("nexus_sdk_transport_" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()) +
               "_" + std::to_string(reinterpret_cast<uintptr_t>(this)));
        fs::create_directories(dir);
        const auto cert = dir / "cert.pem";
        const auto key = dir / "key.pem";
        ASSERT_TRUE(make_localhost_cert(cert, key));
#ifdef _WIN32
        (void)_putenv_s("SSL_CERT_FILE", cert.string().c_str());
#else
        ::setenv("SSL_CERT_FILE", cert.string().c_str(), 1);
#endif
        server = std::make_unique<httplib::SSLServer>(cert.string().c_str(), key.string().c_str());
        ASSERT_TRUE(server->is_valid());
        server->Get("/api/health", [this](const httplib::Request& req, httplib::Response& res) {
            {
                std::lock_guard lock(seen_mutex);
                client_ports.insert(req.remote_port);
                auth_values.insert(req.get_header_value("Authorization"));
            }
            res.set_content(R"({"status":"ok","service":"lemonade-nexus","rp_id":"lemonade-nexus.local"})", "application/json");
        });
        port = server->bind_to_any_port("127.0.0.1");
        ASSERT_GT(port, 0);
        server_thread = std::thread([this] { server->listen_after_bind(); });
        server->wait_until_ready();
    }

    void TearDown() override {
        server->stop();
        if (server_thread.joinable()) server_thread.join();
        std::error_code ec;
        fs::remove_all(dir, ec);
    }

    /// True when the platform's default TLS trust follows SSL_CERT_FILE. It
    /// does on Linux; the macOS keychain ignores it, so there the tests skip.
    bool default_trust_reaches_server() {
        httplib::Client probe("https://localhost:" + std::to_string(port));
        probe.set_connection_timeout(3);
        auto res = probe.Get("/api/health");
        std::lock_guard lock(seen_mutex);
        client_ports.clear();
        auth_values.clear();
        return res && res->status == 200;
    }

    lnsdk::ServerConfig config() const {
        lnsdk::ServerConfig cfg;
        cfg.servers = {{"localhost", static_cast<uint16_t>(port), true}};
        cfg.auto_discover = false;
        return cfg;
    }
};

}  // namespace

TEST_F(SdkTransportTest, SequentialCallsReuseOneConnection) {
    if (!default_trust_reaches_server()) {
#ifdef __linux__
        FAIL() << "default TLS trust cannot reach the test server; SSL_CERT_FILE is "
                  "deterministic on Linux";
#else
        GTEST_SKIP() << "default TLS trust here ignores SSL_CERT_FILE (macOS keychain)";
#endif
    }
    lnsdk::LemonadeNexusClient client(config());
    for (int i = 0; i < 10; ++i) {
        auto r = client.check_health();
        ASSERT_TRUE(r.ok) << r.error;
        EXPECT_EQ(r.value.status, "ok");
        EXPECT_EQ(r.value.rp_id, "lemonade-nexus.local") << "the passkey RP ID reaches the caller";
    }
    std::lock_guard lock(seen_mutex);
    EXPECT_EQ(client_ports.size(), 1u) << "each call opened a new connection";
}

TEST_F(SdkTransportTest, ConcurrentCallsAndTokenChangesStayConsistent) {
    if (!default_trust_reaches_server()) {
#ifdef __linux__
        FAIL() << "default TLS trust cannot reach the test server; SSL_CERT_FILE is "
                  "deterministic on Linux";
#else
        GTEST_SKIP() << "default TLS trust here ignores SSL_CERT_FILE (macOS keychain)";
#endif
    }
    lnsdk::LemonadeNexusClient client(config());
    const std::vector<std::string> tokens = {"token-a", "token-b-longer-than-a",
                                             "token-c-even-longer-than-token-b"};
    std::atomic<int> failures{0};
    std::atomic<bool> stop{false};

    // Token writer racing the requests, as the app does on re-auth.
    std::thread writer([&] {
        for (int i = 0; !stop.load(); ++i) {
            client.set_session_token(tokens[static_cast<std::size_t>(i) % tokens.size()]);
        }
    });
    std::vector<std::thread> callers;
    for (int t = 0; t < 8; ++t) {
        callers.emplace_back([&] {
            for (int i = 0; i < 20; ++i) {
                if (!client.check_health().ok) ++failures;
            }
        });
    }
    for (auto& c : callers) c.join();
    stop = true;
    writer.join();

    EXPECT_EQ(failures.load(), 0);
    std::lock_guard lock(seen_mutex);
    // Requests to one server share its pooled connection.
    EXPECT_LE(client_ports.size(), 2u);
    // A session is a bearer token for the Tier 1 server that issued it. This
    // server issued none, so no request carried a session, whole or torn.
    for (const auto& v : auth_values) {
        EXPECT_TRUE(v.empty()) << "a session went to a server that did not issue it: " << v;
    }
}

// ---------------------------------------------------------------------------
// Private API over the mesh.
//
// A stand-in server: the public API answers the join, and the private API is
// reachable only through a BoringtunMesh that acts as the server's dataplane.
// A second BoringtunMesh is another endpoint in the client's peer list. The
// client runs its real join, private transport, orchestrator, and leave paths.
// ---------------------------------------------------------------------------

namespace {

constexpr const char* kNodeId   = "node-self";
constexpr const char* kPeerId   = "node-peer";
constexpr uint16_t    kPrivPort = 9101;

/// The stand-in server's answer to one private request.
enum class Reply { Ok, Reject, CutAfterHeaders };

/// Send the status line and headers, then close the connection before the
/// body. The client gets no response, although the server ran the request.
void cut_after_headers(httplib::Response& res) {
    res.set_chunked_content_provider("application/json",
                                     [](size_t, httplib::DataSink&) { return false; });
}

template <typename Pred>
bool wait_for(Pred pred, std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return pred();
}

class SdkMeshPrivateApiTest : public ::testing::Test {
protected:
    fs::path dir;
    std::unique_ptr<httplib::SSLServer> pub;
    std::unique_ptr<httplib::SSLServer> priv;
    std::thread pub_thread;
    std::thread priv_thread;
    int pub_port = 0;

    lnsdk::BoringtunMesh server_mesh;  // the server's dataplane
    lnsdk::BoringtunMesh peer_mesh;    // another endpoint in the client's peer list
    std::pair<std::string, std::string> server_keys;
    std::pair<std::string, std::string> peer_keys;

    std::atomic<int>   peer_list_gets{0};
    std::atomic<int>   delete_posts{0};
    std::atomic<Reply> peer_list_reply{Reply::Ok};
    std::atomic<Reply> delete_reply{Reply::Ok};

    // Joins answered 202 pending before one answers 200, and whether each
    // join request carried a link token.
    std::atomic<int>  pending_join_replies{0};
    std::mutex        join_mtx;
    std::vector<bool> join_had_link_token;

    std::vector<bool> joins_with_link_token() {
        std::lock_guard lock(join_mtx);
        return join_had_link_token;
    }
    std::mutex               heartbeat_mtx;
    std::vector<std::string> heartbeat_endpoints;  // the "endpoint" of each heartbeat

    std::vector<std::string> heartbeats() {
        std::lock_guard lock(heartbeat_mtx);
        return heartbeat_endpoints;
    }

    // POST /api/auth answers, and the Authorization header of each join
    // request ("" when it carried none).
    std::atomic<int>         auth_posts{0};
    std::mutex               bearer_mtx;
    std::vector<std::string> join_bearers_seen;

    std::vector<std::string> join_bearers() {
        std::lock_guard lock(bearer_mtx);
        return join_bearers_seen;
    }

    // The tunnel address the peer list gives the other endpoint.
    std::mutex  listed_peer_mtx;
    std::string listed_peer_ip{"10.64.0.4/32"};

    void set_listed_peer_ip(std::string ip) {
        std::lock_guard lock(listed_peer_mtx);
        listed_peer_ip = std::move(ip);
    }
    std::string listed_peer_tunnel_ip() {
        std::lock_guard lock(listed_peer_mtx);
        return listed_peer_ip;
    }

    // The stand-in server is the one reachable Tier 1 member of a five-member
    // epoch: the client verifies it before it sends a tree request. In Epoch 2
    // its node leaves Tier 1 and `next_identity` takes the seat. Once
    // `server_left_tier1` is set, the server serves Epoch 2 and signs its
    // endpoint proofs as the new member.
    nexus::crypto::Ed25519Keypair server_identity{};
    nexus::crypto::Ed25519Keypair next_identity{};
    std::atomic<bool>             server_left_tier1{false};
    tier1_chain_test::Chain chain;

    std::size_t served_epochs() const { return server_left_tier1.load() ? 2 : 1; }

    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        dir = fs::temp_directory_path() /
              ("nexus_sdk_mesh_" + std::to_string(::testing::UnitTest::GetInstance()->random_seed()) +
               "_" + std::to_string(reinterpret_cast<uintptr_t>(this)));
        fs::create_directories(dir);
        const auto cert = dir / "cert.pem";
        const auto key = dir / "key.pem";
        ASSERT_TRUE(make_localhost_cert(cert, key));
#ifdef _WIN32
        (void)_putenv_s("SSL_CERT_FILE", cert.string().c_str());
#else
        ::setenv("SSL_CERT_FILE", cert.string().c_str(), 1);
#endif

        server_keys = lnsdk::BoringtunMesh::generate_keypair();
        peer_keys   = lnsdk::BoringtunMesh::generate_keypair();
        ASSERT_TRUE(server_mesh.start(mesh_config(server_keys, "10.64.0.1/32")));
        ASSERT_TRUE(peer_mesh.start(mesh_config(peer_keys, "10.64.0.4/32")));

        priv = std::make_unique<httplib::SSLServer>(cert.string().c_str(), key.string().c_str());
        ASSERT_TRUE(priv->is_valid());
        priv->Get(std::string("/api/mesh/peers/") + kNodeId,
                  [this](const httplib::Request&, httplib::Response& res) {
            ++peer_list_gets;
            if (peer_list_reply.load() == Reply::CutAfterHeaders) return cut_after_headers(res);
            nlohmann::json peer = {
                {"node_id", kPeerId},
                {"mesh_pubkey", peer_keys.second},
                {"tunnel_ip", listed_peer_tunnel_ip()},
                {"endpoint", "127.0.0.1:" + std::to_string(peer_mesh.bound_port())},
                {"last_seen", 0},
            };
            nlohmann::json body;
            body["peers"] = nlohmann::json::array({peer});
            res.set_content(body.dump(), "application/json");
        });
        priv->Post(std::string("/api/tree/node/delete/") + kNodeId,
                   [this](const httplib::Request&, httplib::Response& res) {
            ++delete_posts;
            switch (delete_reply.load()) {
            case Reply::Ok:
                res.set_content(R"({"success":true})", "application/json");
                break;
            case Reply::Reject:
                res.status = 403;
                res.set_content(R"({"success":false,"error":"denied"})", "application/json");
                break;
            case Reply::CutAfterHeaders:
                cut_after_headers(res);
                break;
            }
        });
        priv->Post("/api/mesh/heartbeat", [this](const httplib::Request& req,
                                                 httplib::Response& res) {
            const auto body = nlohmann::json::parse(req.body, nullptr, false);
            {
                std::lock_guard lock(heartbeat_mtx);
                heartbeat_endpoints.push_back(
                    body.is_object() ? body.value("endpoint", std::string{"<none>"}) : "<bad>");
            }
            res.set_content(R"({"success":true})", "application/json");
        });
        const int priv_port = priv->bind_to_any_port("127.0.0.1");
        ASSERT_GT(priv_port, 0);
        priv_thread = std::thread([this] { priv->listen_after_bind(); });
        priv->wait_until_ready();
        ASSERT_TRUE(server_mesh.tcp_ingress(kPrivPort,
                                            "tcp:127.0.0.1:" + std::to_string(priv_port)));

        pub = std::make_unique<httplib::SSLServer>(cert.string().c_str(), key.string().c_str());
        ASSERT_TRUE(pub->is_valid());
        pub->Get("/api/health", [](const httplib::Request&, httplib::Response& res) {
            res.set_content(R"({"status":"ok"})", "application/json");
        });
        server_identity = tier1_chain_test::new_identity();
        next_identity   = tier1_chain_test::new_identity();
        std::vector<nexus::crypto::Ed25519Keypair> epoch1 = {server_identity};
        std::vector<nexus::crypto::Ed25519Keypair> epoch2 = {next_identity};
        for (int i = 0; i < 4; ++i) {
            const auto member = tier1_chain_test::new_identity();
            epoch1.push_back(member);
            epoch2.push_back(member);
        }
        chain = tier1_chain_test::Chain::make({epoch1, epoch2});
        pub->Get("/api/tier1/authority", [this](const httplib::Request& req,
                                                httplib::Response& res) {
            const auto page = chain.page_after(std::stoull(req.get_param_value("have_epoch")),
                                               served_epochs());
            if (!page) {
                res.status = 404;
                return;
            }
            const auto bytes = nexus::security::encode_authority_chain_page(*page);
            res.set_content(nlohmann::json{{"page", nexus::crypto::to_base64(bytes)}}.dump(),
                            "application/json");
        });
        pub->Get("/api/servers", [](const httplib::Request&, httplib::Response& res) {
            res.set_content("[]", "application/json");
        });
        pub->Get("/api/tier1/proof", [this](const httplib::Request& req, httplib::Response& res) {
            const auto nonce = nexus::crypto::from_hex(req.get_param_value("nonce"));
            const bool left  = server_left_tier1.load();
            const auto epoch = static_cast<uint64_t>(served_epochs());
            const auto proof = nexus::security::sign_tier1_endpoint_proof(
                chain.network, nexus::security::EpochId{epoch}, "localhost",
                static_cast<uint16_t>(pub_port), nonce, left ? next_identity : server_identity);
            res.set_content(
                nlohmann::json{{"node_id", nexus::crypto::to_base64(proof.node.bytes)},
                               {"epoch", epoch},
                               {"host", proof.host},
                               {"port", proof.port},
                               {"signature", nexus::crypto::to_base64(proof.signature)}}
                    .dump(),
                "application/json");
        });
        pub->Post("/api/auth/challenge", [](const httplib::Request&, httplib::Response& res) {
            std::array<uint8_t, 32> challenge{};
            randombytes_buf(challenge.data(), challenge.size());
            res.set_content(
                nlohmann::json{{"challenge", nexus::crypto::to_base64(challenge)}}.dump(),
                "application/json");
        });
        pub->Post("/api/auth", [this](const httplib::Request&, httplib::Response& res) {
            ++auth_posts;
            res.set_content(
                R"({"authenticated":true,"user_id":"user","session_token":"auth-token"})",
                "application/json");
        });
        pub->Post("/api/join", [this](const httplib::Request& req, httplib::Response& res) {
            const auto body = nlohmann::json::parse(req.body, nullptr, false);
            {
                std::lock_guard lock(join_mtx);
                join_had_link_token.push_back(body.is_object() && body.contains("link_token"));
            }
            {
                std::lock_guard lock(bearer_mtx);
                join_bearers_seen.push_back(req.get_header_value("Authorization"));
            }
            if (pending_join_replies.load() > 0) {
                --pending_join_replies;
                res.status = 202;
                res.set_content(nlohmann::json{{"success", true},
                                               {"status", "pending"},
                                               {"op_id", std::string(64, 'b')},
                                               {"node_id", kNodeId}}
                                    .dump(),
                                "application/json");
                return;
            }
            lnsdk::MeshPeer self;
            self.mesh_pubkey = body.is_object() ? body.value("mesh_pubkey", "") : "";
            self.tunnel_ip   = "10.64.0.3/32";
            (void)server_mesh.sync_peers({self});
            (void)peer_mesh.sync_peers({self});
            nlohmann::json j;
            j["token"]               = "session-token";
            j["node_id"]             = kNodeId;
            j["tunnel_ip"]           = "10.64.0.3/32";
            j["server_tunnel_ip"]    = "10.64.0.1";
            j["server_private_fqdn"] = "localhost";
            j["private_api_port"]    = kPrivPort;
            j["mesh_server_pubkey"]  = server_keys.second;
            j["mesh_endpoint"]       = "127.0.0.1:" + std::to_string(server_mesh.bound_port());
            j["tunnel_subnet"]       = "10.64.0.0/10";
            res.set_content(j.dump(), "application/json");
        });
        pub_port = pub->bind_to_any_port("127.0.0.1");
        ASSERT_GT(pub_port, 0);
        pub_thread = std::thread([this] { pub->listen_after_bind(); });
        pub->wait_until_ready();
    }

    void TearDown() override {
        if (pub) pub->stop();
        if (priv) priv->stop();
        if (pub_thread.joinable()) pub_thread.join();
        if (priv_thread.joinable()) priv_thread.join();
        peer_mesh.stop();
        server_mesh.stop();
        std::error_code ec;
        fs::remove_all(dir, ec);
    }

    static lnsdk::BoringtunConfig mesh_config(const std::pair<std::string, std::string>& keys,
                                              const std::string& tunnel_ip) {
        lnsdk::BoringtunConfig cfg;
        cfg.private_key = keys.first;
        cfg.public_key  = keys.second;
        cfg.tunnel_ip   = tunnel_ip;
        cfg.allowed_ips = {"10.64.0.0/10"};
        return cfg;
    }

    bool default_trust_reaches_server() const {
        httplib::Client probe("https://localhost:" + std::to_string(pub_port));
        probe.set_connection_timeout(3);
        auto res = probe.Get("/api/health");
        return res && res->status == 200;
    }

    /// A client that has joined through the stand-in server, with
    /// `link_token` when one is given.
    std::unique_ptr<lnsdk::LemonadeNexusClient> joined_client(const std::string& link_token = {}) {
        lnsdk::ServerConfig cfg;
        cfg.servers = {{"localhost", static_cast<uint16_t>(pub_port), true}};
        cfg.auto_discover = false;
        auto client = std::make_unique<lnsdk::LemonadeNexusClient>(cfg);
        EXPECT_TRUE(client->set_genesis_key(
            nexus::crypto::to_base64(chain.genesis.public_key)).ok);
        client->set_session_token("session-token");
        if (!link_token.empty()) client->set_link_token(link_token);
        auto joined = client->join_network("user", "password");
        EXPECT_TRUE(joined.ok) << joined.error;
        EXPECT_TRUE(client->is_mesh_active());
        return client;
    }

    /// Epoch 2 takes effect: the server's node is no longer a member, and the
    /// client verifies the membership again, as it does every five minutes.
    void server_leaves_tier1(lnsdk::LemonadeNexusClient& client) {
        server_left_tier1 = true;
        auto refreshed = client.refresh_tier1();
        ASSERT_TRUE(refreshed.ok) << refreshed.error;
        ASSERT_EQ(refreshed.value.epoch, 2u);
    }
};

}  // namespace

#ifdef __linux__
#define LN_REQUIRE_TEST_TRUST()                                                     \
    if (!default_trust_reaches_server())                                            \
    FAIL() << "default TLS trust cannot reach the test server; SSL_CERT_FILE is "   \
              "deterministic on Linux"
#else
#define LN_REQUIRE_TEST_TRUST()                                                     \
    if (!default_trust_reaches_server())                                            \
    GTEST_SKIP() << "default TLS trust here ignores SSL_CERT_FILE (macOS keychain)"
#endif

// A link join that the server answers 202 pending has spent its token with
// the pending op. The client joins again without the token until the committed
// node answers 200, and the join succeeds in one call.
TEST_F(SdkMeshPrivateApiTest, APendingJoinIsRepeatedWithoutTheLinkTokenUntilItCommits) {
    LN_REQUIRE_TEST_TRUST();
    pending_join_replies = 1;
    auto client = joined_client("invite-token");
    ASSERT_TRUE(client->is_mesh_active());
    EXPECT_EQ(joins_with_link_token(), (std::vector<bool>{true, false}));
    EXPECT_EQ(pending_join_replies.load(), 0);
}

// Tier 1 rotates a member out at an epoch boundary. A session bound to that
// server can no longer carry private calls, so the SDK drops it instead of
// refusing forever: the next private call is refused and never sent, the
// token is gone, mesh_status() asks for a re-join, and join_network()
// authenticates afresh instead of carrying the stale token to the old server.
TEST_F(SdkMeshPrivateApiTest, ASessionWhoseServerLeftTier1IsDroppedAndJoinedAgain) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    lnsdk::Identity identity;
    identity.generate();
    client->set_identity(identity);
    ASSERT_TRUE(client->mesh_heartbeat(kNodeId, "").ok);
    EXPECT_EQ(client->session_token(), "session-token");
    EXPECT_FALSE(client->mesh_status().needs_rejoin);

    ASSERT_NO_FATAL_FAILURE(server_leaves_tier1(*client));
    const auto sent_before = heartbeats().size();
    EXPECT_FALSE(client->mesh_heartbeat(kNodeId, "").ok);
    EXPECT_EQ(heartbeats().size(), sent_before);
    EXPECT_TRUE(client->session_token().empty());
    EXPECT_TRUE(client->mesh_status().needs_rejoin);
    EXPECT_EQ(auth_posts.load(), 0);

    auto joined = client->join_network("user", "password");
    ASSERT_TRUE(joined.ok) << joined.error;
    EXPECT_EQ(auth_posts.load(), 1);
    EXPECT_EQ(join_bearers(), (std::vector<std::string>{"", "Bearer auth-token"}));
    EXPECT_FALSE(client->mesh_status().needs_rejoin);
    EXPECT_EQ(client->session_token(), "session-token");
    EXPECT_TRUE(client->mesh_heartbeat(kNodeId, "").ok);
    EXPECT_EQ(heartbeats().size(), sent_before + 1);
}

// check_health() names the reason once, when it finds the session's server
// gone. The session is dropped with it, so health itself answers afterwards.
TEST_F(SdkMeshPrivateApiTest, HealthReportsTheDepartedSessionServerOnce) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    ASSERT_TRUE(client->check_health().ok);

    ASSERT_NO_FATAL_FAILURE(server_leaves_tier1(*client));
    auto health = client->check_health();
    EXPECT_FALSE(health.ok);
    EXPECT_EQ(health.error,
              "the session's server is no longer a verified Tier 1 server: join again");
    EXPECT_TRUE(client->session_token().empty());
    EXPECT_TRUE(client->mesh_status().needs_rejoin);
    EXPECT_TRUE(client->check_health().ok);
}

// The node delete travels over the mesh, so leave_network must delete the node
// before it stops the mesh.
TEST_F(SdkMeshPrivateApiTest, LeaveDeletesTheNodeBeforeItStopsTheMesh) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    auto left = client->leave_network();
    EXPECT_TRUE(left.ok) << left.error;
    EXPECT_EQ(delete_posts.load(), 1);
    EXPECT_FALSE(client->is_mesh_active());
    EXPECT_TRUE(client->node_id().empty());
}

// A rejected delete leaves the node joined: the mesh stays up so the caller can
// retry, and the error reaches the caller.
TEST_F(SdkMeshPrivateApiTest, LeaveKeepsTheMeshUpWhenTheDeleteFails) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    delete_reply = Reply::Reject;
    auto left = client->leave_network();
    EXPECT_FALSE(left.ok);
    EXPECT_EQ(left.http_status, 403);
    EXPECT_EQ(delete_posts.load(), 1);
    EXPECT_TRUE(client->is_mesh_active());
    EXPECT_EQ(client->node_id(), kNodeId);
}

// The server can apply a POST and then lose the response. The client must not
// send that POST a second time.
TEST_F(SdkMeshPrivateApiTest, PostWithoutAResponseIsNotSentAgain) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    delete_reply = Reply::CutAfterHeaders;
    auto deleted = client->delete_node(kNodeId);
    EXPECT_FALSE(deleted.ok);
    EXPECT_EQ(delete_posts.load(), 1);
}

// A GET has no side effect, so the client still retries it once.
TEST_F(SdkMeshPrivateApiTest, GetWithoutAResponseIsRetriedOnce) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    peer_list_reply = Reply::CutAfterHeaders;
    auto peers = client->fetch_mesh_peers(kNodeId);
    EXPECT_FALSE(peers.ok);
    EXPECT_EQ(peer_list_gets.load(), 2);
}

// refresh_mesh_peers must run a refresh now, not at the next interval.
TEST_F(SdkMeshPrivateApiTest, RefreshNowFetchesPeersImmediately) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    lnsdk::MeshConfig cfg;
    cfg.peer_refresh_interval_sec = 3600;
    cfg.heartbeat_interval_sec    = 3600;
    client->enable_mesh(cfg);
    ASSERT_TRUE(wait_for([&] { return peer_list_gets.load() >= 1; }, std::chrono::seconds(10)));
    const int before = peer_list_gets.load();
    client->refresh_mesh_peers();
    EXPECT_TRUE(wait_for([&] { return peer_list_gets.load() > before; }, std::chrono::seconds(3)))
        << "refresh_mesh_peers did not wake the orchestrator";
    client->disable_mesh();
}

// A mesh state callback runs on the orchestrator thread and may call back into
// the client. leave_network stops the orchestrator; it must not hold the
// client mutex while it waits for that thread, or the callback and the leave
// wait on each other forever.
TEST_F(SdkMeshPrivateApiTest, LeaveDoesNotDeadlockWithACallbackThatCallsTheClient) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    auto* raw = client.get();
    std::atomic<bool> in_callback{false};
    std::atomic<bool> callback_done{false};
    client->set_mesh_callback([&, raw](const lnsdk::MeshTunnelStatus&) {
        if (in_callback.exchange(true)) return;
        // Hold the orchestrator thread here until the leave has deleted the
        // node and is stopping the orchestrator, then call into the client.
        (void)wait_for([&] { return delete_posts.load() > 0; }, std::chrono::seconds(20));
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        (void)raw->get_mesh_peers();
        (void)raw->mesh_status();
        callback_done = true;
    });
    lnsdk::MeshConfig cfg;
    cfg.heartbeat_interval_sec = 3600;
    client->enable_mesh(cfg);
    ASSERT_TRUE(wait_for([&] { return in_callback.load(); }, std::chrono::seconds(15)));

    auto left = std::make_shared<std::promise<bool>>();
    auto done = left->get_future();
    std::thread leaver([left, raw] { left->set_value(raw->leave_network().ok); });
    if (done.wait_for(std::chrono::seconds(20)) != std::future_status::ready) {
        // The threads are deadlocked and cannot be joined; end the process so
        // the run reports the failure instead of hanging.
        ADD_FAILURE() << "leave_network deadlocked with the mesh state callback";
        std::fprintf(stderr, "deadlock detected; exiting\n");
        std::_Exit(1);
    }
    leaver.join();
    EXPECT_TRUE(done.get());
    EXPECT_TRUE(callback_done.load());
    EXPECT_FALSE(client->is_mesh_active());
}

// The orchestrator takes a peer's handshake time from the dataplane entry with
// the same mesh public key. The server lists tunnel_ip with a prefix and the
// dataplane has no node_id, so neither of those fields can match.
TEST_F(SdkMeshPrivateApiTest, HandshakeIsMatchedToItsPeerByMeshKey) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    lnsdk::MeshConfig cfg;
    cfg.heartbeat_interval_sec = 3600;
    client->enable_mesh(cfg);
    ASSERT_TRUE(wait_for([&] { return client->get_mesh_peers().size() == 1; },
                         std::chrono::seconds(10)));

    // Traffic toward the peer starts the Noise handshake with it.
    const uint16_t egress = client->open_egress("10.64.0.4", 80);
    ASSERT_GT(egress, 0);
    httplib::Client poke("127.0.0.1", egress);
    poke.set_connection_timeout(1);
    poke.set_read_timeout(1);
    (void)poke.Get("/");

    EXPECT_TRUE(wait_for([&] {
        auto peers = client->get_mesh_peers();
        return peers.size() == 1 && peers[0].last_handshake > 0 && peers[0].is_online;
    }, std::chrono::seconds(15))) << "the peer's handshake was not attributed to it";
    client->disable_mesh();
}

// The private API answers on the tunnel address of the server that the client
// joined. A listed peer that claims the same address (all servers and the
// first endpoint each server allocated once held 10.64.0.10) must not take
// that traffic: the private API must still reach the server.
TEST_F(SdkMeshPrivateApiTest, APeerOnTheServerAddressDoesNotTakeThePrivateApi) {
    LN_REQUIRE_TEST_TRUST();
    set_listed_peer_ip("10.64.0.1/32");  // the stand-in server's tunnel address
    auto client = joined_client();
    lnsdk::MeshConfig cfg;
    cfg.heartbeat_interval_sec = 3600;
    client->enable_mesh(cfg);
    // The orchestrator stores the list only after it synced the routes.
    ASSERT_TRUE(wait_for([&] { return client->get_mesh_peers().size() == 1; },
                         std::chrono::seconds(10)));

    const int before = peer_list_gets.load();
    auto peers = client->fetch_mesh_peers(kNodeId);
    EXPECT_TRUE(peers.ok) << "the private API did not reach the server: " << peers.error;
    EXPECT_GT(peer_list_gets.load(), before);
    client->disable_mesh();
}

// The orchestrator learns its reflexive address from the session server's
// STUN service (the canonical port 3478 on the server's host) and publishes
// it with the heartbeat. The address is the mapping the server's own
// dataplane sees, because the query leaves from the dataplane socket.
TEST_F(SdkMeshPrivateApiTest, HeartbeatPublishesTheReflexiveEndpoint) {
    LN_REQUIRE_TEST_TRUST();
    asio::io_context io;
    nexus::crypto::SodiumCryptoService crypto;
    crypto.start();
    std::unique_ptr<nexus::network::StunService> stun;
    try {
        stun = std::make_unique<nexus::network::StunService>(io, 3478, crypto, "test-stun");
    } catch (const std::exception&) {
        crypto.stop();
        GTEST_SKIP() << "UDP port 3478 is in use on this host";
    }
    stun->start();
    auto guard = asio::make_work_guard(io);
    std::thread io_thread([&io] { io.run(); });

    auto client = joined_client();
    lnsdk::MeshConfig cfg;
    cfg.heartbeat_interval_sec    = 1;
    cfg.stun_refresh_interval_sec = 60;
    client->enable_mesh(cfg);

    std::string seen_by_server;
    EXPECT_TRUE(wait_for([&] {
        for (const auto& p : server_mesh.mesh_status().peers) {
            if (!p.endpoint.empty()) seen_by_server = p.endpoint;
        }
        if (seen_by_server.empty()) return false;
        for (const auto& endpoint : heartbeats()) {
            if (endpoint == seen_by_server) return true;
        }
        return false;
    }, std::chrono::seconds(15))) << "no heartbeat carried the reflexive endpoint "
                                  << seen_by_server;

    client->disable_mesh();
    stun->stop();
    guard.reset();
    io.stop();
    io_thread.join();
    crypto.stop();
}

// Without a reflexive address (STUN refresh off) the heartbeat carries an
// empty endpoint, which the server treats as liveness only.
TEST_F(SdkMeshPrivateApiTest, HeartbeatWithoutStunSendsAnEmptyEndpoint) {
    LN_REQUIRE_TEST_TRUST();
    auto client = joined_client();
    lnsdk::MeshConfig cfg;
    cfg.heartbeat_interval_sec    = 1;
    cfg.stun_refresh_interval_sec = 0;
    client->enable_mesh(cfg);
    ASSERT_TRUE(wait_for([&] { return heartbeats().size() >= 2; }, std::chrono::seconds(10)));
    client->disable_mesh();
    for (const auto& endpoint : heartbeats()) EXPECT_EQ(endpoint, "");
}
